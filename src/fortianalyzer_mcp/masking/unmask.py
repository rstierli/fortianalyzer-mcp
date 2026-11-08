"""Tool-argument unmasking (RFC #40 Phase 2 prototype).

When the model sends a token back as a tool argument, the real value must
be restored *before* input validators and the FAZ API see it: a masked
token would otherwise be rejected by ``validate_ip_or_cidr`` and friends,
or would query FAZ for a value that does not exist there.

Three resolution paths, in order of confidence:

1. **Marked tokens, anywhere.** ``host-``/``user-`` prefixes and the
   ``.<mask_suffix>`` domain/email forms are self-identifying, so they are
   resolved wherever they appear: a bare string argument, an item in a
   list, a value nested in a dict, or a substring inside a filter
   expression.
2. **Unmarked tokens by argument name.** Masked IPs and MACs look like
   ordinary IPs and MACs (the "IP wrinkle"), so they can only be resolved
   where the *name* says what the value is: an argument called ``srcip``
   or a filter clause ``srcip=="..."``. The name table is the same
   allowlist used for output masking.
3. **Everything else passes through untouched.**

Failure policy mirrors the output side but inverts the default: if a
value carries a marker and does not decrypt, that is an error worth
surfacing (the caller sent a corrupted or foreign token) and the argument
is left as-is so the validator downstream rejects it loudly. If an
unmarked value in an IP/MAC-named field does not decrypt to anything
sensible, it is passed through unchanged: it is far more likely to be a
real address the user typed than a corrupted token, and passing a real
address through is correct behavior.

Known ambiguities, documented rather than papered over:

- With masking on, a user who types a *real* IP into ``srcip`` gets it
  unmasked as if it were a token, producing a different real IP.
  Deterministic FPE has no way to distinguish the two. Deployments that
  expect operators to paste raw IPs should keep masking off, or the prose
  companion should mask what the operator types on the way in.
- Hostname case is lost at *mask* time, because the hostname alphabet is
  lowercase. ``FGT-BRANCH-01`` round trips to ``fgt-branch-01``. Harmless
  for DNS names, which are case insensitive; it matters for device names
  that are not.
- A fortiview ``devvds`` value masks to ``"<token>[<vdom>]"``. Fed back as
  an argument it will not decrypt as a whole, so it passes through and the
  tool's validator rejects it. That is deliberate: a device argument wants
  a device name, and silently discarding the vdom half to salvage one
  would be guessing at what the caller meant.
"""

import logging
import re
from typing import Any

from pydantic import BaseModel

from fortianalyzer_mcp.masking.fields import (
    COMPOSITE_PREFIXED,
    COMPOSITE_URL_FULL,
    FIELD_NAME_ARGS,
    FIELD_TYPES,
    IP,
    IP_OR_HOST,
    MAC,
    SKIP_VALUES,
    TEXT,
)
from fortianalyzer_mcp.masking.fpe_engine import (
    FPEEngine,
    MaskingError,
    VerificationBudgetExhausted,
)
from fortianalyzer_mcp.query.fields import canonical_log_field
from fortianalyzer_mcp.utils.validation import ValidationError, sanitize_filter_value

logger = logging.getLogger(__name__)

# field==value / field=value / field contain value, single or double quoted.
# The lookbehind keeps the field group from starting mid-string: without it
# a non-clause fragment like "a-srcip=<ip>" (or "x /srcip==<ip>", any
# separator) reads as a srcip clause and the address is silently
# transformed (#73 7a). It is an allowlist of the places a clause can
# legitimately begin, measured against live 7.6.7 and 8.0.0: start of
# string, after whitespace, after "(" (grouping and the !(...) complement),
# after ")" ("(a==b)c==d" parses identically to "a==b and c==d", so a clause
# does begin there), after "&" ("a&&b" parses identically to "a and b";
# single "&", "|", "||", "," and "[" are all rejected by the appliance), and
# after "!" (bare "!f==v" negation is served). The cost is that a dotted spelling ("foo.srcip") no
# longer resolves as srcip, which prices at zero: a dotted field matches
# nothing at the appliance, so such a clause only ever produced zero rows.
#
# The value group is conditional on whether the clause is quoted (#73 item 8):
# unquoted stays exactly as strict as before -- no space, quote or paren can
# be part of it, since those are what an unquoted clause's own boundary is
# built from. A QUOTED value only needs to stop at its own closing quote, so
# it may contain anything but a quote character, including whitespace and
# parens -- excluding both quote characters rather than just the matching one
# is pre-existing (the unquoted branch already excluded both), so a quoted
# value still cannot itself carry a literal quote of either kind.
#
# The conditional tests the inner ``q`` group, not ``quote``: ``quote`` always
# participates (empty when unquoted, so ``(?P=quote)`` and the caller's
# ``match.start("quote")`` keep working), and ``re`` counts an empty match as
# matched. Keyed on ``quote``, an unquoted value would take the quoted branch
# and run on through every later clause.
_FILTER_CLAUSE_RE = re.compile(
    r"(?<![^\s()!&])"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?P<op>==|!=|<=|>=|=~|!~|<|>|=(?![=~])|~|!contain\b|\bcontain\b|\b(?ai:like)\b)\s*"
    # A quoted value ends the way the appliance ends it (measured on 7.6.8
    # and 8.0.2, issue #164): at the next quote of the same kind that does not
    # follow a backslash. The other quote character is inert inside it.
    r"(?P<quote>(?P<q>[\"'])?)"
    r"(?P<value>(?(q)(?:(?!(?P=q))[^\x00]|(?<=\\)(?P=q))+?|[^\"'\s()]+))"
    r"(?(q)(?<!\\)(?P=q))"
)
_FILTER_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
#: A value that is exactly one masking token, by shape: marker, key id, payload
#: and, for a v2 token, the tag. Used only to tell a plaintext's own ``%`` and
#: ``_`` from the caller's text around an embedded token; it resolves nothing.
#: Case-insensitive like ``_V2_SHAPE_RE``: a token whose marker came back
#: re-cased still resolves, and its plaintext's wildcards must still be escaped.
_WHOLE_TOKEN_RE = re.compile(
    r"^(?:ip4|ip6|mac|sn|url|host|user)-[0-9a-f]{4}-[A-Za-z0-9._~-]+(?:-[0-9a-f]{8})?$",
    re.IGNORECASE,
)


def _literal_spans(expression: str) -> list[tuple[int, int]]:
    """The quoted literals of ``expression`` as ``(open, end)`` index pairs.

    Read the way FortiAnalyzer reads a filter (measured on 7.6.8 and 8.0.2,
    issue #164): a quote opens a literal, the same quote closes it unless the
    character before it is a backslash, the other quote character is inert,
    and an unclosed literal runs to the end. ``end`` is the index after the
    closing quote. The clause regex reads a literal the same way, but a
    literal that no clause precedes is still a literal, and clause-shaped
    text inside it is the caller's value, not a clause.
    """
    spans: list[tuple[int, int]] = []
    quote: str | None = None
    start = 0
    for i, char in enumerate(expression):
        if quote is None:
            if char in "\"'":
                quote, start = char, i
        elif char == quote and expression[i - 1] != "\\":
            spans.append((start, i + 1))
            quote = None
    if quote is not None:
        spans.append((start, len(expression)))
    return spans


class ArgUnmasker:
    """Resolve masked tokens in tool arguments back to real values."""

    def __init__(self, engine: FPEEngine) -> None:
        self._engine = engine

    # -- scalar resolution ------------------------------------------------ #

    def _unmask_marked(self, value: str) -> str | None:
        """Resolve a self-identifying token, or None if it carries no marker.

        Engine failures propagate only through :meth:`resolve_scalar`,
        which decides what a bad payload means for the caller.
        """
        return self._engine.unmask_token(value)

    def _unmask_by_type(self, vtype: str, value: str) -> str:
        """Resolve an unmarked IP/MAC token; pass through on failure.

        ``IP_OR_HOST`` fields only reach here when the value carries no
        ``host-`` marker, so whatever is left must be an address.
        """
        try:
            if vtype in (IP, IP_OR_HOST):
                return self._engine.unmask_ip(value)
            if vtype == MAC:
                return self._engine.unmask_mac(value)
        except VerificationBudgetExhausted:
            raise
        except MaskingError:
            # Very likely a real address the operator typed, not a token.
            return value
        return value

    def resolve_scalar(self, value: str, vtype: str | None = None) -> str:
        """Resolve one argument value. ``vtype`` comes from the field name."""
        if not value or value.strip() in SKIP_VALUES:
            return value
        candidate = value.strip()
        if vtype == TEXT and self._engine.is_v2_shaped(candidate):
            # Several tokens joined into one label (an address range masks
            # to "<token>-<token>") are v2-shaped as a whole but are not one
            # token. The whole-string attempt below would spend a tag failure
            # on them before falling back to this same scan; a single token
            # opens here exactly as it would there. The scan runs on the
            # stripped value because a token resolved as a whole string has
            # always come back stripped.
            resolved = self._engine.unmask_embedded(candidate)
            return resolved if resolved != candidate else value
        try:
            marked = self._unmask_marked(candidate)
        except VerificationBudgetExhausted:
            raise
        except MaskingError:
            if vtype == TEXT:
                # A TEXT value's token can open the string (#73 item 8
                # follow-up): unmask_token's legacy v1 prefix dispatch just
                # tried to decrypt the WHOLE candidate as one token and
                # failed, because the token is actually only the first part
                # of a label. The embedded scan finds just the token and
                # leaves the rest of the label as written. Scoped to TEXT
                # specifically -- a bare scalar or a HOSTNAME-typed field
                # (devvds) gets none of this and keeps failing closed below,
                # since there the whole value is supposed to BE the token.
                return self._engine.unmask_embedded(value)
            # Marker present but payload will not decrypt: leave it alone so
            # the downstream validator rejects it instead of us guessing.
            logger.warning("argument carries a masking marker but does not decrypt; passed through")
            return value
        if marked is not None:
            return marked
        if vtype in (IP, MAC, IP_OR_HOST):
            return self._unmask_by_type(vtype, candidate)
        # A masked Host header comes back as ``<token>:<port>``, because the
        # masker splits the pair rather than burning it whole. Without the
        # mirror here that value passed straight through, so a model copying a
        # ported host out of a response into a query argument got no
        # restoration and matched zero rows: the split claimed to preserve the
        # query-back pivot while only half building it.
        #
        # Decompose, resolve, reassemble, exactly as ``resolve_url`` already
        # does for a URL's host and port. Strictly a no-op unless the head
        # genuinely resolves, so an ordinary ``host:port`` a caller typed by
        # hand reaches the appliance as written rather than being rewritten by
        # a failed lookup.
        head, sep, port = candidate.partition(":")
        if sep and head and port.isascii() and port.isdigit() and len(port) <= 5:
            resolved = self.resolve_scalar(head, vtype)
            if resolved != head:
                return f"{resolved}:{port}"
        # A free-text value may carry a token mid-string rather than being
        # one (#73 item 8): a TEXT field masks an embedded IOC in place
        # outbound, so the label handed back as a filter value needs the
        # same in-place treatment inbound. Reuses the whole-string token's
        # own shape/tag verification (``FPEEngine.unmask_embedded``); a
        # value with nothing embedded comes back unchanged.
        return self._engine.unmask_embedded(value)

    # -- masked URLs (#40 url/referralurl) ---------------------------------- #

    def resolve_url(self, value: str) -> str:
        """Resolve a masked ``url``/``referralurl`` back to the original.

        Decompose, resolve, reassemble: the host resolves through the same
        field-context route as any ``IP_OR_HOST`` argument (marked-token
        check first, then the ``unmask_ip`` fallback, so an IP-literal
        host round-trips too), and a ``/url-<kid>-<ct>`` tail segment
        decodes back to the exact original path+query+fragment. A URL
        that carries neither passes through untouched. A host or tail token
        that carries a marker but will not decrypt fails the whole value
        closed. This path is load-bearing: without it a masked URL handed
        back whole would reach FAZ still tokenized and silently match zero
        rows.
        """
        from urllib.parse import urlsplit

        candidate = value.strip()
        try:
            parts = urlsplit(candidate)
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            return value
        if "@" in parts.netloc:
            # The mask side never emits userinfo tokens; do not reassemble lossily.
            return value
        if not host:
            return self.resolve_scalar(value)
        try:
            marked_host = self._unmask_marked(host)
        except VerificationBudgetExhausted:
            raise
        except MaskingError:
            # Marker present but the payload will not decrypt: leave the whole
            # URL alone rather than sending FAZ a half-resolved one that can
            # only match zero rows. Mirrors the tail branch below.
            logger.warning(
                "url argument carries a host token that does not decrypt; passed through"
            )
            return value
        resolved_host = (
            marked_host if marked_host is not None else self._unmask_by_type(IP_OR_HOST, host)
        )
        # Anchor after the ``//`` authority marker (a single-letter host
        # matches inside the scheme from position 0), and pass through if
        # the parsed netloc is not in the raw string at all (urlsplit
        # strips tab/CR/LF, bpo-43882) — never raise for an argument.
        try:
            anchor = candidate.index("//") + 2
            tail = candidate[candidate.index(parts.netloc, anchor) + len(parts.netloc) :]
        except ValueError:
            return value
        resolved_tail = tail
        # Case-insensitive gate: the other token forms tolerate a model
        # re-casing them in prose, and the url tail payload is lowercase
        # over a case-insensitive alphabet, so this one must too.
        if tail[:5].lower() == "/url-":
            try:
                # Through the dispatch rather than the v1 primitive, so this
                # path gets the v2 shape gate and the deprecation window
                # instead of routing around both. A v2 url token also starts
                # "url-", so the prefix test above still selects it, and
                # calling the v1 primitive on one would fail to decrypt and
                # drop the whole URL. None means no marker matched, which
                # leaves the tail as it was.
                resolved_tail = self._engine.unmask_token(tail[1:]) or tail
            except VerificationBudgetExhausted:
                raise
            except MaskingError:
                # Marker present but the payload will not decrypt: leave the
                # whole URL alone so the downstream validator rejects it.
                logger.warning(
                    "url argument carries a url- tail token that does not decrypt; passed through"
                )
                return value
        if resolved_host == host and resolved_tail == tail:
            return value
        if ":" in resolved_host:  # IPv6 literal: re-bracket
            resolved_host = f"[{resolved_host}]"
        netloc = f"{resolved_host}:{port}" if port is not None else resolved_host
        prefix = f"{parts.scheme}://" if parts.scheme else "//"
        return f"{prefix}{netloc}{resolved_tail}"

    # -- prefixed group-by values (alert groupby1/groupby2) ---------------- #

    def resolve_prefixed(self, value: str) -> str:
        """Inverse of ``wrapper._mask_prefixed``.

        The output side masks the inner value of a ``"<fieldname>:<value>"``
        group-by string by the INNER field's type, so the inverse must too:
        the outer key (``groupby1``) has no type, so resolving the string as
        a whole leaves the token untouched and a filter built from it matches
        zero rows. Split on the first colon only, so an IPv6 inner value
        keeps its own colons, resolve the value by the inner field's type,
        and reassemble. Mirrors the mask side's per-element comma handling.
        """
        field, sep, raw = value.partition(":")
        if not sep or not raw:
            return value
        vtype = FIELD_TYPES.get(field.lower())
        if "," in raw:
            resolved = ",".join(self.resolve_scalar(part, vtype) for part in raw.split(","))
        else:
            resolved = self.resolve_scalar(raw, vtype)
        if resolved == raw:
            return value
        return f"{field}{sep}{resolved}"

    # -- filter expressions ------------------------------------------------ #

    def unmask_filter(self, expression: str) -> str:
        """Resolve tokens inside a FAZ filter expression.

        ``srcip=="93.209.148.131" and user=="user-3f2a-k9x2q4"`` becomes the
        expression over real values. Field names drive IP/MAC resolution;
        marked tokens resolve regardless of the field they sit in.

        Raises:
            ValidationError: If a resolved value cannot be written as one
                filter literal (it ends in a backslash, holds both quote
                characters, or holds a control character). A token left in
                place would match nothing, which under a negated operator
                returns every row, so the filter is refused instead.
        """

        def clause_sub(match: re.Match[str]) -> str:
            field = match.group("field")
            raw = match.group("value")
            # ``like`` wraps the token in ``%`` wildcards (``field like "%tok%"``);
            # resolve the token inside them and re-apply so the pattern holds.
            lead, core, trail = "", raw, ""
            if match.group("op").strip().lower() == "like":
                wc = re.match(r"^(%*)(.*?)(%*)$", raw)
                if wc:
                    lead, core, trail = wc.group(1), wc.group(2), wc.group(3)
            if field.lower() in COMPOSITE_URL_FULL:
                resolved = self.resolve_url(core)
            elif field.lower() in COMPOSITE_PREFIXED:
                resolved = self.resolve_prefixed(core)
            else:
                vtype = FIELD_TYPES.get(field.lower())
                resolved = self.resolve_scalar(core, vtype)
            if resolved == core:
                return match.group(0)
            if _FILTER_CONTROL_RE.search(resolved):
                # Left in place, the token would match nothing, which under a
                # negated operator returns every row; refuse the filter instead.
                raise ValidationError(
                    "a resolved filter value holds a control character; the filter was not sent"
                )
            quote = match.group("quote")
            head = match.group(0)[: match.start("quote") - match.start()]
            # Write the plaintext the way the operator reads a literal (issue
            # #164; ``==`` and ``!=`` measured on 7.6.8 and 8.0.2, the other
            # comparisons assumed to read it the same way). ``like`` takes a
            # doubled backslash as one literal backslash; ``==`` reads every
            # character as written.
            is_like = match.group("op").strip().lower() == "like"
            escaped = resolved.replace("\\", "\\\\") if is_like else resolved
            if is_like and _WHOLE_TOKEN_RE.fullmatch(core):
                # The whole value was one token, so every ``%`` and ``_`` in the
                # plaintext is the plaintext's own: write them as the characters
                # (``\%`` and ``\_``, measured). Around an embedded token the
                # caller's own wildcards sit in the same text and cannot be told
                # apart, so there they stay as written.
                escaped = escaped.replace("%", "\\%").replace("_", "\\_")
            if is_like and not quote:
                # An unquoted pattern is quoted on the way out, as a bare
                # comparison value is below, and keeps the ``like`` writing.
                quote = '"'
            if quote:
                literal = f"{lead}{escaped}{trail}"
                if quote in literal:
                    # There is no escape for a quote: the literal takes the
                    # quote character the value does not contain, and the
                    # value then compares as itself. With both present, this
                    # writer does not try.
                    other = "'" if quote == '"' else '"'
                    if other in literal:
                        # Leaving the token would match nothing, which under
                        # a negated operator returns every row. Refuse the
                        # whole filter instead; the message carries no value.
                        raise ValidationError(
                            "a filter literal would hold both quote characters once its "
                            "token is resolved, which this writer does not support; the "
                            "filter was not sent"
                        )
                    quote = other
                if literal.endswith("\\"):
                    # The closing quote would follow a backslash and the literal
                    # would run on into the next clause, whatever that is.
                    raise ValidationError(
                        "a filter literal would end in a backslash once its token is "
                        "resolved, so its closing quote would not close it; the filter "
                        "was not sent"
                    )
                return f"{head}{quote}{literal}{quote}"
            # Use the same safe-bare or quoted convention as callers. A value
            # the sanitiser refuses raises out of here for the same reason.
            # Not stripped: the plaintext's own spaces are part of the value,
            # and a stripped one compares against a different value, which
            # under ``!=`` returns the rows the caller meant to exclude.
            return f"{head}{sanitize_filter_value(resolved, strip=False)}"

        spans = _literal_spans(expression)
        out: list[str] = []
        pos = 0
        while (match := _FILTER_CLAUSE_RE.search(expression, pos)) is not None:
            literal = next((s for s in spans if s[0] < match.start() < s[1]), None)
            if literal is not None:
                # Clause-shaped text inside a quoted literal is the caller's
                # value. Copy the literal through its real end and look for
                # the next clause after it, so a clause that follows the
                # literal is still resolved.
                out.append(expression[pos : literal[1]])
                pos = literal[1]
                continue
            out.append(expression[pos : match.start()])
            out.append(clause_sub(match))
            pos = match.end()
        out.append(expression[pos:])
        return "".join(out)

    # -- structured filter conditions --------------------------------------- #

    #: Keys that make a mapping a filter condition: the value's type is named
    #: by a *sibling* key, not by its own key.
    _CONDITION_KEYS = frozenset({"field", "value"})

    def _is_filter_condition(self, value: Any) -> bool:
        """True for a ``{field, op, value}`` mapping or an equivalent model."""
        if isinstance(value, BaseModel):
            return self._CONDITION_KEYS <= set(type(value).model_fields)
        if isinstance(value, dict):
            return self._CONDITION_KEYS <= set(value)
        return False

    def unmask_filter_conditions(self, condition: Any) -> Any:
        """Resolve tokens in one structured filter condition.

        ``unmask_args`` types a value by its own key, and ``unmask_filter`` types
        it by the field name preceding it in the expression. A condition object
        does neither: the value sits under the literal key ``value`` while its
        field name is a sibling. A masked IP is format-preserving and unmarked,
        so without consulting that sibling the token is indistinguishable from a
        real address and would be sent to the appliance as-is -- returning real
        logs for a different host.

        Models are returned as models (re-validated from the resolved dump) so
        the tool still receives the type its signature declares.

        The sibling field is canonicalised through the query alias table first:
        the compilers accept ``source_ip`` for ``srcip`` and the server guide
        advertises that, but the masking allowlist is keyed on canonical names
        only -- typed by the raw alias spelling, an unmarked IP token would slip
        through untouched. Only the *type lookup* uses the canonical name; the
        condition keeps the caller's spelling for the compiler to resolve.
        """
        is_model = isinstance(condition, BaseModel)
        data = dict(condition.model_dump()) if is_model else dict(condition)

        field = data.get("field")
        if isinstance(field, str):
            data["value"] = self._unmask_entry(canonical_log_field(field), data.get("value"))

        if is_model:
            return type(condition).model_validate(data)
        return data

    # -- recursive argument walk ------------------------------------------- #

    def unmask_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Resolve tokens across a tool's keyword arguments, at any depth."""
        return {key: self._unmask_entry(key, value) for key, value in args.items()}

    def _unmask_entry(self, key: str, value: Any) -> Any:
        lowered = key.lower()
        if lowered in FIELD_NAME_ARGS:
            # Names a field, column or view -- not a value. Resolving a token
            # here turned every echo of the argument (fields_returned, an
            # echoed group_by/sample_by, a refusal message quoting the
            # dimension) into a token -> plaintext oracle; see FIELD_NAME_ARGS.
            return value
        if isinstance(value, str):
            if lowered in ("filter", "filter_applied"):
                return self.unmask_filter(value)
            if lowered in COMPOSITE_URL_FULL:
                return self.resolve_url(value)
            if lowered in COMPOSITE_PREFIXED:
                return self.resolve_prefixed(value)
            vtype = FIELD_TYPES.get(lowered)
            if vtype in (IP, MAC, IP_OR_HOST):
                # comma-joined multi-values, same convention as the output side
                if "," in value:
                    return ",".join(self.resolve_scalar(part, vtype) for part in value.split(","))
                return self.resolve_scalar(value, vtype)
            if vtype == TEXT:
                # No comma-splitting here, unlike above: a TEXT label is a
                # free-form string (an object name, a log message) and a
                # literal comma is part of it, not a multi-value separator.
                return self.resolve_scalar(value, vtype)
            return self.resolve_scalar(value)
        if isinstance(value, list):
            return [
                self._unmask_entry(key, item) if isinstance(item, str) else self._unmask_any(item)
                for item in value
            ]
        if self._is_filter_condition(value):
            return self.unmask_filter_conditions(value)
        if isinstance(value, dict):
            # e.g. the #44 dispatcher's nested "params" object
            return self.unmask_args(value)
        return value

    def _unmask_any(self, value: Any) -> Any:
        if self._is_filter_condition(value):
            return self.unmask_filter_conditions(value)
        if isinstance(value, dict):
            return self.unmask_args(value)
        if isinstance(value, list):
            return [self._unmask_any(item) for item in value]
        if isinstance(value, str):
            return self.resolve_scalar(value)
        return value
