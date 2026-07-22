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

from fortianalyzer_mcp.masking.fields import (
    COMPOSITE_PREFIXED,
    COMPOSITE_URL_FULL,
    FIELD_TYPES,
    IP,
    IP_OR_HOST,
    MAC,
    SKIP_VALUES,
)
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine, MaskingError
from fortianalyzer_mcp.utils.validation import sanitize_filter_value

logger = logging.getLogger(__name__)

# field==value / field=value / field contain value, single or double quoted
_FILTER_CLAUSE_RE = re.compile(
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?P<op>==|!=|<=|>=|=~|!~|<|>|=(?![=~])|~|!contain\b|\bcontain\b)\s*"
    r"(?P<quote>[\"']?)(?P<value>[^\"'\s()]+)(?P=quote)"
)
_FILTER_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


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
        except MaskingError:
            # Very likely a real address the operator typed, not a token.
            return value
        return value

    def resolve_scalar(self, value: str, vtype: str | None = None) -> str:
        """Resolve one argument value. ``vtype`` comes from the field name."""
        if not value or value.strip() in SKIP_VALUES:
            return value
        candidate = value.strip()
        try:
            marked = self._unmask_marked(candidate)
        except MaskingError:
            # Marker present but payload will not decrypt: leave it alone so
            # the downstream validator rejects it instead of us guessing.
            logger.warning("argument carries a masking marker but does not decrypt; passed through")
            return value
        if marked is not None:
            return marked
        if vtype in (IP, MAC, IP_OR_HOST):
            return self._unmask_by_type(vtype, candidate)
        return value

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
                resolved_tail = self._engine.unmask_url_tail(tail[1:])
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
        """

        def clause_sub(match: re.Match[str]) -> str:
            field = match.group("field")
            raw = match.group("value")
            if field.lower() in COMPOSITE_URL_FULL:
                resolved = self.resolve_url(raw)
            elif field.lower() in COMPOSITE_PREFIXED:
                resolved = self.resolve_prefixed(raw)
            else:
                vtype = FIELD_TYPES.get(field.lower())
                resolved = self.resolve_scalar(raw, vtype)
            if resolved == raw:
                return match.group(0)
            if _FILTER_CONTROL_RE.search(resolved):
                logger.warning(
                    "resolved filter value has control characters; token left unresolved"
                )
                return match.group(0)
            quote = match.group("quote")
            head = match.group(0)[: match.start("quote") - match.start()]
            if quote:
                # Preserve caller quoting and escape delimiters introduced by
                # the resolved value so it cannot terminate the clause early.
                escaped = resolved.replace("\\", "\\\\").replace(quote, "\\" + quote)
                return f"{head}{quote}{escaped}{quote}"
            # Use the same safe-bare or double-quoted convention as callers.
            return f"{head}{sanitize_filter_value(resolved)}"

        return _FILTER_CLAUSE_RE.sub(clause_sub, expression)

    # -- recursive argument walk ------------------------------------------- #

    def unmask_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Resolve tokens across a tool's keyword arguments, at any depth."""
        return {key: self._unmask_entry(key, value) for key, value in args.items()}

    def _unmask_entry(self, key: str, value: Any) -> Any:
        lowered = key.lower()
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
            return self.resolve_scalar(value)
        if isinstance(value, list):
            return [
                self._unmask_entry(key, item) if isinstance(item, str) else self._unmask_any(item)
                for item in value
            ]
        if isinstance(value, dict):
            # e.g. the #44 dispatcher's nested "params" object
            return self.unmask_args(value)
        return value

    def _unmask_any(self, value: Any) -> Any:
        if isinstance(value, dict):
            return self.unmask_args(value)
        if isinstance(value, list):
            return [self._unmask_any(item) for item in value]
        if isinstance(value, str):
            return self.resolve_scalar(value)
        return value
