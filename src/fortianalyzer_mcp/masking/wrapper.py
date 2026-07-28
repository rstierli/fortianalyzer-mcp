"""Tool-boundary output masking (RFC #40 Phase 1 prototype).

Masks every tool result before it leaves the MCP toward the LLM. There is
no central tool-registration function to hook (tool modules self-register
with module-level ``@mcp.tool(...)`` at import time), so ``install_masking``
patches ``mcp.tool`` on the shared FastMCP instance BEFORE the tool
modules are imported; every subsequently registered tool is wrapped.

Masking runs in two passes over the result, because a value is only safe
to strip out of free text once we know what it masks to:

1. **Structured pass.** Allowlisted keys are masked by type at any nesting
   depth, and composite keys are parsed and masked part by part
   (``groupby1``/``groupby2`` are ``"<field>:<value>"``, ``grpby`` is an
   embedded JSON blob, ``target`` is a list of ``{name, value}``,
   ``devvds`` is ``"<devname>[<vdom>]"``). Every real value masked here is
   recorded in a response-scoped raw-to-token map.
2. **Free-text pass.** ``msg``, ``logdesc``, ``subject``, ``extrainfo``,
   the echoed ``filter`` strings and friends get an in-place scan for
   embedded IPv4s, MACs and emails, then every raw value from pass 1 is
   substituted wherever it appears. That second step is what catches
   hostnames and domains inside prose: you cannot regex a hostname safely,
   but you can replace the exact strings you just masked elsewhere in the
   same response. It also removes the "masked under one key, cleartext two
   keys away" failure that a leak test over live alert records exposed.

Fail-closed by construction:

- A value that cannot be masked (outside the FPE alphabet, malformed) is
  replaced with an irreversible keyed placeholder, never passed through
  raw, never logged.
- If masking a whole result fails unexpectedly, the tool returns a
  ``masking_failed`` error envelope and the raw result is withheld.

Because FPE is deterministic, a re-masked echo of an unmasked argument
yields exactly the token the caller sent, so follow-up turns stay
consistent.

This module is the OUTPUT side. Argument unmasking (Phase 2) lives in
``unmask.py`` and is applied by the same registration patch.
IPv6-in-text scanning is not yet handled. Device identity
(``devname``, ``devid``, ``sn``, ``csf``, ``fortigate``, ``devvds``,
``detectkey``) is masked only when ``FAZ_MASK_DEVICE_IDENTITY`` is set, so
by default a masked record still fingerprints the reporting device.
"""

import contextvars
import hashlib
import hmac
import inspect
import ipaddress
import json
import logging
import os
import re
from functools import wraps
from typing import Any

from fortianalyzer_mcp.masking.fields import (
    COMPOSITE_DEVICE_VDOM,
    COMPOSITE_FILTER_ENTRIES,
    COMPOSITE_JSON,
    COMPOSITE_PREFIXED,
    COMPOSITE_TARGET,
    COMPOSITE_URL_FULL,
    COMPOSITE_URL_HOST,
    DEVICE_IDENTITY_TYPES,
    DOMAIN,
    EMAIL,
    FIELD_TYPES,
    HOSTNAME,
    IP,
    IP_OR_HOST,
    MAC,
    OBF_URL_KEY,
    SKIP_VALUES,
    TARGET_NAME_TYPES,
    TEXT,
    THREAT_KEY,
    USERNAME,
)
from fortianalyzer_mcp.masking.fpe_engine import MASKING_KEY_ENV, FPEEngine, MaskingError
from fortianalyzer_mcp.masking.unmask import ArgUnmasker

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DEVVDS_RE = re.compile(r"^(?P<dev>[^\[\]]+)\[(?P<vdom>[^\[\]]*)\]$")

#: Values shorter than this are not substituted into free text: a two or
#: three character username would match inside unrelated words.
_MIN_SUBSTITUTION_LEN = 4

_PLACEHOLDER_MARK = "masked-unrepresentable-"


def _find_key(obj: dict[str, Any], name: str) -> str | None:
    """Original spelling of the lowercase ``name`` in ``obj``, or None.

    The composite handlers hand ``_mask_structured`` an override dict it
    looks up with ``key in paired`` against the ORIGINAL keys, so a
    case-insensitive match must give back the key as spelled in ``obj`` or
    the override silently stops applying.
    """
    for key in obj:
        if key.lower() == name:
            return key
    return None


class OutputMasker:
    """Recursive result masker bound to one FPE engine."""

    def __init__(self, engine: FPEEngine, mask_device_identity: bool = False) -> None:
        self._engine = engine
        # Keyed so placeholders are deterministic (correlatable) but not
        # brute-forceable from a leaked transcript. The env var is present
        # because the engine was just built from it.
        self._placeholder_key = os.environ.get(MASKING_KEY_ENV, "").encode()
        self._mask_device_identity = mask_device_identity
        self._field_types = dict(FIELD_TYPES)
        if mask_device_identity:
            self._field_types.update(DEVICE_IDENTITY_TYPES)

    # -- fail-closed primitives ---------------------------------------- #

    def placeholder(self, value: str) -> str:
        """Irreversible, deterministic stand-in for an unmaskable value."""
        digest = hmac.new(self._placeholder_key, value.encode(), hashlib.sha256).hexdigest()[:10]
        return f"{_PLACEHOLDER_MARK}{digest}"

    def _mask_ip_or_host(self, value: str) -> str:
        """Mask a field that holds either an address or a name.

        The token forms stay distinguishable on the way back: a hostname
        token carries the ``host-`` prefix, an IP token parses as an IP.
        """
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            return self._engine.mask_hostname(value)
        return self._engine.mask_ip(value)

    def _mask_one(self, vtype: str, value: str) -> str:
        try:
            if vtype == IP:
                return self._engine.mask_ip(value)
            if vtype == MAC:
                return self._engine.mask_mac(value)
            if vtype == IP_OR_HOST:
                return self._mask_ip_or_host(value)
            if vtype == HOSTNAME:
                return self._engine.mask_hostname(value)
            if vtype == USERNAME:
                return self._engine.mask_username(value)
            if vtype == DOMAIN:
                return self._engine.mask_domain(value)
            if vtype == EMAIL:
                # from/to are emails in virus/emailfilter logs but plain
                # labels elsewhere; only actual addresses mask as email.
                if "@" in value:
                    return self._engine.mask_email(value)
                return self._engine.mask_username(value)
        except MaskingError:
            return self.placeholder(value)
        except Exception:
            # Never let a masking bug leak the raw value. The value itself
            # is deliberately not logged.
            logger.exception("unexpected error masking a %s value; placeholder used", vtype)
            return self.placeholder(value)
        return self.placeholder(value)  # unknown type tag: fail closed

    def _mask_scalar(self, vtype: str, value: str, mapping: dict[str, str] | None = None) -> str:
        if value.strip() in SKIP_VALUES:
            return value
        if "," in value:
            # FAZ packs multi-valued fields into one comma-joined string
            # (live example: the dns ``ipaddr`` answer list). Mask each
            # element; an unmaskable element still fails closed on its own.
            return ",".join(
                part
                if part.strip() in SKIP_VALUES or not part
                else self._mask_scalar(vtype, part, mapping)
                for part in value.split(",")
            )
        token = self._mask_one(vtype, value)
        if mapping is not None and token != value and _PLACEHOLDER_MARK not in token:
            mapping[value] = token
        return token

    # -- composite keys ------------------------------------------------- #

    def _mask_prefixed(self, value: str, mapping: dict[str, str]) -> str:
        """``"<fieldname>:<value>"`` (alert ``groupby1``/``groupby2``)."""
        field, sep, raw = value.partition(":")
        if not sep or not raw:
            return value
        vtype = self._field_types.get(field.lower())
        if vtype is None or vtype == TEXT:
            return value
        return f"{field}{sep}{self._mask_scalar(vtype, raw, mapping)}"

    def _mask_json_blob(self, value: str, mapping: dict[str, str]) -> str:
        """An embedded JSON string (incident ``grpby``)."""
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            # Not JSON after all: at least strip the IOCs a regex can see.
            return self.mask_text(value, mapping)
        return json.dumps(self._mask_structured(parsed, mapping))

    def _mask_device_vdom(self, value: str, mapping: dict[str, str]) -> str:
        """``"<devname>[<vdom>]"``, comma-joined (fortiview ``devvds``).

        The vdom stays clear, like the flat ``vd`` log field. Only the
        device name is estate identity, so the whole key follows
        ``FAZ_MASK_DEVICE_IDENTITY``.
        """
        if not self._mask_device_identity:
            return value
        out: list[str] = []
        for part in value.split(","):
            match = _DEVVDS_RE.match(part.strip())
            if match is None:
                # Bare device name, or a shape we have not seen: mask whole.
                out.append(self._mask_scalar(HOSTNAME, part, mapping))
                continue
            device = self._mask_scalar(HOSTNAME, match.group("dev"), mapping)
            out.append(f"{device}[{match.group('vdom')}]")
        return ",".join(out)

    def _burn_strings(self, value: Any, keep: frozenset[str]) -> Any:
        if isinstance(value, str):
            if value in keep or not value or value.strip() in SKIP_VALUES:
                return value
            return self.placeholder(value)
        if isinstance(value, list | tuple):
            return [self._burn_strings(item, keep) for item in value]
        if isinstance(value, dict):
            # A map-shaped value carries the identifier in the KEY
            # ({"<ip>": {...}}), and no later pass ever scans a key.
            return {
                self._burn_strings(key, keep): self._burn_strings(item, keep)
                for key, item in value.items()
            }
        return value

    def _mask_target(
        self, value: list[Any], mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> list[Any]:
        """``[{"name": "ip", "value": "..."}]`` (alert ``target``).

        A value in ``keep`` is the reporting estate's own identity (it
        appears under a device-identity key elsewhere in this response,
        and the deployment left device identity unmasked): masking it
        here while ``devid`` shows it in clear would hand out the
        token-to-serial pair. Live 8.0.0 alerts do exactly this — the
        appliance serial arrives as a ``device`` target.

        Unknown target names fail closed by burning string content because
        there is no reliable type for reversible masking. So does a whole
        ``target`` that is not a list, an entry that is not a dict, and a
        map-shaped ``value`` whose key carries the identifier. An entry
        that IS a dict but carries neither ``name`` nor ``value`` burns
        whole for the same reason: with no slot to type it by, the
        identifier is parked in the entry's own key, which the allowlist
        walk would copy through in clear (#73).
        """
        out: list[Any] = []
        for item in value:
            if not isinstance(item, dict):
                # No name/value pair to type the entry by: burn it like an
                # unknown target name. The allowlist pass returns a bare
                # string leaf unchanged, which is fail-open here.
                out.append(self._burn_strings(item, keep))
                continue
            name: Any = ""
            raw: Any = None
            has_name = False
            has_value = False
            for key, item_value in item.items():
                lowered = key.lower()
                if lowered == "name":
                    name = item_value
                    has_name = True
                elif lowered == "value":
                    raw = item_value
                    has_value = True
            if not has_name and not has_value:
                out.append(self._burn_strings(item, keep))
                continue
            vtype = TARGET_NAME_TYPES.get(str(name).lower())
            if vtype is None:
                masked_value = self._burn_strings(raw, keep)
            elif isinstance(raw, str):
                masked_value = raw if raw in keep else self._mask_scalar(vtype, raw, mapping)
            elif isinstance(raw, list | tuple):
                masked_value = [
                    elem
                    if isinstance(elem, str) and elem in keep
                    else self._mask_scalar(vtype, elem, mapping)
                    if isinstance(elem, str)
                    else self._burn_strings(elem, keep)
                    for elem in raw
                ]
            elif isinstance(raw, dict):
                masked_value = self._burn_strings(raw, keep)
            else:
                masked_value = raw

            entry: dict[str, Any] = {}
            for key, item_value in item.items():
                lowered = key.lower()
                if lowered == "name":
                    # A label is a short string like "ip" or "device". Any
                    # other shape is not a label, so its content is burned
                    # rather than echoed: nothing else scans this slot.
                    entry[key] = (
                        item_value
                        if isinstance(item_value, str)
                        else self._burn_strings(item_value, keep)
                    )
                elif lowered == "value":
                    entry[key] = masked_value
                elif lowered == "asset_value":
                    # asset_value repeats the identifier on some targets and
                    # carries an internal id on others. The id case is a bare
                    # number; a differing non-numeric string is a second
                    # identifier for the same asset, so it gets the entry's
                    # own type, and with no type to mask by it burns like the
                    # value did (#73). Differing containers burn whole.
                    if item_value == raw:
                        entry[key] = masked_value
                    elif isinstance(item_value, str):
                        if item_value in keep or item_value.isdigit():
                            entry[key] = item_value
                        elif vtype is None:
                            entry[key] = self._burn_strings(item_value, keep)
                        else:
                            entry[key] = self._mask_scalar(vtype, item_value, mapping)
                    elif isinstance(item_value, list | tuple | dict):
                        entry[key] = self._burn_strings(item_value, keep)
                    else:
                        entry[key] = item_value
                else:
                    entry[key] = self._mask_entry(key, item_value, mapping, keep)
            out.append(entry)
        return out

    # -- free-text IOC scan --------------------------------------------- #

    def mask_text(self, text: str, mapping: dict[str, str] | None = None) -> str:
        """Mask embedded IPv4/MAC/email IOCs, then any known raw value."""

        def ip_sub(m: re.Match[str]) -> str:
            candidate = m.group(0)
            try:
                ipaddress.IPv4Address(candidate)
            except ValueError:
                return candidate  # e.g. 999.1.1.1 or a dotted version string
            try:
                return self._engine.mask_ip(candidate)
            except MaskingError:
                return self.placeholder(candidate)

        def mac_sub(m: re.Match[str]) -> str:
            try:
                return self._engine.mask_mac(m.group(0))
            except MaskingError:
                return self.placeholder(m.group(0))

        def email_sub(m: re.Match[str]) -> str:
            try:
                return self._engine.mask_email(m.group(0))
            except MaskingError:
                return self.placeholder(m.group(0))

        out = _IPV4_RE.sub(ip_sub, text)
        out = _MAC_RE.sub(mac_sub, out)
        out = _EMAIL_RE.sub(email_sub, out)
        return self._substitute_known(out, mapping)

    def _substitute_known(self, text: str, mapping: dict[str, str] | None) -> str:
        """Replace values that were masked elsewhere in this response.

        Hostnames and domains cannot be recognized by pattern, but they can
        be recognized by identity: a value masked in a structured field of
        the same response is the same identifier wherever it appears in
        prose, and gets the same token. Longest first, so a domain is not
        partially rewritten by one of its own labels.
        Matching is case-insensitive: hostnames, domains and emails are
        case-insensitive identifiers and mask to the same token whatever
        their spelling, so an echo that re-cases one is the same value.
        The exact spelling still wins the token lookup, because usernames
        are case-sensitive principals and ``Admin``/``admin`` must keep
        their own tokens when both were masked. One alternation in one
        pass, so a token already substituted is never re-scanned.
        """
        if not mapping:
            return text
        raws = [
            raw
            for raw in sorted(mapping, key=len, reverse=True)
            if len(raw) >= _MIN_SUBSTITUTION_LEN
        ]
        if not raws:
            return text
        # An inexact (case-only) match may reuse a token only when exactly one
        # raw owns that folded form. Usernames are case-sensitive principals,
        # so two of them differing only in case make a third spelling
        # ambiguous, and picking either token would resolve to the wrong
        # identity. Ambiguous spellings fail closed to a placeholder instead.
        folded: dict[str, str] = {}
        ambiguous: set[str] = set()
        for raw in raws:
            key = raw.casefold()
            if key in folded and folded[key] != mapping[raw]:
                ambiguous.add(key)
            folded.setdefault(key, mapping[raw])
        # ``(?ai:...)`` scopes both flags to the alternation, and both are
        # load-bearing. Without the scoping, ``re.IGNORECASE`` also widens
        # the boundary look-arounds, because the ASCII class ``[A-Za-z]``
        # then additionally matches the characters that case-fold into it,
        # so an identifier sitting next to one is handed back in clear.
        # Without ``a``, case-insensitivity follows full Unicode folding,
        # which equates U+017F/U+212A/U+0130/U+0131 with ASCII letters: the
        # regex matches a spelling that ``casefold`` then fails to look up,
        # and a known value degrades to an irreversible placeholder. Re-casing
        # an identifier means ASCII case, so ASCII folding is what we want.
        pattern = re.compile(
            r"(?<![A-Za-z0-9._-])(?ai:"
            + "|".join(re.escape(raw) for raw in raws)
            + r")(?![A-Za-z0-9._-])"
        )

        def swap(match: re.Match[str]) -> str:
            found = match.group(0)
            exact = mapping.get(found)
            if exact is not None:
                return exact
            key = found.casefold()
            if key in ambiguous:
                return self.placeholder(found)
            return folded.get(key) or self.placeholder(found)

        return pattern.sub(swap, text)

    # -- the two passes -------------------------------------------------- #

    def mask_result(self, obj: Any) -> Any:
        """Mask a tool result: structured pass, then free-text pass."""
        mapping: dict[str, str] = {}
        keep = frozenset() if self._mask_device_identity else self._device_identity_values(obj)
        staged = self._mask_structured(obj, mapping, keep)
        return self._mask_free_text(staged, mapping)

    def _device_identity_values(self, obj: Any) -> frozenset[str]:
        """Device-identity values present in this response, pre-collected.

        With ``FAZ_MASK_DEVICE_IDENTITY`` off these stay readable by
        design, so any handler that can reach the same value under another
        key (live 8.0.0 alerts carry the reporting appliance's serial in
        ``target[].value``) must leave it clear too. Masking it in one
        place while ``devid`` shows it two keys away is not privacy, it is
        a token-to-serial correlation gift.

        A device-identity key may carry a list of names rather than one
        string: ``devs`` on an alert's ``subject_details`` is list-valued,
        and until it was handled here a device named only there stayed
        clear under ``devs`` while the same name masked inside ``target``,
        which is the pairing this set exists to prevent.

        The comma split applies to the string form ONLY. A string is split
        because FAZ joins aggregated device names into one value
        (``fortigate`` on a multi-device fortiview row), and every part is
        then a device name. A list is already that split form, so
        splitting its elements again would add nothing and would widen the
        one hazard this set has: whatever lands in it is exempted from
        masking inside ``target``, so a value carrying a comma exempts each
        part independently of whether that part names a device.
        """
        out: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key.lower() in DEVICE_IDENTITY_TYPES:
                        if isinstance(value, str):
                            out.update(part.strip() for part in value.split(","))
                        elif isinstance(value, list | tuple):
                            # String elements are taken whole; anything else
                            # (a dict nesting devname deeper) is walked, as
                            # every non-string value already was before the
                            # list form was handled here.
                            for item in value:
                                if isinstance(item, str):
                                    out.add(item.strip())
                                else:
                                    walk(item)
                        else:
                            walk(value)
                    elif key.lower() in COMPOSITE_DEVICE_VDOM and isinstance(value, str):
                        for part in value.split(","):
                            match = _DEVVDS_RE.match(part.strip())
                            out.add(match.group("dev") if match else part.strip())
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(obj)
        return frozenset(v for v in out if v)

    def _mask_structured(
        self, obj: Any, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> Any:
        """Pass 1: mask allowlisted and composite keys, record raw -> token."""
        if isinstance(obj, dict):
            paired = self._mask_threat_pair(obj, mapping)
            paired.update(self._mask_incident_reporter(obj, mapping))
            paired.update(self._mask_indicator_pair(obj, mapping))
            return {
                key: paired[key] if key in paired else self._mask_entry(key, value, mapping, keep)
                for key, value in obj.items()
            }
        if isinstance(obj, list):
            return [self._mask_structured(item, mapping, keep) for item in obj]
        return obj

    def _mask_incident_reporter(
        self, obj: dict[str, Any], mapping: dict[str, str]
    ) -> dict[str, str]:
        """``incident_reporter``: masked only when the record proves it a username.

        The field is polymorphic — a username on manually raised incidents,
        an alert id on auto-raised ones — so typing it outright would
        corrupt alert ids. But the username case is decidable from the
        record itself: when the value equals the sibling ``reporter`` or
        ``lastuser`` (both masked as usernames), it is the same principal
        and must carry the same token; leaving it clear un-masks the
        sibling verbatim (found live by the flag-on round on both boxes).
        Any other value is an id or a principal we cannot prove, and stays
        untouched as before.
        """
        key = _find_key(obj, "incident_reporter")
        if key is None:
            return {}
        value = obj[key]
        if not isinstance(value, str) or not value.strip() or value.strip() in SKIP_VALUES:
            return {}
        siblings = tuple(
            obj[sib]
            for sib in (_find_key(obj, "reporter"), _find_key(obj, "lastuser"))
            if sib is not None
        )
        if value not in siblings:
            return {}
        return {key: self._mask_scalar(USERNAME, value, mapping)}

    def _mask_indicator_pair(self, obj: dict[str, Any], mapping: dict[str, str]) -> dict[str, str]:
        """SOAR ``value``/``type``: the IOC itself, typed by its sibling.

        ``get_indicator_enrichment`` and ``get_linked_indicators`` return
        the indicator under the key ``value``, which is far too generic to
        allowlist outright: the same name carries a severity band, a count
        and a config setting elsewhere in the API, and typing it globally
        would mask ``"high"`` as a hostname. The sibling ``type`` decides
        instead, exactly as ``obf_url`` decides for ``threat`` -- SOAR
        writes it on every indicator row and it names the value's class.

        Only IP, Domain and URL are recognised, which is the set the reader
        tools accept. Any other ``type`` (or none) leaves ``value`` alone,
        so the generic use of the name is untouched.
        """
        key = _find_key(obj, "value")
        type_key = _find_key(obj, "type")
        if key is None or type_key is None:
            return {}
        value = obj[key]
        if not isinstance(value, str) or not value.strip() or value.strip() in SKIP_VALUES:
            return {}
        kind = obj[type_key]
        if not isinstance(kind, str):
            return {}
        lowered = kind.strip().lower()
        if lowered == "ip":
            return {key: self._mask_scalar(IP, value, mapping)}
        if lowered == "domain":
            return {key: self._mask_scalar(DOMAIN, value, mapping)}
        if lowered == "url":
            return {key: self._mask_url_full(value, mapping)}
        return {}

    def _mask_threat_pair(self, obj: dict[str, Any], mapping: dict[str, str]) -> dict[str, str]:
        """fortiview ``threat``/``obf_url``: masked together, as domains (#40).

        ``obf_url`` is populated exactly when ``threat`` holds a browsable
        web domain (it is the ``[dot]``-escaped twin of the same value) and
        is empty on every signature, filename and anomaly row — verified
        across both reference estates on the RFC thread. The sibling, not a
        logtype table or a shape test, decides: ``logtype`` does not
        discriminate (domains arrive as traffic rows on one estate), and
        malware rows carry dotted filenames a shape test would misread.

        Non-empty ``obf_url``: mask ``threat`` as a domain, and unescape,
        mask and re-escape ``obf_url`` so the pair stays consistent
        (deterministic FPE makes the two tokens twins again). The model
        should hand the ``threat`` token back for queries; the re-escaped
        ``obf_url`` form stays display-only, like the raw field it defangs.
        Empty ``obf_url``: leave ``threat`` clear, its analytic value
        (signature or filename) intact.

        Documented residual (fail-open): a row carrying a domain ``threat``
        with an empty ``obf_url`` would leak that domain. Neither estate
        shows such a row and the field exists precisely to defang browsable
        objects; the leak test carries a tripwire assertion so a live
        counterexample fails a test instead of leaking silently.
        """
        obf_key = _find_key(obj, OBF_URL_KEY)
        if obf_key is None:
            return {}
        obf = obj[obf_key]
        if not isinstance(obf, str) or not obf.strip() or obf.strip() in SKIP_VALUES:
            return {}
        out: dict[str, str] = {}
        token = self._mask_scalar(DOMAIN, obf.replace("[dot]", "."), mapping)
        escaped = token.replace(".", "[dot]")
        if _PLACEHOLDER_MARK not in token and escaped != obf:
            # Catch the escaped raw form in prose too; the unescaped form
            # is already in the mapping via _mask_scalar.
            mapping[obf] = escaped
        out[obf_key] = escaped
        threat_key = _find_key(obj, THREAT_KEY)
        if threat_key is not None:
            threat = obj[threat_key]
            if isinstance(threat, str) and threat.strip() and threat.strip() not in SKIP_VALUES:
                out[threat_key] = self._mask_scalar(DOMAIN, threat, mapping)
        return out

    def _mask_url_host(self, value: str, mapping: dict[str, str]) -> str:
        """``http_url`` (alert ``event_details``): mask the HOST component only.

        Live alerts carry the browsed destination as a full URL
        (``https://mask.example.com/``) — the host is the identifier the
        flag-on estate smoke found leaking, while scheme, path and query
        are request mechanics. The host masks with the same IP-or-host
        logic as the flat ``host_name`` field on the same record, so both
        carry the same token. Path/query segments that embed identifiers
        remain a documented residual of the deferred full-URL token design.
        """
        from urllib.parse import urlsplit

        try:
            parts = urlsplit(value.strip())
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            return self.placeholder(value)
        if "@" in parts.netloc:
            # Credentials inside the URL are themselves an identifier;
            # rare enough to fail closed on the whole value.
            return self.placeholder(value)
        if not host:
            # Not a parseable URL: the free-text scan still catches
            # embedded IOCs and values masked elsewhere in this response.
            return self.mask_text(value, mapping)
        masked_host = self._mask_scalar(IP_OR_HOST, host, mapping)
        if ":" in masked_host:  # IPv6 literal: re-bracket
            masked_host = f"[{masked_host}]"
        netloc = f"{masked_host}:{port}" if port is not None else masked_host
        return parts._replace(netloc=netloc).geturl()

    def _mask_url_full(self, value: str, mapping: dict[str, str]) -> str:
        """``url``/``referralurl``: host in place, tail sealed (#40 decision).

        The host masks exactly like :meth:`_mask_url_host` (same guards,
        same token as a sibling ``host_name`` for hostname values). The
        raw remainder after ``scheme://netloc`` — taken verbatim, so ``?``
        and ``#`` appear only when actually present — seals into a single
        reversible ``url-<kid>-<ct>`` path segment. A bare ``/`` goes
        through the token path so ``…/h`` and ``…/h/`` stay distinct;
        only a truly empty remainder short-circuits. Carry-and-reverse:
        substring search inside the tail is an accepted, documented loss.
        """
        from urllib.parse import unquote, urlsplit

        stripped = value.strip()
        try:
            parts = urlsplit(stripped)
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            return self.placeholder(value)
        if "@" in parts.netloc:
            # Credentials inside the URL are themselves an identifier;
            # a reversible userinfo token would hand back a recoverable
            # secret, so the whole value fails closed (#40 decision).
            return self.placeholder(value)
        if not host:
            if not stripped or stripped in SKIP_VALUES:
                return value
            # No parseable host: the live webfilter shape (whole URL
            # percent-encoded, scheme as ``%3A%2F%2F``) and the classic
            # schemeless log shapes (``www.example.com/uri``, ``/uri``,
            # ``example.com:8080/x`` where urlsplit reads the host as the
            # scheme) all land here, and the free-text fallback leaked
            # them — the flag-on live round caught the encoded form, the
            # post-open adversarial review the schemeless ones. Seal the
            # entire value as one reversible url token; percent-encoded
            # userinfo (``%40`` before the first encoded slash boundary)
            # still fails closed per the credentials decision.
            decoded_head = unquote(stripped).partition("://")[2] or unquote(stripped)
            if "@" in decoded_head.partition("/")[0]:
                return self.placeholder(value)
            try:
                return self._engine.mask_url_tail(stripped)
            except MaskingError:
                return self.placeholder(value)
        masked_host = self._mask_scalar(IP_OR_HOST, host, mapping)
        if ":" in masked_host:  # IPv6 literal: re-bracket
            masked_host = f"[{masked_host}]"
        netloc = f"{masked_host}:{port}" if port is not None else masked_host
        prefix = f"{parts.scheme}://" if parts.scheme else "//"
        # Anchor the netloc search after the ``//`` authority marker: from
        # position 0 a single-letter host matches inside the scheme
        # ("https://h") and mis-slices the tail. urlsplit also strips
        # tab/CR/LF (bpo-43882), so the parsed netloc may not exist in the
        # raw string at all; that fails closed instead of raising.
        try:
            anchor = stripped.index("//") + 2
            tail = stripped[stripped.index(parts.netloc, anchor) + len(parts.netloc) :]
        except ValueError:
            return self.placeholder(value)
        if not tail:
            return f"{prefix}{netloc}"
        try:
            token = self._engine.mask_url_tail(tail)
        except MaskingError:
            return self.placeholder(value)
        return f"{prefix}{netloc}/{token}"

    def _mask_entry(
        self, key: str, value: Any, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> Any:
        lowered = key.lower()
        if lowered in COMPOSITE_PREFIXED and isinstance(value, str):
            return self._mask_prefixed(value, mapping)
        if lowered in COMPOSITE_PREFIXED and isinstance(value, list):
            # list-valued group-bys are a normal FAZ variation (#73): each
            # element gets the same prefixed treatment the string form gets.
            # A dict-shaped groupby stays with the allowlist walk below,
            # which types it by its inner keys.
            return [
                self._mask_prefixed(item, mapping)
                if isinstance(item, str)
                else self._mask_structured(item, mapping, keep)
                for item in value
            ]
        if lowered in COMPOSITE_JSON and isinstance(value, str):
            return self._mask_json_blob(value, mapping)
        if lowered in COMPOSITE_URL_HOST and isinstance(value, str):
            return self._mask_url_host(value, mapping)
        if lowered in COMPOSITE_URL_HOST and isinstance(value, list):
            # same list convention the typed fields handle below
            return [
                self._mask_url_host(item, mapping)
                if isinstance(item, str)
                else self._mask_structured(item, mapping, keep)
                for item in value
            ]
        if lowered in COMPOSITE_URL_FULL and isinstance(value, str):
            return self._mask_url_full(value, mapping)
        if lowered in COMPOSITE_URL_FULL and isinstance(value, list):
            # same list convention the typed fields handle below
            return [
                self._mask_url_full(item, mapping)
                if isinstance(item, str)
                else self._mask_structured(item, mapping, keep)
                for item in value
            ]
        if (lowered in COMPOSITE_URL_HOST or lowered in COMPOSITE_URL_FULL) and isinstance(
            value, dict
        ):
            # A map under a URL key has no slot the URL handlers can type,
            # and the allowlist walk knows none of its inner keys, so the
            # destination would ride through in clear (#73). Fail closed on
            # the whole shape, same policy as a non-list target below. The
            # cost is the same too: any analytic structure a producer put
            # there burns rather than round-tripping.
            return self._burn_strings(value, keep)
        if lowered in COMPOSITE_TARGET:
            if isinstance(value, list):
                return self._mask_target(value, mapping, keep)
            # Any other shape has no entries to type from. A scalar would
            # reach the generic tail and be returned verbatim; a container
            # would be walked by the allowlist, which masks the keys it
            # knows and returns everything else in clear. Fail closed on
            # the whole shape rather than depend on what the allowlist
            # happens to cover. The cost is real: a container whose keys
            # are allowlisted was masked reversibly before and now burns.
            return self._burn_strings(value, keep)
        if lowered in COMPOSITE_DEVICE_VDOM and isinstance(value, str):
            return self._mask_device_vdom(value, mapping)

        vtype = self._field_types.get(lowered)
        if vtype is not None and vtype != TEXT:
            if isinstance(value, str):
                return self._mask_scalar(vtype, value, mapping)
            if isinstance(value, list):
                # e.g. dns "ipaddr" is a list of resolved addresses
                return [
                    self._mask_scalar(vtype, item, mapping)
                    if isinstance(item, str)
                    else self._mask_structured(item, mapping, keep)
                    for item in value
                ]
        if isinstance(value, dict | list):
            return self._mask_structured(value, mapping, keep)
        return value  # TEXT values are deliberately left for pass 2

    def _mask_free_text(self, obj: Any, mapping: dict[str, str]) -> Any:
        """Pass 2: mask TEXT fields, now that the raw -> token map is known."""
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for key, value in obj.items():
                if key.lower() in COMPOSITE_FILTER_ENTRIES and isinstance(value, list):
                    out[key] = self._mask_filter_entries(value, mapping)
                elif self._field_types.get(key.lower()) == TEXT:
                    out[key] = self._mask_text_tree(value, mapping)
                else:
                    out[key] = self._mask_free_text(value, mapping)
            return out
        if isinstance(obj, list):
            return [self._mask_free_text(item, mapping) for item in obj]
        return obj

    def _mask_filter_entries(self, value: Any, mapping: dict[str, str]) -> Any:
        """``filter_applied`` as compiled ``[field, op, value]`` entries.

        A tool that compiles a structured filter echoes what it actually sent,
        which is the resolved value: argument unmasking runs at the wrapper
        boundary, so by the time the tool body builds its entries the token the
        caller passed is already the real identifier. Echoed untyped, that
        hands the raw value straight back to the model, and it is the caller's
        own token that unlocked it.

        TEXT alone cannot close it. Pass 2 substitutes values this response
        mapped and scans for IPv4/MAC/email shapes, so an entry survives in
        clear whenever the query matched nothing, which is exactly when the
        mapping is empty. A hostname, a username or an IPv6 address then rides
        back out untouched.

        The entry states its own type, so use it: mask the value by the type of
        the field named beside it, the inverse of the way arguments are
        resolved on the way in. This runs in pass 2 rather than pass 1
        deliberately: pass 2 is the only pass that touches a TEXT key, and a
        masked IPv4 is itself a valid IPv4, so masking in pass 1 and then
        letting the free-text scan walk the same entries would mask it twice.

        Anything that is not a three-part entry, or whose field carries no
        type, falls back to the ordinary free-text treatment rather than being
        guessed at.
        """
        out: list[Any] = []
        for entry in value:
            if not isinstance(entry, list | tuple) or len(entry) != 3:
                out.append(self._mask_text_tree(entry, mapping))
                continue
            field, op, raw = entry
            vtype = self._field_types.get(field.lower()) if isinstance(field, str) else None
            if vtype is None or vtype == TEXT or not isinstance(raw, str):
                out.append(self._mask_text_tree(list(entry), mapping))
                continue
            masked = self._mask_scalar(vtype, raw, mapping)
            out.append([field, op, masked] if isinstance(entry, list) else (field, op, masked))
        return out

    def _mask_text_tree(self, value: Any, mapping: dict[str, str]) -> Any:
        if isinstance(value, str):
            return self._mask_scalar_text(value, mapping)
        if isinstance(value, list):
            # Free-text lines; each string leaf gets the IOC scan. Nested dicts
            # in a list were already masked in pass 1, so recursion leaves them be.
            return [self._mask_text_tree(item, mapping) for item in value]
        # A dict under a TEXT key is a structured object already masked key-by-key
        # in pass 1; scanning it here would double-mask its tokens. Leave it.
        return value

    def _mask_scalar_text(self, value: str, mapping: dict[str, str]) -> str:
        if value.strip() in SKIP_VALUES:
            return value
        try:
            return self.mask_text(value, mapping)
        except Exception:
            logger.exception("unexpected error masking free text; placeholder used")
            return self.placeholder(value)

    # -- tool-result entry point ----------------------------------------- #

    def mask_tool_result(self, result: Any, tool_name: str) -> Any:
        try:
            return self.mask_result(result)
        except Exception:
            logger.exception("output masking failed for %s; raw result withheld", tool_name)
            return {
                "status": "error",
                "error": "masking_failed",
                "message": f"{tool_name}: output masking failed; raw result withheld (fail-closed)",
            }


#: True while a wrapped tool call is inside its masking boundary. Tools
#: call other registered tools through their module-level names (e.g.
#: ``get_top_threats`` -> ``get_fortiview_data``), and those names are the
#: WRAPPED functions, so without a guard the inner result is masked twice:
#: every token stops round-tripping (unmask yields another token) and a
#: second pass over a first-pass token can fail closed into a placeholder.
#: Found by the flag-on live round, 6 double-masked + 2 placeholder rows.
_AT_BOUNDARY: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "faz_masking_boundary", default=False
)


def install_masking(mcp: Any) -> tuple[OutputMasker, ArgUnmasker]:
    """Patch ``mcp.tool`` so every tool registered afterwards is masked.

    Wrapped tools unmask their keyword arguments on the way in (Phase 2,
    before the tool body reaches any validator) and mask their result on
    the way out (Phase 1). Argument restoration is gated on the tool's
    ``readOnlyHint`` annotation (#106): a mutating tool never restores,
    and a whole-value marked token in its arguments is refused, because
    an unauthenticated FF3 token would decrypt to a plausible wrong value
    and be written to the estate. The boundary is the OUTERMOST wrapped call
    only: a wrapped tool invoked from inside another wrapped tool runs
    bare, because the outer boundary already unmasked the arguments and
    masks the combined result exactly once.

    Must run BEFORE the tool modules are imported (they register at import
    time). Raises MaskingError at startup if ``FAZ_MASKING_KEY`` is absent
    or invalid: a deployment that asked for masking must not run without it.
    """
    from fortianalyzer_mcp.utils.config import get_settings

    settings = get_settings()
    # The engine and the placeholder key both read FAZ_MASKING_KEY from the
    # process environment. Settings additionally resolves it from .env (like
    # MASKING_ENABLED), so bridge that value into the environment here when it
    # is set there but not already exported — otherwise a deployment that put
    # both the flag and the key in .env would enable masking, fail to find the
    # key, and crash fail-closed. A real environment variable still wins.
    if settings.FAZ_MASKING_KEY and not os.environ.get(MASKING_KEY_ENV):
        os.environ[MASKING_KEY_ENV] = settings.FAZ_MASKING_KEY

    engine = FPEEngine.from_env()
    masker = OutputMasker(engine, mask_device_identity=settings.FAZ_MASK_DEVICE_IDENTITY)
    unmasker = ArgUnmasker(engine)
    original_tool = mcp.tool

    def marked_arg_key(value: Any, key: str = "") -> str | None:
        """Key under which a whole-value marked token sits, or None.

        Only whole-value tokens count: a token embedded in a longer string
        has nothing that would restore it, so it passes through as token
        text and cannot become a decrypted write. A marker that matches
        but does not decrypt is the forged/stale case, which is exactly
        the threat, so it refuses rather than passing.
        """
        if isinstance(value, str):
            try:
                return key if engine.unmask_token(value) is not None else None
            except MaskingError:
                return key
        if isinstance(value, dict):
            for inner_key, inner in value.items():
                found = marked_arg_key(inner, str(inner_key))
                if found is not None:
                    return found
            return None
        if isinstance(value, list | tuple):
            for inner in value:
                found = marked_arg_key(inner, key)
                if found is not None:
                    return found
        return None

    def refuse_restore(tool_name: str, arg_key: str) -> dict[str, Any]:
        # #106: FF3 tokens carry no integrity tag, so a stale or forged
        # token decrypts to some plausible value; restored into a write
        # surface that value is silently written to the estate. The
        # message names the argument, never the token.
        return {
            "status": "error",
            "error": "masked_token_in_mutating_args",
            "message": (
                f"{tool_name}: argument '{arg_key}' carries a masking token. "
                "This tool changes FortiAnalyzer state, so tokens are not "
                "restored here: a stale or forged token would decrypt to a "
                "plausible wrong value and be written. Re-run with the real "
                "value, obtained from a read-only tool or an operator."
            ),
        }

    def patched_tool(*args: Any, **kwargs: Any) -> Any:
        decorator = original_tool(*args, **kwargs)
        # #106: only tools that annotate themselves read-only get argument
        # restoration. Everything else, including an unannotated tool and
        # the dynamic dispatcher (whose annotation is deliberately the
        # union of everything it can reach), fails closed: no restore, and
        # a whole-value marked token is refused outright. Unmarked IP/MAC
        # tokens are indistinguishable from real addresses and pass
        # through; making them detectable is the #40 v2 envelope work.
        annotations = kwargs.get("annotations")
        read_only = bool(annotations is not None and getattr(annotations, "readOnlyHint", False))

        def register(fn: Any) -> Any:
            if inspect.iscoroutinefunction(fn):

                @wraps(fn)
                async def async_wrapped(*fa: Any, **fk: Any) -> Any:
                    if _AT_BOUNDARY.get():
                        return await fn(*fa, **fk)
                    token = _AT_BOUNDARY.set(True)
                    try:
                        if not read_only:
                            offending = marked_arg_key(fk)
                            if offending is not None:
                                return refuse_restore(fn.__name__, offending)
                            return masker.mask_tool_result(await fn(*fa, **fk), fn.__name__)
                        return masker.mask_tool_result(
                            await fn(*fa, **unmasker.unmask_args(fk)), fn.__name__
                        )
                    finally:
                        _AT_BOUNDARY.reset(token)

                return decorator(async_wrapped)

            @wraps(fn)
            def sync_wrapped(*fa: Any, **fk: Any) -> Any:
                if _AT_BOUNDARY.get():
                    return fn(*fa, **fk)
                token = _AT_BOUNDARY.set(True)
                try:
                    if not read_only:
                        offending = marked_arg_key(fk)
                        if offending is not None:
                            return refuse_restore(fn.__name__, offending)
                        return masker.mask_tool_result(fn(*fa, **fk), fn.__name__)
                    return masker.mask_tool_result(fn(*fa, **unmasker.unmask_args(fk)), fn.__name__)
                finally:
                    _AT_BOUNDARY.reset(token)

            return decorator(sync_wrapped)

        return register

    mcp.tool = patched_tool
    logger.info("masking installed: tools registered from now on unmask args and mask output")
    return masker, unmasker
