"""Tool-boundary output masking (RFC #40 Phase 1 prototype).

Masks every tool result before it leaves the MCP toward the LLM. There is
no central tool-registration function to hook (tool modules self-register
with module-level ``@mcp.tool()`` at import time), so ``install_masking``
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
``unmask.py`` and is applied by the same registration patch. URL masking
and IPv6-in-text scanning are not yet handled. Device identity
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
    COMPOSITE_JSON,
    COMPOSITE_PREFIXED,
    COMPOSITE_TARGET,
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
        """
        out: list[Any] = []
        for item in value:
            if not isinstance(item, dict):
                out.append(self._mask_structured(item, mapping, keep))
                continue
            entry = dict(item)
            vtype = TARGET_NAME_TYPES.get(str(entry.get("name", "")).lower())
            raw = entry.get("value")
            if vtype and isinstance(raw, str) and raw not in keep:
                token = self._mask_scalar(vtype, raw, mapping)
                entry["value"] = token
                # asset_value repeats the identifier on some targets and
                # carries an internal numeric id on others; mask only the
                # former.
                if entry.get("asset_value") == raw:
                    entry["asset_value"] = token
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
        """
        if not mapping:
            return text
        for raw in sorted(mapping, key=len, reverse=True):
            if len(raw) < _MIN_SUBSTITUTION_LEN:
                continue
            token = mapping[raw]
            for variant in dict.fromkeys((raw, raw.lower())):
                pattern = re.compile(
                    r"(?<![A-Za-z0-9._-])" + re.escape(variant) + r"(?![A-Za-z0-9._-])"
                )
                text = pattern.sub(token, text)
        return text

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
        """
        out: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in DEVICE_IDENTITY_TYPES and isinstance(value, str):
                        out.update(part.strip() for part in value.split(","))
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
        value = obj.get("incident_reporter")
        if not isinstance(value, str) or not value.strip() or value.strip() in SKIP_VALUES:
            return {}
        if value not in (obj.get("reporter"), obj.get("lastuser")):
            return {}
        return {"incident_reporter": self._mask_scalar(USERNAME, value, mapping)}

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
        obf = obj.get(OBF_URL_KEY)
        if not isinstance(obf, str) or not obf.strip() or obf.strip() in SKIP_VALUES:
            return {}
        out: dict[str, str] = {}
        token = self._mask_scalar(DOMAIN, obf.replace("[dot]", "."), mapping)
        escaped = token.replace(".", "[dot]")
        if _PLACEHOLDER_MARK not in token and escaped != obf:
            # Catch the escaped raw form in prose too; the unescaped form
            # is already in the mapping via _mask_scalar.
            mapping[obf] = escaped
        out[OBF_URL_KEY] = escaped
        threat = obj.get(THREAT_KEY)
        if isinstance(threat, str) and threat.strip() and threat.strip() not in SKIP_VALUES:
            out[THREAT_KEY] = self._mask_scalar(DOMAIN, threat, mapping)
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

    def _mask_entry(
        self, key: str, value: Any, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> Any:
        lowered = key.lower()
        if lowered in COMPOSITE_PREFIXED and isinstance(value, str):
            return self._mask_prefixed(value, mapping)
        if lowered in COMPOSITE_JSON and isinstance(value, str):
            return self._mask_json_blob(value, mapping)
        if lowered in COMPOSITE_URL_HOST and isinstance(value, str):
            return self._mask_url_host(value, mapping)
        if lowered in COMPOSITE_TARGET and isinstance(value, list):
            return self._mask_target(value, mapping, keep)
        if lowered in COMPOSITE_DEVICE_VDOM and isinstance(value, str):
            return self._mask_device_vdom(value, mapping)

        vtype = self._field_types.get(key)
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
                if self._field_types.get(key) == TEXT and isinstance(value, str):
                    out[key] = self._mask_scalar_text(value, mapping)
                else:
                    out[key] = self._mask_free_text(value, mapping)
            return out
        if isinstance(obj, list):
            return [self._mask_free_text(item, mapping) for item in obj]
        return obj

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
    the way out (Phase 1). The boundary is the OUTERMOST wrapped call
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

    def patched_tool(*args: Any, **kwargs: Any) -> Any:
        decorator = original_tool(*args, **kwargs)

        def register(fn: Any) -> Any:
            if inspect.iscoroutinefunction(fn):

                @wraps(fn)
                async def async_wrapped(*fa: Any, **fk: Any) -> Any:
                    if _AT_BOUNDARY.get():
                        return await fn(*fa, **fk)
                    token = _AT_BOUNDARY.set(True)
                    try:
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
                    return masker.mask_tool_result(fn(*fa, **unmasker.unmask_args(fk)), fn.__name__)
                finally:
                    _AT_BOUNDARY.reset(token)

            return decorator(sync_wrapped)

        return register

    mcp.tool = patched_tool
    logger.info("masking installed: tools registered from now on unmask args and mask output")
    return masker, unmasker
