"""Tool-boundary output masking (RFC #40 Phase 1 prototype).

Masks every tool result before it leaves the MCP toward the LLM. There is
no central tool-registration function to hook (tool modules self-register
with module-level ``@mcp.tool()`` at import time), so ``install_masking``
patches ``mcp.tool`` on the shared FastMCP instance BEFORE the tool
modules are imported; every subsequently registered tool is wrapped.

Fail-closed by construction:

- A value that cannot be masked (outside the FPE alphabet, malformed) is
  replaced with an irreversible keyed placeholder — never passed through
  raw, never logged.
- If masking a whole result fails unexpectedly, the tool returns a
  ``masking_failed`` error envelope — the raw result is withheld.

Free-text fields (``msg``, ``logdesc``, echoed ``filter`` strings, ...)
get an in-place IOC scan: embedded IPv4s, MACs and emails are replaced
with their deterministic tokens. Because FPE is deterministic, a re-masked
echo of an unmasked argument yields exactly the token the caller sent, so
follow-up turns stay consistent.

Scope (deliberately Phase 1 only): tool OUTPUT masking. Unmasking of
tool-call arguments (Phase 2) and URL/IPv6-in-text handling are not here.
"""

import hashlib
import hmac
import inspect
import ipaddress
import logging
import os
import re
from functools import wraps
from typing import Any

from fortianalyzer_mcp.masking.fields import (
    DOMAIN,
    EMAIL,
    FIELD_TYPES,
    HOSTNAME,
    IP,
    MAC,
    SKIP_VALUES,
    TEXT,
    USERNAME,
)
from fortianalyzer_mcp.masking.fpe_engine import MASKING_KEY_ENV, FPEEngine, MaskingError

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


class OutputMasker:
    """Recursive result masker bound to one FPE engine."""

    def __init__(self, engine: FPEEngine) -> None:
        self._engine = engine
        # Keyed so placeholders are deterministic (correlatable) but not
        # brute-forceable from a leaked transcript. The env var is present
        # because the engine was just built from it.
        self._placeholder_key = os.environ.get(MASKING_KEY_ENV, "").encode()

    # -- fail-closed primitives ---------------------------------------- #

    def placeholder(self, value: str) -> str:
        """Irreversible, deterministic stand-in for an unmaskable value."""
        digest = hmac.new(self._placeholder_key, value.encode(), hashlib.sha256).hexdigest()[:10]
        return f"masked-unrepresentable-{digest}"

    def _mask_scalar(self, vtype: str, value: str) -> str:
        if value.strip() in SKIP_VALUES:
            return value
        if vtype != TEXT and "," in value:
            # FAZ packs multi-valued fields into one comma-joined string
            # (live example: the dns ``ipaddr`` answer list). Mask each
            # element; an unmaskable element still fails closed on its own.
            return ",".join(
                part if part.strip() in SKIP_VALUES or not part else self._mask_scalar(vtype, part)
                for part in value.split(",")
            )
        try:
            if vtype == IP:
                return self._engine.mask_ip(value)
            if vtype == MAC:
                return self._engine.mask_mac(value)
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
            if vtype == TEXT:
                return self.mask_text(value)
        except MaskingError:
            return self.placeholder(value)
        except Exception:
            # Never let a masking bug leak the raw value. The value itself
            # is deliberately not logged.
            logger.exception("unexpected error masking a %s value; placeholder used", vtype)
            return self.placeholder(value)
        return self.placeholder(value)  # unknown type tag: fail closed

    # -- free-text IOC scan --------------------------------------------- #

    def mask_text(self, text: str) -> str:
        """Replace embedded IPv4/MAC/email IOCs inside free text."""

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
        return _EMAIL_RE.sub(email_sub, out)

    # -- recursive structure walk ---------------------------------------- #

    def mask_result(self, obj: Any) -> Any:
        """Mask a tool result in depth: allowlisted keys at any nesting."""
        if isinstance(obj, dict):
            return {key: self._mask_entry(key, value) for key, value in obj.items()}
        if isinstance(obj, list):
            return [self.mask_result(item) for item in obj]
        return obj

    def _mask_entry(self, key: str, value: Any) -> Any:
        vtype = FIELD_TYPES.get(key)
        if vtype is not None:
            if isinstance(value, str):
                return self._mask_scalar(vtype, value)
            if isinstance(value, list):
                # e.g. dns "ipaddr" is a list of resolved addresses
                return [
                    self._mask_scalar(vtype, item)
                    if isinstance(item, str)
                    else self.mask_result(item)
                    for item in value
                ]
        if isinstance(value, dict | list):
            return self.mask_result(value)
        return value

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


def install_masking(mcp: Any) -> OutputMasker:
    """Patch ``mcp.tool`` so every tool registered afterwards masks its output.

    Must run BEFORE the tool modules are imported (they register at import
    time). Raises MaskingError at startup if ``FAZ_MASKING_KEY`` is absent
    or invalid — a deployment that asked for masking must not run without it.
    """
    engine = FPEEngine.from_env()
    masker = OutputMasker(engine)
    original_tool = mcp.tool

    def patched_tool(*args: Any, **kwargs: Any) -> Any:
        decorator = original_tool(*args, **kwargs)

        def register(fn: Any) -> Any:
            if inspect.iscoroutinefunction(fn):

                @wraps(fn)
                async def async_wrapped(*fa: Any, **fk: Any) -> Any:
                    return masker.mask_tool_result(await fn(*fa, **fk), fn.__name__)

                return decorator(async_wrapped)

            @wraps(fn)
            def sync_wrapped(*fa: Any, **fk: Any) -> Any:
                return masker.mask_tool_result(fn(*fa, **fk), fn.__name__)

            return decorator(sync_wrapped)

        return register

    mcp.tool = patched_tool
    logger.info("output masking installed: all tools registered from now on are wrapped")
    return masker
