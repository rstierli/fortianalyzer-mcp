"""Shared response helpers for FortiAnalyzer MCP tools.

Provides a single structured error envelope, a deterministic warnings builder, and
a free-text redactor that keeps secrets out of error messages and logs. These are
reused across the log and traffic tools so every error path looks the same.
"""

import re
from typing import Any

from fortianalyzer_mcp.utils.validation import MASK_VALUE, SENSITIVE_FIELDS

# Max length of a (redacted) human error message echoed back to the caller.
_MAX_MESSAGE_LEN = 500

# High-volume floor for the aggregation warning (see build_warnings).
_HIGH_VOLUME_FLOOR = 10_000

# Secret-ish keys to scrub from free text as `key=value` / `key: value`. Drawn
# from SENSITIVE_FIELDS but excluding the most generic words ("key", "auth",
# "pass") so ordinary text is not mangled; the long-token rule below still masks
# real session ids/tokens.
_REDACT_KEYS = sorted(SENSITIVE_FIELDS - {"key", "auth", "pass"}, key=len, reverse=True)
_KV_PATTERN = re.compile(
    r"(?i)\b(" + "|".join(re.escape(k) for k in _REDACT_KEYS) + r")\b\s*[=:]\s*\"?([^\s\"&,;]+)\"?"
)
# Opaque token-like run (mirrors sanitize_for_logging's hex>20 heuristic).
_HEX_TOKEN_PATTERN = re.compile(r"\b[a-fA-F0-9]{20,}\b")


def redact(text: str) -> str:
    """Mask secrets in free text before logging or returning it.

    Scrubs ``key=value`` / ``key: value`` pairs whose key looks sensitive and long
    hexadecimal token-like runs. A normal log filter expression is left intact.
    """
    if not text:
        return text
    redacted = _KV_PATTERN.sub(lambda m: f"{m.group(1)}={MASK_VALUE}", text)
    redacted = _HEX_TOKEN_PATTERN.sub(MASK_VALUE, redacted)
    return redacted


def build_warnings(
    *,
    requested_limit: int,
    limit: int,
    total: int | None,
    total_is_known: bool,
    timezone: str,
    has_more: bool,
) -> list[str]:
    """Build the deterministic ``warnings`` list for a log query response.

    Emits one message for each of exactly four conditions: the requested limit was
    clamped; the total is unknown; the FortiAnalyzer timezone is unknown; or the
    result set is large enough that aggregation tools are a better fit.
    """
    warnings: list[str] = []
    if requested_limit != limit:
        warnings.append(
            f"Requested limit {requested_limit} was clamped to {limit} "
            "(FortiAnalyzer allows 1-1000 rows per fetch)."
        )
    if total is None:
        warnings.append(
            "Total match count is unavailable from FortiAnalyzer for this search; "
            "has_more is best-effort."
        )
    if timezone == "unknown":
        warnings.append(
            "FortiAnalyzer timezone could not be detected; timestamps are interpreted "
            "as naive FortiAnalyzer-local time."
        )
    if (
        has_more
        and total_is_known
        and total is not None
        and total >= max(10 * limit, _HIGH_VOLUME_FLOOR)
    ):
        warnings.append(
            f"Large result set ({total} matches); only this page is returned. Use "
            "get_policy_port_analysis or get_policy_protocol_summary for aggregation, "
            "or narrow the time window."
        )
    return warnings


def error_response(
    *,
    error: str,
    message: object,
    operation: str,
    adom: str | None = None,
    logtype: str | None = None,
    tid: int | None = None,
    retry_count: int = 0,
    **extra: Any,
) -> dict[str, Any]:
    """Build one structured error envelope used by every tool error path.

    ``error`` is a stable machine code; ``message`` is redacted and length-bounded
    human text. ``adom``/``logtype``/``tid`` are included only when provided, and any
    additional context (e.g. ``time_range``, ``timezone``, ``recommendation``) can be
    passed via keyword and is merged verbatim.
    """
    msg = redact(str(message))
    if len(msg) > _MAX_MESSAGE_LEN:
        msg = msg[:_MAX_MESSAGE_LEN] + "... (truncated)"
    resp: dict[str, Any] = {
        "status": "error",
        "error": error,
        "message": msg,
        "operation": operation,
        "retry_count": retry_count,
    }
    if adom is not None:
        resp["adom"] = adom
    if logtype is not None:
        resp["logtype"] = logtype
    if tid is not None:
        resp["tid"] = tid
    resp.update(extra)
    return resp
