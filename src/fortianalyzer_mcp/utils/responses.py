"""Shared response helpers for FortiAnalyzer MCP tools.

Provides a single structured error envelope, a deterministic warnings builder, and
a free-text redactor that keeps secrets out of error messages and logs. These are
reused across the log and traffic tools so every error path looks the same.
"""

import math
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
# Matches bare (adm_pass=x, adm_pass: x) and quoted-key JSON/dict forms
# ("adm_pass": "x", 'adm_pass': 'x') — the optional closing quote after the key
# is what lets the separator match on JSON-style payloads.
_KV_PATTERN = re.compile(
    r"(?i)\b("
    + "|".join(re.escape(k) for k in _REDACT_KEYS)
    + r")\b[\"']?\s*[=:]\s*[\"']?([^\s\"'&,;]+)"
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


def coerce_num(value: Any) -> float | None:
    """Coerce a FAZ count/progress field to a finite number for readiness checks.

    Accepts ``int``/``float`` and numeric strings (``"100"``, ``"100.0"``);
    rejects ``bool``, non-numeric, and non-finite (``inf``/``nan``) values.
    Returns ``None`` when the field is absent or unusable. Used only for
    readiness, never for the reported total.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        num = float(value)
    elif isinstance(value, str):
        try:
            num = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return num if math.isfinite(num) else None


def limit_clamped_warning(requested_limit: int, limit: int) -> str | None:
    """The clamp advisory, or ``None`` when the caller's limit was honoured.

    Its own function because :func:`build_warnings` is a rows-path builder and
    the aggregation paths need this one message without the rest of it: a
    ``group_by`` or ``count_only`` response has no ``has_more`` to reason about
    and must never be told to aggregate instead of paging rows, yet it is bound
    by exactly the same clamp. Emitting it from one place is what keeps a caller
    who passed ``limit=5000`` from being told "1000" by three response shapes
    and nothing by the fourth.

    The parenthetical names the logsearch fetch endpoint's own maximum, which is
    where the number comes from; the server then applies that one bound on every
    path, including the FortiView dispatch behind ``group_by``.
    """
    if requested_limit == limit:
        return None
    return (
        f"Requested limit {requested_limit} was clamped to {limit} "
        "(FortiAnalyzer allows 1-1000 rows per fetch)."
    )


def unknown_timezone_warning(timezone: str) -> str | None:
    """The undetected-timezone advisory, or ``None`` when it was detected.

    Shared for the same reason as :func:`limit_clamped_warning`: FAZ interprets
    a naive window in its own timezone, so this caveat applies to whatever the
    window produced -- rows, an exact grouping, a bounded breakdown or a bare
    count -- and it was previously reported on the rows path alone.
    """
    if timezone != "unknown":
        return None
    return (
        "FortiAnalyzer timezone could not be detected; timestamps are interpreted "
        "as naive FortiAnalyzer-local time."
    )


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
    result set is large enough that aggregation tools are a better fit. The first
    and third are shared with the aggregation paths through
    :func:`limit_clamped_warning` and :func:`unknown_timezone_warning`; the order
    here is unchanged.
    """
    warnings: list[str] = []
    clamped = limit_clamped_warning(requested_limit, limit)
    if clamped is not None:
        warnings.append(clamped)
    if total is None:
        warnings.append(
            "Total match count is unavailable from FortiAnalyzer for this search; "
            "has_more is best-effort."
        )
    unknown_tz = unknown_timezone_warning(timezone)
    if unknown_tz is not None:
        warnings.append(unknown_tz)
    if (
        has_more
        and total_is_known
        and total is not None
        and total >= max(10 * limit, _HIGH_VOLUME_FLOOR)
    ):
        # Names the tool call explicitly rather than "this query's own
        # group_by/sample_by": fetch_more_logs emits this same warning and has
        # neither parameter, so the shorthand pointed its readers at nothing.
        warnings.append(
            f"Large result set ({total} matches); only this page is returned. Aggregate "
            "instead of paging rows: query_logs(group_by=...) or "
            "query_logs(sample_by=[...]), or analyze_policy_traffic for a per-policy "
            "volume question. Otherwise narrow the time window."
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
