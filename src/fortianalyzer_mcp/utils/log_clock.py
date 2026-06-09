"""LogView clock detection for relative time-range alignment.

FortiAnalyzer interprets the naive ``time-range`` timestamps a logview search
sends against its own LogView ingest clock. That clock can drift from the FAZ
*system* timezone "now" — notably after a version upgrade — so a relative window
like ``"1-hour"`` anchored on system-now can land *ahead* of the newest ingested
log and silently return zero rows even though traffic exists.

This module anchors relative windows on the appliance's latest log time instead,
with documented, safe fallbacks:

1. ``logfiles_state`` — newest log end time reported for the log files.
2. ``logstats``       — newest per-device ``last_log_time``.
3. ``faz_tz``         — FAZ system timezone "now" (the previous behavior).
4. ``naive``          — local ``datetime.now()`` when even the FAZ TZ is unknown.

Detection is strictly best-effort: any error or unparseable response degrades to
the next fallback, so a clock probe can never break a query. Custom absolute
ranges skip detection entirely (the caller already supplied explicit bounds).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from fortianalyzer_mcp.utils.time_range import parse_time_range
from fortianalyzer_mcp.utils.validation import build_device_filter

logger = logging.getLogger(__name__)

_TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"

# Keys whose values may carry a log end/last time in a logview response. Matched
# case-insensitively after stripping ``-``/``_`` so e.g. ``last-log-time``,
# ``last_log_time`` and ``lastLogTime`` all match. Kept focused to avoid latching
# onto unrelated timestamps (e.g. a search start time).
_ANCHOR_TIME_KEYS = frozenset(
    {"lastlogtime", "etime", "endtime", "end", "ftime", "maxtime", "latesttime"}
)

# Plausibility guard for a detected anchor relative to FAZ "now": reject values
# that are absurdly stale or in the future (a wrong field or a ms-vs-s unit
# mismatch), falling back rather than trusting a bogus clock.
_MAX_ANCHOR_FUTURE = timedelta(days=2)
_MAX_ANCHOR_PAST = timedelta(days=400)


@dataclass(frozen=True)
class AnchorResult:
    """Outcome of LogView clock detection.

    ``anchor`` is always set (it falls back to FAZ-now / local-now) so callers
    can pass it straight to :func:`parse_time_range`.
    """

    anchor: datetime  # naive, FAZ-local "now" to end relative windows on
    source: str  # logfiles_state | logstats | faz_tz | naive
    timezone: str  # FAZ system tz name, or "unknown"
    clock_skew_seconds: int | None  # anchor - faz_now, when measurable


@dataclass(frozen=True)
class TimeWindow:
    """A resolved query window plus the time-basis audit metadata."""

    time_range: dict[str, str]
    timezone: str
    time_basis_source: str
    clock_skew_seconds: int | None


def _device_to_devid(device: str | None) -> str | None:
    """Return a serial-style devid for logfiles_state, or None for broad scope."""
    if not device:
        return None
    if device.startswith("All_"):
        return None
    filt = build_device_filter(device)
    return filt[0].get("devid")


def _coerce_anchor_dt(value: Any, faz_tz: ZoneInfo | None) -> datetime | None:
    """Coerce one field value to a naive FAZ-local datetime, or None.

    Accepts epoch seconds (int or digit string, converted through ``faz_tz``) and
    naive ``"YYYY-MM-DD HH:MM:SS"`` strings (already FAZ-local). Anything else,
    or a non-positive epoch, yields ``None``.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit()):
        epoch = int(value)
        if epoch <= 0:
            return None
        try:
            aware = datetime.fromtimestamp(epoch, UTC)
        except (OverflowError, OSError, ValueError):
            return None
        if faz_tz is not None:
            aware = aware.astimezone(faz_tz)
        return aware.replace(tzinfo=None)
    if isinstance(value, str):
        try:
            return datetime.strptime(value.strip(), _TIMESTAMP_FMT)
        except ValueError:
            return None
    return None


def _extract_latest_anchor(obj: Any, faz_tz: ZoneInfo | None) -> datetime | None:
    """Walk a logview response and return the newest anchorable timestamp."""
    best: datetime | None = None
    stack: list[Any] = [obj]
    seen = 0
    while stack and seen < 10000:
        seen += 1
        cur = stack.pop()
        if isinstance(cur, dict):
            for key, val in cur.items():
                if isinstance(val, dict | list):
                    stack.append(val)
                    continue
                normalized = str(key).replace("-", "").replace("_", "").lower()
                if normalized in _ANCHOR_TIME_KEYS:
                    candidate = _coerce_anchor_dt(val, faz_tz)
                    if candidate is not None and (best is None or candidate > best):
                        best = candidate
        elif isinstance(cur, list):
            stack.extend(cur)
    return best


def _is_plausible(anchor: datetime, faz_now: datetime) -> bool:
    """Reject anchors that are implausibly stale or in the future."""
    return (faz_now - _MAX_ANCHOR_PAST) <= anchor <= (faz_now + _MAX_ANCHOR_FUTURE)


async def detect_logview_anchor(
    client: Any,
    adom: str,
    device: str | None = None,
) -> AnchorResult:
    """Detect the LogView ingest clock to anchor relative windows on.

    Best-effort: each probe is wrapped so a missing method, network error, or
    unparseable shape degrades to the next fallback. Always returns a usable
    anchor (FAZ-now, or local-now if even the FAZ timezone is unknown).
    """
    faz_tz: ZoneInfo | None = None
    try:
        faz_tz = await client.get_system_timezone()
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"FAZ timezone lookup failed during clock detection: {exc}")
    tz_name = str(faz_tz) if faz_tz else "unknown"

    if faz_tz is not None:
        faz_now = datetime.now(UTC).astimezone(faz_tz).replace(tzinfo=None)
    else:
        faz_now = datetime.now()

    probes: tuple[tuple[str, Any], ...] = (
        (
            "logfiles_state",
            lambda: client.get_logfiles_state(adom=adom, devid=_device_to_devid(device)),
        ),
        (
            "logstats",
            lambda: client.get_logstats(adom=adom, device=build_device_filter(device)),
        ),
    )
    for source, call in probes:
        try:
            resp = await call()
        except Exception as exc:
            logger.debug(f"Clock probe {source} unavailable: {exc}")
            continue
        anchor = _extract_latest_anchor(resp, faz_tz)
        if anchor is None:
            continue
        if not _is_plausible(anchor, faz_now):
            logger.debug(f"Clock probe {source} anchor {anchor} implausible; skipping")
            continue
        skew = int((anchor - faz_now).total_seconds())
        logger.info(f"LogView clock anchored via {source}: {anchor} (skew {skew}s)")
        return AnchorResult(anchor=anchor, source=source, timezone=tz_name, clock_skew_seconds=skew)

    if faz_tz is not None:
        return AnchorResult(anchor=faz_now, source="faz_tz", timezone=tz_name, clock_skew_seconds=0)
    return AnchorResult(anchor=faz_now, source="naive", timezone=tz_name, clock_skew_seconds=None)


async def resolve_time_window(
    client: Any,
    adom: str,
    time_range: str,
    device: str | None = None,
    *,
    faz_tz_for_custom: bool = True,
) -> TimeWindow:
    """Resolve a caller time-range string into a window plus time-basis metadata.

    Relative presets are anchored on the detected LogView clock. Custom absolute
    ranges (``"start|end"``) are passed through verbatim; their reported timezone
    is the FAZ system tz when ``faz_tz_for_custom`` (query_logs convention) or
    ``"unknown"`` otherwise (policy-analysis convention).

    Raises:
        ValueError: If ``time_range`` is neither a known preset nor a valid
            custom range (propagated from :func:`parse_time_range`).
    """
    if "|" in time_range:
        window = parse_time_range(time_range)
        tz_name = "unknown"
        if faz_tz_for_custom:
            try:
                faz_tz = await client.get_system_timezone()
            except Exception:  # pragma: no cover - defensive
                faz_tz = None
            tz_name = str(faz_tz) if faz_tz else "unknown"
        return TimeWindow(
            time_range=window,
            timezone=tz_name,
            time_basis_source="custom",
            clock_skew_seconds=None,
        )

    anchor = await detect_logview_anchor(client, adom, device)
    window = parse_time_range(time_range, anchor=anchor.anchor)
    return TimeWindow(
        time_range=window,
        timezone=anchor.timezone,
        time_basis_source=anchor.source,
        clock_skew_seconds=anchor.clock_skew_seconds,
    )
