"""Tests for LogView clock detection and time-window resolution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from fortianalyzer_mcp.utils.log_clock import (
    detect_logview_anchor,
    resolve_time_window,
)

_UTC = ZoneInfo("UTC")


def _recent_epoch(seconds_ago: int = 300) -> int:
    return int(datetime.now(UTC).timestamp()) - seconds_ago


class FakeClock:
    """Configurable fake exposing only the clock-probe surface."""

    def __init__(
        self,
        *,
        tz: ZoneInfo | None = _UTC,
        logfiles_state: object = None,
        logstats: object = None,
        logfiles_state_error: Exception | None = None,
        logstats_error: Exception | None = None,
    ) -> None:
        self.tz = tz
        self._logfiles_state = logfiles_state
        self._logstats = logstats
        self._logfiles_state_error = logfiles_state_error
        self._logstats_error = logstats_error

    async def get_system_timezone(self) -> ZoneInfo | None:
        return self.tz

    async def get_logfiles_state(self, **_kw: object) -> object:
        if self._logfiles_state_error is not None:
            raise self._logfiles_state_error
        return self._logfiles_state

    async def get_logstats(self, **_kw: object) -> object:
        if self._logstats_error is not None:
            raise self._logstats_error
        return self._logstats


class TestDetectLogviewAnchor:
    async def test_prefers_logfiles_state(self) -> None:
        epoch = _recent_epoch(300)
        fake = FakeClock(
            logfiles_state={"data": [{"etime": epoch}]},
            logstats={"data": [{"last_log_time": _recent_epoch(60)}]},
        )
        result = await detect_logview_anchor(fake, "root")
        assert result.source == "logfiles_state"
        expected = datetime.fromtimestamp(epoch, UTC).replace(tzinfo=None)
        assert result.anchor == expected
        assert result.timezone == "UTC"
        assert result.clock_skew_seconds is not None

    async def test_falls_back_to_logstats(self) -> None:
        epoch = _recent_epoch(120)
        fake = FakeClock(
            logfiles_state={"data": []},  # nothing parseable
            logstats={"data": [{"last_log_time": epoch}]},
        )
        result = await detect_logview_anchor(fake, "root")
        assert result.source == "logstats"
        assert result.anchor == datetime.fromtimestamp(epoch, UTC).replace(tzinfo=None)

    async def test_falls_back_to_faz_tz_when_probes_fail(self) -> None:
        fake = FakeClock(
            logfiles_state_error=RuntimeError("boom"),
            logstats_error=AttributeError("missing"),
        )
        result = await detect_logview_anchor(fake, "root")
        assert result.source == "faz_tz"
        assert result.clock_skew_seconds == 0

    async def test_falls_back_to_naive_when_no_tz(self) -> None:
        fake = FakeClock(tz=None, logfiles_state={"data": []}, logstats={"data": []})
        result = await detect_logview_anchor(fake, "root")
        assert result.source == "naive"
        assert result.timezone == "unknown"
        assert result.clock_skew_seconds is None

    async def test_implausible_future_anchor_is_skipped(self) -> None:
        future = int((datetime.now(UTC) + timedelta(days=30)).timestamp())
        recent = _recent_epoch(120)
        fake = FakeClock(
            logfiles_state={"data": [{"etime": future}]},  # absurd, must be skipped
            logstats={"data": [{"last_log_time": recent}]},
        )
        result = await detect_logview_anchor(fake, "root")
        assert result.source == "logstats"

    async def test_picks_latest_among_devices(self) -> None:
        older = _recent_epoch(600)
        newer = _recent_epoch(60)
        fake = FakeClock(
            logfiles_state={"data": [{"etime": older}, {"etime": newer}]},
        )
        result = await detect_logview_anchor(fake, "root")
        assert result.anchor == datetime.fromtimestamp(newer, UTC).replace(tzinfo=None)


class TestResolveTimeWindow:
    async def test_custom_range_reports_faz_tz_when_requested(self) -> None:
        fake = FakeClock(tz=ZoneInfo("Europe/Zurich"))
        win = await resolve_time_window(
            fake, "root", "2024-01-01 00:00:00|2024-01-02 00:00:00", faz_tz_for_custom=True
        )
        assert win.time_range == {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}
        assert win.timezone == "Europe/Zurich"
        assert win.time_basis_source == "custom"
        assert win.clock_skew_seconds is None

    async def test_custom_range_unknown_tz_when_not_requested(self) -> None:
        fake = FakeClock(tz=ZoneInfo("Europe/Zurich"))
        win = await resolve_time_window(
            fake, "root", "2024-01-01 00:00:00|2024-01-02 00:00:00", faz_tz_for_custom=False
        )
        assert win.timezone == "unknown"
        assert win.time_basis_source == "custom"

    async def test_relative_range_anchored_on_logview_clock(self) -> None:
        epoch = _recent_epoch(300)
        fake = FakeClock(logfiles_state={"data": [{"etime": epoch}]})
        win = await resolve_time_window(fake, "root", "1-hour")
        anchor = datetime.fromtimestamp(epoch, UTC).replace(tzinfo=None)
        assert win.time_range["end"] == anchor.strftime("%Y-%m-%d %H:%M:%S")
        assert win.time_basis_source == "logfiles_state"

    async def test_invalid_preset_raises(self) -> None:
        fake = FakeClock()
        with pytest.raises(ValueError, match="Unknown time_range"):
            await resolve_time_window(fake, "root", "3-hour")
