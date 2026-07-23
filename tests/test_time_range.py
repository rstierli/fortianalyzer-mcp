"""Tests for the shared time-range parser."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from fortianalyzer_mcp.utils.time_range import (
    SUPPORTED_TIME_RANGES,
    parse_time_range,
    parse_time_range_bounds,
)


class TestParseTimeRangePresets:
    """Preset string handling: known keys, unknown keys, all supported values."""

    def test_one_hour_returns_one_hour_window(self) -> None:
        result = parse_time_range("1-hour")
        start = datetime.strptime(result["start"], "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(result["end"], "%Y-%m-%d %H:%M:%S")
        assert end - start == timedelta(hours=1)

    def test_supported_keys_match_advertised_list(self) -> None:
        """SUPPORTED_TIME_RANGES is the contract — every key must parse."""
        for key in SUPPORTED_TIME_RANGES:
            result = parse_time_range(key)
            assert "start" in result and "end" in result, f"key {key!r} returned {result!r}"

    @pytest.mark.parametrize(
        "key,delta",
        [
            ("5-min", timedelta(minutes=5)),
            ("15-min", timedelta(minutes=15)),
            ("30-min", timedelta(minutes=30)),
            ("1-hour", timedelta(hours=1)),
            ("2-hour", timedelta(hours=2)),
            ("6-hour", timedelta(hours=6)),
            ("12-hour", timedelta(hours=12)),
            ("24-hour", timedelta(hours=24)),
            ("1-day", timedelta(days=1)),
            ("2-day", timedelta(days=2)),
            ("7-day", timedelta(days=7)),
            ("30-day", timedelta(days=30)),
            ("90-day", timedelta(days=90)),
        ],
    )
    def test_each_preset_produces_expected_window_size(self, key: str, delta: timedelta) -> None:
        result = parse_time_range(key)
        start = datetime.strptime(result["start"], "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(result["end"], "%Y-%m-%d %H:%M:%S")
        assert end - start == delta

    def test_unknown_key_raises_value_error(self) -> None:
        """Bug A regression: unknown keys must error, not silently fall back to 1h."""
        with pytest.raises(ValueError, match="Unknown time_range"):
            parse_time_range("3-hour")  # not in the supported set

    def test_unknown_key_error_lists_supported_keys(self) -> None:
        """The error message should help the caller fix their typo."""
        with pytest.raises(ValueError) as exc_info:
            parse_time_range("definitely-not-a-real-range")
        msg = str(exc_info.value)
        for key in ("1-hour", "24-hour", "7-day"):
            assert key in msg


class TestParseTimeRangeCustom:
    """Custom 'start|end' range handling."""

    def test_custom_range_returns_input_verbatim(self) -> None:
        result = parse_time_range("2024-01-01 00:00:00|2024-01-02 00:00:00")
        assert result == {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}

    def test_custom_range_strips_whitespace(self) -> None:
        result = parse_time_range("  2024-01-01 00:00:00 | 2024-01-02 00:00:00  ")
        assert result == {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}

    def test_custom_range_empty_start_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty parts"):
            parse_time_range("|2024-01-02 00:00:00")

    def test_custom_range_empty_end_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty parts"):
            parse_time_range("2024-01-01 00:00:00|")

    def test_custom_range_malformed_timestamp_raises(self) -> None:
        with pytest.raises(ValueError, match="timestamps must be"):
            parse_time_range("not-a-date|2024-01-02 00:00:00")

    def test_custom_range_start_after_end_raises(self) -> None:
        with pytest.raises(ValueError, match="start must be <= end"):
            parse_time_range("2024-01-02 00:00:00|2024-01-01 00:00:00")

    def test_minute_precision_normalizes_to_seconds(self) -> None:
        # The GUI emits minute precision; we accept it and pad to the
        # seconds form FAZ documents on every version.
        result = parse_time_range("2024-08-15 10:19|2026-07-23 10:19")
        assert result == {"start": "2024-08-15 10:19:00", "end": "2026-07-23 10:19:00"}

    def test_date_only_covers_the_whole_end_day(self) -> None:
        result = parse_time_range("2024-08-15|2026-07-23")
        assert result == {"start": "2024-08-15 00:00:00", "end": "2026-07-23 23:59:59"}

    def test_mixed_precision_range(self) -> None:
        result = parse_time_range("2024-08-15|2026-07-23 08:30")
        assert result == {"start": "2024-08-15 00:00:00", "end": "2026-07-23 08:30:00"}

    def test_seconds_precision_still_verbatim(self) -> None:
        # Normalizing must not perturb an already-seconds range.
        result = parse_time_range("2024-01-01 00:00:00|2024-01-02 23:59:59")
        assert result == {"start": "2024-01-01 00:00:00", "end": "2024-01-02 23:59:59"}

    def test_still_rejects_nonsense_timestamp(self) -> None:
        with pytest.raises(ValueError, match="timestamps must be"):
            parse_time_range("2024-13-40 99:99|2026-07-23")


class TestParseTimeRangeAnchor:
    """Explicit anchor support for LogView-clock alignment."""

    def test_relative_window_ends_on_anchor(self) -> None:
        anchor = datetime(2026, 6, 1, 12, 0, 0)
        result = parse_time_range("1-hour", anchor=anchor)
        assert result == {
            "start": "2026-06-01 11:00:00",
            "end": "2026-06-01 12:00:00",
        }

    def test_anchor_takes_precedence_over_faz_tz(self) -> None:
        anchor = datetime(2026, 6, 1, 12, 0, 0)
        # faz_tz is supplied but the explicit anchor must win.
        result = parse_time_range("7-day", faz_tz=ZoneInfo("Europe/Zurich"), anchor=anchor)
        assert result["end"] == "2026-06-01 12:00:00"
        assert result["start"] == "2026-05-25 12:00:00"

    def test_tz_aware_anchor_is_stripped_to_naive(self) -> None:
        anchor = datetime(2026, 6, 1, 12, 0, 0, tzinfo=ZoneInfo("Europe/Zurich"))
        result = parse_time_range("1-hour", anchor=anchor)
        # Wall-clock components preserved; tzinfo stripped (naive FAZ-local).
        assert result["end"] == "2026-06-01 12:00:00"

    def test_anchor_ignored_for_custom_range(self) -> None:
        anchor = datetime(2026, 6, 1, 12, 0, 0)
        result = parse_time_range("2024-01-01 00:00:00|2024-01-02 00:00:00", anchor=anchor)
        assert result == {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}


class TestParseTimeRangeTimezone:
    """Bug B regression: timestamps must align with FAZ TZ when provided."""

    def test_faz_tz_applied_to_now(self) -> None:
        """When faz_tz is provided, the formatted timestamps are in that TZ.

        We verify by computing the expected UTC instant for the 'end' string
        (interpreted as faz_tz-local) and comparing to "now" in UTC.
        """
        faz_tz = ZoneInfo("US/Pacific")
        result = parse_time_range("1-hour", faz_tz=faz_tz)

        end_naive = datetime.strptime(result["end"], "%Y-%m-%d %H:%M:%S")
        end_in_faz_tz = end_naive.replace(tzinfo=faz_tz)
        now_utc = datetime.now(UTC)
        drift = abs((now_utc - end_in_faz_tz).total_seconds())
        assert drift < 5, (
            f"end timestamp drifts {drift:.1f}s from now-in-FAZ-TZ "
            f"(end={result['end']!r}, faz_tz={faz_tz})"
        )

    def test_faz_tz_none_uses_local_time(self) -> None:
        """When faz_tz is None, falls back to caller-local naive (legacy)."""
        result = parse_time_range("1-hour", faz_tz=None)
        end_naive = datetime.strptime(result["end"], "%Y-%m-%d %H:%M:%S")
        # End should be within a few seconds of local now.
        drift = abs((datetime.now() - end_naive).total_seconds())
        assert drift < 5

    def test_faz_tz_does_not_affect_custom_range(self) -> None:
        """A caller-provided absolute range is sent verbatim regardless of TZ."""
        custom = "2024-06-15 12:00:00|2024-06-15 13:00:00"
        result_with_tz = parse_time_range(custom, faz_tz=ZoneInfo("US/Pacific"))
        result_without_tz = parse_time_range(custom, faz_tz=None)
        assert (
            result_with_tz
            == result_without_tz
            == {
                "start": "2024-06-15 12:00:00",
                "end": "2024-06-15 13:00:00",
            }
        )

    def test_window_size_unchanged_by_tz(self) -> None:
        """end-start delta equals the preset, regardless of TZ choice."""
        for tz in (None, ZoneInfo("UTC"), ZoneInfo("US/Pacific"), ZoneInfo("Europe/Zurich")):
            result = parse_time_range("6-hour", faz_tz=tz)
            start = datetime.strptime(result["start"], "%Y-%m-%d %H:%M:%S")
            end = datetime.strptime(result["end"], "%Y-%m-%d %H:%M:%S")
            assert end - start == timedelta(hours=6), f"failed for tz={tz}"


class TestParseTimeRangeBounds:
    """Inverse parser used by traffic_tools for slicing."""

    def test_round_trip_preserves_strings(self) -> None:
        original = {"start": "2024-01-01 00:00:00", "end": "2024-01-02 12:34:56"}
        start, end = parse_time_range_bounds(original)
        assert start == datetime(2024, 1, 1, 0, 0, 0)
        assert end == datetime(2024, 1, 2, 12, 34, 56)
