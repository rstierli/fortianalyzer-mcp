"""Tests for FortiAnalyzer FortiView tools.

Tests the client methods for FortiView analytics operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import pytest

import fortianalyzer_mcp.tools.fortiview_tools as fortiview_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.utils.validation import (
    VALID_FORTIVIEW_VIEWS,
    ValidationError,
    build_device_filter,
    validate_fortiview_view,
)


class TestFortiViewHelpers:
    """Tests for FortiView tools helper functions.

    These test the helper function logic by reimplementing the tests
    without importing from tools module (which triggers server init).
    """

    def test_parse_time_range_custom_format(self) -> None:
        """Test parsing custom time range with pipe separator."""
        time_range = "2024-01-01 00:00:00|2024-01-02 00:00:00"
        parts = time_range.split("|")
        result = {"start": parts[0].strip(), "end": parts[1].strip()}
        assert result["start"] == "2024-01-01 00:00:00"
        assert result["end"] == "2024-01-02 00:00:00"

    def test_time_range_predefined_mapping(self) -> None:
        """Test predefined time range mapping logic."""
        from datetime import timedelta

        range_map = {
            "now": timedelta(minutes=5),
            "5-min": timedelta(minutes=5),
            "15-min": timedelta(minutes=15),
            "1-hour": timedelta(hours=1),
            "6-hour": timedelta(hours=6),
            "12-hour": timedelta(hours=12),
            "24-hour": timedelta(hours=24),
            "1-day": timedelta(days=1),
            "7-day": timedelta(days=7),
            "30-day": timedelta(days=30),
        }

        # Verify all expected ranges exist
        assert "now" in range_map
        assert "5-min" in range_map
        assert "1-hour" in range_map
        assert "24-hour" in range_map
        assert "7-day" in range_map

        # Verify timedeltas are correct
        assert range_map["5-min"] == timedelta(minutes=5)
        assert range_map["1-hour"] == timedelta(hours=1)
        assert range_map["24-hour"] == timedelta(hours=24)

    def test_device_filter_build(self) -> None:
        """Test device filter building logic."""
        device = "FGT60F0000000001"
        device_filter = [{"devname": device}] if device else [{"devname": "All_Device"}]
        assert device_filter == [{"devname": "FGT60F0000000001"}]

    def test_device_filter_build_none(self) -> None:
        """Test device filter with None defaults to All_Device."""
        device = None
        device_filter = [{"devname": device}] if device else [{"devname": "All_Device"}]
        assert device_filter == [{"devname": "All_Device"}]


class TestFortiViewDeviceFilter:
    """The all-devices token has two spellings and only one of them works.

    ``build_device_filter`` is logview's: it sends every ``All_*`` group as
    ``devid`` and defaults to ``All_FortiGate``. FortiView answers only to
    ``[{"devname": "All_Device"}]`` -- and answers the other spellings with an
    empty top-N and no error, which reads as "no traffic".
    """

    def test_none_becomes_fortiviews_all_devices(self) -> None:
        assert fortiview_tools.build_fortiview_device_filter(None) == [{"devname": "All_Device"}]

    @pytest.mark.parametrize(
        "token", ["All_FortiGate", "All_FortiMail", "All_Device", "All_FortiWeb"]
    )
    def test_every_all_devices_group_is_translated(self, token: str) -> None:
        assert fortiview_tools.build_fortiview_device_filter(token) == [{"devname": "All_Device"}]
        # The logview builder is what this exists to correct.
        assert build_device_filter(token) == [{"devid": token}]

    def test_a_named_device_is_untouched(self) -> None:
        assert fortiview_tools.build_fortiview_device_filter("FGT1") == [{"devname": "FGT1"}]

    def test_a_serial_still_goes_under_devid(self) -> None:
        """A serial under devname silently matches nothing."""
        assert fortiview_tools.build_fortiview_device_filter("FG100FTK19001333") == [
            {"devid": "FG100FTK19001333"}
        ]

    async def test_get_fortiview_data_sends_the_translated_filter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Asserted at the client, which is the only boundary that matters."""
        captured: dict[str, object] = {}

        class FakeClient:
            async def get_system_timezone(self) -> None:
                return None

            async def fortiview_run(self, **kwargs: object) -> dict[str, object]:
                captured.update(kwargs)
                return {"tid": 1}

            async def fortiview_fetch(self, **kwargs: object) -> dict[str, object]:
                return {"percentage": 100, "data": []}

        monkeypatch.setattr(fortiview_tools, "_get_client", lambda: FakeClient())

        result = await fortiview_tools.get_fortiview_data(
            view_name="top-sources", device="All_FortiGate", fields=["*"]
        )

        assert result["status"] == "success"
        assert captured["device"] == [{"devname": "All_Device"}]

    def test_sort_by_param_build(self) -> None:
        """Test sort_by parameter building logic."""
        sort_by = "bandwidth"
        sort_order = "desc"
        sort_by_param = [{"field": sort_by, "order": sort_order}] if sort_by else None
        assert sort_by_param == [{"field": "bandwidth", "order": "desc"}]

    def test_sort_by_param_none(self) -> None:
        """Test sort_by parameter is None when not specified."""
        sort_by = None
        sort_order = "desc"
        sort_by_param = [{"field": sort_by, "order": sort_order}] if sort_by else None
        assert sort_by_param is None


class TestFortiViewClient:
    """Tests for FortiView client methods."""

    @pytest.fixture
    def mock_client_with_fortiview(
        self,
        mock_client: FortiAnalyzerClient,
        configure_mock_responses: None,
        configure_logview_responses: None,
    ) -> FortiAnalyzerClient:
        """Provide a mock client with FortiView API responses configured."""
        return mock_client

    async def test_fortiview_run_success(
        self, mock_client_with_fortiview: FortiAnalyzerClient
    ) -> None:
        """Test fortiview_run returns TID."""
        result = await mock_client_with_fortiview.fortiview_run(
            adom="root",
            view_name="top-sources",
            device=[{"devname": "All_Device"}],
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
        )
        assert "tid" in result
        assert result["tid"] == 54321

    async def test_fortiview_fetch_success(
        self, mock_client_with_fortiview: FortiAnalyzerClient
    ) -> None:
        """Test fortiview_fetch returns data."""
        result = await mock_client_with_fortiview.fortiview_fetch(
            adom="root",
            view_name="top-sources",
            tid=54321,
        )
        assert result["percentage"] == 100
        assert "data" in result
        assert len(result["data"]) == 2
        assert result["data"][0]["srcip"] == "10.0.0.1"
        assert result["data"][0]["sessions"] == 1000

    async def test_fortiview_run_not_connected(self) -> None:
        """Test fortiview_run raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.fortiview_run(
                adom="root",
                view_name="top-sources",
                device=[{"devid": "All_FortiGate"}],
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
            )

    async def test_fortiview_fetch_not_connected(self) -> None:
        """Test fortiview_fetch raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.fortiview_fetch(
                adom="root",
                view_name="top-sources",
                tid=54321,
            )


class TestFortiViewViews:
    """Tests for different FortiView view names."""

    def test_valid_view_names(self) -> None:
        """Every advertised view name is one the validator accepts."""
        assert VALID_FORTIVIEW_VIEWS == {
            "top-sources",
            "top-destinations",
            "top-applications",
            "top-websites",
            "top-threats",
            "top-cloud-applications",
            # network_context skill; both live-verified on 7.6.7 and 8.0.0
            "top-countries",
            "site-to-site-ipsec",
            "policy-hits",
            "policy-line",
        }
        for view in VALID_FORTIVIEW_VIEWS:
            assert validate_fortiview_view(view) == view

    @pytest.mark.parametrize("view", ["traffic-summary", "fortiview-traffic", "fortiview-threats"])
    def test_views_faz_does_not_serve_are_rejected(self, view: str) -> None:
        """FortiAnalyzer answers "Cannot find FortiView" for these on 7.6 and 8.0.

        The old list accepted them, so the caller got a server error one round
        trip later instead of a validation error naming the views that work.
        """
        with pytest.raises(ValidationError, match="Invalid FortiView view"):
            validate_fortiview_view(view)


class TestFortiViewProjection:
    """FortiView rows are per-view, so there is no curated default."""

    ROWS = [{"srcip": "10.0.0.1", "bandwidth": 100, "sessions": 4}]

    class FakeClient:
        """get_fortiview_data starts a task then polls fetch until 100%."""

        def __init__(self, rows: list[dict[str, object]]) -> None:
            self.rows = rows

        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

        async def fortiview_run(self, **kwargs: object) -> dict[str, object]:
            return {"tid": 4242}

        async def fortiview_fetch(self, **kwargs: object) -> dict[str, object]:
            return {"percentage": 100, "data": self.rows}

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            fortiview_tools, "_get_client", lambda: self.FakeClient(list(self.ROWS))
        )

    async def test_default_returns_full_rows_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await fortiview_tools.get_fortiview_data(view_name="top-sources")

        assert result["data"][0]["sessions"] == 4
        assert any("fields" in w for w in result["warnings"])

    async def test_explicit_fields_select(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install(monkeypatch)

        result = await fortiview_tools.get_fortiview_data(
            view_name="top-sources", fields=["srcip", "bandwidth"]
        )

        # Keys plus the non-PII value: `srcip` is IP-typed, so its value is
        # rewritten by the arg unmasker under MASKING_ENABLED.
        assert result["data"][0].keys() == {"srcip", "bandwidth"}
        assert result["data"][0]["bandwidth"] == 100

    async def test_get_fortiview_data_still_warns_because_it_has_the_parameter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The suppression is scoped to the wrappers, not to the warning."""
        self._install(monkeypatch)

        result = await fortiview_tools.get_fortiview_data(view_name="top-sources")

        assert any("fields" in w for w in result["warnings"])


class TestFortiViewWrapperEquivalence:
    """Each removed wrapper was get_fortiview_data with a fixed view_name."""

    VIEW_FOR_REMOVED_TOOL = {
        "get_top_sources": "top-sources",
        "get_top_destinations": "top-destinations",
        "get_top_applications": "top-applications",
        "get_top_threats": "top-threats",
        "get_top_websites": "top-websites",
        "get_top_cloud_applications": "top-cloud-applications",
        "get_policy_hits": "policy-hits",
    }

    @pytest.mark.parametrize("view", sorted(set(VIEW_FOR_REMOVED_TOOL.values())))
    async def test_the_replacement_reaches_each_view(
        self, monkeypatch: pytest.MonkeyPatch, view: str
    ) -> None:
        captured: dict[str, object] = {}

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_system_timezone(self) -> None:
                return None

            async def fortiview_run(self, **kwargs: object) -> dict[str, object]:
                captured.update(kwargs)
                return {"tid": 1}

            async def fortiview_fetch(self, **kwargs: object) -> dict[str, object]:
                return {"percentage": 100, "data": []}

        monkeypatch.setattr(fortiview_tools, "_get_client", lambda: FakeClient())

        result = await fortiview_tools.get_fortiview_data(view_name=view, fields=["*"])

        assert result["status"] == "success"
        assert captured["view_name"] == view

    @pytest.mark.parametrize("name", sorted(VIEW_FOR_REMOVED_TOOL))
    def test_the_wrapper_is_gone(self, name: str) -> None:
        assert not hasattr(fortiview_tools, name), f"{name} should have been removed"
