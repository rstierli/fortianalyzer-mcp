"""Tests for FortiAnalyzer DVM (Device Manager) tools."""

from typing import Any

import pytest

import fortianalyzer_mcp.tools.dvm_tools as dvm_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.query.filters import FilterCondition


class TestDVMTools:
    """Tests for device management tools."""

    @pytest.fixture
    def mock_client_configured(
        self, mock_client: FortiAnalyzerClient, configure_mock_responses: None
    ) -> FortiAnalyzerClient:
        """Provide a mock client with configured responses."""
        return mock_client

    async def test_list_devices_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test list_devices returns device list."""
        result = await mock_client_configured.list_devices(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "FGT-01"
        assert result[0]["sn"] == "FGT60F0000000001"

    async def test_list_devices_with_fields(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_devices with field filter."""
        result = await mock_client_configured.list_devices(adom="root", fields=["name", "ip"])
        assert len(result) == 2

    async def test_get_device_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test get_device returns device details."""
        result = await mock_client_configured.get_device("FGT-01", adom="root")
        assert result["name"] == "FGT-01"

    async def test_list_device_vdoms_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_device_vdoms returns VDOMs."""
        result = await mock_client_configured.list_device_vdoms(device="FGT-01", adom="root")
        assert len(result) == 1
        assert result[0]["name"] == "root"

    async def test_list_device_groups_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_device_groups returns groups."""
        result = await mock_client_configured.list_device_groups(adom="root")
        assert len(result) == 1
        assert result[0]["name"] == "All_FortiGate"

    async def test_add_device_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test add_device creates device."""
        device = {
            "name": "FGT-NEW",
            "ip": "192.168.1.100",
            "adm_usr": "admin",
            "adm_pass": "password",
        }
        result = await mock_client_configured.add_device(adom="root", device=device)
        assert result is not None

    async def test_delete_device_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test delete_device removes device."""
        result = await mock_client_configured.delete_device(adom="root", device="FGT-01")
        assert result is not None

    async def test_add_device_list_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test add_device_list adds multiple devices."""
        devices = [
            {"name": "FGT-A", "ip": "192.168.1.10"},
            {"name": "FGT-B", "ip": "192.168.1.11"},
        ]
        result = await mock_client_configured.add_device_list(adom="root", devices=devices)
        assert result is not None

    async def test_delete_device_list_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test delete_device_list removes multiple devices."""
        devices = [
            {"name": "FGT-A"},
            {"name": "FGT-B"},
        ]
        result = await mock_client_configured.delete_device_list(adom="root", devices=devices)
        assert result is not None


class TestSearchDevicesStructuredFilters:
    """filters compiles to the array dialect and composes with the old params."""

    class FakeClient:
        """Captures the filter and projection search_devices hands to the client."""

        def __init__(self) -> None:
            self.captured: list[list[Any]] | None = None
            self.captured_fields: list[str] | None = None

        async def list_devices(
            self,
            adom: str,
            filter: list[list[Any]] | None = None,
            fields: list[str] | None = None,
        ) -> list[dict[str, Any]]:
            self.captured = filter
            self.captured_fields = fields
            return []

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> FakeClient:
        fake = self.FakeClient()
        monkeypatch.setattr(dvm_tools, "_get_client", lambda: fake)
        return fake

    async def test_filters_compile_to_array_entries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(
            filters=[FilterCondition(field="os_version", op="contains", value="7.6")]
        )

        assert fake.captured == [["os_ver", "like", "%7.6%"]]

    async def test_enum_name_is_coerced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(
            filters=[FilterCondition(field="conn_status", op="eq", value="down")]
        )

        assert fake.captured == [["conn_status", "==", 2]]

    async def test_structured_and_narrow_params_are_anded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(
            name_filter="fgt",
            filters=[FilterCondition(field="os_version", op="contains", value="7.6")],
        )

        assert fake.captured is not None
        assert ["name", "like", "%fgt%"] in fake.captured
        assert ["os_ver", "like", "%7.6%"] in fake.captured

    async def test_response_echoes_the_compiled_filter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An LLM caller can verify what was sent without live-data inference."""
        self._install(monkeypatch)

        result = await dvm_tools.search_devices(name_filter="fgt")

        assert result["filter_applied"] == [["name", "like", "%fgt%"]]

    async def test_no_filters_echo_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install(monkeypatch)

        result = await dvm_tools.search_devices()

        assert result["filter_applied"] is None

    async def test_fields_projection_is_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """list_devices slims responses with fields=[...]; search_devices must too."""
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(fields=["name", "os_ver"])

        assert fake.captured_fields == ["name", "os_ver"]

    async def test_validation_error_returns_the_standard_envelope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Error handlers normalised on the query_logs contract must not crash here."""
        self._install(monkeypatch)

        result = await dvm_tools.search_devices(
            filters=[FilterCondition(field="bogus", op="eq", value="x")]
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert result["operation"] == "search_devices"
        assert result["retry_count"] == 0

    async def test_unknown_device_field_is_rejected_locally(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The field set is enumerable, so this never reaches the appliance."""

        class Unreachable:
            async def list_devices(self, **kwargs: Any) -> list[dict[str, Any]]:
                raise AssertionError("must not reach the API")

        monkeypatch.setattr(dvm_tools, "_get_client", lambda: Unreachable())

        result = await dvm_tools.search_devices(
            filters=[FilterCondition(field="not_a_field", op="eq", value="x")]
        )

        assert result["status"] == "error"
        assert "conn_status" in result["message"]
