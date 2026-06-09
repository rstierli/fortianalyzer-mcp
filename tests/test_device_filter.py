"""Tests for the shared device-filter builder (utils.validation)."""

from __future__ import annotations

import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.traffic_tools as traffic_tools
from fortianalyzer_mcp.utils.validation import build_device_filter


class TestBuildDeviceFilter:
    def test_none_defaults_to_all_fortigate(self) -> None:
        assert build_device_filter(None) == [{"devid": "All_FortiGate"}]

    def test_empty_string_defaults_to_all_fortigate(self) -> None:
        assert build_device_filter("") == [{"devid": "All_FortiGate"}]

    def test_serial_prefix_uses_devid(self) -> None:
        assert build_device_filter("FG100FTK19001333") == [{"devid": "FG100FTK19001333"}]

    def test_fortimanager_prefix_uses_devid(self) -> None:
        assert build_device_filter("FMG-VM0000000001") == [{"devid": "FMG-VM0000000001"}]

    def test_all_group_uses_devid(self) -> None:
        assert build_device_filter("All_FortiMail") == [{"devid": "All_FortiMail"}]

    def test_plain_name_uses_devname(self) -> None:
        assert build_device_filter("myfw01") == [{"devname": "myfw01"}]

    def test_name_with_vdom_uses_devname(self) -> None:
        assert build_device_filter("myfw01[root]") == [{"devname": "myfw01[root]"}]


class TestModuleAliasesShareImplementation:
    """The per-tool aliases must resolve to the single shared implementation."""

    def test_log_tools_alias_is_shared(self) -> None:
        assert log_tools._build_device_filter is build_device_filter

    def test_traffic_tools_alias_is_shared(self) -> None:
        assert traffic_tools._build_device_filter is build_device_filter
