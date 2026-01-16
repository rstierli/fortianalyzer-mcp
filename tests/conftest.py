"""Pytest fixtures for FortiAnalyzer MCP tests.

Provides mocked client fixtures for testing tools without a real FortiAnalyzer.
"""

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient

# =============================================================================
# Mock Response Data
# =============================================================================


MOCK_SYSTEM_STATUS = {
    "Admin Domain Configuration": "Enabled",
    "BIOS version": "04000002",
    "Branch Point": "2620",
    "Build": "2620",
    "Current Time": "Tue Jan 14 10:00:00 UTC 2026",
    "Daylight Time Saving": "No",
    "FIPS Mode": "Disabled",
    "HA Mode": "Stand Alone",
    "Hostname": "FAZ-TEST",
    "Platform Full Name": "FortiAnalyzer-VM64",
    "Platform Type": "FAZ-VM64",
    "Release Version Information": "GA",
    "Serial Number": "FAZ-VMTM00000000",
    "Time Zone": "UTC",
    "Version": "v7.6.5",
}

MOCK_HA_STATUS = {
    "clusterid": 1,
    "file-quota": 0,
    "hb-interval": 5,
    "hb-lost-threshold": 3,
    "mode": "standalone",
    "peer": [],
}

MOCK_ADOMS = [
    {
        "name": "root",
        "oid": 3,
        "state": 1,
        "flags": 0,
        "version": 700,
        "mr": 0,
        "desc": "Default ADOM",
    },
    {
        "name": "demo",
        "oid": 100,
        "state": 1,
        "flags": 0,
        "version": 700,
        "mr": 0,
        "desc": "Demo ADOM",
    },
]

MOCK_DEVICES = [
    {
        "name": "FGT-01",
        "ip": "192.168.1.1",
        "sn": "FGT60F0000000001",
        "conn_status": 1,
        "db_status": 1,
        "os_ver": 7,
        "mr": 4,
        "patch": 4,
        "platform_str": "FortiGate-60F",
        "desc": "Branch firewall",
        "hostname": "FGT-01",
        "last_checked": 1704067200,
    },
    {
        "name": "FGT-02",
        "ip": "192.168.1.2",
        "sn": "FGT60F0000000002",
        "conn_status": 1,
        "db_status": 1,
        "os_ver": 7,
        "mr": 4,
        "patch": 4,
        "platform_str": "FortiGate-60F",
        "desc": "HQ firewall",
        "hostname": "FGT-02",
        "last_checked": 1704067200,
    },
]

MOCK_DEVICE_GROUPS = [
    {
        "name": "All_FortiGate",
        "oid": 1,
        "desc": "All FortiGate devices",
    },
]

MOCK_TASKS = [
    {
        "id": 1,
        "adom": "root",
        "state": 4,
        "percent": 100,
        "title": "Log search",
        "src": "logview",
        "start_time": 1704067200,
        "end_time": 1704067260,
    },
    {
        "id": 2,
        "adom": "root",
        "state": 2,
        "percent": 50,
        "title": "Report generation",
        "src": "report",
        "start_time": 1704067300,
    },
]

MOCK_LOG_SEARCH_START = {
    "tid": 12345,
}

MOCK_LOG_SEARCH_RESULTS = {
    "percentage": 100,
    "return-lines": 2,
    "total-count": 2,
    "status": {"code": 0, "message": "ok"},
    "data": [
        {
            "id": 1,
            "itime": "2024-01-01 10:00:00",
            "srcip": "10.0.0.1",
            "dstip": "8.8.8.8",
            "action": "accept",
            "logtype": "traffic",
            "logid": "0001000014",
        },
        {
            "id": 2,
            "itime": "2024-01-01 10:01:00",
            "srcip": "10.0.0.2",
            "dstip": "1.1.1.1",
            "action": "accept",
            "logtype": "traffic",
            "logid": "0001000014",
        },
    ],
}

MOCK_LOG_SEARCH_COUNT = {
    "progress-percent": 100,
    "matched-logs": 1234,
    "scanned-logs": 5000,
    "total-logs": 10000,
}

MOCK_LOG_FIELDS = {
    "data": [
        {"name": "srcip", "type": "ip"},
        {"name": "dstip", "type": "ip"},
        {"name": "action", "type": "string"},
        {"name": "service", "type": "string"},
    ],
}

MOCK_LOG_STATS = {
    "data": [
        {
            "devid": "FGT60F0000000001",
            "devname": "FGT-01",
            "last_log_time": 1704067200,
            "log_rate": 100,
        },
    ],
}

MOCK_ALERTS = {
    "data": [
        {
            "alertid": "alert-001",
            "name": "High CPU Usage",
            "severity": "high",
            "timestamp": 1704067200,
            "device": "FGT-01",
            "acknowledged": False,
        },
        {
            "alertid": "alert-002",
            "name": "Login Failed",
            "severity": "medium",
            "timestamp": 1704067100,
            "device": "FGT-02",
            "acknowledged": True,
        },
    ],
    "total-count": 2,
}

MOCK_ALERTS_COUNT = {
    "total": 150,
    "unacknowledged": 50,
}

MOCK_FORTIVIEW_START = {
    "tid": 54321,
}

MOCK_FORTIVIEW_RESULTS = {
    "percentage": 100,
    "data": [
        {"srcip": "10.0.0.1", "sessions": 1000, "bytes": 1048576},
        {"srcip": "10.0.0.2", "sessions": 500, "bytes": 524288},
    ],
}

MOCK_REPORT_TEMPLATES = {
    "data": [
        {"tid": "template-001", "name": "Security Report"},
        {"tid": "template-002", "name": "Traffic Analysis"},
    ],
}

MOCK_REPORT_LAYOUTS = {
    "data": [
        {
            "layout-id": 1,
            "title": "Executive Summary",
            "description": "High-level security overview",
        },
        {
            "layout-id": 2,
            "title": "Detailed Traffic Report",
            "description": "In-depth traffic analysis",
        },
    ],
}

MOCK_REPORT_STATE = {
    "data": [
        {
            "tid": "report-uuid-001",
            "title": "Security Report",
            "state": "generated",
            "start_time": 1704067200,
            "end_time": 1704067260,
        },
    ],
}

MOCK_REPORT_RUN = {
    "tid": "report-uuid-002",
}

MOCK_INCIDENTS = {
    "data": [
        {
            "incid": "inc-001",
            "name": "Malware Detection",
            "severity": "high",
            "status": "new",
            "timestamp": 1704067200,
        },
    ],
    "total-count": 1,
}

MOCK_INCIDENTS_COUNT = {
    "total": 25,
}

MOCK_IOC_LICENSE_STATE = {
    "licensed": True,
    "expiry": 1735689600,
    "status": "valid",
}

MOCK_API_RATELIMIT = {
    "api-ratelimit": 500,
    "api-ratelimit-mode": "enable",
}


# =============================================================================
# Client Fixtures
# =============================================================================


@pytest.fixture
def mock_fmg_instance() -> MagicMock:
    """Create a mock pyfmg FortiManager instance (used by both FMG and FAZ)."""
    fmg = MagicMock()
    fmg.login.return_value = (0, {"status": {"code": 0, "message": "OK"}})
    fmg.logout.return_value = (0, {"status": {"code": 0, "message": "OK"}})
    fmg.sid = "mock-session-id"
    fmg.req_id = 0
    fmg.api_key_used = False
    return fmg


@pytest.fixture
def mock_client(mock_fmg_instance: MagicMock) -> FortiAnalyzerClient:
    """Create a FortiAnalyzerClient with mocked pyfmg backend."""
    client = FortiAnalyzerClient(
        host="test-faz.example.com",
        username="admin",
        password="password",
        verify_ssl=False,
    )
    client._fmg = mock_fmg_instance
    client._connected = True
    return client


@pytest.fixture
def mock_client_disconnected() -> FortiAnalyzerClient:
    """Create a disconnected FortiAnalyzerClient."""
    return FortiAnalyzerClient(
        host="test-faz.example.com",
        username="admin",
        password="password",
    )


# =============================================================================
# Response Configuration Fixtures
# =============================================================================


@pytest.fixture
def configure_mock_responses(mock_fmg_instance: MagicMock) -> None:
    """Configure standard mock responses for common API calls."""

    def mock_get(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock GET responses based on URL."""
        if url == "/sys/status":
            return (0, MOCK_SYSTEM_STATUS)
        elif url == "/sys/ha/status":
            return (0, MOCK_HA_STATUS)
        elif url == "/dvmdb/adom":
            return (0, MOCK_ADOMS)
        elif "/dvmdb/adom/" in url:
            parts = url.split("/")
            # parts[0] is empty string due to leading /
            # /dvmdb/adom/{adom}/device/{device}/vdom -> len 7
            if "/vdom" in url:
                return (0, [{"name": "root", "oid": 1}])
            # /dvmdb/adom/{adom}/device/{device} -> len 6
            elif "/device/" in url and len(parts) == 6:
                device_name = parts[-1]
                for device in MOCK_DEVICES:
                    if device["name"] == device_name:
                        return (0, device)
                return (0, MOCK_DEVICES[0])
            # /dvmdb/adom/{adom}/device -> len 5
            elif url.endswith("/device"):
                return (0, MOCK_DEVICES)
            # /dvmdb/adom/{adom}/group -> len 5
            elif "/group" in url:
                return (0, MOCK_DEVICE_GROUPS)
            # /dvmdb/adom/{adom} -> len 4 (single ADOM)
            elif len(parts) == 4:
                adom_name = parts[-1]
                for adom in MOCK_ADOMS:
                    if adom["name"] == adom_name:
                        return (0, adom)
                return (0, MOCK_ADOMS[0])
        elif "/task/task" in url:
            if url == "/task/task":
                return (0, MOCK_TASKS)
            return (0, MOCK_TASKS[0])
        elif "/cli/global/system/api-ratelimit" in url:
            return (0, MOCK_API_RATELIMIT)
        return (0, {})

    def mock_execute(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock EXEC responses."""
        if "/dvm/cmd/add/device" in url:
            return (0, {"status": {"code": 0, "message": "OK"}})
        elif "/dvm/cmd/del/device" in url:
            return (0, {"status": {"code": 0, "message": "OK"}})
        return (0, {"task": 123})

    def mock_add(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock ADD responses."""
        return (0, {"status": {"code": 0, "message": "OK"}})

    def mock_update(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock UPDATE responses."""
        return (0, {"status": {"code": 0, "message": "OK"}})

    def mock_set(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock SET responses."""
        return (0, {"status": {"code": 0, "message": "OK"}})

    def mock_delete(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock DELETE responses."""
        return (0, {"status": {"code": 0, "message": "OK"}})

    mock_fmg_instance.get.side_effect = mock_get
    mock_fmg_instance.execute.side_effect = mock_execute
    mock_fmg_instance.add.side_effect = mock_add
    mock_fmg_instance.update.side_effect = mock_update
    mock_fmg_instance.set.side_effect = mock_set
    mock_fmg_instance.delete.side_effect = mock_delete


@pytest.fixture
def configure_logview_responses(mock_fmg_instance: MagicMock) -> None:
    """Configure mock responses for LogView API (uses _raw_request)."""
    # LogView API uses raw requests, so we need to mock the session
    mock_response = MagicMock()
    mock_fmg_instance.sess = MagicMock()

    def mock_post(url: str, **kwargs: Any) -> MagicMock:
        """Mock POST for raw requests."""
        data = kwargs.get("data", "{}")
        import json

        request = json.loads(data)
        params = request.get("params", [{}])[0]
        req_url = params.get("url", "")

        # Determine response based on URL
        if "/logsearch" in req_url:
            if "/count/" in req_url:
                result = MOCK_LOG_SEARCH_COUNT
            elif req_url.endswith("/logsearch"):
                result = MOCK_LOG_SEARCH_START
            else:
                result = MOCK_LOG_SEARCH_RESULTS
        elif "/logfields" in req_url:
            result = MOCK_LOG_FIELDS
        elif "/logstats" in req_url:
            result = MOCK_LOG_STATS
        elif "/alerts/count" in req_url:
            result = MOCK_ALERTS_COUNT
        elif "/alerts" in req_url:
            result = MOCK_ALERTS
        elif "/fortiview" in req_url and "/run" in req_url:
            if "run/" in req_url:
                result = MOCK_FORTIVIEW_RESULTS
            else:
                result = MOCK_FORTIVIEW_START
        elif "/report/adom" in req_url and "/template/list" in req_url:
            result = MOCK_REPORT_TEMPLATES
        elif "/sql-report/layout" in req_url:
            result = MOCK_REPORT_LAYOUTS
        elif "/reports/state" in req_url:
            result = MOCK_REPORT_STATE
        elif "/report/adom" in req_url and "/run" in req_url:
            if len(req_url.split("/")) > 5:  # Has TID
                result = {"state": "generated", "progress": 100}
            else:
                result = MOCK_REPORT_RUN
        elif "/incidents/count" in req_url:
            result = MOCK_INCIDENTS_COUNT
        elif "/incidents" in req_url or "/incident" in req_url:
            result = MOCK_INCIDENTS
        elif "/ioc/license/state" in req_url:
            result = MOCK_IOC_LICENSE_STATE
        else:
            result = {"data": []}

        mock_response.json.return_value = {"result": result}
        return mock_response

    mock_fmg_instance.sess.post.side_effect = mock_post


# =============================================================================
# Server/Tool Fixtures
# =============================================================================


@pytest.fixture
def mock_get_faz_client(
    mock_client: FortiAnalyzerClient,
) -> Generator[MagicMock, None, None]:
    """Patch get_faz_client to return mocked client."""
    with patch("fortianalyzer_mcp.server.get_faz_client", return_value=mock_client) as mock:
        yield mock


@pytest.fixture
def mock_get_faz_client_none() -> Generator[MagicMock, None, None]:
    """Patch get_faz_client to return None (disconnected)."""
    with patch("fortianalyzer_mcp.server.get_faz_client", return_value=None) as mock:
        yield mock


# =============================================================================
# Async Fixtures
# =============================================================================


@pytest.fixture
async def async_mock_client(
    mock_client: FortiAnalyzerClient, configure_mock_responses: None
) -> FortiAnalyzerClient:
    """Async fixture that provides a fully configured mock client."""
    return mock_client


@pytest.fixture
async def async_mock_client_with_logview(
    mock_client: FortiAnalyzerClient,
    configure_mock_responses: None,
    configure_logview_responses: None,
) -> FortiAnalyzerClient:
    """Async fixture with LogView API mock responses."""
    return mock_client


# =============================================================================
# Combined Fixtures for Tool Tests
# =============================================================================


@pytest.fixture
def mock_client_configured(
    mock_client: FortiAnalyzerClient, configure_mock_responses: None
) -> FortiAnalyzerClient:
    """Provide a mock client with configured responses for tool tests."""
    return mock_client
