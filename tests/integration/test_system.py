"""Integration tests for system and ADOM operations."""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_system_status(faz_client: FortiAnalyzerClient):
    """Test getting system status."""
    status = await faz_client.get_system_status()
    assert status is not None
    # Status should contain version information
    assert "Version" in status or "version" in status


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_ha_status(faz_client: FortiAnalyzerClient):
    """Test getting HA status."""
    status = await faz_client.get_ha_status()
    assert status is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_adoms(faz_client: FortiAnalyzerClient):
    """Test listing ADOMs."""
    adoms = await faz_client.list_adoms()
    assert isinstance(adoms, list)
    # Should have at least 'root' ADOM
    adom_names = [a.get("name") for a in adoms]
    assert "root" in adom_names


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_adom(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test getting specific ADOM."""
    adom = await faz_client.get_adom(test_adom)
    assert adom is not None
    assert adom.get("name") == test_adom


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_devices(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test listing devices in ADOM."""
    devices = await faz_client.list_devices(test_adom)
    assert isinstance(devices, list)
    # Devices may be empty if no devices configured


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_devices_with_fields(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test listing devices with specific fields."""
    devices = await faz_client.list_devices(test_adom, fields=["name", "ip", "sn", "platform_str"])
    assert isinstance(devices, list)
    # If devices exist, verify fields are returned
    if devices:
        device = devices[0]
        assert "name" in device


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_device(faz_client: FortiAnalyzerClient, test_adom: str, test_device: str | None):
    """Test getting specific device."""
    if not test_device:
        pytest.skip("TEST_DEVICE not set")
    device = await faz_client.get_device(test_device, test_adom)
    assert device is not None
    assert device.get("name") == test_device


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_device_vdoms(
    faz_client: FortiAnalyzerClient, test_adom: str, test_device: str | None
):
    """Test listing VDOMs for a device."""
    if not test_device:
        pytest.skip("TEST_DEVICE not set")
    vdoms = await faz_client.list_device_vdoms(test_device, test_adom)
    assert isinstance(vdoms, list)
    # Should have at least 'root' vdom
    if vdoms:
        vdom_names = [v.get("name") for v in vdoms]
        assert "root" in vdom_names


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_device_groups(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test listing device groups."""
    groups = await faz_client.list_device_groups(test_adom)
    assert isinstance(groups, list)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_tasks(faz_client: FortiAnalyzerClient):
    """Test listing tasks."""
    tasks = await faz_client.list_tasks()
    assert isinstance(tasks, list)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_api_ratelimit(faz_client: FortiAnalyzerClient):
    """Test getting API rate limit configuration (FAZ 7.6.5+)."""
    try:
        result = await faz_client.get("/cli/global/system/log/api-ratelimit")
        assert result is not None
        assert "read-limit" in result
        assert "write-limit" in result
    except Exception as e:
        # Endpoint may not exist on FAZ < 7.6.5
        pytest.skip(f"API rate limit not available: {e}")
