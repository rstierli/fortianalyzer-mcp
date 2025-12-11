"""Integration tests for system and ADOM operations."""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.mark.asyncio
async def test_get_system_status(faz_client: FortiAnalyzerClient):
    """Test getting system status."""
    status = await faz_client.get_system_status()
    assert status is not None
    # Status should contain version information


@pytest.mark.asyncio
async def test_list_adoms(faz_client: FortiAnalyzerClient):
    """Test listing ADOMs."""
    adoms = await faz_client.list_adoms()
    assert isinstance(adoms, list)
    # Should have at least 'root' ADOM
    adom_names = [a.get("name") for a in adoms]
    assert "root" in adom_names


@pytest.mark.asyncio
async def test_get_adom(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test getting specific ADOM."""
    adom = await faz_client.get_adom(test_adom)
    assert adom is not None
    assert adom.get("name") == test_adom


@pytest.mark.asyncio
async def test_list_devices(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test listing devices in ADOM."""
    devices = await faz_client.list_devices(test_adom)
    assert isinstance(devices, list)
    # Devices may be empty if no devices configured


@pytest.mark.asyncio
async def test_list_tasks(faz_client: FortiAnalyzerClient):
    """Test listing tasks."""
    tasks = await faz_client.list_tasks()
    assert isinstance(tasks, list)
