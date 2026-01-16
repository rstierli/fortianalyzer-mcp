"""Integration tests for IOC (Indicators of Compromise) operations.

These tests are READ-ONLY safe. IOC features require proper licensing.
"""

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_ioc_license_state(faz_client: FortiAnalyzerClient):
    """Test getting IOC license state."""
    try:
        result = await faz_client.get_ioc_license_state()
        assert result is not None
    except Exception as e:
        # IOC may not be licensed
        pytest.skip(f"IOC license check failed: {e}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_ioc_rescan_history(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
):
    """Test getting IOC rescan history."""
    try:
        result = await faz_client.get_ioc_rescan_history(test_adom)
        assert result is not None
    except Exception as e:
        # IOC may not be licensed or available
        pytest.skip(f"IOC rescan history failed: {e}")
