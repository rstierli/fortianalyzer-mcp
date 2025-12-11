"""Pytest fixtures for FortiAnalyzer MCP integration tests."""

import os

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.fixture
def faz_host() -> str:
    """Get FortiAnalyzer host from environment."""
    host = os.getenv("FORTIANALYZER_HOST")
    if not host:
        pytest.skip("FORTIANALYZER_HOST not set")
    return host


@pytest.fixture
def faz_credentials() -> dict:
    """Get FortiAnalyzer credentials from environment."""
    return {
        "api_token": os.getenv("FORTIANALYZER_API_TOKEN"),
        "username": os.getenv("FORTIANALYZER_USERNAME"),
        "password": os.getenv("FORTIANALYZER_PASSWORD"),
    }


@pytest.fixture
async def faz_client(faz_host: str, faz_credentials: dict) -> FortiAnalyzerClient:
    """Create and connect FortiAnalyzer client."""
    client = FortiAnalyzerClient(
        host=faz_host,
        api_token=faz_credentials["api_token"],
        username=faz_credentials["username"],
        password=faz_credentials["password"],
        verify_ssl=False,
        timeout=30,
    )
    await client.connect()
    yield client
    await client.disconnect()


@pytest.fixture
def test_adom() -> str:
    """Get test ADOM from environment."""
    return os.getenv("TEST_ADOM", "root")
