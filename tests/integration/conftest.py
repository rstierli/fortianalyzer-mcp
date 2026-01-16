"""Pytest fixtures for FortiAnalyzer MCP integration tests."""

import os
from datetime import datetime, timedelta

import pytest
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from fortianalyzer_mcp.api.client import FortiAnalyzerClient  # noqa: E402


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


@pytest.fixture
def test_device() -> str | None:
    """Get test device name from environment."""
    return os.getenv("TEST_DEVICE")


@pytest.fixture
def time_range_last_hour() -> dict[str, str]:
    """Get time range for last hour."""
    now = datetime.now()
    start = now - timedelta(hours=1)
    return {
        "start": start.strftime("%Y-%m-%d %H:%M:%S"),
        "end": now.strftime("%Y-%m-%d %H:%M:%S"),
    }


@pytest.fixture
def time_range_last_day() -> dict[str, str]:
    """Get time range for last 24 hours."""
    now = datetime.now()
    start = now - timedelta(days=1)
    return {
        "start": start.strftime("%Y-%m-%d %H:%M:%S"),
        "end": now.strftime("%Y-%m-%d %H:%M:%S"),
    }


@pytest.fixture
def time_range_last_week() -> dict[str, str]:
    """Get time range for last 7 days."""
    now = datetime.now()
    start = now - timedelta(days=7)
    return {
        "start": start.strftime("%Y-%m-%d %H:%M:%S"),
        "end": now.strftime("%Y-%m-%d %H:%M:%S"),
    }
