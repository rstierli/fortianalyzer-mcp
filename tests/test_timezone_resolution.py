"""The appliance timezone resolves on hosts whose system tzdata lacks the legacy names.

FortiAnalyzer reports its zone under ``TZ`` as a legacy IANA alias such as
``US/Eastern``. Ubuntu 24.04 ships those aliases only in ``tzdata-legacy``,
which is not installed by default, so ``zoneinfo`` cannot resolve them from the
system database and ``get_system_timezone()`` fell back to naive timestamps for
the life of the process. Declaring the ``tzdata`` package as a dependency gives
``zoneinfo`` a complete database to fall back on.
"""

from __future__ import annotations

import zoneinfo
from collections.abc import Iterator
from unittest.mock import AsyncMock

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.fixture
def no_system_zoneinfo() -> Iterator[None]:
    """Hide the host's zoneinfo directories so only the tzdata package can answer."""
    zoneinfo.reset_tzpath(to=())
    zoneinfo.ZoneInfo.clear_cache()
    try:
        yield
    finally:
        zoneinfo.reset_tzpath()
        zoneinfo.ZoneInfo.clear_cache()


@pytest.mark.parametrize("name", ["US/Eastern", "US/Pacific"])
async def test_legacy_zone_name_resolves_without_system_tzdata(
    no_system_zoneinfo: None, mock_client: FortiAnalyzerClient, name: str
) -> None:
    mock_client.get_system_status = AsyncMock(return_value={"TZ": name})  # type: ignore[method-assign]

    tz = await mock_client.get_system_timezone()

    assert tz is not None, "the appliance zone name must resolve, not fall back to naive"
    assert tz.key == name
