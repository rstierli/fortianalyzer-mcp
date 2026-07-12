"""UEBA endpoint and end-user tools for FortiAnalyzer.

Read-only readers over the UEBA (User and Entity Behavior Analytics) API,
added as building blocks for the Wave-2 skills (asset/identity/risk).
Feature-gated: these endpoints require UEBA to be licensed and enabled on
the FortiAnalyzer. The API paths are identical on 7.6.7 and 8.0.0.

Based on the FNDN FortiAnalyzer UEBA (ueba.json) API specifications.
"""

import logging
from typing import Any

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.responses import redact
from fortianalyzer_mcp.utils.time_range import parse_time_range
from fortianalyzer_mcp.utils.validation import get_default_adom, validate_adom

logger = logging.getLogger(__name__)

_VALID_ENDPOINT_DETAIL = {"simple", "basic", "standard"}
_VALID_ENDUSER_DETAIL = {"basic", "standard", "extended"}
_VALID_DETECTBY = {"FortiClient", "FortiGate"}


def _get_client() -> FortiAnalyzerClient:
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


async def _parse_time_range(time_range: str) -> dict[str, str]:
    """Parse a time-range string, aligning relative presets to FAZ's TZ."""
    if "|" in time_range:
        return parse_time_range(time_range)
    client = _get_client()
    faz_tz = await client.get_system_timezone()
    return parse_time_range(time_range, faz_tz=faz_tz)


@mcp.tool()
async def get_endpoints(
    adom: str | None = None,
    epids: list[int] | None = None,
    detail_level: str = "standard",
    time_range: str | None = None,
) -> dict[str, Any]:
    """Get UEBA endpoint (asset) records from FortiAnalyzer.

    Resolves endpoint/asset profiles: hostname, IP, MAC, OS, first/last
    seen, department, associated users and vulnerability-stat counts.
    Requires UEBA to be enabled/licensed on the FortiAnalyzer.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        epids: Optional list of endpoint IDs to scope the query
        detail_level: "simple", "basic" or "standard" (default: "standard")
        time_range: Optional first-seen window, e.g. "7-day" or a custom
            "start|end" range

    Returns:
        dict with endpoint records under "data"

    Example:
        >>> result = await get_endpoints(detail_level="standard")
        >>> for ep in result["data"]:
        ...     print(ep.get("epname"), ep.get("epip"))
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if detail_level not in _VALID_ENDPOINT_DETAIL:
            valid = ", ".join(sorted(_VALID_ENDPOINT_DETAIL))
            return {
                "status": "error",
                "message": f"Validation error: Invalid detail_level '{detail_level}'. "
                f"Must be one of: {valid}",
            }
        tr = await _parse_time_range(time_range) if time_range else None
        client = _get_client()

        logger.info(f"Getting UEBA endpoints from ADOM {adom}")

        result = await client.get_endpoints(
            adom=adom, epids=epids, detail_level=detail_level, time_range=tr
        )
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"Failed to get UEBA endpoints: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool()
async def get_endpoint_vulnerabilities(
    adom: str | None = None,
    epids: list[int] | None = None,
    detectby: str | None = None,
) -> dict[str, Any]:
    """Get CVE/vulnerability records for UEBA endpoints.

    Returns the per-endpoint vulnerability list (CVE id, severity, type,
    description, references) as detected by FortiClient or FortiGate.
    Requires UEBA to be enabled/licensed on the FortiAnalyzer.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        epids: Optional list of endpoint IDs to scope the query
        detectby: Optional detector filter: "FortiClient" or "FortiGate"

    Returns:
        dict with vulnerability records under "data"

    Example:
        >>> result = await get_endpoint_vulnerabilities(epids=[1025])
        >>> print(len(result["data"]))
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if detectby is not None and detectby not in _VALID_DETECTBY:
            valid = ", ".join(sorted(_VALID_DETECTBY))
            return {
                "status": "error",
                "message": f"Validation error: Invalid detectby '{detectby}'. "
                f"Must be one of: {valid}",
            }
        client = _get_client()

        logger.info(f"Getting UEBA endpoint vulnerabilities from ADOM {adom}")

        result = await client.get_endpoint_vulnerabilities(
            adom=adom, epids=epids, detectby=detectby
        )
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"Failed to get UEBA endpoint vulnerabilities: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool()
async def get_endusers(
    adom: str | None = None,
    euids: list[int] | None = None,
    detail_level: str = "standard",
) -> dict[str, Any]:
    """Get UEBA end-user (identity) records from FortiAnalyzer.

    Resolves user identity records: username, groups, VPN IP, first/last
    seen. With detail_level "extended", also returns email, department,
    title and phone. Requires UEBA to be enabled/licensed on the FAZ.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        euids: Optional list of end-user IDs to scope the query
        detail_level: "basic", "standard" or "extended" (default: "standard")

    Returns:
        dict with end-user records under "data"

    Example:
        >>> result = await get_endusers(detail_level="extended")
        >>> for user in result["data"]:
        ...     print(user.get("euname"), user.get("email"))
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if detail_level not in _VALID_ENDUSER_DETAIL:
            valid = ", ".join(sorted(_VALID_ENDUSER_DETAIL))
            return {
                "status": "error",
                "message": f"Validation error: Invalid detail_level '{detail_level}'. "
                f"Must be one of: {valid}",
            }
        client = _get_client()

        logger.info(f"Getting UEBA end-users from ADOM {adom}")

        result = await client.get_endusers(adom=adom, euids=euids, detail_level=detail_level)
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"Failed to get UEBA end-users: {e}")
        return {"status": "error", "message": redact(str(e))}
