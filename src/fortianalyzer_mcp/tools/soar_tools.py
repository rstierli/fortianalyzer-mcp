"""SOAR indicator/enrichment reader tools for FortiAnalyzer.

Read-only readers over the SOAR indicator API, added as building blocks
for the Wave-2 ``threat_intel`` / ``investigate`` skills. Feature-gated:
these require SOAR to be licensed on the FortiAnalyzer (and enrichment
requires a reputation source, e.g. a VirusTotal/FortiGuard connector,
to have populated indicator data).

Only the GET reads are exposed. The bare ``/indicator/enrichment`` path
is add-only; reputation is read by indicator type+value (or UUID) through
``/indicator/enrichment/{uuid}``. Based on the FNDN SOAR (soar.json) spec.

Note: the request shapes here are verified live against a real appliance;
the enrichment *payload* shape is spec-derived and not yet live-validated,
because the reference estate currently has no populated SOAR indicators.
"""

import logging
from typing import Any

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.responses import redact
from fortianalyzer_mcp.utils.validation import get_default_adom, validate_adom

logger = logging.getLogger(__name__)

_VALID_INDICATOR_TYPES = {"IP", "URL", "Domain"}
_VALID_ENRICHMENT_DETAIL = {"standard", "extended"}


def _get_client() -> FortiAnalyzerClient:
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


@mcp.tool()
async def get_linked_indicators(
    adom: str | None = None,
    alert_id: str | None = None,
    incident_id: str | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """Get IOC indicators linked to an alert or an incident.

    Returns the SOAR indicators (IP/URL/Domain) associated with a specific
    alert or incident — the entry point for enriching the indicators that
    a detection actually involved. Requires SOAR licensed on the FAZ.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        alert_id: Alert ID to look up indicators for
        incident_id: Incident ID to look up indicators for
        filter: Optional filter expression (indicator-uuid/type/value/status)

    Provide exactly one of ``alert_id`` or ``incident_id``.

    Returns:
        dict with the linked indicators under "data"

    Example:
        >>> result = await get_linked_indicators(incident_id="IN00000019")
        >>> for ind in result["data"]:
        ...     print(ind.get("type"), ind.get("value"))
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if bool(alert_id) == bool(incident_id):
            return {
                "status": "error",
                "message": "Validation error: provide exactly one of 'alert_id' or 'incident_id'",
            }
        client = _get_client()

        subject = f"alert {alert_id}" if alert_id else f"incident {incident_id}"
        logger.info(f"Getting linked indicators for {subject} in ADOM {adom}")

        result = await client.get_linked_indicators(
            adom=adom, alert_id=alert_id, incident_id=incident_id, filter=filter
        )
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"Failed to get linked indicators: {e}")
        return {"status": "error", "message": redact(str(e))}


@mcp.tool()
async def get_indicator_enrichment(
    indicator_value: str,
    indicator_type: str,
    adom: str | None = None,
    enrichment_uuid: str | None = None,
    detail_level: str = "standard",
) -> dict[str, Any]:
    """Get IOC reputation/enrichment for an indicator.

    Returns the stored reputation for an IP, URL or domain: verdict
    (Good/Suspicious/Malicious/NoReputationAvailable), confidence (0-100)
    and source. With detail_level "extended", also returns the raw
    enrichment detail. Reads existing enrichment only — it does not trigger
    a new lookup. Requires SOAR licensed with a reputation source.

    Args:
        indicator_value: The indicator value (e.g. an IP, URL or domain)
        indicator_type: "IP", "URL" or "Domain"
        adom: ADOM name (default: from config DEFAULT_ADOM)
        enrichment_uuid: Optional enrichment UUID (resolves by type+value
            when omitted)
        detail_level: "standard" or "extended" (default: "standard")

    Returns:
        dict with the enrichment record under "data"

    Example:
        >>> result = await get_indicator_enrichment(
        ...     indicator_value="8.8.8.8", indicator_type="IP"
        ... )
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if indicator_type not in _VALID_INDICATOR_TYPES:
            valid = ", ".join(sorted(_VALID_INDICATOR_TYPES))
            return {
                "status": "error",
                "message": f"Validation error: Invalid indicator_type "
                f"'{indicator_type}'. Must be one of: {valid}",
            }
        if detail_level not in _VALID_ENRICHMENT_DETAIL:
            valid = ", ".join(sorted(_VALID_ENRICHMENT_DETAIL))
            return {
                "status": "error",
                "message": f"Validation error: Invalid detail_level "
                f"'{detail_level}'. Must be one of: {valid}",
            }
        client = _get_client()

        logger.info(f"Getting indicator enrichment for a {indicator_type} in ADOM {adom}")

        result = await client.get_indicator_enrichment(
            adom=adom,
            indicator_value=indicator_value,
            indicator_type=indicator_type,
            enrichment_uuid=enrichment_uuid,
            detail_level=detail_level,
        )
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"Failed to get indicator enrichment: {e}")
        return {"status": "error", "message": redact(str(e))}
