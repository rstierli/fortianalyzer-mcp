"""Wave-2 enrichment skill: network_context.

Same conventions as ``test_skills_wave2.py``: the underlying FortiView
tool functions are patched at their defining module with ``autospec=True``
(the handler imports them lazily per call), and the dispatcher path is
exercised end-to-end through ``faz_skill``. The geo and VPN sections both
route through ``get_fortiview_data``, so that mock dispatches on the
``view_name`` kwarg.
"""

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.catalog import SKILLS
from fortianalyzer_mcp.skills.dispatcher import faz_skill
from fortianalyzer_mcp.skills.models import (
    SCHEMA_VERSION,
    FeatureGap,
    NetworkContextParams,
)

GET_TOP_DESTINATIONS = "fortianalyzer_mcp.tools.fortiview_tools.get_top_destinations"
GET_TOP_SOURCES = "fortianalyzer_mcp.tools.fortiview_tools.get_top_sources"
GET_FORTIVIEW_DATA = "fortianalyzer_mcp.tools.fortiview_tools.get_fortiview_data"


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


def by_view(**responses: dict[str, Any]) -> Any:
    """Side effect for ``get_fortiview_data``, dispatching on view_name.

    Keys use underscores (python identifiers); view names use hyphens.
    """
    mapping = {key.replace("_", "-"): value for key, value in responses.items()}

    def _route(**kwargs: Any) -> dict[str, Any]:
        return mapping[kwargs["view_name"]]

    return _route


ERR = {"status": "error", "message": "boom"}
DEST_ROWS = [
    {"dstip": "198.51.100.100", "bandwidth": 9001, "sessions": 12},
    {"dstip": "198.51.100.229", "bandwidth": 4500, "sessions": 7},
]
SRC_ROWS = [{"srcip": "192.0.2.10", "bandwidth": 8000, "sessions": 20}]
GEO_ROWS = [{"country": "Switzerland", "traffic_in": 100, "traffic_out": 200}]
VPN_ROWS = [{"vpntunnel": "hq-to-branch", "traffic_in": 10, "traffic_out": 20}]


class TestNetworkContextCatalog:
    def test_registered_as_enrichment(self):
        assert "network_context" in SKILLS
        assert SKILLS["network_context"].tier == "enrichment"

    def test_params_model_forbids_unknown_keys(self):
        with pytest.raises(ValidationError):
            NetworkContextParams(no_such_parameter=True)


class TestNetworkContext:
    async def test_happy_path_all_sections(self):
        with (
            t(GET_TOP_DESTINATIONS, return_value=ok(data=DEST_ROWS)) as dest,
            t(GET_TOP_SOURCES, return_value=ok(data=SRC_ROWS)),
            t(
                GET_FORTIVIEW_DATA,
                side_effect=by_view(
                    top_countries=ok(data=GEO_ROWS), site_to_site_ipsec=ok(data=VPN_ROWS)
                ),
            ) as fortiview,
        ):
            result = await handlers.run_network_context(
                NetworkContextParams(time_range="7-day", device="FGT100F", top_limit=5)
            )
        assert dest.call_args.kwargs["time_range"] == "7-day"
        assert dest.call_args.kwargs["device"] == "FGT100F"
        assert dest.call_args.kwargs["limit"] == 5
        fv = {c.kwargs["view_name"]: c.kwargs for c in fortiview.call_args_list}
        assert set(fv) == {"top-countries", "site-to-site-ipsec"}
        # geo uses the requested window; the session-bucketed VPN view is
        # floored to 90-day so long-lived tunnels are not silently dropped.
        assert fv["top-countries"]["time_range"] == "7-day"
        assert fv["site-to-site-ipsec"]["time_range"] == "90-day"
        assert result.top_destinations == DEST_ROWS
        assert result.top_sources == SRC_ROWS
        assert result.top_countries == GEO_ROWS
        assert result.vpn_tunnels == VPN_ROWS
        assert result.counts == {
            "top_destinations": 2,
            "top_sources": 1,
            "top_countries": 1,
            "vpn_tunnels": 1,
        }
        assert result.time_range == "7-day"
        # tunnels present, so only the window-widening note surfaces
        assert any("queried over 90-day" in w for w in result.warnings)
        assert not any("no site-to-site" in w for w in result.warnings)

    async def test_vpn_window_floored_and_override(self):
        with (
            t(GET_TOP_DESTINATIONS, return_value=ok(data=DEST_ROWS)),
            t(GET_TOP_SOURCES, return_value=ok(data=SRC_ROWS)),
            t(
                GET_FORTIVIEW_DATA,
                side_effect=by_view(
                    top_countries=ok(data=GEO_ROWS), site_to_site_ipsec=ok(data=VPN_ROWS)
                ),
            ) as fortiview,
        ):
            result = await handlers.run_network_context(
                NetworkContextParams(time_range="24-hour", vpn_time_range="30-day")
            )
        fv = {c.kwargs["view_name"]: c.kwargs for c in fortiview.call_args_list}
        # explicit override wins over the floor
        assert fv["site-to-site-ipsec"]["time_range"] == "30-day"
        assert fv["top-countries"]["time_range"] == "24-hour"
        assert any("queried over 30-day" in w for w in result.warnings)

    async def test_wide_window_not_widened_no_note(self):
        with (
            t(GET_TOP_DESTINATIONS, return_value=ok(data=DEST_ROWS)),
            t(GET_TOP_SOURCES, return_value=ok(data=SRC_ROWS)),
            t(
                GET_FORTIVIEW_DATA,
                side_effect=by_view(
                    top_countries=ok(data=GEO_ROWS), site_to_site_ipsec=ok(data=VPN_ROWS)
                ),
            ) as fortiview,
        ):
            result = await handlers.run_network_context(NetworkContextParams(time_range="90-day"))
        fv = {c.kwargs["view_name"]: c.kwargs for c in fortiview.call_args_list}
        assert fv["site-to-site-ipsec"]["time_range"] == "90-day"
        assert not any("queried over" in w for w in result.warnings)

    async def test_empty_vpn_section_warns(self):
        with (
            t(GET_TOP_DESTINATIONS, return_value=ok(data=DEST_ROWS)),
            t(GET_TOP_SOURCES, return_value=ok(data=SRC_ROWS)),
            t(
                GET_FORTIVIEW_DATA,
                side_effect=by_view(
                    top_countries=ok(data=GEO_ROWS), site_to_site_ipsec=ok(data=[])
                ),
            ),
        ):
            result = await handlers.run_network_context(NetworkContextParams(time_range="90-day"))
        assert result.vpn_tunnels == []
        assert any(
            "no site-to-site IPsec tunnels in the 90-day window" in w for w in result.warnings
        )

    def test_vpn_window_helper(self):
        assert handlers._vpn_window("24-hour") == "90-day"
        assert handlers._vpn_window("7-day") == "90-day"
        assert handlers._vpn_window("30-day") == "90-day"
        assert handlers._vpn_window("90-day") == "90-day"
        # custom range and unknown tokens are the caller's intent, untouched
        assert handlers._vpn_window("2024-01-01 00:00:00|2024-02-01 00:00:00") == (
            "2024-01-01 00:00:00|2024-02-01 00:00:00"
        )
        assert handlers._vpn_window("1-year") == "1-year"

    async def test_failed_section_degrades_to_warning_and_gap(self):
        geo_err = {"status": "error", "message": "Validation error: Invalid FortiView view"}
        with (
            t(GET_TOP_DESTINATIONS, return_value=ok(data=DEST_ROWS)),
            t(GET_TOP_SOURCES, return_value=ok(data=SRC_ROWS)),
            t(
                GET_FORTIVIEW_DATA,
                side_effect=by_view(top_countries=geo_err, site_to_site_ipsec=ok(data=VPN_ROWS)),
            ),
        ):
            result = await handlers.run_network_context(NetworkContextParams())
        assert isinstance(result.top_countries, FeatureGap)
        assert "Invalid FortiView view" in result.top_countries.reason
        assert any("top_countries unavailable" in w for w in result.warnings)
        assert result.top_destinations == DEST_ROWS
        assert result.vpn_tunnels == VPN_ROWS
        assert result.counts["top_countries"] == 0

    async def test_disabled_sections_skip_reads_and_report_gaps(self):
        with (
            t(GET_TOP_DESTINATIONS, return_value=ok(data=DEST_ROWS)),
            t(GET_TOP_SOURCES, return_value=ok(data=SRC_ROWS)),
            t(GET_FORTIVIEW_DATA) as fortiview,
        ):
            result = await handlers.run_network_context(
                NetworkContextParams(include_geo=False, include_vpn=False)
            )
        fortiview.assert_not_called()
        assert isinstance(result.top_countries, FeatureGap)
        assert result.top_countries.reason == "disabled by include_geo=false"
        assert isinstance(result.vpn_tunnels, FeatureGap)
        assert result.vpn_tunnels.reason == "disabled by include_vpn=false"
        assert result.warnings == []

    async def test_all_sections_failing_raises(self):
        with (
            t(GET_TOP_DESTINATIONS, return_value=ERR),
            t(GET_TOP_SOURCES, return_value=ERR),
            t(GET_FORTIVIEW_DATA, return_value=ERR),
        ):
            with pytest.raises(
                handlers.SkillExecutionError, match="all network-context sections failed"
            ):
                await handlers.run_network_context(NetworkContextParams())

    async def test_all_attempted_failing_raises_even_with_sections_disabled(self):
        with (
            t(GET_TOP_DESTINATIONS, return_value=ERR),
            t(GET_TOP_SOURCES, return_value=ERR),
            t(GET_FORTIVIEW_DATA) as fortiview,
        ):
            with pytest.raises(handlers.SkillExecutionError):
                await handlers.run_network_context(
                    NetworkContextParams(include_geo=False, include_vpn=False)
                )
        fortiview.assert_not_called()


class TestNetworkContextDispatch:
    async def test_success_envelope_with_serialized_gap(self):
        with (
            t(GET_TOP_DESTINATIONS, return_value=ok(data=DEST_ROWS)),
            t(GET_TOP_SOURCES, return_value=ok(data=SRC_ROWS)),
            t(
                GET_FORTIVIEW_DATA,
                side_effect=by_view(top_countries=ERR, site_to_site_ipsec=ok(data=VPN_ROWS)),
            ),
        ):
            result = await faz_skill(skill="network_context", params={"top_limit": 10})
        assert result["status"] == "success"
        assert result["skill"] == "network_context"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["top_destinations"] == DEST_ROWS
        assert result["result"]["top_countries"]["available"] is False
        assert result["result"]["counts"]["vpn_tunnels"] == 1

    async def test_invalid_params_rejected(self):
        result = await faz_skill(skill="network_context", params={"top_limit": 0})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
