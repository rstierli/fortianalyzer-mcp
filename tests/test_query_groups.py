"""Tests for group_by resolution."""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.query.groups import (
    LOG_GROUP_SURFACES,
    UnsupportedGroupDimension,
    resolve_group_plan,
)


class TestLogDimensions:
    """Every log group_by resolves to a FortiView view or refuses."""

    @pytest.mark.parametrize(
        "dimension,view",
        [
            ("srcip", "top-sources"),
            ("dstip", "top-destinations"),
            ("app", "top-applications"),
            ("hostname", "top-websites"),
            ("website", "top-websites"),
            ("attack", "top-threats"),
            ("threat", "top-threats"),
            ("policyid", "policy-hits"),
            ("dstcountry", "top-countries"),
        ],
    )
    def test_dimension_maps_to_its_native_view(self, dimension: str, view: str) -> None:
        plan = resolve_group_plan("traffic", dimension)
        assert plan.surface == "fortiview"
        assert plan.target == view

    def test_an_alias_resolves_before_dispatch(self) -> None:
        """source_ip is the same question as srcip."""
        plan = resolve_group_plan("traffic", "source_ip")
        assert plan.target == "top-sources"
        assert plan.dimension == "srcip"

    def test_the_plan_carries_fortiviews_all_devices_group(self) -> None:
        """FortiView spells it All_Device; logview spells it All_FortiGate.
        Forwarding logview's default returns zero rows, silently."""
        plan = resolve_group_plan("traffic", "srcip")
        assert plan.all_devices_group == "All_Device"

    def test_every_mapped_view_is_a_view_the_repo_accepts(self) -> None:
        from fortianalyzer_mcp.utils.validation import VALID_FORTIVIEW_VIEWS

        for dimension, view in LOG_GROUP_SURFACES.items():
            assert view in VALID_FORTIVIEW_VIEWS, f"{dimension} maps to unknown view {view}"


class TestAlertAndIncidentDimensions:
    """These dispatch to stats endpoints, not FortiView."""

    @pytest.mark.parametrize("dimension", ["severity", "status"])
    def test_alert_dimensions_dispatch_to_the_stats_endpoint(self, dimension: str) -> None:
        plan = resolve_group_plan("alert", dimension)
        assert plan.surface == "alert_stats"
        assert plan.target == dimension

    @pytest.mark.parametrize("dimension", ["severity", "status", "category"])
    def test_incident_dimensions_dispatch_to_incident_stats(self, dimension: str) -> None:
        plan = resolve_group_plan("incident", dimension)
        assert plan.surface == "incident_stats"


class TestRefusal:
    """A refusal that does not say what works is a dead end."""

    def test_an_unmapped_dimension_raises(self) -> None:
        with pytest.raises(UnsupportedGroupDimension):
            resolve_group_plan("traffic", "sentbyte")

    def test_the_refusal_names_sample_by(self) -> None:
        with pytest.raises(UnsupportedGroupDimension) as exc:
            resolve_group_plan("traffic", "sentbyte")
        assert "sample_by" in str(exc.value)

    def test_the_refusal_lists_the_dimensions_that_do_work(self) -> None:
        with pytest.raises(UnsupportedGroupDimension) as exc:
            resolve_group_plan("traffic", "sentbyte")
        message = str(exc.value)
        assert "srcip" in message and "policyid" in message

    def test_the_refusal_carries_the_dimension_and_the_supported_set(self) -> None:
        """Structured, so the tool can build an envelope without reparsing prose."""
        with pytest.raises(UnsupportedGroupDimension) as exc:
            resolve_group_plan("traffic", "sentbyte")
        assert exc.value.dimension == "sentbyte"
        assert "srcip" in exc.value.supported

    def test_an_alert_dimension_is_not_valid_for_logs(self) -> None:
        """Vocabularies do not share a group surface."""
        with pytest.raises(UnsupportedGroupDimension):
            resolve_group_plan("alert", "srcip")
