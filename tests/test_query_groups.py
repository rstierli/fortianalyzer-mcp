"""Tests for group_by resolution."""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.query.groups import (
    LOG_GROUP_SURFACES,
    GroupSurfacePopulationMismatch,
    UnsupportedGroupDimension,
    aggregate_breakdowns,
    resolve_group_plan,
)

#: The whole dimension table, as (logtype, dimension, view). A view aggregates
#: one log source, so the logtype is part of the key, not decoration -- see
#: TestPopulationBoundary for what the other pairings do.
DIMENSION_TABLE = [
    ("traffic", "srcip", "top-sources"),
    ("traffic", "dstip", "top-destinations"),
    ("traffic", "policyid", "policy-hits"),
    ("traffic", "dstcountry", "top-countries"),
    ("webfilter", "catdesc", "top-websites"),
    ("attack", "attack", "top-threats"),
    ("attack", "threat", "top-threats"),
]

#: Dimensions whose view does not serve what the name promises, removed from
#: the table after live probing on 7.6.7/8.0.0 (#109 review). Each must refuse
#: and name sample_by, not answer with the view's own labelling.
MISLABELLED_DIMENSIONS = [
    ("webfilter", "hostname"),
    ("webfilter", "website"),
    ("traffic", "app"),
]


class TestLogDimensions:
    """Every log group_by resolves to a FortiView view or refuses."""

    @pytest.mark.parametrize("logtype,dimension,view", DIMENSION_TABLE)
    def test_dimension_maps_to_its_native_view(
        self, logtype: str, dimension: str, view: str
    ) -> None:
        plan = resolve_group_plan(logtype, dimension)
        assert plan.surface == "fortiview"
        assert plan.target == view

    def test_an_alias_resolves_before_dispatch(self) -> None:
        """source_ip is the same question as srcip."""
        plan = resolve_group_plan("traffic", "source_ip")
        assert plan.target == "top-sources"
        assert plan.dimension == "srcip"

    @pytest.mark.parametrize("logtype,dimension", MISLABELLED_DIMENSIONS)
    def test_a_mislabelled_dimension_refuses_and_names_sample_by(
        self, logtype: str, dimension: str
    ) -> None:
        """top-websites returns catdesc/catid rows and no hostname column;
        top-applications labels its rows app_group. Dispatching either would
        report the view's own buckets under the caller's dimension name with
        is_exact: true. Refusing is the only honest answer, and the message
        has to point at the surface that does group by the field."""
        with pytest.raises(UnsupportedGroupDimension) as excinfo:
            resolve_group_plan(logtype, dimension)

        assert f"sample_by=['{dimension}']" in str(excinfo.value)

    def test_web_category_is_the_honest_webfilter_dimension(self) -> None:
        """The exact web-category surface stays reachable -- catdesc is what
        top-websites actually aggregates, so the label matches the buckets."""
        plan = resolve_group_plan("webfilter", "web_category")

        assert plan.dimension == "catdesc"
        assert plan.target == "top-websites"

    def test_the_plan_carries_fortiviews_all_devices_group(self) -> None:
        """FortiView spells it All_Device; logview spells it All_FortiGate.
        Forwarding logview's default returns zero rows, silently."""
        plan = resolve_group_plan("traffic", "srcip")
        assert plan.all_devices_group == "All_Device"

    def test_every_mapped_view_is_a_view_the_repo_accepts(self) -> None:
        from fortianalyzer_mcp.utils.validation import VALID_FORTIVIEW_VIEWS

        for dimension, surface in LOG_GROUP_SURFACES.items():
            assert surface.view in VALID_FORTIVIEW_VIEWS, (
                f"{dimension} maps to unknown view {surface.view}"
            )

    def test_every_mapped_surface_serves_a_real_logtype(self) -> None:
        """A serves entry naming a logtype the server rejects is dead code:
        the pairing could never be requested, so the dimension would look
        supported and never resolve."""
        from fortianalyzer_mcp.utils.validation import VALID_LOG_TYPES

        for dimension, surface in LOG_GROUP_SURFACES.items():
            assert surface.serves, f"{dimension} serves nothing"
            unknown = surface.serves - VALID_LOG_TYPES
            assert not unknown, f"{dimension} serves unknown logtypes {sorted(unknown)}"

    def test_the_table_covers_every_mapped_dimension(self) -> None:
        """DIMENSION_TABLE is the parametrisation above; a dimension added to
        the map without a row here would be untested."""
        assert {row[1] for row in DIMENSION_TABLE} == set(LOG_GROUP_SURFACES)


class TestPopulationBoundary:
    """A view aggregates its own log source, so logtype decides nothing.

    ``logtype="attack", group_by="srcip"`` used to dispatch to
    ``fortiview:top-sources`` -- a traffic-log view -- and return
    ``is_exact: true`` beside an echoed ``logtype: "attack"``. The counts were
    real; they just described a population nobody asked about, which is the
    one failure ``group_by``'s exactness promise cannot survive.
    """

    def test_a_dimension_is_refused_for_a_logtype_its_view_does_not_serve(self) -> None:
        with pytest.raises(GroupSurfacePopulationMismatch):
            resolve_group_plan("attack", "srcip")

    def test_that_refusal_names_sample_by(self) -> None:
        with pytest.raises(GroupSurfacePopulationMismatch) as exc:
            resolve_group_plan("attack", "srcip")
        assert "sample_by=['srcip']" in str(exc.value)

    def test_that_refusal_says_which_population_the_view_serves(self) -> None:
        """Without this the caller cannot tell a typo from a boundary."""
        with pytest.raises(GroupSurfacePopulationMismatch) as exc:
            resolve_group_plan("attack", "srcip")
        message = str(exc.value)
        assert "top-sources" in message
        assert "traffic" in message

    def test_that_refusal_carries_the_view_and_its_population(self) -> None:
        with pytest.raises(GroupSurfacePopulationMismatch) as exc:
            resolve_group_plan("attack", "srcip")
        assert exc.value.view == "top-sources"
        assert exc.value.serves == frozenset({"traffic"})

    def test_it_is_still_an_unsupported_group_dimension(self) -> None:
        """One ``except`` in query_logs catches both refusals."""
        with pytest.raises(UnsupportedGroupDimension):
            resolve_group_plan("attack", "srcip")

    @pytest.mark.parametrize("logtype,dimension,view", DIMENSION_TABLE)
    def test_every_other_logtype_is_refused_for_every_dimension(
        self, logtype: str, dimension: str, view: str
    ) -> None:
        """The whole table, per logtype: exactly the mapped logtype resolves."""
        for other in ("traffic", "webfilter", "attack", "event", "app-ctrl", "dns"):
            if other in LOG_GROUP_SURFACES[dimension].serves:
                assert resolve_group_plan(other, dimension).target == view
                continue
            with pytest.raises(UnsupportedGroupDimension):
                resolve_group_plan(other, dimension)

    def test_a_logtype_no_view_serves_can_group_nothing_and_says_so(self) -> None:
        """An empty supported set is an answer, not a broken message."""
        with pytest.raises(UnsupportedGroupDimension) as exc:
            resolve_group_plan("event", "srcip")
        assert exc.value.supported == []
        assert "No dimension can be grouped exactly for event" in str(exc.value)
        assert "sample_by" in str(exc.value)

    def test_the_supported_set_in_a_refusal_is_scoped_to_the_logtype(self) -> None:
        """Listing traffic's dimensions in an attack refusal sends the caller
        straight back into the same wall."""
        with pytest.raises(UnsupportedGroupDimension) as exc:
            resolve_group_plan("attack", "sentbyte")
        assert sorted(exc.value.supported) == ["attack", "threat"]


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


class TestAggregateBreakdowns:
    """One scan, several independent breakdowns."""

    ROWS = [
        {"proto": "6", "dstport": "443", "app": "HTTPS", "service": "HTTPS"},
        {"proto": "6", "dstport": "443", "app": "HTTPS", "service": "HTTPS"},
        {"proto": "6", "dstport": "80", "app": "HTTP", "service": "HTTP"},
        {"proto": "1", "dstport": "0", "app": "PING", "service": "PING"},
    ]

    def test_counts_are_per_dimension_not_a_cross_tab(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["app", "proto"])
        assert set(result) == {"app", "proto"}
        assert result["app"][0] == {"value": "HTTPS", "hits": 2}

    def test_buckets_are_ordered_by_hits_descending(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["app"])
        hits = [bucket["hits"] for bucket in result["app"]]
        assert hits == sorted(hits, reverse=True)

    def test_top_n_truncates(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["app"], top_n=1)
        assert len(result["app"]) == 1
        assert result["app"][0]["value"] == "HTTPS"

    def test_top_n_zero_returns_every_bucket(self) -> None:
        """get_policy_port_analysis returned the complete port list; that survives."""
        result = aggregate_breakdowns(self.ROWS, ["app"], top_n=0)
        assert len(result["app"]) == 3

    def test_a_derived_dimension_works(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["port"])
        assert {"value": "6/443", "hits": 2} in result["port"]

    def test_portless_rows_are_excluded_from_the_port_breakdown(self) -> None:
        """The ICMP row has dstport 0, which is not a port."""
        result = aggregate_breakdowns(self.ROWS, ["port"])
        assert all(bucket["value"] != "1/0" for bucket in result["port"])

    def test_icmp_breakdown_uses_the_derived_decoding(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["icmp_type_code"])
        assert result["icmp_type_code"] == [{"value": "type=8/code=0", "hits": 1}]

    def test_rows_missing_the_dimension_are_skipped_not_bucketed_as_unknown(self) -> None:
        rows = [{"app": "HTTPS"}, {"other": 1}]
        result = aggregate_breakdowns(rows, ["app"])
        assert result["app"] == [{"value": "HTTPS", "hits": 1}]

    def test_no_dimensions_yields_an_empty_mapping(self) -> None:
        assert aggregate_breakdowns(self.ROWS, []) == {}

    def test_no_rows_yields_an_empty_bucket_list_per_dimension(self) -> None:
        """The dimension key survives so the caller sees it was asked for."""
        assert aggregate_breakdowns([], ["app"]) == {"app": []}

    def test_ties_are_broken_deterministically_by_value(self) -> None:
        rows = [{"app": "B"}, {"app": "A"}]
        result = aggregate_breakdowns(rows, ["app"])
        assert [b["value"] for b in result["app"]] == ["A", "B"]
