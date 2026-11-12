"""Wave-3 analysis skill: hunt.

Same conventions as ``test_skills_investigate_deep.py``: composed handlers
import their tool functions lazily, so they are patched at their defining
modules with ``autospec=True``; the dispatcher path is exercised through
``faz_skill``. ``hunt`` has two halves — a log_search + threat_intel sweep
and a percentile-calibrated UEBA behaviour profile — so the mocks are
``query_logs`` (sweep), the SOAR readers (threat_intel), and the UEBA
endpoint/end-user + alert readers (behaviour). The estate-stats readers are
optional, so both estate paths are driven explicitly: their absence and
their presence are simulated on the module rather than inferred from
whether this branch happens to carry them.
"""

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.catalog import SKILLS
from fortianalyzer_mcp.skills.models import (
    SCHEMA_VERSION,
    EntityBehavior,
    EstateContext,
    FeatureGap,
    HuntParams,
    HuntSweep,
    IndicatorSubject,
)
from fortianalyzer_mcp.tools import ueba_tools
from tests.conftest import import_dispatcher_isolated

(faz_skill,) = import_dispatcher_isolated("faz_skill")

GET_ALERTS = "fortianalyzer_mcp.tools.event_tools.get_alerts"
GET_FORTIVIEW_DATA = "fortianalyzer_mcp.tools.fortiview_tools.get_fortiview_data"
GET_LINKED = "fortianalyzer_mcp.tools.soar_tools.get_linked_indicators"
GET_ENRICH = "fortianalyzer_mcp.tools.soar_tools.get_indicator_enrichment"
GET_ENDPOINTS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoints"
GET_VULNS = "fortianalyzer_mcp.tools.ueba_tools.get_endpoint_vulnerabilities"
GET_ENDUSERS = "fortianalyzer_mcp.tools.ueba_tools.get_endusers"
QUERY_LOGS = "fortianalyzer_mcp.tools.log_tools.query_logs"


def t(target: str, **kwargs: Any) -> Any:
    """``patch`` a tool function with autospec (signature-validating)."""
    return patch(target, autospec=True, **kwargs)


def ok(**fields: Any) -> dict[str, Any]:
    """A successful tool envelope."""
    return {"status": "success", **fields}


def logs_ok(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """A successful query_logs envelope."""
    return {"status": "success", "tid": 1, "logs": rows, "total": len(rows)}


def full_page(rows: list[dict[str, Any]], floor: int) -> dict[str, Any]:
    """A query_logs page that filled, as 2.17.0 reports it: more rows may
    exist and ``total`` is a floor, not the window's count."""
    return {
        "status": "success",
        "tid": 1,
        "logs": rows,
        "count": len(rows),
        "total": floor,
        "total_is_known": False,
        "total_is_lower_bound": True,
        "has_more": True,
    }


def by_logtype(**responses: dict[str, Any]) -> Any:
    """Side effect for ``query_logs``, dispatching on logtype."""

    def _route(**kwargs: Any) -> dict[str, Any]:
        return responses[kwargs["logtype"]]

    return _route


@pytest.fixture
def soar() -> Any:
    """Quiet SOAR and threat-landscape readers, for an indicator sweep."""
    with (
        t(GET_LINKED, return_value=ok(data=[])),
        t(GET_ENRICH, return_value=ok(data=[])),
        t(GET_FORTIVIEW_DATA, return_value=ok(data=[])),
    ):
        yield


# The fixture host: risk_score 0.248 among a crowd of ~0.1x hosts, plus
# critical/high vuln-stats — the RFC's "genuinely high-risk entity" case.
HOT_ENDPOINT = {
    "epid": 6676,
    "epname": "EU-83LP4Y2",
    "epip": "192.0.2.7",
    "risk_score": 0.248,
    "importance": "high",
    "vuln-stats": {"cnt_cri": 3, "cnt_hig": 12, "cnt_med": 8, "cnt_low": 10},
}
# The low-risk crowd (0.1x) the hot host must be distinguished from.
CROWD = [
    {"epid": i, "epname": f"host-{i}", "epip": f"10.0.0.{i}", "risk_score": 0.10 + (i % 5) * 0.01}
    for i in range(1, 40)
]
ESTATE = CROWD + [HOT_ENDPOINT]

# The ADOM-wide count snapshot the Layer-1 estate reader returns.
ENDPOINT_STATS = {"total-count": "40", "new-count": "2", "identified-count": "37"}

ENDUSER = {"euid": 42, "euname": "jdoe", "importance": "high"}
BOTNET_ALERT = {
    "alertid": "a-1",
    "alerttype": "Default-Botnet-Communication-Detection-By-Endpoint",
    "severity": "critical",
}
BENIGN_ALERT = {"alertid": "a-2", "alerttype": "Traffic-Baseline", "severity": "low"}
THREATS = [{"threat": "Backdoor.Agent", "threatweight": 500}]


class TestHuntCatalog:
    def test_registered_as_analysis_tier(self):
        assert "hunt" in SKILLS
        assert SKILLS["hunt"].tier == "analysis"

    def test_params_forbid_unknown_keys(self):
        with pytest.raises(ValidationError):
            HuntParams(entity="epid:6676", no_such_parameter=True)

    def test_requires_exactly_one_subject(self):
        with pytest.raises(ValidationError, match="exactly one subject"):
            HuntParams()
        with pytest.raises(ValidationError, match="exactly one subject"):
            HuntParams(entity="epid:1", indicator=IndicatorSubject(value="1.2.3.4", type="IP"))
        with pytest.raises(ValidationError, match="exactly one subject"):
            HuntParams(indicator=IndicatorSubject(value="1.2.3.4", type="IP"), filter="x==y")

    def test_filter_and_ttp_together_are_one_subject(self):
        # filter+ttp count as a single (hypothesis) shape, not two subjects.
        HuntParams(filter='attack like "%x%"', ttp="T1071")


class TestHuntSweep:
    async def test_indicator_ip_sweep_and_threat_intel(self):
        with (
            t(QUERY_LOGS, return_value=logs_ok([{"srcip": "198.21.33.3"}])) as ql,
            t(GET_LINKED, return_value=ok(data=[])),
            t(
                GET_ENRICH,
                return_value=ok(
                    data=[{"value": "198.21.33.3", "enrichment-reputation": "Malicious"}]
                ),
            ),
            t(GET_FORTIVIEW_DATA, return_value=ok(data=THREATS)) as threats_mock,
        ):
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="198.21.33.3", type="IP"),
                    sweep_logtypes=["traffic", "attack"],
                )
            )
        assert result.subject_type == "indicator"
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == "(srcip==198.21.33.3 or dstip==198.21.33.3)"
        assert result.sweep.sweep_searches_run == 2
        assert result.sweep.total_matches == 2  # one row per logtype
        # Every sweep search ran on the indicator pivot.
        assert all(
            c.kwargs["filter"] == "(srcip==198.21.33.3 or dstip==198.21.33.3)"
            for c in ql.call_args_list
        )
        assert threats_mock.call_args.kwargs["view_name"] == "top-threats"
        # An IP indicator gets SOAR reputation; behaviour half is a gap.
        assert not isinstance(result.sweep.threat_intel, FeatureGap)
        assert isinstance(result.behavior, FeatureGap)

    async def test_hash_indicator_has_no_soar_reputation(self):
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="deadbeef", type="Hash"),
                    sweep_logtypes=["traffic"],
                )
            )
        assert isinstance(result.sweep, HuntSweep)
        assert (
            result.sweep.pivot_filter
            == '(filehash like "%deadbeef%" or analyticscksum like "%deadbeef%")'
        )
        assert isinstance(result.sweep.threat_intel, FeatureGap)
        assert (
            ql.call_args.kwargs["filter"]
            == '(filehash like "%deadbeef%" or analyticscksum like "%deadbeef%")'
        )

    async def test_filter_hypothesis_sweep(self):
        with t(QUERY_LOGS, return_value=logs_ok([{"x": 1}])) as ql:
            result = await handlers.run_hunt(
                HuntParams(filter="dstport==4444", ttp="T1571", sweep_logtypes=["traffic"])
            )
        assert result.subject_type == "hypothesis"
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == "dstport==4444"
        assert result.sweep.ttp == "T1571"
        assert ql.call_args.kwargs["filter"] == "dstport==4444"

    async def test_ip_indicator_is_matched_as_source_or_destination(self, soar):
        """#184: an address that is a destination sits in dstip, so an IP
        indicator is matched on either side, on every swept log type."""
        clause = "(srcip==203.0.113.7 or dstip==203.0.113.7)"
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(indicator=IndicatorSubject(value="203.0.113.7", type="IP"))
            )
        assert [c.kwargs["logtype"] for c in ql.call_args_list] == [
            "traffic",
            "attack",
            "app-ctrl",
            "dns",
        ]
        assert [c.kwargs["filter"] for c in ql.call_args_list] == [clause] * 4
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == clause
        assert [m.pivot_filter for m in result.sweep.matches] == [clause] * 4

    async def test_domain_indicator_is_matched_on_qname_in_dns_logs(self, soar):
        """#184: a dns row carries the queried name in qname and no hostname."""
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(indicator=IndicatorSubject(value="bad.example.com", type="Domain"))
            )
        sent = {c.kwargs["logtype"]: c.kwargs["filter"] for c in ql.call_args_list}
        assert sent == {
            "traffic": "hostname==bad.example.com",
            "attack": "hostname==bad.example.com",
            "app-ctrl": "hostname==bad.example.com",
            "dns": "qname==bad.example.com",
        }
        # The clause differs by log type: each match shows the one its search
        # ran on, and the sweep claims no single clause.
        assert isinstance(result.sweep, HuntSweep)
        assert {m.logtype: m.pivot_filter for m in result.sweep.matches} == sent
        assert result.sweep.pivot_filter is None

    @pytest.mark.parametrize("logtype", ["dns", "DNS"])
    async def test_domain_sweep_of_dns_alone_reports_its_one_clause(self, soar, logtype):
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="bad.example.com", type="Domain"),
                    sweep_logtypes=[logtype],
                )
            )
        assert ql.call_args.kwargs["filter"] == "qname==bad.example.com"
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == "qname==bad.example.com"

    async def test_hash_indicator_sweeps_virus_logs_on_either_hash_field(self):
        """#184: virus logs carry the file hash, in analyticscksum on 7.6.7
        and possibly in filehash on another build, and virus is not one of
        the default sweep log types."""
        digest = "d41d8cd98f00b204e9800998ecf8427e"
        clause = (
            '(filehash like "%d41d8cd98f00b204e9800998ecf8427e%" or '
            'analyticscksum like "%d41d8cd98f00b204e9800998ecf8427e%")'
        )
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(indicator=IndicatorSubject(value=digest, type="Hash"))
            )
        assert sorted(c.kwargs["logtype"] for c in ql.call_args_list) == [
            "app-ctrl",
            "attack",
            "dns",
            "traffic",
            "virus",
        ]
        assert [c.kwargs["filter"] for c in ql.call_args_list] == [clause] * 5
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == clause
        assert result.sweep.sweep_searches_run == 5
        # The result says the log type was added.
        assert any(w.startswith("sweep:") and "'virus' added" in w for w in result.warnings)

    async def test_hash_sweep_that_names_virus_does_not_add_it_again(self):
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="deadbeef", type="Hash"),
                    sweep_logtypes=["traffic", "virus"],
                )
            )
        assert [c.kwargs["logtype"] for c in ql.call_args_list] == ["traffic", "virus"]
        assert not any("'virus' added" in w for w in result.warnings)

    async def test_added_virus_search_is_not_the_one_the_cap_drops(self):
        # virus is the log type that carries the hash, so it is swept first
        # and the fan-out cap drops a caller's log type instead, by name.
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="deadbeef", type="Hash"),
                    sweep_logtypes=["traffic"],
                    max_sweep_searches=1,
                )
            )
        assert [c.kwargs["logtype"] for c in ql.call_args_list] == ["virus"]
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.sweep_searches_dropped == 1
        assert any("'traffic' search dropped" in w for w in result.warnings)

    @pytest.mark.parametrize(
        ("subject", "clause"),
        [
            (
                {"indicator": {"value": "bad.example.com/x", "type": "URL"}},
                'url=="bad.example.com/x"',
            ),
            ({"filter": "dstport==4444"}, "dstport==4444"),
            ({"ttp": "T1071"}, 'attack like "%T1071%"'),
        ],
        ids=["url", "filter", "ttp"],
    )
    async def test_other_subjects_sweep_on_the_clause_they_did(self, soar, subject, clause):
        # Not changed by #184: one clause, the caller's log types, no more.
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(HuntParams(**subject))
        assert [c.kwargs["logtype"] for c in ql.call_args_list] == [
            "traffic",
            "attack",
            "app-ctrl",
            "dns",
        ]
        assert [c.kwargs["filter"] for c in ql.call_args_list] == [clause] * 4
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == clause

    async def test_no_search_runs_on_a_clause_the_result_does_not_show(self):
        """A failed search still shows the clause it ran on; a search the
        cap dropped never ran and shows none."""
        with t(
            QUERY_LOGS,
            side_effect=by_logtype(
                virus=logs_ok([{"analyticscksum": "deadbeef"}]),
                traffic={"status": "error", "message": "logview unavailable"},
            ),
        ) as ql:
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="deadbeef", type="Hash"),
                    sweep_logtypes=["virus", "traffic", "dns", "attack"],
                    max_sweep_searches=2,
                )
            )
        assert isinstance(result.sweep, HuntSweep)
        ran = [(c.kwargs["logtype"], c.kwargs["filter"]) for c in ql.call_args_list]
        shown = [(m.logtype, m.pivot_filter) for m in result.sweep.matches]
        assert shown[: len(ran)] == ran
        assert shown[len(ran) :] == [("dns", None), ("attack", None)]

    async def test_sweep_fanout_cap_drops_and_warns(self):
        # 4 logtypes but a cap of 2 -> 2 run, 2 dropped, no silent loss.
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(
                    filter="x==y",
                    sweep_logtypes=["traffic", "attack", "app-ctrl", "dns"],
                    max_sweep_searches=2,
                )
            )
        assert ql.call_count == 2
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.sweep_searches_run == 2
        assert result.sweep.sweep_searches_dropped == 2
        assert any("dropped by the fan-out cap" in w for w in result.warnings)
        dropped = [m.logtype for m in result.sweep.matches if isinstance(m.rows, FeatureGap)]
        assert set(dropped) == {"app-ctrl", "dns"}

    async def test_window_capped_to_seven_day(self):
        with t(QUERY_LOGS, return_value=logs_ok([])) as ql:
            result = await handlers.run_hunt(
                HuntParams(filter="x==y", sweep_logtypes=["traffic"], time_range="30-day")
            )
        assert result.time_range == "7-day"
        assert ql.call_args.kwargs["time_range"] == "7-day"
        assert any("capped to '7-day'" in w for w in result.warnings)

    async def test_sweep_search_failure_degrades_to_gap(self):
        with t(QUERY_LOGS, return_value={"status": "error", "message": "logview unavailable"}):
            result = await handlers.run_hunt(HuntParams(filter="x==y", sweep_logtypes=["traffic"]))
        assert isinstance(result.sweep, HuntSweep)
        assert isinstance(result.sweep.matches[0].rows, FeatureGap)
        assert any("search unavailable" in w for w in result.warnings)


def unbounded_lookup_lines(warnings: list[str]) -> list[str]:
    """The lines that say the indicator lookup ignored the hunt window."""
    return [w for w in warnings if w.startswith("threat_intel:") and "not limited to" in w]


class TestHuntIndicatorWindow:
    """#184: reputation is a property of the indicator, not of the window
    being hunted, so the indicator read runs unbounded. SOAR otherwise hides
    an indicator last seen before the window."""

    async def test_reputation_lookup_is_unbounded_and_the_result_says_so(self):
        with (
            t(QUERY_LOGS, return_value=logs_ok([])) as ql,
            t(
                GET_ENRICH,
                return_value=ok(
                    data=[{"value": "203.0.113.7", "enrichment-reputation": "Malicious"}]
                ),
            ) as enrich,
            t(GET_FORTIVIEW_DATA, return_value=ok(data=THREATS)) as threats_mock,
        ):
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="203.0.113.7", type="IP"),
                    sweep_logtypes=["traffic"],
                )
            )
        assert enrich.call_args.kwargs["time_range"] is None
        assert isinstance(result.sweep, HuntSweep)
        assert not isinstance(result.sweep.threat_intel, FeatureGap)
        assert result.sweep.threat_intel.indicators[0].reputation == "Malicious"
        # The sweep and the threat landscape are views of the window and stay on it.
        assert ql.call_args.kwargs["time_range"] == "7-day"
        assert threats_mock.call_args.kwargs["view_name"] == "top-threats"
        assert threats_mock.call_args.kwargs["time_range"] == "7-day"
        (line,) = unbounded_lookup_lines(result.warnings)
        assert "7-day" in line

    async def test_no_such_line_when_no_indicator_lookup_ran(self):
        with t(QUERY_LOGS, return_value=logs_ok([])):
            result = await handlers.run_hunt(
                HuntParams(filter="dstport==4444", sweep_logtypes=["traffic"])
            )
        assert isinstance(result.sweep, HuntSweep)
        assert isinstance(result.sweep.threat_intel, FeatureGap)
        assert unbounded_lookup_lines(result.warnings) == []

    async def test_envelope_says_the_reputation_lookup_ignored_the_window(self, soar):
        with t(QUERY_LOGS, return_value=logs_ok([])):
            result = await faz_skill(
                skill="hunt",
                params={
                    "indicator": {"value": "bad.example.com", "type": "Domain"},
                    "sweep_logtypes": ["dns"],
                },
            )
        assert result["status"] == "success"
        assert len(unbounded_lookup_lines(result["result"]["warnings"])) == 1


class TestHuntSweepCounts:
    """#184: a sweep search returns one page. A page that filled is not the
    number of matches, and a sweep whose searches all failed is not a sweep
    that matched nothing."""

    ROW = {"logid": "0000000013"}

    async def test_full_pages_make_the_total_a_lower_bound(self, soar):
        # The live case: a domain hunt reported total_matches=200, the rows
        # of its full pages, against thousands of matching rows.
        with t(QUERY_LOGS, return_value=full_page([self.ROW] * 100, floor=6450)):
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="bad.example.com", type="Domain"),
                    sweep_logtypes=["traffic", "dns"],
                )
            )
        assert isinstance(result.sweep, HuntSweep)
        assert [(m.row_count, m.has_more) for m in result.sweep.matches] == [
            (100, True),
            (100, True),
        ]
        assert result.sweep.total_matches == 200
        assert result.sweep.total_matches_is_lower_bound is True
        assert "sweep: at least 200 matches" in result.headline
        assert "lower bound" in result.headline

    async def test_one_full_page_is_enough_to_bound_the_total(self, soar):
        # The other live case: an IP hunt reported 100, one page size.
        with t(
            QUERY_LOGS,
            side_effect=by_logtype(
                traffic=logs_ok([self.ROW] * 3),
                dns=full_page([self.ROW] * 100, floor=7364),
            ),
        ):
            result = await handlers.run_hunt(
                HuntParams(
                    indicator=IndicatorSubject(value="203.0.113.7", type="IP"),
                    sweep_logtypes=["traffic", "dns"],
                )
            )
        assert isinstance(result.sweep, HuntSweep)
        assert [(m.logtype, m.row_count, m.has_more) for m in result.sweep.matches] == [
            ("traffic", 3, False),
            ("dns", 100, True),
        ]
        assert result.sweep.total_matches == 103
        assert result.sweep.total_matches_is_lower_bound is True
        assert "sweep: at least 103 matches" in result.headline
        assert "lower bound" in result.headline

    @pytest.mark.parametrize(
        "page_says",
        [
            {"has_more": True, "total": None, "total_is_known": False},
            {"has_more": False, "total": 40, "total_is_lower_bound": True},
        ],
        ids=["has_more", "total_is_lower_bound"],
    )
    async def test_either_page_signal_marks_the_search_truncated(self, page_says):
        page = {"status": "success", "tid": 1, "logs": [self.ROW] * 2, **page_says}
        with t(QUERY_LOGS, return_value=page):
            result = await handlers.run_hunt(
                HuntParams(filter="dstport==4444", sweep_logtypes=["traffic"])
            )
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.matches[0].has_more is True
        assert result.sweep.total_matches_is_lower_bound is True
        assert "at least 2 matches" in result.headline

    async def test_complete_pages_are_still_a_count(self):
        with t(QUERY_LOGS, return_value=logs_ok([self.ROW] * 3)):
            result = await handlers.run_hunt(
                HuntParams(filter="dstport==4444", sweep_logtypes=["traffic", "dns"])
            )
        assert isinstance(result.sweep, HuntSweep)
        assert [m.has_more for m in result.sweep.matches] == [False, False]
        assert result.sweep.total_matches == 6
        assert result.sweep.total_matches_is_lower_bound is False
        assert result.headline == "hypothesis dstport==4444; sweep: 6 matches across 2 searches"

    async def test_headline_says_the_sweep_failed_when_every_search_did(self):
        with t(QUERY_LOGS, return_value={"status": "error", "message": "logview unavailable"}):
            result = await handlers.run_hunt(
                HuntParams(filter="dstport==4444", sweep_logtypes=["traffic", "dns"])
            )
        assert isinstance(result.sweep, HuntSweep)
        assert all(isinstance(m.rows, FeatureGap) for m in result.sweep.matches)
        assert "sweep: failed" in result.headline
        assert "0 matches" not in result.headline

    async def test_a_sweep_with_one_answer_is_not_a_failed_sweep(self):
        with t(
            QUERY_LOGS,
            side_effect=by_logtype(
                traffic={"status": "error", "message": "logview unavailable"},
                dns=logs_ok([self.ROW]),
            ),
        ):
            result = await handlers.run_hunt(
                HuntParams(filter="dstport==4444", sweep_logtypes=["traffic", "dns"])
            )
        assert result.headline == "hypothesis dstport==4444; sweep: 1 matches across 2 searches"


class TestHuntBehaviorAlertPage:
    """#184: the behavioural detections are narrowed from one page of 200
    alerts, so a page that filled says nothing about the alerts behind it."""

    QUIET_USER = {"euid": 42, "euname": "jdoe", "importance": "low"}

    @staticmethod
    def alerts(count: int, *extra: dict[str, Any]) -> list[dict[str, Any]]:
        """``count`` alerts that are not behavioural, then ``extra``."""
        return [{**BENIGN_ALERT, "alertid": f"b-{i}"} for i in range(count)] + list(extra)

    async def hunt(self, entity: str, alerts: list[dict[str, Any]]) -> Any:
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ENDUSERS, return_value=ok(data=[self.QUIET_USER])),
            t(GET_ALERTS, return_value=ok(data=alerts)),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            return await handlers.run_hunt(HuntParams(entity=entity, sweep_logtypes=["traffic"]))

    @pytest.mark.parametrize("entity", ["epid:5", "euid:42"])
    async def test_a_full_alert_page_is_not_a_clean_negative(self, entity):
        result = await self.hunt(entity, self.alerts(200))
        b = result.behavior
        assert isinstance(b, EntityBehavior)
        assert b.detection_count == 0
        assert b.alerts_truncated is True
        assert any(w.startswith("behavior[") and "first 200 alerts" in w for w in result.warnings)
        # Neither the basis nor the headline reports none found in the window.
        assert "no behavioural/IOC detections in the window" not in b.anomaly_basis
        assert any("first 200 alerts" in reason for reason in b.anomaly_basis)
        assert not result.headline.endswith("0 detections)")
        assert "0 detections in the first 200 alerts" in result.headline

    @pytest.mark.parametrize("entity", ["epid:5", "euid:42"])
    async def test_a_page_that_did_not_fill_is_a_clean_negative(self, entity):
        result = await self.hunt(entity, self.alerts(199))
        b = result.behavior
        assert isinstance(b, EntityBehavior)
        assert b.detection_count == 0
        assert b.alerts_truncated is False
        assert not any("200 alerts" in w for w in result.warnings)
        assert "no behavioural/IOC detections in the window" in b.anomaly_basis
        assert result.headline.endswith("0 detections)")

    async def test_detections_found_on_a_full_page_still_carry_the_warning(self):
        result = await self.hunt("epid:5", self.alerts(199, BOTNET_ALERT))
        b = result.behavior
        assert isinstance(b, EntityBehavior)
        assert b.detection_count == 1
        assert b.anomalous is True
        assert b.alerts_truncated is True
        assert any(w.startswith("behavior[") and "first 200 alerts" in w for w in result.warnings)

    async def test_the_page_is_full_at_the_limit_the_hunt_asked_for(self):
        """The threshold is the limit of the request: an appliance that returns
        as many alerts as it was asked for has filled the page."""
        asked: dict[str, Any] = {}

        def get_alerts(**kwargs: Any) -> dict[str, Any]:
            asked.update(kwargs)
            return ok(data=self.alerts(kwargs["limit"]))

        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, side_effect=get_alerts),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(
                HuntParams(entity="epid:5", sweep_logtypes=["traffic"])
            )

        assert asked["limit"] == 200
        assert isinstance(result.behavior, EntityBehavior)
        assert result.behavior.alerts_truncated is True


class TestHuntBehaviorPercentile:
    async def test_high_risk_entity_flagged_among_low_risk_peers(self):
        # THE calibration test: 0.248 among ~40 hosts at 0.10-0.14 must land at
        # a high percentile and be flagged anomalous — a fixed "risk>0.5" cut
        # would never fire on 0.248.
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, return_value=ok(data=[BOTNET_ALERT, BENIGN_ALERT])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(
                HuntParams(entity="epid:6676", sweep_logtypes=["traffic"])
            )
        assert result.subject_type == "entity"
        assert isinstance(result.behavior, EntityBehavior)
        b = result.behavior
        assert b.entity_type == "endpoint"
        assert b.risk_score == 0.248
        # 0.248 is the max of the estate -> 100th percentile, >= default 90.
        assert b.risk_percentile == 100.0
        assert b.anomalous is True
        # Percentile is the driving flag, and the basis is auditable.
        assert any("percentile" in reason and "ANOMALOUS" in reason for reason in b.anomaly_basis)
        # vuln-stats surfaced per severity.
        assert b.vuln_stats["critical"] == 3
        assert b.vuln_stats["high"] == 12
        # Only the behavioural alert is kept (benign one filtered out).
        assert not isinstance(b.behavioral_detections, FeatureGap)
        assert b.detection_count == 1
        assert b.behavioral_detections[0]["alertid"] == "a-1"

    async def test_low_risk_entity_not_flagged_by_percentile(self):
        # A mid-pack host with no vulns and no detections is NOT anomalous —
        # proves the percentile actually discriminates.
        target = {"epid": 5, "epname": "host-5", "epip": "10.0.0.5", "risk_score": 0.11}
        estate = CROWD + [HOT_ENDPOINT]  # target already in CROWD (epid 5)
        assert target["risk_score"] < 0.15
        with (
            t(GET_ENDPOINTS, return_value=ok(data=estate)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:5"))
        assert isinstance(result.behavior, EntityBehavior)
        b = result.behavior
        assert b.risk_percentile is not None
        assert b.risk_percentile < 90.0
        assert b.anomalous is False

    async def test_serious_vuln_fires_even_if_mid_percentile(self):
        # A host mid-pack on risk but carrying a critical CVE is still flagged.
        vuln_host = {
            "epid": 900,
            "epname": "host-900",
            "epip": "10.0.9.0",
            "risk_score": 0.11,
            "vuln-stats": {"cnt_cri": 1},
        }
        with (
            t(GET_ENDPOINTS, return_value=ok(data=CROWD + [vuln_host, HOT_ENDPOINT])),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:900"))
        assert isinstance(result.behavior, EntityBehavior)
        assert result.behavior.anomalous is True
        assert any("serious vulnerabilities" in r for r in result.behavior.anomaly_basis)

    async def test_single_endpoint_estate_yields_no_percentile(self):
        # A one-host estate cannot be ranked; no false "100th percentile".
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[HOT_ENDPOINT])),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:6676"))
        assert isinstance(result.behavior, EntityBehavior)
        assert result.behavior.risk_percentile is None
        # Still anomalous — the serious vuln-stats flag carries it.
        assert result.behavior.anomalous is True
        assert any("too small to rank" in r for r in result.behavior.anomaly_basis)

    async def test_no_reader_value_becomes_an_output_dict_key(self):
        # PR #90 masking review: OutputMasker rewrites dict values but never
        # keys, so no reader-supplied identifier may surface as a key in hunt's
        # output. The vuln grouping keys an internal dict by epid; this pins
        # that it stays internal — a refactor leaking it would leak the id past
        # the masker.
        vulns = ok(data=[{"epid": 6676, "vuln": [{"cve": "CVE-2025-0001"}]}])
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[HOT_ENDPOINT] + CROWD)),
            t(GET_VULNS, return_value=vulns),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:6676"))

        def all_keys(obj: Any) -> set[str]:
            keys: set[str] = set()
            if isinstance(obj, dict):
                for k, v in obj.items():
                    keys.add(str(k))
                    keys |= all_keys(v)
            elif isinstance(obj, list):
                for item in obj:
                    keys |= all_keys(item)
            return keys

        keys = all_keys(result.model_dump())
        # epid and epname are reader-supplied; neither may appear as a dict key.
        assert "6676" not in keys
        assert "EU-83LP4Y2" not in keys

    async def test_enduser_has_no_risk_score(self):
        with (
            t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])),
            t(GET_ALERTS, return_value=ok(data=[BOTNET_ALERT])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="euid:42"))
        assert isinstance(result.behavior, EntityBehavior)
        b = result.behavior
        assert b.entity_type == "enduser"
        assert b.risk_score is None
        assert b.risk_percentile is None
        assert b.importance == "high"
        # importance high + a detection -> anomalous.
        assert b.anomalous is True

    async def test_endpoint_address_no_literal_can_hold_degrades_both_halves(self):
        """The behaviour half and the entity-scoped sweep each report the gap."""
        estate = [dict(ep) for ep in ESTATE]
        estate[4] = {**estate[4], "epip": "value\\"}
        assert estate[4]["epid"] == 5
        with (
            t(GET_ENDPOINTS, return_value=ok(data=estate)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:5"))
        assert isinstance(result.behavior, EntityBehavior)
        assert any(w.startswith("behavior[") and "backslash" in w for w in result.warnings)
        assert any(w.startswith("hunt:") and "sweep skipped" in w for w in result.warnings)

    async def test_enduser_name_no_literal_can_hold_degrades_the_pivot(self):
        """A name that ends in a backslash cannot be written into a filter
        (#164); the hunt still runs, with the gap in the warnings."""
        user = {"euid": 42, "euname": "value\\", "importance": "high"}
        with (
            t(GET_ENDUSERS, return_value=ok(data=[user])),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="euid:42"))
        assert isinstance(result.behavior, EntityBehavior)
        assert any("backslash" in w for w in result.warnings)

    async def test_entity_subject_runs_entity_scoped_sweep(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])) as ql,
        ):
            result = await handlers.run_hunt(
                HuntParams(entity="epid:6676", sweep_logtypes=["traffic"])
            )
        # The entity subject also sweeps on its own srcip pivot.
        assert isinstance(result.sweep, HuntSweep)
        assert result.sweep.pivot_filter == "srcip==192.0.2.7"
        assert ql.call_args.kwargs["filter"] == "srcip==192.0.2.7"

    async def test_estate_read_is_unwindowed(self):
        # The percentile denominator is the full inventory: the estate read
        # must NOT pass a time_range (which filters by first-seen and would
        # shrink the population / drop the target). Live-verified regression.
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)) as eps,
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            await handlers.run_hunt(HuntParams(entity="epid:6676", time_range="30-day"))
        assert eps.call_args.kwargs.get("time_range") is None

    async def test_string_risk_scores_are_ranked(self):
        # Live FAZ returns risk_score as a float-valued string; the population
        # and the target value must both coerce, or nothing ranks.
        estate = [
            {"epid": 1, "epname": "a", "epip": "10.0.0.1", "risk_score": "0.10"},
            {"epid": 2, "epname": "b", "epip": "10.0.0.2", "risk_score": "0.11"},
            {"epid": 3, "epname": "c", "epip": "10.0.0.3", "risk_score": "0.25"},
        ]
        with (
            t(GET_ENDPOINTS, return_value=ok(data=estate)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:3"))
        assert isinstance(result.behavior, EntityBehavior)
        assert result.behavior.risk_score == 0.25
        assert result.behavior.risk_percentile == 100.0
        assert result.behavior.anomalous is True

    async def test_endpoint_not_found_raises(self):
        with t(GET_ENDPOINTS, return_value=ok(data=CROWD)):  # no epid 6676
            with pytest.raises(handlers.SkillExecutionError, match="not found"):
                await handlers.run_hunt(HuntParams(entity="epid:6676"))

    async def test_unrecognized_entity_raises(self):
        with pytest.raises(handlers.SkillExecutionError, match="entity must be"):
            await handlers.run_hunt(HuntParams(entity="host:foo"))


class TestHuntEstateContext:
    async def test_estate_stats_absent_reader_degrades_to_gap(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        # The estate-stats readers are optional: _hunt_estate imports them
        # inside a try/except ImportError and the whole section degrades to a
        # gap when they are missing (never a hard fail). Their absence is
        # simulated here rather than inferred from the branch not carrying
        # them, so this path keeps its coverage once the Layer-1 readers land.
        monkeypatch.delattr(ueba_tools, "get_endpoint_stats", raising=False)
        monkeypatch.delattr(ueba_tools, "get_enduser_stats", raising=False)
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:6676"))
        assert isinstance(result.estate, FeatureGap)
        assert "not available in this build" in result.estate.reason

    async def test_estate_stats_present_composes_context(self, monkeypatch: pytest.MonkeyPatch):
        # With the readers importable the section is an EstateContext whose
        # halves degrade one at a time, not a single gap. Injected for the
        # same reason the absence is: the assertion then holds whether or not
        # this branch carries Layer 1.
        async def endpoint_stats(**_: Any) -> dict[str, Any]:
            return ok(data=[ENDPOINT_STATS])

        monkeypatch.setattr(ueba_tools, "get_endpoint_stats", endpoint_stats, raising=False)
        monkeypatch.setattr(ueba_tools, "get_enduser_stats", endpoint_stats, raising=False)
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(HuntParams(entity="epid:6676"))
        assert isinstance(result.estate, EstateContext)
        assert result.estate.endpoints == ENDPOINT_STATS
        # An endpoint subject asks for no end-user denominator, so that half
        # is a gap for want, not for failure.
        assert isinstance(result.estate.endusers, FeatureGap)
        assert "not requested" in result.estate.endusers.reason
        assert result.estate.ranked_endpoint_total == len(ESTATE)

    async def test_estate_disabled(self):
        with (
            t(GET_ENDPOINTS, return_value=ok(data=ESTATE)),
            t(GET_ALERTS, return_value=ok(data=[])),
            t(QUERY_LOGS, return_value=logs_ok([])),
        ):
            result = await handlers.run_hunt(
                HuntParams(entity="epid:6676", include_estate_stats=False)
            )
        assert isinstance(result.estate, FeatureGap)
        assert "include_estate_stats" in result.estate.reason


class TestHuntDispatch:
    async def test_success_envelope(self):
        with t(QUERY_LOGS, return_value=logs_ok([])):
            result = await faz_skill(
                skill="hunt",
                params={"filter": "dstport==4444", "sweep_logtypes": ["traffic"]},
            )
        assert result["status"] == "success"
        assert result["skill"] == "hunt"
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["result"]["subject_type"] == "hypothesis"

    async def test_each_match_carries_the_clause_its_search_ran_on(self, soar):
        with t(QUERY_LOGS, return_value=logs_ok([])):
            result = await faz_skill(
                skill="hunt",
                params={
                    "indicator": {"value": "bad.example.com", "type": "Domain"},
                    "sweep_logtypes": ["traffic", "dns"],
                },
            )
        assert result["status"] == "success"
        sweep = result["result"]["sweep"]
        # The field each search matched on (the value is masked when masking is on).
        assert [(m["logtype"], m["pivot_filter"].split("==")[0]) for m in sweep["matches"]] == [
            ("traffic", "hostname"),
            ("dns", "qname"),
        ]
        assert sweep["pivot_filter"] is None

    async def test_a_truncated_page_is_a_lower_bound_in_the_envelope(self):
        page = full_page([{"logid": "0000000013"}], floor=6450)
        with t(QUERY_LOGS, return_value=page):
            result = await faz_skill(
                skill="hunt",
                params={"filter": "dstport==4444", "sweep_logtypes": ["dns"], "sweep_limit": 1},
            )
        assert result["status"] == "success"
        sweep = result["result"]["sweep"]
        assert [(m["row_count"], m["has_more"]) for m in sweep["matches"]] == [(1, True)]
        assert sweep["total_matches"] == 1
        assert sweep["total_matches_is_lower_bound"] is True
        assert "at least 1 matches" in result["result"]["headline"]

    async def test_missing_subject_rejected(self):
        result = await faz_skill(skill="hunt", params={})
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"

    @pytest.mark.parametrize(
        "params",
        [
            {"ttp": """T1071 "a" 'b'"""},
            {"indicator": {"value": """dead"beef'""", "type": "Hash"}},
            {"indicator": {"value": "198.51.100.7\\", "type": "IP"}},
        ],
        ids=["ttp", "hash", "ip"],
    )
    async def test_unwritable_caller_pivot_is_an_invalid_parameter(self, params):
        """A caller's indicator or TTP that no literal can hold is their input
        error, and no search is sent with it."""
        with t(QUERY_LOGS, return_value=logs_ok([])) as query:
            result = await faz_skill(skill="hunt", params=params)
        assert result["status"] == "error"
        assert result["error"] == "invalid_skill_params"
        assert "quote characters" in result["message"] or "backslash" in result["message"]
        query.assert_not_called()


class TestSweepPivotOperator:
    """#173: FortiAnalyzer 7.6.8 and 8.0.2 answer ``=~`` with ``Invalid
    filter``, so the substring pivots are written with ``like``."""

    def test_ttp_pivot_is_a_like_clause(self):
        pivot = handlers._sweep_pivot(HuntParams(ttp="T1071"))
        assert pivot == 'attack like "%T1071%"'

    def test_hash_pivot_is_a_like_clause(self):
        pivot = handlers._sweep_pivot(
            HuntParams(indicator=IndicatorSubject(value="deadbeef", type="Hash"))
        )
        assert pivot == '(filehash like "%deadbeef%" or analyticscksum like "%deadbeef%")'

    @pytest.mark.parametrize(
        "params",
        [
            HuntParams(ttp="T1071"),
            HuntParams(indicator=IndicatorSubject(value="deadbeef", type="Hash")),
        ],
    )
    def test_no_pivot_emits_the_rejected_operator(self, params):
        assert "=~" not in handlers._sweep_pivot(params)

    def test_a_quote_in_the_ttp_stays_inside_the_pattern(self):
        pivot = handlers._sweep_pivot(HuntParams(ttp='T1071" or srcip=="10.0.0.1'))
        # #164: there is no escape for a quote, so the pattern switches to
        # the quote character the value does not contain.
        assert pivot == """attack like '%T1071" or srcip=="10.0.0.1%'"""

    def test_like_wildcards_in_the_ttp_are_literal(self):
        pivot = handlers._sweep_pivot(HuntParams(ttp="T1071_%"))
        assert pivot == 'attack like "%T1071\\_\\%%"'

    def test_a_backslash_in_the_hash_is_doubled_for_like(self):
        pivot = handlers._sweep_pivot(
            HuntParams(indicator=IndicatorSubject(value="dead\\", type="Hash"))
        )
        assert pivot == '(filehash like "%dead\\\\%" or analyticscksum like "%dead\\\\%")'

    @pytest.mark.parametrize(
        "params",
        [
            HuntParams(ttp="""T1071 "a" 'b'"""),
            HuntParams(indicator=IndicatorSubject(value="""dead"beef'""", type="Hash")),
        ],
    )
    def test_a_pattern_no_literal_can_hold_is_a_param_error(self, params):
        with pytest.raises(handlers.SkillParamError, match="both quote characters"):
            handlers._sweep_pivot(params)


class TestImpactEntityResolution:
    async def test_record_values_no_literal_can_hold_become_warnings(self):
        """Both impact pivots degrade; the entity still lists, with no pivot."""
        endpoint = {"epid": 1025, "epname": "WS-ALPHA", "epip": "value\\"}
        user = {"euid": 7, "euname": "value\\"}
        warnings: list[str] = []
        with (
            t(GET_ENDPOINTS, return_value=ok(data=[endpoint])),
            t(GET_ENDUSERS, return_value=ok(data=[user])),
        ):
            resolved = await handlers._resolve_impact_entities(None, [1025], [7], None, warnings)
        assert [e["pivot"] for e in resolved] == [None, None]
        assert sum("backslash" in w and w.startswith("impact:") for w in warnings) == 2
