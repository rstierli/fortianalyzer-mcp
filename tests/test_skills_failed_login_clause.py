"""The failed-login clause of ``risk_assessment`` and ``identity_profile`` (#187 A1).

Both skills counted failed logins with ``action==failure``, which matched no
event log on any build measured: 0 of about 108k rows on 7.6.7, 0 of 1.5
million on 8.0.2. The clause below is the one measured on #187 against real
failed admin logins, user-subtype samples and 1081 SSL-VPN login failures.

The rows in this file are checked with a small evaluator, twice: once with
``and`` binding tighter than ``or`` and once the other way round. The filter a
skill sends must mean the same under both, because nothing here measured which
of the two FortiAnalyzer uses.
"""

import re
from typing import Any

import pytest

from fortianalyzer_mcp.skills import handlers
from fortianalyzer_mcp.skills.models import IdentityProfileParams, RiskAssessmentParams
from tests.test_skills_identity_profile import EP_ALICE, EP_OTHER, USER_ALICE
from tests.test_skills_risk_assessment import (
    ENDPOINT,
    ENDUSER,
    GET_ENDPOINT_VULNS,
    GET_ENDPOINTS,
    GET_ENDUSERS,
    GET_FORTIVIEW,
    QUERY_LOGS,
    THREAT_ROWS,
    VULN_PAYLOAD,
    logs_ok,
    ok,
    t,
)

# As posted on #187, written out here and not imported, so that a change to the
# constant in the handlers has to be made twice.
CLAUSE = (
    "(action==ssl-login-fail or ((action==login or action==authentication "
    "or action==FSS0-auth or action==NTLM-auth) "
    "and (status==failed or status==failure or status==locked_out)))"
)

# What each row is, and whether it is a failed login.
ROWS: list[tuple[dict[str, str], bool]] = [
    # SSL-VPN login failures carry no status field at all (1081 of 1081 measured).
    ({"action": "ssl-login-fail", "subtype": "vpn", "user": "alice"}, True),
    ({"action": "login", "status": "failed", "user": "alice"}, True),  # admin login failed
    ({"action": "login", "status": "success", "user": "alice"}, False),
    ({"action": "authentication", "status": "failure", "user": "alice"}, True),
    ({"action": "authentication", "status": "locked_out", "user": "alice"}, True),
    ({"action": "FSS0-auth", "status": "failure", "user": "alice"}, True),
    ({"action": "NTLM-auth", "status": "failure", "user": "alice"}, True),
    # The noise that a bare status clause counted: IPsec phase 1 and a
    # FortiAnalyzer connection.
    ({"action": "negotiate", "status": "failure", "user": "alice"}, False),
    ({"action": "connect", "status": "failure", "user": "alice"}, False),
    # The old clause, which no row carries.
    ({"action": "failure", "user": "alice"}, False),
]


def _matches(expression: str, row: dict[str, str], *, and_binds_tighter: bool) -> bool:
    """Evaluate ``field==value`` clauses joined by and/or with parentheses."""
    tokens = re.findall(r"\(|\)|[^\s()]+", expression)
    position = 0
    loose, tight = ("or", "and") if and_binds_tighter else ("and", "or")

    def combine(word: str, left: bool, right: bool) -> bool:
        return (left and right) if word == "and" else (left or right)

    def atom() -> bool:
        nonlocal position
        token = tokens[position]
        position += 1
        if token == "(":
            value = level(loose)
            assert tokens[position] == ")", expression
            position += 1
            return value
        field, _, wanted = token.partition("==")
        assert wanted, f"not a clause: {token!r}"
        return row.get(field) == wanted

    def level(word: str) -> bool:
        nonlocal position
        operand = atom if word == tight else (lambda: level(tight))
        value = operand()
        while position < len(tokens) and tokens[position] == word:
            position += 1
            value = combine(word, value, operand())
        return value

    result = level(loose)
    assert position == len(tokens), f"unparsed tail in {expression!r}"
    return result


PRECEDENCE = pytest.mark.parametrize(
    "and_binds_tighter", [True, False], ids=["and-first", "or-first"]
)


class TestTheClause:
    def test_the_handlers_use_the_measured_clause(self) -> None:
        assert handlers._FAILED_LOGIN_CLAUSE == CLAUSE

    @PRECEDENCE
    @pytest.mark.parametrize("row, failed_login", ROWS)
    def test_each_kind_of_row(
        self, row: dict[str, str], failed_login: bool, and_binds_tighter: bool
    ) -> None:
        assert _matches(CLAUSE, row, and_binds_tighter=and_binds_tighter) is failed_login


async def _risk_filter(params: RiskAssessmentParams) -> tuple[str, Any]:
    with (
        t(GET_ENDPOINTS, return_value=ok(data=[ENDPOINT])),
        t(GET_ENDUSERS, return_value=ok(data=[ENDUSER])),
        t(GET_ENDPOINT_VULNS, return_value=ok(data=VULN_PAYLOAD)),
        t(GET_FORTIVIEW, return_value=ok(data=THREAT_ROWS)),
        t(QUERY_LOGS, return_value=logs_ok(4)) as logs,
    ):
        result = await handlers.run_risk_assessment(params)
    return logs.call_args.kwargs["filter"], result


class TestRiskAssessment:
    async def test_an_endpoint_is_counted_with_the_clause(self) -> None:
        sent, _ = await _risk_filter(RiskAssessmentParams(epid=1025))

        assert sent == f"{CLAUSE} and srcip==192.0.2.10"

    async def test_an_end_user_is_counted_with_the_clause(self) -> None:
        sent, _ = await _risk_filter(RiskAssessmentParams(euid=7))

        assert sent == f"{CLAUSE} and user==alice"

    @PRECEDENCE
    async def test_only_the_entitys_own_failed_logins_count(self, and_binds_tighter: bool) -> None:
        """An SSL-VPN failure has no status, so it is the row that leaks to
        every entity if the clause is not closed before the entity is added."""
        sent, _ = await _risk_filter(RiskAssessmentParams(euid=7))

        for row, failed_login in ROWS:
            assert _matches(sent, row, and_binds_tighter=and_binds_tighter) is failed_login
            other = {**row, "user": "bob"}
            assert _matches(sent, other, and_binds_tighter=and_binds_tighter) is False

    async def test_the_result_says_what_was_counted(self) -> None:
        _, result = await _risk_filter(RiskAssessmentParams(epid=1025))

        assert result.failed_login_clause == CLAUSE


async def _identity_filter() -> tuple[str, Any]:
    with (
        t(GET_ENDUSERS, return_value=ok(data=[USER_ALICE])),
        t(GET_ENDPOINTS, return_value=ok(data=[EP_ALICE, EP_OTHER])),
        t(QUERY_LOGS, return_value=ok(logs=[])) as logs,
    ):
        result = await handlers.run_identity_profile(IdentityProfileParams(euid=7))
    return logs.call_args.kwargs["filter"], result


class TestIdentityProfile:
    async def test_failed_logins_or_vpn_activity_of_the_user(self) -> None:
        sent, _ = await _identity_filter()

        assert sent == f"user==alice and ({CLAUSE} or subtype==vpn)"

    @PRECEDENCE
    async def test_which_rows_the_activity_search_takes(self, and_binds_tighter: bool) -> None:
        sent, _ = await _identity_filter()
        vpn_up = {"action": "tunnel-up", "subtype": "vpn", "user": "alice"}

        assert _matches(sent, vpn_up, and_binds_tighter=and_binds_tighter)
        assert not _matches(sent, {**vpn_up, "user": "bob"}, and_binds_tighter=and_binds_tighter)
        for row, failed_login in ROWS:
            wanted = failed_login or row.get("subtype") == "vpn"
            assert _matches(sent, row, and_binds_tighter=and_binds_tighter) is wanted
            other = {**row, "user": "bob"}
            assert _matches(sent, other, and_binds_tighter=and_binds_tighter) is False

    async def test_the_result_says_what_was_searched(self) -> None:
        _, result = await _identity_filter()

        assert result.activity_clause == f"({CLAUSE} or subtype==vpn)"


class TestTheFiltersReachTheApplianceAsWritten:
    """The skill tests above patch ``query_logs``. These run the real tool.

    A nested clause with ``or`` inside ``and`` has to arrive at the log search
    exactly as the skill wrote it, and the masking layer, which reads every
    clause of a raw filter, has to leave it alone: none of its values is a
    token.
    """

    FILTERS = [f"{CLAUSE} and srcip==192.0.2.10", f"user==alice and ({CLAUSE} or subtype==vpn)"]

    @pytest.mark.parametrize("sent", FILTERS, ids=["risk_assessment", "identity_profile"])
    async def test_query_logs_forwards_it_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, sent: str
    ) -> None:
        from fortianalyzer_mcp.tools import log_tools
        from tests.test_response_contract import ContractFaz, _install, _rows

        fake = ContractFaz(page=_rows(2), total=2)
        _install(monkeypatch, fake)

        result = await log_tools.query_logs(
            adom="root", logtype="event", time_range="24-hour", filter=sent
        )

        assert result["status"] == "success"
        assert fake.start_calls[0]["filter"] == sent

    @pytest.mark.parametrize("sent", FILTERS, ids=["risk_assessment", "identity_profile"])
    def test_the_masking_layer_leaves_it_alone(self, sent: str) -> None:
        from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
        from fortianalyzer_mcp.masking.unmask import ArgUnmasker

        # The v1 window closed, as the server has it by default. Open, the
        # endpoint's address would be read as a v1 token (#180); the clause
        # would still be untouched.
        engine = FPEEngine("2DE79D232DF5585D68CE47882AE256D6", accept_v1_tokens=False)

        assert ArgUnmasker(engine).unmask_filter(sent) == sent
