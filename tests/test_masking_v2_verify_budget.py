"""The per-call verification budget and the forgery alarm.

The 32-bit tag is one in 4.3 billion per blind guess, which only sounds
sufficient until the unit is counted properly. The bound is per
VERIFICATION, not per call, and one call can carry thousands of tokens: a
``filters`` list with 5000 entries resolves 5000 of them independently.
At that density 2**31 expected verifications is on the order of 10**5
calls rather than 10**9, so an online grind is a day of traffic rather
than a geological era.

Capping the count per call is what restores the exponent, and it costs
nothing legitimate because no real call comes near the cap. The tag width
was argued on #40 on the explicit basis that this would exist, so these
tests are what makes that argument true rather than intended.
"""

import logging

import pytest

from fortianalyzer_mcp.masking.fpe_engine import (
    V2_FAILURE_ALARM,
    V2_VERIFY_BUDGET,
    FPEEngine,
    MaskingError,
    begin_v2_verification_budget,
)

KEY = "2DE79D232DF5585D68CE47882AE256D6"


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY)


@pytest.fixture(autouse=True)
def _fresh_budget() -> None:
    begin_v2_verification_budget()


class TestTheBudget:
    def test_a_normal_call_never_notices_it(self, engine: FPEEngine) -> None:
        token = engine.mint("ipv4", "192.0.2.9")
        for _ in range(100):
            assert engine.v2_open(token) == "192.0.2.9"

    def test_the_budget_is_spent_by_verifications_not_successes(self, engine: FPEEngine) -> None:
        """A grind pays for attempts. Counting only successes would let a
        forger try for free, which is the opposite of the point."""
        forged = engine.mint("ipv4", "192.0.2.9")[:-1] + "0"

        for _ in range(V2_VERIFY_BUDGET):
            with pytest.raises(MaskingError):
                engine.v2_open(forged)

        with pytest.raises(MaskingError, match="budget for this call is exhausted"):
            engine.v2_open(forged)

    def test_a_genuine_token_is_refused_once_the_budget_is_gone(self, engine: FPEEngine) -> None:
        """Fails closed. Past the cap nothing resolves, valid or not."""
        token = engine.mint("ipv4", "192.0.2.9")
        for _ in range(V2_VERIFY_BUDGET):
            engine.v2_open(token)

        with pytest.raises(MaskingError, match="budget for this call is exhausted"):
            engine.v2_open(token)

    def test_the_budget_resets_per_call(self, engine: FPEEngine) -> None:
        """Otherwise the cap is a process lifetime limit, and a long-lived
        server stops resolving anything after one busy call."""
        token = engine.mint("ipv4", "192.0.2.9")
        for _ in range(V2_VERIFY_BUDGET):
            engine.v2_open(token)

        begin_v2_verification_budget()

        assert engine.v2_open(token) == "192.0.2.9"

    def test_exhaustion_is_reported_once_not_per_token(
        self, engine: FPEEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        token = engine.mint("ipv4", "192.0.2.9")
        for _ in range(V2_VERIFY_BUDGET):
            engine.v2_open(token)

        with caplog.at_level(logging.ERROR, logger="fortianalyzer_mcp.masking.fpe_engine"):
            for _ in range(5):
                with pytest.raises(MaskingError):
                    engine.v2_open(token)

        assert len([r for r in caplog.records if "budget" in r.message]) == 1


class TestTheForgeryAlarm:
    def test_repeated_failures_escalate_to_an_alarm(
        self, engine: FPEEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        """One failure is a corrupted token echoed back. Several in a
        single call is someone trying tags, and the two should not read
        the same in a log."""
        forged = engine.mint("hostname", "fw-hq-01")[:-1] + "0"

        with caplog.at_level(logging.WARNING, logger="fortianalyzer_mcp.masking.fpe_engine"):
            for _ in range(V2_FAILURE_ALARM):
                with pytest.raises(MaskingError):
                    engine.v2_open(forged)

        assert any(r.levelno == logging.ERROR and "forgery" in r.message for r in caplog.records)

    def test_a_single_failure_does_not_raise_the_alarm(
        self, engine: FPEEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        forged = engine.mint("hostname", "fw-hq-01")[:-1] + "0"

        with caplog.at_level(logging.WARNING, logger="fortianalyzer_mcp.masking.fpe_engine"):
            with pytest.raises(MaskingError):
                engine.v2_open(forged)

        assert not [r for r in caplog.records if r.levelno == logging.ERROR]

    def test_no_token_or_value_reaches_the_log(
        self, engine: FPEEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Attacker-influenced text, and the standing rule of this module."""
        forged = engine.mint("hostname", "fw-hq-01")[:-1] + "0"

        with caplog.at_level(logging.DEBUG, logger="fortianalyzer_mcp.masking.fpe_engine"):
            for _ in range(V2_FAILURE_ALARM):
                with pytest.raises(MaskingError):
                    engine.v2_open(forged)

        blob = " ".join(r.getMessage() for r in caplog.records)
        assert forged not in blob
        assert "fw-hq-01" not in blob
