"""The mint point and the v1 deprecation window.

Two halves of the same switch. ``mint`` is where the emitted format is
decided, in one place rather than at each of the seven primitives, and
``accept_v1_tokens`` is how a deployment stops honouring the old format
once nothing returns it any more.

Nothing here changes what the server emits yet: the wrapper still calls
the v1 primitives. This is the substrate under that change, tested on its
own so the switch that follows is one wiring commit rather than a wiring
commit plus a format commit.
"""

import logging

import pytest

from fortianalyzer_mcp.masking.fpe_engine import V2_MARKERS, FPEEngine, MaskingError

KEY = "2DE79D232DF5585D68CE47882AE256D6"


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY)


VALUES = {
    "ipv4": "192.0.2.9",
    "ipv6": "2001:db8::5",
    "mac": "54:01:81:74:f5:ef",
    "serial": "FGT60FTK20000001",
    "hostname": "fw-hq-01",
    "username": "Admin",
    "url_tail": "/a/b?c=1",
}


class TestMint:
    @pytest.mark.parametrize("vtype", sorted(VALUES))
    def test_every_enveloped_type_mints_v2_and_round_trips(
        self, engine: FPEEngine, vtype: str
    ) -> None:
        token = engine.mint(vtype, VALUES[vtype])

        assert engine.is_v2_shaped(token), vtype
        assert token.startswith(f"{V2_MARKERS[vtype]}-"), vtype
        assert engine.v2_open(token) == VALUES[vtype], vtype

    def test_mint_covers_exactly_the_enveloped_types(self, engine: FPEEngine) -> None:
        """If a v2 marker is added later, this fails until mint knows it."""
        assert set(VALUES) == set(V2_MARKERS)

    def test_a_username_keeps_its_case_through_the_envelope(self, engine: FPEEngine) -> None:
        assert engine.v2_open(engine.mint("username", "Admin")) == "Admin"

    def test_minting_is_deterministic(self, engine: FPEEngine) -> None:
        """The correlation property the whole layer exists for."""
        assert engine.mint("ipv4", "192.0.2.9") == engine.mint("ipv4", "192.0.2.9")

    @pytest.mark.parametrize("vtype", ["domain", "email_local"])
    def test_the_suffix_marked_types_stay_v1_by_decision(
        self, engine: FPEEngine, vtype: str
    ) -> None:
        """Not an omission. They are suffix-marked, so a v2 spelling is a
        different parse rather than a different envelope, and #40 left
        them for later."""
        value = "example.com" if vtype == "domain" else "user@example.com"

        token = engine.mint(vtype, value)

        assert not engine.is_v2_shaped(token)
        assert token.endswith(engine.mask_suffix)

    def test_an_unknown_type_refuses_rather_than_returning_the_value(
        self, engine: FPEEngine
    ) -> None:
        with pytest.raises(MaskingError):
            engine.mint("not_a_type", "whatever")

    def test_the_v1_primitives_are_untouched(self, engine: FPEEngine) -> None:
        """Golden vectors shared with fortimanager-mcp pin these, so mint
        must be additive rather than a change of format at the source."""
        assert engine.mask_hostname("fw-hq-01").startswith("host-")
        assert not engine.is_v2_shaped(engine.mask_hostname("fw-hq-01"))


class TestTheDeprecationWindow:
    def test_v1_resolves_while_the_window_is_open(self, engine: FPEEngine) -> None:
        assert engine.unmask_token(engine.mask_hostname("fw-hq-01")) == "fw-hq-01"

    def test_v1_is_refused_once_the_window_closes(self) -> None:
        minting = FPEEngine(KEY)
        closed = FPEEngine(KEY, accept_v1_tokens=False)

        with pytest.raises(MaskingError, match="deprecation window is closed"):
            closed.unmask_token(minting.mask_hostname("fw-hq-01"))

    def test_the_suffix_forms_are_not_refused(self) -> None:
        """This used to assert the opposite, and the reasoning was wrong.

        It said domain and email "stay v1 the longest, so the window has to
        reach them or closing it means nothing". They do not stay v1 the
        longest -- they stay v1 permanently, because they have no v2
        envelope by decision (#40). So the window reaching them did not make
        closing it mean more, it made closing it impossible: the same engine
        minted a domain token and then refused it, in one process with one
        key. Closing the window broke domain and email masking outright.

        The window retires an encoding that has a replacement. The suffix
        form has none, so there is nothing to retire it to.

        Asserted through ``unmask_token`` on purpose, which is the route the
        old test used and the route production uses: ``ArgUnmasker``
        resolves a marked token by calling ``unmask_token``, not the
        primitive. Going straight to ``unmask_domain`` here would leave the
        dispatch unguarded -- re-adding a window check on the suffix branch
        of the dispatch passes the whole suite otherwise, while breaking
        domain and email on the only path that matters.
        """
        minting = FPEEngine(KEY)
        closed = FPEEngine(KEY, accept_v1_tokens=False)

        assert closed.unmask_token(minting.mask_domain("example.com")) == "example.com"
        assert closed.unmask_token(minting.mask_email("alice@example.com")) == "alice@example.com"

    def test_a_direct_primitive_call_cannot_route_around_the_window(self) -> None:
        """The reason the check sits on the key-id split.

        ``ArgUnmasker`` resolves a URL tail by calling ``unmask_url_tail``
        directly rather than going through ``unmask_token``, so a check on
        the dispatch would miss it entirely.
        """
        minting = FPEEngine(KEY)
        closed = FPEEngine(KEY, accept_v1_tokens=False)

        with pytest.raises(MaskingError, match="deprecation window is closed"):
            closed.unmask_url_tail(minting.mask_url_tail("/a/b?c=1"))

    def test_v2_still_resolves_with_the_window_closed(self) -> None:
        """Closing the window must retire v1, not masking."""
        closed = FPEEngine(KEY, accept_v1_tokens=False)

        assert closed.v2_open(closed.mint("hostname", "fw-hq-01")) == "fw-hq-01"
        assert closed.unmask_token(closed.mint("hostname", "fw-hq-01")) == "fw-hq-01"

    def test_the_unmarked_forms_are_unaffected(self) -> None:
        """A masked IP carries no key id and is not a v1 *token*; it is a
        value resolved by field context, so there is nothing to refuse and
        refusing it would break resolution outright."""
        closed = FPEEngine(KEY, accept_v1_tokens=False)

        assert closed.unmask_ip(closed.mask_ip("192.0.2.9")) == "192.0.2.9"
        assert closed.unmask_mac(closed.mask_mac("54:01:81:74:f5:ef")) == "54:01:81:74:f5:ef"

    def test_the_open_window_says_so_once(
        self, engine: FPEEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The flag is only useful if an operator can tell when to close it.

        Once at INFO rather than per token, because one response can carry
        thousands and a per-token line would bury the signal it exists to
        give.
        """
        with caplog.at_level(logging.INFO, logger="fortianalyzer_mcp.masking.fpe_engine"):
            engine.unmask_token(engine.mask_hostname("fw-hq-01"))
            engine.unmask_token(engine.mask_hostname("fw-hq-02"))

        lines = [r for r in caplog.records if "deprecation window is open" in r.message]
        assert len(lines) == 1

    def test_the_log_line_carries_no_payload(
        self, engine: FPEEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Standing rule in this module: never log a value or a token."""
        token = engine.mask_hostname("fw-hq-01")

        with caplog.at_level(logging.DEBUG, logger="fortianalyzer_mcp.masking.fpe_engine"):
            engine.unmask_token(token)

        blob = " ".join(r.getMessage() for r in caplog.records)
        assert "fw-hq-01" not in blob
        assert token not in blob


class TestClosingTheWindowDoesNotRefuseOurOwnOutput:
    """Closing the window must not break the types that have no v2 form.

    domain and email_local are suffix-marked and have no v2 envelope by
    decision (#40). Their suffix token is therefore not a legacy encoding
    waiting to be retired, it is the only encoding they have ever had.
    Gating the suffix key-id split on the v1 window made this build refuse
    a token it had just minted, which made the window unclosable: closing
    it broke domain and email masking outright.
    """

    @pytest.fixture
    def closed(self) -> FPEEngine:
        return FPEEngine(KEY, accept_v1_tokens=False)

    def test_a_domain_round_trips_with_the_window_closed(self, closed: FPEEngine) -> None:
        token = closed.mask_domain("corp.example.com")
        assert closed.unmask_domain(token) == "corp.example.com"

    def test_an_email_round_trips_with_the_window_closed(self, closed: FPEEngine) -> None:
        token = closed.mask_email("alice@corp.example.com")
        assert closed.unmask_email(token) == "alice@corp.example.com"

    @pytest.mark.parametrize("vtype", ["domain", "email_local"])
    def test_mint_and_resolve_agree_with_the_window_closed(
        self, closed: FPEEngine, vtype: str
    ) -> None:
        """The self-consistency the old behaviour broke: whatever mint emits,
        this same engine must be able to read back."""
        value = "example.com" if vtype == "domain" else "user@example.com"
        token = closed.mint(vtype, value)

        if vtype == "domain":
            assert closed.unmask_domain(token) == value
        else:
            assert closed.unmask_email(token) == value

    def test_a_prefix_form_v1_token_is_still_refused(self, closed: FPEEngine) -> None:
        """The exemption is scoped to the suffix form. The prefix forms do
        have a v2 envelope, so their v1 spelling is genuinely legacy and
        closing the window still has to refuse it."""
        open_engine = FPEEngine(KEY, accept_v1_tokens=True)
        v1_hostname = open_engine.mask_hostname("fw01")

        with pytest.raises(MaskingError, match="deprecation window is closed"):
            closed.unmask_hostname(v1_hostname)

    def test_the_exemption_is_not_a_blanket_off_switch(self, closed: FPEEngine) -> None:
        """Guards against 'fixing' this by disabling the window everywhere.

        Asserts behaviour rather than the constructor flag. Reading
        ``_accept_v1_tokens`` proved nothing: exempting the prefix split as
        well leaves the flag False and the attribute assertion green while
        the window stops refusing anything at all.
        """
        minting = FPEEngine(KEY)

        for v1_token in (
            minting.mask_hostname("fw01"),
            minting.mask_username("admin"),
            minting.mask_url_tail("/a/b?c=1"),
        ):
            with pytest.raises(MaskingError, match="deprecation window is closed"):
                closed.unmask_token(v1_token)
