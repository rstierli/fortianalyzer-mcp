"""Forgery refusal, wired to the paths a caller actually reaches.

The v2 envelope was built as format only: ``is_v2_shaped`` and ``v2_open``
existed and were tested, and nothing consulted them. So the property the
whole design is for did not hold in the running server. A v2 token with a
flipped tag is a byte-valid v1 token, because the tag is hex and a hyphen
and both are inside the v1 alphabet, so the v1 path decrypted it happily
to plausible garbage.

Ordering IS the gate. A v2 hostname token also starts with ``host-``, so
checking the shape after the prefix dispatch would never run. Both entry
points therefore have to ask the shape question first:
``FPEEngine.unmask_token`` and ``ArgUnmasker``, which delegates to it.

Committed means committed: something v2-shaped is never retried on the v1
path, whatever v2 says about it. Falling back would hand the forger the
exact decrypt the gate exists to refuse.
"""

import pytest

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine, MaskingError
from fortianalyzer_mcp.masking.unmask import ArgUnmasker

KEY = "2DE79D232DF5585D68CE47882AE256D6"
OTHER_KEY = "00112233445566778899AABBCCDDEEFF"


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY)


@pytest.fixture
def unmasker(engine: FPEEngine) -> ArgUnmasker:
    return ArgUnmasker(engine)


def _ct(token: str) -> str:
    """Bare ciphertext out of a v1 ``<marker>-<kid>-<ct>`` token."""
    return token.split("-", 2)[2]


def _flip_tag(token: str) -> str:
    return token[:-1] + ("0" if token[-1] != "0" else "1")


class TestTheGateRunsBeforeThePrefixDispatch:
    def test_a_v2_hostname_token_resolves_through_v2(self, engine: FPEEngine) -> None:
        token = engine.v2_token("hostname", _ct(engine.mask_hostname("fw-hq-01")))

        assert engine.unmask_token(token) == "fw-hq-01"

    def test_a_forged_v2_token_is_refused_not_decrypted(self, engine: FPEEngine) -> None:
        """The property the format was built for, at the boundary.

        Before the gate this returned plausible garbage instead of
        raising, because `host-` matched first.
        """
        forged = _flip_tag(engine.v2_token("hostname", _ct(engine.mask_hostname("fw-hq-01"))))

        assert engine.is_v2_shaped(forged)
        with pytest.raises(MaskingError):
            engine.unmask_token(forged)

    def test_a_token_minted_under_another_key_is_refused(self, engine: FPEEngine) -> None:
        foreign = FPEEngine(OTHER_KEY)
        token = foreign.v2_token("hostname", _ct(foreign.mask_hostname("fw-hq-01")))

        with pytest.raises(MaskingError):
            engine.unmask_token(token)

    @pytest.mark.parametrize(
        ("vtype", "value"),
        [("ipv4", "192.0.2.9"), ("ipv6", "2001:db8::5"), ("mac", "54:01:81:74:f5:ef")],
    )
    def test_the_unmarked_types_now_resolve_too(
        self, engine: FPEEngine, vtype: str, value: str
    ) -> None:
        """v1 IP and MAC tokens carry no marker, so unmask_token skipped
        them and left resolution to field context. Their v2 forms DO carry
        one, so the gate is also the first time these resolve by
        self-identification."""
        ct = engine.mask_mac(value) if vtype == "mac" else engine.mask_ip(value)

        assert engine.unmask_token(engine.v2_token(vtype, ct)) == value


class TestTheV1PathIsUntouched:
    """The gate must only capture what is v2-shaped."""

    def test_a_v1_hostname_token_still_resolves(self, engine: FPEEngine) -> None:
        assert engine.unmask_token(engine.mask_hostname("fw-hq-01")) == "fw-hq-01"

    def test_a_v1_username_keeps_its_case(self, engine: FPEEngine) -> None:
        assert engine.unmask_token(engine.mask_username("Admin")) == "Admin"

    def test_a_v1_domain_still_resolves(self, engine: FPEEngine) -> None:
        assert engine.unmask_token(engine.mask_domain("example.com")) == "example.com"

    @pytest.mark.parametrize(
        "ordinary", ["host-fw01", "sn-abc", "user-admin", "host-2a85-plainct", "plain-value"]
    )
    def test_an_unshaped_value_is_not_committed_to_v2(
        self, engine: FPEEngine, ordinary: str
    ) -> None:
        """Either it resolves on the v1 path or it returns None.

        What it must never do is raise, because that would mean an
        ordinary argument was captured by the gate.
        """
        assert not engine.is_v2_shaped(ordinary)
        try:
            engine.unmask_token(ordinary)
        except MaskingError:
            pass  # a v1 marker that fails to decrypt is the v1 path's own business


class TestTheArgumentBoundary:
    """ArgUnmasker delegates to unmask_token, so it inherits the gate.

    Asserted rather than assumed: the delegation is one line today and a
    future refactor that reintroduces a prefix check here would reopen the
    hole silently.
    """

    def test_a_forged_token_in_an_argument_does_not_resolve_to_garbage(
        self, engine: FPEEngine, unmasker: ArgUnmasker
    ) -> None:
        forged = _flip_tag(engine.v2_token("hostname", _ct(engine.mask_hostname("fw-hq-01"))))

        with pytest.raises(MaskingError):
            unmasker._unmask_marked(forged)

    def test_a_genuine_token_in_an_argument_resolves(
        self, engine: FPEEngine, unmasker: ArgUnmasker
    ) -> None:
        token = engine.v2_token("hostname", _ct(engine.mask_hostname("fw-hq-01")))

        assert unmasker._unmask_marked(token) == "fw-hq-01"
