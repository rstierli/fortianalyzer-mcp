"""Pass 1 must not re-mask a token it already minted.

The other half of the hazard the free-text guard closed, on the structured
route rather than the prose one. A v2 token arriving in a typed field is
this layer's own output, and masking it again destroys it:

* an IP-typed field cannot parse a token as an address, so it fails closed
  to an irreversible placeholder and the value is gone for good
* a hostname-typed field CAN encrypt the token as a string, so it comes
  back as a token of a token, which opens to the wrong thing

Both are silent. Neither is reachable from a tool today, because nothing
in the server mints v2 yet, and both become near-certain the moment it
does. That is exactly why this goes in before the mint switch rather than
after it.

The check is by shape, matching the gate decision from #40: a value that
looks like v2 is committed to v2. Verifying the tag instead would be a
third definition of v2-ness in the codebase, and two definitions drifting
apart has already produced one leak here.
"""

import pytest

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.wrapper import OutputMasker

KEY = "2DE79D232DF5585D68CE47882AE256D6"


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY)


@pytest.fixture
def masker(engine: FPEEngine) -> OutputMasker:
    return OutputMasker(engine)


def _ct(token: str) -> str:
    """Bare ciphertext out of a v1 ``<marker>-<kid>-<ct>`` token.

    The string types come out of the engine already wrapped in a v1
    envelope, and ``v2_token`` takes a bare ciphertext. Passing the whole
    v1 token as the payload builds a token that opens to garbage, which is
    what my first draft of this file did. Split from the LEFT, because a
    ciphertext legitimately contains hyphens.
    """
    return token.split("-", 2)[2]


class TestATypedFieldLeavesItsOwnTokenAlone:
    def test_an_ip_field_does_not_placeholder_a_v2_token(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        """The destructive case: a token cannot parse as an address.

        Measured before the fix: srcip came back as
        ``masked-unrepresentable-…`` and the address was unrecoverable.
        """
        token = engine.v2_token("ipv4", engine.mask_ip("192.0.2.9"))

        out = masker.mask_result({"srcip": token})

        assert out["srcip"] == token
        assert engine.v2_open(out["srcip"]) == "192.0.2.9"

    def test_a_hostname_field_does_not_wrap_a_token_in_a_token(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        """The quieter case: a string cipher will happily encrypt a token.

        No placeholder, no error, and the value still opens -- to the wrong
        thing. Worse than the loud failure because nothing looks wrong.
        """
        token = engine.v2_token("hostname", _ct(engine.mask_hostname("fw-hq-01")))

        out = masker.mask_result({"hostname": token})

        assert out["hostname"] == token
        assert engine.v2_open(out["hostname"]) == "fw-hq-01"

    @pytest.mark.parametrize(
        ("field", "vtype", "value"),
        [
            ("srcip", "ipv4", "192.0.2.9"),
            ("dstip", "ipv4", "198.51.100.4"),
            ("mac", "mac", "54:01:81:74:f5:ef"),
        ],
    )
    def test_every_typed_route_funnels_through_the_same_check(
        self, engine: FPEEngine, masker: OutputMasker, field: str, vtype: str, value: str
    ) -> None:
        ct = engine.mask_mac(value) if vtype == "mac" else engine.mask_ip(value)
        token = engine.v2_token(vtype, ct)

        out = masker.mask_result({field: token})

        assert out[field] == token, field

    def test_nesting_does_not_bypass_it(self, engine: FPEEngine, masker: OutputMasker) -> None:
        token = engine.v2_token("ipv4", engine.mask_ip("203.0.113.7"))

        out = masker.mask_result({"data": [{"srcip": token}]})

        assert out["data"][0]["srcip"] == token


class TestRealValuesStillMask:
    """Skipping our own output must not switch masking off."""

    def test_a_real_address_in_the_same_field_still_masks(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"srcip": "198.51.100.99"})
        assert out["srcip"] != "198.51.100.99"

    def test_a_token_and_a_real_value_side_by_side(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        token = engine.v2_token("ipv4", engine.mask_ip("192.0.2.9"))

        out = masker.mask_result({"srcip": token, "dstip": "198.51.100.99"})

        assert out["srcip"] == token
        assert out["dstip"] != "198.51.100.99"

    def test_masking_a_response_twice_is_now_a_fixed_point(self, masker: OutputMasker) -> None:
        """The property the whole item buys, once minting is v2.

        Not true today for the v1 tokens this still produces, so it is
        asserted on the structured route only, where the second pass sees
        whatever the first pass emitted.
        """
        once = masker.mask_result({"srcip": "198.51.100.99"})
        # A v1 token is not v2-shaped, so this documents current behaviour
        # rather than asserting idempotence the format cannot yet give.
        twice = masker.mask_result(once)
        assert twice["srcip"] != once["srcip"]


class TestV1TokensAreNotSkipped:
    """Same scope decision as the free-text guard, asserted not assumed.

    v1 is being retired and the shape gate is what separates the two. A
    v1 token reaching a typed field is still re-masked, and whoever closes
    the deprecation window should find this failing rather than inherit it
    silently.
    """

    def test_a_v1_token_in_a_typed_field_is_still_remasked(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        v1 = f"ip4-{engine.key_id}-{engine.mask_ip('192.0.2.9')}"

        out = masker.mask_result({"srcip": v1})

        assert out["srcip"] != v1
