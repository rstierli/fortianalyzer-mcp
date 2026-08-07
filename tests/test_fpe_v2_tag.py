"""The v2 envelope's authentication tag (#40).

The envelope is ``<type>-<kid>-<ct>-<tag>``. This file covers the tag
primitive on its own, before any minting or parsing is wired up: the tag is
the part both servers must agree on byte for byte, so it is specified and
pinned independently of how a token is spelled around it.
"""

import hashlib
import hmac

import pytest

from fortianalyzer_mcp.masking.fpe_engine import (
    V2_TAG_HEX,
    V2_TYPES,
    FPEEngine,
    MaskingError,
)

KEY = "2DE79D232DF5585D68CE47882AE256D6"
OTHER_KEY = "00112233445566778899AABBCCDDEEFF"


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY)


class TestTagShape:
    def test_tag_is_eight_lowercase_hex(self, engine: FPEEngine):
        # 32 bits, the size settled on #40: one in 4.3 billion per blind
        # forgery attempt, and every attempt costs the attacker a tool call.
        tag = engine.v2_tag("ipv4", "248.194.94.248")
        assert V2_TAG_HEX == 8
        assert len(tag) == V2_TAG_HEX
        assert all(c in "0123456789abcdef" for c in tag)

    def test_tag_is_deterministic(self, engine: FPEEngine):
        assert engine.v2_tag("ipv4", "10.0.0.1") == engine.v2_tag("ipv4", "10.0.0.1")

    def test_tag_depends_on_the_key(self, engine: FPEEngine):
        assert engine.v2_tag("ipv4", "10.0.0.1") != FPEEngine(OTHER_KEY).v2_tag("ipv4", "10.0.0.1")


class TestDomainSeparation:
    def test_same_ciphertext_under_two_types_gets_two_tags(self, engine: FPEEngine):
        # Without per-type separation a token could be lifted from one field
        # type to another and still verify.
        assert engine.v2_tag("ipv4", "abc123") != engine.v2_tag("mac", "abc123")

    def test_tag_input_is_injective_over_the_pinned_type_set(self, engine: FPEEngine):
        # The tag input is "...:<type>:<ct>". Two different (type, ct) pairs
        # must never build the same string. That holds only because no type
        # name contains a colon -- ciphertexts do (IPv6, MAC), so the first
        # colon after the prefix is what delimits the type. This asserts the
        # property rather than trusting the comment.
        for vtype in V2_TYPES:
            assert ":" not in vtype, f"type {vtype!r} would break tag injectivity"

    def test_a_colon_bearing_type_is_rejected(self, engine: FPEEngine):
        # The guard above is only worth having if the code enforces it.
        with pytest.raises(MaskingError, match="type"):
            engine.v2_tag("ip:v4", "abc")


class TestVerification:
    def test_correct_tag_verifies(self, engine: FPEEngine):
        ct = "248.194.94.248"
        assert engine.v2_tag_ok("ipv4", ct, engine.v2_tag("ipv4", ct))

    def test_one_flipped_character_fails(self, engine: FPEEngine):
        ct = "248.194.94.248"
        tag = engine.v2_tag("ipv4", ct)
        flipped = ("0" if tag[0] != "0" else "1") + tag[1:]
        assert not engine.v2_tag_ok("ipv4", ct, flipped)

    def test_tag_from_another_type_fails(self, engine: FPEEngine):
        ct = "abc123"
        assert not engine.v2_tag_ok("ipv4", ct, engine.v2_tag("mac", ct))

    def test_tag_from_another_key_fails(self, engine: FPEEngine):
        ct = "abc123"
        assert not engine.v2_tag_ok("ipv4", ct, FPEEngine(OTHER_KEY).v2_tag("ipv4", ct))

    def test_empty_and_malformed_tags_fail(self, engine: FPEEngine):
        for bad in ("", "  ", "zzzzzzzz", "deadbeef0", "deadbee"):
            assert not engine.v2_tag_ok("ipv4", "248.194.94.248", bad)


class TestSpecPin:
    """The tag is the shared contract with fortimanager-mcp, so its
    derivation is pinned here as a literal rather than recomputed the way
    the implementation does it."""

    def test_tag_key_derivation_is_pinned(self, engine: FPEEngine):
        expected = hashlib.sha256(f"faz-mcp-fpe:v2:tagkey:{KEY.lower()}".encode()).digest()
        assert engine._v2_tag_key == expected

    def test_tag_value_is_pinned(self, engine: FPEEngine):
        # Independent recomputation of the whole construction. If either side
        # of the shared format drifts, this fails rather than the two servers
        # silently disagreeing in production.
        tag_key = hashlib.sha256(f"faz-mcp-fpe:v2:tagkey:{KEY.lower()}".encode()).digest()
        expected = hmac.new(
            tag_key, b"faz-mcp-fpe:v2:tag:ipv4:248.194.94.248", hashlib.sha256
        ).hexdigest()[:8]
        assert engine.v2_tag("ipv4", "248.194.94.248") == expected
