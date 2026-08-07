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

    def test_verification_is_total_over_untrusted_tags(self, engine: FPEEngine):
        # The tag arrives inside a token a model hands back, so it is
        # untrusted input and verification must be a predicate, not a
        # hazard. compare_digest raises TypeError on non-ASCII rather than
        # returning False, and uppercase hex is a plausible re-casing, so
        # both have to be handled before the comparison.
        for bad in (
            "déadbeef",  # non-ASCII: compare_digest would raise
            "DEADBEEF",  # re-cased hex
            "dead beef",
            "\n",
            "0x1234ab",
        ):
            assert engine.v2_tag_ok("ipv4", "248.194.94.248", bad) is False

    def test_a_recased_token_still_verifies(self, engine: FPEEngine):
        # The engine already tolerates re-casing for every type except
        # username: unmask_hostname round-trips an upper- or title-cased
        # token. The tag has to tolerate exactly as much, or a model that
        # re-cases a token in prose turns it into something we no longer
        # recognise as ours and hand to the appliance as a literal.
        ct = "xwekcqanzm"
        tag = engine.v2_tag("hostname", ct)

        assert engine.v2_tag_ok("hostname", ct, tag.upper())
        assert engine.v2_tag_ok("hostname", ct.upper(), tag)
        assert engine.v2_tag_ok("hostname", ct.upper(), tag.upper())

    def test_username_tags_stay_case_sensitive(self, engine: FPEEngine):
        # Usernames are the documented exception: Admin and admin can be
        # different principals, the cipher is mixed-case, and re-casing a
        # username token already corrupts it. Folding case here would make
        # two distinct principals' tokens authenticate each other.
        ct = "AbCdEfGh"

        assert engine.v2_tag("username", ct) != engine.v2_tag("username", ct.lower())
        assert not engine.v2_tag_ok("username", ct, engine.v2_tag("username", ct.lower()))

    def test_an_unknown_type_still_raises_on_verify(self, engine: FPEEngine):
        # Deliberately NOT swallowed. The value type comes from our own field
        # table, never from the wire, so an unknown one is a bug in this
        # repo and should be loud. Only the tag itself is untrusted.
        with pytest.raises(MaskingError, match="unknown v2 value type"):
            engine.v2_tag_ok("not-a-type", "abc", "deadbeef")


class TestConstantTimeComparison:
    """The one property behaviour cannot express.

    Swapping ``hmac.compare_digest`` for ``==`` changes nothing observable:
    same answer for every input, and a mutation test over the whole file
    leaves it alive. The difference is timing, and a timing assertion in a
    unit test is flaky by construction. So the property is pinned
    structurally instead, which is honest about what it checks: not that the
    comparison IS constant-time, but that the code still calls the function
    that makes it so.

    It matters because the alternative is not a slower check, it is a
    different threat model: a byte-by-byte timing signal takes forgery from
    2**32 blind attempts down to a few hundred measured ones.
    """

    def test_verification_uses_compare_digest(self):
        import inspect

        source = inspect.getsource(FPEEngine.v2_tag_ok)
        assert "compare_digest" in source, (
            "v2_tag_ok must compare the tag with hmac.compare_digest; "
            "a plain == is functionally identical and no behavioural test "
            "will catch the swap"
        )
        body = source.split('"""')[-1]
        assert "==" not in body.replace("!=", ""), (
            "v2_tag_ok compares something with == outside its docstring; "
            "if that is the tag comparison it is a timing leak"
        )


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
