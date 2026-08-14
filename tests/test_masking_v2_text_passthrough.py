"""The free-text scan must not chew on tokens it already minted.

``mask_text`` runs the IOC scan over prose: every dotted quad becomes a
masked IPv4, every MAC becomes a masked MAC. A v2 IPv4 token carries its
ciphertext as a **dotted quad**, so the scan matches the address *inside*
the token and re-encrypts it. The envelope survives, the payload does
not, and the tag no longer verifies the payload beside it, so the token
is destroyed rather than merely double-masked.

IPv6 and MAC v2 payloads went colon-free hex on #40, which is what makes
them invisible to this scan. IPv4 stayed dotted because a masked IPv4 has
to remain a valid IPv4, so it is the one type exposed. That asymmetry is
the whole reason this file exists.

Same class as the ``_AT_BOUNDARY`` re-entrancy work: a layer that reads
its own output has to recognise it.
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


def _v2_ipv4(engine: FPEEngine, address: str = "192.0.2.9") -> str:
    return engine.v2_token("ipv4", engine.mask_ip(address))


class TestAV2TokenSurvivesTheFreeTextScan:
    def test_a_bare_v2_ipv4_token_is_left_alone(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        token = _v2_ipv4(engine)

        out = masker.mask_text(token, {})

        assert out == token
        assert engine.v2_open(out) == "192.0.2.9"

    def test_a_v2_token_embedded_in_prose_is_left_alone(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        """The shape a log line actually has."""
        token = _v2_ipv4(engine, "198.51.100.23")

        out = masker.mask_text(f"denied traffic from {token} to port 443", {})

        assert token in out
        embedded = out.split("from ")[1].split(" to")[0]
        assert engine.v2_open(embedded) == "198.51.100.23"

    def test_a_real_address_beside_a_token_still_gets_masked(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        """Skipping tokens must not switch the scan off for real values."""
        token = _v2_ipv4(engine, "203.0.113.7")

        out = masker.mask_text(f"{token} talked to 198.51.100.99", {})

        assert token in out
        assert "198.51.100.99" not in out

    @pytest.mark.parametrize("vtype,value", [("ipv6", "2001:db8::5"), ("mac", "54:01:81:74:f5:ef")])
    def test_the_hex_payload_types_were_already_safe(
        self, engine: FPEEngine, masker: OutputMasker, vtype: str, value: str
    ) -> None:
        """Pins WHY ipv4 is the exposed one, so the reason is not lost.

        These pass before the fix. They are here so that a later change
        making an IPv6 or MAC payload colon-bearing again fails loudly
        rather than silently reopening this hole for two more types.
        """
        ct = engine.mask_ip(value) if vtype == "ipv6" else engine.mask_mac(value)
        token = engine.v2_token(vtype, ct)

        out = masker.mask_text(f"saw {token} on the wire", {})

        assert token in out
        assert engine.v2_open(token) == value


class TestTheTokenIsDestroyedNotJustDoubleMasked:
    def test_the_tag_no_longer_verifies_after_a_rescan(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        """Names the actual damage, so nobody reads this as cosmetic.

        Re-encrypting the payload leaves the tag bound to the payload that
        was there before, so the token stops opening at all. The original
        address is not recoverable from it by anyone, including us.
        """
        token = _v2_ipv4(engine, "192.0.2.42")

        out = masker.mask_text(token, {})

        assert engine.v2_open(out) == "192.0.2.42"

    def test_the_token_survives_repeated_scans(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        """A response can carry the same text through more than one path.

        Scoped to the token on purpose. The first draft asserted the whole
        string was a fixed point and failed against correct code, because
        the bare address beside the token is NOT stable: pass 1 masks it
        into a valid-looking IPv4, and a later scan masks that again, since
        a masked IPv4 with no envelope around it cannot be told from a real
        one. That is inherent to v1 and is the argument for v2 envelopes,
        not a defect this guard should paper over. Kept as a note because
        the difference between "the token is stable" and "the text is
        stable" is exactly what v2 buys.
        """
        token = _v2_ipv4(engine, "192.0.2.11")
        text = f"src {token} dst 198.51.100.4"

        once = masker.mask_text(text, {})
        twice = masker.mask_text(once, {})

        assert token in once
        assert token in twice
        assert engine.v2_open(token) == "192.0.2.11"


class TestV1TokensAreNotProtectedByThis:
    """Scope marker, deliberately asserting the current behaviour.

    A v1 IPv4 token is also a dotted quad in an envelope, so the scan
    chews it the same way. That is not fixed here: the v1 path is being
    retired, the shape gate is what tells the two apart, and widening
    this to v1 would change behaviour during the deprecation window
    rather than only protecting the new format.

    Written as a test rather than a comment so that whoever closes the
    window finds a failing assertion pointing at this decision instead of
    silently inheriting it.
    """

    def test_a_v1_ipv4_token_is_still_rewritten(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        v1 = f"ip4-{engine.key_id}-{engine.mask_ip('192.0.2.9')}"

        out = masker.mask_text(v1, {})

        assert out != v1


class TestTheGuardDoesNotOverMatch:
    """Over-matching here is a leak, so it is worse than under-matching.

    The first version of the guard anchored the envelope head with `$` and
    searched an unbounded prefix, with no boundary on the left. Both ends
    of that were wrong, and an adversarial pass measured all of it.
    """

    @pytest.mark.parametrize(
        "prefix",
        ["myhost", "localhost", "poweruser", "gossip4", "tarmac", "unsn"],
    )
    def test_a_word_merely_ending_in_a_marker_is_not_an_envelope(
        self, masker: OutputMasker, prefix: str
    ) -> None:
        """`myhost-` ends with `host-`, and a bare `search` accepted that.

        Measured leak before the fix: `myhost-1234-10.0.0.1-deadbeef` came
        back verbatim with the address in clear.
        """
        out = masker.mask_text(f"{prefix}-1234-10.0.0.1-deadbeef", {})
        assert "10.0.0.1" not in out

    def test_a_newline_does_not_terminate_the_envelope_head(self, masker: OutputMasker) -> None:
        """Python's `$` also matches just before a trailing newline.

        A genuine token can never contain one, so this was pure
        over-match. Measured: the LF form leaked, the CRLF form did not,
        which is exactly the signature of `$` rather than `\\Z`.
        """
        out = masker.mask_text("ip4-2a85-\n10.0.0.1-deadbeef", {})
        assert "10.0.0.1" not in out

    def test_the_guard_protects_exactly_what_this_engine_minted(
        self, engine: FPEEngine, masker: OutputMasker
    ) -> None:
        """The invariant that actually matters, corrected.

        This test used to assert the guard agreed with ``is_v2_shaped``,
        and in doing so it pinned the very conflation that leaked twice:
        shape is the inbound question, ownership is the outbound one. A
        string can be shaped and not ours, and the last case below is
        exactly that, so the old assertion demanded the leak.

        Note it passed while the guard was wrong, because both sides of
        the comparison were the same mistaken notion.
        """
        cases = [
            _v2_ipv4(engine, "192.0.2.9"),
            "myhost-1234-10.0.0.1-deadbeef",
            "localhost-cafe-10.0.0.1-deadbeef",
            "ip4-2a85-10.0.0.1-deadbeef",
        ]
        for case in cases:
            protected = masker.mask_text(case, {}) == case
            assert protected == engine.is_own_v2_token(case), case


class TestTheGuardStaysLinear:
    """The guard runs per IPv4 match; it must not read the whole string.

    Slicing `text[:start]` and `text[end:]` copies the input on every
    match, so a quad-dense log line went quadratic: measured 3.5 s for
    4000 addresses, with per-match cost doubling on every doubling of n.
    Free text is attacker-supplied, so that is a remote CPU-exhaustion
    primitive rather than a tuning matter.

    The envelope head is at most ten characters, so the check needs a
    bounded window, never the whole prefix.
    """

    def test_a_quad_dense_line_does_not_blow_up(self, masker: OutputMasker) -> None:
        import time

        text = " ".join(f"10.0.{i // 256}.{i % 256}" for i in range(4000))

        start = time.perf_counter()
        masker.mask_text(text, {})
        elapsed = time.perf_counter() - start

        # Generous: measured ~3.5s quadratic before, well under 0.2s after.
        # The bound is here to catch a return to quadratic, not to police
        # cipher throughput on a slow runner.
        assert elapsed < 1.5, f"{elapsed:.2f}s for 4000 addresses looks quadratic again"


class TestShapeIsNotOwnership:
    """The root cause of three leaks in this cutover, pinned.

    Two questions were being conflated. "Does this LOOK like a v2
    envelope" is the right question inbound, where a shaped token must be
    committed to v2 rather than retried on v1. Outbound it is the wrong
    question, because a real value can be shaped like a token and the
    shape regex accepts any key id, not only ours.

    Every skip on the output side now asks ``is_own_v2_token``, which adds
    the key id and the tag. These cases all leaked before that change.
    """

    @pytest.mark.parametrize(
        "value",
        [
            "host-ab12-web-01-cafe0123",
            "user-1234-svc-deadbeef",
            "sn-0000-FGT60F-12345678",
        ],
    )
    def test_a_real_value_shaped_like_a_token_is_still_masked(
        self, masker: OutputMasker, engine: FPEEngine, value: str
    ) -> None:
        assert engine.is_v2_shaped(value)  # shaped...
        assert not engine.is_own_v2_token(value)  # ...but not ours
        assert masker.mask_result({"hostname": value})["hostname"] != value

    @pytest.mark.parametrize(
        "text",
        [
            "my-host-2a85-10.0.0.1-deadbeef",
            "src_ip4-2a85-10.0.0.1-deadbeef",
            "sub.host-2a85-10.0.0.1-deadbeef",
            "ip4-2a85-10.0.0.1-deadbeefzz",
            "ip4-2a85-10.0.0.1-deadbeef-cafe",
        ],
    )
    def test_a_near_envelope_in_prose_does_not_shelter_an_address(
        self, masker: OutputMasker, text: str
    ) -> None:
        """The boundary cases that made the old positional guard laxer
        than the shape predicate. They no longer decide anything: they
        only widen the candidate, and the tag settles it."""
        assert "10.0.0.1" not in masker.mask_text(text, {})

    def test_a_foreign_key_id_is_not_ours(self, engine: FPEEngine) -> None:
        """The shape regex takes any four hex, so a token minted under
        another key is shaped but must never be treated as our output."""
        foreign = FPEEngine("00112233445566778899AABBCCDDEEFF")
        token = foreign.mint("ipv4", "192.0.2.9")

        assert engine.is_v2_shaped(token)
        assert not engine.is_own_v2_token(token)

    def test_our_own_token_is_recognised_everywhere(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        """The other direction: the tightened check must not start
        re-masking real output on any route."""
        token = engine.mint("ipv4", "192.0.2.9")

        assert engine.is_own_v2_token(token)
        assert masker.mask_text(token, {}) == token
        assert masker.mask_result({"srcip": token})["srcip"] == token
