"""Tests for the FPE masking engine (RFC #40, Phase 0).

Covers per-type round-trips, determinism, reversibility from the key
alone, FF3-1 domain-size edge cases (short values, chunked long values),
token conventions, and key handling.
"""

import ipaddress
import re

import pytest

from fortianalyzer_mcp.masking import FPEEngine, MaskingError
from fortianalyzer_mcp.masking.fpe_engine import MASKING_KEY_ENV

KEY_128 = "2DE79D232DF5585D68CE47882AE256D6"
KEY_256 = "2DE79D232DF5585D68CE47882AE256D64977ECD3F3F5064531B77B70098AA9F4"
OTHER_KEY = "00000000000000000000000000000001"


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY_128)


# --------------------------------------------------------------------- #
# Key handling                                                          #
# --------------------------------------------------------------------- #


class TestKeyHandling:
    def test_accepts_aes_128_192_256_hex_keys(self):
        FPEEngine(KEY_128)
        FPEEngine(KEY_128 + KEY_128[:16])
        FPEEngine(KEY_256)

    @pytest.mark.parametrize("bad", ["", "abc", "zz" * 16, KEY_128[:-2], KEY_128 + "00"])
    def test_rejects_invalid_keys(self, bad: str):
        with pytest.raises(MaskingError):
            FPEEngine(bad)

    def test_invalid_key_error_does_not_echo_key_material(self):
        with pytest.raises(MaskingError) as excinfo:
            FPEEngine(KEY_128[:-2])
        assert KEY_128[:8] not in str(excinfo.value)

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv(MASKING_KEY_ENV, KEY_128)
        eng = FPEEngine.from_env()
        assert eng.unmask_ip(eng.mask_ip("192.0.2.48")) == "192.0.2.48"

    def test_from_env_unset(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv(MASKING_KEY_ENV, raising=False)
        with pytest.raises(MaskingError, match=MASKING_KEY_ENV):
            FPEEngine.from_env()


# --------------------------------------------------------------------- #
# IP addresses                                                          #
# --------------------------------------------------------------------- #


class TestIpMasking:
    @pytest.mark.parametrize(
        "ip", ["192.0.2.48", "198.51.100.53", "0.0.0.0", "255.255.255.255", "8.8.8.8"]
    )
    def test_ipv4_roundtrip_and_validity(self, engine: FPEEngine, ip: str):
        masked = engine.mask_ip(ip)
        assert masked != ip
        ipaddress.IPv4Address(masked)  # masked form is a valid IPv4
        assert engine.unmask_ip(masked) == ip

    @pytest.mark.parametrize("ip", ["2001:db8::1", "fe80::1", "::1"])
    def test_ipv6_roundtrip_and_validity(self, engine: FPEEngine, ip: str):
        masked = engine.mask_ip(ip)
        assert masked != ip
        ipaddress.IPv6Address(masked)
        assert engine.unmask_ip(masked) == ip

    def test_deterministic_across_instances(self):
        assert FPEEngine(KEY_128).mask_ip("192.0.2.48") == FPEEngine(KEY_128).mask_ip(
            "192.0.2.48"
        )

    def test_different_key_different_token(self):
        assert FPEEngine(KEY_128).mask_ip("192.0.2.48") != FPEEngine(OTHER_KEY).mask_ip(
            "192.0.2.48"
        )

    def test_invalid_ip_raises(self, engine: FPEEngine):
        with pytest.raises(MaskingError):
            engine.mask_ip("not-an-ip")


# --------------------------------------------------------------------- #
# MAC addresses                                                         #
# --------------------------------------------------------------------- #


class TestMacMasking:
    @pytest.mark.parametrize(
        "mac", ["00:1a:2b:3c:4d:5e", "00-1A-2B-3C-4D-5E", "001a.2b3c.4d5e", "001a2b3c4d5e"]
    )
    def test_roundtrip_normalizes_to_colon_form(self, engine: FPEEngine, mac: str):
        masked = engine.mask_mac(mac)
        assert re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", masked)
        assert engine.unmask_mac(masked) == "00:1a:2b:3c:4d:5e"

    def test_masked_mac_differs(self, engine: FPEEngine):
        assert engine.mask_mac("00:1a:2b:3c:4d:5e") != "00:1a:2b:3c:4d:5e"

    def test_invalid_mac_raises(self, engine: FPEEngine):
        with pytest.raises(MaskingError):
            engine.mask_mac("00:1a:2b:3c:4d")


# --------------------------------------------------------------------- #
# Hostnames / usernames (incl. FF3-1 min-domain padding edges)          #
# --------------------------------------------------------------------- #


class TestNameMasking:
    @pytest.mark.parametrize(
        "name",
        [
            "edge-fw-01",
            "dc1",  # below FF3-1 min length -> padded
            "a",  # 1 char, extreme pad case
            "abcd",  # exactly min length, no padding
            "a" * 36,  # exactly max single-block length
        ],
    )
    def test_hostname_roundtrip(self, engine: FPEEngine, name: str):
        masked = engine.mask_hostname(name)
        assert masked.startswith("host-")
        assert engine.unmask_hostname(masked) == name

    @pytest.mark.parametrize("length", [37, 40, 72, 73, 100])
    def test_long_hostname_chunked_roundtrip(self, engine: FPEEngine, length: int):
        name = ("x9" * 50)[:length]
        assert engine.unmask_hostname(engine.mask_hostname(name)) == name

    def test_chunked_tokens_do_not_repeat_for_repeating_plaintext(self, engine: FPEEngine):
        # 72 = two full 36-char blocks of identical plaintext; the
        # position-varied tweak must yield different ciphertext blocks.
        masked = engine.mask_hostname("a" * 72).removeprefix("host-")
        assert masked[:36] != masked[36:72]

    def test_username_roundtrip_with_underscore(self, engine: FPEEngine):
        masked = engine.mask_username("john_doe")
        assert masked.startswith("user-")
        assert engine.unmask_username(masked) == "john_doe"

    def test_hostname_and_username_tweaks_differ(self, engine: FPEEngine):
        # Same raw value masked as different types must not collide.
        host_ct = engine.mask_hostname("admin").removeprefix("host-")
        user_ct = engine.mask_username("admin").removeprefix("user-")
        assert host_ct != user_ct

    def test_normalizes_to_lowercase(self, engine: FPEEngine):
        assert engine.unmask_hostname(engine.mask_hostname("EDGE-FW-01")) == "edge-fw-01"

    def test_empty_value_raises(self, engine: FPEEngine):
        with pytest.raises(MaskingError):
            engine.mask_hostname("  ")

    def test_pad_char_in_value_raises(self, engine: FPEEngine):
        with pytest.raises(MaskingError):
            engine.mask_hostname("bad~name")

    def test_out_of_alphabet_value_raises(self, engine: FPEEngine):
        with pytest.raises(MaskingError):
            engine.mask_username("dom\\user")


# --------------------------------------------------------------------- #
# Domains / emails                                                      #
# --------------------------------------------------------------------- #


class TestDomainEmailMasking:
    @pytest.mark.parametrize("domain", ["example.com", "sub.example.co.uk", "xn--nxasmq6b.com"])
    def test_domain_roundtrip_and_marker(self, engine: FPEEngine, domain: str):
        masked = engine.mask_domain(domain)
        assert masked.endswith(".masked.invalid")
        assert engine.unmask_domain(masked) == domain

    def test_long_domain_chunked_roundtrip(self, engine: FPEEngine):
        domain = "a-very-long-subdomain-label-here.department.example-corporation.com"
        assert engine.unmask_domain(engine.mask_domain(domain)) == domain

    def test_email_roundtrip_and_marker(self, engine: FPEEngine):
        masked = engine.mask_email("jdoe@example.com")
        local, _, domain = masked.partition("@")
        assert local and domain.endswith(".masked.invalid")
        assert engine.unmask_email(masked) == "jdoe@example.com"

    def test_email_same_domain_same_domain_token(self, engine: FPEEngine):
        # Correlation: two users on one domain share the domain ciphertext.
        d1 = engine.mask_email("alice@example.com").partition("@")[2]
        d2 = engine.mask_email("bob@example.com").partition("@")[2]
        assert d1 == d2

    def test_email_domain_token_matches_domain_masking(self, engine: FPEEngine):
        # The domain inside an email token uses the domain tweak, so it
        # correlates with the same domain masked standalone.
        email_domain = engine.mask_email("alice@example.com").partition("@")[2]
        assert email_domain == engine.mask_domain("example.com")

    def test_invalid_email_raises(self, engine: FPEEngine):
        with pytest.raises(MaskingError):
            engine.mask_email("no-at-sign")

    def test_custom_mask_suffix(self):
        eng = FPEEngine(KEY_128, mask_suffix="masked.example.net")
        masked = eng.mask_domain("example.com")
        assert masked.endswith(".masked.example.net")
        assert eng.unmask_domain(masked) == "example.com"

    def test_unmask_with_wrong_suffix_raises(self, engine: FPEEngine):
        with pytest.raises(MaskingError):
            engine.unmask_domain("abcde.masked.other")


# --------------------------------------------------------------------- #
# Generic token recognition                                             #
# --------------------------------------------------------------------- #


class TestUnmaskToken:
    def test_recognizes_all_marked_types(self, engine: FPEEngine):
        cases = {
            engine.mask_hostname("edge-fw-01"): "edge-fw-01",
            engine.mask_username("jdoe"): "jdoe",
            engine.mask_domain("example.com"): "example.com",
            engine.mask_email("alice@example.com"): "alice@example.com",
        }
        for token, real in cases.items():
            assert engine.unmask_token(token) == real

    def test_returns_none_for_unmarked_values(self, engine: FPEEngine):
        assert engine.unmask_token("192.0.2.48") is None
        assert engine.unmask_token("plain-hostname") is None
        assert engine.unmask_token("alice@example.com") is None

    def test_suffix_marker_wins_over_prefix(self, engine: FPEEngine):
        # A token that looks like both must route by suffix (the stronger
        # marker) — a domain payload can start with "host-" by chance.
        token = "host-abcd.masked.invalid"
        result = engine.unmask_token(token)
        assert result == engine.unmask_domain(token)

    def test_marker_with_garbage_payload_raises(self, engine: FPEEngine):
        with pytest.raises(MaskingError):
            engine.unmask_token("host-###")
