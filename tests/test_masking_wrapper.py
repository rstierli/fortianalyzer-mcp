"""Tests for the Phase 1 output-masking wrapper (RFC #40).

Covers the recursive field walk, per-type dispatch, the from/to email
duality, list-valued fields, free-text IOC scanning, response echo keys,
fail-closed placeholders, and the mcp.tool registration patch.
"""

import ipaddress
import re

import pytest

from fortianalyzer_mcp.masking.fields import FIELD_TYPES
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.wrapper import OutputMasker, install_masking

KEY = "2DE79D232DF5585D68CE47882AE256D6"


def _settings_with(**overrides: object) -> object:
    """A stand-in settings object for install_masking's get_settings() call.

    Defaults device-identity masking off; callers override the fields the
    test cares about (e.g. FAZ_MASKING_KEY).
    """
    from types import SimpleNamespace

    fields = {"FAZ_MASK_DEVICE_IDENTITY": False, "FAZ_MASKING_KEY": None}
    fields.update(overrides)
    return SimpleNamespace(**fields)


@pytest.fixture
def masker(monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    return OutputMasker(FPEEngine(KEY))


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY)


class TestFieldTable:
    def test_rfc_dead_names_absent(self):
        # Names the RFC drafted that do not exist in any FAZ schema must
        # not be in the table (masking them would be a silent no-op that
        # feigns coverage).
        for dead in (
            "src",
            "srcaddr",
            "dst",
            "dstaddr",
            "srchost",
            "dsthost",
            "srcuser",
            "remotename",
            "email",
            "message",
            "domain",
        ):
            assert dead not in FIELD_TYPES

    def test_core_fields_present(self):
        for name in (
            "srcip",
            "dstip",
            "srcmac",
            "user",
            "dstuser",
            "srcname",
            "qname",
            "sender",
            "msg",
            "filter",
            "ipv6",
            "bssid",
            "prompt",
        ):
            assert name in FIELD_TYPES


class TestStructureWalk:
    def test_masks_allowlisted_fields_at_any_depth(self, masker: OutputMasker, engine: FPEEngine):
        result = {
            "status": "success",
            "logs": [
                {"srcip": "192.0.2.102", "user": "jdoe", "action": "deny", "bytes": 42},
                {"srcip": "192.0.2.103", "srcmac": "00:1a:2b:3c:4d:5e"},
            ],
            "nested": {"event_details": {"src_ip": "192.0.2.7", "host_name": "edge-fw-01"}},
        }
        masked = masker.mask_result(result)
        assert masked["status"] == "success"
        assert masked["logs"][0]["action"] == "deny"
        assert masked["logs"][0]["bytes"] == 42
        assert masked["logs"][0]["srcip"] != "192.0.2.102"
        ipaddress.IPv4Address(masked["logs"][0]["srcip"])
        assert engine.unmask_ip(masked["logs"][0]["srcip"]) == "192.0.2.102"
        assert masked["logs"][0]["user"].startswith("user-")
        assert masked["logs"][1]["srcmac"] != "00:1a:2b:3c:4d:5e"
        assert masked["nested"]["event_details"]["src_ip"] != "192.0.2.7"
        assert masked["nested"]["event_details"]["host_name"].startswith("host-")

    def test_list_valued_ip_field(self, masker: OutputMasker):
        masked = masker.mask_result({"ipaddr": ["192.0.2.1", "192.0.2.2"]})
        assert len(masked["ipaddr"]) == 2
        for item in masked["ipaddr"]:
            assert item not in ("192.0.2.1", "192.0.2.2")
            ipaddress.IPv4Address(item)

    def test_comma_joined_ip_string(self, masker: OutputMasker, engine: FPEEngine):
        # Live FAZ packs dns answers into one comma-joined string.
        masked = masker.mask_result({"ipaddr": "192.0.2.1,192.0.2.2,2001:db8::1"})
        parts = masked["ipaddr"].split(",")
        assert len(parts) == 3
        assert "192.0.2.1" not in parts and "2001:db8::1" not in parts
        assert engine.unmask_ip(parts[0]) == "192.0.2.1"
        assert engine.unmask_ip(parts[2]) == "2001:db8::1"

    def test_skip_values_pass_through(self, masker: OutputMasker):
        masked = masker.mask_result({"user": "N/A", "srcip": "", "dstuser": "unknown"})
        assert masked == {"user": "N/A", "srcip": "", "dstuser": "unknown"}

    def test_non_string_scalars_untouched(self, masker: OutputMasker):
        masked = masker.mask_result({"count": 5, "has_more": False, "tid": None})
        assert masked == {"count": 5, "has_more": False, "tid": None}


class TestEmailDuality:
    def test_email_value_masks_as_email(self, masker: OutputMasker, engine: FPEEngine):
        masked = masker.mask_result({"from": "alice@example.com"})
        assert masked["from"].endswith(".masked.invalid")
        assert engine.unmask_email(masked["from"]) == "alice@example.com"

    def test_non_email_value_masks_as_username(self, masker: OutputMasker):
        # webfilter/event logs use from/to as plain labels, not addresses
        masked = masker.mask_result({"from": "wad"})
        assert masked["from"].startswith("user-")


class TestTextScan:
    def test_embedded_ip_and_email_masked(self, masker: OutputMasker):
        text = "blocked 192.0.2.102 for alice@example.com (rule 7)"
        out = masker.mask_text(text)
        assert "192.0.2.102" not in out
        assert "alice@example.com" not in out
        assert "(rule 7)" in out

    def test_invalid_ipv4_lookalike_untouched(self, masker: OutputMasker):
        assert masker.mask_text("version 999.1.2.3 ok") == "version 999.1.2.3 ok"

    def test_embedded_mac_masked(self, masker: OutputMasker):
        out = masker.mask_text("client ae:42:a1:52:45:d6 associated")
        assert "ae:42:a1:52:45:d6" not in out
        assert re.search(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", out)

    def test_echo_keys_scanned(self, masker: OutputMasker):
        masked = masker.mask_result({"filter": 'srcip=="192.0.2.102"', "device": "FGT-BRANCH-01"})
        assert "192.0.2.102" not in masked["filter"]
        assert masked["device"].startswith("host-")

    def test_echo_remask_matches_field_token(self, masker: OutputMasker, engine: FPEEngine):
        # Deterministic FPE: the IP inside an echoed filter string masks to
        # the same token as the srcip field, so follow-up turns correlate.
        masked = masker.mask_result(
            {"filter": 'srcip=="192.0.2.102"', "logs": [{"srcip": "192.0.2.102"}]}
        )
        assert masked["logs"][0]["srcip"] in masked["filter"]


class TestFailClosed:
    def test_unmaskable_value_becomes_placeholder(self, masker: OutputMasker):
        masked = masker.mask_result({"user": "DOMAIN\\user with spaces"})
        assert masked["user"].startswith("masked-unrepresentable-")

    def test_placeholder_is_deterministic_and_distinct(self, masker: OutputMasker):
        a1 = masker.placeholder("DOMAIN\\alice")
        a2 = masker.placeholder("DOMAIN\\alice")
        b = masker.placeholder("DOMAIN\\bob")
        assert a1 == a2 != b

    def test_result_level_failure_withholds_raw(self, masker: OutputMasker, monkeypatch):
        def boom(obj):
            raise RuntimeError("engine exploded")

        monkeypatch.setattr(masker, "mask_result", boom)
        out = masker.mask_tool_result({"srcip": "192.0.2.102"}, "get_alerts")
        assert out["status"] == "error"
        assert out["error"] == "masking_failed"
        assert "192.0.2.102" not in str(out)


class TestInstallMasking:
    async def test_tools_registered_after_install_are_wrapped(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        from mcp.server.fastmcp import FastMCP

        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        mcp = FastMCP("test")
        install_masking(mcp)

        @mcp.tool()
        async def fake_tool() -> dict:
            return {"logs": [{"srcip": "192.0.2.102", "user": "jdoe"}], "count": 1}

        result = await fake_tool()
        assert result["count"] == 1
        assert result["logs"][0]["srcip"] != "192.0.2.102"
        assert result["logs"][0]["user"].startswith("user-")

    def test_install_without_key_fails_loud(self, monkeypatch: pytest.MonkeyPatch):
        from mcp.server.fastmcp import FastMCP

        import fortianalyzer_mcp.utils.config as config_mod
        from fortianalyzer_mcp.masking.fpe_engine import MaskingError

        # Neutralize BOTH key sources: the process environment and the
        # Settings/.env value the fix bridges from (a local .env with a key
        # would otherwise mask this crash — the very failure the fix prevents).
        monkeypatch.delenv("FAZ_MASKING_KEY", raising=False)
        monkeypatch.setattr(
            config_mod, "get_settings", lambda: _settings_with(FAZ_MASKING_KEY=None)
        )
        with pytest.raises(MaskingError, match="FAZ_MASKING_KEY"):
            install_masking(FastMCP("test"))

    def test_key_resolves_from_settings_when_not_in_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Regression: MASKING_ENABLED reads .env via Settings, but the engine
        reads FAZ_MASKING_KEY from os.environ. If the key lives only in .env
        (as the README documents), install_masking must bridge it or the
        server crashes fail-closed on startup. A real env var still wins."""
        from mcp.server.fastmcp import FastMCP

        import fortianalyzer_mcp.utils.config as config_mod

        monkeypatch.delenv("FAZ_MASKING_KEY", raising=False)
        monkeypatch.setattr(config_mod, "get_settings", lambda: _settings_with(FAZ_MASKING_KEY=KEY))
        masker, _ = install_masking(FastMCP("test"))
        assert masker is not None
        # the bridge exported it so the engine and placeholder key both see it
        import os

        assert os.environ.get("FAZ_MASKING_KEY") == KEY
