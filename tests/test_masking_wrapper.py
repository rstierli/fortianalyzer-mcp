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

    def test_text_list_scans_each_string(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"msg": ["Connection from 192.0.2.7 by bob@example.com", "second line"]}
        )

        assert "192.0.2.7" not in str(masked)
        assert "bob@example.com" not in str(masked)
        assert masked["msg"][1] == "second line"

    def test_text_dict_typed_key_is_not_double_masked(self, masker: OutputMasker):
        nested = masker.mask_result({"msg": {"srcip": "192.0.2.9"}})["msg"]["srcip"]
        bare = masker.mask_result({"srcip": "192.0.2.9"})["srcip"]

        assert nested == bare

    def test_text_dict_composite_key_is_not_double_masked(self, masker: OutputMasker):
        raw = "srcip:192.0.2.17"
        nested = masker.mask_result({"msg": {"groupby1": raw}})["msg"]["groupby1"]
        bare = masker.mask_result({"groupby1": raw})["groupby1"]

        assert nested == bare
        assert "192.0.2.17" not in nested


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


class TestTargetFailClosed:
    def test_non_dict_target_item_is_burned(self, masker: OutputMasker):
        raw = "192.0.2.50"
        masked = masker.mask_result({"target": [raw]})

        assert masked["target"][0].startswith("masked-unrepresentable-")
        assert raw not in str(masked)

    def test_nested_list_target_item_is_burned(self, masker: OutputMasker):
        raw = "192.0.2.51"
        masked = masker.mask_result({"target": [[raw]]})

        assert masked["target"][0][0].startswith("masked-unrepresentable-")
        assert raw not in str(masked)

    def test_nested_dict_target_item_is_burned(self, masker: OutputMasker):
        raw = "192.0.2.52"
        masked = masker.mask_result({"target": [[{"name": "ip", "value": raw}]]})

        assert raw not in str(masked)

    def test_known_name_dict_key_is_burned(self, masker: OutputMasker):
        raw = "192.0.2.53"
        masked = masker.mask_result({"target": [{"name": "ip", "value": {raw: {"hits": 3}}}]})

        assert raw not in str(masked)

    def test_unknown_name_dict_key_is_burned(self, masker: OutputMasker):
        raw = "192.0.2.54"
        masked = masker.mask_result({"target": [{"name": "whatever", "value": {raw: 1}}]})

        assert raw not in str(masked)

    def test_known_name_deeply_nested_string_leaf_is_burned(self, masker: OutputMasker):
        """This passes before the fix and pins the existing deep recursion."""
        raw = "192.0.2.55"
        masked = masker.mask_result(
            {
                "target": [
                    {"name": "ip", "value": [{"a": [{"b": raw}]}]},
                ]
            }
        )

        assert raw not in str(masked)

    def test_non_list_target_string_is_burned(self, masker: OutputMasker):
        raw = "bad.example.com"
        masked = masker.mask_result({"target": raw})

        assert masked["target"].startswith("masked-unrepresentable-")
        assert raw not in str(masked)

    def test_non_list_target_dict_is_burned(self, masker: OutputMasker):
        raw = "192.0.2.90"
        masked = masker.mask_result({"target": {"name": "ip", "value": raw}})

        assert raw not in str(masked)

    def test_tuple_target_is_burned(self, masker: OutputMasker):
        """JSON payloads never produce tuples; this is defensive only.

        Pin tuple support so ``list | tuple`` is not simplified to ``list``.
        """
        raw = "192.0.2.91"
        masked = masker.mask_result({"target": ({"name": "ip", "value": raw},)})

        assert raw not in str(masked)

    def test_scalar_target_passes_through(self, masker: OutputMasker):
        masked = masker.mask_result({"target": 1107})

        assert masked["target"] == 1107

    def test_stray_string_beside_a_valid_target_entry_burns_only_the_stray(
        self, masker: OutputMasker, engine: FPEEngine
    ):
        raw_ip = "192.0.2.92"
        stray = "bad.example.com"
        masked = masker.mask_result({"target": [{"name": "ip", "value": raw_ip}, stray]})
        valid, burned = masked["target"]

        assert engine.unmask_ip(valid["value"]) == raw_ip
        assert "masked-unrepresentable-" not in valid["value"]
        assert burned.startswith("masked-unrepresentable-")
        assert raw_ip not in str(masked)
        assert stray not in str(masked)

    def test_keep_value_as_dict_key_stays_clear(self, masker: OutputMasker):
        devid = "FGT60F0000000000"
        masked = masker.mask_result(
            {"devid": devid, "target": [{"name": "ip", "value": {devid: 1}}]}
        )

        assert devid in masked["target"][0]["value"]

    def test_non_list_target_keeps_device_identity_clear(self, masker: OutputMasker):
        devid = "FGT60F0000000000"
        masked = masker.mask_result({"devid": devid, "target": devid})

        assert masked["target"] == devid

    def test_known_name_list_masks_each_string(self, masker: OutputMasker):
        raw_values = ["192.0.2.10", "192.0.2.11"]
        masked = masker.mask_result({"target": [{"name": "ip", "value": raw_values}]})
        values = masked["target"][0]["value"]

        assert all(value not in raw_values for value in values)
        assert all(raw not in str(masked) for raw in raw_values)

    def test_unknown_name_string_is_burned(self, masker: OutputMasker):
        raw = "bob@example.com"
        masked = masker.mask_result({"target": [{"name": "email", "value": raw}]})

        assert masked["target"][0]["value"].startswith("masked-unrepresentable-")
        assert raw not in str(masked)

    def test_unknown_name_list_strings_are_burned(self, masker: OutputMasker):
        raw_values = ["bob@example.com", "alice@example.org"]
        masked = masker.mask_result({"target": [{"name": "email", "value": raw_values}]})
        values = masked["target"][0]["value"]

        assert all(value.startswith("masked-unrepresentable-") for value in values)
        assert all(raw not in str(masked) for raw in raw_values)

    def test_nested_sibling_key_uses_normal_masking(self, masker: OutputMasker):
        masked = masker.mask_result(
            {
                "target": [
                    {
                        "name": "user",
                        "value": "alice",
                        "detail": {"srcip": "192.0.2.12"},
                    }
                ]
            }
        )
        entry = masked["target"][0]

        assert entry["value"].startswith("user-")
        assert entry["detail"]["srcip"] != "192.0.2.12"
        assert "192.0.2.12" not in str(masked)

    def test_known_name_dict_burns_nested_strings(self, masker: OutputMasker):
        masked = masker.mask_result({"target": [{"name": "ip", "value": {"note": "192.0.2.13"}}]})

        value = next(iter(masked["target"][0]["value"].values()))
        assert value.startswith("masked-unrepresentable-")
        assert "192.0.2.13" not in str(masked)

    def test_known_name_list_burns_nested_strings(self, masker: OutputMasker):
        masked = masker.mask_result({"target": [{"name": "ip", "value": [{"note": "192.0.2.14"}]}]})

        value = next(iter(masked["target"][0]["value"][0].values()))
        assert value.startswith("masked-unrepresentable-")
        assert "192.0.2.14" not in str(masked)

    def test_repeated_list_asset_value_reuses_masked_value(self, masker: OutputMasker):
        raw = ["192.0.2.50"]
        masked = masker.mask_result({"target": [{"name": "ip", "value": raw, "asset_value": raw}]})
        entry = masked["target"][0]

        assert entry["asset_value"] == entry["value"]
        assert "192.0.2.50" not in str(masked)

    def test_known_name_value_in_keep_stays_clear(self, masker: OutputMasker):
        devid = "FGT60F0000000000"
        masked = masker.mask_result(
            {"devid": devid, "target": [{"name": "device", "value": devid}]}
        )

        assert masked["target"][0]["value"] == devid

    def test_unknown_name_value_in_keep_stays_clear(self, masker: OutputMasker):
        devid = "FGT60F0000000000"
        masked = masker.mask_result({"devid": devid, "target": [{"name": "email", "value": devid}]})

        assert masked["target"][0]["value"] == devid


class TestCaseInsensitiveFieldLookup:
    def test_mixed_case_reporter_sibling_still_masks_incident_reporter(self, masker: OutputMasker):
        user = "example-user"
        masked = masker.mask_result({"Reporter": user, "incident_reporter": user})

        assert user not in str(masked)
        assert masked["incident_reporter"] == masked["Reporter"]

    def test_mixed_case_incident_reporter_key_masks_and_keeps_its_spelling(
        self, masker: OutputMasker
    ):
        user = "example-operator"
        masked = masker.mask_result({"lastuser": user, "Incident_Reporter": user})

        assert user not in str(masked)
        assert "Incident_Reporter" in masked

    def test_mixed_case_threat_sibling_masks_with_obf_url(self, masker: OutputMasker):
        domain = "bad.example.com"
        masked = masker.mask_result({"obf_url": "bad[dot]example[dot]com", "Threat": domain})

        assert domain not in str(masked)
        assert masked["Threat"] == masked["obf_url"].replace("[dot]", ".")

    def test_mixed_case_obf_url_key_masks_the_pair(self, masker: OutputMasker):
        domain = "bad.example.com"
        escaped = "bad[dot]example[dot]com"
        masked = masker.mask_result({"OBF_URL": escaped, "THREAT": domain})

        assert domain not in str(masked)
        assert escaped not in str(masked)
        assert list(masked) == ["OBF_URL", "THREAT"]

    def test_mixed_case_auto_raised_alert_id_still_stays_clear(self, masker: OutputMasker):
        alert_id = "202607101000000020"
        masked = masker.mask_result({"Reporter": "Auto-Raised", "incident_reporter": alert_id})

        assert masked["incident_reporter"] == alert_id

    def test_tuple_value_under_a_known_target_name_is_masked(self, masker: OutputMasker):
        # The known-name branch accepts tuples as well as lists; without that
        # a tuple falls through to the verbatim tail and the address survives.
        masked = masker.mask_result({"target": [{"name": "ip", "value": ("192.0.2.93",)}]})

        assert "192.0.2.93" not in str(masked)

    def test_non_string_target_name_is_burned(self, masker: OutputMasker):
        # A label is a short string. Any other shape is not a label, and the
        # name slot is echoed verbatim by design, so its content must burn.
        masked = masker.mask_result(
            {"target": [{"name": {"label": "bad.example.com"}, "value": "192.0.2.94"}]}
        )

        assert "bad.example.com" not in str(masked)
        assert "192.0.2.94" not in str(masked)

    def test_unhashable_reporter_sibling_does_not_break_masking(self, masker: OutputMasker):
        # The sibling values are compared as a tuple, not a set: a malformed
        # record can carry a list under `reporter`, and a set comprehension
        # would raise TypeError straight out of mask_result.
        user = "example-user"
        masked = masker.mask_result({"incident_reporter": user, "reporter": [user]})

        assert masked["incident_reporter"] == user

    def test_mixed_case_typed_key_masks(self, masker: OutputMasker):
        masked = masker.mask_result({"SrcIP": "192.0.2.20"})

        assert masked["SrcIP"] != "192.0.2.20"

    def test_mixed_case_text_key_is_scanned(self, masker: OutputMasker):
        masked = masker.mask_result({"Msg": "from 192.0.2.21"})

        assert "192.0.2.21" not in masked["Msg"]

    def test_mixed_case_device_identity_populates_keep(self, masker: OutputMasker):
        devid = "FGT60F0000000000"
        masked = masker.mask_result(
            {"DevId": devid, "target": [{"name": "device", "value": devid}]}
        )

        assert masked["target"][0]["value"] == devid

    def test_mixed_case_target_structural_keys_mask_value(self, masker: OutputMasker):
        masked = masker.mask_result({"target": [{"Name": "ip", "Value": "192.0.2.18"}]})

        assert "Value" in masked["target"][0]
        assert "192.0.2.18" not in str(masked)


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
