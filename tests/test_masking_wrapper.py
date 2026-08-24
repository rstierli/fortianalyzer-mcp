"""Tests for the Phase 1 output-masking wrapper (RFC #40).

Covers the recursive field walk, per-type dispatch, the from/to email
duality, list-valued fields, free-text IOC scanning, response echo keys,
fail-closed placeholders, and the mcp.tool registration patch.
"""

import pytest

from fortianalyzer_mcp.masking.fields import DOMAIN, EMAIL, FIELD_TYPES, TEXT
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.wrapper import OutputMasker, install_masking

KEY = "2DE79D232DF5585D68CE47882AE256D6"


def _settings_with(**overrides: object) -> object:
    """A stand-in settings object for install_masking's get_settings() call.

    Defaults device-identity masking off; callers override the fields the
    test cares about (e.g. FAZ_MASKING_KEY).
    """
    from types import SimpleNamespace

    fields = {
        "FAZ_MASK_DEVICE_IDENTITY": False,
        "FAZ_MASKING_KEY": None,
        # Mirrors the real default. A stub that omits a field the composition
        # point reads fails with an AttributeError rather than silently
        # exercising a different configuration, which is why this is listed
        # here instead of being defaulted away with getattr in production.
        "FAZ_MASKING_ACCEPT_V1_TOKENS": True,
    }
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
        ):
            assert dead not in FIELD_TYPES

    def test_names_dead_in_logview_but_live_on_another_reader(self):
        # These three left the list above because a real tool response
        # carries them: UEBA end-users answer under "email", a fortiview
        # top-websites row names the browsed site "domain", and every tool
        # error answers under "message". Absent from get_log_fields is not
        # absent from a tool response.
        assert FIELD_TYPES["email"] == EMAIL
        assert FIELD_TYPES["domain"] == DOMAIN
        assert FIELD_TYPES["message"] == TEXT

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
        # A masked IPv4 used to BE an IPv4. Under the v2 envelope it is a
        # marked token whose payload is one, which is what lets the layer
        # recognise its own output instead of re-masking it.
        assert engine.is_v2_shaped(masked["logs"][0]["srcip"])
        assert engine.unmask_token(masked["logs"][0]["srcip"]) == "192.0.2.102"
        assert masked["logs"][0]["user"].startswith("user-")
        assert masked["logs"][1]["srcmac"] != "00:1a:2b:3c:4d:5e"
        assert masked["nested"]["event_details"]["src_ip"] != "192.0.2.7"
        assert masked["nested"]["event_details"]["host_name"].startswith("host-")

    def test_list_valued_ip_field(self, masker: OutputMasker, engine: FPEEngine):
        masked = masker.mask_result({"ipaddr": ["192.0.2.1", "192.0.2.2"]})
        assert len(masked["ipaddr"]) == 2
        for item, original in zip(masked["ipaddr"], ("192.0.2.1", "192.0.2.2"), strict=True):
            assert item != original
            assert engine.v2_open(item) == original

    def test_comma_joined_ip_string(self, masker: OutputMasker, engine: FPEEngine):
        # Live FAZ packs dns answers into one comma-joined string.
        masked = masker.mask_result({"ipaddr": "192.0.2.1,192.0.2.2,2001:db8::1"})
        parts = masked["ipaddr"].split(",")
        assert len(parts) == 3
        assert "192.0.2.1" not in parts and "2001:db8::1" not in parts
        assert engine.unmask_token(parts[0]) == "192.0.2.1"
        assert engine.unmask_token(parts[2]) == "2001:db8::1"

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

    def test_embedded_mac_masked(self, masker: OutputMasker, engine: FPEEngine):
        """A MAC in prose masks into a marked token, not another MAC.

        The old assertion looked for a colon-separated MAC in the output,
        which was right while a masked MAC was itself a MAC. The v2 MAC
        payload is colon-free hex precisely so the free-text MAC scan
        cannot see it and chew it on a later pass, so the property to
        assert now is the marker and the round trip.
        """
        out = masker.mask_text("client ae:42:a1:52:45:d6 associated")

        assert "ae:42:a1:52:45:d6" not in out
        token = out.split("client ")[1].split(" associated")[0]
        assert token.startswith("mac-")
        assert engine.v2_open(token) == "ae:42:a1:52:45:d6"

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

    def test_uuid_name_labels_typed_text(self):
        # srcuuid_name/dstuuid_name are resolved address-object labels, added
        # as TEXT (#80): free-form, so HOSTNAME would burn on spaces.
        assert FIELD_TYPES["srcuuid_name"] == TEXT
        assert FIELD_TYPES["dstuuid_name"] == TEXT
        # The raw uuids carry no human content and stay out of the table.
        assert "srcuuid" not in FIELD_TYPES
        assert "dstuuid" not in FIELD_TYPES

    def test_uuid_name_masks_embedded_ioc_leaves_label_clear(self, masker: OutputMasker):
        # TEXT masks an embedded IOC in place; a plain label rides through
        # (the documented residual).
        masked = masker.mask_result(
            {"srcuuid_name": "host 192.0.2.51", "dstuuid_name": "Printer Floor 3"}
        )
        assert "192.0.2.51" not in masked["srcuuid_name"]
        assert masked["dstuuid_name"] == "Printer Floor 3"

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

        assert engine.unmask_token(valid["value"]) == raw_ip
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
        from mcp.server.mcpserver import MCPServer

        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        mcp = MCPServer("test")
        install_masking(mcp)

        @mcp.tool()
        async def fake_tool() -> dict:
            return {"logs": [{"srcip": "192.0.2.102", "user": "jdoe"}], "count": 1}

        result = await fake_tool()
        assert result["count"] == 1
        assert result["logs"][0]["srcip"] != "192.0.2.102"
        assert result["logs"][0]["user"].startswith("user-")

    def test_install_without_key_fails_loud(self, monkeypatch: pytest.MonkeyPatch):
        from mcp.server.mcpserver import MCPServer

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
            install_masking(MCPServer("test"))

    def test_key_resolves_from_settings_when_not_in_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Regression: MASKING_ENABLED reads .env via Settings, but the engine
        reads FAZ_MASKING_KEY from os.environ. If the key lives only in .env
        (as the README documents), install_masking must bridge it or the
        server crashes fail-closed on startup. A real env var still wins."""
        from mcp.server.mcpserver import MCPServer

        import fortianalyzer_mcp.utils.config as config_mod

        monkeypatch.delenv("FAZ_MASKING_KEY", raising=False)
        monkeypatch.setattr(config_mod, "get_settings", lambda: _settings_with(FAZ_MASKING_KEY=KEY))
        masker, _ = install_masking(MCPServer("test"))
        assert masker is not None
        # the bridge exported it so the engine and placeholder key both see it
        import os

        assert os.environ.get("FAZ_MASKING_KEY") == KEY


class TestCompositeListShapes:
    """#73 item 1: composite keys arriving as lists must not fall through
    to the allowlist walk, which cannot type a bare string element."""

    def test_prefixed_list_masks_each_element(self, masker: OutputMasker):
        raw = "192.0.2.90"
        masked = masker.mask_result({"groupby1": [f"srcip:{raw}", "srcport:443"]})

        assert raw not in str(masked)
        assert masked["groupby1"][0].startswith("srcip:")
        # same treatment as the string shape, element for element
        twin = masker.mask_result({"groupby1": f"srcip:{raw}"})["groupby1"]
        assert masked["groupby1"][0] == twin
        # an untyped inner field is left alone, exactly like the string shape
        assert masked["groupby1"][1] == "srcport:443"

    def test_prefixed_list_non_string_item_is_walked(self, masker: OutputMasker):
        masked = masker.mask_result({"groupby1": ["srcip:192.0.2.90", {"srcip": "192.0.2.91"}]})

        assert "192.0.2.90" not in str(masked)
        assert "192.0.2.91" not in str(masked)

    def test_url_host_list_masks_each_element(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"http_url": ["https://bad.example.com/x", "https://other.example.net/y"]}
        )

        assert "bad.example.com" not in str(masked)
        assert "other.example.net" not in str(masked)
        # host-only masking: request mechanics stay readable
        assert masked["http_url"][0].endswith("/x")
        twin = masker.mask_result({"http_url": "https://bad.example.com/x"})["http_url"]
        assert masked["http_url"][0] == twin


class TestCompositeDictShapesFailClosed:
    """#73 item 1, the dict half: a map under a URL composite key has no
    slot the handler can type, so it burns whole, same policy as target."""

    def test_url_full_dict_burns(self, masker: OutputMasker):
        masked = masker.mask_result({"url": {"u": "https://bad.example.com/x"}})

        assert "bad.example.com" not in str(masked)
        # keys burn too: a key can carry the identifier just as a value can
        value = next(iter(masked["url"].values()))
        assert value.startswith("masked-unrepresentable-")

    def test_url_host_dict_burns(self, masker: OutputMasker):
        masked = masker.mask_result({"http_url": {"u": "https://bad.example.com/x"}})

        assert "bad.example.com" not in str(masked)

    def test_url_dict_key_is_burned(self, masker: OutputMasker):
        masked = masker.mask_result({"url": {"https://bad.example.com/x": 3}})

        assert "bad.example.com" not in str(masked)

    def test_prefixed_dict_keeps_allowlist_walk(self, masker: OutputMasker):
        # groupby1 as a dict is typed by its inner keys and was never the
        # leak; pin that it keeps the reversible walk rather than burning.
        raw = "192.0.2.92"
        masked = masker.mask_result({"groupby1": {"srcip": raw}})

        assert raw not in str(masked)
        assert not masked["groupby1"]["srcip"].startswith("masked-unrepresentable-")


class TestTargetEntryWithoutNameOrValue:
    """#73 item 2: an entry dict with neither slot parks the identifier in
    its own key, where the rebuild loop used to copy it through."""

    def test_entry_keyed_by_identifier_burns(self, masker: OutputMasker):
        masked = masker.mask_result({"target": [{"192.0.2.5": {"note": "campus"}}]})

        assert "192.0.2.5" not in str(masked)
        assert "campus" not in str(masked)

    def test_entry_with_name_slot_keeps_current_treatment(self, masker: OutputMasker):
        # Only the neither-slot shape burns; a named entry keeps the walk.
        masked = masker.mask_result({"target": [{"name": "ip", "note": "campus"}]})

        assert masked["target"][0]["note"] == "campus"


class TestAssetValueDiffering:
    """#73 item 3: an asset_value that differs from value used to pass
    through in clear even when it is a second identifier."""

    def test_differing_string_asset_value_masks_by_name_type(
        self, masker: OutputMasker, engine: FPEEngine
    ):

        masked = masker.mask_result(
            {"target": [{"name": "ip", "value": "192.0.2.57", "asset_value": "192.0.2.58"}]}
        )
        entry = masked["target"][0]

        assert "192.0.2.58" not in str(masked)
        # reversibly masked by the entry's own type, not burned
        assert engine.v2_open(entry["asset_value"]) == "192.0.2.58"

    def test_numeric_id_asset_value_stays_clear(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"target": [{"name": "ip", "value": "192.0.2.57", "asset_value": "84021"}]}
        )

        assert masked["target"][0]["asset_value"] == "84021"

    def test_differing_asset_value_unknown_name_burns(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"target": [{"name": "whatever", "value": "x", "asset_value": "192.0.2.59"}]}
        )

        assert "192.0.2.59" not in str(masked)
        assert masked["target"][0]["asset_value"].startswith("masked-unrepresentable-")

    def test_differing_container_asset_value_burns(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"target": [{"name": "ip", "value": "192.0.2.60", "asset_value": ["192.0.2.61"]}]}
        )

        assert "192.0.2.61" not in str(masked)

    def test_asset_value_in_keep_stays_clear(self, masker: OutputMasker):
        devid = "FGT60F0000000000"
        masked = masker.mask_result(
            {
                "devid": devid,
                "target": [{"name": "ip", "value": "192.0.2.62", "asset_value": devid}],
            }
        )

        assert masked["target"][0]["asset_value"] == devid


class TestMutatingToolGate:
    """#106: unmask_args must not restore tokens into mutating tools.

    FF3 tokens carry no integrity tag, so a stale or forged token decrypts
    to some plausible value; restored into a write surface that value is
    silently written to the estate. Read-only tools keep restoration.
    """

    def _install(self, monkeypatch: pytest.MonkeyPatch):
        from mcp.server.mcpserver import MCPServer

        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        mcp = MCPServer("test-gate")
        install_masking(mcp)
        return mcp

    async def test_marked_token_to_mutating_tool_is_refused(self, monkeypatch: pytest.MonkeyPatch):
        from fortianalyzer_mcp.tool_annotations import CREATES

        mcp = self._install(monkeypatch)
        engine = FPEEngine(KEY)
        token = engine.mask_hostname("fw-branch.example.com")
        calls: list[str] = []

        @mcp.tool(annotations=CREATES)
        async def fake_add_device(name: str) -> dict:
            calls.append(name)
            return {"status": "success"}

        result = await fake_add_device(name=token)

        assert calls == []  # the body never ran
        assert result["status"] == "error"
        assert result["error"] == "masked_token_in_mutating_args"
        assert "name" in result["message"]
        assert token not in str(result)  # the token itself is not echoed

    async def test_forged_token_to_mutating_tool_is_refused(self, monkeypatch: pytest.MonkeyPatch):
        # A marker that matches but does not decrypt is the forged/stale
        # case, which is exactly the threat: it must refuse, not pass.
        from fortianalyzer_mcp.tool_annotations import DESTRUCTIVE

        mcp = self._install(monkeypatch)
        calls: list[str] = []

        @mcp.tool(annotations=DESTRUCTIVE)
        async def fake_delete_device(name: str) -> dict:
            calls.append(name)
            return {"status": "success"}

        result = await fake_delete_device(name="host-ffff-zzzzzzzzzzzz")

        assert calls == []
        assert result["error"] == "masked_token_in_mutating_args"

    async def test_real_value_to_mutating_tool_runs_and_masks_output(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        from fortianalyzer_mcp.tool_annotations import CREATES

        mcp = self._install(monkeypatch)
        calls: list[str] = []

        @mcp.tool(annotations=CREATES)
        async def fake_add_device(name: str) -> dict:
            calls.append(name)
            return {"status": "success", "hostname": name}

        result = await fake_add_device(name="fw-branch.example.com")

        assert calls == ["fw-branch.example.com"]  # arg untouched on the way in
        assert result["hostname"].startswith("host-")  # output still masks

    async def test_unmarked_ip_token_passes_through_untouched(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        # An IP token carries no marker, so it is indistinguishable from a
        # real address and passes through as given: the gate closes the
        # decrypt-and-write path, it cannot detect unmarked ciphertext.
        # That detection is the #40 v2 envelope work.
        from fortianalyzer_mcp.tool_annotations import CREATES

        mcp = self._install(monkeypatch)
        engine = FPEEngine(KEY)
        ip_token = engine.mask_ip("192.0.2.55")
        calls: list[str] = []

        @mcp.tool(annotations=CREATES)
        async def fake_add_device(ip: str) -> dict:
            calls.append(ip)
            return {"status": "success"}

        await fake_add_device(ip=ip_token)

        assert calls == [ip_token]  # NOT decrypted

    async def test_read_only_tool_still_restores(self, monkeypatch: pytest.MonkeyPatch):
        from fortianalyzer_mcp.tool_annotations import READ_ONLY

        mcp = self._install(monkeypatch)
        engine = FPEEngine(KEY)
        token = engine.mask_ip("192.0.2.102")
        calls: list[str] = []

        @mcp.tool(annotations=READ_ONLY)
        async def fake_query(srcip: str) -> dict:
            calls.append(srcip)
            return {"count": 0}

        await fake_query(srcip=token)

        assert calls == ["192.0.2.102"]  # restored before the body

    async def test_unannotated_tool_fails_closed_as_mutating(self, monkeypatch: pytest.MonkeyPatch):
        mcp = self._install(monkeypatch)
        engine = FPEEngine(KEY)
        token = engine.mask_hostname("fw-branch.example.com")
        calls: list[str] = []

        @mcp.tool()
        async def unannotated(name: str) -> dict:
            calls.append(name)
            return {"status": "success"}

        result = await unannotated(name=token)

        assert calls == []
        assert result["error"] == "masked_token_in_mutating_args"

    async def test_token_embedded_in_prose_passes_as_token_text(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        # A token inside a longer string cannot be decrypted-and-written
        # (nothing restores it), so it passes through as token text: the
        # estate-side record shows the token, which discloses nothing.
        from fortianalyzer_mcp.tool_annotations import UPDATES

        mcp = self._install(monkeypatch)
        engine = FPEEngine(KEY)
        token = engine.mask_hostname("fw-branch.example.com")
        calls: list[str] = []

        @mcp.tool(annotations=UPDATES)
        async def fake_update_incident(description: str) -> dict:
            calls.append(description)
            return {"status": "success"}

        await fake_update_incident(description=f"seen on {token} overnight")

        assert calls == [f"seen on {token} overnight"]

    async def test_marked_token_nested_in_container_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        from fortianalyzer_mcp.tool_annotations import CREATES

        mcp = self._install(monkeypatch)
        engine = FPEEngine(KEY)
        token = engine.mask_hostname("fw-branch.example.com")
        calls: list[object] = []

        @mcp.tool(annotations=CREATES)
        async def fake_bulk(devices: list[dict]) -> dict:
            calls.append(devices)
            return {"status": "success"}

        result = await fake_bulk(devices=[{"name": token}])

        assert calls == []
        assert result["error"] == "masked_token_in_mutating_args"
        # the message names the tool's parameter, not the innermost dict key
        assert "devices" in result["message"]

    @pytest.mark.parametrize(
        "legit",
        [
            "host-fw01",
            "host-fw01.example",
            "user-svc",
            "url-shortener",
        ],
    )
    async def test_marker_prefixed_legit_name_is_not_refused(
        self, monkeypatch: pytest.MonkeyPatch, legit: str
    ):
        # A genuine name can start with host-/user-/url-. Only a value that
        # is structurally a token (the <4-hex-kid>- group, or the suffix
        # form) is treated as forged when it fails to decrypt.
        from fortianalyzer_mcp.tool_annotations import CREATES

        mcp = self._install(monkeypatch)
        calls: list[str] = []

        @mcp.tool(annotations=CREATES)
        async def fake_add_device(name: str) -> dict:
            calls.append(name)
            return {"status": "success"}

        result = await fake_add_device(name=legit)

        assert calls == [legit]
        assert result.get("error") != "masked_token_in_mutating_args"

    async def test_forged_suffix_form_is_refused(self, monkeypatch: pytest.MonkeyPatch):
        # The domain/email token form is marked by its suffix; a value in
        # that shape which does not decrypt is forged and stays refused.
        from fortianalyzer_mcp.tool_annotations import CREATES

        mcp = self._install(monkeypatch)
        engine = FPEEngine(KEY)
        calls: list[str] = []

        @mcp.tool(annotations=CREATES)
        async def fake_add_device(name: str) -> dict:
            calls.append(name)
            return {"status": "success"}

        result = await fake_add_device(name="zzz." + engine.mask_suffix)

        assert calls == []
        assert result["error"] == "masked_token_in_mutating_args"


class TestFailClosedValuesInProse:
    """#73 item 4: a value that fails closed under a typed key was not
    recorded, so pass 2 had nothing to substitute and the raw form of the
    same value rode out in the prose beside it."""

    def test_burned_value_does_not_survive_in_prose(self, masker: OutputMasker):
        raw = "DOMAIN\\alice"
        masked = masker.mask_result({"user": raw, "msg": f"login failure for {raw} at the console"})

        assert raw not in masked["msg"]
        # the prose carries the same placeholder the typed key got, so the
        # two references stay recognisable as one identifier
        assert masked["msg"] == f"login failure for {masked['user']} at the console"
        assert masked["user"].startswith("masked-unrepresentable-")

    def test_reversible_values_still_map_to_their_token(self, masker: OutputMasker):
        # the ordinary path is unchanged: a maskable value still substitutes
        # to its reversible token, not to a placeholder
        masked = masker.mask_result(
            {"hostname": "fw-branch.example.com", "msg": "seen on fw-branch.example.com"}
        )

        assert masked["msg"] == f"seen on {masked['hostname']}"
        assert not masked["hostname"].startswith("masked-unrepresentable-")


class TestKeepSetAcrossBothPasses:
    """#73 item 5: with device identity left clear, the same name masked
    under another typed key and was then substituted into prose, so a
    reader saw the name and a token for it in one record."""

    def test_kept_name_stays_clear_under_another_typed_key(self, masker: OutputMasker):
        name = "fgt-branch-01"
        masked = masker.mask_result({"devname": name, "hostname": name})

        assert masked["devname"] == name
        assert masked["hostname"] == name

    def test_kept_name_stays_clear_in_prose(self, masker: OutputMasker):
        name = "fgt-branch-01"
        masked = masker.mask_result(
            {"devname": name, "hostname": name, "msg": f"seen on {name} overnight"}
        )

        assert masked["msg"] == f"seen on {name} overnight"

    def test_flag_on_masks_every_occurrence(
        self, engine: FPEEngine, monkeypatch: pytest.MonkeyPatch
    ):
        # With the flag set there is no keep set, so the same record masks
        # everywhere and the prose token matches the structured one.
        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        flagged = OutputMasker(engine, mask_device_identity=True)
        name = "fgt-branch-01"
        masked = flagged.mask_result(
            {"devname": name, "hostname": name, "msg": f"seen on {name} overnight"}
        )

        assert name not in str(masked)
        assert masked["msg"] == f"seen on {masked['devname']} overnight"

    def test_kept_name_stays_clear_in_prose_even_when_a_composite_masked_it(
        self, masker: OutputMasker
    ):
        # Written when the URL composite still masked a kept host, which put
        # the name into the mapping for pass 2 to substitute. Pass 1 no longer
        # does that, so this now pins the composed result rather than the
        # pass-2 guard alone; ``TestPassTwoRefusesKeptValues`` pins the guard
        # itself, which stays as the layer under this one.
        name = "fgt-branch-01"
        masked = masker.mask_result(
            {"devname": name, "url": f"https://{name}/admin", "msg": f"seen on {name}"}
        )

        assert masked["devname"] == name
        assert masked["msg"] == f"seen on {name}"

    def test_kept_name_stays_clear_in_a_breakdown_bucket(self, masker: OutputMasker):
        # The pass-2 breakdown handler (#109) is a second route into prose.
        # Written against the #112 merge, where a composite still seeded the
        # mapping and dropping ``keep`` from this handler printed a token for
        # the name ``devname`` showed in clear. Pass 1 no longer seeds it, so
        # like the test above this now pins the composed result; the handler's
        # own ``keep`` argument is pinned by ``TestPassTwoRefusesKeptValues``.
        name = "fgt-branch-01"
        masked = masker.mask_result(
            {
                "devname": name,
                "url": f"https://{name}/admin",
                "msg": f"seen on {name} overnight",
                "breakdowns": {"msg": [{"value": f"seen on {name} overnight", "count": 3}]},
            }
        )

        assert masked["devname"] == name
        assert masked["msg"] == f"seen on {name} overnight"
        assert masked["breakdowns"]["msg"][0]["value"] == f"seen on {name} overnight"

    def test_kept_name_stays_clear_under_a_list_valued_typed_key(self, masker: OutputMasker):
        # #112 put the keep guard on the typed-scalar STRING branch only. The
        # list branch beside it masks each element straight through
        # ``_mask_scalar``, so a device named in a list-valued typed field
        # tokenises beside its own clear ``devname`` -- item 5 again, one
        # branch across.
        name = "fgt-branch-01"
        masked = masker.mask_result({"devname": name, "srcname": [name]})

        assert masked["devname"] == name
        assert masked["srcname"] == [name]

    def test_kept_name_stays_clear_in_a_prefixed_group_by(self, masker: OutputMasker):
        # ``groupby1`` types its value by the field name it carries. A
        # device-identity field name drops out of the type table with the flag
        # off, but any other typed name still resolves and masked the value.
        name = "fgt-branch-01"
        masked = masker.mask_result({"devname": name, "groupby1": f"hostname:{name}"})

        assert masked["groupby1"] == f"hostname:{name}"

    def test_kept_name_stays_clear_inside_a_json_blob(self, masker: OutputMasker):
        # The incident ``grpby`` blob is re-walked by pass 1, and the walk was
        # started without the keep set: the same key and the same string form
        # stayed clear at the top level and tokenised one level in.
        name = "fgt-branch-01"
        masked = masker.mask_result({"devname": name, "grpby": f'{{"srcname": "{name}"}}'})

        assert masked["grpby"] == f'{{"srcname": "{name}"}}'

    def test_kept_name_stays_clear_whatever_case_it_is_written_in(self, masker: OutputMasker):
        # Device names are routinely uppercase live, and two things fold case
        # before the value is compared: urlsplit lowercases the host it
        # returns, and a sibling field may simply spell the name differently
        # from the key the keep set was built from. The engine already folds
        # case for every type except USERNAME, so both spellings mask to one
        # token -- which is exactly what makes the mismatch a leak rather
        # than a cosmetic difference: the reader sees the name in clear under
        # ``devname`` and its token beside it.
        name = "FW-BRANCH-01"
        masked = masker.mask_result(
            {
                "devname": name,
                "url": f"https://{name}/admin",
                "http_url": f"https://{name}/x",
                "srcname": name.lower(),
            }
        )

        assert masked["devname"] == name
        assert masked["srcname"] == name.lower()
        # Both URL handlers hand back the response's own spelling. Letting the
        # value fall through to the scalar path instead would keep it out of a
        # token but return urlsplit's lowercased copy, so the host would no
        # longer match the ``devname`` printed beside it.
        assert masked["url"].startswith(f"https://{name}/")
        assert masked["http_url"] == f"https://{name}/x"

    def test_a_kept_username_still_respects_case(self, masker: OutputMasker):
        # The engine does NOT fold case for usernames, so two spellings are
        # two principals and the case-insensitive match must not reach them.
        # A device named ADMIN must not exempt a user called admin.
        masked = masker.mask_result({"devname": "ADMIN", "user": "admin"})

        assert masked["devname"] == "ADMIN"
        assert masked["user"] != "admin"

    def test_kept_name_stays_clear_in_a_url_host(self, masker: OutputMasker):
        # The URL handlers mask the host component through the same scalar
        # path every typed field uses, so a device reached as a URL host
        # tokenised beside its own clear ``devname``.
        name = "fgt-branch-01"
        masked = masker.mask_result(
            {"devname": name, "url": f"https://{name}/admin", "http_url": f"https://{name}/x"}
        )

        assert masked["url"].startswith(f"https://{name}/")
        assert masked["http_url"].startswith(f"https://{name}/")

    def test_kept_name_stays_clear_in_the_unparseable_fallbacks(self, masker: OutputMasker):
        # Both keep-less ``mask_text`` fallbacks (a ``grpby`` that is not JSON
        # after all, a ``http_url`` with no parseable host) substitute from
        # the pass-1 mapping, so they leaked as soon as any route seeded a
        # kept value into it.
        name = "fgt-branch-01"
        masked = masker.mask_result(
            {
                "devname": name,
                "srcname": [name],
                "grpby": f"not json at all: {name}",
                "http_url": f"::: {name} :::",
            }
        )

        assert masked["grpby"] == f"not json at all: {name}"
        assert masked["http_url"] == f"::: {name} :::"

    def test_kept_name_stays_clear_in_the_sibling_typed_pairs(self, masker: OutputMasker):
        # The four sibling-typed handlers run before the allowlist walk and
        # took no keep set at all, so a device reached as an enriched
        # indicator, a beaconing destination or a reporting principal masked
        # while ``devname`` showed it in clear on the same record. How likely
        # each shape is varies; the keep contract does not, which is why #73
        # item 5 was decided per value rather than per key.
        name = "fgt-branch-01.corp.example.com"

        assert masker.mask_result({"devname": name, "value": name, "type": "domain"})["value"] == (
            name
        )
        assert masker.mask_result({"devname": name, "value": f"https://{name}/x", "type": "url"})[
            "value"
        ].startswith(f"https://{name}/")
        assert (
            masker.mask_result({"devname": name, "incident_reporter": name, "reporter": name})[
                "incident_reporter"
            ]
            == name
        )
        assert masker.mask_result({"devname": name, "threat": name, "obf_url": name})["threat"] == (
            name
        )

    def test_kept_name_stays_clear_in_a_compiled_filter_entry(self, masker: OutputMasker):
        # ``filter_applied`` echoes the compiled filter back. Its handler
        # receives the keep set but typed each entry's value through
        # ``_mask_scalar`` without passing it on, so the echo printed a token
        # for the name ``devname`` shows in clear on the same record. Missed
        # twice: once when this route was written, once when every other
        # route was threaded, because ``_mask_scalar`` still had a default
        # that made the omission silent. It no longer has one.
        name = "fgt-branch-01"
        masked = masker.mask_result({"devname": name, "filter_applied": [["srcname", "==", name]]})

        assert masked["devname"] == name
        assert masked["filter_applied"] == [["srcname", "==", name]]

    def test_kept_names_stay_clear_inside_a_comma_joined_value(self, masker: OutputMasker):
        # FAZ joins aggregated device names into one value, and the keep set
        # is built by splitting that form -- so it holds the parts, never the
        # join. An ``x in keep`` test at a call site therefore misses the
        # joined string; only the per-part check inside ``_mask_scalar`` sees
        # it. ``target`` is the shape that carries both forms live.
        joined = "fgt-branch-01,fgt-branch-02"
        masked = masker.mask_result(
            {
                "fortigate": joined,
                "target": [{"name": "device", "value": joined}],
            }
        )

        assert masked["target"][0]["value"] == joined

    def test_unrelated_identifier_still_masks_when_keep_set_is_present(self, masker: OutputMasker):
        # The keep set must not become a blanket exemption: a different
        # identifier in the same response still masks normally.
        masked = masker.mask_result(
            {
                "devname": "fgt-branch-01",
                "hostname": "nas-branch.example.com",
                "msg": "seen on nas-branch.example.com",
            }
        )

        assert "nas-branch.example.com" not in str(masked)
        assert masked["msg"] == f"seen on {masked['hostname']}"


class TestPassTwoRefusesKeptValues:
    """Pass 2's ``keep`` guard, pinned at the pass rather than end to end.

    Every pass-1 route now refuses kept values, so no whole-response input
    can put one into the mapping any more -- which means an end-to-end test
    can no longer distinguish a pass 2 that honours ``keep`` from one that
    ignores it. The guard is still wanted: it is the layer that caught the
    #112/#109 composition trap, and pass 1 gaining a new composite handler
    is exactly the change that would seed the mapping again.

    Calling the pass directly is deliberate, and the only place this file
    does it. The alternative was leaving five handlers' ``keep`` arguments
    unpinned and removable without a failing test.
    """

    KEPT = "fgt-branch-01"
    TOKEN = "host-2a85-1uk-r2r2yn0nv"

    def _pass_two(self, masker: OutputMasker, obj: object) -> object:
        # A mapping that would substitute the kept name, as a pass-1 handler
        # that forgot the keep set would have left it.
        return masker._mask_free_text(obj, {self.KEPT: self.TOKEN}, frozenset({self.KEPT}))

    def test_prose_keeps_it(self, masker: OutputMasker):
        out = self._pass_two(masker, {"msg": f"seen on {self.KEPT} overnight"})

        assert out == {"msg": f"seen on {self.KEPT} overnight"}

    def test_breakdown_bucket_keeps_it(self, masker: OutputMasker):
        out = self._pass_two(
            masker, {"breakdowns": {"msg": [{"value": f"seen on {self.KEPT}", "count": 3}]}}
        )

        assert out["breakdowns"]["msg"][0]["value"] == f"seen on {self.KEPT}"

    def test_filter_entries_keep_it(self, masker: OutputMasker):
        out = self._pass_two(masker, {"filter_applied": [f"devname=={self.KEPT}"]})

        assert out["filter_applied"] == [f"devname=={self.KEPT}"]

    def test_an_unkept_value_still_substitutes(self, masker: OutputMasker):
        # Negative control: the same call path with an empty keep set must
        # still replace the mapped value, or these tests would pass against a
        # pass 2 that had simply stopped substituting anything.
        out = masker._mask_free_text(
            {"msg": f"seen on {self.KEPT} overnight"}, {self.KEPT: self.TOKEN}, frozenset()
        )

        assert out == {"msg": f"seen on {self.TOKEN} overnight"}


class TestSubstitutionPlanIsBuiltOncePerResponse:
    """#73 item 7c, re-measured. The item names peak memory as the concern.

    Memory was never the problem. Measured at ``329ba81`` it is ~1.1 KB per
    distinct identifier and linear, about half the ~2 KB the issue states.
    **Time** was the problem, and it was quadratic: pass 2 calls ``mask_text``
    once per TEXT field and each call rebuilt and recompiled the whole
    n-branch alternation, so n texts over n identifiers cost n x O(n).

        ids    secs   fitted
        250    0.04     -
        500    0.14   O(n^1.8)
       1000    0.51   O(n^1.9)
       2000    2.01   O(n^2.0)

    Extrapolated, 10k distinct identifiers is ~50s in one call.
    """

    def test_the_plan_is_compiled_once_regardless_of_row_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The whole fix in one assertion: rows must not multiply compiles."""
        masker = OutputMasker(FPEEngine(KEY))

        calls: list[int] = []
        original = OutputMasker._build_substitution_plan

        def spy(self, mapping, keep):  # type: ignore[no-untyped-def]
            calls.append(len(mapping))
            return original(self, mapping, keep)

        monkeypatch.setattr(OutputMasker, "_build_substitution_plan", spy)

        rows = [{"hostname": f"fw-site-{i:03d}", "msg": f"row {i} saw traffic"} for i in range(40)]
        masker.mask_result({"data": rows})

        assert len(calls) == 1, (
            f"expected one substitution plan for the response, got {len(calls)}. "
            "Rebuilding per TEXT field is what made this quadratic."
        )

    def test_a_value_masked_in_row_one_is_substituted_in_a_later_row(self) -> None:
        """The case a naive cache breaks.

        A hostname masked in a structured field must still be substituted in
        prose many rows later, which only works if the cached plan covers the
        whole mapping rather than whatever was known when it was first built.
        """
        masker = OutputMasker(FPEEngine(KEY))

        rows: list[dict[str, str]] = [{"hostname": "fw-hq-01", "msg": "first row"}]
        rows += [{"msg": f"filler {i}"} for i in range(1, 50)]
        rows.append({"msg": "later mention of fw-hq-01 in prose"})

        out = masker.mask_result({"data": rows})

        assert "fw-hq-01" not in out["data"][-1]["msg"]
        assert out["data"][-1]["msg"] != "later mention of fw-hq-01 in prose"

    def test_a_pass_two_overwrite_invalidates_the_plan(self) -> None:
        """The bug an adversarial review found in the first version of this.

        That version keyed the cache on ``len(mapping)``, on the belief that
        pass 2 never writes to the map. It does: ``_mask_filter_entries`` runs
        in pass 2 and reaches ``_mask_scalar``, which writes
        ``mapping[value] = token``. When the value is already present under a
        different type that write is an OVERWRITE, so the length does not
        move and a size key never fires.

        Here ``fw-hq-01`` is typed HOSTNAME in pass 1 and re-typed USERNAME by
        the filter entry. The later TEXT field spells it in a different case,
        so it resolves through the folded table rather than by exact lookup,
        and a stale plan hands back the hostname token where the uncached path
        hands back the username one.

        The assertion is deliberately against the CURRENT behaviour of the
        uncached path rather than against a token spelling: the point is that
        caching changes nothing, not that either answer is the right one.
        """
        masker = OutputMasker(FPEEngine(KEY), mask_device_identity=True)
        payload = {
            "data": [{"devname": "fw-hq-01", "msg": "structured row"}],
            "filter_applied": [["user", "=", "fw-hq-01"]],
            "tail": [{"msg": "later mention of FW-HQ-01 in prose"}],
        }

        out = masker.mask_result(payload)
        token = out["tail"][0]["msg"].split("later mention of ")[1].split(" in prose")[0]

        assert token.startswith("user-"), (
            f"expected the username token the filter entry re-typed it to, got {token!r}. "
            "A host- token means the cached plan served a mapping entry that had "
            "since been overwritten."
        )

    def test_a_burned_value_recorded_by_setdefault_reaches_pass_two(self) -> None:
        """The cleartext leak an adversarial review constructed.

        I claimed I could not build a payload where the ``setdefault`` hole
        diverged. The reviewer built one, and it is worse than a divergence:
        the raw value rides out while its own burn placeholder sits two keys
        away, which is exactly the token-beside-plaintext pairing the masker
        exists to prevent.

        The chain needs four things in one response, which is why it is rare
        and why hand-written tests missed it:

        1. a tracked write, so a plan can exist at all
        2. a PASS 1 route into ``mask_text`` so the plan is built early. Here
           ``grpby`` carrying a non-JSON string takes ``_mask_json_blob``'s
           fallback. ``_mask_device_vdom`` comma parts and
           ``_mask_url_host``'s unparseable-URL fallback do the same.
        3. ``_burn_and_record`` recording a burn via ``mapping.setdefault``,
           which in CPython never routes through a subclass ``__setitem__``
        4. a later TEXT field naming the burned value

        Any ordinary ``mapping[k] = v`` between 3 and 4 rebuilds the plan and
        the leak vanishes, which is why it was about 0.5% of fuzz payloads
        and deterministic when the shape lines up.
        """
        masker = OutputMasker(FPEEngine(KEY), mask_device_identity=True)
        payload = {
            "data": [
                {"devname": "fw-hq-01"},
                {"grpby": "context line"},
                {"groupby1": {"customdim": "j.doe.contractor"}},
                {"msg": "observed j.doe.contractor in prose"},
            ]
        }

        out = masker.mask_result(payload)

        assert "j.doe.contractor" not in out["data"][3]["msg"], (
            "a value burned in groupby1 rode out in clear in a later TEXT "
            "field, publishing the placeholder beside the plaintext"
        )

    def test_a_grown_mapping_invalidates_the_plan(self) -> None:
        """Correctness must not rest on pass 2 leaving ``mapping`` alone.

        Measured on ``329ba81``, it does: the free-text scan mints through the
        engine rather than writing to ``mapping``, and both write sites are
        pass-1 paths. The plan is keyed on ``len(mapping)`` anyway, so a future
        route that does add an entry mid-pass rebuilds instead of substituting
        against a stale alternation. This asserts the guard, not the
        observation.
        """
        masker = OutputMasker(FPEEngine(KEY))
        mapping = {"fw-hq-01": "host-tok-1"}
        keep: frozenset[str] = frozenset()

        first = masker.mask_text("about fw-hq-01", mapping, keep)
        assert "fw-hq-01" not in first

        mapping["fw-branch-02"] = "host-tok-2"
        second = masker.mask_text("about fw-branch-02", mapping, keep)
        assert "fw-branch-02" not in second, (
            "a value added to mapping after the plan was built was not picked up"
        )
