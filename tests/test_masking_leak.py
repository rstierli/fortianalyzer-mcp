"""Adversarial leak tests for output masking (RFC #40).

The other masking tests assert that allowlisted fields get masked. That is
the wrong question, and it is why a coverage hole survived a green suite:
alerts and incidents are not log rows, they carry identifiers under keys a
log-derived allowlist never mentions, and inside composite strings that key
matching cannot reach.

The right question is the one here: take a whole record, mask it, then
search the output for the exact original values. Masked IPs are valid IPs
and masked hostnames are plausible hostnames, so scanning the output for
"looks like an IP" proves nothing. Only identity comparison does.

Records below mirror the shape of real FAZ alert, incident, traffic,
fortiview, ueba and event-handler objects, with documentation values
(RFC 5737 / RFC 2606) throughout. The shapes were taken from live 7.6.7
responses; no value from any real estate appears here.
"""

import re
import time
from typing import Any

import pytest

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.unmask import ArgUnmasker
from fortianalyzer_mcp.masking.wrapper import OutputMasker

KEY = "2DE79D232DF5585D68CE47882AE256D6"

# Every identifier that must not survive masking.
ENDPOINT_NAME = "tablet-a3"
ENDPOINT_IP = "192.0.2.19"
GATEWAY_IP = "192.0.2.1"
BAD_DOMAIN = "suspicious.example.com"
PEER_IP = "198.51.100.7"
SRC_NAME = "workstation-14"
ANALYST = "jdoe"
SOC_EMAIL = "soc@example.org"
# Device identity: masked only when the deployment opts in.
DEV_NAME = "fgt-branch-01"
DEV_PEER = "fgt-branch-02"
DEV_SERIAL = "fgtserial0001"
DETECT_KEY = "fazserial0001"
FABRIC = "fabric-alpha"
VDOM = "root"
# Masked as a pair: a non-empty obf_url marks threat as a browsed domain
# (#40). Signature/filename rows carry an empty obf_url and stay clear.
THREAT_DOMAIN = "threat.example.net"
OBF_URL = "threat[dot]example[dot]net"
THREAT_SIGNATURE = "Adobe.Flash.Exploit"
THREAT_FILENAME = "Microsoft.MixedReality.Portal_2000.21051.1282.0_neutral_8wekyb3d8bbwe.AppxBundle"

ALERT: dict[str, Any] = {
    "alertid": "202607101000000020",
    "epid": "1107",
    "epname": ENDPOINT_NAME,
    "subject": f"DNS request to suspicious destination from {ENDPOINT_NAME} detected",
    "epip": ENDPOINT_IP,
    "dstepname": GATEWAY_IP,  # this key holds an address on some records
    "dstepip": GATEWAY_IP,
    "devname": DEV_NAME,
    "devid": DEV_SERIAL,
    "csf": FABRIC,
    "groupby1": f"qname:{BAD_DOMAIN}",
    "groupby2": f"endpoint:{ENDPOINT_NAME}",
    "extrainfo": f"Domain:{BAD_DOMAIN} traffic path {GATEWAY_IP}:53",
    "event_details": {
        "devid": DEV_SERIAL,
        "dst_ip": GATEWAY_IP,
        "src_ip": ENDPOINT_IP,
        # Live webfilter alerts carry the browsed destination as a flat
        # host_name AND inside a full URL; the flag-on estate smoke found
        # the URL (and the host_name target below) leaking.
        "host_name": BAD_DOMAIN,
        "http_url": f"https://{BAD_DOMAIN}/",
    },
    "target": [
        {"name": "domain", "value": BAD_DOMAIN},
        {"name": "device", "value": ENDPOINT_NAME, "asset_value": ENDPOINT_NAME},
        {"name": "device", "value": ENDPOINT_NAME, "asset_value": "1107"},
        {"name": "host_name", "value": BAD_DOMAIN},
        # Live 8.0.0 alerts carry the reporting appliance itself as a
        # device target; estate identity must stay consistent with devid.
        {"name": "device", "value": DEV_SERIAL, "asset_value": DEV_SERIAL},
    ],
}
INCIDENT: dict[str, Any] = {
    "incid": "IN00000001",
    "endpoint": ENDPOINT_IP,
    "reporter": ANALYST,
    "lastuser": ANALYST,
    # On a manually raised incident this repeats the reporter username;
    # the flag-on live round proved leaving it clear un-masks `reporter`.
    "incident_reporter": ANALYST,
    "grpby": f'[{{"dstendpoint": "{PEER_IP}"}}]',
}
TRAFFIC: dict[str, Any] = {
    "srcip": ENDPOINT_IP,
    "dstip": PEER_IP,
    "srcname": SRC_NAME,
    "devname": DEV_NAME,
    "msg": f"session from {SRC_NAME} ({ENDPOINT_IP}) to {PEER_IP}",
}


# The wrapper masks every tool's output, but alert/incident/traffic rows are
# only three of the shapes that flow through it. The five below come from
# fortiview, ueba and the event-handler config, whose keys no log schema
# mentions and which the first version of this file never exercised.
FORTIVIEW_THREAT: dict[str, Any] = {
    "fortigate": DEV_NAME,
    "devvds": f"{DEV_NAME}[{VDOM}]",
    "threat": THREAT_DOMAIN,
    "obf_url": OBF_URL,
    "threatlevel": 4,
}
# Signature and malware rows: threat is an app signature or a dotted
# filename, obf_url is empty, and the value must stay readable.
FORTIVIEW_SIGNATURE: dict[str, Any] = {
    "threat": THREAT_SIGNATURE,
    "obf_url": "",
    "threatlevel": 3,
}
FORTIVIEW_MALWARE: dict[str, Any] = {
    "threat": THREAT_FILENAME,
    "obf_url": "",
    "threattype": "malware-detected",
}

# Full-shape ``top-threats`` rows, sanitized from a live 7.6.7 capture (a
# complete 7-day window; the #40 thread). Unlike the minimal dicts above,
# these carry every sibling key the view emits, so the pair rule runs
# against real row shapes — including the device-identity keys sitting
# next to the pair. One row per class observed live; the filename row
# keeps the ``~``/``_`` characters real bundle names carry (both outside
# the domain alphabet, so a shape test would have failed closed on them).
LIVE_THREAT_DOMAIN = "relay.privacy.example.com"
LIVE_SPAM_FQDN = "cell8013.fra.mobile.event.ads.example-adnetwork.com"
LIVE_MALICIOUS_DOMAIN = "malhost.example.net"
LIVE_FILENAME = "Vendor.Example.Utility_4.7.18.0_neutral_~_abcdefgh.Msixbundle"


def _top_threats_row(
    threat: str,
    threattype: str,
    logtype: str = "10",
    logtype_str: str = "traffic",
    obf: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "logtype": logtype,
        "logtype_str": logtype_str,
        "threat": threat,
        "threattype": threattype,
        "threatlevel": "3",
        "level_s": "High",
        "threatweight": "1000",
        "threat_block": "1000",
        "threat_pass": "0",
        "incidents": "10",
        "incident_block": "10",
        "incident_pass": "0",
        "fortigate": DEV_SERIAL,
        "devvds": f"{DEV_SERIAL}[{VDOM}]",
        "cve_list": "",
        "appid": "0",
        "obf_url": threat.replace(".", "[dot]") if obf else "",
    }
    row.update(extra)
    return row


FORTIVIEW_LIVE_ROWS: list[dict[str, Any]] = [
    _top_threats_row("blocked-connection", "blocked-connection"),
    _top_threats_row(LIVE_THREAT_DOMAIN, "Proxy Avoidance", obf=True),
    _top_threats_row("udp_flood", "ips", logtype="1", logtype_str="anomaly"),
    _top_threats_row("Proxy.HTTP", "Proxy", appid="107347980"),
    _top_threats_row(LIVE_FILENAME, "malware-detected"),
    _top_threats_row(LIVE_SPAM_FQDN, "Spam URLs", obf=True),
    _top_threats_row(LIVE_MALICIOUS_DOMAIN, "Malicious Websites", obf=True),
]
LIVE_ROW_IDS = [
    "fv-live-blocked-connection",
    "fv-live-proxy-avoidance-domain",
    "fv-live-anomaly-udp-flood",
    "fv-live-app-signature",
    "fv-live-malware-filename",
    "fv-live-spam-url-fqdn",
    "fv-live-malicious-website",
]

FORTIVIEW_COUNTRY: dict[str, Any] = {
    "fortigate": f"{DEV_NAME},{DEV_PEER}",
    "devvds": f"{DEV_NAME}[{VDOM}],{DEV_PEER}[{VDOM}]",
    "dstcountry": "Canada",
}
UEBA_ENDUSER: dict[str, Any] = {
    "euid": "1025",
    "euname": ENDPOINT_IP,  # live records put an address in this "name" field
    "socialid": {"data": []},
    "importance": 0,
}
UEBA_ENDPOINT: dict[str, Any] = {
    "epid": "1025",
    "epname": ".self",
    "detectkey": DETECT_KEY,
}
HANDLER: dict[str, Any] = {
    "name": "Default-Botnet-Communication-Detection-By-Endpoint",
    "description": f"Escalate when {GATEWAY_IP} beacons out; page {SOC_EMAIL}",
    "template-url": "/fazcfg-template/basic-handler/fgt",
    "mitre-domain": "enterprise",
}

RECORDS = [
    ALERT,
    INCIDENT,
    TRAFFIC,
    FORTIVIEW_THREAT,
    FORTIVIEW_SIGNATURE,
    FORTIVIEW_MALWARE,
    *FORTIVIEW_LIVE_ROWS,
    FORTIVIEW_COUNTRY,
    UEBA_ENDUSER,
    UEBA_ENDPOINT,
    HANDLER,
]
RECORD_IDS = [
    "alert",
    "incident",
    "traffic",
    "fv-threat",
    "fv-signature",
    "fv-malware",
    *LIVE_ROW_IDS,
    "fv-country",
    "ueba-enduser",
    "ueba-endpoint",
    "handler",
]

PERSONAL = [
    ENDPOINT_NAME,
    ENDPOINT_IP,
    GATEWAY_IP,
    BAD_DOMAIN,
    PEER_IP,
    SRC_NAME,
    ANALYST,
    SOC_EMAIL,
    THREAT_DOMAIN,
    OBF_URL,
    LIVE_THREAT_DOMAIN,
    LIVE_SPAM_FQDN,
    LIVE_MALICIOUS_DOMAIN,
    LIVE_THREAT_DOMAIN.replace(".", "[dot]"),
    LIVE_SPAM_FQDN.replace(".", "[dot]"),
    LIVE_MALICIOUS_DOMAIN.replace(".", "[dot]"),
]
DEVICE_IDENTITY = [DEV_NAME, DEV_PEER, DEV_SERIAL, DETECT_KEY, FABRIC]


def survivors(masked: Any, secrets: list[str]) -> dict[str, list[str]]:
    """Original values that still appear anywhere in the masked structure."""
    hits: dict[str, list[str]] = {}

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            for s in secrets:
                if s in node:
                    hits.setdefault(s, []).append(path)

    walk(masked, "")
    return hits


@pytest.fixture
def masker(monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    return OutputMasker(FPEEngine(KEY))


@pytest.fixture
def full_masker(monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    return OutputMasker(FPEEngine(KEY), mask_device_identity=True)


class TestNoIdentifierSurvives:
    @pytest.mark.parametrize("record", RECORDS, ids=RECORD_IDS)
    def test_no_personal_identifier_survives(self, masker: OutputMasker, record: dict[str, Any]):
        leaked = survivors(masker.mask_result(record), PERSONAL)
        assert leaked == {}, f"masking leaked: {leaked}"

    @pytest.mark.parametrize("record", RECORDS, ids=RECORD_IDS)
    def test_device_identity_survives_by_default(
        self, masker: OutputMasker, record: dict[str, Any]
    ):
        """Documented, deliberate: estate identity stays readable unless opted in."""
        present = [d for d in DEVICE_IDENTITY if d in str(record)]
        leaked = survivors(masker.mask_result(record), DEVICE_IDENTITY)
        assert sorted(leaked) == sorted(present)

    @pytest.mark.parametrize("record", RECORDS, ids=RECORD_IDS)
    def test_nothing_survives_with_device_identity_masked(
        self, full_masker: OutputMasker, record: dict[str, Any]
    ):
        leaked = survivors(full_masker.mask_result(record), PERSONAL + DEVICE_IDENTITY)
        assert leaked == {}, f"masking leaked: {leaked}"


class TestCompositeKeys:
    def test_prefixed_groupby_masks_only_the_value_half(self, masker: OutputMasker):
        masked = masker.mask_result({"groupby1": f"qname:{BAD_DOMAIN}"})
        assert masked["groupby1"].startswith("qname:")
        assert BAD_DOMAIN not in masked["groupby1"]
        assert masked["groupby1"].endswith(".masked.invalid")

    def test_unknown_prefix_left_alone(self, masker: OutputMasker):
        masked = masker.mask_result({"groupby1": "action:deny"})
        assert masked["groupby1"] == "action:deny"

    def test_json_blob_is_parsed_and_remasked(self, masker: OutputMasker):
        masked = masker.mask_result({"grpby": f'[{{"dstendpoint": "{PEER_IP}"}}]'})
        assert PEER_IP not in masked["grpby"]
        import json

        assert json.loads(masked["grpby"])[0]["dstendpoint"] != PEER_IP

    def test_malformed_json_blob_still_scrubs_ips(self, masker: OutputMasker):
        masked = masker.mask_result({"grpby": f"not json at all {PEER_IP}"})
        assert PEER_IP not in masked["grpby"]

    def test_target_uses_sibling_name_as_type_hint(self, masker: OutputMasker):
        masked = masker.mask_result({"target": [{"name": "domain", "value": BAD_DOMAIN}]})
        assert masked["target"][0]["value"].endswith(".masked.invalid")

    def test_target_asset_value_masked_only_when_it_repeats_the_identifier(
        self, masker: OutputMasker
    ):
        masked = masker.mask_result(
            {
                "target": [
                    {"name": "device", "value": ENDPOINT_NAME, "asset_value": ENDPOINT_NAME},
                    {"name": "device", "value": ENDPOINT_NAME, "asset_value": "1107"},
                ]
            }
        )
        assert masked["target"][0]["asset_value"] == masked["target"][0]["value"]
        assert masked["target"][1]["asset_value"] == "1107"  # an internal id, not an identifier


class TestFreeTextSubstitution:
    def test_uppercase_echo_of_a_masked_hostname_is_substituted(self, masker: OutputMasker):
        name = "edge.example.com"
        masked = masker.mask_result(
            {"srcname": name, "msg": f"blocked session from {name.upper()} at the edge"}
        )

        assert name.upper() not in masked["msg"]
        assert masked["srcname"] in masked["msg"]

    def test_title_case_echo_of_a_masked_domain_is_substituted(self, masker: OutputMasker):
        domain = "example.org"
        masked = masker.mask_result(
            {
                "groupby1": f"qname:{domain}",
                "extrainfo": f"Domain:{domain.title()} blocked",
            }
        )
        token = masked["groupby1"].partition(":")[2]

        assert domain.title() not in masked["extrainfo"]
        assert token in masked["extrainfo"]

    def test_case_variant_usernames_keep_distinct_tokens(self, masker: OutputMasker):
        masked = masker.mask_result(
            {
                "logs": [{"user": "Admin"}, {"user": "admin"}],
                "msg": "Admin changed policy; admin logged out",
            }
        )
        upper_token = masked["logs"][0]["user"]
        lower_token = masked["logs"][1]["user"]
        engine = FPEEngine(KEY)

        assert upper_token != lower_token
        assert upper_token in masked["msg"]
        assert lower_token in masked["msg"]
        assert engine.unmask_username(upper_token) == "Admin"
        assert engine.unmask_username(lower_token) == "admin"

    def test_uppercase_short_values_are_not_substituted_into_prose(self, masker: OutputMasker):
        masked = masker.mask_result({"user": "abc", "msg": "ABC is a short code"})

        assert "ABC is a short code" == masked["msg"]

    def test_uppercase_echo_respects_token_boundaries(self, masker: OutputMasker):
        name = "edge.example.com"
        compound = f"{name.upper()}-SUFFIX"
        masked = masker.mask_result({"srcname": name, "msg": f"{compound} is a different host"})

        assert compound in masked["msg"]

    def test_uppercase_echo_respects_the_leading_token_boundary(self, masker: OutputMasker):
        # The trailing lookahead is covered above. Without the leading
        # lookbehind this prefixed word is partially rewritten instead of
        # being left alone.
        name = "edge.example.com"
        compound = f"NOT{name.upper()}"
        masked = masker.mask_result({"srcname": name, "msg": f"{compound} is a different host"})

        assert compound in masked["msg"]

    # Escapes on purpose: these are exactly the characters an editor,
    # terminal or copy-paste is most likely to flatten to ASCII, which
    # would silently turn the two tests below into no-ops.
    @pytest.mark.parametrize("adjacent", ["\u017f", "\u212a", "\u0130", "\u0131"])
    def test_echo_next_to_a_case_folding_character_is_still_substituted(
        self, masker: OutputMasker, adjacent: str
    ):
        # These four characters case-fold into the ASCII boundary class, so a
        # pattern-wide re.IGNORECASE widens the boundary look-arounds and the
        # identifier next to one is handed back in clear. The flag must stay
        # scoped to the alternation with (?ai:...).
        name = "edge.example.com"
        masked = masker.mask_result(
            {"srcname": name, "msg": f"seen {adjacent}{name} and {name}{adjacent} here"}
        )

        assert name not in masked["msg"]

    @pytest.mark.parametrize("other", ["te\u017ft.example", "test.examp\u0142e"])
    def test_unicode_lookalike_is_left_alone_not_burned(self, masker: OutputMasker, other: str):
        # Folding is ASCII-only. Under full Unicode folding the regex matches
        # these spellings but the casefold lookup misses, and a value that is
        # not the known identifier at all degrades to an irreversible
        # placeholder. Re-casing means ASCII case; leave anything else alone.
        out = masker._substitute_known(f"{other} is here", {"test.example": "TOKEN"})

        assert out == f"{other} is here"

    def test_ambiguous_case_variant_principals_fail_closed(self, masker: OutputMasker):
        # Two principals differing only in case make a third spelling
        # ambiguous. Reusing either token would resolve to the wrong identity,
        # so the occurrence burns instead.
        mapping = {"Example-User": "user-aaaa", "example-user": "user-bbbb"}
        out = masker._substitute_known("EXAMPLE-USER changed policy", mapping)

        assert out.startswith("masked-unrepresentable-")
        assert "user-aaaa" not in out
        assert "user-bbbb" not in out

    def test_unambiguous_case_variant_echo_keeps_the_single_token(self, masker: OutputMasker):
        # Only one principal owns this folded form, so the echo is safe to
        # attribute to it. This is the common case and must keep working.
        out = masker._substitute_known("EXAMPLE-USER changed policy", {"Example-User": "user-aaaa"})

        assert out == "user-aaaa changed policy"

    def test_longest_raw_wins_at_the_same_start_position(self, masker: OutputMasker):
        # Alternation order is load-bearing: shortest-first would rewrite the
        # local part and leave the domain half of the address in prose.
        mapping = {"person": "USERTOKEN", "person@example.com": "EMAILTOKEN"}

        assert masker._substitute_known("person@example.com sent mail", mapping) == (
            "EMAILTOKEN sent mail"
        )

    def test_a_substituted_token_is_not_rescanned(self, masker: OutputMasker):
        first_raw = "edge.example.com"
        first_token = "~fragment~"
        mapping = {first_raw: first_token, "fragment": "replacement"}

        assert masker._substitute_known(first_raw, mapping) == first_token

    def test_substitution_compiles_one_pattern_regardless_of_mapping_size(
        self, masker: OutputMasker, monkeypatch: pytest.MonkeyPatch
    ):
        # The mechanism the wall-clock test below can only approximate: the
        # old code compiled one regex per known value, so a large response
        # blew past re's internal cache and every field recompiled from
        # scratch. Counting compiles pins that directly and cannot flake on
        # a slow runner.
        compiled: list[Any] = []
        real_compile = re.compile

        def counting_compile(*args: Any, **kwargs: Any):
            compiled.append(args[0] if args else None)
            return real_compile(*args, **kwargs)

        mapping = {f"host-{index:04d}.example.com": f"token-{index}" for index in range(200)}
        monkeypatch.setattr(re, "compile", counting_compile)
        out = masker._substitute_known("prose naming host-0007.example.com here", mapping)

        assert out == "prose naming token-7 here"
        assert len(compiled) == 1

    def test_large_result_masks_within_a_wall_clock_budget(self, masker: OutputMasker):
        # Smoke bound only, to catch a catastrophic regression. Kept very
        # generous on purpose: this asserted < 5s and flaked at 5.8s on a
        # loaded CI runner while taking ~0.45s locally. The pre-fix
        # implementation took ~23s here, so a regression still trips it.
        # The compile-count test above is what actually pins the fix.
        rows = []
        blocks = ("192.0.2", "198.51.100", "203.0.113")
        for index in range(500):
            ip = f"{blocks[index // 254]}.{index % 254 + 1}"
            user = f"example-user-{index:03d}"
            hostname = f"host-{index}.example.com"
            destination = f"destination-{index}.example.org"
            rows.append(
                {
                    "srcip": ip,
                    "user": user,
                    "hostname": hostname,
                    "dstname": destination,
                    "msg": f"{hostname} connected as {user} to {destination}",
                }
            )

        started = time.perf_counter()
        masker.mask_result({"logs": rows})
        elapsed = time.perf_counter() - started

        assert elapsed < 60

    def test_hostname_masked_in_a_field_is_also_masked_in_prose(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"srcname": SRC_NAME, "msg": f"blocked session from {SRC_NAME} at the edge"}
        )
        assert SRC_NAME not in masked["msg"]
        assert masked["srcname"] in masked["msg"]  # same identifier, same token

    def test_domain_from_a_composite_key_is_masked_in_prose(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"groupby1": f"qname:{BAD_DOMAIN}", "extrainfo": f"Domain:{BAD_DOMAIN} blocked"}
        )
        assert BAD_DOMAIN not in masked["extrainfo"]

    def test_ip_or_host_field_holding_an_address_masks_as_an_ip(self, masker: OutputMasker):
        import ipaddress

        masked = masker.mask_result({"epname": GATEWAY_IP})
        ipaddress.ip_address(masked["epname"])  # still a valid address, not a host- token

    def test_ip_or_host_field_holding_a_name_masks_as_a_hostname(self, masker: OutputMasker):
        masked = masker.mask_result({"epname": ENDPOINT_NAME})
        assert masked["epname"].startswith("host-")

    def test_short_values_are_not_substituted_into_prose(self, masker: OutputMasker):
        """A three-character username must not rewrite unrelated words."""
        masked = masker.mask_result({"user": "wad", "msg": "forwarded by wadware upstream"})
        assert "wadware" in masked["msg"]

    def test_substitution_respects_token_boundaries(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"srcname": SRC_NAME, "msg": f"{SRC_NAME}-backup is a different host"}
        )
        # "workstation-14-backup" must not be rewritten as "<token>-backup"
        assert f"{SRC_NAME}-backup" in masked["msg"]


class TestFortiViewDeviceVdom:
    """``devvds`` is ``"<devname>[<vdom>]"``: brackets break a plain mask."""

    def test_composite_keeps_the_vdom_and_stays_reversible(self, full_masker: OutputMasker):
        masked = full_masker.mask_result({"devvds": f"{DEV_NAME}[{VDOM}]"})
        assert DEV_NAME not in masked["devvds"]
        assert masked["devvds"].endswith(f"[{VDOM}]")
        # A hostname mask over the whole string fails closed to a placeholder,
        # which is irreversible and destroys the vdom with it.
        assert "masked-unrepresentable-" not in masked["devvds"]

    def test_comma_joined_devices_are_masked_element_by_element(self, full_masker: OutputMasker):
        masked = full_masker.mask_result({"devvds": f"{DEV_NAME}[{VDOM}],{DEV_PEER}[{VDOM}]"})
        first, second = masked["devvds"].split(",")
        assert first.startswith("host-") and second.startswith("host-")
        assert first != second  # distinct devices keep distinct tokens
        assert first.endswith(f"[{VDOM}]") and second.endswith(f"[{VDOM}]")
        assert "masked-unrepresentable-" not in masked["devvds"]

    def test_bare_device_name_without_brackets_still_masks(self, full_masker: OutputMasker):
        masked = full_masker.mask_result({"devvds": DEV_NAME})
        assert masked["devvds"].startswith("host-")

    def test_untouched_when_device_identity_masking_is_off(self, masker: OutputMasker):
        record = {"devvds": f"{DEV_NAME}[{VDOM}]"}
        assert masker.mask_result(record) == record

    def test_the_same_device_gets_the_same_token_in_devvds_and_fortigate(
        self, full_masker: OutputMasker
    ):
        masked = full_masker.mask_result(FORTIVIEW_THREAT)
        assert masked["devvds"] == f"{masked['fortigate']}[{VDOM}]"


class TestIncidentReporterSibling:
    """``incident_reporter`` masks only when the record proves it a username."""

    def test_manual_incident_gets_the_reporter_token(self, masker: OutputMasker):
        masked = masker.mask_result(dict(INCIDENT))
        assert ANALYST not in str(masked)
        assert masked["incident_reporter"] == masked["reporter"]  # same principal, same token

    def test_auto_raised_alert_id_stays_clear(self, masker: OutputMasker):
        """On auto-raised incidents the field holds an alert id; masking it
        as a username would corrupt the id, so only sibling-proven
        usernames mask."""
        record = {"reporter": "Auto-Raised", "incident_reporter": "202607101000000020"}
        masked = masker.mask_result(record)
        assert masked["incident_reporter"] == "202607101000000020"


class TestTargetDeviceIdentityConsistency:
    """The reporting appliance inside ``target[]`` follows the flag, like
    every other device-identity carrier: half-masked estate identity would
    pair each token with its clear serial two keys away."""

    def test_list_valued_device_stays_clear_in_device_target(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"devs": [DEV_NAME], "target": [{"name": "device", "value": DEV_NAME}]}
        )

        assert masked["target"][0]["value"] == DEV_NAME

    def test_list_valued_device_stays_clear_in_unknown_target(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"devs": [DEV_NAME], "target": [{"name": "unknown", "value": DEV_NAME}]}
        )

        assert masked["target"][0]["value"] == DEV_NAME
        assert "masked-unrepresentable-" not in masked["target"][0]["value"]

    def test_two_list_valued_devices_stay_clear_in_targets(self, masker: OutputMasker):
        masked = masker.mask_result(
            {
                "devs": [DEV_NAME, DEV_PEER],
                "target": [
                    {"name": "device", "value": DEV_NAME},
                    {"name": "device", "value": DEV_PEER},
                ],
            }
        )

        assert [entry["value"] for entry in masked["target"]] == [DEV_NAME, DEV_PEER]

    def test_list_valued_device_absent_from_target_is_unchanged(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"devs": [DEV_NAME], "target": [{"name": "device", "value": DEV_PEER}]}
        )

        assert masked["devs"] == [DEV_NAME]
        assert masked["target"][0]["value"] != DEV_PEER

    def test_non_device_value_alongside_device_list_still_masks(self, masker: OutputMasker):
        masked = masker.mask_result({"devs": [DEV_NAME], "srcname": ENDPOINT_NAME})

        assert masked["devs"] == [DEV_NAME]
        assert masked["srcname"] != ENDPOINT_NAME

    def test_list_valued_device_still_masks_when_flag_on(self, full_masker: OutputMasker):
        masked = full_masker.mask_result({"devs": [DEV_NAME]})

        assert masked["devs"][0] != DEV_NAME

    def test_a_comma_inside_a_list_element_is_not_split(self, masker: OutputMasker):
        """The split is for the string form only, and deliberately so.

        Whatever lands in the keep set is exempted from masking inside
        ``target``, so splitting exempts each part on its own. A string has
        to be split because FAZ joins aggregated device names into one
        value; a list is already that split form, so splitting its elements
        would widen the exemption for nothing.
        """
        analyst = "analyst-example"
        masked = masker.mask_result(
            {
                "devs": [f"{DEV_NAME},{analyst}"],
                "target": [{"name": "user", "value": analyst}],
            }
        )

        assert masked["target"][0]["value"] != analyst

    def test_whitespace_around_a_list_element_is_stripped(self, masker: OutputMasker):
        """The string branch strips; the list branch must agree.

        Without it, a name padded by the appliance fails the exact-string
        match and the same device masks in ``target`` while staying clear
        under ``devs``, which is the inconsistency this set exists to close.
        """
        masked = masker.mask_result(
            {
                "devs": [f"  {DEV_NAME}  "],
                "target": [{"name": "device", "value": DEV_NAME}],
            }
        )

        assert masked["target"][0]["value"] == DEV_NAME

    def test_a_non_string_list_element_is_not_admitted(self, masker: OutputMasker):
        """Whatever enters the keep set is exempted from masking.

        Stringifying arbitrary elements would let a bare id exempt any
        ``target`` value that happens to render the same way, so only real
        string names are collected.
        """
        masked = masker.mask_result(
            {"devs": [1305], "target": [{"name": "device", "value": "1305"}]}
        )

        assert masked["target"][0]["value"] != "1305"

    def test_a_dict_nested_in_a_list_element_is_still_walked(self, masker: OutputMasker):
        """A non-string list element keeps its device-identity keys.

        Before lists were handled here they fell through to the recursive
        walk, so ``devs: [{"devname": ...}]`` contributed the nested name.
        The list branch must not cut that path off: it takes string
        elements whole and walks the rest.
        """
        masked = masker.mask_result(
            {
                "devs": [{"devname": DEV_NAME}],
                "target": [{"name": "device", "value": DEV_NAME}],
            }
        )

        assert masked["target"][0]["value"] == DEV_NAME

    def test_estate_serial_in_target_stays_clear_when_flag_off(self, masker: OutputMasker):
        masked = masker.mask_result(ALERT)
        entry = masked["target"][4]
        assert entry["value"] == DEV_SERIAL  # consistent with the clear devid
        assert entry["asset_value"] == DEV_SERIAL
        # endpoint targets still mask; only estate identity is exempt
        assert masked["target"][1]["value"] != ENDPOINT_NAME

    def test_estate_serial_in_target_masks_with_the_devid_token_when_flag_on(
        self, full_masker: OutputMasker
    ):
        masked = full_masker.mask_result(ALERT)
        assert masked["target"][4]["value"] == masked["devid"]  # same identifier, same token
        assert DEV_SERIAL not in str(masked)


class TestUrlHostMasking:
    """``http_url``: the URL's HOST component masks in place; scheme, path
    and query stay clear. Found leaking by the flag-on estate smoke — the
    browsed destination survived inside the URL while the flat host_name
    masked one key away."""

    def test_url_host_masks_and_pair_with_flat_host_name(self, masker: OutputMasker):
        masked = masker.mask_result(ALERT)
        url = masked["event_details"]["http_url"]
        assert BAD_DOMAIN not in url
        assert url.startswith("https://host-") and url.endswith("/")
        # same value, same token: flat host_name, host_name target, URL host
        token = masked["event_details"]["host_name"]
        assert url == f"https://{token}/"
        assert masked["target"][3]["value"] == token

    def test_ip_host_url(self, masker: OutputMasker):
        masked = masker.mask_result({"http_url": f"http://{ENDPOINT_IP}:8080/admin"})
        url = masked["http_url"]
        assert ENDPOINT_IP not in url
        assert url.startswith("http://") and url.endswith(":8080/admin")

    def test_path_and_query_stay_clear(self, masker: OutputMasker):
        masked = masker.mask_result({"http_url": f"https://{BAD_DOMAIN}/downloads/tool.zip?v=2"})
        assert masked["http_url"].endswith("/downloads/tool.zip?v=2")
        assert BAD_DOMAIN not in masked["http_url"]

    def test_userinfo_url_fails_closed(self, masker: OutputMasker):
        masked = masker.mask_result({"http_url": f"https://{ANALYST}@{BAD_DOMAIN}/"})
        assert masked["http_url"].startswith("masked-unrepresentable-")
        assert ANALYST not in masked["http_url"]

    def test_non_url_value_falls_back_to_text_scan(self, masker: OutputMasker):
        # An IP hiding in a non-URL string still gets caught by the scan.
        masked = masker.mask_result({"http_url": f"redirect target {ENDPOINT_IP}"})
        assert ENDPOINT_IP not in masked["http_url"]


def _looks_like_web_domain(value: str) -> bool:
    """Test-only tripwire heuristic, NOT dispatch logic: lowercase dotted
    labels ending in an alphabetic TLD. Signatures (``Adobe.Flash.Exploit``)
    and filenames carry uppercase or non-label characters and do not match.
    """
    import re

    return re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,24}", value.strip()) is not None


class TestThreatObfUrlPair:
    """#40: a non-empty ``obf_url`` marks ``threat`` as a browsed domain and
    both mask as a consistent pair; an empty one leaves ``threat`` clear."""

    def test_domain_threat_masks_and_does_not_leak(self, masker: OutputMasker):
        masked = masker.mask_result(FORTIVIEW_THREAT)
        assert THREAT_DOMAIN not in str(masked)
        assert OBF_URL not in str(masked)
        assert masked["threat"].endswith(".masked.invalid")

    def test_pair_stays_consistent(self, masker: OutputMasker):
        """obf_url must remain the [dot]-escaped twin of threat after
        masking, or a reader diffing the two would see two identities."""
        masked = masker.mask_result(FORTIVIEW_THREAT)
        assert masked["obf_url"] == masked["threat"].replace(".", "[dot]")

    def test_signature_row_stays_clear(self, masker: OutputMasker):
        """Empty obf_url: an app signature keeps its analytic value."""
        assert masker.mask_result(FORTIVIEW_SIGNATURE)["threat"] == THREAT_SIGNATURE

    def test_malware_filename_stays_clear(self, masker: OutputMasker):
        """Dotted filenames would fool any shape test; the sibling rule
        leaves them readable."""
        assert masker.mask_result(FORTIVIEW_MALWARE)["threat"] == THREAT_FILENAME

    def test_threat_without_obf_url_key_stays_clear(self, masker: OutputMasker):
        record = {"threat": "udp_flood", "count": 3}
        assert masker.mask_result(record) == record

    def test_obf_url_alone_still_masks(self, masker: OutputMasker):
        masked = masker.mask_result({"obf_url": OBF_URL})
        assert OBF_URL not in str(masked)
        assert masked["obf_url"].endswith("[dot]masked[dot]invalid")

    def test_mismatched_pair_leaks_neither(self, masker: OutputMasker):
        """Defensive: if threat and obf_url ever disagree, each masks on its
        own value; determinism keeps twins twins, disagreement stays safe."""
        masked = masker.mask_result({"threat": "other.example.org", "obf_url": OBF_URL})
        assert "other.example.org" not in str(masked)
        assert OBF_URL not in str(masked)

    def test_threat_token_resolves_back_as_an_argument(self, masker: OutputMasker):
        """The threat token is a standard marked domain token, so Phase 2
        resolves it anywhere. The escaped obf_url form is display-only."""
        from fortianalyzer_mcp.masking.unmask import ArgUnmasker

        masked = masker.mask_result(FORTIVIEW_THREAT)
        unmasker = ArgUnmasker(FPEEngine(KEY))
        assert unmasker.resolve_scalar(masked["threat"]) == THREAT_DOMAIN

    def test_domain_from_the_pair_is_substituted_in_prose(self, masker: OutputMasker):
        masked = masker.mask_result(
            {
                "threat": THREAT_DOMAIN,
                "obf_url": OBF_URL,
                "extrainfo": f"endpoint browsed {THREAT_DOMAIN} twice",
            }
        )
        assert THREAT_DOMAIN not in masked["extrainfo"]
        assert masked["threat"] in masked["extrainfo"]

    @pytest.mark.parametrize("record", RECORDS, ids=RECORD_IDS)
    def test_tripwire_no_domain_threat_with_empty_obf_url(self, record: dict[str, Any]):
        """The rule's one assumption, asserted so a counterexample fails a
        test instead of leaking silently: any fixture row whose ``threat``
        looks like a web domain must carry a non-empty ``obf_url``. Add
        live-captured rows to RECORDS and this trips on the day a build
        emits a domain threat without its escaped twin."""
        threat = record.get("threat")
        if not isinstance(threat, str) or not _looks_like_web_domain(threat):
            return
        obf = record.get("obf_url")
        assert isinstance(obf, str) and obf.strip(), (
            f"domain-shaped threat {threat!r} with empty obf_url would leak; "
            "the #40 sibling rule assumption no longer holds"
        )

    @pytest.mark.parametrize(
        "row",
        [r for r in FORTIVIEW_LIVE_ROWS if r["obf_url"]],
        ids=[i for r, i in zip(FORTIVIEW_LIVE_ROWS, LIVE_ROW_IDS, strict=True) if r["obf_url"]],
    )
    def test_live_shape_domain_rows_mask_as_pair(self, masker: OutputMasker, row: dict[str, Any]):
        """Full-shape rows (every sibling key the view emits): domain rows
        mask, the pair stays consistent, and neither raw form survives."""
        masked = masker.mask_result(row)
        assert row["threat"] not in str(masked)
        assert row["obf_url"] not in str(masked)
        assert masked["threat"].endswith(".masked.invalid")
        assert masked["obf_url"] == masked["threat"].replace(".", "[dot]")

    @pytest.mark.parametrize(
        "row",
        [r for r in FORTIVIEW_LIVE_ROWS if not r["obf_url"]],
        ids=[i for r, i in zip(FORTIVIEW_LIVE_ROWS, LIVE_ROW_IDS, strict=True) if not r["obf_url"]],
    )
    def test_live_shape_non_domain_rows_stay_clear(self, masker: OutputMasker, row: dict[str, Any]):
        """Signature, filename, anomaly and connection-verdict rows keep
        their analytic value — including the ``~``/``_`` filename class only
        one estate produces."""
        assert masker.mask_result(row)["threat"] == row["threat"]


class TestDocumentedGaps:
    """Pins for limits we chose not to close. A pin failing means someone
    changed the behavior, and the reasoning in fields.py needs revisiting."""

    def test_bare_username_in_prose_is_not_masked(self, masker: OutputMasker):
        """Free text is only as good as the response it sits in: a username
        that is masked nowhere else in the same response has no raw-to-token
        entry to substitute, and no regex can recognize one safely."""
        masked = masker.mask_result({"description": "escalate to jrivera"})
        assert "jrivera" in masked["description"]

    def test_handler_metadata_is_not_masked(self, full_masker: OutputMasker):
        masked = full_masker.mask_result(HANDLER)
        assert masked["name"] == HANDLER["name"]
        assert masked["template-url"] == HANDLER["template-url"]
        assert masked["mitre-domain"] == "enterprise"  # ATT&CK domain, not a DNS name

    def test_socialid_container_is_walked_not_typed(self, masker: OutputMasker):
        """Empty on every reference record; shape unknown, so it is only
        descended into. Whatever allowlisted keys it turns out to hold get
        masked by the ordinary recursive walk."""
        masked = masker.mask_result({"socialid": {"data": [{"srcip": ENDPOINT_IP}]}})
        assert masked["socialid"]["data"][0]["srcip"] != ENDPOINT_IP


class TestHandlerDescription:
    def test_embedded_ip_and_email_are_masked_in_the_description(self, masker: OutputMasker):
        masked = masker.mask_result(HANDLER)
        assert GATEWAY_IP not in masked["description"]
        assert SOC_EMAIL not in masked["description"]


class TestUrlFullMasking:
    """``url``/``referralurl``: host masks in place, the whole tail
    (path+query+fragment) seals into one reversible ``url-`` token.
    Maintainer decision on #40: these fields are carry-and-reverse, not
    greppable; scheme and port stay clear; credentials fail closed."""

    def test_tail_identifiers_do_not_survive(self, masker: OutputMasker):
        raw = f"https://{BAD_DOMAIN}/employees/{ANALYST}/profile?dept=finance&user={ANALYST}#t"
        masked = masker.mask_result({"url": raw})
        out = masked["url"]
        assert BAD_DOMAIN not in out
        assert ANALYST not in out
        assert "finance" not in out
        assert "employees" not in out

    def test_masked_url_shape(self, masker: OutputMasker):
        masked = masker.mask_result({"url": f"https://{BAD_DOMAIN}/a/b?c=d"})
        out = masked["url"]
        scheme, rest = out.split("://", 1)
        assert scheme == "https"
        host_part, _, tail_part = rest.partition("/")
        assert host_part.startswith("host-")
        assert tail_part.startswith("url-") and "/" not in tail_part

    def test_bare_host_and_bare_slash_stay_distinct(self, masker: OutputMasker):
        no_slash = masker.mask_result({"url": f"https://{BAD_DOMAIN}"})["url"]
        with_slash = masker.mask_result({"url": f"https://{BAD_DOMAIN}/"})["url"]
        assert no_slash != with_slash
        assert "url-" not in no_slash  # empty remainder short-circuits
        assert "url-" in with_slash  # bare / goes through the token path

    def test_referralurl_same_treatment_and_host_correlates(self, masker: OutputMasker):
        masked = masker.mask_result(
            {"referralurl": f"https://{BAD_DOMAIN}/from?x=1", "host_name": BAD_DOMAIN}
        )
        host_token = masked["host_name"]
        assert masked["referralurl"].startswith(f"https://{host_token}/url-")

    def test_userinfo_fails_closed_whole_value(self, masker: OutputMasker):
        masked = masker.mask_result({"url": f"https://{ANALYST}:secret@{BAD_DOMAIN}/x"})
        assert masked["url"].startswith("masked-unrepresentable-")
        assert ANALYST not in masked["url"] and "secret" not in masked["url"]

    def test_port_preserved_scheme_clear(self, masker: OutputMasker):
        masked = masker.mask_result({"url": f"https://{BAD_DOMAIN}:8443/x/y"})
        assert masked["url"].startswith("https://host-")
        assert ":8443/" in masked["url"]

    def test_non_url_value_seals_whole(self, masker: OutputMasker):
        # No parseable host: anything lands in the whole-value seal, so
        # even free-text junk in the field carries no identifier out.
        masked = masker.mask_result({"url": f"visited {ENDPOINT_IP} twice"})
        assert ENDPOINT_IP not in masked["url"]
        assert masked["url"].startswith("url-")

    def test_percent_encoded_url_seals_whole_value(self, masker: OutputMasker):
        # The live webfilter shape on both 7.6.7 and 8.0.0: the url field
        # carries the whole URL percent-encoded (scheme as %3A%2F%2F), so
        # nothing parses as a host and the free-text fallback cannot see
        # the hostname behind the %2F boundary. Found by the flag-on live
        # round; the whole raw value seals as one url token instead.
        encoded = f"https%3A%2F%2F{BAD_DOMAIN}%2Fportal%2Flogin%3Fuser%3D{ANALYST}"
        masked = masker.mask_result({"url": encoded, "hostname": BAD_DOMAIN})
        assert BAD_DOMAIN not in masked["url"]
        assert ANALYST not in masked["url"]
        assert masked["url"].startswith("url-")
        # the record keeps the masked-host correlation through the sibling
        assert masked["hostname"].startswith("host-")

    def test_schemeless_url_seals_whole(self, masker: OutputMasker):
        # Classic FAZ webfilter shapes carry no scheme; urlsplit finds no
        # host and the old fallback leaked the whole value raw (found by
        # the post-open adversarial review).
        for raw in (f"{BAD_DOMAIN}/login?user={ANALYST}", "/download/report-jdoe.pdf"):
            masked = masker.mask_result({"url": raw})["url"]
            assert masked.startswith("url-")
            assert BAD_DOMAIN not in masked and "login" not in masked and "jdoe" not in masked

    def test_control_chars_in_netloc_do_not_kill_the_result(self, masker: OutputMasker):
        # urlsplit strips tab/CR/LF (bpo-43882) so the parsed netloc is not
        # a substring of the raw value; the naive .index() raised and the
        # whole multi-row result failed closed.
        hostile = "http://exa\tmple.com/x"
        masked = masker.mask_result({"url": hostile, "other": "keep"})
        assert masked.get("other") == "keep"  # result survived
        assert "example.com" not in str(masked["url"])

    def test_single_letter_host_short_circuits(self, masker: OutputMasker):
        # 'https://h': .index() from position 0 found the 'h' inside the
        # scheme, mis-slicing the tail. The empty remainder must short
        # circuit with no url- token.
        masked = masker.mask_result({"url": "https://h"})["url"]
        assert "url-" not in masked
        assert masked.startswith("https://host-")

    def test_list_valued_url_masks(self, masker: OutputMasker):
        masked = masker.mask_result({"url": [f"https://{BAD_DOMAIN}/a/b"]})["url"]
        assert isinstance(masked, list)
        assert BAD_DOMAIN not in str(masked)

    def test_percent_encoded_userinfo_fails_closed(self, masker: OutputMasker):
        # Roland's decision: credentials never ride a reversible token.
        # The percent-encoded live shape can smuggle userinfo past the
        # netloc check; decode-and-inspect closes it.
        encoded = f"https%3A%2F%2F{ANALYST}%3Asecret%40{BAD_DOMAIN}%2Fpath"
        masked = masker.mask_result({"url": encoded})["url"]
        assert masked.startswith("masked-unrepresentable-")
        assert ANALYST not in masked and "secret" not in masked


class TestNonLogviewVocabulary:
    """Keys that no logview schema has, but a real tool response carries.

    The allowlist was built from ``get_log_fields``, so ``email``, ``domain``
    and ``message`` were dropped as names that mask nothing. The UEBA, SOAR
    and FortiView readers answer under exactly those names, and each of
    these records is the shape its reader returns.
    """

    def test_ueba_enduser_email_is_masked(self, masker: OutputMasker):
        engine = FPEEngine(KEY)
        record = {"euid": 5, "euname": ANALYST, "email": SOC_EMAIL, "department": "SOC"}
        masked = masker.mask_result({"status": "success", "data": [record]})
        out = masked["data"][0]

        assert SOC_EMAIL not in str(masked)
        assert engine.unmask_email(out["email"]) == SOC_EMAIL

    def test_fortiview_top_website_domain_is_masked(self, masker: OutputMasker):
        masked = masker.mask_result({"data": [{"domain": BAD_DOMAIN, "bandwidth": 2}]})

        assert BAD_DOMAIN not in str(masked)

    def test_error_message_embedded_ip_is_masked_in_place(self, masker: OutputMasker):
        # ``message`` is TEXT, so pass 2 scans it. A username in the same
        # prose is only substituted when the response masked it somewhere
        # (see the mapping residual in #73); an embedded address always is.
        masked = masker.mask_result({"status": "error", "message": f"could not reach {PEER_IP}"})

        assert PEER_IP not in masked["message"]


class TestSoarIndicatorPair:
    """``value`` typed by its sibling ``type``, the way SOAR returns an IOC."""

    def test_indicator_ip_is_masked(self, masker: OutputMasker):
        engine = FPEEngine(KEY)
        row = {"value": PEER_IP, "type": "IP", "enrichment-reputation": "Malicious"}
        out = masker.mask_result({"data": [row]})["data"][0]

        assert PEER_IP not in str(out)
        assert engine.unmask_ip(out["value"]) == PEER_IP
        assert out["enrichment-reputation"] == "Malicious"  # verdict stays readable

    def test_indicator_domain_is_masked(self, masker: OutputMasker):
        out = masker.mask_result({"data": [{"value": BAD_DOMAIN, "type": "Domain"}]})

        assert BAD_DOMAIN not in str(out)

    def test_indicator_url_is_masked(self, masker: OutputMasker):
        url = f"https://{BAD_DOMAIN}/payload"
        out = masker.mask_result({"data": [{"value": url, "type": "URL"}]})["data"][0]

        assert BAD_DOMAIN not in str(out)
        assert out["value"].startswith("https://host-")

    def test_indicator_type_is_case_insensitive(self, masker: OutputMasker):
        # SOAR spells them IP/URL/Domain; nothing guarantees the casing.
        for spelling in ("ip", "IP", "Ip"):
            out = masker.mask_result({"data": [{"value": PEER_IP, "type": spelling}]})
            assert PEER_IP not in str(out), spelling

    def test_generic_value_type_pair_is_left_alone(self, masker: OutputMasker):
        # The whole reason "value" is not allowlisted outright: the same key
        # names a severity band, a count and a setting elsewhere in the API.
        # An unrecognised type must leave it exactly as it was.
        for kind in ("string", "severity", "int", ""):
            out = masker.mask_result({"value": "high", "type": kind})
            assert out["value"] == "high", kind

    def test_value_without_a_type_sibling_is_left_alone(self, masker: OutputMasker):
        assert masker.mask_result({"value": "high"})["value"] == "high"

    def test_indicator_echo_in_prose_carries_the_same_token(self, masker: OutputMasker):
        # The skills layer names the indicator in its caller-facing warning.
        # Masked under one key and clear two keys away is the exact failure
        # the two-pass design exists to close.
        masked = masker.mask_result(
            {
                "data": [{"value": BAD_DOMAIN, "type": "Domain"}],
                "warnings": [f"no stored enrichment for Domain '{BAD_DOMAIN}'"],
            }
        )

        assert BAD_DOMAIN not in str(masked)
        assert masked["data"][0]["value"] in masked["warnings"][0]


class TestDeviceListAndSourceLink:
    """Two more names the log vocabulary never had.

    ``devs`` is the device list on an eventmgmt alert's ``subject_details``,
    and ``link`` is the reference URL a SOAR reputation source returns.
    """

    def test_devs_follows_the_device_identity_flag(self, masker: OutputMasker):
        # Flag off is the default: the appliance stays clear, like devname.
        subject = {"alertid": "A1", "devs": [DEV_NAME], "epids": [3]}
        masked = masker.mask_result({"subject_details": subject})

        assert masked["subject_details"]["devs"] == [DEV_NAME]

    def test_devs_masks_when_the_flag_is_on(self, full_masker: OutputMasker):
        subject = {"alertid": "A1", "devs": [DEV_NAME], "epids": [3]}
        masked = full_masker.mask_result({"subject_details": subject})

        assert DEV_NAME not in str(masked)

    def test_devs_and_devname_agree_under_the_flag(self, full_masker: OutputMasker):
        # The reason this matters: while devs was unlisted, the same device
        # was a token under devname and clear under devs in one record,
        # which hands over exactly the pairing the flag withholds.
        masked = full_masker.mask_result(
            {"devname": DEV_NAME, "subject_details": {"devs": [DEV_NAME]}}
        )

        assert DEV_NAME not in str(masked)
        assert masked["subject_details"]["devs"] == [masked["devname"]]

    def test_source_link_tail_is_sealed(self, masker: OutputMasker):
        # The reputation source puts the indicator in the query string.
        link = f"https://ioc.example.org/search?query={BAD_DOMAIN}"
        masked = masker.mask_result({"sources": [{"source": "cts", "link": link}]})
        out = masked["sources"][0]["link"]

        assert BAD_DOMAIN not in str(masked)
        assert "url-" in out  # sealed, not burned: it resolves back

    def test_dvmdb_device_name_masks_under_the_flag(self, full_masker: OutputMasker):
        """``name`` is dvmdb's device-name key, and it is in neither
        FIELD_TYPES nor DEVICE_IDENTITY_TYPES, so with the flag on a clear
        ``name`` sat beside its own ``devname`` token -- the flag defeated
        rather than followed, the same shape as ``devs`` (#79) and
        ``dev_name`` (#83), and made routine by this branch's curated
        ``_DEVICE_PROJECTION`` putting ``name`` in every default
        ``search_devices`` row (#109 review).

        It cannot be typed key-name-globally: ``name`` is also the ADOM key,
        the report-layout key and the device-group key, and a blanket entry
        burns "Monthly Security Report" to an irreversible placeholder.
        The record decides, exactly as ``incident_reporter`` does.
        """
        device = {"name": DEV_NAME, "devname": DEV_NAME, "sn": DEV_SERIAL, "os_ver": "7.4"}

        masked = full_masker.mask_result(device)

        assert DEV_NAME not in str(masked)
        assert masked["name"] == masked["devname"]

    def test_dvmdb_device_name_stays_clear_by_default(self, masker: OutputMasker):
        device = {"name": DEV_NAME, "sn": DEV_SERIAL, "os_ver": "7.4"}

        assert masker.mask_result(device)["name"] == DEV_NAME

    @pytest.mark.parametrize(
        "record",
        [
            {"name": "root", "desc": "default adom"},
            {"name": "Monthly Security Report", "layout-id": 7},
            {"name": "Branch-Group", "member": ["fgt-a"]},
        ],
        ids=["adom", "report-layout", "device-group"],
    )
    def test_a_name_with_no_device_siblings_is_untouched(
        self, full_masker: OutputMasker, record: dict[str, Any]
    ):
        """The blast radius the shape check exists to avoid. A report layout
        name is the sharp case: it is not a valid hostname, so a blanket
        entry would not tokenise it but burn it, with no way back."""
        assert full_masker.mask_result(dict(record)) == record

    def test_a_device_name_joins_the_keep_set_with_the_flag_off(self, masker: OutputMasker):
        """Flag off, the pairing runs the other way: the name must stay clear
        everywhere, including where another handler would have masked it."""
        payload = {
            "device": {"name": DEV_NAME, "sn": DEV_SERIAL},
            "target": [{"name": "srcname", "value": DEV_NAME}],
        }

        masked = masker.mask_result(payload)

        assert masked["target"][0]["value"] == DEV_NAME

    def test_a_non_device_name_does_not_join_the_keep_set(self, masker: OutputMasker):
        """The other half of the shape check: an ADOM or report name must not
        exempt an arbitrary string from masking elsewhere in the response."""
        payload = {
            "adom": {"name": SRC_NAME, "desc": "an adom that happens to be named this"},
            "target": [{"name": "srcname", "value": SRC_NAME}],
        }

        masked = masker.mask_result(payload)

        assert masked["target"][0]["value"] != SRC_NAME

    def test_source_link_round_trips(self, masker: OutputMasker):
        from fortianalyzer_mcp.masking.unmask import ArgUnmasker

        link = f"https://ioc.example.org/search?query={BAD_DOMAIN}"
        masked = masker.mask_result({"link": link})["link"]

        assert ArgUnmasker(FPEEngine(KEY)).resolve_url(masked) == link


class TestFortiViewResolvedName:
    """``srcip_hostname``/``dstip_hostname``: the resolved twin of a masked address.

    FortiView puts the reverse-resolved name for a row's address here, and
    the address itself when nothing resolves. Untyped, the second case
    handed the raw address back beside its own token, which gives away the
    token-to-raw pairing and not just the one value.
    """

    def test_unresolved_row_no_longer_leaks_the_address(self, masker: OutputMasker):
        row = {"dstip": PEER_IP, "dstip_hostname": PEER_IP, "sessions": 3}
        out = masker.mask_result({"data": [row]})["data"][0]

        assert PEER_IP not in str(out)

    def test_the_pair_agrees_so_no_pairing_is_disclosed(self, masker: OutputMasker):
        # The whole point: one raw value must not appear as a token under
        # one key and in clear under its sibling in the same row.
        row = {"srcip": PEER_IP, "srcip_hostname": PEER_IP}
        out = masker.mask_result({"data": [row]})["data"][0]

        assert out["srcip"] == out["srcip_hostname"]

    def test_resolved_row_masks_the_name_and_reverses(self, masker: OutputMasker):
        row = {"dstip": PEER_IP, "dstip_hostname": BAD_DOMAIN}
        out = masker.mask_result({"data": [row]})["data"][0]

        assert BAD_DOMAIN not in str(out)
        assert FPEEngine(KEY).unmask_hostname(out["dstip_hostname"]) == BAD_DOMAIN

    def test_address_form_stays_reversible(self, masker: OutputMasker):
        out = masker.mask_result({"dstip_hostname": PEER_IP})["dstip_hostname"]

        assert FPEEngine(KEY).unmask_ip(out) == PEER_IP

    @pytest.mark.parametrize("key", ["srcip_hostname", "dstip_hostname"])
    def test_both_columns_take_the_resolved_form_reversibly(self, masker: OutputMasker, key: str):
        # Asserting the resolved form on one column only left the other free
        # to be typed IP, which burns a hostname irreversibly, or TEXT, which
        # ships it in clear. Both passed the address-only assertions above.
        out = masker.mask_result({key: BAD_DOMAIN})[key]

        assert BAD_DOMAIN not in out
        assert not out.startswith("masked-unrepresentable-")
        assert FPEEngine(KEY).unmask_hostname(out) == BAD_DOMAIN


class TestIncidentWorkflowPrincipals:
    """``assigned_to``/``remedy_executor``/``remedy_approver``.

    Empty on an estate that does not work incidents, which is how they
    escaped the leak tests that were built from live records.
    """

    @pytest.mark.parametrize("key", ["assigned_to", "remedy_executor", "remedy_approver"])
    def test_workflow_principal_is_masked(self, masker: OutputMasker, key: str):
        masked = masker.mask_result({"incid": "IN00000001", key: ANALYST})

        assert ANALYST not in str(masked)

    def test_one_analyst_keeps_one_token_across_every_slot(self, masker: OutputMasker):
        # EMAIL falls back to username masking with no "@", so these agree
        # with the USERNAME siblings. If they did not, the same person would
        # read as several different principals in one record.
        masked = masker.mask_result(
            {
                "reporter": ANALYST,
                "lastuser": ANALYST,
                "assigned_to": ANALYST,
                "remedy_executor": ANALYST,
                "remedy_approver": ANALYST,
            }
        )

        assert len(set(masked.values())) == 1

    @pytest.mark.parametrize("key", ["assigned_to", "remedy_executor", "remedy_approver"])
    def test_at_shaped_login_masks_instead_of_burning(self, masker: OutputMasker, key: str):
        # The reason these are EMAIL and not USERNAME. Parametrised over all
        # three, because asserting it on one leaves the other two free to be
        # retyped back to USERNAME without any test noticing.
        masked = masker.mask_result({key: SOC_EMAIL})[key]

        assert SOC_EMAIL not in masked
        assert not masked.startswith("masked-unrepresentable-")

    def test_empty_slot_is_untouched(self, masker: OutputMasker):
        # The live shape on an estate that does not work incidents.
        assert masker.mask_result({"assigned_to": ""})["assigned_to"] == ""


class TestNestedDeviceName:
    """``device_info.dev_name``: the appliance, spelled a second way."""

    def test_nested_dev_name_follows_the_flag_too(self, full_masker: OutputMasker):
        # fortiview policy-hits spells the appliance dev_name inside a
        # device_info sub-object. Unlisted, it kept the name clear next to a
        # masked devid on the same row.
        #
        # devid holds the SERIAL and dev_name the hostname, as a live row
        # does. Reusing one string for both would let this pass even if
        # dev_name were typed TEXT, because pass 2 would substitute it from
        # the sibling's mapping entry and the field would never be typed at
        # all -- the original bug, shipping green.
        masked = full_masker.mask_result(
            {"devid": DEV_SERIAL, "device_info": {"dev_name": DEV_NAME, "ha_dev": "no"}}
        )

        assert DEV_NAME not in str(masked)
        assert DEV_SERIAL not in str(masked)

    def test_nested_dev_name_stays_clear_with_the_flag_off(self, masker: OutputMasker):
        masked = masker.mask_result({"device_info": {"dev_name": DEV_NAME}})

        assert masked["device_info"]["dev_name"] == DEV_NAME


class TestWave3SkillAssemblyKeys:
    """Keys the Wave-3 skills build themselves around an identifier.

    ``investigate_deep`` writes ``srcip==<value>`` clauses under ``pivot``
    and the caller's entity under ``entity_ref``; ``hunt`` writes the same
    clause shape under ``sweep.pivot_filter``; both interpolate the subject
    into ``headline``. The same response masks the value under its own key,
    so an untyped assembly key handed over the token-to-raw pairing, the
    srcip_hostname class. Typed TEXT they get exactly the ``filter``
    treatment: a value this response mapped is substituted (closing the
    pairing) and a bare IPv4 is caught by the IOC scan with the same token
    the structured pass mints. The residual they share with ``filter`` (a
    cold value that is neither mapped nor IPv4/MAC/email-shaped) is not
    pinned here because it is unchanged shipped behaviour, tracked for the
    whole filter family in #80.
    """

    def test_pivot_filter_tracks_the_row_token(self, masker: OutputMasker):
        # The pairing case: rows mask srcip, the sweep echoes the raw value.
        masked = masker.mask_result(
            {
                "rows": [{"srcip": PEER_IP}],
                "sweep": {"pivot_filter": f'srcip=="{PEER_IP}"'},
            }
        )

        assert PEER_IP not in str(masked)
        token = masked["rows"][0]["srcip"]
        assert masked["sweep"]["pivot_filter"] == f'srcip=="{token}"'

    def test_pivot_tracks_the_enduser_token(self, masker: OutputMasker):
        # investigate_deep: pivot built from the UEBA record's euname.
        masked = masker.mask_result(
            {
                "record": {"euname": ANALYST},
                "impact": {"entities": [{"pivot": f"user=={ANALYST}"}]},
            }
        )

        assert ANALYST not in str(masked)
        token = masked["record"]["euname"]
        assert masked["impact"]["entities"][0]["pivot"] == f"user=={token}"

    def test_entity_ref_ip_masks_and_numeric_ref_survives(self, masker: OutputMasker):
        # A cold entity_ref must carry the SAME token the typed path would
        # mint, or the model cannot pivot on it; a burn or a blank would
        # also satisfy a mere != assertion.
        expected = masker.mask_result({"srcip": PEER_IP})["srcip"]
        masked = masker.mask_result(
            {"impact": {"entities": [{"entity_ref": PEER_IP}, {"entity_ref": "12"}]}}
        )

        entities = masked["impact"]["entities"]
        assert entities[0]["entity_ref"] == expected
        # investigate_deep emits bare numeric refs for epid/euid subjects;
        # they are selectors, not identifiers, and TEXT never burns.
        assert entities[1]["entity_ref"] == "12"

    def test_headline_carries_the_exact_ip_token(self, masker: OutputMasker):
        expected = masker.mask_result({"srcip": PEER_IP})["srcip"]
        masked = masker.mask_result({"headline": f"indicator IP {PEER_IP}; sweep: 0 hits"})

        assert masked["headline"] == f"indicator IP {expected}; sweep: 0 hits"

    def test_pivot_pairing_holds_with_device_masking_on(self, full_masker: OutputMasker):
        masked = full_masker.mask_result(
            {
                "rows": [{"srcip": PEER_IP}],
                "sweep": {"pivot_filter": f'srcip=="{PEER_IP}"'},
            }
        )

        assert PEER_IP not in str(masked)
        token = masked["rows"][0]["srcip"]
        assert masked["sweep"]["pivot_filter"] == f'srcip=="{token}"'


class TestCompiledFilterEntries:
    """``filter_applied`` echoed as compiled ``[field, op, value]`` entries.

    Argument unmasking runs at the wrapper boundary, so a tool that compiles a
    caller's structured filter holds the RESOLVED identifier by the time it
    builds its entries. Echoing them untyped hands the raw value back to the
    model, unlocked by the model's own token, and TEXT alone cannot stop it:
    pass 2 can only substitute values this response mapped or match an
    IPv4/MAC/email shape, so an entry survives in clear exactly when the query
    matched nothing.
    """

    def test_a_hostname_entry_carries_the_typed_token(self, masker: OutputMasker):
        expected = masker.mask_result({"hostname": SRC_NAME})["hostname"]
        masked = masker.mask_result(
            {"count": 0, "devices": [], "filter_applied": [["hostname", "==", SRC_NAME]]}
        )

        assert SRC_NAME not in str(masked)
        assert masked["filter_applied"] == [["hostname", "==", expected]]

    def test_a_username_entry_carries_the_typed_token(self, masker: OutputMasker):
        expected = masker.mask_result({"user": ANALYST})["user"]
        masked = masker.mask_result({"count": 0, "filter_applied": [["user", "==", ANALYST]]})

        assert masked["filter_applied"] == [["user", "==", expected]]

    def test_an_ipv6_entry_masks_where_the_text_scan_cannot(self, masker: OutputMasker):
        # The pass-2 IOC scan is IPv4 only, so this one is invisible to it.
        ipv6 = "2001:db8::7"
        expected = masker.mask_result({"srcip": ipv6})["srcip"]
        masked = masker.mask_result({"count": 0, "filter_applied": [["srcip", "==", ipv6]]})

        assert ipv6 not in str(masked)
        assert masked["filter_applied"] == [["srcip", "==", expected]]

    def test_an_ipv4_entry_is_masked_exactly_once(self, masker: OutputMasker):
        # A masked IPv4 is still a valid IPv4, so an entry masked in pass 1 and
        # then walked again by the free-text scan would come back double
        # masked. Equality with the typed token is what pins single masking.
        expected = masker.mask_result({"srcip": PEER_IP})["srcip"]
        masked = masker.mask_result({"count": 0, "filter_applied": [["srcip", "==", PEER_IP]]})

        assert masked["filter_applied"] == [["srcip", "==", expected]]

    def test_the_string_form_keeps_its_text_treatment(self, masker: OutputMasker):
        expected = masker.mask_result({"srcip": PEER_IP})["srcip"]
        masked = masker.mask_result({"filter_applied": f"srcip=={PEER_IP}"})

        assert masked["filter_applied"] == f"srcip=={expected}"

    def test_an_untypeable_field_falls_back_to_the_text_scan(self, masker: OutputMasker):
        # No type to mask by, so the entry is not guessed at; the IOC scan
        # still catches an address shape rather than passing it through.
        masked = masker.mask_result({"filter_applied": [["mystery", "==", PEER_IP]]})

        assert PEER_IP not in str(masked)

    def test_shapes_that_are_not_entries_are_left_alone(self, masker: OutputMasker):
        masked = masker.mask_result({"filter_applied": ["a note", ["only", "two"]]})

        assert masked["filter_applied"] == ["a note", ["only", "two"]]


class TestProjectionEchoIsNotAnOracle:
    """``fields_returned`` echoes what ``fields`` resolved to.

    The round trip the projection feature opened, verified end to end rather
    than argued about:

    1. the model holds ``host-<...>``, a token this server issued;
    2. it passes that token in ``fields``;
    3. ``ArgUnmasker.resolve_scalar`` resolves any *self-identifying* token
       wherever it appears, so the token became the plaintext;
    4. ``query.fields.resolve_field`` passes an unknown-but-well-shaped name
       through, and a token is well shaped, so it survived as a projection
       key;
    5. the tool echoed it under ``fields_returned``, which no allowlist
       mentioned -- handing back plaintext unlocked by the model's own token.

    Structurally the ``filter_applied`` bug (#95) again, and the same lesson:
    a response key that reflects a caller argument needs a decision, and the
    absence of one defaults to leaking. Here the decision is that ``fields``
    names response KEYS, so there is nothing for unmasking to be right about.
    """

    @pytest.fixture
    def unmasker(self, monkeypatch: pytest.MonkeyPatch) -> ArgUnmasker:
        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        return ArgUnmasker(FPEEngine(KEY))

    def test_a_token_in_fields_is_not_resolved_to_plaintext(
        self, masker: OutputMasker, unmasker: ArgUnmasker
    ) -> None:
        """Step 3, closed: the projection key stays the token it arrived as."""
        token = masker.mask_result({"hostname": SRC_NAME})["hostname"]
        assert token != SRC_NAME, "fixture precondition: the value must mask"

        resolved = unmasker.unmask_args({"fields": [token]})

        assert resolved == {"fields": [token]}
        assert SRC_NAME not in str(resolved)

    def test_a_bare_token_argument_is_still_resolved(
        self, masker: OutputMasker, unmasker: ArgUnmasker
    ) -> None:
        """The skip is scoped to the field-NAME args, not to tokens in general.

        ``device`` carries a value, so a token there must still resolve --
        that is the whole point of argument unmasking. Without this, the tests
        either side would pass just as well if argument unmasking had been
        switched off wholesale, or if ``FIELD_NAME_ARGS`` had grown to swallow
        a value-carrying key.
        """
        token = masker.mask_result({"hostname": SRC_NAME})["hostname"]

        assert unmasker.unmask_args({"device": token}) == {"device": SRC_NAME}

    def test_nested_params_fields_are_skipped_too(
        self, masker: OutputMasker, unmasker: ArgUnmasker
    ) -> None:
        """faz_skill nests every tool argument under ``params``."""
        token = masker.mask_result({"hostname": SRC_NAME})["hostname"]

        resolved = unmasker.unmask_args({"skill": "log_search", "params": {"fields": [token]}})

        assert SRC_NAME not in str(resolved)

    def test_the_echo_is_masked_when_it_carries_a_mapped_value(self, masker: OutputMasker) -> None:
        """Step 5, closed independently: the echo is allowlisted as TEXT.

        Belt to the braces above -- any other route by which a real value
        reaches this key gets the same pass-2 treatment ``filter_applied`` and
        ``warnings`` already get, rather than no treatment at all.
        """
        masked = masker.mask_result(
            {"logs": [{"srcname": SRC_NAME}], "fields_returned": [f"srcname of {SRC_NAME}"]}
        )

        assert SRC_NAME not in str(masked["fields_returned"])

    def test_the_echo_scans_for_bare_indicators(self, masker: OutputMasker) -> None:
        masked = masker.mask_result({"count": 0, "fields_returned": [f"srcip {PEER_IP}"]})

        assert PEER_IP not in str(masked["fields_returned"])

    def test_ordinary_field_names_pass_through_unharmed(self, masker: OutputMasker) -> None:
        """The echo is the normal case; masking must not corrupt it."""
        names = ["action", "dstport", "policyid", "srcip", "user"]

        assert (
            masker.mask_result({"count": 0, "fields_returned": names})["fields_returned"] == names
        )


class TestAggregationArgEchoIsNotAnOracle:
    """``group_by``/``sample_by`` are the projection oracle again, worse.

    ``fields`` needed a *valid* field name to reach ``fields_returned``. The
    aggregation arguments do not: an unmapped ``group_by`` is refused, and the
    refusal quotes the dimension back verbatim. So resolving a token there
    would hand the plaintext to any caller who supplies a token that cannot
    possibly be a dimension -- which every token is. Measured on the previous
    code: ``group_by='host-2a85-...'`` came back as
    ``secret-internal.corp.example`` inside the refusal message.

    Both echoes are covered here, because both exist: ``sample_by`` is echoed
    on the *success* path (and again as every ``breakdowns`` key), ``group_by``
    on both.
    """

    @pytest.fixture
    def unmasker(self, monkeypatch: pytest.MonkeyPatch) -> ArgUnmasker:
        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        return ArgUnmasker(FPEEngine(KEY))

    @pytest.mark.parametrize("arg", ["group_by", "sort_by", "view_name"])
    def test_a_token_in_a_name_argument_is_not_resolved(
        self, masker: OutputMasker, unmasker: ArgUnmasker, arg: str
    ) -> None:
        token = masker.mask_result({"hostname": SRC_NAME})["hostname"]
        assert token != SRC_NAME, "fixture precondition: the value must mask"

        resolved = unmasker.unmask_args({arg: token})

        assert resolved == {arg: token}
        assert SRC_NAME not in str(resolved)

    def test_a_token_in_sample_by_is_not_resolved(
        self, masker: OutputMasker, unmasker: ArgUnmasker
    ) -> None:
        """sample_by takes a list, so the skip must survive the list walk."""
        token = masker.mask_result({"hostname": SRC_NAME})["hostname"]

        resolved = unmasker.unmask_args({"sample_by": [token, "app"]})

        assert resolved == {"sample_by": [token, "app"]}
        assert SRC_NAME not in str(resolved)

    def test_nested_params_aggregation_args_are_skipped_too(
        self, masker: OutputMasker, unmasker: ArgUnmasker
    ) -> None:
        """faz_skill nests every tool argument under ``params``."""
        token = masker.mask_result({"hostname": SRC_NAME})["hostname"]

        resolved = unmasker.unmask_args(
            {"skill": "log_search", "params": {"group_by": token, "sample_by": [token]}}
        )

        assert SRC_NAME not in str(resolved)

    async def test_the_refusal_path_hands_back_the_token_not_the_value(
        self, masker: OutputMasker, unmasker: ArgUnmasker, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End to end in the wrapper's own order: unmask args, run the tool,
        mask the result. A token in group_by can only ever be refused, so the
        refusal message is the echo that matters."""
        import fortianalyzer_mcp.tools.log_tools as log_tools

        token = masker.mask_result({"hostname": SRC_NAME})["hostname"]
        args = unmasker.unmask_args({"logtype": "traffic", "group_by": token})

        result = masker.mask_result(await log_tools.query_logs(**args))

        assert result["status"] == "error"
        assert SRC_NAME not in str(result)
        assert token in result["message"]

    async def test_the_success_echo_hands_back_the_token_not_the_value(
        self, masker: OutputMasker, unmasker: ArgUnmasker, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """sample_by *can* be a passthrough dimension, so it reaches the
        success path and is echoed there and under ``breakdowns``."""
        import fortianalyzer_mcp.tools.log_tools as log_tools

        class _Faz:
            async def ensure_connected(self) -> None:
                return None

            async def get_system_timezone(self) -> None:
                return None

        async def fake_page(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"logs": [], "total": 0, "tid": 1, "timed_out": False, "percentage": 100}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: _Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        token = masker.mask_result({"hostname": SRC_NAME})["hostname"]
        args = unmasker.unmask_args(
            {
                "logtype": "traffic",
                "time_range": "2024-01-01 00:00:00|2024-01-02 00:00:00",
                "sample_by": [token],
            }
        )

        result = masker.mask_result(await log_tools.query_logs(**args))

        assert result["status"] == "success"
        assert SRC_NAME not in str(result)
        assert result["sample_by"] == [token]
        assert token in result["breakdowns"]


class TestBreakdownsComposite:
    """``analyze_policy_traffic`` and ``query_logs(sample_by=...)`` both
    return ``{dimension: [{"value": ..., "hits": N}, ...]}``, and the raw
    value survived masking whole (#98): pass 1 only masks a bare ``"value"``
    key when a sibling ``"type"`` key exists (SOAR's ``_mask_indicator_pair``),
    and pass 2 only scans keys typed TEXT, which a plain ``"value"`` key never
    is. The dimension name -- the dict key one level up -- now decides the
    type of each bucket's ``"value"``.

    ``sample_by``/``group_by`` are not restricted to a safe subset: grouping
    by source or user is legitimate SOC functionality, so the fix lives
    entirely in the masking layer.
    """

    def test_the_reviewers_synthetic_payload_no_longer_survives(self, masker: OutputMasker) -> None:
        """The exact shape the review found leaking, reproduced verbatim."""
        masked = masker.mask_result({"breakdowns": {"srcip": [{"value": ENDPOINT_IP, "hits": 5}]}})

        assert ENDPOINT_IP not in str(masked)

    def test_a_typed_sibling_key_in_a_bucket_still_masks(self, masker: OutputMasker) -> None:
        """Before this handler existed, a bucket's sibling keys went through
        the allowlist walk; the handler must not trade the ``value`` leak it
        closes for a sibling leak it opens (#83's list-shape lesson). No
        shipped producer emits a typed sibling today -- this pins the walk
        so one can appear without re-opening it."""
        payload = {
            "breakdowns": {
                "srcip": [{"value": ENDPOINT_IP, "hits": 5, "hostname": SRC_NAME}],
            }
        }

        masked = masker.mask_result(payload)
        bucket = masked["breakdowns"]["srcip"][0]

        assert ENDPOINT_IP not in str(masked)
        assert SRC_NAME not in str(masked)
        assert bucket["hits"] == 5

    def test_analyze_policy_traffic_shape_masks_sensitive_dimensions(
        self, masker: OutputMasker
    ) -> None:
        """``analyze_policy_traffic``'s per-policy ``results[].breakdowns``."""
        payload = {
            "status": "success",
            "results": [
                {
                    "policy_id": 7,
                    "breakdowns": {
                        "srcip": [{"value": ENDPOINT_IP, "hits": 5}],
                        "user": [{"value": ANALYST, "hits": 3}],
                        "hostname": [{"value": SRC_NAME, "hits": 2}],
                        "port": [{"value": "6/443", "hits": 10}],
                        "app": [{"value": "HTTPS", "hits": 10}],
                    },
                    "is_exact": True,
                }
            ],
        }

        masked = masker.mask_result(payload)
        breakdowns = masked["results"][0]["breakdowns"]

        assert ENDPOINT_IP not in str(masked)
        assert ANALYST not in str(masked)
        assert SRC_NAME not in str(masked)
        # Non-sensitive dimensions are ordinary log fields with no type in
        # the allowlist, and must not be burned to a placeholder just
        # because sample_by can point at almost anything.
        assert breakdowns["port"] == [{"value": "6/443", "hits": 10}]
        assert breakdowns["app"] == [{"value": "HTTPS", "hits": 10}]

    def test_query_logs_sample_by_shape_masks_the_same_way(self, masker: OutputMasker) -> None:
        """``query_logs(sample_by=...)`` returns the identical shape (Task 4)."""
        payload = {
            "status": "success",
            "sample_by": ["srcip", "app"],
            "breakdowns": {
                "srcip": [{"value": PEER_IP, "hits": 12}],
                "app": [{"value": "SSL", "hits": 12}],
            },
        }

        masked = masker.mask_result(payload)

        assert PEER_IP not in str(masked)
        assert masked["breakdowns"]["app"] == [{"value": "SSL", "hits": 12}]

    def test_derived_dimensions_have_no_type_and_are_never_masked(
        self, masker: OutputMasker
    ) -> None:
        """``port``/``icmp_type_code`` are computed, not stored fields."""
        payload = {
            "breakdowns": {
                "port": [{"value": "6/443", "hits": 4}],
                "icmp_type_code": [{"value": "type=8/code=0", "hits": 1}],
            }
        }

        assert masker.mask_result(payload) == payload

    def test_device_identity_dimension_stays_clear_by_default(self, masker: OutputMasker) -> None:
        """A dimension named after a device-identity field follows the same
        keep-set as a flat field: clear unless the deployment opts in."""
        payload = {"breakdowns": {"fortigate": [{"value": DEV_NAME, "hits": 5}]}}

        masked = masker.mask_result(payload)

        assert masked["breakdowns"]["fortigate"][0]["value"] == DEV_NAME

    def test_device_identity_dimension_masks_when_flag_is_on(
        self, full_masker: OutputMasker
    ) -> None:
        payload = {"breakdowns": {"fortigate": [{"value": DEV_NAME, "hits": 5}]}}

        masked = full_masker.mask_result(payload)

        assert masked["breakdowns"]["fortigate"][0]["value"] != DEV_NAME

    def test_multiple_hits_all_mask_to_the_same_token(self, masker: OutputMasker) -> None:
        """Deterministic FPE: the same raw value in two buckets of the same
        breakdown (unlikely given aggregate_breakdowns's dedup, but not
        structurally impossible) still gets one consistent token."""
        payload = {
            "breakdowns": {
                "srcip": [
                    {"value": ENDPOINT_IP, "hits": 3},
                    {"value": PEER_IP, "hits": 1},
                ]
            }
        }

        masked = masker.mask_result(payload)["breakdowns"]["srcip"]

        assert masked[0]["value"] != ENDPOINT_IP
        assert masked[1]["value"] != PEER_IP
        assert masked[0]["value"] != masked[1]["value"]


BREAKDOWN_URL = "https://intranet.example.org/hr/salary?user=jdoe"


class TestBreakdownsCompositeDimensions:
    """A dimension whose flat key is handled by a COMPOSITE table, not by
    ``FIELD_TYPES`` (#109 review).

    The first cut of ``_mask_breakdowns`` typed a bucket from
    ``FIELD_TYPES`` alone, but ``url``/``referralurl``/``http_url``/``link``
    and ``devvds`` carry no entry there -- their flat keys are served by
    ``COMPOSITE_URL_FULL``/``COMPOSITE_URL_HOST``/``COMPOSITE_DEVICE_VDOM``.
    An untyped dimension passes through by design, so those rode out whole,
    beside the token the same host carried under a flat key in the same
    response: ``hits`` is the join key that pairs them.

    The fix is the rule the handler's docstring already stated -- a bucket
    value gets exactly what the same value gets under a flat key of the
    dimension's name -- so the walk now goes through :meth:`_mask_entry`
    rather than a ``FIELD_TYPES`` lookup.
    """

    @pytest.mark.parametrize("dimension", ["url", "referralurl", "http_url", "link"])
    def test_a_url_dimension_masks_like_its_flat_key(
        self, masker: OutputMasker, dimension: str
    ) -> None:
        payload = {"breakdowns": {dimension: [{"value": BREAKDOWN_URL, "hits": 2}]}}

        masked = masker.mask_result(payload)
        bucket = masked["breakdowns"][dimension][0]

        assert BREAKDOWN_URL not in str(masked)
        assert "intranet.example.org" not in str(masked)
        assert bucket["hits"] == 2

    def test_a_url_bucket_gets_the_same_token_as_the_flat_key(self, masker: OutputMasker) -> None:
        """The pairing that made this a correlation gift, pinned both ways:
        the bucket and the flat key must agree, not merely both be masked."""
        payload = {
            "url": BREAKDOWN_URL,
            "breakdowns": {"url": [{"value": BREAKDOWN_URL, "hits": 1}]},
        }

        masked = masker.mask_result(payload)

        assert masked["breakdowns"]["url"][0]["value"] == masked["url"]

    def test_a_devvds_dimension_follows_the_device_flag(
        self, masker: OutputMasker, full_masker: OutputMasker
    ) -> None:
        """``devvds`` is ``"<devname>[<vdom>]"`` -- composite, and device
        identity, so it must follow the flag exactly as the flat key does."""
        payload = {"breakdowns": {"devvds": [{"value": f"{DEV_NAME}[{VDOM}]", "hits": 3}]}}

        assert masker.mask_result(payload)["breakdowns"]["devvds"][0]["value"] == (
            f"{DEV_NAME}[{VDOM}]"
        )
        assert DEV_NAME not in str(full_masker.mask_result(payload))

    def test_an_untyped_dimension_still_passes_through(self, masker: OutputMasker) -> None:
        """The deliberate passthrough the handler's docstring argues for must
        survive the switch to _mask_entry: sample_by accepts almost any field
        and most of them (port, service, app, proto) are not identifiers."""
        payload = {"breakdowns": {"service": [{"value": "HTTPS", "hits": 9}]}}

        assert masker.mask_result(payload) == payload


class TestBreakdownsMalformedShapes:
    """An unrecognised bucket shape under a dimension we know is an
    identifier field (#109 review).

    ``_mask_target`` and the URL-dict branch both burn a shape they cannot
    type rather than trust the allowlist walk to cover it (#104). The
    breakdown handler failed open instead, so a bucket list holding bare
    strings rode out in clear under a dimension positively typed as an IP.
    No shipped producer emits either shape -- ``aggregate_breakdowns`` always
    emits ``[{"value", "hits"}]`` -- so this pins the policy, not a live bug.

    An *untyped* dimension keeps its passthrough: burning there would
    placeholder every legitimate non-identifier breakdown.
    """

    def test_a_bare_string_bucket_under_a_typed_dimension_burns(self, masker: OutputMasker) -> None:
        payload = {"breakdowns": {"srcip": [ENDPOINT_IP, 42, None]}}

        masked = masker.mask_result(payload)

        assert ENDPOINT_IP not in str(masked)
        assert masked["breakdowns"]["srcip"][1] == 42
        assert masked["breakdowns"]["srcip"][2] is None

    def test_a_non_list_bucket_container_under_a_typed_dimension_burns(
        self, masker: OutputMasker
    ) -> None:
        payload = {"breakdowns": {"srcip": {"value": ENDPOINT_IP}}}

        assert ENDPOINT_IP not in str(masker.mask_result(payload))

    def test_a_malformed_shape_under_an_untyped_dimension_passes_through(
        self, masker: OutputMasker
    ) -> None:
        payload = {"breakdowns": {"service": ["HTTPS", "DNS"]}}

        assert masker.mask_result(payload) == payload


class TestBreakdownsTextDimensions:
    """A TEXT dimension's bucket values, raised on review of #109.

    Pass 1 types a bucket's ``"value"`` from the dimension name, which covers
    every dimension whose values ARE identifiers. A TEXT dimension has no
    scalar type to mask by: its values are prose that may embed an identifier
    anywhere, which is what pass 2's free-text scan exists for. Under a flat
    ``msg``/``ui``/``subject`` key that scan fires because the KEY is typed
    TEXT; inside a bucket the key is a generic ``"value"``, so pass 2 never
    reached it and the free text rode out in clear.

    ``sample_by`` is not validated against a vocabulary -- deliberately, since
    a caller may break down on any field the rows carry -- so
    ``query_logs(logtype="event", sample_by=["msg"])`` is an ordinary call,
    not a contrived one.

    The invariant asserted here is parity: a bucket value gets exactly what
    the same string gets under its own flat key. That is one rule for all
    three classes of dimension (TEXT scanned, identifier tokenised, untyped
    passed through) instead of three, and it is what the review asked for.
    """

    # (dimension, bucket text). The last two are the deliberate passthroughs
    # a flat key of the same name also gets, kept here so the boundary is
    # asserted rather than assumed.
    TEXT_CASES = [
        ("msg", f"Admin login from {ENDPOINT_IP} failed"),
        ("ui", f"GUI({ENDPOINT_IP})"),
        ("subject", f"Report delivery to {SOC_EMAIL} deferred"),
        ("extrainfo", "client mac 00:11:22:33:44:55 not on the allow list"),
        ("logdesc", f"Traffic from {PEER_IP} denied by policy"),
        ("prompt", f"summarise the credentials for {SRC_NAME}"),
        ("srcip", ENDPOINT_IP),
        ("user", ANALYST),
        ("port", "6/443"),
        ("app", "HTTPS"),
    ]

    @pytest.mark.parametrize("dimension,text", TEXT_CASES, ids=[case[0] for case in TEXT_CASES])
    def test_a_bucket_value_gets_what_the_flat_field_gets(
        self, masker: OutputMasker, dimension: str, text: str
    ) -> None:
        flat = masker.mask_result({"rows": [{dimension: text}]})["rows"][0][dimension]
        bucket = masker.mask_result({"breakdowns": {dimension: [{"value": text, "hits": 3}]}})

        assert bucket["breakdowns"][dimension][0]["value"] == flat

    def test_embedded_iocs_do_not_survive_a_text_bucket(self, masker: OutputMasker) -> None:
        """The whole point, stated as identity comparison rather than parity."""
        payload = {
            "status": "success",
            "sample_by": ["msg", "subject", "extrainfo"],
            "breakdowns": {
                "msg": [{"value": f"Admin login from {ENDPOINT_IP} failed", "hits": 4}],
                "subject": [{"value": f"mail to {SOC_EMAIL}", "hits": 2}],
                "extrainfo": [{"value": "client mac 00:11:22:33:44:55", "hits": 1}],
            },
        }

        masked = masker.mask_result(payload)

        assert ENDPOINT_IP not in str(masked)
        assert SOC_EMAIL not in str(masked)
        assert "00:11:22:33:44:55" not in str(masked)
        # Counts are not identifiers and must survive the scan intact.
        assert [b["hits"] for b in masked["breakdowns"]["msg"]] == [4]

    def test_a_value_masked_elsewhere_is_resolved_inside_a_text_bucket(
        self, masker: OutputMasker
    ) -> None:
        """The sharp case: a hostname cannot be recognised by pattern, so it
        survives a bucket unless pass 2 substitutes what this response already
        mapped. Leaving it clear beside its own token in a sibling row is the
        token-to-plaintext pairing the layer exists to withhold."""
        payload = {
            "rows": [{"hostname": SRC_NAME}],
            "breakdowns": {"msg": [{"value": f"session from {SRC_NAME} blocked", "hits": 2}]},
        }

        masked = masker.mask_result(payload)

        assert SRC_NAME not in str(masked)
        assert masked["rows"][0]["hostname"] in masked["breakdowns"]["msg"][0]["value"]

    def test_an_identifier_dimension_is_not_masked_twice(self, masker: OutputMasker) -> None:
        """Pass 1 already tokenised this bucket, and a masked IPv4 is itself a
        valid IPv4, so a pass-2 scan over the same value would mask it again
        and hand back a token that matches nothing else in the response. Same
        hazard ``_mask_filter_entries`` documents."""
        payload = {
            "rows": [{"srcip": ENDPOINT_IP}],
            "breakdowns": {"srcip": [{"value": ENDPOINT_IP, "hits": 6}]},
        }

        masked = masker.mask_result(payload)

        assert masked["breakdowns"]["srcip"][0]["value"] == masked["rows"][0]["srcip"]

    def test_odd_bucket_shapes_do_not_crash_the_scan(self, masker: OutputMasker) -> None:
        """``aggregate_breakdowns`` always emits ``[{"value", "hits"}]``, but
        masking runs on whatever the appliance and the tools actually returned,
        so the handler must survive a shape it did not write."""
        payload = {
            "breakdowns": {
                "msg": [f"bare string from {ENDPOINT_IP}", {"value": None, "hits": 1}, None],
                "subject": {"not": "a list"},
            }
        }

        masked = masker.mask_result(payload)

        assert ENDPOINT_IP not in str(masked["breakdowns"]["msg"])
        assert masked["breakdowns"]["msg"][1] == {"value": None, "hits": 1}
        assert masked["breakdowns"]["subject"] == {"not": "a list"}


class TestGroupByGroupsRowsAlreadyCovered:
    """Third leak surface, checked per the review: ``query_logs(group_by=...)``
    returns ``groups: [<native FortiView row>, ...]``. Unlike ``breakdowns``,
    these rows carry the view's OWN field names (``srcip``, ``srcip_hostname``,
    ``threat``/``obf_url``, ``fortigate``) directly as dict keys -- the same
    keys ``FIELD_TYPES`` already documents as fortiview-sourced -- so the
    ordinary per-key allowlist already reaches them with no composite handler
    needed. These tests lock that finding in as a regression guard rather
    than leaving it as an unverified claim.
    """

    def test_top_sources_style_groups_are_masked_by_the_ordinary_allowlist(
        self, masker: OutputMasker
    ) -> None:
        payload = {
            "status": "success",
            "group_by": "srcip",
            "groups": [
                {"srcip": ENDPOINT_IP, "srcip_hostname": SRC_NAME, "hits": 42},
                {"srcip": PEER_IP, "hits": 7},
            ],
        }

        masked = masker.mask_result(payload)

        assert ENDPOINT_IP not in str(masked)
        assert PEER_IP not in str(masked)
        assert SRC_NAME not in str(masked)

    def test_top_threats_style_groups_use_the_existing_pair_handler(
        self, masker: OutputMasker
    ) -> None:
        payload = {
            "group_by": "attack",
            "groups": [
                {"threat": THREAT_DOMAIN, "obf_url": OBF_URL, "hits": 3},
                {"threat": THREAT_SIGNATURE, "obf_url": "", "hits": 1},
            ],
        }

        masked = masker.mask_result(payload)

        assert THREAT_DOMAIN not in str(masked)
        assert masked["groups"][1]["threat"] == THREAT_SIGNATURE

    def test_device_identity_in_groups_follows_the_same_flag(
        self, masker: OutputMasker, full_masker: OutputMasker
    ) -> None:
        payload = {"group_by": "srcip", "groups": [{"srcip": ENDPOINT_IP, "fortigate": DEV_NAME}]}

        default = masker.mask_result(payload)
        assert default["groups"][0]["fortigate"] == DEV_NAME

        flagged = full_masker.mask_result(payload)
        assert flagged["groups"][0]["fortigate"] != DEV_NAME


class TestCompositeMapShapes:
    """A map under a group-by key must not ride through in clear.

    A dict-shaped group-by used to fall through to the plain allowlist
    walk, on the reasoning that the walk would type it by its inner keys.
    That holds only when those keys happen to be allowlisted. Measured on
    2.13.0 (``cfc2585``) before the fix, with RFC 5737 values:

        {"groupby1": {"srcip": "192.0.2.90"}}     masked
        {"groupby1": {"a": "srcip:192.0.2.90"}}   LEAK, verbatim
        {"groupby1": {"a": "192.0.2.90"}}         LEAK, verbatim
        {"groupby1": [{"a": "srcip:192.0.2.90"}]} LEAK, verbatim
        {"groupby1": {"192.0.2.90": 5}}           LEAK, in the key

    upstream #73 item 1.
    """

    IP = "192.0.2.90"

    @pytest.mark.parametrize("key", ["groupby1", "groupby2"])
    def test_an_unknown_inner_key_does_not_leak_its_value(
        self, masker: OutputMasker, key: str
    ) -> None:
        out = masker.mask_result({key: {"a": f"srcip:{self.IP}"}})
        assert self.IP not in str(out)

    def test_an_unknown_inner_key_holding_a_bare_address_does_not_leak(
        self, masker: OutputMasker
    ) -> None:
        out = masker.mask_result({"groupby1": {"a": self.IP}})
        assert self.IP not in str(out)

    def test_an_identifier_used_as_the_key_does_not_leak(self, masker: OutputMasker) -> None:
        """The allowlist walk never masks a key, so a group-by keyed by the
        identifier handed it over as the key itself."""
        out = masker.mask_result({"groupby1": {self.IP: 5}})
        assert self.IP not in str(out)

    def test_a_map_nested_in_a_list_does_not_leak(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"groupby1": [{"a": f"srcip:{self.IP}"}]})
        assert self.IP not in str(out)

    def test_an_allowlisted_inner_key_still_masks_reversibly(self, masker: OutputMasker) -> None:
        """The half that worked is kept: burning the whole map would throw
        away a reversible mask, which is why this is not the blanket burn
        the URL composites and ``target`` use."""
        out = masker.mask_result({"groupby1": {"srcip": self.IP}})
        assert self.IP not in str(out)
        assert "srcip" in out["groupby1"]
        assert not str(out["groupby1"]["srcip"]).startswith("masked-unrepresentable")

    def test_known_and_unknown_keys_are_handled_separately(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"groupby1": {"srcip": self.IP, "a": "192.0.2.91"}})
        rendered = str(out)
        assert self.IP not in rendered
        assert "192.0.2.91" not in rendered
        assert "srcip" in out["groupby1"]

    def test_the_string_form_is_untouched(self, masker: OutputMasker) -> None:
        """The shape that already worked keeps working."""
        out = masker.mask_result({"groupby1": f"srcip:{self.IP}"})
        assert self.IP not in str(out)
        assert str(out["groupby1"]).startswith("srcip:")

    def test_a_known_key_holding_a_container_does_not_leak(self, masker: OutputMasker) -> None:
        """Recognising the key is not enough. _mask_entry's branches are
        shape-gated to strings, so a known key holding a container fell
        back into the allowlist walk this function exists to distrust."""
        for payload in (
            {"groupby1": {"srcip": {"nested": self.IP}}},
            {"groupby1": {"srcip": [{"nested": self.IP}]}},
            {"groupby1": [{"srcip": [{"nested": self.IP}]}]},
            {"groupby1": {"devvds": {"x": self.IP}}},
            {"groupby1": {"grpby": {"x": self.IP}}},
        ):
            assert self.IP not in str(masker.mask_result(payload)), payload

    def test_a_known_key_holding_a_list_of_strings_still_masks(self, masker: OutputMasker) -> None:
        """The shape _mask_entry can type is still handed to it, so
        narrowing the known branch does not burn what worked."""
        out = masker.mask_result({"groupby1": {"srcip": [self.IP]}})
        assert self.IP not in str(out)
        assert not str(out["groupby1"]["srcip"]).startswith("['masked-unrepresentable")

    def test_a_devvds_list_does_not_leak_device_identity(self, full_masker: OutputMasker) -> None:
        """_typeable() claims every composite branch handles a list of
        strings, but COMPOSITE_DEVICE_VDOM only had a str arm in
        _mask_entry -- a list value was waved through _mask_composite_map
        as "known and typeable", then fell through every typed branch
        (list is not str) straight to _mask_structured with no key
        context, which cannot identify bare strings as device[vdom]
        pairs. Leaked real device names verbatim even with
        mask_device_identity on."""
        device = "fw-paris-01[root]"
        out = full_masker.mask_result({"groupby1": {"devvds": [device, "fw-lyon-02[root]"]}})
        assert device not in str(out)

    def test_a_grpby_list_does_not_leak_an_embedded_identifier(self, masker: OutputMasker) -> None:
        """Same gap as devvds above, for COMPOSITE_JSON: a list of JSON
        blob strings under "grpby" fell through to _mask_structured with
        no key context and returned the embedded IP verbatim."""
        out = masker.mask_result({"groupby1": {"grpby": [f'{{"dstendpoint": "{self.IP}"}}']}})
        assert self.IP not in str(out)

    def test_a_burned_value_is_recorded_so_its_twin_in_prose_follows(
        self, masker: OutputMasker
    ) -> None:
        """_burn_strings takes no mapping, so a burned value's twin in a
        free-text field rode out in clear beside its own burned copy."""
        out = masker.mask_result(
            {"groupby1": {"srcuser": "walter.white"}, "msg": "blocked walter.white today"}
        )
        assert "walter.white" not in str(out)

    def test_a_masked_value_is_recorded_so_its_twin_in_prose_follows(
        self, masker: OutputMasker
    ) -> None:
        """The known branch has to keep feeding the shared mapping. Dropping
        its result on the floor left the map masked and the same name in
        clear two keys away, with the whole suite green."""
        out = masker.mask_result(
            {"groupby1": {"user": "walter.white"}, "msg": "blocked walter.white today"}
        )
        assert "walter.white" not in str(out)

    def test_a_device_identity_key_keeps_its_name_with_the_flag_off(
        self, masker: OutputMasker
    ) -> None:
        """The "is this name known" question is flag-independent. Asking
        the flag-mutated table made devname read as unknown with the flag
        off, so the KEY burned while the value stayed readable: mangled
        schema on the majority configuration, for no gain."""
        out = masker.mask_result({"groupby1": {"devname": "fw-paris-01"}})
        assert "devname" in out["groupby1"]

    def test_a_device_identity_key_still_masks_with_the_flag_on(
        self, full_masker: OutputMasker
    ) -> None:
        out = full_masker.mask_result({"groupby1": {"devname": "fw-paris-01"}})
        assert "devname" in out["groupby1"]
        assert "fw-paris-01" not in str(out)

    def test_a_known_key_is_matched_case_insensitively(self, masker: OutputMasker) -> None:
        """FortiAnalyzer surfaces do not agree on case. Matching the key
        verbatim would burn a dimension that masks reversibly today."""
        out = masker.mask_result({"groupby1": {"SrcIP": self.IP}})
        assert self.IP not in str(out)
        assert "SrcIP" in out["groupby1"]
        assert not str(out["groupby1"]["SrcIP"]).startswith("masked-unrepresentable")

    def test_a_kept_value_is_not_burned_inside_the_map(self, masker: OutputMasker) -> None:
        """A value the deployment chose to leave readable stays readable
        under every key. Burning it here while devname shows it two keys
        away is the same mismatch the keep set exists to prevent."""
        out = masker.mask_result({"devname": "fw-paris-01", "groupby1": {"unknown": "fw-paris-01"}})
        assert out["groupby1"]["unknown"] == "fw-paris-01"


class TestCompositeContainerShapesKeepKeyContext:
    """A composite key must keep deciding the type at every depth.

    Each composite kind dispatches on the key, then on the value's shape.
    The shapes with no arm fall to the generic tail, which walks by
    allowlist and knows none of these inner names, so the payload rides
    out in clear. The list arms had the same hole one level down: they
    delegated a non-string element to ``_mask_structured``, which is the
    route that strips the key context the value can only be typed by.

    Measured on ``1f60904`` before the fix, RFC 5737 / RFC 2606 values:

        {"devvds": {"a": "fw-oslo-01[root]"}}       LEAK, flag ON
        {"devvds": {"fw-oslo-01[root]": 5}}         LEAK, flag ON, in the key
        {"devvds": [["fw-oslo-01[root]"]]}          LEAK, flag ON
        {"grpby": {"a": '{"dstendpoint": "<ip>"}'}} LEAK
        {"grpby": {"<ip>": ...}}                    LEAK, in the key
        {"grpby": [['{"dstendpoint": "<ip>"}']]}    LEAK
        {"http_url": [["https://bad.example.com/x"]]} LEAK
        {"url":      [["https://bad.example.com/x"]]} LEAK

    Reachable rather than observed: no live surface sampled in the #80
    sweep emitted a composite under a map or a nested list. The same was
    true of ``groupby3`` and of the map shapes #116 closed.
    """

    IP = "192.0.2.90"
    DEV = "fw-oslo-01[root]"
    DEV_NAME = "fw-oslo-01"
    HOST = "bad.example.com"
    URL = "https://bad.example.com/x"

    def _blob(self) -> str:
        return f'{{"dstendpoint": "{self.IP}"}}'

    # ---- devvds: the device-identity flag must survive every shape ----

    def test_a_devvds_map_value_does_not_leak(self, full_masker: OutputMasker) -> None:
        out = full_masker.mask_result({"devvds": {"a": self.DEV}})
        assert self.DEV_NAME not in str(out)

    def test_a_devvds_map_keyed_by_the_device_does_not_leak(
        self, full_masker: OutputMasker
    ) -> None:
        """No later pass ever scans a key, so the map form hands the
        device name over as the key itself."""
        out = full_masker.mask_result({"devvds": {self.DEV: 5}})
        assert self.DEV_NAME not in str(out)

    def test_a_devvds_nested_list_does_not_leak(self, full_masker: OutputMasker) -> None:
        out = full_masker.mask_result({"devvds": [[self.DEV]]})
        assert self.DEV_NAME not in str(out)

    def test_a_devvds_map_stays_readable_with_the_flag_off(self, masker: OutputMasker) -> None:
        """The counterpart pin. Device identity is clear by design unless
        the deployment opts in, so the container shapes must not be closed
        by burning -- that would mask an estate name the flag-off
        deployment is entitled to read, under a key whose string form
        hands it back in clear two rows away."""
        out = masker.mask_result({"devvds": {"a": self.DEV}})
        assert out["devvds"]["a"] == self.DEV

    # ---- grpby: a JSON blob under a container ----

    def test_a_grpby_map_value_does_not_leak(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"grpby": {"a": self._blob()}})
        assert self.IP not in str(out)

    def test_a_grpby_map_keyed_by_the_identifier_does_not_leak(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"grpby": {self.IP: self._blob()}})
        assert self.IP not in str(out)

    def test_a_grpby_nested_list_does_not_leak(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"grpby": [[self._blob()]]})
        assert self.IP not in str(out)

    # ---- the URL composites, one level down from the arm that works ----

    @pytest.mark.parametrize("key", ["http_url", "url", "referralurl", "link"])
    def test_a_url_nested_list_does_not_leak(self, masker: OutputMasker, key: str) -> None:
        out = masker.mask_result({key: [[self.URL]]})
        assert self.HOST not in str(out)

    # ---- the shapes that already worked keep working ----

    def test_the_shapes_that_already_worked_are_untouched(
        self, masker: OutputMasker, full_masker: OutputMasker
    ) -> None:
        assert self.DEV_NAME not in str(full_masker.mask_result({"devvds": self.DEV}))
        assert self.DEV_NAME not in str(full_masker.mask_result({"devvds": [self.DEV]}))
        assert self.IP not in str(masker.mask_result({"grpby": self._blob()}))
        assert self.IP not in str(masker.mask_result({"grpby": [self._blob()]}))
        assert self.HOST not in str(masker.mask_result({"http_url": self.URL}))
        assert self.HOST not in str(masker.mask_result({"http_url": [self.URL]}))


class TestAuditConfirmedLeaks:
    """The five leaks confirmed by the live coverage sweep (#80).

    Every one has the same shape: the masker covers one spelling of an
    identifier and the appliance ships a second spelling of the same
    value on the same surface, often in the same record. Because FPE is
    deterministic, a record carrying both publishes the token and the
    plaintext for one identifier and hands over the mapping.

    Measured on 2.13.0 (``cfc2585``) with a known test key, in the live
    record shape, with the device-identity flag both off and on:

        {"mac_devtype_agg": "<mac>,DSM 7.3-86009"}   byte-identical
        {"dev_src_agg": "<host>,DSM 7.3-86009"}      byte-identical
        {"f_user": "<user>"}                         5 of 5 shapes verbatim
        {"auto_raise_grpby": '[{"dstendpoint": "<ip>"}]'}   verbatim

    while the covered twins (``mac``, ``dstmac``, ``hostname``,
    ``srcname``, ``device``, ``unauthuser``, ``grpby``) all masked the
    identical value.
    """

    MAC = "aa:bb:cc:dd:ee:11"
    HOST = "wkstn-audit-01"
    DEVTYPE = "Ubuntu 22.04.5"
    UUID = "ffeb3f77-0000-4000-8000-000000000001"
    IP = "198.51.100.22"
    USER = "audituser"

    # ---- f_user: a plain username slot, no composite involved ----

    @pytest.mark.parametrize(
        "payload",
        [
            "audituser",
            "audituser@example.com",
            "EXAMPLE\\audituser",
            "wkstn-audit-01",
            "198.51.100.22",
        ],
    )
    @pytest.mark.parametrize("flag", [False, True])
    def test_f_user_does_not_leak_any_measured_payload_shape(
        self, payload: str, flag: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """All five shapes the audit measured. Whether a given one becomes
        a token or a placeholder is the USERNAME handler's business; not
        plaintext is the contract.

        Asserts against the field, NOT against ``str(out)``: the repr
        escapes a backslash, so ``EXAMPLE\\audituser`` is not a substring
        of the rendered dict and that case could never have failed."""
        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        masker = OutputMasker(FPEEngine(KEY), mask_device_identity=flag)
        out = masker.mask_result({"f_user": payload})
        assert out["f_user"] != payload
        assert payload not in out["f_user"]

    def test_f_user_masks_like_its_covered_twin(self, masker: OutputMasker) -> None:
        """unauthuser holding the same literal masked while f_user did
        not, in the same dict. That pairing is what hands over the map."""
        out = masker.mask_result({"unauthuser": self.USER, "f_user": self.USER})
        assert out["f_user"] == out["unauthuser"]

    # ---- auto_raise_grpby: the twin of the covered grpby ----

    def test_auto_raise_grpby_does_not_leak(self, masker: OutputMasker) -> None:
        """COMPOSITE_JSON was ("grpby",) only. The audit's exact payload is
        a JSON array string, not an object."""
        blob = f'[{{"dstendpoint": "{self.IP}"}}]'
        out = masker.mask_result({"auto_raise_grpby": blob})
        assert self.IP not in str(out)

    def test_auto_raise_grpby_masks_like_grpby(self, masker: OutputMasker) -> None:
        blob = f'[{{"dstendpoint": "{self.IP}"}}]'
        out = masker.mask_result({"grpby": blob, "auto_raise_grpby": blob})
        assert out["auto_raise_grpby"] == out["grpby"]

    # ---- the two <identifier>,<devtype> aggregates ----

    @pytest.mark.parametrize("flag", [False, True])
    def test_mac_devtype_agg_masks_the_mac_and_keeps_the_devtype(
        self, flag: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        masker = OutputMasker(FPEEngine(KEY), mask_device_identity=flag)
        out = masker.mask_result({"mac_devtype_agg": f"{self.MAC},{self.DEVTYPE}"})
        rendered = out["mac_devtype_agg"]
        assert self.MAC not in rendered
        assert rendered.endswith(f",{self.DEVTYPE}")

    @pytest.mark.parametrize("flag", [False, True])
    def test_dev_src_agg_masks_the_device_and_keeps_the_devtype(
        self, flag: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        masker = OutputMasker(FPEEngine(KEY), mask_device_identity=flag)
        out = masker.mask_result({"dev_src_agg": f"{self.HOST},{self.DEVTYPE}"})
        rendered = out["dev_src_agg"]
        assert self.HOST not in rendered
        assert rendered.endswith(f",{self.DEVTYPE}")

    def test_the_agg_heads_mask_like_their_covered_twins(self, masker: OutputMasker) -> None:
        """The whole point of the finding: the covered and uncovered
        spellings land in the same record, so they must agree."""
        out = masker.mask_result(
            {
                "mac": self.MAC,
                "mac_devtype_agg": f"{self.MAC},{self.DEVTYPE}",
                "hostname": self.HOST,
                "dev_src_agg": f"{self.HOST},{self.DEVTYPE}",
            }
        )
        assert out["mac_devtype_agg"] == f"{out['mac']},{self.DEVTYPE}"
        assert out["dev_src_agg"] == f"{out['hostname']},{self.DEVTYPE}"

    def test_the_aggs_are_not_gated_on_the_device_identity_flag(self, masker: OutputMasker) -> None:
        """Their covered twins (mac, hostname) are FIELD_TYPES entries, so
        they mask with the flag OFF. The neighbouring devvds handler IS
        flag-gated, so the asymmetry needs a pin rather than an assumption
        of symmetry."""
        out = masker.mask_result(
            {
                "mac_devtype_agg": f"{self.MAC},{self.DEVTYPE}",
                "dev_src_agg": f"{self.HOST},{self.DEVTYPE}",
            }
        )
        assert self.MAC not in str(out)
        assert self.HOST not in str(out)

    def test_a_forticlient_uuid_head_is_masked_too(self, masker: OutputMasker) -> None:
        """dev_src_agg also carries the FortiClient UUID form. The
        srcuuid/dstuuid carve-out is scoped to those KEYS, not to the
        value's shape, and nothing else in this masker types by shape, so
        the head is masked by the key's type either way."""
        out = masker.mask_result({"dev_src_agg": f"{self.UUID},macOS 10.15.7"})
        assert self.UUID not in str(out)

    def test_a_second_pair_in_the_tail_does_not_leak(self, masker: OutputMasker) -> None:
        """These are agg fields: devvds's own docstring records that an
        aggregating row comma-joins several. A verbatim tail would hand
        back every identifier after the first."""
        second = "aa:bb:cc:dd:ee:22"
        out = masker.mask_result(
            {"mac_devtype_agg": f"{self.MAC},{self.DEVTYPE},{second},{self.DEVTYPE}"}
        )
        rendered = str(out)
        assert self.MAC not in rendered
        assert second not in rendered

    def test_a_second_hostname_pair_in_the_tail_does_not_leak(self, masker: OutputMasker) -> None:
        """mac_devtype_agg's second-pair coverage above is incidental,
        not designed: mask_text's MAC regex happens to catch a second
        MAC, but has no hostname regex, so dev_src_agg's second pair had
        no protection at all. Walking every pair by position rather than
        only typing the first closes this without needing one."""
        second = "wkstn-02.corp.local"
        out = masker.mask_result(
            {"dev_src_agg": f"{self.HOST},{self.DEVTYPE},{second},{self.DEVTYPE}"}
        )
        rendered = str(out)
        assert self.HOST not in rendered
        assert second not in rendered
        # the devtype strings stay readable
        assert rendered.count(self.DEVTYPE) == 2

    def test_a_value_with_no_comma_is_masked_whole(self, masker: OutputMasker) -> None:
        """Same fallback devvds uses for a shape it has not seen: mask the
        whole thing rather than hand back an untyped string."""
        out = masker.mask_result({"mac_devtype_agg": self.MAC})
        assert self.MAC not in str(out)

    def test_an_empty_value_is_unchanged(self, masker: OutputMasker) -> None:
        """The audit measured these empty on most live rows. An empty
        string must not become a placeholder."""
        out = masker.mask_result({"mac_devtype_agg": "", "dev_src_agg": "", "f_user": ""})
        assert out == {"mac_devtype_agg": "", "dev_src_agg": "", "f_user": ""}

    # ---- the new kind must be wired everywhere the existing kinds are ----

    @pytest.mark.parametrize("key", ["mac_devtype_agg", "dev_src_agg", "auto_raise_grpby"])
    def test_the_new_keys_survive_the_container_shapes(
        self, masker: OutputMasker, key: str
    ) -> None:
        """A composite kind handled at one site and not another is exactly
        how #73, #116 and #117 each found a leak. This walks the same
        shapes #117's matrix walks."""
        payloads = {
            "mac_devtype_agg": f"{self.MAC},{self.DEVTYPE}",
            "dev_src_agg": f"{self.HOST},{self.DEVTYPE}",
            "auto_raise_grpby": f'[{{"dstendpoint": "{self.IP}"}}]',
        }
        secrets = {
            "mac_devtype_agg": self.MAC,
            "dev_src_agg": self.HOST,
            "auto_raise_grpby": self.IP,
        }
        value, secret = payloads[key], secrets[key]
        for shape in (value, [value], {"a": value}, [[value]], {value: 1}):
            out = masker.mask_result({key: shape})
            assert secret not in str(out), f"{key} leaked under {shape!r}"

    @pytest.mark.parametrize("key", ["mac_devtype_agg", "dev_src_agg", "auto_raise_grpby"])
    def test_the_new_keys_work_as_a_groupby_dimension(self, masker: OutputMasker, key: str) -> None:
        """A composite key served by a handler rather than by FIELD_TYPES
        has to be listed as a composite dimension too, or a breakdown
        bucket under that name types from the empty table and passes
        through in clear (the #109 review's finding)."""
        payloads = {
            "mac_devtype_agg": (f"{self.MAC},{self.DEVTYPE}", self.MAC),
            "dev_src_agg": (f"{self.HOST},{self.DEVTYPE}", self.HOST),
            "auto_raise_grpby": (f'[{{"dstendpoint": "{self.IP}"}}]', self.IP),
        }
        value, secret = payloads[key]
        out = masker.mask_result({"breakdowns": {key: [{"value": value, "hits": 3}]}})
        assert secret not in str(out)
