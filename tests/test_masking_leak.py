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

from typing import Any

import pytest

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
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
