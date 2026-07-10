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

Records below mirror the shape of real FAZ alert, incident and traffic
objects, with documentation values (RFC 5737 / RFC 2606) throughout.
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
# Device identity: masked only when the deployment opts in.
DEV_NAME = "fgt-branch-01"
DEV_SERIAL = "fgtserial0001"
FABRIC = "fabric-alpha"

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
    "event_details": {"devid": DEV_SERIAL, "dst_ip": GATEWAY_IP, "src_ip": ENDPOINT_IP},
    "target": [
        {"name": "domain", "value": BAD_DOMAIN},
        {"name": "device", "value": ENDPOINT_NAME, "asset_value": ENDPOINT_NAME},
        {"name": "device", "value": ENDPOINT_NAME, "asset_value": "1107"},
    ],
}
INCIDENT: dict[str, Any] = {
    "incid": "IN00000001",
    "endpoint": ENDPOINT_IP,
    "reporter": ANALYST,
    "lastuser": ANALYST,
    "grpby": f'[{{"dstendpoint": "{PEER_IP}"}}]',
}
TRAFFIC: dict[str, Any] = {
    "srcip": ENDPOINT_IP,
    "dstip": PEER_IP,
    "srcname": SRC_NAME,
    "devname": DEV_NAME,
    "msg": f"session from {SRC_NAME} ({ENDPOINT_IP}) to {PEER_IP}",
}

PERSONAL = [ENDPOINT_NAME, ENDPOINT_IP, GATEWAY_IP, BAD_DOMAIN, PEER_IP, SRC_NAME, ANALYST]
DEVICE_IDENTITY = [DEV_NAME, DEV_SERIAL, FABRIC]


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
    @pytest.mark.parametrize(
        "record", [ALERT, INCIDENT, TRAFFIC], ids=["alert", "incident", "traffic"]
    )
    def test_no_personal_identifier_survives(self, masker: OutputMasker, record: dict[str, Any]):
        leaked = survivors(masker.mask_result(record), PERSONAL)
        assert leaked == {}, f"masking leaked: {leaked}"

    @pytest.mark.parametrize(
        "record", [ALERT, INCIDENT, TRAFFIC], ids=["alert", "incident", "traffic"]
    )
    def test_device_identity_survives_by_default(
        self, masker: OutputMasker, record: dict[str, Any]
    ):
        """Documented, deliberate: estate identity stays readable unless opted in."""
        present = [d for d in DEVICE_IDENTITY if d in str(record)]
        leaked = survivors(masker.mask_result(record), DEVICE_IDENTITY)
        assert sorted(leaked) == sorted(present)

    @pytest.mark.parametrize(
        "record", [ALERT, INCIDENT, TRAFFIC], ids=["alert", "incident", "traffic"]
    )
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
