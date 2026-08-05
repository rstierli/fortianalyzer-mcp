"""Tests for computed group dimensions."""

from __future__ import annotations

from typing import Any

import pytest

from fortianalyzer_mcp.query.derive import derive, dimension_value, is_derived


class TestPortDimension:
    """port is proto/dstport, the key get_policy_port_analysis counted on."""

    def test_tcp_port_is_proto_slash_port(self) -> None:
        assert derive("port", {"proto": "6", "dstport": "443"}) == "6/443"

    def test_integer_values_are_accepted(self) -> None:
        assert derive("port", {"proto": 6, "dstport": 443}) == "6/443"

    def test_a_zero_port_is_portless_and_yields_none(self) -> None:
        """ICMP and friends carry dstport 0; that is not port 0."""
        assert derive("port", {"proto": "1", "dstport": "0"}) is None

    def test_a_missing_port_yields_none(self) -> None:
        assert derive("port", {"proto": "6"}) is None


class TestIcmpTypeCodeDimension:
    """The decoding lifted out of get_policy_port_analysis before its deletion."""

    def test_ping_is_echo_request(self) -> None:
        row = {"proto": "1", "service": "PING"}
        assert derive("icmp_type_code", row) == "type=8/code=0"

    def test_ping_is_matched_case_insensitively(self) -> None:
        assert derive("icmp_type_code", {"proto": "1", "service": "ping"}) == "type=8/code=0"

    def test_icmp_slash_form_is_decoded(self) -> None:
        row = {"proto": "1", "service": "icmp/3/3"}
        assert derive("icmp_type_code", row) == "type=3/code=3"

    def test_icmp_slash_form_is_matched_case_insensitively(self) -> None:
        """PING two branches up matches any case; an uppercase ICMP/ spelling
        would have fallen through to type=unknown, a silent misbucket."""
        assert derive("icmp_type_code", {"proto": "1", "service": "ICMP/3/3"}) == "type=3/code=3"

    def test_malformed_icmp_form_does_not_leak_the_raw_string(self) -> None:
        row = {"proto": "1", "service": "icmp/9"}
        assert derive("icmp_type_code", row) == "type=unknown"

    def test_sdwan_probe_mislabel_becomes_unknown_not_a_fake_type(self) -> None:
        """A FortiGate SD-WAN SLA probe tags an ICMP packet with the probed
        application service. That is not an ICMP encoding, and recording it as
        one would invent a type that never crossed the wire."""
        row = {"proto": "1", "service": "DNS"}
        assert derive("icmp_type_code", row) == "type=unknown"

    def test_empty_service_is_unknown(self) -> None:
        assert derive("icmp_type_code", {"proto": "1", "service": ""}) == "type=unknown"

    def test_a_non_icmp_row_is_not_an_icmp_bucket(self) -> None:
        row = {"proto": "6", "service": "HTTPS"}
        assert derive("icmp_type_code", row) is None


class TestDimensionValue:
    """One accessor for both derived and plain dimensions."""

    def test_derived_dimension_is_computed(self) -> None:
        assert dimension_value("port", {"proto": "6", "dstport": "443"}) == "6/443"

    def test_plain_dimension_is_read_and_stringified(self) -> None:
        assert dimension_value("dstport", {"dstport": 443}) == "443"

    def test_absent_plain_dimension_yields_none(self) -> None:
        assert dimension_value("dstport", {}) is None

    def test_empty_string_counts_as_absent(self) -> None:
        """An empty value is not a bucket; it is a missing value."""
        assert dimension_value("app", {"app": ""}) is None

    @pytest.mark.parametrize("name,expected", [("port", True), ("dstport", False)])
    def test_is_derived_reports_membership(self, name: str, expected: bool) -> None:
        assert is_derived(name) is expected

    def test_a_dict_valued_field_is_not_a_bucket(self) -> None:
        """Nested values cannot be group keys; stringifying one would produce
        a bucket label nobody can filter on afterwards."""
        row: dict[str, Any] = {"target": {"name": "srcip"}}
        assert dimension_value("target", row) is None
