"""Tests for Phase 2 tool-argument unmasking (RFC #40)."""

import pytest

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.unmask import ArgUnmasker
from fortianalyzer_mcp.masking.wrapper import OutputMasker, install_masking

KEY = "2DE79D232DF5585D68CE47882AE256D6"


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY)


@pytest.fixture
def unmasker(engine: FPEEngine) -> ArgUnmasker:
    return ArgUnmasker(engine)


@pytest.fixture
def masker(engine: FPEEngine, monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    return OutputMasker(engine)


class TestScalarResolution:
    def test_marked_tokens_resolve_without_field_context(
        self, unmasker: ArgUnmasker, engine: FPEEngine
    ):
        for real, token in [
            ("edge-fw-01", engine.mask_hostname("edge-fw-01")),
            ("jdoe", engine.mask_username("jdoe")),
            ("example.com", engine.mask_domain("example.com")),
            ("alice@example.com", engine.mask_email("alice@example.com")),
        ]:
            assert unmasker.resolve_scalar(token) == real

    def test_unmarked_ip_resolves_only_with_field_type(
        self, unmasker: ArgUnmasker, engine: FPEEngine
    ):
        token = engine.mask_ip("192.0.2.102")
        assert unmasker.resolve_scalar(token) == token  # no context: untouched
        assert unmasker.resolve_scalar(token, "ip") == "192.0.2.102"

    def test_unmarked_mac_resolves_with_field_type(self, unmasker: ArgUnmasker, engine: FPEEngine):
        token = engine.mask_mac("00:1a:2b:3c:4d:5e")
        assert unmasker.resolve_scalar(token, "mac") == "00:1a:2b:3c:4d:5e"

    def test_plain_values_pass_through(self, unmasker: ArgUnmasker):
        assert unmasker.resolve_scalar("traffic") == "traffic"
        assert unmasker.resolve_scalar("24-hour") == "24-hour"
        assert unmasker.resolve_scalar("") == ""

    def test_corrupt_marked_token_passes_through_for_validator(self, unmasker: ArgUnmasker):
        # Marker present, payload undecryptable: leave it so the downstream
        # validator rejects it loudly instead of us guessing a real value.
        assert unmasker.resolve_scalar("host-###") == "host-###"


class TestFilterExpressions:
    def test_ip_clause_resolved_by_field_name(self, unmasker: ArgUnmasker, engine: FPEEngine):
        token = engine.mask_ip("192.0.2.102")
        out = unmasker.unmask_filter(f'srcip=="{token}"')
        assert out == 'srcip=="192.0.2.102"'

    def test_marked_token_resolved_in_any_clause(self, unmasker: ArgUnmasker, engine: FPEEngine):
        token = engine.mask_username("jdoe")
        assert unmasker.unmask_filter(f'user=="{token}"') == 'user=="jdoe"'

    def test_multi_clause_expression(self, unmasker: ArgUnmasker, engine: FPEEngine):
        ip = engine.mask_ip("192.0.2.102")
        user = engine.mask_username("jdoe")
        out = unmasker.unmask_filter(f'srcip=="{ip}" and user=="{user}" and action=="deny"')
        assert out == 'srcip=="192.0.2.102" and user=="jdoe" and action=="deny"'

    def test_unquoted_and_operators_preserved(self, unmasker: ArgUnmasker, engine: FPEEngine):
        ip = engine.mask_ip("192.0.2.102")
        assert unmasker.unmask_filter(f"srcip=={ip}") == "srcip==192.0.2.102"
        assert unmasker.unmask_filter("dstport>=443") == "dstport>=443"

    def test_non_ioc_clauses_untouched(self, unmasker: ArgUnmasker):
        expr = 'action=="deny" and dstport==443'
        assert unmasker.unmask_filter(expr) == expr


class TestArgumentWalk:
    def test_flat_args(self, unmasker: ArgUnmasker, engine: FPEEngine):
        args = {
            "srcip": engine.mask_ip("192.0.2.102"),
            "logtype": "traffic",
            "limit": 100,
        }
        out = unmasker.unmask_args(args)
        assert out == {"srcip": "192.0.2.102", "logtype": "traffic", "limit": 100}

    def test_filter_argument(self, unmasker: ArgUnmasker, engine: FPEEngine):
        token = engine.mask_ip("192.0.2.102")
        out = unmasker.unmask_args({"filter": f'srcip=="{token}"'})
        assert out["filter"] == 'srcip=="192.0.2.102"'

    def test_nested_dispatcher_params(self, unmasker: ArgUnmasker, engine: FPEEngine):
        # RFC #44's faz_skill(skill, params) nests everything one level down.
        ip = engine.mask_ip("192.0.2.102")
        args = {
            "skill": "log_search",
            "params": {"logtype": "traffic", "filter": f'srcip=="{ip}"', "limit": 10},
        }
        out = unmasker.unmask_args(args)
        assert out["params"]["filter"] == 'srcip=="192.0.2.102"'
        assert out["skill"] == "log_search"
        assert out["params"]["limit"] == 10

    def test_list_of_marked_tokens(self, unmasker: ArgUnmasker, engine: FPEEngine):
        tokens = [engine.mask_hostname("edge-fw-01"), engine.mask_hostname("core-sw-02")]
        out = unmasker.unmask_args({"devices": tokens})
        assert out["devices"] == ["edge-fw-01", "core-sw-02"]

    def test_comma_joined_ip_argument(self, unmasker: ArgUnmasker, engine: FPEEngine):
        joined = ",".join(engine.mask_ip(ip) for ip in ("192.0.2.1", "192.0.2.2"))
        out = unmasker.unmask_args({"ipaddr": joined})
        assert out["ipaddr"] == "192.0.2.1,192.0.2.2"

    def test_non_string_values_untouched(self, unmasker: ArgUnmasker):
        args = {"limit": 50, "include_alerts": True, "adom": None}
        assert unmasker.unmask_args(args) == args


class TestRoundTrip:
    def test_masked_output_token_resolves_as_argument(
        self, masker: OutputMasker, unmasker: ArgUnmasker
    ):
        # The exact loop the RFC needs: mask an IP into a result, feed the
        # token back as a tool argument, get the real IP at the API boundary.
        masked = masker.mask_result({"logs": [{"srcip": "192.0.2.102", "user": "jdoe"}]})
        token_ip = masked["logs"][0]["srcip"]
        token_user = masked["logs"][0]["user"]
        args = unmasker.unmask_args({"srcip": token_ip, "filter": f'user=="{token_user}"'})
        assert args["srcip"] == "192.0.2.102"
        assert args["filter"] == 'user=="jdoe"'

    async def test_wrapped_tool_unmasks_args_and_masks_output(
        self, monkeypatch: pytest.MonkeyPatch, engine: FPEEngine
    ):
        from mcp.server.fastmcp import FastMCP

        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        mcp = FastMCP("test")
        install_masking(mcp)
        seen: dict[str, str] = {}

        @mcp.tool()
        async def fake_search(srcip: str) -> dict:
            seen["srcip"] = srcip  # what the tool body (and validators) observe
            return {"logs": [{"srcip": srcip}]}

        token = engine.mask_ip("192.0.2.102")
        result = await fake_search(srcip=token)
        assert seen["srcip"] == "192.0.2.102"  # unmasked before the body ran
        assert result["logs"][0]["srcip"] == token  # re-masked on the way out

    async def test_nested_wrapped_tool_masks_exactly_once(
        self, monkeypatch: pytest.MonkeyPatch, engine: FPEEngine
    ):
        """Tools call other registered tools through their module-level
        names, which are the WRAPPED functions. The boundary guard must
        keep masking at the outermost call only: without it the inner
        result masks twice, no token round-trips (unmask yields another
        token) and a second pass over a first-pass token can fail closed
        into a placeholder. Found by the flag-on live round: 8 of 8
        fortiview threat rows arrived double-masked, 2 as placeholders."""
        from mcp.server.fastmcp import FastMCP

        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        mcp = FastMCP("test")
        install_masking(mcp)

        @mcp.tool()
        async def inner_search() -> dict:
            return {"logs": [{"srcip": "192.0.2.102", "qname": "threat.example.net"}]}

        @mcp.tool()
        async def outer_report() -> dict:
            return {"data": (await inner_search())["logs"]}

        row = (await outer_report())["data"][0]
        unmasker = ArgUnmasker(engine)
        assert row["qname"].endswith(".masked.invalid")
        assert "masked-unrepresentable-" not in row["qname"]
        # One unmask step must yield the raw value, not another token.
        assert unmasker.resolve_scalar(row["qname"]) == "threat.example.net"
        assert unmasker.unmask_args({"srcip": row["srcip"]})["srcip"] == "192.0.2.102"


@pytest.fixture
def full_masker(engine: FPEEngine, monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    return OutputMasker(engine, mask_device_identity=True)


# (field, real value) for every masking type the wrapper can emit, including
# the shapes live FAZ actually returns: epname holds an address on some
# records and a name on others, and euname holds an address on ueba rows.
ROUND_TRIP_FIELDS = [
    ("srcip", "192.0.2.19"),
    ("srcmac", "00:1a:2b:3c:4d:5e"),
    ("srcname", "workstation-14"),
    ("user", "jdoe"),
    ("qname", "suspicious.example.com"),
    ("sender", "soc@example.org"),
    ("epname", "192.0.2.19"),
    ("epname", "tablet-a3"),
    ("euname", "192.0.2.19"),
    ("device", "fgt-branch-01"),
    ("endpoint", "192.0.2.19"),
    ("reporter", "jdoe"),
]


class TestRoundTripEveryType:
    """Masking is only useful if the token survives the trip back.

    The output tests prove a value leaves masked. These prove the model can
    hand that token to a tool and the API sees the real value again. A type
    that masks but does not unmask is worse than one that does neither: the
    model gets a token it can never use.
    """

    @pytest.mark.parametrize(
        "field,raw", ROUND_TRIP_FIELDS, ids=[f"{f}-{r}" for f, r in ROUND_TRIP_FIELDS]
    )
    def test_token_from_output_resolves_as_an_argument(
        self, masker: OutputMasker, unmasker: ArgUnmasker, field: str, raw: str
    ):
        token = masker.mask_result({field: raw})[field]
        assert token != raw, f"{field} was never masked, so this proves nothing"
        assert unmasker.unmask_args({field: token})[field] == raw

    def test_device_identity_token_resolves_under_any_argument_name(
        self, full_masker: OutputMasker, unmasker: ArgUnmasker
    ):
        """``fortigate`` is not an argument name the unmasker knows, but a
        hostname token carries its own ``host-`` marker, so it resolves
        wherever the model puts it."""
        token = full_masker.mask_result({"fortigate": "fgt-branch-01"})["fortigate"]
        assert unmasker.unmask_args({"device": token})["device"] == "fgt-branch-01"
        assert unmasker.unmask_args({"fortigate": token})["fortigate"] == "fgt-branch-01"


class TestRoundTripDocumentedLimits:
    def test_devvds_token_does_not_resolve_as_an_argument(
        self, full_masker: OutputMasker, unmasker: ArgUnmasker
    ):
        """``"<token>[<vdom>]"`` is a fortiview display string, not a device
        argument. It carries a marker but will not decrypt as a whole, so it
        passes through untouched and the tool's validator rejects it. Failing
        closed here beats guessing that the caller meant the device half."""
        token = full_masker.mask_result({"devvds": "fgt-branch-01[root]"})["devvds"]
        assert token.startswith("host-") and token.endswith("[root]")
        assert unmasker.unmask_args({"device": token})["device"] == token

    def test_hostname_case_is_not_preserved(self, masker: OutputMasker, unmasker: ArgUnmasker):
        """The hostname alphabet is lowercase, so case is lost at mask time,
        not at unmask time. Harmless for DNS names, which are case
        insensitive; worth knowing for device names that are not."""
        token = masker.mask_result({"srcname": "FGT-BRANCH-01"})["srcname"]
        assert unmasker.unmask_args({"srcname": token})["srcname"] == "fgt-branch-01"
