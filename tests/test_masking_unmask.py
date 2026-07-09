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
