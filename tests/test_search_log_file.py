"""search_log_file: raw log file search, one device at a time."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.unmask import ArgUnmasker
from fortianalyzer_mcp.masking.wrapper import OutputMasker
from fortianalyzer_mcp.query.filters import FilterCondition
from fortianalyzer_mcp.tools import log_tools

HUB = "FGVMMLTM00000001"
HA_A = "FGVMMLTM00000002"
HA_B = "FGVMMLTM00000003"

STATS = {
    "data": {
        "devs": [
            {"devid": HUB, "devname": "hub"},
            {"devid": HA_A, "devname": "branch-ha"},
            {"devid": HA_B, "devname": "branch-ha"},
        ]
    }
}

KEY = "2DE79D232DF5585D68CE47882AE256D6"


def _client(rows: list[dict[str, Any]] | None = None, total: int | None = None) -> MagicMock:
    client = MagicMock()
    client.get_logstats = AsyncMock(return_value=STATS)
    result: dict[str, Any] = {"data": rows or [], "return-lines": len(rows or [])}
    if total is not None:
        result["total-count"] = total
    client.search_logfiles = AsyncMock(return_value=result)
    return client


async def _search(client: MagicMock, **kwargs: Any) -> dict[str, Any]:
    kwargs = {"adom": "root", "device": "hub", **kwargs}
    with patch.object(log_tools, "_get_client", return_value=client):
        return await log_tools.search_log_file(**kwargs)


@pytest.mark.asyncio
async def test_resolves_a_name_and_defaults_to_the_current_file() -> None:
    client = _client([{"srcip": "192.0.2.10"}], total=1)
    result = await _search(client, filter="srcip==192.0.2.10")

    client.search_logfiles.assert_awaited_once_with(
        adom="root",
        devid=HUB,
        vdom="root",
        filename="tlog.log",
        logtype="traffic",
        filter="srcip==192.0.2.10",
        limit=100,
        offset=0,
    )
    assert result["status"] == "success"
    assert result["devid"] == HUB
    assert result["count"] == 1
    assert result["has_more"] is False
    assert result["next_offset"] is None


@pytest.mark.asyncio
async def test_event_defaults_to_the_event_file() -> None:
    client = _client()
    await _search(client, logtype="event")
    assert client.search_logfiles.await_args.kwargs["filename"] == "elog.log"


@pytest.mark.asyncio
async def test_a_serial_skips_the_lookup() -> None:
    client = _client()
    await _search(client, device=HA_A)
    client.get_logstats.assert_not_called()
    assert client.search_logfiles.await_args.kwargs["devid"] == HA_A


@pytest.mark.asyncio
async def test_a_lowercased_serial_is_sent_as_the_appliance_stores_it() -> None:
    """Live 7.6.7 answers a lowercase devid with "not in the user scope"."""
    client = _client()
    await _search(client, device=HA_A.lower())
    client.get_logstats.assert_not_called()
    assert client.search_logfiles.await_args.kwargs["devid"] == HA_A


@pytest.mark.asyncio
async def test_ha_name_is_refused_with_its_members_as_candidates() -> None:
    client = _client()
    result = await _search(client, device="branch-ha")

    assert result["status"] == "error"
    assert result["error"] == "ambiguous_device"
    assert [c["devid"] for c in result["candidates"]] == [HA_A, HA_B]
    # The serials travel under a key masking types, not only in prose.
    assert HA_A not in result["message"] and HA_B not in result["message"]
    client.search_logfiles.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_device() -> None:
    client = _client()
    result = await _search(client, device="nope")
    assert result["error"] == "device_not_found"
    assert result["devname"] == "nope"
    client.search_logfiles.assert_not_called()


@pytest.mark.asyncio
async def test_an_unexpected_logstats_shape_reads_as_not_found() -> None:
    client = _client()
    client.get_logstats = AsyncMock(return_value={"data": [{"devid": HUB}]})
    result = await _search(client)
    assert result["error"] == "device_not_found"


@pytest.mark.asyncio
async def test_unmapped_logtype_needs_a_filename() -> None:
    client = _client()
    result = await _search(client, logtype="virus")
    assert result["error"] == "filename_required"
    client.search_logfiles.assert_not_called()


@pytest.mark.asyncio
async def test_unmapped_logtype_with_a_filename_searches_it() -> None:
    client = _client()
    result = await _search(client, logtype="virus", filename="Xlog.1778137200.log.zst")
    assert result["status"] == "success"
    assert client.search_logfiles.await_args.kwargs["filename"] == "Xlog.1778137200.log.zst"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filename",
    ["../tlog.log", "/var/log/tlog.log", "sub/tlog.log", "tlog..log", ".tlog.log", "tlog.log\x00"],
)
async def test_a_filename_that_is_not_a_bare_name_is_refused(filename: str) -> None:
    client = _client()
    result = await _search(client, filename=filename)
    assert result["error"] == "validation_error"
    client.search_logfiles.assert_not_called()


@pytest.mark.asyncio
async def test_a_file_of_another_logtype_warns() -> None:
    client = _client()
    result = await _search(client, filename="elog.log")
    assert any("logtype='event'" in w for w in result["warnings"])


@pytest.mark.asyncio
@pytest.mark.parametrize("device", ["hub[root]", "a b", "x" * 65, ""])
async def test_an_invalid_device_is_refused(device: str) -> None:
    client = _client()
    result = await _search(client, device=device)
    assert result["error"] == "validation_error"
    client.get_logstats.assert_not_called()
    client.search_logfiles.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("vdom", ["", "root/..", "vd 1"])
async def test_an_invalid_vdom_is_refused(vdom: str) -> None:
    client = _client()
    result = await _search(client, vdom=vdom)
    assert result["error"] == "validation_error"
    client.search_logfiles.assert_not_called()


@pytest.mark.asyncio
async def test_a_negative_offset_is_refused() -> None:
    client = _client()
    result = await _search(client, offset=-1)
    assert result["error"] == "validation_error"
    client.search_logfiles.assert_not_called()


@pytest.mark.asyncio
async def test_filter_and_filters_together_are_refused() -> None:
    """Same contract as query_logs: no silent choice between the two."""
    client = _client()
    result = await _search(
        client,
        filter="dstport==443",
        filters=[FilterCondition(field="srcip", op="eq", value="192.0.2.10")],
    )
    assert result["error"] == "conflicting_filter_input"
    client.search_logfiles.assert_not_called()


@pytest.mark.asyncio
async def test_structured_filters_and_fields() -> None:
    client = _client(
        [{"srcip": "192.0.2.10", "dstip": "192.0.2.20", "action": "accept", "x": 1}], total=1
    )
    result = await _search(
        client,
        filters=[FilterCondition(field="srcip", op="eq", value="192.0.2.10")],
        fields=["dstip"],
    )

    assert client.search_logfiles.await_args.kwargs["filter"] == "srcip==192.0.2.10"
    assert result["filter"] == "srcip==192.0.2.10"
    assert result["logs"] == [{"dstip": "192.0.2.20"}]
    assert result["fields_returned"] == ["dstip"]


@pytest.mark.asyncio
async def test_contains_compiles_to_like() -> None:
    """The spelling live 7.6.7 serves here; `contain` matches nothing."""
    client = _client()
    await _search(client, filters=[FilterCondition(field="service", op="contains", value="DNS")])
    assert client.search_logfiles.await_args.kwargs["filter"] == 'service like "%DNS%"'


@pytest.mark.asyncio
async def test_an_unknown_filter_field_passes_with_a_warning() -> None:
    client = _client()
    result = await _search(
        client, filters=[FilterCondition(field="no_such_field", op="eq", value="1")]
    )
    assert result["status"] == "success"
    assert any("no_such_field" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_a_field_name_carrying_syntax_is_refused_before_the_call() -> None:
    client = _client()
    result = await _search(
        client, filters=[FilterCondition(field="srcip) or (1", op="eq", value="1")]
    )
    assert result["error"] == "validation_error"
    client.search_logfiles.assert_not_called()


@pytest.mark.asyncio
async def test_no_logs() -> None:
    client = _client([], total=0)
    result = await _search(client)
    assert result["status"] == "success"
    assert result["count"] == 0
    assert result["logs"] == []
    assert result["has_more"] is False
    assert result["next_offset"] is None
    assert result["fields_returned"]


@pytest.mark.asyncio
async def test_total_count_drives_the_next_offset() -> None:
    client = _client([{"srcip": "192.0.2.10"}] * 2, total=10)
    result = await _search(client, limit=2, offset=4)
    assert result["total"] == 10
    assert result["has_more"] is True
    assert result["next_offset"] == 6


@pytest.mark.asyncio
async def test_a_full_last_page_has_no_next_offset() -> None:
    client = _client([{"srcip": "192.0.2.10"}] * 2, total=6)
    result = await _search(client, limit=2, offset=4)
    assert result["has_more"] is False
    assert result["next_offset"] is None


@pytest.mark.asyncio
async def test_without_total_a_full_page_offers_the_next_offset() -> None:
    client = _client([{"srcip": "192.0.2.10"}] * 2)
    result = await _search(client, limit=2, offset=4)
    assert result["total"] is None
    assert result["next_offset"] == 6


@pytest.mark.asyncio
async def test_limit_is_clamped_to_the_endpoint_maximum() -> None:
    client = _client()
    result = await _search(client, limit=1000)
    assert client.search_logfiles.await_args.kwargs["limit"] == 500
    assert result["limit"] == 500
    assert any("clamped to 500" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_an_appliance_error_is_an_error_envelope() -> None:
    client = _client()
    client.search_logfiles = AsyncMock(
        side_effect=RuntimeError("Invalid params: invalid log filename.")
    )
    result = await _search(client, filename="nosuch.log")
    assert result["status"] == "error"
    assert result["error"] == "faz_operation_failed"
    assert result["operation"] == "search_log_file"
    assert "invalid log filename" in result["message"]


@pytest.mark.asyncio
async def test_client_sends_the_fndn_parameters() -> None:
    """FNDN logview: devid, vdom, filename, logtype, limit, offset, filter."""
    client = FortiAnalyzerClient(host="test-faz.example.com", username="admin", password="password")
    with patch.object(client, "_raw_request", AsyncMock(return_value={"data": []})) as raw:
        await client.search_logfiles(
            adom="root",
            devid=HUB,
            vdom="root",
            filename="tlog.log",
            logtype="traffic",
            filter="dstport==443",
            limit=5,
            offset=10,
        )
    (method, url), params = raw.call_args.args, raw.call_args.kwargs
    assert (method, url) == ("get", "/logview/adom/root/logfiles/search")
    assert params == {
        "apiver": 3,
        "devid": HUB,
        "vdom": "root",
        "filename": "tlog.log",
        "logtype": "traffic",
        "case-sensitive": True,
        "limit": 5,
        "offset": 10,
        "filter": "dstport==443",
    }


class TestMasking:
    """Output masking applies to this tool as to query_logs; these pin its keys."""

    @pytest.fixture
    def engine(self, monkeypatch: pytest.MonkeyPatch) -> FPEEngine:
        monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
        return FPEEngine(KEY)

    @pytest.mark.asyncio
    async def test_rows_are_masked(self, engine: FPEEngine) -> None:
        client = _client([{"srcip": "192.0.2.10", "dstip": "192.0.2.20", "devid": HUB}], total=1)
        masked = OutputMasker(engine).mask_result(await _search(client, fields=["*"]))
        assert "192.0.2.10" not in str(masked)
        assert "192.0.2.20" not in str(masked)

    @pytest.mark.asyncio
    async def test_devid_stays_clear_with_device_identity_off(self, engine: FPEEngine) -> None:
        """Even with no rows: a serial under ``device`` used to mask as a hostname."""
        masked = OutputMasker(engine).mask_result(await _search(_client(), device=HUB))
        assert masked["devid"] == HUB

    @pytest.mark.asyncio
    async def test_devid_round_trips_with_device_identity_on(self, engine: FPEEngine) -> None:
        client = _client([{"srcip": "192.0.2.10", "devid": HUB}], total=1)
        masked = OutputMasker(engine, mask_device_identity=True).mask_result(
            await _search(client, fields=["*"])
        )
        token = masked["devid"]
        assert token != HUB
        assert masked["logs"][0]["devid"] == token
        assert ArgUnmasker(engine).unmask_args({"device": token}) == {"device": HUB}

    @pytest.mark.asyncio
    async def test_ambiguous_device_leaks_neither_serials_nor_name(self, engine: FPEEngine) -> None:
        result = await _search(_client(), device="branch-ha")
        masked = OutputMasker(engine, mask_device_identity=True).mask_result(result)
        assert masked["error"] == "ambiguous_device"
        text = str(masked)
        assert HA_A not in text and HA_B not in text
        assert "branch-ha" not in text

    @pytest.mark.asyncio
    async def test_device_not_found_does_not_echo_the_name(self, engine: FPEEngine) -> None:
        result = await _search(_client(), device="branch-fw")
        masked = OutputMasker(engine, mask_device_identity=True).mask_result(result)
        assert "branch-fw" not in str(masked)
