"""Tests for the UEBA reader tools (Wave-2 skills building blocks).

Two layers, matching the rest of the suite:
- tool-level: patch ``get_faz_client`` in ``ueba_tools`` with a fake client
  and assert the envelope, validation, and parameter forwarding;
- client-level: use the ``mock_client`` fixture and patch the request layer
  to assert the endpoint URL and JSON-RPC params.
"""

from typing import Any

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.tools import ueba_tools


class _FakeClient:
    """Records the last call and returns a canned payload."""

    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.calls: dict[str, dict[str, Any]] = {}
        self.vuln_detectby_seen: list[Any] = []

    async def get_endpoints(self, **kwargs: Any) -> Any:
        self.calls["get_endpoints"] = kwargs
        return self.payload

    async def get_endpoint_vulnerabilities(self, **kwargs: Any) -> Any:
        self.calls["get_endpoint_vulnerabilities"] = kwargs
        self.vuln_detectby_seen.append(kwargs.get("detectby"))
        return self.payload

    async def get_endusers(self, **kwargs: Any) -> Any:
        self.calls["get_endusers"] = kwargs
        return self.payload

    async def get_endpoint_stats(self, **kwargs: Any) -> Any:
        self.calls["get_endpoint_stats"] = kwargs
        return self.payload

    async def get_enduser_stats(self, **kwargs: Any) -> Any:
        self.calls["get_enduser_stats"] = kwargs
        return self.payload

    async def get_system_timezone(self) -> Any:
        # The stats readers parse a relative window, which touches the TZ.
        from zoneinfo import ZoneInfo

        return ZoneInfo("UTC")


def _patch_client(monkeypatch: pytest.MonkeyPatch, payload: Any) -> _FakeClient:
    fake = _FakeClient(payload)
    monkeypatch.setattr(ueba_tools, "get_faz_client", lambda: fake)
    return fake


# --------------------------------------------------------------------- #
# get_endpoints                                                         #
# --------------------------------------------------------------------- #


class TestGetEndpoints:
    async def test_success_and_param_forwarding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # epname/epip are the real (curated) identity fields, so this
        # exercises the default projection rather than opting out with
        # fields=["*"] -- see TestUebaProjection for why that matters.
        fake = _patch_client(monkeypatch, [{"epname": "host-1", "epip": "10.0.0.5"}])
        result = await ueba_tools.get_endpoints(adom="root", epids=[7], detail_level="basic")
        assert result["status"] == "success"
        assert result["data"][0]["epname"] == "host-1"
        sent = fake.calls["get_endpoints"]
        assert sent["adom"] == "root"
        assert sent["epids"] == [7]
        assert sent["detail_level"] == "basic"

    async def test_rejects_invalid_detail_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, [])
        result = await ueba_tools.get_endpoints(detail_level="everything")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_client_missing_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ueba_tools, "get_faz_client", lambda: None)
        result = await ueba_tools.get_endpoints()
        assert result["status"] == "error"


# --------------------------------------------------------------------- #
# get_endpoint_vulnerabilities                                          #
# --------------------------------------------------------------------- #


class TestGetEndpointVulnerabilities:
    async def test_success_and_param_forwarding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(monkeypatch, [{"vulnid": "CVE-2024-0001"}])
        result = await ueba_tools.get_endpoint_vulnerabilities(epids=[1025], detectby="FortiClient")
        assert result["status"] == "success"
        assert result["data"][0]["vulnid"] == "CVE-2024-0001"
        sent = fake.calls["get_endpoint_vulnerabilities"]
        assert sent["epids"] == [1025]
        assert sent["detectby"] == "FortiClient"

    async def test_rejects_invalid_detectby(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, [])
        result = await ueba_tools.get_endpoint_vulnerabilities(detectby="FortiGuard")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_detectby_omitted_unions_all_detectors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The appliance returns nothing without a detector filter, so an
        # omitted detectby must query every detector and combine (#87), not
        # forward a single None that reads as "no vulnerabilities".
        fake = _patch_client(monkeypatch, [{"epid": "1", "vuln-group": {"vulnerabilities": []}}])
        result = await ueba_tools.get_endpoint_vulnerabilities()
        assert result["status"] == "success"
        assert sorted(fake.vuln_detectby_seen) == ["FortiClient", "FortiGate"]
        # one record per detector call is combined into the result
        assert len(result["data"]) == 2


# --------------------------------------------------------------------- #
# get_endusers                                                          #
# --------------------------------------------------------------------- #


class TestGetEndusers:
    async def test_success_extended(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(monkeypatch, [{"euname": "jdoe", "email": "jdoe@example.com"}])
        result = await ueba_tools.get_endusers(detail_level="extended", fields=["*"])
        assert result["status"] == "success"
        assert result["data"][0]["email"] == "jdoe@example.com"
        assert fake.calls["get_endusers"]["detail_level"] == "extended"

    async def test_rejects_invalid_detail_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, [])
        result = await ueba_tools.get_endusers(
            detail_level="simple"
        )  # valid for endpoints, not endusers
        assert result["status"] == "error"
        assert "Validation error" in result["message"]


# --------------------------------------------------------------------- #
# get_endpoint_stats                                                    #
# --------------------------------------------------------------------- #


class TestGetEndpointStats:
    async def test_success_and_param_forwarding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(
            monkeypatch,
            [{"total-count": "9", "new-count": "4", "identified-count": "0"}],
        )
        result = await ueba_tools.get_endpoint_stats(
            adom="root", time_range="2026-07-17 00:00:00|2026-07-24 00:00:00", filter="category=IOT"
        )
        assert result["status"] == "success"
        assert result["data"][0]["total-count"] == "9"
        sent = fake.calls["get_endpoint_stats"]
        assert sent["adom"] == "root"
        assert sent["filter"] == "category=IOT"
        assert sent["time_range"] == {
            "start": "2026-07-17 00:00:00",
            "end": "2026-07-24 00:00:00",
        }

    async def test_default_window_is_sent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(monkeypatch, [{"total-count": "0"}])
        result = await ueba_tools.get_endpoint_stats(adom="root")
        assert result["status"] == "success"
        sent = fake.calls["get_endpoint_stats"]
        assert set(sent["time_range"]) == {"start", "end"}
        assert sent["filter"] is None

    async def test_client_missing_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ueba_tools, "get_faz_client", lambda: None)
        result = await ueba_tools.get_endpoint_stats(
            time_range="2026-07-17 00:00:00|2026-07-24 00:00:00"
        )
        assert result["status"] == "error"


# --------------------------------------------------------------------- #
# get_enduser_stats                                                     #
# --------------------------------------------------------------------- #


class TestGetEnduserStats:
    async def test_success_and_param_forwarding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(monkeypatch, {"total-count": "2", "new-count": "0"})
        result = await ueba_tools.get_enduser_stats(
            adom="root",
            time_range="2026-07-17 00:00:00|2026-07-24 00:00:00",
            stats_item=["total-count"],
        )
        assert result["status"] == "success"
        assert result["data"]["total-count"] == "2"
        sent = fake.calls["get_enduser_stats"]
        assert sent["adom"] == "root"
        assert sent["stats_item"] == ["total-count"]
        assert sent["time_range"] == {
            "start": "2026-07-17 00:00:00",
            "end": "2026-07-24 00:00:00",
        }

    async def test_rejects_invalid_stats_item(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, {})
        result = await ueba_tools.get_enduser_stats(
            time_range="2026-07-17 00:00:00|2026-07-24 00:00:00",
            stats_item=["total-count", "bogus"],
        )
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_default_stats_item_left_to_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _patch_client(monkeypatch, {"total-count": "0"})
        result = await ueba_tools.get_enduser_stats(
            time_range="2026-07-17 00:00:00|2026-07-24 00:00:00"
        )
        assert result["status"] == "success"
        # The reader forwards None; the client fills the FAZ-required default.
        assert fake.calls["get_enduser_stats"]["stats_item"] is None


# --------------------------------------------------------------------- #
# client methods (endpoint URL + JSON-RPC params)                       #
# --------------------------------------------------------------------- #


class TestUebaClientMethods:
    async def test_get_endpoints_request_shape(self, mock_client: FortiAnalyzerClient) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(
            mock_client, "_generic_request", AsyncMock(return_value=[{"epid": 1}])
        ) as req:
            await mock_client.get_endpoints(adom="root", epids=[1], detail_level="standard")
        assert req.await_args.args[0] == "get"
        assert req.await_args.args[1] == "/ueba/adom/root/endpoints"
        kwargs = req.await_args.kwargs
        assert kwargs["detail-level"] == "standard"
        assert kwargs["epids"] == [1]
        assert kwargs["apiver"] == 3

    async def test_get_endusers_request_shape(self, mock_client: FortiAnalyzerClient) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(mock_client, "_generic_request", AsyncMock(return_value=[])) as req:
            await mock_client.get_endusers(adom="root", detail_level="extended")
        assert req.await_args.args[1] == "/ueba/adom/root/endusers"
        assert req.await_args.kwargs["detail-level"] == "extended"

    async def test_get_endpoint_vulnerabilities_request_shape(
        self, mock_client: FortiAnalyzerClient
    ) -> None:
        from unittest.mock import AsyncMock, patch

        with patch.object(mock_client, "_generic_request", AsyncMock(return_value=[])) as req:
            await mock_client.get_endpoint_vulnerabilities(adom="root", detectby="FortiGate")
        assert req.await_args.args[1] == "/ueba/adom/root/endpoints/vuln"
        assert req.await_args.kwargs["detectby"] == "FortiGate"

    async def test_get_endpoint_stats_request_shape(self, mock_client: FortiAnalyzerClient) -> None:
        from unittest.mock import AsyncMock, patch

        tr = {"start": "2026-07-17 00:00:00", "end": "2026-07-24 00:00:00"}
        with patch.object(
            mock_client,
            "_generic_request",
            AsyncMock(return_value=[{"total-count": "9"}]),
        ) as req:
            result = await mock_client.get_endpoint_stats(
                adom="root", time_range=tr, filter="category=IOT"
            )
        assert req.await_args.args[0] == "get"
        assert req.await_args.args[1] == "/ueba/adom/root/endpoints/stats"
        kwargs = req.await_args.kwargs
        assert kwargs["apiver"] == 3
        assert kwargs["time-range"] == tr
        assert kwargs["filter"] == "category=IOT"
        assert result == [{"total-count": "9"}]

    async def test_get_endpoint_stats_wraps_dict_result(
        self, mock_client: FortiAnalyzerClient
    ) -> None:
        from unittest.mock import AsyncMock, patch

        tr = {"start": "2026-07-17 00:00:00", "end": "2026-07-24 00:00:00"}
        with patch.object(
            mock_client, "_generic_request", AsyncMock(return_value={"total-count": "9"})
        ):
            result = await mock_client.get_endpoint_stats(adom="root", time_range=tr)
        assert result == [{"total-count": "9"}]

    async def test_get_enduser_stats_request_shape(self, mock_client: FortiAnalyzerClient) -> None:
        from unittest.mock import AsyncMock, patch

        tr = {"start": "2026-07-17 00:00:00", "end": "2026-07-24 00:00:00"}
        with patch.object(
            mock_client,
            "_generic_request",
            AsyncMock(return_value={"total-count": "2", "new-count": "0"}),
        ) as req:
            await mock_client.get_enduser_stats(adom="root", time_range=tr)
        assert req.await_args.args[1] == "/ueba/adom/root/endusers/stats"
        kwargs = req.await_args.kwargs
        assert kwargs["apiver"] == 3
        assert kwargs["time-range"] == tr
        # FAZ requires stats-item alongside time-range; the client defaults it.
        assert kwargs["stats-item"] == ["total-count", "new-count"]

    async def test_get_enduser_stats_custom_stats_item(
        self, mock_client: FortiAnalyzerClient
    ) -> None:
        from unittest.mock import AsyncMock, patch

        tr = {"start": "2026-07-17 00:00:00", "end": "2026-07-24 00:00:00"}
        with patch.object(mock_client, "_generic_request", AsyncMock(return_value={})) as req:
            await mock_client.get_enduser_stats(
                adom="root", time_range=tr, stats_item=["total-count"]
            )
        assert req.await_args.kwargs["stats-item"] == ["total-count"]


# --------------------------------------------------------------------- #
# projection                                                            #
# --------------------------------------------------------------------- #


class TestUebaProjection:
    """Endpoints and endusers project against realistic UEBA rows.

    Rows here are shaped like the live appliance response -- epname/epip for
    endpoints, euname for end-users -- per the evidence in
    ``masking/fields.py`` (verified against live 7.6.7/8.0.0 schemas),
    ``skills/handlers.py``'s field usages, and the docstring ``Example``
    blocks in this module. A row shaped like the wrong, guessed field names
    (``hostname``/``ip``/``username``) would pass the default-projection
    assertions below whether or not the curated set was correct, so it
    cannot catch a curated set drifting from what the appliance sends --
    only a realistic row can.
    """

    async def test_endpoints_default_keeps_identity_and_join_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        row = {
            "epid": 1,
            "euid": 2,
            "epname": "WS-ALPHA",
            "epip": "192.0.2.10",
            "vulnstat": {"big": "payload"},
        }

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_endpoints(self, **kwargs: object) -> list[dict[str, object]]:
                return [row]

        monkeypatch.setattr(ueba_tools, "_get_client", lambda: FakeClient())

        result = await ueba_tools.get_endpoints()

        row = result["data"][0]
        # Keys plus the non-PII values. `epname` and `epip` are masked types,
        # so their values are rewritten by the arg unmasker when
        # MASKING_ENABLED is set -- asserting on them makes the outcome depend
        # on a deployment flag rather than on the projection. The join-key ids
        # carry no type, so they still pin that real values came through.
        assert row.keys() == {"epid", "euid", "epname", "epip"}
        assert row["epid"] == 1
        assert row["euid"] == 2
        assert "vulnstat" not in row

    async def test_endusers_default_drops_email_keeps_euname(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No ``fields`` at all -- the no-op-catcher finding 2 asked for.

        Every other ``get_endusers`` call in this file passes ``fields=["*"]``
        (an identity pass-through) or never reaches a successful projection,
        so none of them would notice a regression that silently reverted the
        default path (e.g. ``"data": result`` instead of the projected
        ``data``). This one omits ``fields`` and checks both directions: a
        canonical-but-not-curated field (``email``) is actually gone, and a
        curated field (``euname``) actually survives.
        """
        row = {"euid": 2, "euname": "jdoe", "email": "jdoe@example.com"}

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_endusers(self, **kwargs: object) -> list[dict[str, object]]:
                return [row]

        monkeypatch.setattr(ueba_tools, "_get_client", lambda: FakeClient())

        result = await ueba_tools.get_endusers()

        row = result["data"][0]
        assert row.keys() == {"euid", "euname"}
        assert row["euid"] == 2, "a real value, not a null-padded key"
        assert "email" not in row

    async def test_endusers_star_returns_everything(self, monkeypatch: pytest.MonkeyPatch) -> None:
        row = {"euid": 2, "euname": "jdoe", "email": "jdoe@example.com"}

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_endusers(self, **kwargs: object) -> list[dict[str, object]]:
                return [row]

        monkeypatch.setattr(ueba_tools, "_get_client", lambda: FakeClient())

        result = await ueba_tools.get_endusers(fields=["*"])

        # The claim is that ["*"] keeps the key the curated default drops, so
        # key presence is the whole assertion; `email` is a masked type and its
        # value is rewritten under MASKING_ENABLED.
        assert result["data"][0].keys() == set(row)
        assert "email" in result["data"][0]
