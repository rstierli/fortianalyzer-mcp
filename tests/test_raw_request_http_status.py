"""The raw request path reads the HTTP status before the body (#187 A4).

A reply that is not a 2xx used to be parsed like any other. A gateway's 429
or 502 with a JSON body holds neither ``error`` nor ``result``, so it came
back as the documented empty success and the tools answered ``status:
success`` with no rows.
"""

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

import fortianalyzer_mcp.tools.event_tools as event_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.utils.errors import APIError

WINDOW = {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}


class _Reply:
    """What ``requests`` hands back: a status, the text, and ``json()``."""

    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self) -> Any:
        return json.loads(self.text)


def _answer_with(fmg: MagicMock, status_code: int, body: Any) -> None:
    fmg.sess = MagicMock()
    fmg.sess.post.return_value = _Reply(status_code, body)


class TestRawRequestHttpStatus:
    async def test_a_429_with_a_json_body_is_an_error(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _answer_with(mock_fmg_instance, 429, {"message": "Too Many Requests"})

        with pytest.raises(APIError, match="429"):
            await mock_client.get_alerts(adom="root", time_range=WINDOW)

    @pytest.mark.parametrize("status_code", [400, 404, 429, 500, 502, 503, 504])
    async def test_a_gateway_reply_shaped_like_json_rpc_is_an_error(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock, status_code: int
    ) -> None:
        """The body alone reads as the documented empty reply."""
        _answer_with(mock_fmg_instance, status_code, {"jsonrpc": "2.0", "id": 1})

        with pytest.raises(APIError, match=str(status_code)):
            await mock_client.get_incidents(adom="root", time_range=WINDOW)

    async def test_the_error_names_the_call_and_not_the_body(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _answer_with(mock_fmg_instance, 502, "<html>upstream said: s3cret-detail</html>")

        with pytest.raises(APIError) as caught:
            await mock_client.get_alerts(adom="root", time_range=WINDOW)

        message = str(caught.value)
        assert "GET /eventmgmt/adom/root/alerts" in message
        assert "s3cret-detail" not in message

    async def test_the_request_is_not_sent_again(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Not a session error and not a transient one: one POST, no re-login."""
        _answer_with(mock_fmg_instance, 502, {"jsonrpc": "2.0", "id": 1})

        with pytest.raises(APIError):
            await mock_client.get_alerts(adom="root", time_range=WINDOW)

        assert mock_fmg_instance.sess.post.call_count == 1
        assert mock_fmg_instance.login.call_count == 0

    async def test_a_200_reply_without_result_is_still_empty_data(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """The documented case stays: no running report answers with no result."""
        _answer_with(mock_fmg_instance, 200, {"jsonrpc": "2.0", "id": 1})

        result = await mock_client._raw_request("get", "/report/adom/root/run")

        assert result == {"data": []}

    async def test_a_200_reply_with_a_json_rpc_error_keeps_its_code(
        self, mock_client: FortiAnalyzerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _answer_with(
            mock_fmg_instance,
            200,
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "Invalid params"}},
        )

        with pytest.raises(APIError) as caught:
            await mock_client.get_alerts(adom="root", time_range=WINDOW)

        assert caught.value.code == -32602


class TestToolsOnAGatewayReply:
    async def test_get_alerts_answers_an_error_not_zero_rows(
        self,
        mock_client: FortiAnalyzerClient,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _answer_with(mock_fmg_instance, 429, {"message": "Too Many Requests"})
        monkeypatch.setattr(event_tools, "_get_client", lambda: mock_client)

        result = await event_tools.get_alerts(time_range="1-hour")

        assert result["status"] == "error"
        assert "data" not in result
