"""A login FortiAnalyzer rejects is an authentication error (#204, item 15).

With a user name and password, pyFMG drops FortiAnalyzer's reply to the login
(-22 "Login fail") and goes on to read the workspace mode. Without a session
that read raises pyFMG's "no valid session" exception, and ``connect()``
wrapped it as a connection error whose text was the path of that read and
pyFMG's parameter dump. After a login that did open a session, a gateway page
in answer to that read dropped the client with the new session still open on
FortiAnalyzer, once per tool call (item 16). The same rule as
fortimanager-mcp#141, whose codes were measured on FortiManager 8.0.2.
"""

from typing import Any

import pytest

from fortianalyzer_mcp.tools import event_tools, system_tools
from fortianalyzer_mcp.utils.errors import AuthenticationError, ConnectionError
from tests.appliance_wire import AUTH, BAD_GATEWAY, Wire, new_client

BOTH = pytest.mark.parametrize("auth", list(AUTH))
#: What pyFMG's exception put into the error text.
PYFMG_DUMP = ("/cli/global/system/global", "valid session", "Paramaters", "workspace-mode")
SECRETS = ("password-for-tests", "token-for-tests")

#: The codes with which FortiAnalyzer is taken to refuse a login, its message
#: for each, and what the error and a tool say.
REFUSED_LOGINS = {
    -22: ("Login fail", "FortiAnalyzer login failed: Login fail"),
    -11: (
        "No permission for the resource",
        "FortiAnalyzer login failed: No permission for the resource",
    ),
    -23: ("Reach login limit", "FortiAnalyzer login failed: Reach login limit"),
}
REFUSALS = pytest.mark.parametrize("code", list(REFUSED_LOGINS))


def reject(wire: Wire, auth: str) -> None:
    """Make FortiAnalyzer reject the credentials of ``auth``."""
    if auth == "session":
        wire.login = (-22, "Login fail")
    else:
        wire.answers["/sys/status"] = (-11, "No permission for the resource", None)


def attempts(wire: Wire, auth: str) -> int:
    """Requests that presented the credentials."""
    return wire.logins() if auth == "session" else wire.calls.count(("get", "/sys/status"))


@REFUSALS
async def test_a_refusing_code_at_the_login_is_an_authentication_error(
    wire: Wire, code: int
) -> None:
    said, text = REFUSED_LOGINS[code]
    wire.login = (code, said)
    client = new_client("session")
    with pytest.raises(AuthenticationError) as refused:
        await client.connect()
    assert str(refused.value) == text
    assert refused.value.code == code
    assert not client.is_connected
    assert wire.logins() == 1


@REFUSALS
async def test_a_tool_reports_it_in_fortianalyzers_words(
    wire: Wire, code: int, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    said, text = REFUSED_LOGINS[code]
    wire.login = (code, said)
    client = new_client("session")
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    result = await system_tools.get_system_status()
    assert result == {"status": "error", "message": text}
    assert not any(secret in caplog.text for secret in SECRETS)


async def test_a_refused_token_is_one_as_before(
    wire: Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A control: the token check already failed closed."""
    reject(wire, "token")
    client = new_client("token")
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    result = await system_tools.get_system_status()
    assert result == {
        "status": "error",
        "message": "FortiAnalyzer token verification failed: No permission for the resource",
    }


async def test_another_code_at_the_login_is_a_connection_error(
    wire: Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its internal error in answer to a login says nothing about the
    credentials, and the next call logs in."""
    wire.login = (-1, "Internal error")
    client = new_client("session")
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    result = await system_tools.get_system_status()
    assert result == {
        "status": "error",
        "message": "Failed to connect to FortiAnalyzer: "
        "FortiAnalyzer login failed with code -1: Internal error",
    }
    assert wire.logins() == 1

    wire.login = (0, "OK")
    result = await system_tools.get_system_status()
    assert result["status"] == "success", result
    assert wire.logins() == 2
    assert client.is_reachable


@REFUSALS
async def test_each_later_call_logs_in_again(
    wire: Wire, code: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A control, not a fix: an authentication error does not stop the next
    tool call from logging in. ensure_connected shares a failed attempt only
    with the calls that waited for it, and the next call makes its own."""
    wire.login = (code, REFUSED_LOGINS[code][0])
    client = new_client("session")
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    for number in range(1, 6):
        await system_tools.get_system_status()
        assert wire.logins() == number


@BOTH
async def test_a_tool_with_a_time_window_presents_the_credentials_once_per_call(
    wire: Wire, auth: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The time zone lookup in front of the request stops on a rejected
    login as on a refused connection: going on, the request itself would
    log in a second time in the same call."""
    reject(wire, auth)
    client = new_client(auth)
    monkeypatch.setattr(event_tools, "get_faz_client", lambda: client)
    for number in range(1, 4):
        result = await event_tools.get_alerts(time_range="1-hour")
        assert result["status"] == "error", result
        assert attempts(wire, auth) == number


#: A status message as an appliance could send it, and what is quoted of it.
#: Not hex: a tool's message masks a long hex run.
NOISY = "Internal error\r\n\x1b[31m" + "Z" * 1000
QUOTED = "Internal error[31m" + "Z" * 182 + "..."


@BOTH
async def test_the_status_text_in_a_tool_error_and_the_log_is_bounded(
    wire: Wire, auth: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """No control characters and no more than 200 characters of it reach
    the caller and the log."""
    if auth == "session":
        wire.login = (-1, NOISY)
        expected = (
            f"Failed to connect to FortiAnalyzer: FortiAnalyzer login failed with code -1: {QUOTED}"
        )
    else:
        wire.answers["/sys/status"] = (-1, NOISY, None)
        expected = f"FortiAnalyzer token verification failed: {QUOTED}"
    client = new_client(auth)
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    result = await system_tools.get_system_status()
    assert result == {"status": "error", "message": expected}
    assert "Z" * 183 not in caplog.text
    assert "\x1b" not in caplog.text


@BOTH
async def test_a_rejection_quotes_a_bounded_status_text(wire: Wire, auth: str) -> None:
    if auth == "session":
        wire.login = (-22, NOISY)
        expected = f"FortiAnalyzer login failed: {QUOTED}"
    else:
        wire.answers["/sys/status"] = (-11, NOISY, None)
        expected = f"FortiAnalyzer token verification failed: {QUOTED}"
    with pytest.raises(AuthenticationError) as refused:
        await new_client(auth).connect()
    assert str(refused.value) == expected


async def test_a_login_answered_without_a_session_is_a_connection_error(wire: Wire) -> None:
    """The reply holds no code that refuses the administrator, so nothing
    says the credentials are wrong."""
    wire.opens_session = False
    with pytest.raises(ConnectionError) as refused:
        await new_client("session").connect()
    assert not isinstance(refused.value, AuthenticationError)
    assert str(refused.value) == (
        "Failed to connect to FortiAnalyzer: the login was answered without a session"
    )


async def test_a_page_at_login_is_named_for_what_it_is_not(
    wire: Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A proxy serves such a page, and so may FortiAnalyzer's own web server
    while its JSON-RPC backend restarts: the text holds for both."""
    wire.page = BAD_GATEWAY
    client = new_client("session")
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    result = await system_tools.get_system_status()
    assert result == {
        "status": "error",
        "message": "Failed to connect to FortiAnalyzer: the reply to the login was not "
        "FortiAnalyzer's JSON-RPC answer (its body is not JSON)",
    }


@BOTH
async def test_a_refused_connection_is_not_an_authentication_error(wire: Wire, auth: str) -> None:
    wire.refuses = True
    with pytest.raises(ConnectionError) as refused:
        await new_client(auth).connect()
    assert not isinstance(refused.value, AuthenticationError)


@BOTH
async def test_an_accepted_login_connects(wire: Wire, auth: str) -> None:
    client = new_client(auth)
    await client.connect()
    assert client.is_connected
    assert attempts(wire, auth) == 1


async def test_a_session_login_is_one_request(wire: Wire) -> None:
    """pyFMG's read of the workspace mode after the login is switched off, as
    it already was with an API token: it serves lock helpers of pyFMG that the
    client does not use, and it is what raised after a rejected login."""
    await new_client("session").connect()
    assert wire.calls == [("exec", "sys/login/user")]


async def test_a_gateway_page_after_the_login_leaves_no_session_behind(
    wire: Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item 16. The page answered pyFMG's workspace read, which raised
    "'Response' object is not subscriptable", and the client was dropped with
    its new session open, once per call. Without that read the login is the
    whole connect: the client keeps its one session, and each call fails on
    its own request."""
    wire.page_after_login = BAD_GATEWAY
    client = new_client("session")
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    results: list[dict[str, Any]] = [await system_tools.get_system_status() for _ in range(5)]
    assert all(result["status"] == "error" for result in results)
    assert not any("not subscriptable" in result["message"] for result in results)
    assert wire.logins() == 1
    assert len(wire.live) == 1
    assert client.is_connected


async def test_a_re_login_refused_after_minus_11_is_an_authentication_error(
    wire: Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On -11 the client ends its session and logs in once more (#187 D21).
    When FortiAnalyzer refuses that login, the call says so in its words."""
    client = new_client("session")
    await client.connect()
    wire.answers["/sys/status"] = (-11, "No permission for the resource", None)
    wire.login = (-11, "No permission for the resource")
    monkeypatch.setattr(system_tools, "get_faz_client", lambda: client)
    result = await system_tools.get_system_status()
    assert result == {
        "status": "error",
        "message": "FortiAnalyzer login failed: No permission for the resource",
    }
    assert wire.logins() == 2
    assert wire.live == set()
