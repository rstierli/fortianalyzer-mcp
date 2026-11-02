"""The server exits promptly when it is stopped, even after FortiAnalyzer went away.

Shutdown disconnects the client, and that used to send ``sys/logout`` on the
full ``FORTIANALYZER_TIMEOUT``. A FortiAnalyzer that stopped answering after
the server connected therefore held every stop for that long: SIGTERM in
HTTP mode, stdin closing in stdio mode. With an API token the logout had
nothing to end in the first place. In stdio mode, ``asyncio.run()`` also
waited for a request still in flight when stdin closed, such as a login.

The servers run as subprocesses against an HTTPS stub on 127.0.0.1 that
answers like FortiAnalyzer until it is told to go silent. From then on it
reads requests on open connections without answering and never completes a
TLS handshake on new ones, which is what an appliance behind a stateful
firewall looks like once it has gone away. All credentials are dummies.
"""

import datetime
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient

REPO_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
# FORTIANALYZER_TIMEOUT for the server under test. Before the fix every stop
# below took this long.
REQUEST_TIMEOUT = 20
# A healthy exit takes well under a second; the margin absorbs a slow CI host.
EXIT_BUDGET = 5.0
CONNECTED = "FortiAnalyzer connection established"


def _self_signed_cert(directory: Path) -> tuple[str, str]:
    """A throwaway certificate for the stub, made at test time."""
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "faz-stub")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "stub.crt", directory / "stub.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


class FazStub:
    """FortiAnalyzer JSON-RPC over HTTPS on 127.0.0.1, until told to go silent."""

    def __init__(self, cert: str, key: str) -> None:
        self.silent = threading.Event()
        self.answered: list[str] = []  # "<method> <url>" of each answered request
        self.held = 0  # connections accepted while silent
        self._release = threading.Event()
        self._held_sockets: list[socket.socket] = []
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if stub.silent.is_set():
                    # Read it, never answer it.
                    stub._release.wait()
                    self.close_connection = True
                    return
                request = json.loads(body or b"{}")
                url = (request.get("params") or [{}])[0].get("url")
                stub.answered.append(f"{request.get('method')} {url}")
                result: dict[str, Any] = {"status": {"code": 0, "message": "OK"}, "url": url}
                if url == "/sys/status":
                    result["data"] = {"Hostname": "faz-stub", "Version": "v7.6.5-build3653"}
                elif url == "/cli/global/system/global":
                    result["data"] = {"workspace-mode": 0, "adom-status": 1}
                reply: dict[str, Any] = {"id": request.get("id"), "result": [result]}
                if url == "sys/login/user":
                    reply["session"] = "stub-session"
                payload = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self) -> tuple[Any, Any]:
                sock, addr = self.socket.accept()
                if stub.silent.is_set():
                    # Accept the TCP connection, never complete TLS.
                    stub._held_sockets.append(sock)
                    stub.held += 1
                    raise OSError("silent")
                return tls.wrap_socket(sock, server_side=True), addr

            def handle_error(self, request: Any, client_address: Any) -> None:
                pass

        self._server = Server(("127.0.0.1", 0), Handler)
        self.host = f"127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._release.set()
        self._server.shutdown()
        self._server.server_close()
        for sock in self._held_sockets:
            sock.close()


@pytest.fixture
def faz_stub(tmp_path: Path) -> Iterator[FazStub]:
    stub = FazStub(*_self_signed_cert(tmp_path))
    try:
        yield stub
    finally:
        stub.close()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


class McpServer:
    """``python -m fortianalyzer_mcp`` with dummy credentials against ``host``."""

    def __init__(self, mode: str, host: str, *, token: bool) -> None:
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("FORTIANALYZER_", "MCP_", "FAZ_"))
        }
        env.update(
            PYTHONPATH=REPO_SRC,
            MCP_SERVER_MODE=mode,
            MCP_SERVER_HOST="127.0.0.1",
            MCP_SERVER_PORT=str(_free_port()),
            MCP_AUTH_TOKEN="dummy-mcp-auth",
            LOG_LEVEL="INFO",
            FORTIANALYZER_HOST=host,
            FORTIANALYZER_VERIFY_SSL="false",
            FORTIANALYZER_CA_BUNDLE="",
            FORTIANALYZER_TIMEOUT=str(REQUEST_TIMEOUT),
            MASKING_ENABLED="false",
        )
        if token:
            env.update(
                FORTIANALYZER_API_TOKEN="dummy-api-token",
                FORTIANALYZER_USERNAME="",
                FORTIANALYZER_PASSWORD="",
            )
        else:
            env.update(
                FORTIANALYZER_API_TOKEN="",
                FORTIANALYZER_USERNAME="dummy-user",
                FORTIANALYZER_PASSWORD="dummy-password",
            )
        stdio = mode == "stdio"
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "fortianalyzer_mcp"],
            env=env,
            stdin=subprocess.PIPE if stdio else subprocess.DEVNULL,
            stdout=subprocess.PIPE if stdio else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.log: list[str] = []
        threading.Thread(target=self._drain_log, daemon=True).start()
        if stdio:
            self._initialize()

    def _drain_log(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self.log.append(line.decode(errors="replace"))

    def _initialize(self) -> None:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "shutdown-test", "version": "0"},
            },
        }
        self.proc.stdin.write(json.dumps(request).encode() + b"\n")
        self.proc.stdin.flush()
        assert self.proc.stdout.readline(), "no reply to initialize"
        stdout = self.proc.stdout
        threading.Thread(target=lambda: stdout.read(), daemon=True).start()

    def wait_until(self, condition: Callable[[], bool], what: str) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert self.proc.poll() is None, f"server exited early:\n{''.join(self.log)}"
            if condition():
                return
            time.sleep(0.1)
        raise AssertionError(f"timed out waiting for {what}:\n{''.join(self.log)}")

    def wait_connected(self) -> None:
        self.wait_until(lambda: any(CONNECTED in line for line in self.log), "the connect")

    def stop(self) -> float:
        """SIGTERM (HTTP) or close stdin (stdio); return seconds until exit."""
        started = time.monotonic()
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        else:
            self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=REQUEST_TIMEOUT + 15)
        except subprocess.TimeoutExpired:
            pass
        return time.monotonic() - started

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


@pytest.fixture
def start_server() -> Iterator[Callable[..., McpServer]]:
    servers: list[McpServer] = []

    def start(mode: str, host: str, *, token: bool) -> McpServer:
        server = McpServer(mode, host, token=token)
        servers.append(server)
        return server

    try:
        yield start
    finally:
        for server in servers:
            server.kill()


@pytest.mark.parametrize("mode", ["http", "stdio"])
def test_token_mode_exits_promptly_after_fortianalyzer_went_away(
    faz_stub: FazStub, start_server: Callable[..., McpServer], mode: str
) -> None:
    """The token logout ended nothing and waited out the whole timeout."""
    server = start_server(mode, faz_stub.host, token=True)
    server.wait_connected()
    faz_stub.silent.set()

    elapsed = server.stop()

    assert elapsed < EXIT_BUDGET, f"{mode} exit took {elapsed:.1f}s"
    assert not any("sys/logout" in a for a in faz_stub.answered)


@pytest.mark.parametrize("mode", ["http", "stdio"])
def test_session_logout_is_capped_after_fortianalyzer_went_away(
    faz_stub: FazStub, start_server: Callable[..., McpServer], mode: str
) -> None:
    """Username/password auth still logs out, on a timeout capped well
    below FORTIANALYZER_TIMEOUT."""
    server = start_server(mode, faz_stub.host, token=False)
    server.wait_connected()
    faz_stub.silent.set()

    elapsed = server.stop()

    budget = FortiAnalyzerClient._LOGOUT_TIMEOUT + EXIT_BUDGET
    assert elapsed < budget, f"{mode} exit took {elapsed:.1f}s"


def test_stdio_exits_promptly_with_a_login_in_flight(
    faz_stub: FazStub, start_server: Callable[..., McpServer]
) -> None:
    """stdin closing while the startup login still waits on FortiAnalyzer:
    asyncio.run() used to join that worker thread before exiting."""
    faz_stub.silent.set()
    server = start_server("stdio", faz_stub.host, token=False)
    server.wait_until(lambda: faz_stub.held > 0, "the login to reach the stub")

    elapsed = server.stop()

    assert elapsed < EXIT_BUDGET, f"exit took {elapsed:.1f}s"
