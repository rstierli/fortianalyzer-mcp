"""get_pcap_by_session names the devices a session id matched on (#187 item A12).

The session search runs over All_FortiGate unless a device is given, and
session ids are per device. When rows from two devices carried the same id,
the first row with a capture was used and the other device was not
mentioned. Now, when the matched rows come from more than one device, the
result carries ``devices`` (devid and devname of each, the one the result is
from first) and a warning in ``warnings``.

The device identity sits under the keys masking types as device identity, so
with FAZ_MASK_DEVICE_IDENTITY on it is masked like every other devid and
devname. The warning names no device.
"""

from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path
from typing import Any

import pytest

import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.pcap_tools as pcap_tools
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.wrapper import OutputMasker

KEY = "2DE79D232DF5585D68CE47882AE256D6"
CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"
SESSION = 906654

DEVICE_A = {"devid": "FGVM01TM00000001", "devname": "fw-a"}
DEVICE_B = {"devid": "FGVM01TM00000002", "devname": "fw-b"}

WARNING = (
    f"Session id {SESSION} matched rows from 2 devices, and session ids are per "
    "device. This result is from the first entry of 'devices'. Pass device= to "
    "choose another."
)


def _row(device: dict[str, str], pcapurl: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "sessionid": SESSION,
        "attack": "Example.Attack",
        "severity": "critical",
        "action": "dropped",
        "srcip": "192.0.2.10",
        "dstip": "198.51.100.20",
        **device,
    }
    if pcapurl:
        row["pcapurl"] = pcapurl
    return row


def _zip_b64() -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("capture.pcap", b"pcap")
    return base64.b64encode(buf.getvalue()).decode()


class FakeFaz:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    async def ensure_connected(self) -> None:
        return None

    async def logsearch_start(self, **_kw: Any) -> dict[str, int]:
        return {"tid": 901}

    async def logsearch_fetch(self, *, adom: str, tid: int, limit: int, offset: int) -> dict:
        page = self.rows[offset : offset + limit]
        return {"percentage": 100, "data": page, "total-count": len(self.rows)}

    async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, Any]:
        return {}

    async def get_pcapfile(self, *, key_data: str, key_type: str) -> dict[str, Any]:
        return {"data": _zip_b64()}


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setattr(log_tools, "_INITIAL_POLL_DELAY", 0)
    monkeypatch.setattr(log_tools, "POLL_INTERVAL", 0)
    monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))

    async def _run(rows: list[dict[str, Any]]) -> dict[str, Any]:
        monkeypatch.setattr(pcap_tools, "get_faz_client", lambda: FakeFaz(rows))
        return await pcap_tools.get_pcap_by_session(
            session_id=SESSION, adom="root", time_range=CUSTOM_RANGE, output_dir=str(tmp_path)
        )

    return _run


async def test_a_capture_with_the_id_on_another_device_names_both(run: Any) -> None:
    result = await run([_row(DEVICE_A), _row(DEVICE_B, pcapurl="u-b")])

    assert result["status"] == "success"
    assert result["devices"] == [DEVICE_B, DEVICE_A]
    assert result["warnings"] == [WARNING]


async def test_no_capture_on_two_devices_names_both(run: Any) -> None:
    result = await run([_row(DEVICE_A), _row(DEVICE_B)])

    assert result["status"] == "no_pcap"
    assert result["devices"] == [DEVICE_A, DEVICE_B]
    assert result["warnings"] == [WARNING]


async def test_rows_from_one_device_add_nothing(run: Any) -> None:
    result = await run([_row(DEVICE_A), _row(DEVICE_A, pcapurl="u-a")])

    assert result["status"] == "success"
    assert "devices" not in result
    assert "warnings" not in result


@pytest.mark.parametrize("flag", [True, False], ids=["identity masked", "identity clear"])
async def test_the_devices_mask_as_device_identity(
    run: Any, monkeypatch: pytest.MonkeyPatch, flag: bool
) -> None:
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    result = await run([_row(DEVICE_A), _row(DEVICE_B, pcapurl="u-b")])

    masked = OutputMasker(FPEEngine(KEY), mask_device_identity=flag).mask_tool_result(
        result, "get_pcap_by_session"
    )

    assert masked["status"] == "success"
    assert masked["warnings"] == [WARNING]
    text = repr(masked)
    for value in (*DEVICE_A.values(), *DEVICE_B.values()):
        assert (value in text) is not flag
