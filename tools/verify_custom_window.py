#!/usr/bin/env python3
"""Live verification for the report custom-window fix (schedule-config approach).

Live-lab helper; not part of the server. Usage (from the repo root, venv active):
    FAZ_HOST=<host_or_host:port> FAZ_USER=admin FAZ_PASS=... \
        python tools/verify_custom_window.py [--layout 10002] [--phase all]

Phases:
  format  - discover the exact period-start/period-end string FAZ accepts:
            reads schedule config, tries candidate timedate formats via
            update + read-back, prints the accepted format and the full
            stored period field set. Restores the schedule afterwards.
  e2e     - run_and_wait_report with a custom window through the repo's own
            tool code, download the HTML report, unzip, grep the dates.
            PASS = only the requested day appears; FAIL = default period.
  all     - both (default).

Run against both lab units (7.6.7 and 8.0.0).
"""

import argparse
import asyncio
import base64
import io
import json
import os
import re
import sys
import zipfile

FAZ_HOST = os.environ.get("FAZ_HOST", "")
FAZ_USER = os.environ.get("FAZ_USER", "admin")
FAZ_PASS = os.environ.get("FAZ_PASS", "")
ADOM = os.environ.get("FAZ_ADOM", "root")

if not FAZ_HOST or not FAZ_PASS:
    sys.exit("Set FAZ_HOST and FAZ_PASS (and optionally FAZ_USER/FAZ_ADOM)")

# The repo settings load at server import; point them at the lab unit.
os.environ["FORTIANALYZER_HOST"] = FAZ_HOST
os.environ["FORTIANALYZER_USERNAME"] = FAZ_USER
os.environ["FORTIANALYZER_PASSWORD"] = FAZ_PASS
os.environ["FORTIANALYZER_VERIFY_SSL"] = os.environ.get("FAZ_VERIFY_SSL", "false")
os.environ["DEFAULT_ADOM"] = ADOM

from fortianalyzer_mcp.api.client import FortiAnalyzerClient  # noqa: E402

# Requested window: full day of 2026-06-27 (FAZ-local).
WIN_START = "2026-06-27 00:00:00"
WIN_END = "2026-06-28 00:00:00"

# Candidate period-start/end encodings, most likely first.
FORMAT_CANDIDATES = [
    ("timedate time-first", "00:00 2026/06/27", "00:00 2026/06/28"),
    ("timedate time-first w/ seconds", "00:00:00 2026/06/27", "00:00:00 2026/06/28"),
    ("slash date-first minute", "2026/06/27 00:00", "2026/06/28 00:00"),
    ("dash date-first seconds", "2026-06-27 00:00:00", "2026-06-28 00:00:00"),
    ("dash date-first minute", "2026-06-27 00:00", "2026-06-28 00:00"),
]

PERIOD_FIELDS = (
    "time-period",
    "period-opt",
    "period-till-now",
    "period-last-n",
    "period-start",
    "period-end",
)


def schedule_obj(result):
    obj = result.get("data", result) if isinstance(result, dict) else result
    if isinstance(obj, list):
        obj = obj[0] if obj else {}
    return obj if isinstance(obj, dict) else {}


async def phase_format(client, layout_id):
    print(f"== format discovery on schedule {layout_id} ==")
    before = schedule_obj(await client.get_report_schedule(adom=ADOM, layout_id=layout_id))
    saved = {k: before.get(k) for k in PERIOD_FIELDS}
    print("current period fields:", json.dumps(saved, indent=2))

    winner = None
    for label, start, end in FORMAT_CANDIDATES:
        fields = {"time-period": 16, "period-opt": 1, "period-start": start, "period-end": end}
        try:
            await client.update_report_schedule(adom=ADOM, layout_id=layout_id, fields=fields)
        except Exception as e:
            print(f"  {label!r}: update REJECTED: {e}")
            continue
        stored = schedule_obj(await client.get_report_schedule(adom=ADOM, layout_id=layout_id))
        ps, pe = stored.get("period-start"), stored.get("period-end")
        tp = stored.get("time-period")
        print(f"  {label!r}: stored time-period={tp!r} period-start={ps!r} period-end={pe!r}")
        if ps and pe and str(tp) in ("16", "other"):
            winner = (label, start, ps, pe)
            print("  --> ACCEPTED. Full stored object period fields:")
            print(json.dumps({k: stored.get(k) for k in PERIOD_FIELDS}, indent=2))
            break

    # restore original period (never null dates back)
    restore = {
        "time-period": saved.get("time-period") if saved.get("time-period") is not None else 5
    }
    if saved.get("period-opt") is not None:
        restore["period-opt"] = saved["period-opt"]
    if saved.get("period-start") and saved.get("period-end"):
        restore["period-start"] = saved["period-start"]
        restore["period-end"] = saved["period-end"]
    await client.update_report_schedule(adom=ADOM, layout_id=layout_id, fields=restore)
    print("schedule restored:", restore)

    if not winner:
        print("NO candidate format accepted -- capture a GUI-saved 'Other' schedule and diff.")
        return False
    print(f"WINNER: {winner[0]} (sent {winner[1]!r} -> stored {winner[2]!r})")
    return True


async def phase_e2e(layout_id):
    print(f"== end-to-end custom-window report on layout {layout_id} ==")
    # Import tools (registers against the module-level server/settings).
    import fortianalyzer_mcp.server as server
    from fortianalyzer_mcp.tools import report_tools

    client = FortiAnalyzerClient.from_settings(server.settings)
    await client.connect()
    server.faz_client = client
    try:
        result = await report_tools.run_and_wait_report(
            layout=str(layout_id),
            time_range=f"{WIN_START}|{WIN_END}",
            timeout=600,
        )
        print("run_and_wait_report:", {k: result.get(k) for k in ("status", "tid", "message")})
        if result.get("status") != "success":
            print("FAIL: report did not complete")
            return False
        data = await report_tools.get_report_data(tid=result["tid"], output_format="HTML")
        payload = data.get("data") if isinstance(data, dict) else {}
        if isinstance(payload, dict):
            b64 = payload.get("data", "")
        else:
            b64 = payload or ""
        blob = base64.b64decode(b64)
        text = ""
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for name in zf.namelist():
                if name.lower().endswith((".html", ".htm")):
                    text += zf.read(name).decode("utf-8", errors="replace")
        dates = sorted(set(re.findall(r"2026[-/]\d{2}[-/]\d{2}", text)))
        print("dates found in report:", dates)
        target = {"2026-06-27", "2026/06/27"}
        wrong = [d for d in dates if d.replace("/", "-") not in ("2026-06-27", "2026-06-28")]
        if any(d in target for d in dates) and not any(
            d.replace("/", "-") in ("2026-06-25", "2026-06-26", "2026-06-30", "2026-07-01")
            for d in dates
        ):
            print("PASS: report covers the requested window")
            return True
        print(f"FAIL: unexpected dates (default period?): {wrong}")
        return False
    finally:
        await client.disconnect()


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--layout", type=int, default=10002)
    ap.add_argument("--phase", choices=["format", "e2e", "all"], default="all")
    args = ap.parse_args()

    ok = True
    if args.phase in ("format", "all"):
        client = FortiAnalyzerClient(
            host=FAZ_HOST, username=FAZ_USER, password=FAZ_PASS, verify_ssl=False
        )
        await client.connect()
        try:
            ok = await phase_format(client, args.layout) and ok
        finally:
            await client.disconnect()
    if args.phase in ("e2e", "all"):
        ok = await phase_e2e(args.layout) and ok
    sys.exit(0 if ok else 1)


asyncio.run(main())
