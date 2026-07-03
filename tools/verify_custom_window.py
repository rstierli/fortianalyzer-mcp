#!/usr/bin/env python3
"""Live verification for report custom time windows (lab helper, not the server).

Usage (repo root, venv active):
    FAZ_HOST=<host_or_host:port> FAZ_USER=admin FAZ_PASS=... \
        python tools/verify_custom_window.py [--layout 10002] [--phase all]

Phases:
  format - which period-start/period-end string the schedule config PARSES:
           tries candidates via update + read-back, prints the accepted format
           and the stored period field set, restores the schedule.
           (Known result: timedate "HH:MM yyyy/mm/dd" is accepted on
           7.6.7/8.0.0 — parsing is solved; consumption is not.)
  mech   - which RUN mechanism the report generator actually CONSUMES:
           A: schedule untouched; run time-period="other" + run-side dates in
              timedate format (the one form never tried on the run endpoint —
              all previously rejected run-side attempts were date-first).
           B: schedule window set + held; run WITHOUT any time-period key
              (a run-side "other" may override the schedule with an empty
              run-side window, which would explain the EMPTY report).
           C: schedule window set + held; run "other" + run-side timedate dates.
           D: control — schedule window set + held; run "other" with no dates
              (previously produced an EMPTY report; validates the harness).
           Each: submit, wait for completion, download HTML, grep dates,
           classify WINDOW / DEFAULT / EMPTY / OTHER, restore the schedule.
  e2e    - the repo's own run_and_wait_report with a custom range, then
           download + grep. This is the acceptance test for the shipped code.
  all    - format + mech + e2e.

Run against both lab units (7.6.7 and 8.0.0). If no mech hypothesis yields
WINDOW, capture the GUI flow: run a custom-period report in the FAZ GUI with
browser devtools open, record the exact JSON-RPC run payload and the stored
schedule fields — that is the deterministic answer.
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
WIN_START_TD = "00:00 2026/06/27"  # timedate form (accepted by the schedule object)
WIN_END_TD = "00:00 2026/06/28"
WIN_RANGE = "2026-06-27 00:00:00|2026-06-28 00:00:00"

# Days that only appear when the layout default (last-7-days) window was used.
DEFAULT_ONLY_DAYS = {"2026-06-25", "2026-06-26", "2026-06-29", "2026-06-30", "2026-07-01"}

# Candidate period-start/end encodings for the format phase, most likely first.
FORMAT_CANDIDATES = [
    ("timedate time-first", WIN_START_TD, WIN_END_TD),
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

WAIT_TIMEOUT = 600
POLL = 3.0


def schedule_obj(result):
    obj = result.get("data", result) if isinstance(result, dict) else result
    if isinstance(obj, list):
        obj = obj[0] if obj else {}
    return obj if isinstance(obj, dict) else {}


async def read_schedule(client, layout_id):
    return schedule_obj(await client.get_report_schedule(adom=ADOM, layout_id=layout_id))


async def set_window(client, layout_id):
    """Write the custom window to the schedule; returns saved fields for restore."""
    saved = {k: (await read_schedule(client, layout_id)).get(k) for k in PERIOD_FIELDS}
    fields = {
        "time-period": 16,
        "period-opt": saved.get("period-opt") if saved.get("period-opt") is not None else 1,
        "period-start": WIN_START_TD,
        "period-end": WIN_END_TD,
    }
    await client.update_report_schedule(adom=ADOM, layout_id=layout_id, fields=fields)
    stored = await read_schedule(client, layout_id)
    if not stored.get("period-start") or not stored.get("period-end"):
        raise RuntimeError(f"schedule did not store the window: {stored}")
    return saved


async def restore_schedule(client, layout_id, saved):
    fields = {
        "time-period": saved.get("time-period") if saved.get("time-period") is not None else 5
    }
    if saved.get("period-opt") is not None:
        fields["period-opt"] = saved["period-opt"]
    if saved.get("period-start") and saved.get("period-end"):
        fields["period-start"] = saved["period-start"]
        fields["period-end"] = saved["period-end"]
    await client.update_report_schedule(adom=ADOM, layout_id=layout_id, fields=fields)


async def wait_generated(client, tid):
    loop = asyncio.get_running_loop()
    start = loop.time()
    while loop.time() - start < WAIT_TIMEOUT:
        running = await client.get_running_reports(adom=ADOM)
        data = running.get("data", []) if isinstance(running, dict) else []
        if not isinstance(data, list):
            data = [data] if data else []
        mine = next((r for r in data if r.get("tid") == tid), None)
        if mine is None:
            fetched = await client.report_fetch(adom=ADOM, tid=tid)
            state = fetched.get("state") if isinstance(fetched, dict) else None
            if state == "generated":
                return fetched
            if state not in ("pending", "running"):
                raise RuntimeError(f"report ended in state {state!r}")
        await asyncio.sleep(POLL)
    raise TimeoutError(f"report {tid} did not complete in {WAIT_TIMEOUT}s")


async def download_dates(client, tid):
    """Download the HTML report and return the set of yyyy-mm-dd dates in it."""
    result = await client.report_get_data(adom=ADOM, tid=tid, output_format="HTML")
    payload = result.get("data") if isinstance(result, dict) else None
    if isinstance(payload, dict):
        b64 = payload.get("data", "")
    elif isinstance(payload, str):
        b64 = payload
    else:
        b64 = ""
    blob = base64.b64decode(b64)
    text = ""
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for name in zf.namelist():
            if name.lower().endswith((".html", ".htm")):
                text += zf.read(name).decode("utf-8", errors="replace")
    return {d.replace("/", "-") for d in re.findall(r"2026[-/]\d{2}[-/]\d{2}", text)}


def classify(dates):
    if not dates:
        return "EMPTY"
    if dates & DEFAULT_ONLY_DAYS:
        return "DEFAULT"
    if "2026-06-27" in dates:
        return "WINDOW"
    return "OTHER"


async def run_hypothesis(client, layout_id, label, *, hold_schedule, run_time_period, run_dates):
    print(
        f"-- {label}: schedule_window={'HELD' if hold_schedule else 'no'} "
        f"run.time-period={run_time_period!r} run_dates={'timedate' if run_dates else 'no'}"
    )
    saved = None
    try:
        if hold_schedule:
            saved = await set_window(client, layout_id)
        kwargs = {}
        if run_dates:
            kwargs = {"period_start": WIN_START_TD, "period_end": WIN_END_TD}
        rr = await client.report_run(
            adom=ADOM, layout_id=layout_id, time_period=run_time_period, **kwargs
        )
        tid = rr.get("tid") if isinstance(rr, dict) else None
        if not tid:
            print(f"   no tid: {rr}")
            return None
        await wait_generated(client, tid)
        dates = await download_dates(client, tid)
        verdict = classify(dates)
        print(f"   tid={tid} verdict={verdict} dates={sorted(dates)}")
        return verdict
    except Exception as e:
        print(f"   FAILED: {e}")
        return None
    finally:
        if saved is not None:
            await restore_schedule(client, layout_id, saved)


async def phase_format(client, layout_id):
    print(f"== format discovery on schedule {layout_id} ==")
    saved = {k: (await read_schedule(client, layout_id)).get(k) for k in PERIOD_FIELDS}
    print("current period fields:", json.dumps(saved, indent=2))
    winner = None
    for label, start, end in FORMAT_CANDIDATES:
        fields = {"time-period": 16, "period-opt": 1, "period-start": start, "period-end": end}
        try:
            await client.update_report_schedule(adom=ADOM, layout_id=layout_id, fields=fields)
        except Exception as e:
            print(f"  {label!r}: update REJECTED: {e}")
            continue
        stored = await read_schedule(client, layout_id)
        ps, pe, tp = (
            stored.get("period-start"),
            stored.get("period-end"),
            stored.get("time-period"),
        )
        print(f"  {label!r}: stored time-period={tp!r} period-start={ps!r} period-end={pe!r}")
        if ps and pe and str(tp) in ("16", "other"):
            winner = label
            print("  --> ACCEPTED; full stored period fields:")
            print(json.dumps({k: stored.get(k) for k in PERIOD_FIELDS}, indent=2))
            break
    await restore_schedule(client, layout_id, saved)
    print("schedule restored")
    print(
        f"WINNER: {winner}" if winner else "NO candidate accepted -> capture a GUI-saved schedule"
    )
    return winner is not None


async def phase_mech(client, layout_id):
    print(f"== run-mechanism discovery on layout {layout_id} ==")
    results = {}
    results["A"] = await run_hypothesis(
        client,
        layout_id,
        "A run-side timedate dates",
        hold_schedule=False,
        run_time_period="other",
        run_dates=True,
    )
    results["B"] = await run_hypothesis(
        client,
        layout_id,
        "B schedule held, no run time-period",
        hold_schedule=True,
        run_time_period=None,
        run_dates=False,
    )
    results["C"] = await run_hypothesis(
        client,
        layout_id,
        "C schedule held + run-side dates",
        hold_schedule=True,
        run_time_period="other",
        run_dates=True,
    )
    results["D"] = await run_hypothesis(
        client,
        layout_id,
        "D control: schedule held, run 'other', no dates",
        hold_schedule=True,
        run_time_period="other",
        run_dates=False,
    )
    winners = [k for k, v in results.items() if v == "WINDOW"]
    print(f"mechanism results: {results} -> WINDOW via: {winners or 'NONE'}")
    if not winners:
        print(
            "No hypothesis produced the requested window. Capture the GUI flow:\n"
            "  1. FAZ GUI -> Reports -> run the layout with Time Period 'Other' + explicit\n"
            "     dates, with browser devtools (Network tab) open.\n"
            "  2. Record the exact JSON-RPC payload(s) the GUI sends (URL, method, every\n"
            "     param) and re-read the stored schedule fields afterwards.\n"
        )
    return bool(winners)


async def phase_e2e(layout_id):
    print(f"== e2e via the repo's run_and_wait_report on layout {layout_id} ==")
    import fortianalyzer_mcp.server as server
    from fortianalyzer_mcp.tools import report_tools

    client = FortiAnalyzerClient.from_settings(server.settings)
    await client.connect()
    server.faz_client = client
    try:
        result = await report_tools.run_and_wait_report(
            layout=str(layout_id), time_range=WIN_RANGE, timeout=WAIT_TIMEOUT
        )
        keys = ("status", "tid", "message", "requested_window", "report_period", "warning")
        print("run_and_wait_report:", {k: result.get(k) for k in keys if k in result})
        if result.get("status") != "success":
            print("FAIL: report did not complete")
            return False
        dates = await download_dates(client, result["tid"])
        verdict = classify(dates)
        print(f"verdict={verdict} dates={sorted(dates)}")
        print("PASS" if verdict == "WINDOW" else f"FAIL ({verdict})")
        return verdict == "WINDOW"
    finally:
        await client.disconnect()


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--layout", type=int, default=10002)
    ap.add_argument("--phase", choices=["format", "mech", "e2e", "all"], default="all")
    args = ap.parse_args()

    ok = True
    if args.phase in ("format", "mech", "all"):
        client = FortiAnalyzerClient(
            host=FAZ_HOST, username=FAZ_USER, password=FAZ_PASS, verify_ssl=False
        )
        await client.connect()
        try:
            if args.phase in ("format", "all"):
                ok = await phase_format(client, args.layout) and ok
            if args.phase in ("mech", "all"):
                ok = await phase_mech(client, args.layout) and ok
        finally:
            await client.disconnect()
    if args.phase in ("e2e", "all"):
        ok = await phase_e2e(args.layout) and ok
    sys.exit(0 if ok else 1)


asyncio.run(main())
