# Annotate every MCP tool, and draw the read-only line at FortiAnalyzer state

**Status:** accepted

## Context

Every tool was declared with a bare `@mcp.tool()`, so all 89 declaration sites — the 86 registered in
full mode (85 raw tools plus the `faz_skill` dispatcher) and the 3 dynamic-mode discovery tools —
shipped without `ToolAnnotations`. (Counts as of 2.11.0; the 2.12.0 consolidation took the raw tool
surface to 73, so the equivalent figures are 77 / 74. The decision below is unaffected — it is about
what every declaration site carries, not how many there are.) On the wire that is not neutral. The MCP spec's defaults are `readOnlyHint=false`,
`destructiveHint=true`, `idempotentHint=false` — so an unannotated `get_system_status` advertises
*"may modify its environment, possibly destructively, and is not safe to repeat"*. A client that gates
auto-approval on those hints has no way to distinguish a status read from `delete_device`, and the
useful behaviour (approve readers freely, confirm writers) collapses into confirming everything or
confirming nothing.

The tools split unevenly: 74 are pure readers, 14 change FortiAnalyzer state, and one
(`execute_advanced_tool`) dispatches to any tool by name. Two classes sit on the boundary and decide
what "read-only" means here:

- **Transient task handles.** `query_logs`, `run_report`, `run_fortiview` and the search wrappers
  create a server-side TID on the appliance before returning rows. They create state, but only a
  result set keyed to the caller's own request.
- **Local file writes.** `save_report` and the four PCAP downloaders decode what the appliance returns
  and write files into `~/Downloads`. The appliance is untouched; the operator's filesystem is not.

## Decision

Every tool declares one of six named categories from `fortianalyzer_mcp.tool_annotations`. All four
hint fields are set explicitly on all six, including the two the spec calls meaningful "only when
`readOnlyHint` is false" — because `destructiveHint` defaults to *true*, so omitting it on a reader
tells any client that reads that field without first checking `readOnlyHint` that
`get_system_status` may perform destructive updates. Explicit `False` costs one line and can only
narrow what a client believes.

| Category | readOnly | destructive | idempotent | openWorld | Applies to |
| --- | --- | --- | --- | --- | --- |
| `READ_ONLY` | ✓ | ✗ | ✓ | ✓ | 72 — every reader, the TID queries, the file writers, `faz_skill` |
| `READ_ONLY_LOCAL` | ✓ | ✗ | ✓ | ✗ | 2 — the dynamic-mode discovery tools |
| `CREATES` | ✗ | ✗ | ✗ | ✓ | 6 — `add_device(s_bulk)`, `create_incident`, `add_alert_comment`, `run(_and_wait)_ioc_rescan` |
| `UPDATES` | ✗ | ✗ | ✓ | ✓ | 3 — `(un)acknowledge_alerts`, `acknowledge_ioc_events` |
| `DESTRUCTIVE` | ✗ | ✓ | ✓ | ✓ | 5 — `delete_device(s_bulk)`, `update_incident`, `update_api_ratelimit`, `cancel_log_search` |
| `UNCONSTRAINED` | ✗ | ✓ | ✗ | ✓ | 1 — `execute_advanced_tool` |

**The read-only line is FortiAnalyzer's stored state.** A tool is read-only when a call leaves the
appliance's data as it found it. Both boundary classes above are therefore `READ_ONLY`: a TID is a
handle to the caller's own query, and a saved PDF is outside the appliance entirely.

Three further calls worth recording, because each is the kind a reviewer re-opens:

- **`DESTRUCTIVE` covers replacement, not only removal.** `update_incident`, `update_api_ratelimit`
  and `cancel_log_search` do not delete an object, but each overwrites a value or discards a result
  set with no recovery path. That is what the spec means by a destructive update as opposed to an
  additive one. `(un)acknowledge_alerts` by contrast is `UPDATES`: a reversible flag with a twin tool
  that undoes it.
- **`execute_advanced_tool` is annotated by reachability.** Its own body only looks up a name in a
  dict, but the dict contains `delete_device`. Its hints are the union of everything it can dispatch
  to. Letting it inherit `READ_ONLY` would be the single most misleading annotation in the server:
  one tool claiming to change nothing while exposing every mutating operation behind a string.
- **`openWorldHint=False` is confined to `find_fortianalyzer_tool` and
  `list_fortianalyzer_categories`,** the only tools that answer from an in-process catalogue and never
  open a socket.

`tool_annotations.py` sits at package top level rather than under `tools/`. Importing anything under
`fortianalyzer_mcp.tools` executes `tools/__init__.py`, which imports all twelve tool modules and
registers all 85 raw tools — so had the constants lived there, `register_dynamic_tools` importing them
would have silently replaced dynamic mode's three-tool surface with the full one. The module imports
nothing from the package, so `server.py`, `tools/*` and `skills/*` all reach it with no cycle and no
side effect.

## Consequences

Annotations are advertisement: no tool's behaviour changes, and the masking wrapper is unaffected
(`install_masking` patches `mcp.tool` with `*args, **kwargs` passthrough, verified with
`MASKING_ENABLED=true`).

A wrong hint is now a safety bug rather than a cosmetic one, so `tests/test_tool_annotations.py`
freezes the classification with four independent contracts: every tool is annotated with all four
fields set; every tool's hints are *identical to* an approved category, so nobody hand-rolls an
unreviewed combination; the set of non-read-only tool names equals an explicit list, which fails in
**both** directions — a reader becoming a writer, and the more dangerous reverse, a writer
mis-annotated `READ_ONLY`; and `openWorldHint=False` stays confined to the two local tools. Both
`FAZ_TOOL_MODE` surfaces are covered. Adding a mutating tool now requires updating
`EXPECTED_MUTATING` in the same commit — deliberately, since that edit is the review prompt.

The accepted cost is the local-file half of the read-only line: a client cannot tell from
`save_report`'s hints that a PDF landed on disk. Rejected alternatives, and why:

- **Counting local writes as non-read-only** surfaces the filesystem effect, but puts the report and
  PCAP retrieval tools behind confirmation prompts in gating clients, where they are the terminal step
  of ordinary read-only investigations.
- **Counting any server-side side effect as non-read-only** (every TID-creating tool) is the strictest
  reading, and would flip roughly 25 more tools — including `query_logs` and all `get_top_*`. Routine
  log searching would prompt for confirmation, gutting the read-only analyst workflow this server
  exists to serve.

If a client ever needs to distinguish "writes to my disk" from "writes to the appliance", that is a
`WRITES_LOCAL_FILE` category and a change to this ADR, not a reinterpretation of the existing hints.
