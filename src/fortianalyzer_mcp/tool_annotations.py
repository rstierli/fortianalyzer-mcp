"""MCP tool annotation categories (spec ``ToolAnnotations``).

Every registered tool declares one of the constants below via
``@mcp.tool(annotations=...)``. Annotations are advertisement only -- they
change nothing about how a tool runs, they tell a client what a call is
going to do so it can decide what to auto-approve, what to confirm and
what to surface. A wrong hint is therefore a safety bug, not a cosmetic
one, and ``tests/test_tool_annotations.py`` freezes the classification.

Why this module sits at package top level and not under ``tools/``:
``register_dynamic_tools`` in ``server.py`` needs these constants, and
importing anything under ``fortianalyzer_mcp.tools`` executes
``tools/__init__.py``, which imports all twelve tool modules and thereby
registers all 85 raw tools. In dynamic mode that would silently replace
the three-tool discovery surface with the full one. This module imports
nothing from the package, so ``server.py``, ``tools/*`` and ``skills/*``
can all reach it with no side effect and no cycle.

All four hint fields are set explicitly on every category, including the
two the spec calls meaningful "only when ``readOnlyHint`` is false".
``destructiveHint`` **defaults to true** on the wire, so omitting it on a
reader means a client that reads that field without first checking
``readOnlyHint`` sees "may perform destructive updates" on
``get_system_status``. Explicit ``False`` costs one line and can only
narrow what a client believes a reader might do.

Where the read-only line falls (the decision a reader is most likely to
want to re-litigate; recorded in ``docs/adr/0003-mcp-tool-annotations.md``):
a tool is read-only when it does not change FortiAnalyzer's stored state.
Two consequences worth stating outright:

- **Transient task handles do not count.** ``query_logs``, ``run_report``
  and ``run_fortiview`` create a server-side TID on the appliance, and are
  still ``READ_ONLY``. The alternative makes routine log searching prompt
  for confirmation in clients that gate on the hint, which would gut the
  server for the read-only analyst workflow it exists to serve.
- **Writing a local file does not count.** ``save_report`` and the PCAP
  downloaders drop files in ``~/Downloads``; they are ``READ_ONLY``
  because the appliance is untouched. This is the weaker half of the
  decision -- a client cannot tell from the hints that a PDF appeared on
  disk -- and it is deliberate rather than overlooked.
"""

from mcp.types import ToolAnnotations

#: Reads FortiAnalyzer and changes nothing on it. The default for this
#: server: 70 of 87 tools, every ``get_*``/``list_*``/``search_*``/
#: ``fetch_*``, the TID-creating queries, the local-file writers and the
#: ``faz_skill`` dispatcher (whose skills are all readers by contract).
READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

#: Reads nothing outside this process. Only the dynamic-mode discovery
#: tools, which answer from an in-process catalogue and never reach the
#: network -- hence ``openWorldHint=False``, the one place in this server
#: where that field is not true.
READ_ONLY_LOCAL = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

#: Adds new state to FortiAnalyzer. Additive, so not destructive; a
#: repeat call adds again (a second device, a second comment, a second
#: rescan job), so not idempotent.
CREATES = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

#: Flips a reversible flag on existing FortiAnalyzer state. Not
#: destructive because nothing is lost -- each of these has a twin that
#: undoes it -- and idempotent because acknowledging an acknowledged
#: alert is a no-op.
UPDATES = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

#: Removes FortiAnalyzer state, or replaces it with no recovery path.
#: Deletes obviously; also the value-replacing updates, because the prior
#: value is unrecoverable afterwards, which is what "destructive update"
#: means in the spec as opposed to "additive only".
DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=True,
)

#: Dispatches to an arbitrary tool chosen by name at call time, so its
#: hints must be the union of everything it can reach -- and it can reach
#: ``delete_device``. ``execute_advanced_tool`` alone. Inheriting
#: ``READ_ONLY`` here would be the single most misleading annotation in
#: the server: one tool that advertises "changes nothing" while exposing
#: every mutating operation behind a string argument.
UNCONSTRAINED = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

#: Every approved category, by name. The annotation contract test asserts
#: each registered tool's annotations equal one of these, so a new tool
#: cannot introduce an unreviewed hint combination by hand.
CATEGORIES: dict[str, ToolAnnotations] = {
    "READ_ONLY": READ_ONLY,
    "READ_ONLY_LOCAL": READ_ONLY_LOCAL,
    "CREATES": CREATES,
    "UPDATES": UPDATES,
    "DESTRUCTIVE": DESTRUCTIVE,
    "UNCONSTRAINED": UNCONSTRAINED,
}

__all__ = [
    "CATEGORIES",
    "CREATES",
    "DESTRUCTIVE",
    "READ_ONLY",
    "READ_ONLY_LOCAL",
    "UNCONSTRAINED",
    "UPDATES",
]
