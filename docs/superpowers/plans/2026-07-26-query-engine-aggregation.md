# Query Engine, Plan 3 of 3: Honest Aggregation and Tool Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two aggregation entry points whose names say what they are — `group_by` resolves to a native appliance surface or refuses, `sample_by` carries today's bounded-sample honesty contract — and a catalogue that shrinks from **85 tools to 73** by folding thirteen single-purpose wrappers into the three parameterised tools that now subsume them.

> **The 83→71 in earlier drafts of this plan and in the spec is stale.** Measured at `627a138`: `mcp.list_tools()` returns **85**, and all thirteen removal targets are present. 85 − 13 + 1 (`analyze_policy_traffic`) = **73**. The spec's "Tool consolidation: 83 → 71" heading was written when the surface was 83. Verify the count yourself before Task 10 asserts it:
>
> ```bash
> FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run python -c "
> import asyncio, fortianalyzer_mcp.server as s
> print(len(asyncio.run(s.mcp.list_tools())), 'registered tools')
> "
> ```

**Architecture:** `query/groups.py` (pure) decides *what kind of answer a dimension can give*: a `GroupPlan` naming a native FortiView view or stats endpoint, or a refusal that names `sample_by` as the alternative. `query/derive.py` (pure) holds the computed dimensions — `port`, `icmp_type_code` — that would otherwise vanish with the tools being merged. `tools/` execute the plan and own the bounded scan machinery, which is reused unchanged.

**Tech Stack:** Python 3.12, Pydantic v2, `mcp` FastMCP, pytest + pytest-asyncio, ruff, mypy strict.

**Spec:** `docs/superpowers/specs/2026-07-25-query-engine-design.md` — the "`group_by` (native, exact) and `sample_by` (bounded, labelled)" and "Tool consolidation: 83 → 71" sections, plus the skills-layer and dynamic-mirror obligations under "Cross-layer obligations" and guard tests #2 and #4 under "Testing".

**Predecessors:** Plan 1 (`2026-07-25-query-engine-filters.md`, shipped as PR #94 — squashed to `ab60ad8` + `627a138`; the `749a9c7`..`c1cdffc` range earlier drafts named no longer exists) and Plan 2 (`2026-07-26-query-engine-projection.md`). This plan assumes `query/fields.py`, `query/filters.py` and `query/shape.py` exist as those plans left them, and that `query_logs` already takes `filters` and `fields`.

> **Before starting, verify the predecessor actually landed as planned.** Plan 2 was written before it was executed, so re-read `query/shape.py` and `query/fields.py` rather than trusting this plan's description of them. In particular: confirm `Vocabulary.projection` exists, confirm `resolve_projection` returns `tuple[frozenset[str] | None, list[str]]`, and confirm whether Plan 2's Task 5 helper is named `project_payload`. If any differ, adapt this plan's call sites and **report the deviation** rather than reshaping Plan 2's work to match this document.
>
> Plan 1 diverged from its own plan in one way that reaches this document: **`contains` compiles to `like "%v%"`, not to `contain`** — probed live, `contain` is accepted by both dialects and silently matches zero rows. Nothing here compiles a filter, but Task 7's equivalence tests assert on compiled filter *strings*, so they were written against the `like` reality. Do not "fix" them back to `contain`.

**Line numbers in this document were re-verified at `627a138`.** `traffic_tools` and `fortiview_tools` anchors were already correct; `log_tools`, `skills/handlers.py` and `server.py` had all moved and are corrected here. Treat every line number as a hint and locate by name.

## Global Constraints

- Python `>=3.12`. Target `py312`.
- **mypy strict**: `disallow_untyped_defs`, `disallow_incomplete_defs`, `warn_return_any`, `no_implicit_optional`. Every function needs annotations, including `-> None` on tests.
- **ruff** line-length 100, `E501` ignored. Selected rules: `E`, `W`, `F`, `I`, `B`, `C4`, `UP`. Note `B017`: never write `pytest.raises(Exception)` — name the concrete exception.
- Style: `isinstance(x, list | tuple)` (PEP 604 unions), `from __future__ import annotations` at the top of new modules.
- **`query/` must stay pure.** No imports from `fortianalyzer_mcp.tools`, `fortianalyzer_mcp.server`, or `fortianalyzer_mcp.api`. Importing from `fortianalyzer_mcp.utils` is fine.
- **Do not reorder** the tool-import block at the bottom of `server.py`. Task 9 edits `register_dynamic_tools`, which sits above that block — leave the block itself alone.
- **NO AI attribution in commit messages.** `.github/workflows/no-ai-attribution.yml` fails any PR whose commits match `Co-Authored-By: Claude|Anthropic`, `noreply@anthropic.com`, `Generated with Claude`, or `🤖 Generated with`.
- Commit subjects: conventional-commit with scope, e.g. `feat(query): resolve group_by to a native appliance surface`.
- **`CLAUDE.md` is gitignored** (`.gitignore:149`). Edit it locally if useful; it cannot be committed.
- **Test command** (`PYTHONPATH=src` is required on this machine):

  ```bash
  FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
  ```

- **Baseline: whatever Plan 2 ended at.** Record it before Task 1 and use that number, not a number copied from this document. Plan 2 started from **1545** (measured at `627a138`; earlier drafts said 1414 and CLAUDE.md still does — both stale) and adds roughly 60 tests of its own.
- The three CI gates, clean at every commit:

  ```bash
  uv run ruff check src/ tests/
  uv run ruff format --check src/ tests/
  PYTHONPATH=src uv run mypy src/
  ```

- **The masking-enabled suite has 10 pre-existing failures** (in `tests/test_ueba_tools.py` and `tests/test_soar_tools.py`) and is not gated in CI. Measured at `627a138`: `10 failed, 1535 passed`. Compare against that baseline, never against green:

  ```bash
  MASKING_ENABLED=true FAZ_MASKING_KEY=$(python3 -c "print('0'*64)") \
    FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
  ```

- Do not write a test whose assertion depends on masking being off. Values in IP-typed fields are rewritten by the arg unmasker; filter and group on ports, protocols or app names in tool-level tests.
- **This is a breaking change.** Minor version bump in `pyproject.toml`, the README badge and `CHANGELOG.md`, with a migration table mapping every removed call to its replacement. Task 10 owns that.

## The honesty contract this plan must not weaken

`group_by` and `sample_by` exist as two names rather than one because they make
different promises, and the whole point of the split is that a caller can tell
which they got:

- **`group_by` is exact or it is an error.** It dispatches to an appliance
  surface that counted every row. It never falls back to sampling — a top-N over
  a 1000-row sample reads as fact and gets quoted as fact.
- **`sample_by` is bounded and says so.** It carries today's metadata verbatim:
  `is_exact`, `analysis_mode`, `total_hits`, `total_hits_is_known`,
  `total_hit_source`, `observed_hits`, `slices_scanned`, `truncated_slices`,
  `log_limit_per_slice`, `recommendation`.

If a task tempts you to make `group_by` degrade gracefully into `sample_by`,
that is the one change this plan forbids. The refusal must name `sample_by`
instead.

## File Structure

| File | Responsibility |
| --- | --- |
| `src/fortianalyzer_mcp/query/derive.py` | **Create.** Computed dimensions: `port` (`"{proto}/{dstport}"`) and `icmp_type_code`. Pure. |
| `src/fortianalyzer_mcp/query/groups.py` | **Create.** `GroupPlan`, the native-dimension map, `resolve_group_plan`, and the in-process `aggregate_breakdowns`. Pure. |
| `src/fortianalyzer_mcp/query/__init__.py` | **Modify.** Re-export the new surface. |
| `src/fortianalyzer_mcp/tools/log_tools.py` | **Modify.** `query_logs` gains `group_by`, `sample_by`, `count_only`. Delete `search_traffic_logs`, `search_security_logs`, `search_event_logs`. |
| `src/fortianalyzer_mcp/tools/traffic_tools.py` | **Modify.** Add `analyze_policy_traffic`; delete the three `get_policy_*` tools and the three `_aggregate_*` helpers they own. |
| `src/fortianalyzer_mcp/tools/fortiview_tools.py` | **Modify.** Delete the six `get_top_*` tools and `get_policy_hits`. |
| `src/fortianalyzer_mcp/skills/handlers.py` | **Modify.** Six call sites move to `get_fortiview_data`. |
| `src/fortianalyzer_mcp/server.py` | **Modify.** One derived catalogue replaces `tool_catalog` + `tool_map` + the hardcoded `total_tools`. |
| `src/fortianalyzer_mcp/tools/__init__.py` | **Probably untouched.** It imports the ten tool *modules*, not tool functions — deleting a tool from a module needs no change here. Verify before assuming.  |
| `src/fortianalyzer_mcp/instructions.py` | **Modify.** Aggregation surface + consolidated names. |
| `tests/test_query_derive.py` | New. Derived dimensions including the SD-WAN probe case. |
| `tests/test_query_groups.py` | New. Dimension → plan mapping, refusals, bounded aggregation. |
| `tests/test_tool_catalogue_parity.py` | New. The catalogue equals the registered tool set. |
| `tests/test_removed_tools.py` | New. Removed names are gone and their replacements answer. |
| `docs/probes/2026-07-fortiview-surface.md` | New (Task 0). The measured view catalogue, sort columns and filter-acceptance matrix that Tasks 2 and 4 encode. |

---

### Task 0: Probe the live FortiView surface

**Files:**
- Create: `docs/probes/2026-07-fortiview-surface.md`

**Interfaces:**
- Consumes: a live FortiAnalyzer. No repo code changes.
- Produces: three measured tables that Task 2's `LOG_GROUP_SURFACES` and Task 4's filter forwarding read from — the served-view list, the per-view sort columns, and the filter-acceptance matrix.

**Why this is Task 0 and not a follow-up.** `group_by` promises exactness, and Task 4
forwards the caller's compiled filter to a FortiView view. If that view does not
know the field, the appliance does not error — the same inertness that made
`contain` match zero rows means an unknown filter field can yield an **unfiltered
top-N returned under `is_exact: true`**. That is the worst failure this plan can
ship: not a wrong-looking answer, but a confident one about the wrong population.
Spec verification items 2, 3 and 4 all bear on it, and none can be closed by
reading documentation.

**How to probe** (the method that produced the operator truth table on PR #94):
`.mcp.json` defines a `fortianalyzer-dev` MCP server running this working copy
over stdio against the lab appliance, masking and skills OFF. Two gotchas, learned
the hard way and still true:

- **The MCP server process is spawned at session start**, so it runs the code as
  it was on disk *then*. Editing source does not change what the live tools
  execute — restart the session, or exercise the new path in-process with
  `uv run python`.
- **A past-hour window still drifts.** Re-running the same query minutes later
  moved counts by a few hundred rows (late-arriving logs). Arithmetic across
  queries only holds *within one burst*; say so when quoting a sum as proof.

**The lab's shape constrains what a null result can mean.** The appliance carries
one FortiGate and has had no attack/IPS logs for days. So an empty `top-threats`
is ambiguous — unserved view, or served view with nothing to show. **Design every
check so that the signal is a parser or endpoint *rejection*, not a row count**,
and use a positive control on a value known to be present wherever a count is
load-bearing. A count of zero proves nothing here.

- [ ] **Step 1: Record the environment**

Create `docs/probes/2026-07-fortiview-surface.md` with a header capturing what was
probed, so a later reader can tell whether it still applies:

```markdown
# FortiView surface, measured

Appliance: <hostname> (FAZ <version>), ADOM <adom>, masking OFF, skills OFF.
Probed: <date>. Devices present: <n> (<names>).
Method: fortianalyzer-dev MCP server over stdio, fixed custom window
"<start>|<end>" so re-runs are comparable.

**Null results are ambiguous on this estate** — one FortiGate, no IPS/attack
logs — so every verdict below is based on acceptance/rejection, not on row
counts, unless a positive control is named.
```

- [ ] **Step 2: Probe the view catalogue (spec item 3)**

For each of the ten names in `VALID_FORTIVIEW_VIEWS` (`utils/validation.py:164-175`),
call the view and record whether the *endpoint* accepts it:

```
get_fortiview_data(view_name="<view>", time_range="<fixed window>", limit=5)
```

Record per view: the `status`, whether a tid came back, the `percentage` the fetch
reached, the row count, and the **column names present on row 0**. The column list
is the part Tasks 2 and 4 need; the row count is not evidence.

Write the result as a table:

```markdown
## Views served

| view_name | endpoint accepted | rows | columns on row 0 |
| --- | --- | --- | --- |
| top-sources | yes | 42 | srcip, bandwidth, sessions, ... |
| top-threats | yes | 0 | (none — no threat logs on this estate) |
```

A view whose *endpoint* rejects the name is the only one that must be dropped from
`LOG_GROUP_SURFACES`. A served-but-empty view stays: it is a data gap, not a
capability gap. Note which is which explicitly — that distinction is the whole
reason this table exists.

- [ ] **Step 3: Probe the per-view sort columns (spec item 2)**

The repo's wrappers default to sorting by `bandwidth`; the published example uses
`bytes`; commit `eaef437` fixed a default naming a column that does not exist. For
each view that Step 2 found served, try each candidate sort column and record
acceptance:

```
get_fortiview_data(view_name="<view>", sort_by="<candidate>", time_range="<window>", limit=5)
```

Candidates to try per view, at minimum: `bandwidth`, `bytes`, `sessions`, and any
column name Step 2 actually observed on row 0. Record:

```markdown
## Sort columns

| view_name | accepted | rejected |
| --- | --- | --- |
| top-sources | bandwidth, sessions | bytes |
```

Prefer sort names Step 2 *observed as columns* — a column that exists in the
response is the strongest candidate, and this is the check that would have caught
`eaef437` before it shipped.

- [ ] **Step 4: Probe filter acceptance per view (spec item 4) — the load-bearing one**

This decides whether Task 4 may forward a compiled filter to a view at all, and
whether `unsupported_view_filter` ever needs to fire.

For each served view, and for a field the logview dialect definitely knows
(`srcip`, `dstport`, `service`, `app`, `policyid`), send the same filter to the
view and to `query_logs`, on the same fixed window:

```
get_fortiview_data(view_name="<view>", filter='<field>==<value>', time_range="<window>")
query_logs(logtype="traffic", filter='<field>==<value>', time_range="<window>", limit=1)
```

**Include the inertness control.** Because the parser does not reject operators it
does not know, also send a nonsense clause to each view:

```
get_fortiview_data(view_name="<view>", filter='<field> zzqq <value>', time_range="<window>")
```

and a field that certainly does not exist:

```
get_fortiview_data(view_name="<view>", filter='definitelynotafield==1', time_range="<window>")
```

Then classify each view into exactly one of three verdicts:

| Verdict | Evidence | Consequence for Task 4 |
| --- | --- | --- |
| **Filters honoured** | Filtered result differs from unfiltered in the expected direction, AND the nonsense clause behaves differently from the real one | Forward the filter. `unsupported_view_filter` never fires for this view/field. |
| **Filters rejected loudly** | The endpoint returns an error for the unknown field | Forward the filter; the appliance polices it. |
| **Filters silently ignored** | The unknown field and the nonsense clause return the *same* result as no filter at all | **Task 4 must refuse** `group_by` combined with a filter for this view. This is the unfiltered-top-N-as-exact case. |

Record the matrix:

```markdown
## Filter acceptance

| view_name | field | filtered vs unfiltered | unknown field | nonsense op | verdict |
| --- | --- | --- | --- | --- | --- |
| top-sources | srcip | differs | error | error | honoured |
```

- [ ] **Step 5: Encode the consequences, or record that you could not**

Finish the document with a short "What this means for the code" section stating,
in plain terms:

1. Which entries `LOG_GROUP_SURFACES` (Task 2) may contain.
2. Which per-view sort default the field map should carry.
3. Whether Task 4 forwards `filter` to the view, refuses the combination, or
   refuses only for named views.

**If you have no appliance access, do not skip this task — record that fact and
take the conservative branch**, which the spec already specifies:

- `LOG_GROUP_SURFACES` keeps only views already in `VALID_FORTIVIEW_VIEWS`
  (Task 2's `test_every_mapped_view_is_a_view_the_repo_accepts` enforces this
  either way).
- Task 4 **refuses** `group_by` combined with a non-empty `filter`, returning
  `unsupported_view_filter` with a message saying the combination is unverified
  and naming `sample_by` as the filtered alternative.

That fallback is strictly safe: it declines to answer rather than answering about
a population nobody asked for. Write down which branch you took — a later reader
must not have to guess whether "no filter forwarding" was a measurement or a
default.

- [ ] **Step 6: Commit**

```bash
git add docs/probes/2026-07-fortiview-surface.md
git commit -m "docs(probes): measure the FortiView surface before wiring group_by

group_by promises exactness and Task 4 forwards a compiled filter to a FortiView
view. FortiAnalyzer does not reject filter fields it does not know -- the same
inertness that made 'contain' match zero rows -- so an unknown field can produce
an unfiltered top-N returned under is_exact: true, which is a confident answer
about the wrong population.

Records which views the endpoint actually serves, which sort columns each
accepts, and whether filters are honoured, rejected or silently ignored per
view. Verdicts are based on acceptance and rejection rather than row counts:
this estate has one FortiGate and no threat logs, so a zero count proves
nothing."
```

---

### Task 1: Derived dimensions

**Files:**
- Create: `src/fortianalyzer_mcp/query/derive.py`
- Test: `tests/test_query_derive.py`

**Interfaces:**
- Consumes: nothing outside the standard library.
- Produces:
  - `DERIVED: Mapping[str, Callable[[Mapping[str, Any]], str | None]]`
  - `is_derived(dimension: str) -> bool`
  - `derive(dimension: str, row: Mapping[str, Any]) -> str | None`
  - `dimension_value(dimension: str, row: Mapping[str, Any]) -> str | None` — derived if derived, else the plain key stringified.

**Why first:** `get_policy_port_analysis` is deleted in Task 5, and the ICMP
decoding at `traffic_tools.py:504-526` is real domain knowledge — FortiAnalyzer
hides ICMP type and code in the `service` field, and SD-WAN SLA probes mislabel
it. Extracting it before the deletion is what stops it vanishing with the tool.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_query_derive.py`:

```python
"""Tests for computed group dimensions."""

from __future__ import annotations

from typing import Any

import pytest

from fortianalyzer_mcp.query.derive import derive, dimension_value, is_derived


class TestPortDimension:
    """port is proto/dstport, the key get_policy_port_analysis counted on."""

    def test_tcp_port_is_proto_slash_port(self) -> None:
        assert derive("port", {"proto": "6", "dstport": "443"}) == "6/443"

    def test_integer_values_are_accepted(self) -> None:
        assert derive("port", {"proto": 6, "dstport": 443}) == "6/443"

    def test_a_zero_port_is_portless_and_yields_none(self) -> None:
        """ICMP and friends carry dstport 0; that is not port 0."""
        assert derive("port", {"proto": "1", "dstport": "0"}) is None

    def test_a_missing_port_yields_none(self) -> None:
        assert derive("port", {"proto": "6"}) is None


class TestIcmpTypeCodeDimension:
    """The decoding lifted out of get_policy_port_analysis before its deletion."""

    def test_ping_is_echo_request(self) -> None:
        row = {"proto": "1", "service": "PING"}
        assert derive("icmp_type_code", row) == "type=8/code=0"

    def test_ping_is_matched_case_insensitively(self) -> None:
        assert derive("icmp_type_code", {"proto": "1", "service": "ping"}) == "type=8/code=0"

    def test_icmp_slash_form_is_decoded(self) -> None:
        row = {"proto": "1", "service": "icmp/3/3"}
        assert derive("icmp_type_code", row) == "type=3/code=3"

    def test_malformed_icmp_form_does_not_leak_the_raw_string(self) -> None:
        row = {"proto": "1", "service": "icmp/9"}
        assert derive("icmp_type_code", row) == "type=unknown"

    def test_sdwan_probe_mislabel_becomes_unknown_not_a_fake_type(self) -> None:
        """A FortiGate SD-WAN SLA probe tags an ICMP packet with the probed
        application service. That is not an ICMP encoding, and recording it as
        one would invent a type that never crossed the wire."""
        row = {"proto": "1", "service": "DNS"}
        assert derive("icmp_type_code", row) == "type=unknown"

    def test_empty_service_is_unknown(self) -> None:
        assert derive("icmp_type_code", {"proto": "1", "service": ""}) == "type=unknown"

    def test_a_non_icmp_row_is_not_an_icmp_bucket(self) -> None:
        row = {"proto": "6", "service": "HTTPS"}
        assert derive("icmp_type_code", row) is None


class TestDimensionValue:
    """One accessor for both derived and plain dimensions."""

    def test_derived_dimension_is_computed(self) -> None:
        assert dimension_value("port", {"proto": "6", "dstport": "443"}) == "6/443"

    def test_plain_dimension_is_read_and_stringified(self) -> None:
        assert dimension_value("dstport", {"dstport": 443}) == "443"

    def test_absent_plain_dimension_yields_none(self) -> None:
        assert dimension_value("dstport", {}) is None

    def test_empty_string_counts_as_absent(self) -> None:
        """An empty value is not a bucket; it is a missing value."""
        assert dimension_value("app", {"app": ""}) is None

    @pytest.mark.parametrize("name,expected", [("port", True), ("dstport", False)])
    def test_is_derived_reports_membership(self, name: str, expected: bool) -> None:
        assert is_derived(name) is expected

    def test_a_dict_valued_field_is_not_a_bucket(self) -> None:
        """Nested values cannot be group keys; stringifying one would produce
        a bucket label nobody can filter on afterwards."""
        row: dict[str, Any] = {"target": {"name": "srcip"}}
        assert dimension_value("target", row) is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_derive.py -q --no-cov
```
Expected: collection error — `ModuleNotFoundError: No module named 'fortianalyzer_mcp.query.derive'`.

- [ ] **Step 3: Write the implementation**

Create `src/fortianalyzer_mcp/query/derive.py`:

```python
"""Group dimensions FortiAnalyzer does not store as fields.

Two of the aggregations this repo performs are over values that no log field
holds. They were computed inline inside ``get_policy_port_analysis``, and when
that tool folded into ``analyze_policy_traffic`` the domain knowledge would
have gone with it. As dimensions they survive the merge and become available
to every caller rather than to one tool.

``icmp_type_code`` is the substantive one. FortiAnalyzer does not populate
``icmptype``/``icmpcode`` on traffic logs; it encodes the pair in the
``service`` field as ``PING`` (echo request) or ``icmp/<type>/<code>``. A
FortiGate running an SD-WAN SLA probe muddies that further by tagging the ICMP
packet with the *probed application's* service name, so a proto-1 row can
arrive reading ``DNS``. Recording that as a type would invent an ICMP type that
never crossed the wire, so anything that is not one of the two known encodings
becomes ``type=unknown``. That choice is also what keeps the ICMP bucket sum
equal to the proto=1 count in a protocol breakdown.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

#: Values that mean "the appliance sent nothing here", not "a bucket named X".
_ABSENT = {"", "n/a", "null", "none", "unknown"}


def _port(row: Mapping[str, Any]) -> str | None:
    """``"{proto}/{dstport}"``, or None for a portless protocol.

    A ``dstport`` of 0 is how FortiAnalyzer spells "this protocol has no
    ports" (ICMP, GRE, ESP). Bucketing those under port 0 would invent
    traffic to a port that does not exist.
    """
    proto = row.get("proto")
    dstport = row.get("dstport")
    if proto is None or dstport is None:
        return None
    port_str = str(dstport).strip()
    if not port_str or port_str == "0":
        return None
    return f"{str(proto).strip()}/{port_str}"


def _icmp_type_code(row: Mapping[str, Any]) -> str | None:
    """Decode the ICMP type/code FortiAnalyzer hides in ``service``.

    Returns None for a non-ICMP row so it does not land in the ICMP
    breakdown at all; returns ``type=unknown`` for an ICMP row whose service
    is not one of the two known encodings.
    """
    if str(row.get("proto", "")).strip() != "1":
        return None

    service = str(row.get("service", "")).strip()
    if service.upper() == "PING":
        return "type=8/code=0"
    if service.startswith("icmp/"):
        parts = service.split("/")
        if len(parts) == 3:
            return f"type={parts[1]}/code={parts[2]}"
        # Malformed "icmp/..." value: do not leak the raw string as a label.
        return "type=unknown"
    # An application name (an SD-WAN SLA probe tag) or an empty service.
    return "type=unknown"


#: Dimension name -> the function that computes it from one row.
DERIVED: Mapping[str, Callable[[Mapping[str, Any]], str | None]] = {
    "port": _port,
    "icmp_type_code": _icmp_type_code,
}


def is_derived(dimension: str) -> bool:
    """Whether this dimension is computed rather than read from a field."""
    return dimension.strip().lower() in DERIVED


def derive(dimension: str, row: Mapping[str, Any]) -> str | None:
    """Compute a derived dimension for one row.

    Raises:
        KeyError: if ``dimension`` is not derived. Callers should route
            through :func:`dimension_value`, which handles both kinds.
    """
    return DERIVED[dimension.strip().lower()](row)


def dimension_value(dimension: str, row: Mapping[str, Any]) -> str | None:
    """The bucket label for one row under one dimension, or None to skip it.

    None means "this row does not belong in this breakdown" -- an absent
    field, an empty value, or a nested structure. A nested value is excluded
    rather than stringified because a bucket labelled with a dict repr is one
    the caller cannot filter on afterwards, which makes the breakdown a dead
    end.
    """
    name = dimension.strip().lower()
    if name in DERIVED:
        return DERIVED[name](row)

    value = row.get(name)
    if value is None or isinstance(value, dict | list):
        return None
    text = str(value).strip()
    if not text or text.lower() in _ABSENT:
        return None
    return text
```

- [ ] **Step 4: Run the tests and the gates**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_derive.py -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: all PASS, gates clean.

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/query/derive.py tests/test_query_derive.py
git commit -m "feat(query): computed group dimensions for port and ICMP type/code

FortiAnalyzer does not populate icmptype/icmpcode on traffic logs -- it hides
the pair in the service field as PING or icmp/<type>/<code> -- and a FortiGate
SD-WAN SLA probe tags an ICMP packet with the probed application's service
name, so a proto-1 row can arrive reading DNS.

That decoding lived inline in get_policy_port_analysis, which Plan 3 deletes.
Lifting it to a dimension first is what keeps the knowledge: anything that is
not one of the two known encodings becomes type=unknown rather than inventing
an ICMP type that never crossed the wire, which is also what keeps the ICMP
bucket sum equal to the proto=1 count.

dstport 0 yields no port bucket: that is how FAZ spells a portless protocol,
not traffic to port zero."
```

---

### Task 2: `GroupPlan` and native dimension resolution

**Files:**
- Create: `src/fortianalyzer_mcp/query/groups.py`
- Modify: `src/fortianalyzer_mcp/query/__init__.py`
- Test: `tests/test_query_groups.py`

**Interfaces:**
- Consumes: `resolve_field` from `query/fields.py`; `ValidationError` from `fortianalyzer_mcp.utils.errors`.
- Produces:
  - `GroupPlan` frozen dataclass: `dimension: str`, `surface: str`, `target: str`, `all_devices_group: str`
  - `LOG_GROUP_SURFACES: Mapping[str, str]`, `ALERT_GROUP_DIMENSIONS: frozenset[str]`, `INCIDENT_GROUP_DIMENSIONS: frozenset[str]`
  - `resolve_group_plan(vocabulary: str, dimension: str) -> GroupPlan`
  - `UnsupportedGroupDimension(ValidationError)` — carries `.dimension` and `.supported`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_query_groups.py`:

```python
"""Tests for group_by resolution."""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.query.groups import (
    LOG_GROUP_SURFACES,
    UnsupportedGroupDimension,
    resolve_group_plan,
)


class TestLogDimensions:
    """Every log group_by resolves to a FortiView view or refuses."""

    @pytest.mark.parametrize(
        "dimension,view",
        [
            ("srcip", "top-sources"),
            ("dstip", "top-destinations"),
            ("app", "top-applications"),
            ("hostname", "top-websites"),
            ("website", "top-websites"),
            ("attack", "top-threats"),
            ("threat", "top-threats"),
            ("policyid", "policy-hits"),
            ("dstcountry", "top-countries"),
        ],
    )
    def test_dimension_maps_to_its_native_view(self, dimension: str, view: str) -> None:
        plan = resolve_group_plan("traffic", dimension)
        assert plan.surface == "fortiview"
        assert plan.target == view

    def test_an_alias_resolves_before_dispatch(self) -> None:
        """source_ip is the same question as srcip."""
        plan = resolve_group_plan("traffic", "source_ip")
        assert plan.target == "top-sources"
        assert plan.dimension == "srcip"

    def test_the_plan_carries_fortiviews_all_devices_group(self) -> None:
        """FortiView spells it All_Device; logview spells it All_FortiGate.
        Forwarding logview's default returns zero rows, silently."""
        plan = resolve_group_plan("traffic", "srcip")
        assert plan.all_devices_group == "All_Device"

    def test_every_mapped_view_is_a_view_the_repo_accepts(self) -> None:
        from fortianalyzer_mcp.utils.validation import VALID_FORTIVIEW_VIEWS

        for dimension, view in LOG_GROUP_SURFACES.items():
            assert view in VALID_FORTIVIEW_VIEWS, f"{dimension} maps to unknown view {view}"


class TestAlertAndIncidentDimensions:
    """These dispatch to stats endpoints, not FortiView."""

    @pytest.mark.parametrize("dimension", ["severity", "status"])
    def test_alert_dimensions_dispatch_to_the_stats_endpoint(self, dimension: str) -> None:
        plan = resolve_group_plan("alert", dimension)
        assert plan.surface == "alert_stats"
        assert plan.target == dimension

    @pytest.mark.parametrize("dimension", ["severity", "status", "category"])
    def test_incident_dimensions_dispatch_to_incident_stats(self, dimension: str) -> None:
        plan = resolve_group_plan("incident", dimension)
        assert plan.surface == "incident_stats"


class TestRefusal:
    """A refusal that does not say what works is a dead end."""

    def test_an_unmapped_dimension_raises(self) -> None:
        with pytest.raises(UnsupportedGroupDimension):
            resolve_group_plan("traffic", "sentbyte")

    def test_the_refusal_names_sample_by(self) -> None:
        with pytest.raises(UnsupportedGroupDimension) as exc:
            resolve_group_plan("traffic", "sentbyte")
        assert "sample_by" in str(exc.value)

    def test_the_refusal_lists_the_dimensions_that_do_work(self) -> None:
        with pytest.raises(UnsupportedGroupDimension) as exc:
            resolve_group_plan("traffic", "sentbyte")
        message = str(exc.value)
        assert "srcip" in message and "policyid" in message

    def test_the_refusal_carries_the_dimension_and_the_supported_set(self) -> None:
        """Structured, so the tool can build an envelope without reparsing prose."""
        with pytest.raises(UnsupportedGroupDimension) as exc:
            resolve_group_plan("traffic", "sentbyte")
        assert exc.value.dimension == "sentbyte"
        assert "srcip" in exc.value.supported

    def test_an_alert_dimension_is_not_valid_for_logs(self) -> None:
        """Vocabularies do not share a group surface."""
        with pytest.raises(UnsupportedGroupDimension):
            resolve_group_plan("alert", "srcip")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_groups.py -q --no-cov
```
Expected: collection error — `ModuleNotFoundError: No module named 'fortianalyzer_mcp.query.groups'`.

- [ ] **Step 3: Write the implementation**

Create `src/fortianalyzer_mcp/query/groups.py`:

```python
"""Where an exact grouping can actually come from.

``group_by`` promises an exact answer, so it may only resolve to a surface the
appliance itself aggregated. For logs every such surface is a FortiView view;
for alerts and incidents it is a stats endpoint. A dimension with no native
surface is refused rather than answered by scanning a bounded sample, because a
top-N over a 1000-row sample reads as fact and gets quoted as fact. The refusal
names ``sample_by``, which makes exactly that trade-off explicitly and labels
the result.

Three translations the plan carries, each of which silently returns zero rows
if missed:

* FortiView's all-devices group is ``All_Device``; logview's is
  ``All_FortiGate``. Forwarding the logview default to a view yields an empty
  top-N with no error.
* The compiled filter has to be re-emitted against the view's own filterable
  vocabulary, which is not provably identical to logview's. Until that is
  verified live, the caller of this module is expected to refuse a filter on a
  field the view is not known to accept rather than silently returning an
  unfiltered top-N.
* The already-resolved ``{start, end}`` window is reused rather than
  re-derived, preserving the "resolve the window once at tool entry"
  invariant across the hand-off.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from fortianalyzer_mcp.query.fields import resolve_field
from fortianalyzer_mcp.utils.errors import ValidationError

#: FortiView's spelling of "every device". Logview says All_FortiGate.
FORTIVIEW_ALL_DEVICES = "All_Device"

#: Log dimension -> the FortiView view that aggregates it natively.
LOG_GROUP_SURFACES: Mapping[str, str] = {
    "srcip": "top-sources",
    "dstip": "top-destinations",
    "app": "top-applications",
    "hostname": "top-websites",
    "website": "top-websites",
    "attack": "top-threats",
    "threat": "top-threats",
    "policyid": "policy-hits",
    "dstcountry": "top-countries",
}

#: Alert dimensions served by /eventmgmt/adom/{adom}/alert-incident/stats.
ALERT_GROUP_DIMENSIONS: frozenset[str] = frozenset({"severity", "status"})

#: Incident dimensions served by /incidentmgmt/adom/{adom}/incident/stats.
INCIDENT_GROUP_DIMENSIONS: frozenset[str] = frozenset({"severity", "status", "category"})


class UnsupportedGroupDimension(ValidationError):
    """Raised when a dimension has no native surface to group on.

    Subclasses ValidationError so existing handlers still catch it, but carries
    the dimension and the supported set so a tool can build a structured
    envelope without re-parsing the message.
    """

    def __init__(self, dimension: str, supported: list[str], vocabulary: str) -> None:
        self.dimension = dimension
        self.supported = supported
        valid = ", ".join(supported)
        super().__init__(
            f"group_by='{dimension}' has no exact surface for {vocabulary}. "
            f"Dimensions the appliance can group exactly: {valid}. "
            f"For any other dimension use sample_by=['{dimension}'], which scans a "
            "bounded sample and labels the result as one."
        )


@dataclass(frozen=True)
class GroupPlan:
    """How to obtain an exact grouping for one dimension."""

    #: The canonical dimension name, after alias resolution.
    dimension: str
    #: Which executor handles it: "fortiview", "alert_stats", "incident_stats".
    surface: str
    #: The view name or stats item the executor should request.
    target: str
    #: The device-group token the target surface understands.
    all_devices_group: str = FORTIVIEW_ALL_DEVICES


def _supported_for(vocabulary: str) -> list[str]:
    if vocabulary == "alert":
        return sorted(ALERT_GROUP_DIMENSIONS)
    if vocabulary == "incident":
        return sorted(INCIDENT_GROUP_DIMENSIONS)
    return sorted(LOG_GROUP_SURFACES)


def resolve_group_plan(vocabulary: str, dimension: str) -> GroupPlan:
    """Resolve a ``group_by`` dimension to the surface that answers it exactly.

    Args:
        vocabulary: The logtype, or ``"alert"``/``"incident"``.
        dimension: The caller's dimension name; aliases are accepted.

    Returns:
        The plan an executor can act on.

    Raises:
        UnsupportedGroupDimension: when no native surface exists. The message
            names ``sample_by`` as the way to ask the same question with an
            honest label.
    """
    # Resolve aliases first so source_ip and srcip are the same question. An
    # unknown name on an incomplete vocabulary passes through with a warning
    # we discard here: an unmapped dimension is refused below regardless.
    try:
        canonical, _ = resolve_field(vocabulary, dimension)
    except ValidationError:
        canonical = dimension.strip().lower()

    if vocabulary == "alert":
        if canonical in ALERT_GROUP_DIMENSIONS:
            return GroupPlan(dimension=canonical, surface="alert_stats", target=canonical)
        raise UnsupportedGroupDimension(dimension, _supported_for("alert"), "alerts")

    if vocabulary == "incident":
        if canonical in INCIDENT_GROUP_DIMENSIONS:
            return GroupPlan(dimension=canonical, surface="incident_stats", target=canonical)
        raise UnsupportedGroupDimension(dimension, _supported_for("incident"), "incidents")

    view = LOG_GROUP_SURFACES.get(canonical)
    if view is None:
        raise UnsupportedGroupDimension(dimension, _supported_for(vocabulary), vocabulary)
    return GroupPlan(dimension=canonical, surface="fortiview", target=view)
```

Add `GroupPlan`, `UnsupportedGroupDimension`, `resolve_group_plan` and
`LOG_GROUP_SURFACES` to `query/__init__.py`'s imports and `__all__`.

- [ ] **Step 4: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_groups.py -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: green. If `test_every_mapped_view_is_a_view_the_repo_accepts` fails, the
mapping names a view outside `VALID_FORTIVIEW_VIEWS:164-175` — **remove the
mapping**, do not widen the allowlist. Adding a view is a live-verification item
(spec item 3), and commit `9e5d091` already removed three documented names the
appliance does not actually serve.

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/query/groups.py src/fortianalyzer_mcp/query/__init__.py \
  tests/test_query_groups.py
git commit -m "feat(query): resolve group_by to a native appliance surface or refuse

group_by promises exactness, so it may only resolve to a surface the appliance
itself aggregated: a FortiView view for logs, a stats endpoint for alerts and
incidents. There is deliberately no fallback to a bounded scan -- a top-N over
a 1000-row sample reads as fact and gets quoted as fact -- so an unmapped
dimension raises, and the refusal names sample_by, which asks the same question
and labels the answer.

The plan carries FortiView's All_Device group rather than logview's
All_FortiGate: forwarding the logview default to a view returns an empty top-N
with no error at all.

A test asserts every mapped view is one the repo's allowlist accepts, so a
dimension cannot point at a view the appliance does not serve."
```

---

### Task 3: In-process bounded aggregation

**Files:**
- Modify: `src/fortianalyzer_mcp/query/groups.py`
- Test: `tests/test_query_groups.py`

**Interfaces:**
- Consumes: `dimension_value` from Task 1.
- Produces: `aggregate_breakdowns(rows, dimensions, top_n=10) -> dict[str, list[dict[str, Any]]]`

**Design note:** `sample_by` takes a **list** because one row scan yields several
independent breakdowns — which is exactly what `get_policy_traffic_profile` does
today with ports, services and applications. It is not a cross-tab; cardinality
would explode and no caller asked for one.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_query_groups.py`:

```python
from fortianalyzer_mcp.query.groups import aggregate_breakdowns


class TestAggregateBreakdowns:
    """One scan, several independent breakdowns."""

    ROWS = [
        {"proto": "6", "dstport": "443", "app": "HTTPS", "service": "HTTPS"},
        {"proto": "6", "dstport": "443", "app": "HTTPS", "service": "HTTPS"},
        {"proto": "6", "dstport": "80", "app": "HTTP", "service": "HTTP"},
        {"proto": "1", "dstport": "0", "app": "PING", "service": "PING"},
    ]

    def test_counts_are_per_dimension_not_a_cross_tab(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["app", "proto"])
        assert set(result) == {"app", "proto"}
        assert result["app"][0] == {"value": "HTTPS", "hits": 2}

    def test_buckets_are_ordered_by_hits_descending(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["app"])
        hits = [bucket["hits"] for bucket in result["app"]]
        assert hits == sorted(hits, reverse=True)

    def test_top_n_truncates(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["app"], top_n=1)
        assert len(result["app"]) == 1
        assert result["app"][0]["value"] == "HTTPS"

    def test_top_n_zero_returns_every_bucket(self) -> None:
        """get_policy_port_analysis returned the complete port list; that survives."""
        result = aggregate_breakdowns(self.ROWS, ["app"], top_n=0)
        assert len(result["app"]) == 3

    def test_a_derived_dimension_works(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["port"])
        assert {"value": "6/443", "hits": 2} in result["port"]

    def test_portless_rows_are_excluded_from_the_port_breakdown(self) -> None:
        """The ICMP row has dstport 0, which is not a port."""
        result = aggregate_breakdowns(self.ROWS, ["port"])
        assert all(bucket["value"] != "1/0" for bucket in result["port"])

    def test_icmp_breakdown_uses_the_derived_decoding(self) -> None:
        result = aggregate_breakdowns(self.ROWS, ["icmp_type_code"])
        assert result["icmp_type_code"] == [{"value": "type=8/code=0", "hits": 1}]

    def test_rows_missing_the_dimension_are_skipped_not_bucketed_as_unknown(self) -> None:
        rows = [{"app": "HTTPS"}, {"other": 1}]
        result = aggregate_breakdowns(rows, ["app"])
        assert result["app"] == [{"value": "HTTPS", "hits": 1}]

    def test_no_dimensions_yields_an_empty_mapping(self) -> None:
        assert aggregate_breakdowns(self.ROWS, []) == {}

    def test_no_rows_yields_an_empty_bucket_list_per_dimension(self) -> None:
        """The dimension key survives so the caller sees it was asked for."""
        assert aggregate_breakdowns([], ["app"]) == {"app": []}

    def test_ties_are_broken_deterministically_by_value(self) -> None:
        rows = [{"app": "B"}, {"app": "A"}]
        result = aggregate_breakdowns(rows, ["app"])
        assert [b["value"] for b in result["app"]] == ["A", "B"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_groups.py -q --no-cov
```
Expected: `ImportError: cannot import name 'aggregate_breakdowns'`.

- [ ] **Step 3: Write the implementation**

Append to `src/fortianalyzer_mcp/query/groups.py` (and add the import
`from collections import Counter` plus `from typing import Any` at the top, and
`from fortianalyzer_mcp.query.derive import dimension_value`):

```python
def aggregate_breakdowns(
    rows: list[Any],
    dimensions: list[str],
    top_n: int = 10,
) -> dict[str, list[dict[str, Any]]]:
    """Count rows per dimension, independently.

    One scan yields one breakdown per requested dimension. This is deliberately
    not a cross-tab: ``get_policy_traffic_profile`` wants ports *and* services
    *and* applications from a single scan, and the product of three dimensions
    would explode in cardinality to answer a question nobody asked.

    Args:
        rows: The sampled rows.
        dimensions: Dimension names; plain fields and derived dimensions both
            work.
        top_n: Buckets to keep per dimension. ``0`` keeps every bucket, which
            is what ``get_policy_port_analysis``'s complete port list needed.

    Returns:
        ``{dimension: [{"value": str, "hits": int}, ...]}``, each list ordered
        by hits descending then value ascending, so equal counts come back in
        a stable order rather than one that depends on scan order.
    """
    breakdowns: dict[str, list[dict[str, Any]]] = {}

    for dimension in dimensions:
        counter: Counter[str] = Counter()
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = dimension_value(dimension, row)
            # None means the row does not belong in this breakdown -- an
            # absent field or a portless protocol -- rather than belonging in
            # an "unknown" bucket that would inflate the total.
            if value is not None:
                counter[value] += 1

        ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        if top_n > 0:
            ordered = ordered[:top_n]
        breakdowns[dimension] = [{"value": value, "hits": hits} for value, hits in ordered]

    return breakdowns
```

Add `aggregate_breakdowns` to `query/__init__.py`.

- [ ] **Step 4: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_groups.py -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/query/groups.py src/fortianalyzer_mcp/query/__init__.py \
  tests/test_query_groups.py
git commit -m "feat(query): independent per-dimension breakdowns from one row scan

sample_by takes a list because one scan yields several breakdowns -- ports and
services and applications, which is exactly what get_policy_traffic_profile
does today. Deliberately not a cross-tab: the product would explode in
cardinality to answer a question nobody asked.

top_n=0 keeps every bucket, preserving get_policy_port_analysis's complete port
list. Ties break by value so equal counts return in a stable order rather than
one that depends on scan order. A row missing the dimension is skipped rather
than bucketed as unknown, which would inflate the total with rows that were
never candidates."
```

---

### Task 4: `query_logs` gains `group_by`, `sample_by` and `count_only`

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/log_tools.py`
- Test: `tests/test_log_tools.py`

**Interfaces:**
- Consumes: `resolve_group_plan`, `UnsupportedGroupDimension`, `aggregate_breakdowns` from Tasks 2-3; the bounded helpers in `traffic_tools` are **not** used here (see the note below).
- Produces: `query_logs(..., group_by: str | None = None, sample_by: list[str] | None = None, count_only: bool = False)` with four mutually exclusive modes.

**Mode table** (from the spec; assert it, do not paraphrase it):

| Mode | Set by | Returns |
| --- | --- | --- |
| rows | none of the three | `logs` + `fields_returned` |
| exact groups | `group_by="<dim>"` | `groups`, `group_source`, `is_exact: true` |
| bounded breakdowns | `sample_by=["<dim>", …]` | `breakdowns` + the bounded-metadata block |
| count only | `count_only=True` | `total`, `total_is_known`, `count_source` |

Any two of the three together → `conflicting_aggregation`. `fields` alongside any
of them is **inert and warns** rather than erroring, because it describes a row
shape no rows will be returned in.

**Import direction note.** `query_logs` must not import from `traffic_tools`:
`traffic_tools` already imports `_run_logsearch_page` and `_clamp_limit` from
`log_tools`, so the reverse import would be a cycle. `query_logs(sample_by=…)`
therefore scans **one** window (its own `limit`), not the multi-slice fan-out —
which is exactly the boundary the spec draws: `query_logs(sample_by=…)` is one
query yielding one aggregate set, `analyze_policy_traffic` is the multi-policy,
multi-slice fan-out.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_log_tools.py`:

```python
class TestQueryLogsAggregationModes:
    """Four modes, mutually exclusive, each labelled for what it is."""

    CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"
    ROWS = [
        {"app": "HTTPS", "proto": "6", "dstport": "443"},
        {"app": "HTTPS", "proto": "6", "dstport": "443"},
        {"app": "HTTP", "proto": "6", "dstport": "80"},
    ]

    class _Faz:
        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

    def _install(self, monkeypatch: pytest.MonkeyPatch, total: int | None = 3) -> None:
        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            return {
                "timed_out": False,
                "tid": 11,
                "logs": [dict(r) for r in TestQueryLogsAggregationModes.ROWS],
                "total": total,
            }

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

    async def test_sample_by_returns_labelled_breakdowns_and_no_rows(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, sample_by=["app"]
        )

        assert "logs" not in result, "aggregation modes suppress raw rows"
        assert result["breakdowns"]["app"][0] == {"value": "HTTPS", "hits": 2}
        assert result["analysis_mode"] in ("bounded_sample", "exact")
        assert "is_exact" in result
        assert "total_hits_is_known" in result

    async def test_sample_by_accepts_several_dimensions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, sample_by=["app", "port"]
        )

        assert set(result["breakdowns"]) == {"app", "port"}

    async def test_sample_by_top_n_zero_keeps_every_bucket(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, sample_by=["app"], top_n=0
        )

        assert len(result["breakdowns"]["app"]) == 2

    async def test_count_only_returns_a_total_and_no_rows(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, count_only=True
        )

        assert "logs" not in result
        assert result["total"] == 3
        assert result["total_is_known"] is True
        assert result["count_source"]

    async def test_count_only_is_honest_when_the_appliance_gave_no_total(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, total=None)

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, count_only=True
        )

        assert result["total_is_known"] is False

    async def test_group_by_and_sample_by_together_conflict(self) -> None:
        result = await log_tools.query_logs(
            logtype="traffic", group_by="srcip", sample_by=["app"]
        )

        assert result["status"] == "error"
        assert result["error"] == "conflicting_aggregation"

    async def test_count_only_with_sample_by_conflicts(self) -> None:
        result = await log_tools.query_logs(
            logtype="traffic", sample_by=["app"], count_only=True
        )

        assert result["error"] == "conflicting_aggregation"

    async def test_an_unsupported_group_dimension_names_sample_by(self) -> None:
        result = await log_tools.query_logs(logtype="traffic", group_by="sentbyte")

        assert result["status"] == "error"
        assert result["error"] == "unsupported_group_dimension"
        assert "sample_by" in result["message"]

    # Include this test ONLY if Task 0 put you on the refusal branch -- i.e. the
    # probe found filters silently ignored for the target view, or you had no
    # appliance and took the conservative fallback. If Task 0 proved the view
    # honours filters, delete this test and assert the forwarding instead:
    # that the fake's fortiview_run received the compiled filter string.
    async def test_group_by_with_a_filter_is_refused_when_unverified(self) -> None:
        """An ignored filter would return an unfiltered top-N under is_exact."""
        result = await log_tools.query_logs(
            logtype="traffic", group_by="srcip", filter="dstport==443"
        )

        assert result["status"] == "error"
        assert result["error"] == "unsupported_view_filter"
        assert "sample_by" in result["recommendation"]

    async def test_fields_with_an_aggregation_warns_rather_than_erroring(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """fields describes a row shape no rows will be returned in."""
        self._install(monkeypatch)

        result = await log_tools.query_logs(
            logtype="traffic",
            time_range=self.CUSTOM_RANGE,
            sample_by=["app"],
            fields=["srcip"],
        )

        assert result["status"] == "success"
        assert any("fields" in w for w in result["warnings"])

    async def test_rows_mode_is_unchanged_when_no_aggregation_is_asked_for(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await log_tools.query_logs(logtype="traffic", time_range=self.CUSTOM_RANGE)

        assert "logs" in result
        assert "breakdowns" not in result
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_log_tools.py -k AggregationModes -q --no-cov
```
Expected: FAIL — unexpected keyword argument `sample_by`.

- [ ] **Step 3: Add the parameters and mode validation**

Add the imports to `log_tools.py`:

```python
from fortianalyzer_mcp.query.groups import (
    UnsupportedGroupDimension,
    aggregate_breakdowns,
    resolve_group_plan,
)
```

Extend the signature (after `fields`, before `limit`):

```python
    group_by: str | None = None,
    sample_by: list[str] | None = None,
    count_only: bool = False,
    top_n: int = 10,
```

Add to the docstring's `Args:`:

```
        group_by: Return exact per-value counts for one dimension instead of
            rows. Only dimensions the appliance aggregates natively are
            accepted (srcip, dstip, app, hostname, attack, policyid,
            dstcountry); anything else is an error naming sample_by. The
            answer is exact because the appliance counted it.
        sample_by: Return per-value counts for one or more dimensions from a
            bounded row scan. Unlike group_by this is a *sample*, and the
            response says so: check is_exact and analysis_mode before quoting
            any number. Derived dimensions work here: "port" is proto/dstport,
            "icmp_type_code" decodes the ICMP pair FAZ hides in `service`.
        count_only: Return just the total row count for the query.
        top_n: Buckets per dimension for sample_by (default 10). 0 returns
            every bucket.
```

Immediately after the `filters`/`filter` conflict check added in Plan 1, insert
the mode validation:

```python
        # Exactly one aggregation mode, or none. Two would each describe a
        # different response shape and there is no sensible merge.
        chosen = [
            name
            for name, active in (
                ("group_by", group_by is not None),
                ("sample_by", bool(sample_by)),
                ("count_only", count_only),
            )
            if active
        ]
        if len(chosen) > 1:
            return error_response(
                error="conflicting_aggregation",
                message=(
                    f"Pass at most one of group_by, sample_by or count_only; got "
                    f"{', '.join(chosen)}. Each returns a different response shape."
                ),
                operation="query_logs",
                adom=adom,
                logtype=logtype,
                recommendation=(
                    "Use group_by for an exact grouping the appliance computes, "
                    "sample_by for a bounded breakdown over a row scan, or count_only "
                    "for just the total."
                ),
            )

        aggregating = bool(chosen)
        if aggregating and fields is not None:
            # Inert rather than fatal: it describes a row shape that no rows
            # will be returned in, which is a harmless mistake, not a wrong
            # query.
            filter_warnings.append(
                f"'fields' is ignored with {chosen[0]}: no raw rows are returned."
            )
```

Guard the projection resolution added in Plan 2 so it does not run (and cannot
raise) in an aggregation mode:

```python
        if aggregating:
            projection, projection_warnings = None, []
        else:
            projection, projection_warnings = resolve_projection(logtype, fields)
```

- [ ] **Step 4: Implement the `group_by` branch**

`group_by` must reach a FortiView view, and `log_tools` cannot import
`fortiview_tools` (that module imports nothing from `log_tools`, so the
direction is safe — verify before writing, and if a cycle appears, call the
client directly instead).

**Filter forwarding depends on Task 0's measurement — read it before writing this.**
The block below forwards the caller's `filter` to the view. That is only correct if
Task 0 classified the target view as *filters honoured* or *filters rejected
loudly*. If Task 0 found filters **silently ignored** for that view — or if you
took the no-appliance fallback branch — insert this refusal *before* the
`get_fortiview_data` call instead of forwarding:

```python
            # Task 0 could not prove this view honours a logview filter. Forwarding
            # it would return an unfiltered top-N under is_exact: true -- a
            # confident answer about a population nobody asked for.
            if filter:
                return error_response(
                    error="unsupported_view_filter",
                    message=(
                        f"group_by='{group_by}' dispatches to the FortiView view "
                        f"'{plan.target}', and this server has not verified that the view "
                        "applies a logview filter rather than ignoring it. Refusing rather "
                        "than returning a top-N that may cover unfiltered traffic."
                    ),
                    operation="query_logs",
                    adom=adom,
                    logtype=logtype,
                    recommendation=(
                        f"Drop the filter to group the whole window, or use "
                        f"sample_by=['{group_by}'] which applies the filter and labels the "
                        "result as a bounded sample."
                    ),
                )
```

Whichever branch you take, **say which in the commit message**, so the next reader
knows it was measured rather than assumed.

Insert after the window is resolved and before `_run_logsearch_page`:

```python
        if group_by is not None:
            try:
                plan = resolve_group_plan(logtype, group_by)
            except UnsupportedGroupDimension as e:
                return error_response(
                    error="unsupported_group_dimension",
                    message=str(e),
                    operation="query_logs",
                    adom=adom,
                    logtype=logtype,
                    recommendation=f"Use sample_by=['{group_by}'] for a bounded breakdown.",
                )

            from fortianalyzer_mcp.tools.fortiview_tools import get_fortiview_data

            view = await get_fortiview_data(
                view_name=plan.target,
                adom=adom,
                # The plan carries FortiView's own all-devices token; passing
                # logview's All_FortiGate here returns an empty top-N silently.
                device=device or plan.all_devices_group,
                time_range=time_range,
                filter=filter,
                limit=limit,
                fields=["*"],
            )
            if view.get("status") != "success":
                return view

            return {
                "status": "success",
                "adom": adom,
                "logtype": logtype,
                "group_by": plan.dimension,
                "groups": view.get("data", []),
                "group_source": f"fortiview:{plan.target}",
                # The appliance aggregated this. That is the whole reason
                # group_by refuses dimensions with no native surface.
                "is_exact": True,
                "time_range": time_range_dict,
                "timezone": tz_name,
                "filter": filter,
                "warnings": filter_warnings,
            }
```

The lazy import inside the branch is deliberate: a module-level import of
`fortiview_tools` from `log_tools` would change tool-registration order, and
`server.py`'s bottom import block depends on that order.

- [ ] **Step 5: Implement the `count_only` and `sample_by` branches**

After the `page = await _run_logsearch_page(...)` call and its timeout check:

```python
        if count_only:
            total = page["total"]
            return {
                "status": "success",
                "adom": adom,
                "logtype": logtype,
                "total": total,
                "total_is_known": total is not None,
                "count_source": "logsearch_total_count",
                "time_range": time_range_dict,
                "timezone": tz_name,
                "filter": filter,
                "warnings": filter_warnings,
            }

        if sample_by:
            rows = page["logs"]
            observed = len(rows)
            total = page["total"]
            total_known = total is not None
            # One page, one window: exact only when the appliance's own total
            # equals what we actually scanned. A full page means rows were
            # left behind, so nothing here may claim exactness.
            truncated = observed >= limit
            is_exact = total_known and not truncated and total == observed
            return {
                "status": "success",
                "adom": adom,
                "logtype": logtype,
                "sample_by": list(sample_by),
                "breakdowns": aggregate_breakdowns(rows, list(sample_by), top_n=top_n),
                "is_exact": is_exact,
                "analysis_mode": "exact" if is_exact else "bounded_sample",
                "total_hits": total if total_known else observed,
                "total_hits_is_known": total_known,
                "total_hit_source": "logsearch_total_count" if total_known else "observed_rows",
                "observed_hits": observed,
                "log_limit_per_slice": limit,
                "slices_scanned": 1,
                "truncated_slices": 1 if truncated else 0,
                "recommendation": (
                    "Narrow the time window or raise limit for a closer count."
                    if not is_exact
                    else ""
                ),
                "time_range": time_range_dict,
                "timezone": tz_name,
                "filter": filter,
                "warnings": filter_warnings,
            }
```

- [ ] **Step 6: Run the tests and the contract suites**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_log_tools.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_response_contract.py tests/test_log_pagination.py tests/test_mcp_tools.py \
  tests/test_tool_annotations.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: green.

- [ ] **Step 7: Commit**

```bash
git add src/fortianalyzer_mcp/tools/log_tools.py tests/test_log_tools.py
git commit -m "feat(log-tools): group_by, sample_by and count_only on query_logs

Four mutually exclusive modes. group_by dispatches to the FortiView view that
aggregates the dimension natively and reports is_exact: true because the
appliance counted it; an unmapped dimension is refused with a message naming
sample_by rather than quietly sampling. sample_by scans one bounded window and
carries the full honesty block -- is_exact, analysis_mode, total_hits,
total_hits_is_known, total_hit_source, observed_hits, truncated_slices --
so no number arrives without its provenance. count_only returns the total
alone.

Two modes together error rather than merging, since each names a different
response shape. fields alongside an aggregation only warns: it describes a row
shape no rows will be returned in, which is a harmless mistake rather than a
wrong query.

The FortiView import is lazy inside the branch: importing it at module level
would change tool-registration order, which server.py's bottom import block
depends on."
```

---

### Task 5: `analyze_policy_traffic` replaces the three policy tools

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/traffic_tools.py` — add `analyze_policy_traffic`; delete `get_policy_traffic_profile` (:709), `get_policy_port_analysis` (:786), `get_policy_protocol_summary` (:856) and the three `_aggregate_*` helpers (:433, :476, :544)
- Test: `tests/test_traffic_tools.py`

**Interfaces:**
- Consumes: `aggregate_breakdowns` (Task 3), `dimension_value` (Task 1), and the existing `_run_bounded_policy_analysis` (:575), `_bounded_metadata` (:374), `_build_bounded_time_slices` (:173) — all reused unchanged.
- Produces: `analyze_policy_traffic(adom=None, device=None, policy_ids=None, time_range="24-hour", action=None, sample_by=None, top_n=10)`.

**Default `sample_by`.** When omitted it is `["port", "service", "app"]` — the
three breakdowns `get_policy_traffic_profile` produced — so the most common old
call has a direct equivalent with fewer parameters, not more.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_traffic_tools.py`:

```python
class TestAnalyzePolicyTraffic:
    """One tool replaces three, and keeps the bounded-honesty contract."""

    async def test_default_sample_by_reproduces_the_profile_breakdowns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [
            {"proto": "6", "dstport": "443", "service": "HTTPS", "app": "HTTPS"},
            {"proto": "6", "dstport": "80", "service": "HTTP", "app": "HTTP"},
        ]

        async def fake_analysis(**kwargs: Any) -> dict[str, Any]:
            return {
                "logs": rows,
                "total_hits": 2,
                "total_hits_is_known": True,
                "all_slices_exact": True,
                "slices_scanned": 1,
                "truncated_slices": 0,
            }

        monkeypatch.setattr(traffic_tools, "_run_bounded_policy_analysis", fake_analysis)

        result = await traffic_tools.analyze_policy_traffic(policy_ids=[7])

        breakdowns = result["results"][0]["breakdowns"]
        assert set(breakdowns) == {"port", "service", "app"}
        assert {"value": "6/443", "hits": 1} in breakdowns["port"]

    async def test_explicit_sample_by_selects_dimensions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [{"proto": "1", "dstport": "0", "service": "PING"}]

        async def fake_analysis(**kwargs: Any) -> dict[str, Any]:
            return {
                "logs": rows,
                "total_hits": 1,
                "total_hits_is_known": True,
                "all_slices_exact": True,
                "slices_scanned": 1,
                "truncated_slices": 0,
            }

        monkeypatch.setattr(traffic_tools, "_run_bounded_policy_analysis", fake_analysis)

        result = await traffic_tools.analyze_policy_traffic(
            policy_ids=[7], sample_by=["icmp_type_code"]
        )

        assert result["results"][0]["breakdowns"]["icmp_type_code"] == [
            {"value": "type=8/code=0", "hits": 1}
        ]

    async def test_the_bounded_contract_is_reported_per_policy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_analysis(**kwargs: Any) -> dict[str, Any]:
            return {
                "logs": [{"proto": "6", "dstport": "443"}],
                "total_hits": 5000,
                "total_hits_is_known": True,
                "all_slices_exact": False,
                "slices_scanned": 4,
                "truncated_slices": 4,
            }

        monkeypatch.setattr(traffic_tools, "_run_bounded_policy_analysis", fake_analysis)

        result = await traffic_tools.analyze_policy_traffic(policy_ids=[7])

        entry = result["results"][0]
        assert entry["is_exact"] is False
        assert entry["analysis_mode"] == "bounded_sample"
        assert entry["total_hits_is_known"] is True
        assert entry["truncated_slices"] == 4
        assert entry["recommendation"]

    async def test_top_n_zero_keeps_the_complete_port_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """get_policy_port_analysis returned every port; that must survive."""
        rows = [{"proto": "6", "dstport": str(p)} for p in range(1000, 1030)]

        async def fake_analysis(**kwargs: Any) -> dict[str, Any]:
            return {
                "logs": rows,
                "total_hits": len(rows),
                "total_hits_is_known": True,
                "all_slices_exact": True,
                "slices_scanned": 1,
                "truncated_slices": 0,
            }

        monkeypatch.setattr(traffic_tools, "_run_bounded_policy_analysis", fake_analysis)

        result = await traffic_tools.analyze_policy_traffic(
            policy_ids=[7], sample_by=["port"], top_n=0
        )

        assert len(result["results"][0]["breakdowns"]["port"]) == 30

    async def test_an_unknown_dimension_is_rejected_before_the_scan(self) -> None:
        result = await traffic_tools.analyze_policy_traffic(
            policy_ids=[7], sample_by=["not_a_dimension_at_all"]
        )

        assert result["status"] == "error"
        assert result["error"] == "unknown_field"

    async def test_too_many_policies_is_still_refused(self) -> None:
        result = await traffic_tools.analyze_policy_traffic(
            policy_ids=list(range(1, traffic_tools.MAX_POLICY_IDS + 5))
        )

        assert result["status"] == "error"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_traffic_tools.py -k AnalyzePolicy -q --no-cov
```
Expected: FAIL — `module has no attribute 'analyze_policy_traffic'`.

- [ ] **Step 3: Write the new tool**

Add to `traffic_tools.py`:

```python
from fortianalyzer_mcp.query.fields import resolve_field
from fortianalyzer_mcp.query.groups import aggregate_breakdowns
```

Add the tool. Model its structure on the deleted `get_policy_traffic_profile`
(read it before deleting it — it owns the ADOM validation, the policy-id
validation, the window resolution and the fan-out loop, all of which are reused):

```python
@mcp.tool(annotations=READ_ONLY)
async def analyze_policy_traffic(
    adom: str | None = None,
    device: str | None = None,
    policy_ids: list[int] | None = None,
    time_range: str = "24-hour",
    action: str | None = None,
    sample_by: list[str] | None = None,
    top_n: int = DEFAULT_TOP_N,
) -> dict[str, Any]:
    """Break down what traffic each firewall policy actually carried.

    Replaces get_policy_traffic_profile, get_policy_port_analysis and
    get_policy_protocol_summary: the three differed only in which breakdowns
    they produced, which is now the sample_by parameter.

    This is a *bounded sample*, not a census. It scans a fixed number of time
    slices per policy and stops at a row cap, so check `is_exact` before
    quoting any number. When it is False, `analysis_mode` is "bounded_sample"
    and `total_hits` is a floor, not a total.

    Use query_logs(sample_by=[...]) instead when you want one aggregate set for
    one query; this tool fans out across up to MAX_POLICY_IDS policies under a
    shared query budget and reports each separately.

    Args:
        adom: ADOM name (default: from config DEFAULT_ADOM)
        device: Device filter (serial, name, or an All_* group)
        policy_ids: Firewall policy IDs to analyse
        time_range: Preset token or "start|end"
        action: Optional traffic action filter (accept, deny, ...)
        sample_by: Dimensions to break down. Defaults to
            ["port", "service", "app"] -- what get_policy_traffic_profile
            returned. "port" is proto/dstport; "icmp_type_code" decodes the
            ICMP type/code FortiAnalyzer hides in the service field.
        top_n: Buckets per dimension (default 10). 0 returns every bucket,
            which is what get_policy_port_analysis's complete port list needed.

    Returns:
        dict with per-policy entries under `results`, each carrying
        `breakdowns` plus the bounded metadata block (`is_exact`,
        `analysis_mode`, `total_hits`, `total_hits_is_known`,
        `total_hit_source`, `observed_hits`, `slices_scanned`,
        `truncated_slices`, `log_limit_per_slice`, `recommendation`).
    """
    dimensions = list(sample_by) if sample_by else ["port", "service", "app"]

    try:
        adom = validate_adom(adom or get_default_adom())
        action = validate_action(action)
        policy_ids = validate_policy_ids(policy_ids or [])

        # Validate dimensions before any appliance work: a typo should cost
        # nothing. Derived dimensions bypass the field registry, which only
        # knows stored fields.
        for dimension in dimensions:
            if not is_derived(dimension):
                resolve_field("traffic", dimension)
    except ValidationError as e:
        return error_response(
            error="unknown_field" if "field" in str(e).lower() else "validation_error",
            message=str(e),
            operation="analyze_policy_traffic",
            adom=adom,
        )

    # ... resolve the window once, exactly as get_policy_traffic_profile did,
    # then for each policy id call _run_bounded_policy_analysis and build:
    #
    #     entry = {
    #         "policy_id": policy_id,
    #         "breakdowns": aggregate_breakdowns(
    #             policy_result["logs"], dimensions, top_n=top_n
    #         ),
    #         **_bounded_metadata(
    #             total_hits=policy_result["total_hits"],
    #             total_hits_is_known=policy_result["total_hits_is_known"],
    #             observed_hits=len(policy_result["logs"]),
    #             slices_scanned=policy_result["slices_scanned"],
    #             truncated_slices=policy_result["truncated_slices"],
    #             all_slices_exact=policy_result.get("all_slices_exact") is True,
    #         ),
    #     }
```

Import `is_derived` from `query.derive` alongside the others.

**Read `get_policy_traffic_profile:709-786` and copy its fan-out loop verbatim**
before deleting it — the semaphore use, the per-policy error handling and the
`_bounded_metadata(...)` argument names must match what that function passes
today. The comment block above marks the one part that changes (the aggregation
call); everything else is a move, not a rewrite.

- [ ] **Step 4: Delete the three old tools and their helpers**

Delete in this order, running `ruff check` after each to let `F401` name any
import that became unused:

1. `get_policy_traffic_profile` (:709)
2. `get_policy_port_analysis` (:786)
3. `get_policy_protocol_summary` (:856)
4. `_aggregate_traffic_profile` (:433), `_aggregate_port_analysis` (:476), `_aggregate_protocol_summary` (:544)

`_aggregate_port_analysis` contains the ICMP decoding — Task 1 already extracted
it to `query/derive.py`, so deleting it here loses nothing. Confirm
`tests/test_query_derive.py` still passes after the deletion; if it fails, the
extraction was not faithful and the deletion must be reverted until it is.

`tools/__init__.py` needs **no change**: it imports the ten tool modules, not the
tool functions, so adding and removing tools inside `traffic_tools` is invisible
to it. Confirm with `grep -n analyze_policy_traffic src/fortianalyzer_mcp/tools/__init__.py`
returning nothing, and that the tool is registered:

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run python -c "
import asyncio, fortianalyzer_mcp.server as s
print('analyze_policy_traffic' in {t.name for t in asyncio.run(s.mcp.list_tools())})
"
```

- [ ] **Step 5: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_traffic_tools.py tests/test_query_derive.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Existing tests referencing the deleted tools will fail. Rewrite each against
`analyze_policy_traffic` rather than deleting it — a test that covered the old
behaviour still covers something real. Where the old assertion was about a
response key that no longer exists (`ports`, `protocols`, `icmp`), map it onto
the equivalent `breakdowns` entry.

- [ ] **Step 6: Commit**

```bash
git add src/fortianalyzer_mcp/tools/traffic_tools.py tests/test_traffic_tools.py
git commit -m "feat(traffic): analyze_policy_traffic replaces the three policy tools

get_policy_traffic_profile, get_policy_port_analysis and
get_policy_protocol_summary differed only in which breakdowns they produced.
That difference is now sample_by, defaulting to the profile's three, and the
scan machinery, the fan-out budget and the bounded-metadata block are reused
unchanged.

top_n=0 keeps the complete port list get_policy_port_analysis returned. The
ICMP type/code decoding those tools owned moved to query/derive.py first, so
deleting them loses no domain knowledge -- a dimension test guards that.

Dimensions are validated before any appliance work, so a typo costs nothing."
```

---

### Task 6: Retire the FortiView wrappers

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/fortiview_tools.py` — delete `get_top_sources` (:369), `get_top_destinations` (:410), `get_top_applications` (:443), `get_top_threats` (:481), `get_top_websites` (:522), `get_top_cloud_applications` (:555), `get_policy_hits` (:597)
- Test: `tests/test_fortiview_tools.py`

**Interfaces:** no new names. Every deleted tool was a fixed-`view_name` call to
the same endpoint `get_fortiview_data` already exposes.

- [ ] **Step 1: Write the equivalence tests first**

Before deleting anything, prove the replacement produces what each wrapper did.
Append to `tests/test_fortiview_tools.py`:

```python
class TestFortiViewWrapperEquivalence:
    """Each removed wrapper was get_fortiview_data with a fixed view_name."""

    VIEW_FOR_REMOVED_TOOL = {
        "get_top_sources": "top-sources",
        "get_top_destinations": "top-destinations",
        "get_top_applications": "top-applications",
        "get_top_threats": "top-threats",
        "get_top_websites": "top-websites",
        "get_top_cloud_applications": "top-cloud-applications",
        "get_policy_hits": "policy-hits",
    }

    @pytest.mark.parametrize("view", sorted(set(VIEW_FOR_REMOVED_TOOL.values())))
    async def test_the_replacement_reaches_each_view(
        self, monkeypatch: pytest.MonkeyPatch, view: str
    ) -> None:
        captured: dict[str, object] = {}

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_system_timezone(self) -> None:
                return None

            async def fortiview_run(self, **kwargs: object) -> dict[str, object]:
                captured.update(kwargs)
                return {"tid": 1}

            async def fortiview_fetch(self, **kwargs: object) -> dict[str, object]:
                return {"percentage": 100, "data": []}

        monkeypatch.setattr(fortiview_tools, "_get_client", lambda: FakeClient())

        result = await fortiview_tools.get_fortiview_data(view_name=view, fields=["*"])

        assert result["status"] == "success"
        assert captured["view_name"] == view

    @pytest.mark.parametrize("name", sorted(VIEW_FOR_REMOVED_TOOL))
    def test_the_wrapper_is_gone(self, name: str) -> None:
        assert not hasattr(fortiview_tools, name), f"{name} should have been removed"
```

- [ ] **Step 2: Run them — the equivalence tests pass, the removal tests fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_fortiview_tools.py -k WrapperEquivalence -q --no-cov
```
Expected: the seven `test_the_wrapper_is_gone` cases FAIL (the tools still
exist); the per-view cases PASS, which is what licenses the deletion.

- [ ] **Step 3: Delete the seven tools**

Delete each `@mcp.tool()`-decorated function and its decorator. `tools/__init__.py`
needs no change — it lists modules, not tool functions. Run `ruff check` to surface
imports that became unused.

Leave `run_fortiview` and `fetch_fortiview` alone — consolidating those into
`get_fortiview_data` is explicitly out of scope in the spec.

- [ ] **Step 4: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_fortiview_tools.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
The skills suite will fail here — six handlers still call these tools. That is
Task 8 and is expected; note the failure count and proceed. **Do not** fix
handlers in this task: keeping the breakage visible in one commit is what makes
Task 8's diff reviewable.

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/tools/fortiview_tools.py tests/test_fortiview_tools.py
git commit -m "refactor(fortiview): retire the six get_top_* wrappers and get_policy_hits

Each was get_fortiview_data with a fixed view_name and no other behaviour, so
seven catalogue entries competed for one job and an LLM had to choose between
names that differ only in a string constant.

Parametrised tests prove get_fortiview_data reaches each of the seven views
before the deletions, and assert each wrapper is gone afterwards.

run_fortiview and fetch_fortiview stay: folding those into get_fortiview_data
is named out of scope in the spec.

The skills suite fails after this commit -- six handlers still call the removed
names. That is the next commit, kept separate so its diff is reviewable."
```

---

### Task 7: Retire the log-search wrappers

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/log_tools.py` — delete `search_traffic_logs` (:1236), `search_security_logs` (:1350), `search_event_logs` (:1459)
- Test: `tests/test_removed_tools.py`

**Interfaces:** no new names. Each was `query_logs` with a hand-built filter
string, which `filters` now builds correctly.

- [ ] **Step 1: Write the equivalence and removal tests**

Create `tests/test_removed_tools.py`:

```python
"""The consolidation removed thirteen tools. Prove they are gone, and that
each removed call pattern has a working replacement.

A test that only asserts absence would pass just as well if the replacement
were broken, so every entry pairs the two.
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.tools.fortiview_tools as fortiview_tools
import fortianalyzer_mcp.tools.log_tools as log_tools
import fortianalyzer_mcp.tools.traffic_tools as traffic_tools
from fortianalyzer_mcp.query.filters import FilterCondition

CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"

#: (module, removed tool name, the call that replaces it).
REMOVED = [
    (log_tools, "search_traffic_logs", "query_logs(logtype='traffic', filters=[...])"),
    (log_tools, "search_security_logs", "query_logs(logtype='attack', filters=[...])"),
    (log_tools, "search_event_logs", "query_logs(logtype='event', filters=[...])"),
    (fortiview_tools, "get_top_sources", "get_fortiview_data(view_name='top-sources')"),
    (fortiview_tools, "get_top_destinations", "get_fortiview_data('top-destinations')"),
    (fortiview_tools, "get_top_applications", "get_fortiview_data('top-applications')"),
    (fortiview_tools, "get_top_threats", "get_fortiview_data('top-threats')"),
    (fortiview_tools, "get_top_websites", "get_fortiview_data('top-websites')"),
    (
        fortiview_tools,
        "get_top_cloud_applications",
        "get_fortiview_data('top-cloud-applications')",
    ),
    (fortiview_tools, "get_policy_hits", "get_fortiview_data(view_name='policy-hits')"),
    (traffic_tools, "get_policy_traffic_profile", "analyze_policy_traffic(sample_by=[...])"),
    (traffic_tools, "get_policy_port_analysis", "analyze_policy_traffic(sample_by=['port'])"),
    (
        traffic_tools,
        "get_policy_protocol_summary",
        "analyze_policy_traffic(sample_by=['proto'])",
    ),
]


@pytest.mark.parametrize(
    "module,name,replacement", REMOVED, ids=[name for _, name, _ in REMOVED]
)
def test_removed_tool_is_gone(module: object, name: str, replacement: str) -> None:
    assert not hasattr(module, name), f"{name} is still defined; use {replacement}"


@pytest.mark.parametrize("name", [name for _, name, _ in REMOVED])
def test_removed_tool_is_not_registered(name: str) -> None:
    """Gone from the module is not enough; it must be off the MCP surface."""
    import asyncio

    import fortianalyzer_mcp.server as server

    registered = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert name not in registered, f"{name} is still advertised to clients"


class TestSearchWrapperReplacement:
    """The filters surface expresses what the deleted wrappers hard-coded."""

    class _Faz:
        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

    async def test_traffic_search_by_port_and_action(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        async def fake_page(client: object, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        await log_tools.query_logs(
            logtype="traffic",
            time_range=CUSTOM_RANGE,
            filters=[
                FilterCondition(field="dstport", op="eq", value=443),
                FilterCondition(field="action", op="eq", value="deny"),
            ],
        )

        assert captured["filter"] == "dstport==443 and action==deny"

    async def test_security_search_by_severity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        async def fake_page(client: object, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        await log_tools.query_logs(
            logtype="attack",
            time_range=CUSTOM_RANGE,
            filters=[FilterCondition(field="severity", op="in", value=["critical", "high"])],
        )

        assert captured["filter"] == "(severity==critical or severity==high)"

    async def test_event_search_by_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        async def fake_page(client: object, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        await log_tools.query_logs(
            logtype="event",
            time_range=CUSTOM_RANGE,
            filters=[FilterCondition(field="level", op="eq", value="warning")],
        )

        assert captured["filter"] == "level==warning"
```

- [ ] **Step 2: Run it**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_removed_tools.py -q --no-cov
```
Expected: the three `search_*_logs` removal cases FAIL; the FortiView and policy
removal cases already PASS (Tasks 5-6 deleted those); the three replacement
cases PASS.

- [ ] **Step 3: Delete the three wrappers**

Delete `search_traffic_logs`, `search_security_logs` and `search_event_logs`
with their decorators. `tools/__init__.py` again needs no change.

Several validators exist only for these wrappers (`validate_event_level`,
`validate_event_subtype`, `validate_severity`, `validate_traffic_action` are
imported at `log_tools.py:24-31`). Let `ruff check`'s `F401` tell you which
became unused, and remove those imports — but leave the functions in
`utils/validation.py`: `pcap_tools` and `traffic_tools` also use some of them,
and an unused public validator is harmless while a wrongly deleted one is not.

- [ ] **Step 4: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_removed_tools.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
The skills suite is still red from Task 6; that is expected until Task 8.

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/tools/log_tools.py tests/test_removed_tools.py
git commit -m "refactor(log-tools): retire the three search_*_logs wrappers

Each was query_logs with a hand-built filter string, and hand-building is what
the filters surface removed -- including the two spellings of contains that
the duplication produced.

tests/test_removed_tools.py pairs every removal with the call that replaces it,
so the suite cannot pass by having deleted a tool whose replacement is broken.
It covers all thirteen removed names, including the ten already deleted."
```

---

### Task 8: The skills layer moves to the consolidated tools

**Files:**
- Modify: `src/fortianalyzer_mcp/skills/handlers.py` — the import/call pairs at :760/:829 (`run_incident_summary`), :1268/:1359 (`run_threat_intel`), :1497-1524 (`run_app_usage`, three views) and :1655-1670 (`run_network_context`, two views)
- Test: `tests/test_skills*.py` (there is no `test_skills_handlers.py`; the skills suite is split per skill — `test_skills.py`, `test_skills_app_usage.py`, `test_skills_threat_intel.py`, `test_skills_network_context.py`, `test_skills_wave2.py`, and siblings)

**Interfaces:** no new names. Every call becomes
`get_fortiview_data(view_name=…, …)`.

**The existing test design is the safety net.** Handlers import raw tools lazily
per call and the tests patch them at their defining module with `autospec=True`,
so a missed call site fails at test time with a clear name — not at runtime
against a live appliance. Trust that signal: if the skills suite is green, the
migration is complete.

- [ ] **Step 1: Run the skills suite to enumerate the breakage**

```bash
FORTIANALYZER_HOST=ci-dummy.local FAZ_SKILLS_ENABLED=true PYTHONPATH=src uv run pytest \
  tests/test_skills*.py -q --no-cov 2>&1 | tail -30
```
Record the failing test names. Each names a handler and the tool it cannot
import — that list is the work.

- [ ] **Step 2: Migrate each call site**

The mapping is one-to-one:

| Removed call | Replacement |
| --- | --- |
| `get_top_threats(adom=…, time_range=…, limit=N)` | `get_fortiview_data(view_name="top-threats", adom=…, time_range=…, limit=N)` |
| `get_top_applications(...)` | `get_fortiview_data(view_name="top-applications", ...)` |
| `get_top_websites(...)` | `get_fortiview_data(view_name="top-websites", ...)` |
| `get_top_cloud_applications(...)` | `get_fortiview_data(view_name="top-cloud-applications", ...)` |
| `get_top_sources(...)` | `get_fortiview_data(view_name="top-sources", ...)` |
| `get_top_destinations(...)` | `get_fortiview_data(view_name="top-destinations", ...)` |

At `handlers.py:760` and `:1268` the import line becomes:

```python
    from fortianalyzer_mcp.tools.fortiview_tools import get_fortiview_data
```

and the call at `:829`:

```python
            get_fortiview_data,
            view_name="top-threats",
            adom=params.adom,
            time_range=params.time_range,
            limit=10,
```

At `:1497-1524` three imports (`get_top_applications`, `get_top_cloud_applications`,
`get_top_websites`) collapse to one `get_fortiview_data`, with each `_call(...)`
gaining its `view_name=`. Same at `:1655-1670` for the two network-context calls
(`get_top_destinations`, `get_top_sources`).

The full set of call sites, confirmed at `627a138` — six imports across four
handlers, eight call sites in total:

```
handlers.py:760   import get_top_threats            -> :829   call
handlers.py:1268  import get_top_threats            -> :1359  call
handlers.py:1497  import get_top_applications       -> :1510  call
handlers.py:1499  import get_top_websites           -> :1517  call
handlers.py:1498  import get_top_cloud_applications -> :1524  call
handlers.py:1655  import get_top_destinations       -> :1669  call
handlers.py:1656  import get_top_sources            -> :1670  call
```

`grep -n "get_top_\|get_policy_hits" src/fortianalyzer_mcp/skills/handlers.py`
reproduces this list; run it first and reconcile against the above rather than
trusting either.

**Add `fields=["*"]` to each migrated call.** Plan 2 gave `get_fortiview_data` a
`fields` parameter that defaults to full-rows-plus-a-warning; the skills read
specific columns out of these rows and their output models are validated, so an
explicit `["*"]` both preserves today's behaviour and silences a warning that
would otherwise appear in every skill response.

- [ ] **Step 3: Update the tests' patch targets**

Each test patching `fortiview_tools.get_top_*` now patches
`fortiview_tools.get_fortiview_data`. Where a single test patched two or three
different `get_top_*` functions, it now patches one function called several
times — assert on `view_name` in the recorded calls so the test still
distinguishes them. That is a strictly better assertion: it checks the view
actually requested rather than which wrapper name was invoked.

- [ ] **Step 4: Run the skills suite and the full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local FAZ_SKILLS_ENABLED=true PYTHONPATH=src uv run pytest \
  tests/test_skills*.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: green, including the suites that were red after Tasks 6-7.

Also confirm the skills still work end-to-end with masking on, since
`faz_skill` is the masking boundary for composed calls:

```bash
MASKING_ENABLED=true FAZ_MASKING_KEY=$(python3 -c "print('0'*64)") FAZ_SKILLS_ENABLED=true \
  FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_skills*.py -q --no-cov
```

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/skills/handlers.py tests/test_skills*.py  # quote or expand the glob for your shell
git commit -m "refactor(skills): compose get_fortiview_data instead of the get_top_* wrappers

Six call sites across run_incident_summary, run_threat_intel, run_app_usage and
run_network_context moved to get_fortiview_data(view_name=...). No skill
behaviour changes; the view requested is identical in each case.

Each migrated call passes fields=[\"*\"], preserving the full rows these
handlers read columns out of and suppressing the uncurated-projection warning
that would otherwise surface in every composed response.

The tests now patch one function and assert on view_name rather than patching
a differently-named wrapper per view, which checks the view actually requested
instead of which wrapper name was invoked."
```

---

### Task 9: The dynamic-mode catalogue stops being able to drift

**Files:**
- Modify: `src/fortianalyzer_mcp/server.py` — `register_dynamic_tools` (:132), `tool_catalog` (:148), `tool_map` (:295), `total_tools: 72` (:463)
- Test: `tests/test_tool_catalogue_parity.py`

**Interfaces:**
- Produces: `TOOL_CATALOGUE: Mapping[str, tuple[str, ...]]` — one static structure, category → tool names — replacing both hand-written ones.

**The problem being fixed.** `tool_catalog` (search text) and `tool_map`
(dispatch) are two hand-maintained structures, neither derived from what is
registered. They already disagree: `total_tools` is the literal `72` at
`server.py:463` against **85** actually registered, `tool_catalog` omits
pcap/soar/ueba tools that `tool_map` can execute, and
`get_api_ratelimit`/`update_api_ratelimit` are in neither. Consolidation must
touch this file anyway, so it gets one source and a test.

(The drift is worse than the numbers suggest: 72 was already wrong when the
surface was 83, and the surface has since grown to 85 without the literal
moving. That is exactly what a hand-maintained mirror does.)

**Why the catalogue stays static.** `find_fortianalyzer_tool` must **not**
derive the catalogue by importing tool modules: that would register every tool
on the first search call and destroy the minimal surface dynamic mode exists
for. `execute_advanced_tool` already imports them all, so *its* dispatch map can
be derived for free — the static structure is only needed for search.

- [ ] **Step 1: Write the parity test**

Create `tests/test_tool_catalogue_parity.py`:

```python
"""The dynamic-mode catalogue must equal the registered tool set.

Dynamic mode keeps a hand-written catalogue so that searching for a tool does
not import every tool module -- which would register all of them and destroy
the minimal surface the mode exists for. The cost of hand-maintenance is drift,
and it had already drifted: the catalogue reported 72 tools against 85
registered, omitted the pcap/soar/ueba tools that dispatch could nonetheless
execute, and listed neither get_api_ratelimit nor update_api_ratelimit.

This test converts that drift into a failing suite.
"""

from __future__ import annotations

import pytest


def _registered_tool_names() -> set[str]:
    """Every tool name registered in full mode.

    Read from FastMCP, not from `tools.__all__`: that list holds the ten tool
    *modules*, never the tool functions, so using it here would compare the
    catalogue against the wrong thing and pass while saying nothing.
    """
    import asyncio

    import fortianalyzer_mcp.server as server

    return {tool.name for tool in asyncio.run(server.mcp.list_tools())}


def _catalogue_names() -> set[str]:
    from fortianalyzer_mcp.server import TOOL_CATALOGUE

    return {name for names in TOOL_CATALOGUE.values() for name in names}


def test_catalogue_lists_every_registered_tool() -> None:
    missing = _registered_tool_names() - _catalogue_names()
    assert not missing, f"registered but not in the catalogue: {sorted(missing)}"


def test_catalogue_lists_nothing_that_is_not_registered() -> None:
    extra = _catalogue_names() - _registered_tool_names()
    assert not extra, f"in the catalogue but not registered: {sorted(extra)}"


def test_no_tool_appears_in_two_categories() -> None:
    """A duplicate makes the reported count wrong even when both sets match."""
    from fortianalyzer_mcp.server import TOOL_CATALOGUE

    seen: set[str] = set()
    duplicated: set[str] = set()
    for names in TOOL_CATALOGUE.values():
        for name in names:
            if name in seen:
                duplicated.add(name)
            seen.add(name)
    assert not duplicated, f"listed in more than one category: {sorted(duplicated)}"


def test_reported_total_matches_the_catalogue() -> None:
    """The hardcoded 72 against 85 registered is the bug this closes."""
    from fortianalyzer_mcp.server import TOOL_CATALOGUE

    total = sum(len(names) for names in TOOL_CATALOGUE.values())
    assert total == len(_catalogue_names())
    assert total == len(_registered_tool_names())


@pytest.mark.parametrize(
    "removed",
    [
        "get_top_sources",
        "get_top_destinations",
        "get_top_applications",
        "get_top_threats",
        "get_top_websites",
        "get_top_cloud_applications",
        "get_policy_hits",
        "search_traffic_logs",
        "search_security_logs",
        "search_event_logs",
        "get_policy_traffic_profile",
        "get_policy_port_analysis",
        "get_policy_protocol_summary",
    ],
)
def test_consolidated_tools_are_absent_from_the_catalogue(removed: str) -> None:
    assert removed not in _catalogue_names()


def test_the_replacement_is_present() -> None:
    assert "analyze_policy_traffic" in _catalogue_names()
```

- [ ] **Step 2: Run it**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_tool_catalogue_parity.py -q --no-cov
```
Expected: `ImportError: cannot import name 'TOOL_CATALOGUE'`, then — once the
constant exists — real parity failures reflecting the pre-existing drift.

- [ ] **Step 3: Introduce the single catalogue**

In `server.py`, above `register_dynamic_tools`, add the module-level constant.
Build it from the authoritative list of what is actually registered — not from
the current `tool_catalog`, which is the structure known to be wrong.

**Do not use `tools.__all__` for this.** It holds the ten tool *modules*
(`log_tools`, `dvm_tools`, …), never the tool functions, so it would give you
ten names and a catalogue that agrees with nothing. Ask FastMCP:

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run python -c "
import asyncio, fortianalyzer_mcp.server as s
for t in sorted(x.name for x in asyncio.run(s.mcp.list_tools())): print(t)
"
```

Assign each name to exactly one category:

```python
#: Category -> tool names, for dynamic mode's search surface.
#:
#: Static on purpose. find_fortianalyzer_tool must not import the tool modules
#: to build this, because importing them registers every tool and destroys the
#: minimal surface dynamic mode exists for. The cost is that it can drift from
#: what is registered -- and it had, badly -- so
#: tests/test_tool_catalogue_parity.py asserts the two match exactly.
TOOL_CATALOGUE: Mapping[str, tuple[str, ...]] = {
    "logs": (
        "query_logs",
        "fetch_more_logs",
        "cancel_log_search",
        "get_log_fields",
        # ... every registered log tool
    ),
    # ... the remaining categories
}
```

Replace `tool_catalog`'s body inside `register_dynamic_tools` with a reference
to `TOOL_CATALOGUE`, and replace the hardcoded count:

```python
            "total_tools": sum(len(names) for names in TOOL_CATALOGUE.values()),
```

Derive `tool_map` from the imports `execute_advanced_tool` already performs
rather than hand-listing it:

```python
        # execute_advanced_tool imports every tool module anyway, so its
        # dispatch map can be derived -- unlike the search catalogue, which
        # must stay static to avoid that import.
        import fortianalyzer_mcp.tools as tools_module

        tool_map = {
            name: getattr(tools_module, name)
            for name in TOOL_CATALOGUE_NAMES
            if hasattr(tools_module, name)
        }
```

with `TOOL_CATALOGUE_NAMES` a module-level frozenset derived from
`TOOL_CATALOGUE`. Keep that import inside the function body — hoisting it would
break the registration-order constraint.

- [ ] **Step 4: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_tool_catalogue_parity.py -q --no-cov
FAZ_TOOL_MODE=dynamic FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/ --ignore=tests/integration -q --no-cov 2>&1 | tail -5
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: green. The dynamic-mode run is a smoke check that the mode still
starts; if it was already failing before this task, note that and do not treat
it as a regression.

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/server.py tests/test_tool_catalogue_parity.py
git commit -m "refactor(server): one dynamic-mode catalogue, and a test that it cannot drift

Dynamic mode kept two hand-written structures -- tool_catalog for search,
tool_map for dispatch -- neither derived from what is registered, and they had
already drifted apart: 72 reported against 85 registered, pcap/soar/ueba tools
dispatchable but unsearchable, and the two ratelimit tools in neither.

TOOL_CATALOGUE is now the single source. It stays static because deriving it
would mean importing every tool module inside find_fortianalyzer_tool, which
registers all of them and destroys the minimal surface dynamic mode exists for.
execute_advanced_tool already imports them, so its dispatch map is derived from
the catalogue for free.

The parity test asserts the catalogue equals the registered set in both
directions, that no tool is double-listed, and that the reported total is
computed rather than typed."
```

---

### Task 10: Document the consolidation and ship the breaking change

**Files:**
- Modify: `src/fortianalyzer_mcp/instructions.py`
- Modify: `tests/test_server_instructions.py`
- Modify: `CHANGELOG.md`
- Modify: `pyproject.toml`, `README.md` (version bump)

**Interfaces:** none — documentation and versioning.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_server_instructions.py`:

```python
AGGREGATION_PARAMETERS = ("group_by", "sample_by", "count_only", "top_n")

CONSOLIDATED_TOOLS = (
    "get_fortiview_data",
    "analyze_policy_traffic",
    "query_logs",
)

REMOVED_TOOL_NAMES = (
    "get_top_sources",
    "get_top_destinations",
    "get_top_applications",
    "get_top_threats",
    "get_top_websites",
    "get_top_cloud_applications",
    "get_policy_hits",
    "search_traffic_logs",
    "search_security_logs",
    "search_event_logs",
    "get_policy_traffic_profile",
    "get_policy_port_analysis",
    "get_policy_protocol_summary",
)


@pytest.mark.parametrize("parameter", AGGREGATION_PARAMETERS)
def test_aggregation_parameters_are_documented(instructions: str, parameter: str) -> None:
    assert parameter in instructions, f"{parameter} missing from the usage guide"


@pytest.mark.parametrize("name", CONSOLIDATED_TOOLS)
def test_the_surviving_tools_are_named(instructions: str, name: str) -> None:
    assert name in instructions


@pytest.mark.parametrize("name", REMOVED_TOOL_NAMES)
def test_removed_tools_are_not_recommended(instructions: str, name: str) -> None:
    """A guide that still names a deleted tool sends every client to an error."""
    assert name not in instructions, f"{name} was removed but is still recommended"


def test_the_exactness_split_is_stated(instructions: str) -> None:
    """group_by exact, sample_by bounded -- the reason there are two names."""
    lowered = instructions.lower()
    assert "exact" in lowered
    assert "sample" in lowered
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_server_instructions.py -q --no-cov
```
Expected: the aggregation-parameter cases fail; some `test_removed_tools_are_not_recommended`
cases fail, because the "Choosing among overlapping tools" section still names
`search_traffic_logs` and the policy trio.

- [ ] **Step 3: Rewrite the affected instruction sections**

Replace the whole `## Choosing among overlapping tools` section with:

```
## Choosing among overlapping tools

- Raw log rows, any logtype, any filter -> query_logs.
- "How much / top N", where the dimension is one FortiAnalyzer aggregates
  natively -> query_logs(group_by="srcip"), or get_fortiview_data(view_name=...)
  when you want the view's own columns. Both are exact.
- "How much / top N" for any other dimension -> query_logs(sample_by=["..."]).
  Bounded, and the response says so.
- Per-policy breakdowns across several policies -> analyze_policy_traffic.
- IPS/attack events, especially with PCAP -> search_ips_logs.
- Unsure what is filterable -> get_log_fields(name_filter="...").
```

Add a new section after `## Projection`:

```
## Aggregation

Three parameters on query_logs, mutually exclusive, and the names carry the
guarantee:

  group_by="srcip"        exact. The appliance counted it.
  sample_by=["port"]      bounded. A row scan, labelled as one.
  count_only=True         just the total.

`group_by` only accepts dimensions FortiAnalyzer aggregates natively: srcip,
dstip, app, hostname, attack, policyid, dstcountry. Anything else is an error
that names sample_by -- there is no silent fallback, because a top-N over a
sample reads as fact.

`sample_by` takes a list, because one scan yields several independent
breakdowns (not a cross-tab). It accepts derived dimensions too: "port" is
proto/dstport, and "icmp_type_code" decodes the ICMP type and code that
FortiAnalyzer hides in the service field. `top_n` defaults to 10; `top_n=0`
returns every bucket.

Before quoting any sample_by number, read `is_exact`. When it is false,
`analysis_mode` is "bounded_sample" and `total_hits` is a floor, not a total.

analyze_policy_traffic is the same idea fanned out across policies: it takes
the same sample_by and top_n and reports each policy separately under a shared
query budget.
```

- [ ] **Step 4: Bump the version**

This is a breaking change. Bump the minor version in `pyproject.toml`, the
README badge, and the `CHANGELOG.md` heading. Read the current version first
rather than assuming:

```bash
grep -n '^version' pyproject.toml
grep -n 'version-' README.md | head -3
```

- [ ] **Step 5: Write the CHANGELOG entry with the migration table**

Under `## [Unreleased]`, add a `### Removed` block and extend `### Added`:

```markdown
### Added
- **Honest aggregation on `query_logs`: `group_by`, `sample_by` and `count_only`.** Three mutually exclusive parameters whose names carry the guarantee. `group_by="<dim>"` dispatches to the surface FortiAnalyzer aggregated itself — a FortiView view for logs (`srcip`→`top-sources`, `dstip`→`top-destinations`, `app`→`top-applications`, `hostname`/`website`→`top-websites`, `attack`/`threat`→`top-threats`, `policyid`→`policy-hits`, `dstcountry`→`top-countries`), a stats endpoint for alerts and incidents — and reports `is_exact: true` because the appliance counted every row. A dimension with no native surface is **refused**, with a message naming `sample_by`: there is deliberately no fallback to sampling, because a top-N over a 1000-row sample reads as fact and gets quoted as fact. `sample_by=["<dim>", …]` is that bounded path, carrying the existing contract verbatim (`is_exact`, `analysis_mode`, `total_hits`, `total_hits_is_known`, `total_hit_source`, `observed_hits`, `slices_scanned`, `truncated_slices`, `log_limit_per_slice`, `recommendation`); it takes a list because one scan yields several independent breakdowns rather than a cross-tab, and `top_n=0` returns every bucket. `count_only=True` returns the total alone. Two of the three together is `conflicting_aggregation`; `fields` alongside any of them warns rather than errors, since it describes a row shape no rows will be returned in. Two **derived dimensions** — `port` (`"{proto}/{dstport}"`) and `icmp_type_code` — survive the consolidation as first-class dimensions: FortiAnalyzer does not populate `icmptype`/`icmpcode` but encodes the pair in `service`, and a FortiGate SD-WAN SLA probe tags an ICMP packet with the probed application's name, so anything that is not one of the two known encodings becomes `type=unknown` rather than inventing a type that never crossed the wire.

### Removed
- **Thirteen tools consolidated into three (85 → 73).** Every removed tool's parameters are expressible on its replacement, so no capability is lost — but this is a **breaking change** to the tool surface. Migration:

  | Removed | Replacement |
  | --- | --- |
  | `get_top_sources` | `get_fortiview_data(view_name="top-sources")` or `query_logs(group_by="srcip")` |
  | `get_top_destinations` | `get_fortiview_data(view_name="top-destinations")` or `query_logs(group_by="dstip")` |
  | `get_top_applications` | `get_fortiview_data(view_name="top-applications")` or `query_logs(group_by="app")` |
  | `get_top_threats` | `get_fortiview_data(view_name="top-threats")` or `query_logs(group_by="attack")` |
  | `get_top_websites` | `get_fortiview_data(view_name="top-websites")` or `query_logs(group_by="hostname")` |
  | `get_top_cloud_applications` | `get_fortiview_data(view_name="top-cloud-applications")` |
  | `get_policy_hits` | `get_fortiview_data(view_name="policy-hits")` or `query_logs(group_by="policyid")` |
  | `search_traffic_logs` | `query_logs(logtype="traffic", filters=[…])` |
  | `search_security_logs` | `query_logs(logtype="attack", filters=[…])` |
  | `search_event_logs` | `query_logs(logtype="event", filters=[…])` |
  | `get_policy_traffic_profile` | `analyze_policy_traffic(policy_ids=[…])` (its three breakdowns are the default `sample_by`) |
  | `get_policy_port_analysis` | `analyze_policy_traffic(policy_ids=[…], sample_by=["port"], top_n=0)` |
  | `get_policy_protocol_summary` | `analyze_policy_traffic(policy_ids=[…], sample_by=["proto"])` |

  Seven of the removals were FortiView wrappers that differed from `get_fortiview_data` only in a hard-coded `view_name`; three were `query_logs` with a hand-built filter string, which is exactly what the `filters` surface removed; three were one bounded policy scan differing only in which breakdowns it aggregated, which is now `sample_by`. `tests/test_removed_tools.py` pairs every removed name with a working call to its replacement, so the suite cannot pass merely by having deleted something.

### Fixed
- **The dynamic-mode catalogue can no longer drift from what is registered.** `server.py::register_dynamic_tools` kept two hand-maintained structures — `tool_catalog` for search and `tool_map` for dispatch — neither derived from the registered tool set, and they had already diverged: `total_tools` reported 72 against 85 registered, `tool_catalog` omitted pcap/soar/ueba tools that `tool_map` could nonetheless execute, and neither listed `get_api_ratelimit`/`update_api_ratelimit`. A single `TOOL_CATALOGUE` constant replaces both, the reported total is computed rather than typed, and `execute_advanced_tool`'s dispatch map is derived from it. The catalogue stays static deliberately — deriving it would require importing every tool module inside `find_fortianalyzer_tool`, registering all of them and destroying the minimal surface dynamic mode exists for — so a parity test asserts it equals the registered set in both directions.
```

- [ ] **Step 6: Run everything**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
MASKING_ENABLED=true FAZ_MASKING_KEY=$(python3 -c "print('0'*64)") \
  FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
FAZ_SKILLS_ENABLED=true FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/ --ignore=tests/integration -q --no-cov
```
Expected: green; the masking run at its 10-failure baseline, no more.

Confirm the final tool count:

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run python -c "
import asyncio, fortianalyzer_mcp.server as s
print(len(asyncio.run(s.mcp.list_tools())), 'registered tools')
"
```
Expected: **73** (85 before this plan, minus 13, plus `analyze_policy_traffic`). Re-derive rather than trusting this number: if the surface grew again between the audit and your run, the arithmetic is `<measured> - 13 + 1`.

- [ ] **Step 7: Commit**

```bash
git add src/fortianalyzer_mcp/instructions.py tests/test_server_instructions.py \
  CHANGELOG.md pyproject.toml README.md
git commit -m "docs: document the aggregation surface and the 83-to-71 consolidation

The usage guide gains an Aggregation section stating the split the two names
exist to make: group_by is exact because the appliance counted it, sample_by is
a labelled bounded scan, and there is no silent fallback between them. The
tool-selection section stops naming thirteen tools that no longer exist -- a
guide that recommends a deleted tool sends every client straight to an error,
so a test asserts each removed name is absent.

CHANGELOG carries the full migration table, one row per removed tool. Minor
version bump: this is a breaking change to the tool surface, even though every
removed tool's parameters are expressible on its replacement."
```

---

## Self-Review

**Spec coverage.** This plan implements the spec's "`group_by` (native, exact) and `sample_by` (bounded, labelled)" section (Tasks 1-5), "Tool consolidation: 83 → 71" — in practice 85 → 73, see the header note (Tasks 5-7, 10), the skills-layer obligation (Task 8), the dynamic-mirror obligation (Task 9), the `instructions.py` correction for the new surface (Task 10), and guard tests #2 (catalogue parity, Task 9) and #4 (removed names are gone, Task 7). **Task 0 now closes three of the spec's six live-verification items** — item 2 (per-view sort columns), item 3 (the FortiView view catalogue) and item 4 (FortiView filterable fields versus logview's) — because Task 4 cannot be written honestly without item 4's answer. Item 1 (tier-2 operators) was largely closed during Plan 1's execution: `like` is proven on both dialects and `contain` proven inert. Items 5 (curated projections against live `logfields`) and 6 (OR in the array dialect) remain open and are not this plan's to close; `compile_to_array` already refuses `in` rather than guessing, which is the conservative branch item 6 asks for.

With Plans 1 and 2 this completes the spec.

**Three deliberate deviations from the spec, flagged for a reviewer.**

1. **The spec's parameter table gives `query_logs` and `fetch_more_logs` the full `group_by`/`sample_by`/`count_only` set.** This plan puts them on `query_logs` only. `fetch_more_logs` pages a stored search, and an aggregation returns no rows to page — a `sample_by` on page 2 would either re-aggregate the same window (identical answer, wasted scan) or aggregate one page's slice (a breakdown of an arbitrary window fragment, which is worse than useless). If a reviewer wants it, the honest form is an error directing the caller back to `query_logs`.
2. **`query_logs(sample_by=…)` scans one window, not multiple slices.** `traffic_tools` imports `_run_logsearch_page` from `log_tools`, so reusing the multi-slice fan-out from `log_tools` would be an import cycle. This matches the boundary the spec itself draws between the two aggregation entry points, and `analyze_policy_traffic` keeps the true multi-slice machinery — but it does mean `query_logs(sample_by=…)` is exact less often than the policy tool. The response says so through the same metadata, so nothing is over-claimed.
3. **`group_by` on `get_alerts`/`get_incidents` is resolved but not wired.** Task 2 produces `alert_stats`/`incident_stats` plans and tests them, but no task adds the parameter to those two tools. The spec's table asks for it. It is omitted because `get_alert_incident_stats` (`client.py:1196`) and `get_incident_stats` (`client.py:1732`) return a stats shape this plan has not verified against a live appliance, and inventing a `groups` mapping for an unverified response shape is the kind of guess the spec's honesty rules forbid elsewhere. The plan resolves cleanly, so wiring it is a small follow-up once the shape is confirmed — **report this gap when the plan completes** rather than letting it look finished.

**Placeholder scan.** No `TBD`/`TODO`. Two steps deliberately instruct rather than dictate: Task 5 Step 3 tells the implementer to copy the existing fan-out loop verbatim from the function being deleted (a move, not a rewrite, and transcribing 70 lines into this document would invite them to drift), and Task 9 Step 3 tells them to derive the catalogue's contents from `mcp.list_tools()` with a given command rather than listing 73 names that would be stale the moment the count changed. Both name the exact source and the exact command; neither leaves a decision open.

**Type consistency.** `GroupPlan` fields (`dimension`, `surface`, `target`, `all_devices_group`) are used with those names in Tasks 2 and 4. `UnsupportedGroupDimension` carries `.dimension` and `.supported` and subclasses `ValidationError`, so `log_tools`' existing `except ValidationError` still catches it — Task 4 catches the subclass first to produce the specific error code. `aggregate_breakdowns(rows, dimensions, top_n)` returns `dict[str, list[dict[str, Any]]]` in Task 3 and is consumed that way in Tasks 4 and 5. `dimension_value` returns `str | None` in Task 1 and its `None` is the skip signal in Task 3. `derive` raises `KeyError` for a non-derived name, which is why Task 5 guards with `is_derived` before calling `resolve_field`.

**Two risks flagged for the implementer.**

1. **Task 5 is the largest single task** — a new tool plus six deletions. If the fan-out transcription and the deletions cannot both be verified in one pass, split it: land `analyze_policy_traffic` alongside the old tools first (they can coexist; nothing shared is mutated), then delete in a second commit. The plan's task boundary is a suggestion here, not a constraint.
2. **Tasks 6 and 7 leave the suite red on purpose** — the skills layer still calls the removed FortiView tools until Task 8. That is deliberate, so each diff stays reviewable, but it means those two commits do not satisfy the "all gates clean at every commit" constraint for the *test* gate. The three CI gates (ruff, ruff format, mypy) must still be clean at each. If your workflow requires a green suite per commit, squash Tasks 6-8 into one.

## Reconciliation with HEAD (2026-07-28)

Verified against `627a138` (`upstream/main`) and corrected in place. The audit was first run on `pr/tool-ergonomics` at `627a138`; every number re-measured identically on `upstream/main`, which additionally carries #100 and the #102 `mcp<2` pin.

| # | What the plan said | What HEAD says | Fixed in |
| --- | --- | --- | --- |
| 1 | Consolidation is 83 → 71 | `mcp.list_tools()` returns **85**; all 13 removal targets present, so **85 → 73** | Goal, Task 9, Task 10, CHANGELOG, self-review |
| 2 | Predecessor commits `749a9c7`..`c1cdffc` | Squashed to `ab60ad8` + `627a138` | Predecessors |
| 3 | Plan 2 started from 1414 | **1545** | Global Constraints |
| 4 | Masking suite has 9 pre-existing failures | **10** | Global Constraints, Task 10 Step 6 |
| 5 | `search_*_logs` at :1213/:1325/:1423 | **:1236/:1350/:1459** | Task 7 Files |
| 6 | `handlers.py` call sites at :747, :816, :1251, :1342, :1480-1507, :1638-1653 | **:760/:829, :1268/:1359, :1497-1524, :1655-1670** | Task 8 Files and Step 2 |
| 7 | `server.py` anchors at :89, :105, :251, :406 | **:132, :148, :295, :463** | Task 9 Files |
| 8 | Nothing gated on live measurement | `group_by` forwards a filter to a view that may silently ignore it, returning an unfiltered top-N under `is_exact: true` | **New Task 0**, consumed by Task 4 |

**What the audit confirmed rather than changed** — worth recording, because these
are the anchors the plan leans on hardest:

- Every `traffic_tools` line number is still correct: `get_policy_traffic_profile`
  (:709), `get_policy_port_analysis` (:786), `get_policy_protocol_summary` (:856),
  the three `_aggregate_*` helpers (:433, :476, :544), `_run_bounded_policy_analysis`
  (:575), `_bounded_metadata` (:374), `_build_bounded_time_slices` (:173), plus
  `ANALYSIS_QUERY_BUDGET`/`MAX_POLICY_IDS` (:48-50) and `DEFAULT_TOP_N` (:51).
- Every `fortiview_tools` line number is still correct (:369, :410, :443, :481,
  :522, :555, :597).
- `VALID_FORTIVIEW_VIEWS` (`utils/validation.py:164-175`) contains all seven views
  `LOG_GROUP_SURFACES` maps to, **including `top-countries`** — so Task 2's
  `test_every_mapped_view_is_a_view_the_repo_accepts` passes without widening the
  allowlist.
- `error_response` takes `**extra`, so the `recommendation=` and `logtype=`
  keywords Tasks 4 and 5 pass are merged verbatim into the envelope.
- `filter_warnings` is in scope at `log_tools.py:531`, where Task 4 appends the
  inert-`fields` warning.

**One consequence of Plan 1's divergence.** Task 7's equivalence tests assert
compiled filter strings — `"dstport==443 and action==deny"`,
`"(severity==critical or severity==high)"`, `"level==warning"`. All three use `eq`
and `in`, which compile to symbols, so they are unaffected by `contains` now
emitting `like`. No change needed; noted so a reader does not go looking.
