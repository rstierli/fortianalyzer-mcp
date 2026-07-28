# Query Engine, Plan 1 of 3: Structured Filters Implementation Plan

> ## ✅ SHIPPED — historical record, do not execute
>
> Landed as PR #94 (`ab60ad8`, plus the follow-up `627a138`) on `pr/tool-ergonomics`.
> Kept for its reasoning, not as instructions.
>
> **Execution diverged from this document in ways that matter to a reader.** Live
> probing during the work disproved several of its assumptions, so the code is
> authoritative and this plan is not:
>
> | This plan says | What actually shipped |
> | --- | --- |
> | `contains` → `f contain v` / `["f","contain",v]` | `like` with `%` wildcards on **both** dialects — `contain` is accepted and matches zero rows |
> | `not_contains` → `f !contain v` | `!(f like "%v%")` on the string dialect; **refused** on the array dialect (no spelling works) |
> | `in` compiles on both dialects | **Refused** on the array dialect — no verified OR form |
> | `_TASK_STATE_CODES` (private) | Public `TASK_STATE_CODES`; `system_tools` imports it |
> | — | Three things this plan never anticipated: `canonical_log_field`, `enum_names`, and `_reject_substring_on_enum` (a substring op over an enum-coded field compiles to a wildcard over the integer — `%1%` matches state 1 *and* state 10 — so it is refused) |
>
> Read `src/fortianalyzer_mcp/query/filters.py` and `fields.py` for current
> behaviour. Plans 2 and 3 have been reconciled against that code; each carries a
> "Reconciliation with HEAD" section recording what changed.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Callers describe log and device filters as structured `{field, op, value}` conditions instead of hand-writing FortiAnalyzer filter strings, with one compiler owning operator spelling, value quoting, field aliases and enum coercion for both of the API's filter dialects.

**Architecture:** A new pure package `src/fortianalyzer_mcp/query/` holds a vocabulary registry (`fields.py`) and a two-dialect filter compiler (`filters.py`). Nothing in `query/` imports a client, `server.py`, or anything from `tools/` — it is data plus pure functions, so it cannot participate in the import-order constraint that `server.py`'s bottom import block depends on, and it tests without an appliance. Tools call the compiler, then feed the result into the request path they already use.

**Tech Stack:** Python 3.12, Pydantic v2 (already a dependency), `mcp` FastMCP, pytest + pytest-asyncio, ruff, mypy strict.

**Spec:** `docs/superpowers/specs/2026-07-25-query-engine-design.md`. This plan implements the "filter surface" section plus the filter-related cross-layer obligations. Projection (`fields`) is Plan 2; `group_by`/`sample_by` and the 83→71 consolidation are Plan 3.

## Global Constraints

- Python `>=3.12`. Target `py312`.
- **mypy strict**: `disallow_untyped_defs`, `disallow_incomplete_defs`, `warn_return_any`, `no_implicit_optional`. Every function needs annotations, including `-> None` on tests.
- **ruff** line-length 100, `E501` ignored (the formatter owns line length). Selected rules: `E`, `W`, `F`, `I`, `B`, `C4`, `UP`.
- Style: `isinstance(x, list | tuple)` (PEP 604 unions), `from __future__ import annotations` at the top of new modules.
- **`query/` must stay pure.** No imports from `fortianalyzer_mcp.tools`, `fortianalyzer_mcp.server`, or `fortianalyzer_mcp.api`. Importing from `fortianalyzer_mcp.utils` is fine.
- **Do not reorder** the tool-import block at the bottom of `server.py`.
- **NO AI attribution in commit messages.** `.github/workflows/no-ai-attribution.yml` fails any PR whose commits match `Co-Authored-By: Claude|Anthropic`, `noreply@anthropic.com`, `Generated with Claude`, or `🤖 Generated with`. This overrides any default commit template.
- Commit subjects: conventional-commit with scope, e.g. `feat(query): compile structured filter conditions to the string dialect`.
- **Test command** (note `PYTHONPATH=src` — the venv's editable install is not honoured on this machine; without it every test errors at collection with `ModuleNotFoundError: No module named 'fortianalyzer_mcp'`):

  ```bash
  FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
  ```

- **Baseline: 1328 passed.** (CLAUDE.md says 1280; that number is stale.) Every task must end at 1328 + the tests it added, with no failures.
- The three CI gates, all of which must be clean at every commit:

  ```bash
  uv run ruff check src/ tests/
  uv run ruff format --check src/ tests/
  PYTHONPATH=src uv run mypy src/
  ```

- `FORTIANALYZER_HOST` must be set for any test run: `server.py` calls `get_settings()` at import, so without it 22 files fail at *collection*.

## File Structure

| File | Responsibility |
| --- | --- |
| `src/fortianalyzer_mcp/query/__init__.py` | Public surface: re-export `FilterCondition`, `compile_to_string`, `compile_to_array`, `resolve_field`, `coerce_value`. |
| `src/fortianalyzer_mcp/query/fields.py` | The vocabulary registry: canonical field names, aliases, enum coercions, dialect, and whether the field set is complete. Data plus three pure lookups. |
| `src/fortianalyzer_mcp/query/filters.py` | `FilterCondition` and the two emitters. Owns operator spelling and value quoting. |
| `src/fortianalyzer_mcp/masking/unmask.py` | **Modify.** Add filter-condition handling that types each `value` by its sibling `field`. |
| `src/fortianalyzer_mcp/tools/log_tools.py` | **Modify.** `query_logs` gains `filters`, mutually exclusive with `filter`. |
| `src/fortianalyzer_mcp/tools/dvm_tools.py` | **Modify.** `search_devices` gains `filters`; its inline enum map moves to the registry. |
| `src/fortianalyzer_mcp/tools/system_tools.py` | **Modify.** `list_tasks` gains `filters`; its inline state map moves to the registry. |
| `src/fortianalyzer_mcp/tools/traffic_tools.py` | **Modify.** Delete the duplicate `sanitize_filter_value`. |
| `src/fortianalyzer_mcp/instructions.py` | **Modify.** Document `filters`; correct the operator claims to what is provable. |
| `tests/test_query_filters.py` | New. Compiler behaviour, both dialects. |
| `tests/test_query_fields.py` | New. Registry lookups, aliases, coercions, strictness. |
| `tests/test_masking_filter_conditions.py` | New. The measured masking behaviours. |

Projection lists will be added to `fields.py` in Plan 2; the registry is shaped for that from the start (a `Vocabulary` gains a `projection` attribute then).

---

### Task 1: The vocabulary registry

**Files:**
- Create: `src/fortianalyzer_mcp/query/__init__.py`
- Create: `src/fortianalyzer_mcp/query/fields.py`
- Test: `tests/test_query_fields.py`

**Interfaces:**
- Consumes: `fortianalyzer_mcp.utils.errors.ValidationError`.
- Produces:
  - `Vocabulary` frozen dataclass with `name: str`, `dialect: str`, `canonical: frozenset[str]`, `aliases: Mapping[str, str]`, `coercions: Mapping[str, Mapping[str, int]]`, `complete: bool`
  - `get_vocabulary(name: str) -> Vocabulary`
  - `resolve_field(vocabulary: str, name: str) -> tuple[str, str | None]` returning `(canonical, warning_or_None)`
  - `coerce_value(vocabulary: str, canonical_field: str, value: Any) -> Any`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_query_fields.py`:

```python
"""Tests for the query vocabulary registry."""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.query.fields import (
    coerce_value,
    get_vocabulary,
    resolve_field,
)
from fortianalyzer_mcp.utils.errors import ValidationError


class TestResolveField:
    """Canonical names, aliases, and the strict/non-strict split."""

    def test_canonical_name_resolves_to_itself(self) -> None:
        assert resolve_field("traffic", "srcip") == ("srcip", None)

    def test_alias_resolves_to_canonical(self) -> None:
        assert resolve_field("traffic", "source_ip") == ("srcip", None)

    def test_alias_resolution_is_case_insensitive(self) -> None:
        assert resolve_field("traffic", "Source_IP") == ("srcip", None)

    def test_canonical_wins_over_alias(self) -> None:
        """An alias may never shadow a real field name."""
        vocab = get_vocabulary("device")
        for alias in vocab.aliases:
            assert alias not in vocab.canonical, f"alias {alias!r} shadows a canonical field"

    def test_unknown_field_on_incomplete_vocabulary_warns_and_passes_through(self) -> None:
        canonical, warning = resolve_field("traffic", "some_unlisted_field")
        assert canonical == "some_unlisted_field"
        assert warning is not None
        assert "get_log_fields" in warning

    def test_unknown_field_on_complete_vocabulary_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            resolve_field("device", "definitely_not_a_field")
        assert "conn_status" in str(exc.value)

    def test_unregistered_logtype_falls_back_to_the_generic_log_vocabulary(self) -> None:
        canonical, warning = resolve_field("voip", "srcip")
        assert canonical == "srcip"
        assert warning is None


class TestCoerceValue:
    """LLM-friendly enum names become the codes FortiAnalyzer stores."""

    def test_device_connection_status_name_becomes_code(self) -> None:
        assert coerce_value("device", "conn_status", "down") == 2

    def test_coercion_is_case_insensitive(self) -> None:
        assert coerce_value("device", "conn_status", "UP") == 1

    def test_task_state_name_becomes_code(self) -> None:
        assert coerce_value("task", "state", "running") == 1

    def test_already_numeric_value_passes_through(self) -> None:
        assert coerce_value("device", "conn_status", 2) == 2

    def test_unknown_enum_name_raises_listing_valid_values(self) -> None:
        with pytest.raises(ValidationError) as exc:
            coerce_value("device", "conn_status", "sideways")
        message = str(exc.value)
        assert "up" in message and "down" in message

    def test_field_without_coercions_passes_value_through(self) -> None:
        assert coerce_value("traffic", "srcip", "10.0.0.1") == "10.0.0.1"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_fields.py -q --no-cov
```
Expected: collection error — `ModuleNotFoundError: No module named 'fortianalyzer_mcp.query'`.

- [ ] **Step 3: Write the implementation**

Create `src/fortianalyzer_mcp/query/__init__.py`:

```python
"""Pure query-shaping layer: vocabularies, filter compilation, response shaping.

Everything here is data and pure functions. No module in this package imports a
client, ``server``, or anything from ``tools`` -- so it cannot take part in the
import-time registration order that ``server.py``'s bottom import block relies
on, and it is testable without an appliance.

See docs/superpowers/specs/2026-07-25-query-engine-design.md.
"""

from fortianalyzer_mcp.query.fields import (
    Vocabulary,
    coerce_value,
    get_vocabulary,
    resolve_field,
)

__all__ = [
    "Vocabulary",
    "coerce_value",
    "get_vocabulary",
    "resolve_field",
]
```

Create `src/fortianalyzer_mcp/query/fields.py`:

```python
"""What is filterable in each FortiAnalyzer vocabulary, and under what names.

A "vocabulary" is one namespace of field names: a logtype (``traffic``,
``event``, ``attack``), or an object type in the dvmdb/task family (``device``,
``task``). Each records four things:

* **canonical** -- field names FortiAnalyzer itself uses. For the dvmdb-family
  vocabularies this set is enumerable and treated as complete; for logtypes it
  deliberately is not (see below).
* **aliases** -- the English an LLM reaches for (``source_ip``,
  ``destination_port``, ``application``) mapped onto the cryptic real name. A
  canonical name always wins over an alias, so adding an alias can never shadow
  a real field.
* **coercions** -- enum names mapped to the integer codes the appliance stores.
  ``search_devices`` and ``list_tasks`` each carried their own inline copy of
  one of these; centralising them means every caller translates identically.
* **complete** -- whether ``canonical`` is the whole truth. ``False`` for
  logtypes on purpose: the appliance publishes hundreds of fields per logtype
  via ``/logview/logfields`` and this module does not reproduce that catalogue,
  so an unrecognised log field is passed through with a warning rather than
  rejected on authority this module does not have. The dvmdb-family sets are
  small and stable, so an unknown name there is a genuine error.

Once the per-logtype catalogues are generated from a live appliance (a spec
verification item) the log vocabularies can flip to ``complete=True`` and
unknown-field rejection becomes uniform.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from fortianalyzer_mcp.utils.errors import ValidationError

# Fields every FortiGate log record carries, regardless of logtype. Used as the
# base of each log vocabulary and as the whole of the generic fallback.
_LOG_COMMON: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "itime",
        "eventtime",
        "devname",
        "devid",
        "vd",
        "logid",
        "type",
        "subtype",
        "level",
        "action",
        "srcip",
        "dstip",
        "msg",
        "user",
    }
)

_TRAFFIC_FIELDS: frozenset[str] = _LOG_COMMON | {
    "srcport",
    "dstport",
    "proto",
    "policyid",
    "service",
    "app",
    "appcat",
    "srcintf",
    "dstintf",
    "sentbyte",
    "rcvdbyte",
    "duration",
    "sessionid",
    "srccountry",
    "dstcountry",
    "unauthuser",
    "hostname",
    "dstname",
}

_EVENT_FIELDS: frozenset[str] = _LOG_COMMON | {
    "ui",
    "cfgpath",
    "cfgattr",
    "status",
}

# Field names proven by the IPS filters in pcap_tools.search_ips_logs.
_ATTACK_FIELDS: frozenset[str] = _LOG_COMMON | {
    "severity",
    "attack",
    "attackid",
    "srcport",
    "dstport",
    "proto",
    "service",
    "sessionid",
    "pcapurl",
    "cve",
    "ref",
    "policyid",
    "hostname",
    "url",
    "profile",
}

# Aliases shared by every log vocabulary. Kept in one dict so a name means the
# same thing in every logtype. Deliberately omitted: bare "country" and "port",
# which are ambiguous between src and dst -- an ambiguous alias silently filters
# on the wrong dimension, which is worse than an unknown-field warning.
_LOG_ALIASES: Mapping[str, str] = {
    "source_ip": "srcip",
    "src_ip": "srcip",
    "destination_ip": "dstip",
    "dest_ip": "dstip",
    "dst_ip": "dstip",
    "source_port": "srcport",
    "src_port": "srcport",
    "destination_port": "dstport",
    "dest_port": "dstport",
    "dst_port": "dstport",
    "protocol": "proto",
    "application": "app",
    "application_category": "appcat",
    "policy_id": "policyid",
    "session_id": "sessionid",
    "username": "user",
    "user_name": "user",
    "device_name": "devname",
    "device_id": "devid",
    "source_interface": "srcintf",
    "destination_interface": "dstintf",
    "bytes_sent": "sentbyte",
    "sent_bytes": "sentbyte",
    "bytes_received": "rcvdbyte",
    "received_bytes": "rcvdbyte",
    "attack_name": "attack",
    "source_country": "srccountry",
    "destination_country": "dstcountry",
    "message": "msg",
}

_DEVICE_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "ip",
        "sn",
        "hostname",
        "desc",
        "os_ver",
        "mr",
        "patch",
        "platform_str",
        "conn_status",
        "dev_status",
        "mgmt_mode",
        "adm_usr",
        "vdom",
        "hdisk_size",
        "build",
    }
)

_DEVICE_ALIASES: Mapping[str, str] = {
    "device_name": "name",
    "serial": "sn",
    "serial_number": "sn",
    "os_version": "os_ver",
    "platform": "platform_str",
    "connection_status": "conn_status",
    "description": "desc",
}

# DVMDB stores conn_status as an integer. Moved here from the inline map in
# dvm_tools.search_devices.
_CONN_STATUS_CODES: Mapping[str, int] = {"unknown": 0, "up": 1, "down": 2}

_TASK_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "title",
        "src",
        "user",
        "adom",
        "state",
        "percent",
        "num_done",
        "num_err",
        "num_lines",
        "num_warn",
        "start_tm",
        "end_tm",
    }
)

_TASK_ALIASES: Mapping[str, str] = {
    "task_id": "id",
    "status": "state",
    "progress": "percent",
}

# Mirrors system_tools._TASK_STATE_NAMES, inverted. Kept in sync by
# tests/test_query_fields.py::test_task_state_codes_match_system_tools.
_TASK_STATE_CODES: Mapping[str, int] = {
    "pending": 0,
    "running": 1,
    "cancelling": 2,
    "cancelled": 3,
    "done": 4,
    "error": 5,
    "aborting": 6,
    "aborted": 7,
    "warning": 8,
    "to_continue": 9,
    "unknown": 10,
}

_NO_COERCIONS: Mapping[str, Mapping[str, int]] = {}


@dataclass(frozen=True)
class Vocabulary:
    """One filterable namespace and everything known about its field names."""

    name: str
    dialect: str
    canonical: frozenset[str]
    aliases: Mapping[str, str]
    coercions: Mapping[str, Mapping[str, int]]
    complete: bool


_GENERIC_LOG = Vocabulary(
    name="log",
    dialect="string",
    canonical=_LOG_COMMON,
    aliases=_LOG_ALIASES,
    coercions=_NO_COERCIONS,
    complete=False,
)

_VOCABULARIES: Mapping[str, Vocabulary] = {
    "traffic": Vocabulary(
        name="traffic",
        dialect="string",
        canonical=_TRAFFIC_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
    ),
    "event": Vocabulary(
        name="event",
        dialect="string",
        canonical=_EVENT_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
    ),
    "attack": Vocabulary(
        name="attack",
        dialect="string",
        canonical=_ATTACK_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
    ),
    "device": Vocabulary(
        name="device",
        dialect="array",
        canonical=_DEVICE_FIELDS,
        aliases=_DEVICE_ALIASES,
        coercions={"conn_status": _CONN_STATUS_CODES},
        complete=True,
    ),
    "task": Vocabulary(
        name="task",
        dialect="array",
        canonical=_TASK_FIELDS,
        aliases=_TASK_ALIASES,
        coercions={"state": _TASK_STATE_CODES},
        complete=True,
    ),
}


def get_vocabulary(name: str) -> Vocabulary:
    """Return the vocabulary for a logtype or object type.

    An unregistered name falls back to the generic log vocabulary, so a logtype
    with no curated field set (``voip``, ``icap``, ``dlp``, ...) still gets
    aliases and the common-field core rather than an error.
    """
    return _VOCABULARIES.get(name.strip().lower(), _GENERIC_LOG)


def resolve_field(vocabulary: str, name: str) -> tuple[str, str | None]:
    """Resolve a caller-supplied field name to its canonical FAZ spelling.

    Returns ``(canonical_name, warning_or_None)``.

    Raises:
        ValidationError: if the vocabulary enumerates its fields
            (``complete=True``) and the name is neither canonical nor an alias.
    """
    vocab = get_vocabulary(vocabulary)
    lowered = name.strip().lower()

    if lowered in vocab.canonical:
        return lowered, None
    if lowered in vocab.aliases:
        return vocab.aliases[lowered], None

    if vocab.complete:
        valid = ", ".join(sorted(vocab.canonical))
        raise ValidationError(
            f"Unknown field '{name}' for {vocab.name}. Valid fields: {valid}"
        )

    return lowered, (
        f"field '{name}' is not in the known {vocab.name} field set; passing it through "
        f"to FortiAnalyzer. Confirm the spelling with "
        f'get_log_fields(logtype="{vocab.name}", name_filter="...").'
    )


def coerce_value(vocabulary: str, canonical_field: str, value: Any) -> Any:
    """Translate an enum name to the integer code FortiAnalyzer stores.

    Values that are not strings pass through untouched, so a caller who already
    knows the code can supply it directly.

    Raises:
        ValidationError: if the field has an enum mapping and the string is not
            one of its names.
    """
    vocab = get_vocabulary(vocabulary)
    mapping = vocab.coercions.get(canonical_field)
    if mapping is None or not isinstance(value, str):
        return value

    code = mapping.get(value.strip().lower())
    if code is None:
        valid = ", ".join(sorted(mapping))
        raise ValidationError(
            f"Invalid value '{value}' for {canonical_field}. Must be one of: {valid}"
        )
    return code
```

- [ ] **Step 4: Add the drift guard test**

Append to `tests/test_query_fields.py`:

```python
class TestRegistryMatchesTheToolsItReplaces:
    """The registry duplicates two enum maps; assert they cannot drift apart."""

    def test_task_state_codes_match_system_tools(self) -> None:
        from fortianalyzer_mcp.query.fields import _TASK_STATE_CODES
        from fortianalyzer_mcp.tools.system_tools import _TASK_STATE_CODES as TOOL_CODES

        assert dict(_TASK_STATE_CODES) == dict(TOOL_CODES)

    def test_conn_status_codes_cover_the_documented_names(self) -> None:
        from fortianalyzer_mcp.query.fields import _CONN_STATUS_CODES

        assert dict(_CONN_STATUS_CODES) == {"unknown": 0, "up": 1, "down": 2}
```

- [ ] **Step 5: Run the tests and the gates**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_fields.py -q --no-cov
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: all new tests PASS, all three gates clean.

- [ ] **Step 6: Run the full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: `1328 + <new count> passed`, 0 failed.

- [ ] **Step 7: Commit**

```bash
git add src/fortianalyzer_mcp/query/ tests/test_query_fields.py
git commit -m "feat(query): a vocabulary registry for filterable field names

Field names, the English aliases an LLM reaches for, and the enum coercions
that search_devices and list_tasks each carried inline. Logtype vocabularies
are marked incomplete on purpose: the appliance publishes hundreds of fields
per logtype and this module does not reproduce that catalogue, so an
unrecognised log field passes through with a warning rather than being
rejected on authority the module does not have. The dvmdb-family sets are
small and stable, so an unknown name there is a real error."
```

---

### Task 2: The string-dialect compiler

**Files:**
- Create: `src/fortianalyzer_mcp/query/filters.py`
- Modify: `src/fortianalyzer_mcp/query/__init__.py`
- Test: `tests/test_query_filters.py`

**Interfaces:**
- Consumes: `resolve_field`, `coerce_value` from Task 1; `sanitize_filter_value` and `ValidationError` from `fortianalyzer_mcp.utils.validation`.
- Produces:
  - `FilterOp` = `Literal["eq","ne","gt","gte","lt","lte","contains","not_contains","in","not_in"]`
  - `FilterCondition` Pydantic model with `field: str`, `op: FilterOp = "eq"`, `value: str | bool | int | float | list[str | int]`
  - `compile_to_string(conditions: Sequence[FilterCondition], vocabulary: str) -> tuple[str, list[str]]`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_query_filters.py`:

```python
"""Tests for the structured filter compiler."""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.query.filters import FilterCondition, compile_to_string
from fortianalyzer_mcp.utils.errors import ValidationError


def _c(field: str, op: str = "eq", value: object = "x") -> FilterCondition:
    """Build one condition without repeating the keyword names everywhere."""
    return FilterCondition(field=field, op=op, value=value)  # type: ignore[arg-type]


class TestStringDialectOperators:
    """Each op emits the spelling this repo has working evidence for."""

    @pytest.mark.parametrize(
        "op,expected",
        [
            ("eq", "srcip==10.0.0.1"),
            ("ne", "srcip!=10.0.0.1"),
            ("gt", "srcip>10.0.0.1"),
            ("gte", "srcip>=10.0.0.1"),
            ("lt", "srcip<10.0.0.1"),
            ("lte", "srcip<=10.0.0.1"),
        ],
    )
    def test_symbol_operators_emit_without_spaces(self, op: str, expected: str) -> None:
        result, _ = compile_to_string([_c("srcip", op, "10.0.0.1")], "traffic")
        assert result == expected

    def test_contains_emits_the_word_operator_with_spaces(self) -> None:
        result, _ = compile_to_string([_c("attack", "contains", "Botnet")], "attack")
        assert result == "attack contain Botnet"

    def test_not_contains_emits_the_negated_word_operator(self) -> None:
        result, _ = compile_to_string([_c("attack", "not_contains", "Botnet")], "attack")
        assert result == "attack !contain Botnet"


class TestStringDialectCombination:
    """AND across conditions, parenthesised OR within one field."""

    def test_multiple_conditions_are_anded(self) -> None:
        result, _ = compile_to_string(
            [_c("srcip", "eq", "10.0.0.1"), _c("dstport", "eq", 443)], "traffic"
        )
        assert result == "srcip==10.0.0.1 and dstport==443"

    def test_in_emits_a_parenthesised_or_group(self) -> None:
        result, _ = compile_to_string([_c("dstport", "in", [80, 443])], "traffic")
        assert result == "(dstport==80 or dstport==443)"

    def test_not_in_emits_a_parenthesised_and_group(self) -> None:
        result, _ = compile_to_string([_c("dstport", "not_in", [80, 443])], "traffic")
        assert result == "(dstport!=80 and dstport!=443)"

    def test_in_combines_with_a_sibling_condition(self) -> None:
        result, _ = compile_to_string(
            [_c("srcip", "eq", "10.0.0.1"), _c("dstport", "in", [80, 443])], "traffic"
        )
        assert result == "srcip==10.0.0.1 and (dstport==80 or dstport==443)"

    def test_no_conditions_compiles_to_an_empty_filter(self) -> None:
        result, warnings = compile_to_string([], "traffic")
        assert result == ""
        assert warnings == []


class TestValueHandling:
    """Quoting is the string dialect's injection boundary."""

    def test_plain_values_are_left_unquoted(self) -> None:
        result, _ = compile_to_string([_c("srcip", "eq", "10.0.0.1")], "traffic")
        assert result == "srcip==10.0.0.1"

    def test_ipv6_literals_are_not_quoted(self) -> None:
        """The traffic_tools sanitiser copy quoted these; the survivor does not."""
        result, _ = compile_to_string([_c("srcip", "eq", "2001:db8::1")], "traffic")
        assert result == "srcip==2001:db8::1"

    def test_values_with_spaces_are_quoted(self) -> None:
        result, _ = compile_to_string([_c("attack", "contains", "Remote Code")], "attack")
        assert result == 'attack contain "Remote Code"'

    def test_injection_attempt_is_neutralised_by_quoting(self) -> None:
        result, _ = compile_to_string([_c("srcip", "eq", '1.1.1.1" or 1==1 or "')], "traffic")
        assert result.startswith("srcip==\"")
        assert result.count('\\"') >= 1

    def test_integer_values_survive_as_numbers(self) -> None:
        result, _ = compile_to_string([_c("dstport", "eq", 443)], "traffic")
        assert result == "dstport==443"


class TestInputRejection:
    """Bad input fails locally with a message that says what to do."""

    def test_scalar_op_with_a_list_value_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("dstport", "eq", [80, 443])], "traffic")
        assert "'in'" in str(exc.value)

    def test_in_with_a_scalar_value_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("dstport", "in", 80)], "traffic")
        assert "list" in str(exc.value)

    def test_in_with_an_empty_list_raises(self) -> None:
        with pytest.raises(ValidationError):
            compile_to_string([_c("dstport", "in", [])], "traffic")

    def test_boolean_value_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_string([_c("srcip", "eq", True)], "traffic")
        assert "boolean" in str(exc.value).lower()

    def test_unknown_op_is_rejected_by_the_model(self) -> None:
        with pytest.raises(Exception):
            FilterCondition(field="srcip", op="matches", value="x")  # type: ignore[arg-type]

    def test_extra_keys_are_rejected_by_the_model(self) -> None:
        with pytest.raises(Exception):
            FilterCondition(field="srcip", op="eq", value="x", extra="nope")  # type: ignore[call-arg]


class TestFieldResolution:
    """The compiler resolves names through the registry."""

    def test_alias_is_compiled_to_the_canonical_name(self) -> None:
        result, _ = compile_to_string([_c("source_ip", "eq", "10.0.0.1")], "traffic")
        assert result == "srcip==10.0.0.1"

    def test_unknown_log_field_passes_through_with_a_warning(self) -> None:
        result, warnings = compile_to_string([_c("weird_field", "eq", "x")], "traffic")
        assert result == "weird_field==x"
        assert len(warnings) == 1
        assert "get_log_fields" in warnings[0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_filters.py -q --no-cov
```
Expected: collection error — `ModuleNotFoundError: No module named 'fortianalyzer_mcp.query.filters'`.

- [ ] **Step 3: Write the implementation**

Create `src/fortianalyzer_mcp/query/filters.py`:

```python
"""Structured filter conditions, compiled to FortiAnalyzer's filter dialects.

FortiAnalyzer speaks two unrelated filter syntaxes and this module owns both:

* the **string dialect** -- logview, fortiview, eventmgmt, incidentmgmt:
  ``"srcip==10.0.0.1 and dstport==443"``, with parenthesised OR groups.
* the **array dialect** -- dvmdb, config, task:
  ``[["name", "contain", "fgt"], ["conn_status", "==", 2]]``, entries
  implicitly ANDed.

Callers describe a query once as ``FilterCondition`` objects; this module emits
whichever dialect the endpoint speaks. That is what makes operator spelling
consistent: before this existed the repo spelled "contains" two ways
(``attack contain X`` in log_tools, ``attack=*X*`` in pcap_tools) and carried
two sanitisers with different safe-character classes.

Only operator spellings with working evidence against a live appliance are
emitted. FortiAnalyzer 7.0.1 also documents ``like``, ``~``, ``!~``, ``isnull``,
``isnotnull`` and ``<>`` for its Log View parser, but none is exercised through
JSON-RPC anywhere in this repo, so they are deliberately absent until a live
check confirms them -- see the spec's verification items. The op set is data, so
adding one later is a one-line change.

Quoting is a *string-dialect* concern only. Array-dialect values travel as JSON
scalars and are never interpolated into a string, so they need no escaping.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict

from fortianalyzer_mcp.query.fields import coerce_value, resolve_field
from fortianalyzer_mcp.utils.validation import ValidationError, sanitize_filter_value

FilterOp = Literal[
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "not_contains",
    "in",
    "not_in",
]

#: Ops that emit as a symbol with no surrounding spaces (``srcip==1.2.3.4``).
_SYMBOL_OPS: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
}

#: Ops that emit as a bare word and need spaces (``attack contain Botnet``).
_WORD_OPS: dict[str, str] = {
    "contains": "contain",
    "not_contains": "!contain",
}

_MULTI_VALUE_OPS = frozenset({"in", "not_in"})


class FilterCondition(BaseModel):
    """One field/operator/value condition, independent of dialect.

    A Pydantic model rather than a dict so FastMCP publishes a real JSON schema
    for it -- including the ``op`` enum, which is what stops an invalid operator
    at the protocol boundary instead of at the appliance.
    """

    model_config = ConfigDict(extra="forbid")

    field: str
    op: FilterOp = "eq"
    value: str | bool | int | float | list[str | int]


def _reject_bool(field: str, value: object) -> None:
    """Reject booleans. ``bool`` is a subclass of ``int``, so check it first."""
    if isinstance(value, bool):
        raise ValidationError(
            f"Filter on '{field}' has a boolean value. FortiAnalyzer filters compare "
            "against text or numbers -- pass the concrete value instead."
        )


def _scalar(condition: FilterCondition) -> str | int | float:
    """Return the single value for a scalar op."""
    value = condition.value
    if isinstance(value, list):
        raise ValidationError(
            f"Filter on '{condition.field}' with op '{condition.op}' takes one value, not "
            "a list. Use op 'in' or 'not_in' for multiple values."
        )
    _reject_bool(condition.field, value)
    return value


def _values(condition: FilterCondition) -> list[str | int]:
    """Return the value list for ``in``/``not_in``."""
    value = condition.value
    if not isinstance(value, list):
        raise ValidationError(
            f"Filter on '{condition.field}' with op '{condition.op}' takes a list of "
            "values, not a single value."
        )
    if not value:
        raise ValidationError(
            f"Filter on '{condition.field}' has an empty value list; nothing to match."
        )
    for item in value:
        _reject_bool(condition.field, item)
    return list(value)


def _quote(value: str | int | float, field: str) -> str:
    """Sanitise one value for interpolation into the string dialect."""
    return sanitize_filter_value(str(value), field)


def compile_to_string(
    conditions: Sequence[FilterCondition],
    vocabulary: str,
) -> tuple[str, list[str]]:
    """Compile conditions into the string dialect, ANDed together.

    ``in``/``not_in`` become parenthesised groups. Parentheses are supported:
    the administration guide documents
    ``dstip==192.168.1.168 and ( dstport == 514 or dstport == 515 )``, and this
    repo already ships ``(severity="critical" or severity="high")``.

    Args:
        conditions: The conditions to compile. Empty yields an empty filter.
        vocabulary: The logtype or object type whose field names apply.

    Returns:
        ``(filter_string, warnings)``. ``warnings`` holds one entry per field
        name that was passed through unrecognised.

    Raises:
        ValidationError: on a value/op mismatch, a boolean value, or an unknown
            field in a vocabulary that enumerates its fields.
    """
    clauses: list[str] = []
    warnings: list[str] = []

    for condition in conditions:
        field, warning = resolve_field(vocabulary, condition.field)
        if warning:
            warnings.append(warning)

        op = condition.op
        if op in _MULTI_VALUE_OPS:
            values = [coerce_value(vocabulary, field, v) for v in _values(condition)]
            if op == "in":
                inner = " or ".join(f"{field}=={_quote(v, field)}" for v in values)
            else:
                inner = " and ".join(f"{field}!={_quote(v, field)}" for v in values)
            clauses.append(f"({inner})")
            continue

        value = coerce_value(vocabulary, field, _scalar(condition))
        if op in _SYMBOL_OPS:
            clauses.append(f"{field}{_SYMBOL_OPS[op]}{_quote(value, field)}")
        else:
            clauses.append(f"{field} {_WORD_OPS[op]} {_quote(value, field)}")

    return " and ".join(clauses), warnings
```

Then extend `src/fortianalyzer_mcp/query/__init__.py`:

```python
from fortianalyzer_mcp.query.fields import (
    Vocabulary,
    coerce_value,
    get_vocabulary,
    resolve_field,
)
from fortianalyzer_mcp.query.filters import (
    FilterCondition,
    FilterOp,
    compile_to_string,
)

__all__ = [
    "FilterCondition",
    "FilterOp",
    "Vocabulary",
    "coerce_value",
    "compile_to_string",
    "get_vocabulary",
    "resolve_field",
]
```

- [ ] **Step 4: Run the tests**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_filters.py -q --no-cov
```
Expected: all PASS. If `test_ipv6_literals_are_not_quoted` fails, check that you imported `sanitize_filter_value` from `utils.validation` (whose safe class includes `:`) and not the `traffic_tools` copy.

- [ ] **Step 5: Run the gates and the full suite**

```bash
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: gates clean, suite green.

- [ ] **Step 6: Commit**

```bash
git add src/fortianalyzer_mcp/query/ tests/test_query_filters.py
git commit -m "feat(query): compile structured conditions to the string filter dialect

One FilterCondition model, ten ops, ANDed clauses with parenthesised OR
groups for in/not_in. Only spellings with working evidence against a live
appliance are emitted; the operators 7.0.1 documents for the Log View parser
but that nothing here exercises through JSON-RPC (like, ~, isnull, isnotnull,
<>) are held back until a live check confirms them.

Pydantic rather than a dict so FastMCP publishes the op enum in the tool
schema, which rejects an invalid operator at the protocol boundary instead of
at the appliance."
```

---

### Task 3: The array-dialect compiler

**Files:**
- Modify: `src/fortianalyzer_mcp/query/filters.py`
- Modify: `src/fortianalyzer_mcp/query/__init__.py`
- Test: `tests/test_query_filters.py`

**Interfaces:**
- Produces: `compile_to_array(conditions: Sequence[FilterCondition], vocabulary: str) -> tuple[list[list[object]], list[str]]`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_query_filters.py`:

```python
class TestArrayDialect:
    """dvmdb/config/task take a list of [field, op, value] entries, ANDed."""

    def test_eq_emits_one_entry(self) -> None:
        result, _ = compile_to_array([_c("name", "eq", "fgt-01")], "device")
        assert result == [["name", "==", "fgt-01"]]

    def test_contains_uses_the_appliance_word_operator(self) -> None:
        result, _ = compile_to_array([_c("name", "contains", "fgt")], "device")
        assert result == [["name", "contain", "fgt"]]

    def test_multiple_conditions_become_multiple_entries(self) -> None:
        result, _ = compile_to_array(
            [_c("name", "contains", "fgt"), _c("os_ver", "contains", "7.")], "device"
        )
        assert result == [["name", "contain", "fgt"], ["os_ver", "contain", "7."]]

    def test_enum_name_is_coerced_to_its_code(self) -> None:
        result, _ = compile_to_array([_c("conn_status", "eq", "down")], "device")
        assert result == [["conn_status", "==", 2]]

    def test_task_state_name_is_coerced_to_its_code(self) -> None:
        result, _ = compile_to_array([_c("state", "eq", "running")], "task")
        assert result == [["state", "==", 1]]

    def test_alias_resolves_before_emitting(self) -> None:
        result, _ = compile_to_array([_c("serial_number", "eq", "FG100F0000")], "device")
        assert result == [["sn", "==", "FG100F0000"]]

    def test_values_are_not_quoted_because_they_travel_as_json(self) -> None:
        result, _ = compile_to_array([_c("desc", "eq", 'has "quotes" and spaces')], "device")
        assert result == [["desc", "==", 'has "quotes" and spaces']]

    def test_not_in_becomes_one_negated_entry_per_value(self) -> None:
        result, _ = compile_to_array([_c("name", "not_in", ["a", "b"])], "device")
        assert result == [["name", "!=", "a"], ["name", "!=", "b"]]

    def test_in_is_refused_rather_than_guessed(self) -> None:
        with pytest.raises(ValidationError) as exc:
            compile_to_array([_c("name", "in", ["a", "b"])], "device")
        assert "one call per value" in str(exc.value)

    def test_no_conditions_compiles_to_an_empty_list(self) -> None:
        result, warnings = compile_to_array([], "device")
        assert result == []
        assert warnings == []

    def test_unknown_device_field_raises_because_the_set_is_complete(self) -> None:
        with pytest.raises(ValidationError):
            compile_to_array([_c("not_a_device_field", "eq", "x")], "device")
```

Add the import at the top of the file:

```python
from fortianalyzer_mcp.query.filters import (
    FilterCondition,
    compile_to_array,
    compile_to_string,
)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_filters.py -q --no-cov
```
Expected: `ImportError: cannot import name 'compile_to_array'`.

- [ ] **Step 3: Write the implementation**

Append to `src/fortianalyzer_mcp/query/filters.py`:

```python
#: Array-dialect operator spellings. ``search_devices`` proves ``==`` and
#: ``contain`` against a live appliance; the comparison operators follow the
#: same FortiManager grammar.
_ARRAY_OPS: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
    "contains": "contain",
    "not_contains": "!contain",
}


def compile_to_array(
    conditions: Sequence[FilterCondition],
    vocabulary: str,
) -> tuple[list[list[object]], list[str]]:
    """Compile conditions into the array dialect (dvmdb, config, task).

    Entries are implicitly ANDed, the only combining form proven here --
    ``search_devices`` and ``list_tasks`` both rely on it. Values are *not*
    quoted or escaped: they travel as JSON scalars and are never interpolated
    into a filter string, so the string dialect's injection boundary does not
    apply.

    ``in`` is refused rather than guessed. Its explicit OR-separator syntax is
    documented for FortiManager but unexercised in this repo, and the tempting
    fallback -- one ``contain`` over a shared prefix -- is wrong, because it
    silently matches values the caller never asked for.

    Returns:
        ``(entries, warnings)``.

    Raises:
        ValidationError: on ``in``, a value/op mismatch, a boolean value, or an
            unknown field.
    """
    entries: list[list[object]] = []
    warnings: list[str] = []

    for condition in conditions:
        field, warning = resolve_field(vocabulary, condition.field)
        if warning:
            warnings.append(warning)

        op = condition.op
        if op in _ARRAY_OPS:
            value = coerce_value(vocabulary, field, _scalar(condition))
            entries.append([field, _ARRAY_OPS[op], value])
            continue

        if op == "not_in":
            for item in _values(condition):
                entries.append([field, "!=", coerce_value(vocabulary, field, item)])
            continue

        raise ValidationError(
            f"Filter op '{op}' on '{field}' is not supported against this endpoint. "
            "Issue one call per value instead."
        )

    return entries, warnings
```

Add `compile_to_array` to the `query/__init__.py` imports and `__all__`.

- [ ] **Step 4: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_filters.py -q --no-cov
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: all PASS, gates clean.

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/query/ tests/test_query_filters.py
git commit -m "feat(query): compile structured conditions to the array filter dialect

dvmdb, config and task take [field, op, value] entries, implicitly ANDed --
the only combining form proven against the appliance here. Values travel as
JSON scalars, so unlike the string dialect they are never quoted or escaped.

in is refused rather than guessed: its explicit OR-separator syntax is
documented for FortiManager but unexercised here, and the tempting fallback
of one contain over a shared prefix silently matches values the caller never
asked for."
```

---

### Task 4: Filter-aware unmasking

**Files:**
- Modify: `src/fortianalyzer_mcp/masking/unmask.py`
- Test: `tests/test_masking_filter_conditions.py`

**Why this precedes any tool wiring:** with masking enabled, a `FilterCondition` carrying a masked IP would reach the appliance **unresolved**, and a masked IP is format-preserving and unmarked. The query would succeed and return real logs *for a different host*. Three behaviours, each measured against current code before this plan was written:

- `unmask_args({"srcip": "137.154.78.119"})` → resolves (the dict key types the value)
- `unmask_args({"field": "srcip", "op": "eq", "value": "137.154.78.119"})` → **does not resolve** (the key is `value`, which carries no type)
- a `BaseModel` instance in a list → **passes through untouched** (`_unmask_any` handles `dict`/`list`/`str` only)

**Interfaces:**
- Consumes: the existing `ArgUnmasker.resolve_scalar`, `FIELD_TYPES`, `COMPOSITE_URL_FULL`, `COMPOSITE_PREFIXED`.
- Produces: `ArgUnmasker.unmask_filter_conditions(value: Any) -> Any`, invoked from `_unmask_any` and `_unmask_entry`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_masking_filter_conditions.py`:

```python
"""Masked values inside structured filter conditions must resolve.

A masked IP is format-preserving and unmarked, so only the sibling `field` key
identifies it as an IP. Without that, a masked filter reaches the appliance as
a valid-but-different address and returns real logs for the wrong host.
"""

from __future__ import annotations

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.unmask import ArgUnmasker
from fortianalyzer_mcp.query.filters import FilterCondition

KEY = "0" * 64


def _engine() -> FPEEngine:
    return FPEEngine(KEY)


class TestFilterConditionDicts:
    """The dict form, as it arrives before model validation."""

    def test_masked_ip_resolves_using_the_sibling_field(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_ip("10.0.0.5")
        assert token != "10.0.0.5", "precondition: the IP must actually be masked"

        result = unmasker.unmask_args(
            {"filters": [{"field": "srcip", "op": "eq", "value": token}]}
        )

        assert result["filters"][0]["value"] == "10.0.0.5"

    def test_masked_username_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")

        result = unmasker.unmask_args(
            {"filters": [{"field": "user", "op": "eq", "value": token}]}
        )

        assert result["filters"][0]["value"] == "jdoe"

    def test_masked_mac_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_mac("00:11:22:33:44:55")

        result = unmasker.unmask_args(
            {"filters": [{"field": "srcmac", "op": "eq", "value": token}]}
        )

        assert result["filters"][0]["value"] == "00:11:22:33:44:55"

    def test_list_values_resolve_elementwise(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        tokens = [engine.mask_ip("10.0.0.5"), engine.mask_ip("10.0.0.6")]

        result = unmasker.unmask_args(
            {"filters": [{"field": "srcip", "op": "in", "value": tokens}]}
        )

        assert result["filters"][0]["value"] == ["10.0.0.5", "10.0.0.6"]

    def test_unmasked_value_is_left_alone(self) -> None:
        unmasker = ArgUnmasker(_engine())
        result = unmasker.unmask_args(
            {"filters": [{"field": "dstport", "op": "eq", "value": 443}]}
        )
        assert result["filters"][0]["value"] == 443


class TestFilterConditionModels:
    """The model form, which is what FastMCP passes to the tool."""

    def test_model_instance_is_resolved_and_stays_a_model(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_ip("10.0.0.5")

        result = unmasker.unmask_args(
            {"filters": [FilterCondition(field="srcip", op="eq", value=token)]}
        )

        condition = result["filters"][0]
        assert isinstance(condition, FilterCondition)
        assert condition.value == "10.0.0.5"
        assert condition.field == "srcip"
        assert condition.op == "eq"


class TestMeasuredStringFilterBehaviour:
    """Freeze what unmask_filter does today, including what it cannot do.

    The embedded-token case is asserted as broken on purpose: it predates this
    work, a compiler cannot turn a phrase into a token, and fixing it needs
    substring resolution inside resolve_scalar. Asserting it keeps the
    limitation visible and forces a future fix to update this test knowingly.
    """

    def test_quoted_token_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")
        assert unmasker.unmask_filter(f'user=="{token}"') == 'user=="jdoe"'

    def test_bare_token_resolves(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")
        assert unmasker.unmask_filter(f"user=={token}") == "user==jdoe"

    def test_token_embedded_in_a_quoted_phrase_does_not_resolve(self) -> None:
        engine = _engine()
        unmasker = ArgUnmasker(engine)
        token = engine.mask_username("jdoe")
        expression = f'msg contain "login failed for {token}"'
        assert unmasker.unmask_filter(expression) == expression
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_masking_filter_conditions.py -q --no-cov
```
Expected: the `TestFilterConditionDicts::test_masked_ip_resolves_using_the_sibling_field`, `test_masked_mac_resolves`, `test_list_values_resolve_elementwise` and `TestFilterConditionModels` tests FAIL (values come back as tokens / the model is untouched). The username test and the three `TestMeasuredStringFilterBehaviour` tests should already PASS — they document existing behaviour.

- [ ] **Step 3: Write the implementation**

In `src/fortianalyzer_mcp/masking/unmask.py`, add the import near the top:

```python
from pydantic import BaseModel
```

Add this method to `ArgUnmasker`, directly after `unmask_filter`:

```python
    # -- structured filter conditions --------------------------------------- #

    #: Keys that make a mapping a filter condition: the value's type is named
    #: by a *sibling* key, not by its own key.
    _CONDITION_KEYS = frozenset({"field", "value"})

    def _is_filter_condition(self, value: Any) -> bool:
        """True for a ``{field, op, value}`` mapping or an equivalent model."""
        if isinstance(value, BaseModel):
            return self._CONDITION_KEYS <= set(type(value).model_fields)
        if isinstance(value, dict):
            return self._CONDITION_KEYS <= set(value)
        return False

    def unmask_filter_conditions(self, condition: Any) -> Any:
        """Resolve tokens in one structured filter condition.

        ``unmask_args`` types a value by its own key, and ``unmask_filter`` types
        it by the field name preceding it in the expression. A condition object
        does neither: the value sits under the literal key ``value`` while its
        field name is a sibling. A masked IP is format-preserving and unmarked,
        so without consulting that sibling the token is indistinguishable from a
        real address and would be sent to the appliance as-is -- returning real
        logs for a different host.

        Models are returned as models (re-validated from the resolved dump) so
        the tool still receives the type its signature declares.
        """
        is_model = isinstance(condition, BaseModel)
        data = dict(condition.model_dump()) if is_model else dict(condition)

        field = data.get("field")
        if isinstance(field, str):
            data["value"] = self._unmask_entry(field, data.get("value"))

        if is_model:
            return type(condition).model_validate(data)
        return data
```

Then route both walkers through it. In `_unmask_entry`, add the condition check **before** the `isinstance(value, dict)` branch:

```python
            if self._is_filter_condition(value):
                return self.unmask_filter_conditions(value)
```

And in `_unmask_any`, add the same check as its first branch:

```python
    def _unmask_any(self, value: Any) -> Any:
        if self._is_filter_condition(value):
            return self.unmask_filter_conditions(value)
        if isinstance(value, dict):
            return self.unmask_args(value)
        if isinstance(value, list):
            return [self._unmask_any(item) for item in value]
        if isinstance(value, str):
            return self.resolve_scalar(value)
        return value
```

Note `_unmask_entry(field, value)` already handles a `str` value (typed by `field`) and a `list` of strings elementwise, which is exactly what `in`/`not_in` need — so the list case comes for free.

- [ ] **Step 4: Run the tests**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_masking_filter_conditions.py -q --no-cov
```
Expected: all PASS.

- [ ] **Step 5: Run the masking suites specifically, then everything**

The masking layer has three dedicated suites and a leak guard; run them before the full sweep so a regression is attributed clearly:

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_masking_leak.py tests/test_masking_unmask.py tests/test_masking_wrapper.py \
  tests/test_masking_filter_conditions.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: green throughout. If `test_masking_wrapper.py` regresses, the likely cause is `_is_filter_condition` matching a response dict that happens to carry both `field` and `value` keys — tighten it by also requiring `op`, and add a test for the dict that broke.

- [ ] **Step 6: Commit**

```bash
git add src/fortianalyzer_mcp/masking/unmask.py tests/test_masking_filter_conditions.py
git commit -m "fix(masking): resolve tokens inside structured filter conditions

unmask_args types a value by its own key and unmask_filter types it by the
field name preceding it in the expression. A {field, op, value} condition does
neither: the value sits under the literal key 'value' while its field name is
a sibling, and a Pydantic model instance -- which is what FastMCP passes for a
list[FilterCondition] parameter -- was not walked at all.

That matters because a masked IP is format-preserving and unmarked. Measured
on the current code, unmask_args({'field': 'srcip', 'op': 'eq', 'value':
<masked ip>}) returns the token untouched, so a masked deployment would send
a valid-but-different address to the appliance and get real logs for a host
nobody asked about -- a confident wrong answer rather than an empty result.

Conditions are now typed by their sibling field, in both dict and model form,
and models are re-validated so the tool still receives its declared type.
Tests also freeze the three measured unmask_filter behaviours, including the
pre-existing case that a token embedded in a quoted phrase does not resolve."
```

---

### Task 5: Retire the duplicate sanitiser

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/traffic_tools.py:111-135` (delete `sanitize_filter_value`), and `:57` (delete `_SAFE_UNQUOTED_RE`)
- Test: `tests/test_traffic_tools.py`

**Interfaces:**
- Consumes: `fortianalyzer_mcp.utils.validation.sanitize_filter_value`.
- Produces: no new names. `traffic_tools.sanitize_filter_value` becomes a module-level alias so any existing importer keeps working.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_traffic_tools.py`:

```python
class TestSanitiserIsShared:
    """traffic_tools carried its own copy whose safe class omitted ':'."""

    def test_traffic_sanitiser_is_the_shared_implementation(self) -> None:
        from fortianalyzer_mcp.tools import traffic_tools
        from fortianalyzer_mcp.utils import validation

        assert traffic_tools.sanitize_filter_value is validation.sanitize_filter_value

    def test_ipv6_literal_is_not_quoted(self) -> None:
        """The old copy quoted every IPv6 address because ':' was unsafe to it."""
        from fortianalyzer_mcp.tools import traffic_tools

        assert traffic_tools.sanitize_filter_value("2001:db8::1") == "2001:db8::1"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_traffic_tools.py -k Sanitiser -q --no-cov
```
Expected: FAIL — the two functions are different objects, and the local copy quotes the IPv6 literal.

- [ ] **Step 3: Delete the copy**

In `src/fortianalyzer_mcp/tools/traffic_tools.py`, delete the whole `sanitize_filter_value` function (lines 111-135) and the now-unused `_SAFE_UNQUOTED_RE` constant (line 57). Add `sanitize_filter_value` to the existing import from `utils.validation`:

```python
from fortianalyzer_mcp.utils.validation import (
    ValidationError,
    build_device_filter,
    get_default_adom,
    sanitize_filter_value,
    validate_adom,
)
```

The module already calls `sanitize_filter_value(action)` in `_build_policy_filter`; the shared version takes an optional second `field` argument, so that call site is unchanged. Keep the name importable by leaving the plain import (no alias line needed — the imported name *is* the module attribute).

If `re` becomes unused after deleting `_SAFE_UNQUOTED_RE`, remove the `import re` too; ruff `F401` will tell you.

- [ ] **Step 4: Run the tests and gates**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_traffic_tools.py -q --no-cov
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: all PASS. `tests/test_validation_consistency.py` exists and may already assert something about the two copies — if it fails, update it to assert the single implementation.

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/tools/traffic_tools.py tests/test_traffic_tools.py
git commit -m "refactor(traffic): use the shared filter-value sanitiser

traffic_tools carried a second sanitize_filter_value whose safe-character
class omitted ':', so it wrapped every IPv6 literal in quotes while the
utils.validation copy left it bare -- two spellings of the same value
depending on which tool built the filter. The shared implementation is the
survivor."
```

---

### Task 6: `query_logs` accepts structured filters

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/log_tools.py` (`query_logs`, around lines 403-661)
- Test: `tests/test_log_tools.py`

**Interfaces:**
- Consumes: `FilterCondition`, `compile_to_string` from Task 2.
- Produces: `query_logs(..., filters: list[FilterCondition] | None = None)`. The response's `filter` key echoes the **compiled** string, so an audit shows what was actually sent. `warnings` gains any field-passthrough advisories.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_log_tools.py`. Match the file's existing patching style for `_run_logsearch_page`:

```python
class TestQueryLogsStructuredFilters:
    """filters compiles to the string dialect; filter stays as an escape hatch."""

    async def test_filters_compile_into_the_sent_filter(self, monkeypatch) -> None:
        captured: dict[str, object] = {}

        async def fake_page(client, **kwargs):  # type: ignore[no-untyped-def]
            captured.update(kwargs)
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        result = await log_tools.query_logs(
            logtype="traffic",
            filters=[
                FilterCondition(field="source_ip", op="eq", value="10.0.0.1"),
                FilterCondition(field="dstport", op="in", value=[80, 443]),
            ],
        )

        assert captured["filter"] == "srcip==10.0.0.1 and (dstport==80 or dstport==443)"
        assert result["filter"] == "srcip==10.0.0.1 and (dstport==80 or dstport==443)"

    async def test_raw_filter_still_works_unchanged(self, monkeypatch) -> None:
        captured: dict[str, object] = {}

        async def fake_page(client, **kwargs):  # type: ignore[no-untyped-def]
            captured.update(kwargs)
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        await log_tools.query_logs(logtype="traffic", filter="srcip==10.0.0.1")

        assert captured["filter"] == "srcip==10.0.0.1"

    async def test_both_filter_forms_is_a_conflict_error(self) -> None:
        result = await log_tools.query_logs(
            logtype="traffic",
            filter="srcip==10.0.0.1",
            filters=[FilterCondition(field="dstport", op="eq", value=443)],
        )

        assert result["status"] == "error"
        assert result["error"] == "conflicting_filter_input"
        assert "filters" in result["message"]

    async def test_unknown_field_warning_reaches_the_response(self, monkeypatch) -> None:
        async def fake_page(client, **kwargs):  # type: ignore[no-untyped-def]
            return {"timed_out": False, "tid": 1, "logs": [], "total": 0}

        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        result = await log_tools.query_logs(
            logtype="traffic",
            filters=[FilterCondition(field="mystery_field", op="eq", value="x")],
        )

        assert any("get_log_fields" in w for w in result["warnings"])

    async def test_invalid_condition_returns_a_validation_error(self) -> None:
        result = await log_tools.query_logs(
            logtype="traffic",
            filters=[FilterCondition(field="dstport", op="in", value=443)],
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
```

Add to the imports at the top of `tests/test_log_tools.py`:

```python
from fortianalyzer_mcp.query.filters import FilterCondition
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_log_tools.py -k StructuredFilters -q --no-cov
```
Expected: FAIL — `query_logs() got an unexpected keyword argument 'filters'`.

- [ ] **Step 3: Write the implementation**

In `src/fortianalyzer_mcp/tools/log_tools.py`, add the import:

```python
from fortianalyzer_mcp.query.filters import FilterCondition, compile_to_string
```

Change the signature (keep `filter` where it is so existing positional callers are unaffected, and put `filters` after it):

```python
async def query_logs(
    adom: str | None = None,
    logtype: str = "traffic",
    device: str | None = None,
    time_range: str = "1-hour",
    filter: str | None = None,
    filters: list[FilterCondition] | None = None,
    limit: int = 100,
    offset: int = 0,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
```

Add to the docstring's `Args:` section, immediately after the existing `filter:` entry:

```
        filters: Structured filter conditions, each {field, op, value} —
            preferred over `filter` because the field names are validated here
            and the operator spelling is handled for you. Mutually exclusive
            with `filter`.
            Ops: eq, ne, gt, gte, lt, lte, contains, not_contains, in, not_in.
            Example: [{"field": "srcip", "op": "eq", "value": "10.0.0.1"},
                      {"field": "dstport", "op": "in", "value": [80, 443]}]
            English field names are accepted where unambiguous (source_ip,
            destination_port, application); get_log_fields lists the rest.
```

Inside the `try:` block, right after `logtype = validate_log_type(logtype)` and before `client = _get_client()`:

```python
        filter_warnings: list[str] = []
        if filters and filter:
            return error_response(
                error="conflicting_filter_input",
                message=(
                    "Pass either 'filters' (structured conditions) or 'filter' (a raw "
                    "FortiAnalyzer filter string), not both."
                ),
                operation="query_logs",
                adom=adom,
                logtype=logtype,
                recommendation=(
                    "Use 'filters' unless you need syntax it cannot express, such as a "
                    "regex match."
                ),
            )
        if filters:
            filter, filter_warnings = compile_to_string(filters, logtype)
```

`compile_to_string` raises `ValidationError`, which the function's existing `except ValidationError` handler already converts to a `validation_error` envelope — no new handler needed.

Then extend the warnings list. Find the existing `warnings = build_warnings(...)` call and add immediately after it:

```python
        warnings.extend(filter_warnings)
```

The response already echoes `"filter": filter`, which now carries the compiled string — that is deliberate and worth one line in the `Returns:` docstring section:

```
            - filter: The filter string actually sent to FortiAnalyzer (the
              compiled form when `filters` was used)
```

- [ ] **Step 4: Run the tests**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_log_tools.py -q --no-cov
```
Expected: all PASS, including the pre-existing tests in the file.

- [ ] **Step 5: Check the contract and pagination suites**

`fetch_more_logs` replays the stored context, which now holds the compiled string, and `tests/test_response_contract.py` asserts on response keys:

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_response_contract.py tests/test_log_pagination.py tests/test_logsearch_runner.py \
  tests/test_mcp_tools.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: green. `test_tool_annotations.py` introspects every tool's signature — if it asserts a parameter count, update it for the new parameter.

- [ ] **Step 6: Commit**

```bash
git add src/fortianalyzer_mcp/tools/log_tools.py tests/test_log_tools.py
git commit -m "feat(log-tools): query_logs takes structured filter conditions

filters=[{field, op, value}] compiles to the string dialect through the shared
compiler, so field names are validated before the call and operator spelling
stops being the caller's problem. A wrong field name now fails here with the
valid names listed, or -- for a logtype whose catalogue is not reproduced
locally -- passes through with a warning naming get_log_fields, instead of
returning the appliance's opaque 'Invalid filter'.

The raw filter string stays as an escape hatch but is mutually exclusive with
filters: ANDing a caller-supplied string that may contain 'or' onto a compiled
clause produces a filter meaning neither side intended. The response echoes
the compiled string, so an audit shows what was actually sent."
```

---

### Task 7: The dvmdb-family tools accept structured filters

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/dvm_tools.py` (`search_devices`, lines 479-550)
- Modify: `src/fortianalyzer_mcp/tools/system_tools.py` (`list_tasks`, lines 305-366)
- Test: `tests/test_dvm_tools.py`, `tests/test_system_tools.py`

**Interfaces:**
- Consumes: `FilterCondition`, `compile_to_array` from Task 3.
- Produces: `search_devices(..., filters: list[FilterCondition] | None = None)` and `list_tasks(..., filters: list[FilterCondition] | None = None)`. The existing narrow parameters (`name_filter`, `platform_filter`, `os_version_filter`, `connection_status`, `filter_state`) keep working and compose with `filters` by ANDing.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_dvm_tools.py`:

```python
class TestSearchDevicesStructuredFilters:
    """filters compiles to the array dialect and composes with the old params."""

    async def test_filters_compile_to_array_entries(self, monkeypatch) -> None:
        captured: dict[str, object] = {}

        class FakeClient:
            async def list_devices(self, adom, filter=None):  # type: ignore[no-untyped-def]
                captured["filter"] = filter
                return []

        monkeypatch.setattr(dvm_tools, "_get_client", lambda: FakeClient())

        await dvm_tools.search_devices(
            filters=[FilterCondition(field="os_version", op="contains", value="7.6")]
        )

        assert captured["filter"] == [["os_ver", "contain", "7.6"]]

    async def test_enum_name_is_coerced(self, monkeypatch) -> None:
        captured: dict[str, object] = {}

        class FakeClient:
            async def list_devices(self, adom, filter=None):  # type: ignore[no-untyped-def]
                captured["filter"] = filter
                return []

        monkeypatch.setattr(dvm_tools, "_get_client", lambda: FakeClient())

        await dvm_tools.search_devices(
            filters=[FilterCondition(field="conn_status", op="eq", value="down")]
        )

        assert captured["filter"] == [["conn_status", "==", 2]]

    async def test_structured_and_narrow_params_are_anded(self, monkeypatch) -> None:
        captured: dict[str, object] = {}

        class FakeClient:
            async def list_devices(self, adom, filter=None):  # type: ignore[no-untyped-def]
                captured["filter"] = filter
                return []

        monkeypatch.setattr(dvm_tools, "_get_client", lambda: FakeClient())

        await dvm_tools.search_devices(
            name_filter="fgt",
            filters=[FilterCondition(field="os_version", op="contains", value="7.6")],
        )

        assert ["name", "contain", "fgt"] in captured["filter"]  # type: ignore[operator]
        assert ["os_ver", "contain", "7.6"] in captured["filter"]  # type: ignore[operator]

    async def test_unknown_device_field_is_rejected_locally(self) -> None:
        result = await dvm_tools.search_devices(
            filters=[FilterCondition(field="not_a_field", op="eq", value="x")]
        )

        assert result["status"] == "error"
        assert "conn_status" in result["message"]
```

Add the import to the test file:

```python
from fortianalyzer_mcp.query.filters import FilterCondition
```

Append the mirror test to `tests/test_system_tools.py`:

```python
class TestListTasksStructuredFilters:
    """The task vocabulary coerces state names exactly as filter_state did."""

    async def test_state_name_is_coerced_to_its_code(self, monkeypatch) -> None:
        captured: dict[str, object] = {}

        class FakeClient:
            async def list_tasks(self, filter=None):  # type: ignore[no-untyped-def]
                captured["filter"] = filter
                return []

        monkeypatch.setattr(system_tools, "_get_client", lambda: FakeClient())

        await system_tools.list_tasks(
            filters=[FilterCondition(field="state", op="eq", value="running")]
        )

        assert captured["filter"] == [["state", "==", 1]]

    async def test_legacy_filter_state_still_works(self, monkeypatch) -> None:
        captured: dict[str, object] = {}

        class FakeClient:
            async def list_tasks(self, filter=None):  # type: ignore[no-untyped-def]
                captured["filter"] = filter
                return []

        monkeypatch.setattr(system_tools, "_get_client", lambda: FakeClient())

        await system_tools.list_tasks(filter_state="done")

        assert captured["filter"] == [["state", "==", 4]]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_dvm_tools.py -k StructuredFilters tests/test_system_tools.py -k StructuredFilters \
  -q --no-cov
```
Expected: FAIL — unexpected keyword argument `filters`.

- [ ] **Step 3: Implement in `search_devices`**

Add the import to `dvm_tools.py`:

```python
from fortianalyzer_mcp.query.filters import FilterCondition, compile_to_array
```

Add the parameter after `connection_status`:

```python
async def search_devices(
    adom: str | None = None,
    name_filter: str | None = None,
    platform_filter: str | None = None,
    os_version_filter: str | None = None,
    connection_status: str | None = None,
    filters: list[FilterCondition] | None = None,
) -> dict[str, Any]:
```

Replace the inline `conn_status_map` block with a `compile_to_array` call, and append the structured conditions. The existing body builds `filters: list[list[Any]]` — rename that local to `entries` to avoid shadowing the new parameter, then:

```python
        entries: list[list[Any]] = []
        if name_filter:
            entries.append(["name", "contain", name_filter])
        if platform_filter:
            entries.append(["platform_str", "contain", platform_filter])
        if os_version_filter:
            entries.append(["os_ver", "contain", os_version_filter])
        if connection_status:
            # Coercion lives in the query vocabulary now, so "down" means 2
            # here and everywhere else that filters on conn_status.
            entries.append(
                ["conn_status", "==", coerce_value("device", "conn_status", connection_status)]
            )
        if filters:
            structured, _ = compile_to_array(filters, "device")
            entries.extend(structured)
```

Import `coerce_value` alongside the compiler. `coerce_value` raises `ValidationError` for a bad name, listing the valid ones — the function's existing `except Exception` handler turns that into `{"status": "error", "message": ...}`, which is what the current inline check produced, so the observable behaviour for a bad `connection_status` is preserved.

Add to the docstring:

```
        filters: Structured conditions, each {field, op, value}, ANDed with the
            narrow parameters above. Fields: name, ip, sn, hostname, desc,
            os_ver, platform_str, conn_status, dev_status, mgmt_mode, vdom.
            Ops: eq, ne, gt, gte, lt, lte, contains, not_contains, not_in.
            Example: [{"field": "os_ver", "op": "contains", "value": "7.6"}]
```

- [ ] **Step 4: Implement in `list_tasks`**

Add the same imports to `system_tools.py`, add `filters: list[FilterCondition] | None = None` to the signature, rename the local `filter_list` handling to build a list, and append:

```python
        entries: list[list[Any]] = []
        if filter_state:
            state_code = _TASK_STATE_CODES.get(filter_state.strip().lower())
            if state_code is None:
                valid = ", ".join(sorted(_TASK_STATE_CODES))
                return {
                    "status": "error",
                    "message": f"Invalid filter_state '{filter_state}'. Must be one of: {valid}",
                }
            entries.append(["state", "==", state_code])
        if filters:
            structured, _ = compile_to_array(filters, "task")
            entries.extend(structured)
        filter_list = entries or None
```

Keep the existing `filter_state` branch exactly as it is — it already returns the documented error, and Task 1's drift test guarantees the registry agrees with `_TASK_STATE_CODES`.

- [ ] **Step 5: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_dvm_tools.py tests/test_system_tools.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: green.

- [ ] **Step 6: Commit**

```bash
git add src/fortianalyzer_mcp/tools/dvm_tools.py src/fortianalyzer_mcp/tools/system_tools.py \
  tests/test_dvm_tools.py tests/test_system_tools.py
git commit -m "feat(tools): structured filters for the dvmdb-family readers

search_devices and list_tasks accept filters=[{field, op, value}] compiled to
the array dialect, ANDed with the narrow parameters they already had. Both
tools carried their own inline enum map -- 'down' to 2, 'running' to its code
-- and both now translate through the shared vocabulary, so a conn_status or
state value means the same thing wherever it is filtered.

Unknown field names are rejected locally here, listing the valid ones: unlike
the logtypes, these field sets are small and stable enough to enumerate."
```

---

### Task 8: Document the surface

**Files:**
- Modify: `src/fortianalyzer_mcp/instructions.py` (the `## Log filters` section)
- Modify: `tests/test_server_instructions.py:48`
- Modify: `CLAUDE.md`
- Modify: `CHANGELOG.md`

**Interfaces:** none — documentation only.

- [ ] **Step 1: Write the failing test**

In `tests/test_server_instructions.py`, extend the frozen facts. Replace the `FILTER_OPERATORS` tuple with the structured surface:

```python
FILTER_OPERATORS = ("==", "!=", "<=", ">=", "contain", "!contain")
STRUCTURED_FILTER_OPS = (
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "not_contains",
    "in",
    "not_in",
)


def test_structured_filter_ops_are_documented() -> None:
    """The op vocabulary is what a caller must get right; freeze it."""
    for op in STRUCTURED_FILTER_OPS:
        assert op in SERVER_INSTRUCTIONS, f"op {op!r} missing from the usage guide"


def test_filters_parameter_is_named() -> None:
    assert "filters" in SERVER_INSTRUCTIONS


def test_unverified_operators_are_not_advertised() -> None:
    """like/regex/isnull are documented by Fortinet but unproven through the
    API here, so the guide must not promise them."""
    for token in (" like ", "isnull", "isnotnull"):
        assert token not in SERVER_INSTRUCTIONS
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_server_instructions.py -q --no-cov
```
Expected: the three new tests FAIL.

- [ ] **Step 3: Rewrite the instructions section**

In `src/fortianalyzer_mcp/instructions.py`, replace the whole `## Log filters` section with:

```
## Filters

Prefer `filters` -- a list of structured conditions -- over the raw `filter`
string. Field names are validated before the call and the operator spelling is
handled for you:

  filters=[{"field": "srcip", "op": "eq", "value": "10.0.0.1"},
           {"field": "dstport", "op": "in", "value": [80, 443]}]

  ops: eq, ne, gt, gte, lt, lte, contains, not_contains, in, not_in
  conditions are ANDed; use `in` for OR within one field

English field names are accepted where they are unambiguous (source_ip,
destination_port, application, policy_id); bare "port" and "country" are not,
because they do not say src or dst. get_log_fields(name_filter="...") lists
what a logtype actually carries -- the unfiltered catalogue runs to hundreds of
entries.

`filter` still accepts a raw FortiAnalyzer expression for syntax `filters`
cannot express, and the two are mutually exclusive -- passing both is an error
rather than a silently merged filter. The operators the server emits are `==`,
`!=`, `<`, `>`, `<=`, `>=`, `contain` and `!contain`, combined with `and`/`or`
and grouped with parentheses. FortiAnalyzer's parser documents more than that
(`like`, regex `~`, `isnull`) but none is verified against this API here, so
reach for them only via `filter`, and expect to find out empirically.

search_devices and list_tasks take the same `filters` parameter. Their field
sets are small enough to enumerate, so an unknown field name there is a hard
error listing the valid names; for logtypes an unrecognised name is passed
through with a warning instead, since the appliance's catalogue is larger than
the server's list.
```

- [ ] **Step 4: Update CLAUDE.md**

In the "Layer structure" tree, add the new package after `tools/`:

```text
  query/               pure: field vocabularies, filter compilation (two dialects)
```

In "Adding a tool touches three places", add a fourth bullet:

```markdown
4. If it reads a filterable collection, give it `filters: list[FilterCondition] | None`
   and compile with `query.filters.compile_to_string` (logview/fortiview/eventmgmt/
   incidentmgmt) or `compile_to_array` (dvmdb/config/task). Never hand-build a filter
   string in a tool — that is how the repo ended up spelling "contains" two ways.
```

Fix the stale baseline in the Commands section: `1280 tests` becomes `1328 tests`. Add the `PYTHONPATH=src` note:

```markdown
If every test errors at collection with `ModuleNotFoundError: No module named
'fortianalyzer_mcp'`, the venv's editable install is not being honoured — prefix
with `PYTHONPATH=src`.
```

- [ ] **Step 5: Add the CHANGELOG entry**

Under `## [Unreleased]`, in an `### Added` block:

```markdown
- **Structured filters (`filters`) on `query_logs`, `search_devices` and `list_tasks`.** A list of `{field, op, value}` conditions compiled by one shared engine (`query/`) into whichever of FortiAnalyzer's *two* filter dialects the endpoint speaks — the string grammar for logview/fortiview/eventmgmt/incidentmgmt, the `[field, op, value]` array for dvmdb/config/task. Ops: `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`, `not_contains`, `in`, `not_in`; conditions AND, and `in` becomes a parenthesised OR group. Because the parameter is a Pydantic model, FastMCP publishes the op enum in the tool schema, so an invalid operator is rejected at the protocol boundary rather than by the appliance. Field names resolve through a vocabulary registry that accepts unambiguous English aliases (`source_ip`, `destination_port`, `application`) and carries the enum coercions `search_devices` and `list_tasks` each held inline, so `conn_status` `"down"` means `2` everywhere. Unknown names are a hard error listing the valid set where the field set is enumerable (device, task) and a pass-through warning naming `get_log_fields` where it is not (logtypes, whose catalogues run to hundreds of entries the server does not reproduce). The raw `filter` string remains, mutually exclusive with `filters`. Only operator spellings with working evidence against a live appliance are emitted: FortiAnalyzer documents `like`, regex `~`, `isnull` and `isnotnull` for its Log View parser, but nothing here exercises them through JSON-RPC, so they are reachable only via `filter` until a live check confirms them.

### Fixed
- **Masked values inside structured filter conditions are resolved (`masking/unmask.py`).** `unmask_args` types a value by its own key and `unmask_filter` types it by the field name preceding it in the expression; a `{field, op, value}` condition does neither, since the value sits under the literal key `value` while its field name is a sibling — and a Pydantic model instance, which is what FastMCP passes for a `list[FilterCondition]` parameter, was not walked at all. Measured on the previous code, `unmask_args({"field": "srcip", "op": "eq", "value": <masked ip>})` returned the token untouched. Because a masked IP is format-preserving and unmarked, a masking-enabled deployment would have sent a valid-but-different address to the appliance and received real logs for a host nobody asked about — a confident wrong answer rather than an empty result. Conditions are now typed by their sibling field in both dict and model form.
- **One filter-value sanitiser (`traffic_tools`).** The module carried a second `sanitize_filter_value` whose safe-character class omitted `:`, so it quoted every IPv6 literal while `utils.validation` left it bare — the same value spelled two ways depending on which tool built the filter.
```

- [ ] **Step 6: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_server_instructions.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: green.

- [ ] **Step 7: Commit**

```bash
git add src/fortianalyzer_mcp/instructions.py tests/test_server_instructions.py CLAUDE.md CHANGELOG.md
git commit -m "docs: document the structured filter surface and correct the operator claims

The usage guide told every client that a bare '=' or '&&' returns an opaque
'Invalid filter'. Fortinet documents both as valid since the 7.0.1 parser
unification, and this repo's own pcap_tools sends '='-with-quoted-values to
logview successfully -- so that line was discouraging valid syntax. It is
replaced by a statement of what the server itself emits and a note that the
parser accepts more than is verified here.

Also documents filters on query_logs, search_devices and list_tasks, adds the
query/ package to the CLAUDE.md layer tree with the rule that tools must not
hand-build filter strings, and fixes the stale 1280-test baseline (1328) plus
the PYTHONPATH=src note for collection failures."
```

---

## Self-Review

**Spec coverage.** This plan implements the spec's "filter surface" section (Tasks 1-3, 6, 7), the filter-related part of "Cross-layer obligations" (Task 4), the duplicate-sanitiser cleanup named in the Problem section (Task 5), and the `instructions.py` correction (Task 8). Deliberately deferred, with the plan that carries them:

| Spec section | Plan |
| --- | --- |
| Projection, curated defaults, `fields_returned`, cross-tool key survival | Plan 2 |
| `group_by`, `sample_by`, `GroupPlan`, derived dimensions | Plan 3 |
| Consolidation 83→71, skills handler rewrites, catalogue parity test | Plan 3 |
| Error envelope for the rewritten tools | Plan 3 (Task 6 here already returns the envelope for the two new codes) |

**One deliberate deviation from the spec, worth a reviewer's attention.** The spec says an unknown field name produces "a local error listing valid names". That holds fully for `device` and `task`, whose field sets are enumerable. For logtypes it does **not**: the appliance publishes hundreds of fields per logtype via `/logview/logfields`, this plan does not reproduce that catalogue, and rejecting against an incomplete list would refuse valid queries. So log vocabularies pass unknown names through with a warning naming `get_log_fields`. Aliased mistakes and enum mistakes are still caught locally. Generating the per-logtype catalogues from a live appliance is already a spec verification item; when it lands, `complete=True` makes the behaviour uniform.

**Placeholder scan.** No `TBD`/`TODO`. Every code step carries the actual code. Every test step carries the actual test. Task 5's "if `re` becomes unused, remove it" is a conditional the linter answers deterministically, not a judgement call left open.

**Type consistency.** `resolve_field` returns `tuple[str, str | None]` in Task 1 and is consumed that way in Tasks 2 and 3. `compile_to_string` returns `tuple[str, list[str]]` and Task 6 unpacks two values. `compile_to_array` returns `tuple[list[list[object]], list[str]]` and Tasks 3 and 7 unpack two values, discarding warnings with `_` in Task 7 (device/task vocabularies are `complete=True`, so they raise instead of warning — no warnings can be produced there). `FilterCondition.op` defaults to `"eq"` in Task 2 and every test that omits `op` relies on it. `_scalar`/`_values`/`_reject_bool` are defined in Task 2 and reused by Task 3's `compile_to_array`, which is why Task 3 modifies `filters.py` rather than creating a module.

**One risk flagged for the implementer.** Task 4's `_is_filter_condition` matches any mapping carrying both `field` and `value` keys. Tool *responses* are also walked on the output side by a different class (`OutputMasker`), not `ArgUnmasker`, so a response dict shaped like a condition is not at risk — but a *request* argument that happens to carry both keys would be. Task 4 Step 5 names the mitigation (also require `op`) and requires a test for whatever dict triggered it.
