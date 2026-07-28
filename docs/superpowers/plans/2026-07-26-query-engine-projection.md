# Query Engine, Plan 2 of 3: Projection and Curated Defaults Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every read tool takes `fields: list[str] | None`, returning a curated projection by default, the full object under `fields=["*"]`, and a `fields_returned` echo — so a caller stops paying for ~60 keys per row to read four of them, without ever being silently handed a payload chosen by guesswork.

**Architecture:** A new pure module `src/fortianalyzer_mcp/query/shape.py` decides *which keys survive*; `tools/` apply the decision to the rows they already fetched. Curated sets live beside the filter vocabularies in `query/fields.py`, so one registry answers both "can I filter on this?" and "do I get it back?". Projection is in-process for logs/alerts/incidents/UEBA/FortiView because the appliance offers nothing; `list_adoms`/`list_devices` keep passing `fields` through to dvmdb, where it is native.

**Tech Stack:** Python 3.12, Pydantic v2, `mcp` FastMCP, pytest + pytest-asyncio, ruff, mypy strict.

**Spec:** `docs/superpowers/specs/2026-07-25-query-engine-design.md`, the "Projection and curated defaults" section plus the cross-tool key-survival obligation under "Testing". `group_by`/`sample_by` and the 83→71 consolidation are Plan 3.

**Predecessor:** Plan 1 (`docs/superpowers/plans/2026-07-25-query-engine-filters.md`) shipped as PR #94, squashed onto `pr/tool-ergonomics` as `ab60ad8` plus the follow-up `627a138`. The unsquashed commit range this plan originally named (`749a9c7`..`c1cdffc`) no longer exists — do not try to read it.

**What Plan 1 actually left behind, verified against HEAD rather than assumed.** Plan 1 was revised during execution by live probing, so several of its outputs differ from what it predicted. This plan has been reconciled against the real code, but read these before starting:

| Fact at HEAD | Why it matters here |
| --- | --- |
| `query/fields.py` exports `Vocabulary`, `get_vocabulary`, `resolve_field`, `coerce_value`, `canonical_log_field`, `enum_names`, `TASK_STATE_CODES` | The task-state map is **public** (`TASK_STATE_CODES`, no leading underscore). Task 1 wires it into `_VOCABULARIES` under that name. |
| Registered vocabularies are exactly `traffic`, `event`, `attack`, `device`, `task` | The nine Task 1 adds are genuinely new. Nothing to merge. |
| `Vocabulary` has **no** `projection` attribute | Plan 1 said the registry would be "shaped for that from the start"; it was not. Task 1 adds the attribute. |
| `get_vocabulary` falls back to `_GENERIC_LOG`, whose `.name` is `"log"` | An unregistered vocabulary reports its name as `log`, not as what the caller asked for. Task 2 works around this deliberately — see its note. |
| `contains` compiles to `like "%v%"` on **both** dialects; `not_contains` is `!(f like "%v%")` on the string dialect and **refused** on the array dialect; `in` is refused on the array dialect | Nothing in this plan compiles filters, but the `search_devices` docstring in Task 7 sits next to text describing these, so do not "correct" it back to `contain`. |
| `search_devices` **already takes `fields`** and passes it straight to dvmdb, unvalidated | Task 7 is a rework of an existing parameter, not an addition. Its scope changed accordingly. |

## Global Constraints

- Python `>=3.12`. Target `py312`.
- **mypy strict**: `disallow_untyped_defs`, `disallow_incomplete_defs`, `warn_return_any`, `no_implicit_optional`. Every function needs annotations, including `-> None` on tests.
- **ruff** line-length 100, `E501` ignored (the formatter owns line length). Selected rules: `E`, `W`, `F`, `I`, `B`, `C4`, `UP`. Note `B017`: never write `pytest.raises(Exception)` — name the concrete exception.
- Style: `isinstance(x, list | tuple)` (PEP 604 unions), `from __future__ import annotations` at the top of new modules.
- **`query/` must stay pure.** No imports from `fortianalyzer_mcp.tools`, `fortianalyzer_mcp.server`, or `fortianalyzer_mcp.api`. Importing from `fortianalyzer_mcp.utils` is fine.
- **Do not reorder** the tool-import block at the bottom of `server.py`.
- **NO AI attribution in commit messages.** `.github/workflows/no-ai-attribution.yml` fails any PR whose commits match `Co-Authored-By: Claude|Anthropic`, `noreply@anthropic.com`, `Generated with Claude`, or `🤖 Generated with`. This overrides any default commit template.
- Commit subjects: conventional-commit with scope, e.g. `feat(query): curated projections for the log vocabularies`.
- **`CLAUDE.md` is gitignored in this repo** (`.gitignore:149`). Edit it for the local reader if you like, but it cannot be committed — do not `git add -f` it.
- **Test command** (note `PYTHONPATH=src` — the venv's editable install is not honoured on this machine; without it every test errors at collection with `ModuleNotFoundError: No module named 'fortianalyzer_mcp'`):

  ```bash
  FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
  ```

- **Baseline: 1545 passed.** Measured at `627a138` (`upstream/main`, the base of `feat/query-engine`). The same numbers held on `pr/tool-ergonomics` at `627a138`. (Earlier drafts of this plan said 1414 and CLAUDE.md says 1414; both are stale.) Every task must end at 1545 + the tests it added, with no failures. Re-measure before Task 1 and use what you measure — if it is not 1545, say so before continuing rather than adjusting silently.
- The three CI gates, all clean at every commit:

  ```bash
  uv run ruff check src/ tests/
  uv run ruff format --check src/ tests/
  PYTHONPATH=src uv run mypy src/
  ```

- **The masking-enabled suite has 10 pre-existing failures** (in `tests/test_ueba_tools.py` and `tests/test_soar_tools.py`) and is not gated in CI. Measured at `627a138`: `10 failed, 1535 passed`. Compare against that baseline rather than expecting green:

  ```bash
  MASKING_ENABLED=true FAZ_MASKING_KEY=$(python3 -c "print('0'*64)") \
    FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
  ```

  Do not write a test whose assertion depends on masking being off. Values in IP-typed fields (`srcip`, `dstip`) are rewritten by the arg unmasker under masking; filter on ports or non-PII fields instead.

## File Structure

| File | Responsibility |
| --- | --- |
| `src/fortianalyzer_mcp/query/fields.py` | **Modify.** `Vocabulary` gains `projection: frozenset[str]`. Curated sets for the vocabularies the spec names, plus the vocabularies projection needs that filters did not (`alert`, `incident`, `endpoint`, `enduser`, `report`, and the FortiView views). |
| `src/fortianalyzer_mcp/query/shape.py` | **Create.** `resolve_projection` (names → key set + warnings) and `project_rows` (apply it). Pure. |
| `src/fortianalyzer_mcp/query/__init__.py` | **Modify.** Re-export the two new functions. |
| `src/fortianalyzer_mcp/tools/log_tools.py` | **Modify.** `query_logs` and `fetch_more_logs` gain `fields`; the handle records it so paging stays consistent. |
| `src/fortianalyzer_mcp/tools/event_tools.py` | **Modify.** `get_alerts`, `get_alert_logs` gain `fields`. |
| `src/fortianalyzer_mcp/tools/incident_tools.py` | **Modify.** `get_incidents` gains `fields`. |
| `src/fortianalyzer_mcp/tools/ueba_tools.py` | **Modify.** `get_endpoints`, `get_endusers` gain `fields`. |
| `src/fortianalyzer_mcp/tools/fortiview_tools.py` | **Modify.** `get_fortiview_data` gains `fields`. |
| `src/fortianalyzer_mcp/tools/report_tools.py` | **Modify.** `get_report_history` gains `fields`. |
| `src/fortianalyzer_mcp/tools/dvm_tools.py` | **Modify.** `search_devices`'s existing raw `fields` pass-through gains resolution, aliases, validation and a curated default. |
| `src/fortianalyzer_mcp/instructions.py` | **Modify.** Document the projection surface. |
| `tests/test_query_fields.py` | **Modify.** Task 1 appends the curated-projection tests. |
| `tests/test_query_shape.py` | New. Projection resolution and application. |
| `tests/test_projection_join_keys.py` | New. The cross-tool key-survival guard. |

`query/groups.py` arrives in Plan 3; nothing here should anticipate it.

---

### Task 1: Curated projections in the registry

**Files:**
- Modify: `src/fortianalyzer_mcp/query/fields.py`
- Test: `tests/test_query_fields.py`

**Interfaces:**
- Consumes: the existing `Vocabulary` dataclass, `_LOG_COMMON`, `_TRAFFIC_FIELDS`, `_EVENT_FIELDS`, `_ATTACK_FIELDS`, `_DEVICE_FIELDS`, `_TASK_FIELDS`.
- Produces:
  - `Vocabulary.projection: frozenset[str]` — empty frozenset means "uncurated".
  - New registered vocabularies: `virus`, `webfilter`, `app-ctrl`, `dns`, `alert`, `incident`, `endpoint`, `enduser`, `report`.
  - `has_projection(vocabulary: str) -> bool`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_query_fields.py`:

```python
class TestCuratedProjections:
    """Every curated set is a subset of what the vocabulary says exists."""

    CURATED = ("traffic", "event", "attack", "device", "task", "alert", "incident")

    @pytest.mark.parametrize("name", CURATED)
    def test_curated_vocabularies_have_a_projection(self, name: str) -> None:
        assert get_vocabulary(name).projection, f"{name} has no curated projection"

    @pytest.mark.parametrize("name", CURATED)
    def test_projection_is_a_subset_of_canonical(self, name: str) -> None:
        """A curated name the vocabulary does not know is a typo, not a field."""
        vocab = get_vocabulary(name)
        unknown = vocab.projection - vocab.canonical
        assert not unknown, f"{name} projects unknown fields: {sorted(unknown)}"

    def test_an_uncurated_logtype_has_an_empty_projection(self) -> None:
        """voip has no curated set; that must read as absence, not as {}."""
        assert get_vocabulary("voip").projection == frozenset()

    def test_has_projection_reports_curation(self) -> None:
        assert has_projection("traffic") is True
        assert has_projection("voip") is False

    def test_traffic_projection_carries_identity_magnitude_and_summary(self) -> None:
        """The spec's shape requirement, asserted rather than assumed."""
        traffic = get_vocabulary("traffic").projection
        assert {"srcip", "dstip"} <= traffic, "identity missing"
        assert "action" in traffic, "discriminator missing"
        assert {"sentbyte", "rcvdbyte"} <= traffic, "magnitude missing"
        assert {"service", "app"} <= traffic, "summary missing"
```

Add `has_projection` to the import at the top of the file:

```python
from fortianalyzer_mcp.query.fields import (
    coerce_value,
    get_vocabulary,
    has_projection,
    resolve_field,
)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_fields.py -q --no-cov
```
Expected: collection error — `ImportError: cannot import name 'has_projection'`.

- [ ] **Step 3: Add the projection attribute and the new vocabularies**

In `src/fortianalyzer_mcp/query/fields.py`, extend the module docstring's bullet list with a fifth entry, immediately after the `complete` bullet:

```
* **projection** -- the curated subset returned when a caller passes no
  ``fields``. Empty means uncurated: the tool returns full rows plus a warning
  naming ``fields``, which is today's behaviour, rather than a payload chosen
  by guesswork. Curations are added as they are verified against live
  ``logfields`` output, so an empty set is a "not yet", not a "never".
```

Add the field to the dataclass:

```python
@dataclass(frozen=True)
class Vocabulary:
    """One filterable namespace and everything known about its field names."""

    name: str
    dialect: str
    canonical: frozenset[str]
    aliases: Mapping[str, str]
    coercions: Mapping[str, Mapping[str, int]]
    complete: bool
    projection: frozenset[str] = frozenset()
```

A default of `frozenset()` keeps every existing `Vocabulary(...)` call valid, which matters because `_GENERIC_LOG` must stay uncurated.

Now add the field sets and curations. Insert after `_ATTACK_FIELDS`:

```python
# Curated projections. Each carries identity (who/where), the discriminator
# (action/level/severity), the magnitude, the human-readable summary, and --
# non-negotiably -- the join keys another tool takes as input. Dropping
# sessionid from traffic breaks get_pcap_by_session with no error that traces
# back here; tests/test_projection_join_keys.py is the guard.
_TRAFFIC_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "srcip",
        "srcport",
        "dstip",
        "dstport",
        "proto",
        "action",
        "service",
        "app",
        "policyid",
        "sentbyte",
        "rcvdbyte",
        "duration",
        "user",
        "sessionid",
        "srccountry",
        "dstcountry",
    }
)

_EVENT_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "level",
        "subtype",
        "action",
        "user",
        "ui",
        "msg",
        "status",
    }
)

_ATTACK_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "severity",
        "attack",
        "attackid",
        "srcip",
        "srcport",
        "dstip",
        "dstport",
        "proto",
        "action",
        "service",
        "policyid",
        "cve",
        "sessionid",
        "pcapurl",
        "msg",
    }
)

# The four remaining curated logtypes the spec names. Each set is the common
# core plus the fields that make that logtype worth querying; every name is
# also added to the vocabulary's canonical set so the subset test holds.
_VIRUS_FIELDS: frozenset[str] = _LOG_COMMON | {
    "virus",
    "filename",
    "url",
    "service",
    "srcport",
    "dstport",
    "proto",
    "profile",
    "eventtype",
    "filehash",
}
_VIRUS_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "action",
        "virus",
        "filename",
        "filehash",
        "url",
        "srcip",
        "dstip",
        "user",
        "service",
        "msg",
    }
)

_WEBFILTER_FIELDS: frozenset[str] = _LOG_COMMON | {
    "hostname",
    "url",
    "catdesc",
    "cat",
    "service",
    "srcport",
    "dstport",
    "proto",
    "profile",
    "eventtype",
    "reqtype",
    "sentbyte",
    "rcvdbyte",
}
_WEBFILTER_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "action",
        "hostname",
        "url",
        "catdesc",
        "srcip",
        "dstip",
        "user",
        "sentbyte",
        "rcvdbyte",
        "msg",
    }
)

_APPCTRL_FIELDS: frozenset[str] = _LOG_COMMON | {
    "app",
    "appcat",
    "apprisk",
    "hostname",
    "url",
    "service",
    "srcport",
    "dstport",
    "proto",
    "profile",
    "eventtype",
    "sentbyte",
    "rcvdbyte",
}
_APPCTRL_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "action",
        "app",
        "appcat",
        "apprisk",
        "hostname",
        "srcip",
        "dstip",
        "user",
        "sentbyte",
        "rcvdbyte",
        "msg",
    }
)

_DNS_FIELDS: frozenset[str] = _LOG_COMMON | {
    "qname",
    "qtype",
    "qclass",
    "xid",
    "srcport",
    "dstport",
    "proto",
    "profile",
    "eventtype",
    "catdesc",
}
_DNS_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "action",
        "qname",
        "qtype",
        "catdesc",
        "srcip",
        "dstip",
        "user",
        "msg",
    }
)
```

Insert after `TASK_STATE_CODES` — note the name is public, no leading underscore; `system_tools` imports it to derive its code→name display table, so do not rename it — the non-log vocabularies:

```python
# --- non-log vocabularies -------------------------------------------------- #
# These carry no filter dialect of their own in this plan (eventmgmt and
# incidentmgmt take the string dialect, which Plan 1 already emits), but they
# need canonical sets so projection can validate names against something.

_ALERT_FIELDS: frozenset[str] = frozenset(
    {
        "alertid",
        "adom",
        "severity",
        "status",
        "alerttime",
        "firstlogtime",
        "lastlogtime",
        "count",
        "eventtype",
        "extrainfo",
        "devname",
        "devid",
        "subject",
        "subject_details",
        "triggername",
        "epid",
        "euid",
        "acknowledged",
        "comments",
        "target",
    }
)
_ALERT_PROJECTION: frozenset[str] = frozenset(
    {
        "alertid",
        "severity",
        "status",
        "alerttime",
        "lastlogtime",
        "count",
        "eventtype",
        "devname",
        "subject",
        "triggername",
        "epid",
        "euid",
        "acknowledged",
    }
)
_ALERT_ALIASES: Mapping[str, str] = {
    "alert_id": "alertid",
    "event_type": "eventtype",
    "device_name": "devname",
    "trigger": "triggername",
}

_INCIDENT_FIELDS: frozenset[str] = frozenset(
    {
        "incid",
        "adom",
        "severity",
        "status",
        "category",
        "createtime",
        "updatetime",
        "banner",
        "description",
        "assignee",
        "reporter",
        "endpoint",
        "epid",
        "euid",
        "alertid",
        "attachment",
        "connector",
        "ticket",
    }
)
_INCIDENT_PROJECTION: frozenset[str] = frozenset(
    {
        "incid",
        "severity",
        "status",
        "category",
        "createtime",
        "updatetime",
        "banner",
        "assignee",
        "reporter",
        "epid",
        "euid",
        "alertid",
    }
)
_INCIDENT_ALIASES: Mapping[str, str] = {
    "incident_id": "incid",
    "title": "banner",
    "owner": "assignee",
}

_ENDPOINT_FIELDS: frozenset[str] = frozenset(
    {
        "epid",
        "hostname",
        "ip",
        "mac",
        "os",
        "osversion",
        "firstseen",
        "lastseen",
        "department",
        "euid",
        "username",
        "vulnstat",
        "devname",
        "devid",
        "onnet",
        "status",
        "detectkey",
    }
)
_ENDPOINT_PROJECTION: frozenset[str] = frozenset(
    {
        "epid",
        "hostname",
        "ip",
        "mac",
        "os",
        "lastseen",
        "department",
        "euid",
        "username",
        "status",
    }
)
_ENDPOINT_ALIASES: Mapping[str, str] = {
    "endpoint_id": "epid",
    "host": "hostname",
    "last_seen": "lastseen",
}

_ENDUSER_FIELDS: frozenset[str] = frozenset(
    {
        "euid",
        "username",
        "groups",
        "email",
        "department",
        "title",
        "phone",
        "vpnip",
        "firstseen",
        "lastseen",
        "epids",
    }
)
_ENDUSER_PROJECTION: frozenset[str] = frozenset(
    {
        "euid",
        "username",
        "groups",
        "department",
        "lastseen",
        "epids",
    }
)
_ENDUSER_ALIASES: Mapping[str, str] = {
    "enduser_id": "euid",
    "user": "username",
    "last_seen": "lastseen",
}

_REPORT_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "title",
        "adom",
        "start-time",
        "end-time",
        "state",
        "progress-percent",
        "period-start",
        "period-end",
        "template",
        "format",
        "size",
        "owner",
    }
)
_REPORT_PROJECTION: frozenset[str] = frozenset(
    {
        "id",
        "title",
        "state",
        "start-time",
        "end-time",
        "period-start",
        "period-end",
        "format",
    }
)
_REPORT_ALIASES: Mapping[str, str] = {
    "report_id": "id",
    "name": "title",
    "status": "state",
}

_DEVICE_PROJECTION: frozenset[str] = frozenset(
    {
        "name",
        "ip",
        "sn",
        "hostname",
        "os_ver",
        "mr",
        "patch",
        "platform_str",
        "conn_status",
        "dev_status",
        "vdom",
    }
)

_TASK_PROJECTION: frozenset[str] = frozenset(
    {
        "id",
        "title",
        "state",
        "percent",
        "user",
        "adom",
        "start_tm",
        "end_tm",
        "num_err",
        "num_warn",
    }
)
```

Now wire them into `_VOCABULARIES`. Add `projection=` to the five existing entries and append the nine new ones:

```python
_VOCABULARIES: Mapping[str, Vocabulary] = {
    "traffic": Vocabulary(
        name="traffic",
        dialect="string",
        canonical=_TRAFFIC_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_TRAFFIC_PROJECTION,
    ),
    "event": Vocabulary(
        name="event",
        dialect="string",
        canonical=_EVENT_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_EVENT_PROJECTION,
    ),
    "attack": Vocabulary(
        name="attack",
        dialect="string",
        canonical=_ATTACK_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_ATTACK_PROJECTION,
    ),
    "virus": Vocabulary(
        name="virus",
        dialect="string",
        canonical=_VIRUS_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_VIRUS_PROJECTION,
    ),
    "webfilter": Vocabulary(
        name="webfilter",
        dialect="string",
        canonical=_WEBFILTER_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_WEBFILTER_PROJECTION,
    ),
    "app-ctrl": Vocabulary(
        name="app-ctrl",
        dialect="string",
        canonical=_APPCTRL_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_APPCTRL_PROJECTION,
    ),
    "dns": Vocabulary(
        name="dns",
        dialect="string",
        canonical=_DNS_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_DNS_PROJECTION,
    ),
    "device": Vocabulary(
        name="device",
        dialect="array",
        canonical=_DEVICE_FIELDS,
        aliases=_DEVICE_ALIASES,
        coercions={"conn_status": _CONN_STATUS_CODES},
        complete=True,
        projection=_DEVICE_PROJECTION,
    ),
    "task": Vocabulary(
        name="task",
        dialect="array",
        canonical=_TASK_FIELDS,
        aliases=_TASK_ALIASES,
        coercions={"state": TASK_STATE_CODES},
        complete=True,
        projection=_TASK_PROJECTION,
    ),
    "alert": Vocabulary(
        name="alert",
        dialect="string",
        canonical=_ALERT_FIELDS,
        aliases=_ALERT_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_ALERT_PROJECTION,
    ),
    "incident": Vocabulary(
        name="incident",
        dialect="string",
        canonical=_INCIDENT_FIELDS,
        aliases=_INCIDENT_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_INCIDENT_PROJECTION,
    ),
    "endpoint": Vocabulary(
        name="endpoint",
        dialect="string",
        canonical=_ENDPOINT_FIELDS,
        aliases=_ENDPOINT_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_ENDPOINT_PROJECTION,
    ),
    "enduser": Vocabulary(
        name="enduser",
        dialect="string",
        canonical=_ENDUSER_FIELDS,
        aliases=_ENDUSER_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_ENDUSER_PROJECTION,
    ),
    "report": Vocabulary(
        name="report",
        dialect="string",
        canonical=_REPORT_FIELDS,
        aliases=_REPORT_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_REPORT_PROJECTION,
    ),
}
```

The five non-log vocabularies are `complete=False` on purpose: their field sets come from observed responses and public documentation, not from a schema endpoint this repo can enumerate, so an unrecognised name is a warning rather than a refusal. Only `device` and `task` — whose sets Plan 1 already established as enumerable — reject.

Finally, add the lookup after `get_vocabulary`:

```python
def has_projection(vocabulary: str) -> bool:
    """Whether this vocabulary has a curated default projection.

    ``False`` means a caller who passes no ``fields`` gets full rows and a
    warning, which is the pre-projection behaviour -- never a guessed subset.
    """
    return bool(get_vocabulary(vocabulary).projection)
```

- [ ] **Step 4: Run the tests and the gates**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_fields.py -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: all PASS, gates clean. If `test_projection_is_a_subset_of_canonical` fails, a curated name is missing from that vocabulary's `canonical` set — add it there rather than deleting it from the projection.

- [ ] **Step 5: Run the full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: `1545 + <new count> passed`, 0 failed.

- [ ] **Step 6: Commit**

```bash
git add src/fortianalyzer_mcp/query/fields.py tests/test_query_fields.py
git commit -m "feat(query): curated projections in the vocabulary registry

Vocabulary gains a projection set, and nine vocabularies join the registry so
projection has something to validate names against: the four remaining curated
logtypes plus alert, incident, endpoint, enduser and report.

An empty projection means uncurated, and that reads as absence rather than as
an empty selection -- the tool returns full rows and a warning naming fields,
which is exactly today's behaviour. Curating by guesswork would be worse than
not curating, so a logtype with no verified logfields output stays empty until
one exists.

Every curated name is asserted to be a name its vocabulary already claims,
so a typo in a projection fails the suite instead of silently dropping a key."
```

---

### Task 2: The projection resolver

**Files:**
- Create: `src/fortianalyzer_mcp/query/shape.py`
- Modify: `src/fortianalyzer_mcp/query/__init__.py`
- Test: `tests/test_query_shape.py`

**Interfaces:**
- Consumes: `resolve_field`, `get_vocabulary`, `has_projection` from Task 1; `ValidationError` from `fortianalyzer_mcp.utils.errors`.
- Produces:
  - `ALL_FIELDS: str = "*"`
  - `resolve_projection(vocabulary: str, fields: list[str] | None) -> tuple[frozenset[str] | None, list[str]]` — `(keys_or_None, warnings)`; `None` means "return everything".
  - `project_rows(rows: list[dict[str, Any]], keys: frozenset[str] | None) -> list[dict[str, Any]]`
  - `fields_returned(rows: list[dict[str, Any]], keys: frozenset[str] | None) -> list[str]`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_query_shape.py`:

```python
"""Tests for the projection resolver."""

from __future__ import annotations

from typing import Any

import pytest

from fortianalyzer_mcp.query.shape import (
    fields_returned,
    project_rows,
    resolve_projection,
)
from fortianalyzer_mcp.utils.errors import ValidationError


def _row(**kw: Any) -> dict[str, Any]:
    base = {"srcip": "10.0.0.1", "dstip": "10.0.0.2", "dstport": 443, "noise": "x"}
    base.update(kw)
    return base


class TestResolveProjection:
    """None -> curated, ["*"] -> everything, a list -> that list."""

    def test_none_gives_the_curated_set(self) -> None:
        keys, warnings = resolve_projection("traffic", None)
        assert keys is not None
        assert "srcip" in keys and "sessionid" in keys
        assert warnings == []

    def test_none_on_an_uncurated_vocabulary_gives_everything_and_warns(self) -> None:
        keys, warnings = resolve_projection("voip", None)
        assert keys is None, "uncurated must degrade to full rows, not to an empty set"
        assert len(warnings) == 1
        assert "fields" in warnings[0]

    def test_the_uncurated_warning_names_the_requested_vocabulary(self) -> None:
        """An unregistered name falls back to the generic log vocabulary, whose
        own name is "log". The warning must still say "voip" -- naming the
        fallback would describe something the caller never asked about."""
        _, warnings = resolve_projection("voip", None)
        assert "voip" in warnings[0]
        assert "for log yet" not in warnings[0]

    def test_star_gives_everything(self) -> None:
        keys, warnings = resolve_projection("traffic", ["*"])
        assert keys is None
        assert warnings == []

    def test_explicit_list_selects_exactly_those_keys(self) -> None:
        keys, _ = resolve_projection("traffic", ["srcip", "dstport"])
        assert keys == frozenset({"srcip", "dstport"})

    def test_aliases_resolve_to_canonical_names(self) -> None:
        keys, _ = resolve_projection("traffic", ["source_ip", "destination_port"])
        assert keys == frozenset({"srcip", "dstport"})

    def test_star_mixed_with_names_is_rejected(self) -> None:
        """"* plus srcip" has no coherent meaning; refuse rather than guess."""
        with pytest.raises(ValidationError) as exc:
            resolve_projection("traffic", ["*", "srcip"])
        assert "'*'" in str(exc.value)

    def test_empty_list_is_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            resolve_projection("traffic", [])
        assert "empty" in str(exc.value).lower()

    def test_unknown_field_on_a_complete_vocabulary_raises(self) -> None:
        with pytest.raises(ValidationError):
            resolve_projection("device", ["not_a_device_field"])

    def test_unknown_field_on_an_incomplete_vocabulary_warns_and_passes(self) -> None:
        keys, warnings = resolve_projection("traffic", ["srcip", "mystery"])
        assert keys == frozenset({"srcip", "mystery"})
        assert len(warnings) == 1
        assert "get_log_fields" in warnings[0]


class TestProjectRows:
    """Selecting is subtractive: it never renames, invents or reorders keys."""

    def test_only_selected_keys_survive(self) -> None:
        rows = project_rows([_row()], frozenset({"srcip", "dstport"}))
        assert rows == [{"srcip": "10.0.0.1", "dstport": 443}]

    def test_none_returns_rows_untouched(self) -> None:
        original = _row()
        rows = project_rows([original], None)
        assert rows == [original]

    def test_a_selected_key_absent_from_the_row_is_not_invented(self) -> None:
        """No null padding -- an absent key means the appliance did not send it."""
        rows = project_rows([{"srcip": "10.0.0.1"}], frozenset({"srcip", "sessionid"}))
        assert rows == [{"srcip": "10.0.0.1"}]

    def test_nested_values_are_kept_whole(self) -> None:
        """Selecting a key with a nested structure keeps the structure intact.

        Alerts carry subject_details and target[]; masking handles those
        composites specially, so splitting them here would break it.
        """
        row = {"alertid": "1", "target": [{"name": "srcip", "value": "10.0.0.1"}]}
        rows = project_rows([row], frozenset({"alertid", "target"}))
        assert rows[0]["target"] == [{"name": "srcip", "value": "10.0.0.1"}]

    def test_a_non_dict_row_passes_through(self) -> None:
        """Some FAZ endpoints answer with bare scalars in the data list."""
        assert project_rows(["raw"], frozenset({"srcip"})) == ["raw"]

    def test_projection_does_not_mutate_the_input(self) -> None:
        original = _row()
        project_rows([original], frozenset({"srcip"}))
        assert "noise" in original


class TestFieldsReturned:
    """The echo that tells a caller what is queryable next."""

    def test_reports_the_projection_even_when_no_rows_came_back(self) -> None:
        """A zero-row page is exactly when this signal matters most."""
        assert fields_returned([], frozenset({"srcip", "dstport"})) == ["dstport", "srcip"]

    def test_reports_observed_keys_when_no_projection_applied(self) -> None:
        assert fields_returned([{"b": 1, "a": 2}], None) == ["a", "b"]

    def test_unions_observed_keys_across_rows(self) -> None:
        rows = [{"a": 1}, {"b": 2}]
        assert fields_returned(rows, None) == ["a", "b"]

    def test_no_projection_and_no_rows_is_empty(self) -> None:
        assert fields_returned([], None) == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_shape.py -q --no-cov
```
Expected: collection error — `ModuleNotFoundError: No module named 'fortianalyzer_mcp.query.shape'`.

- [ ] **Step 3: Write the implementation**

Create `src/fortianalyzer_mcp/query/shape.py`:

```python
"""Which keys survive a response row, and the echo that reports them.

FortiAnalyzer projects nothing for logs, alerts, incidents or FortiView rows --
there is no server-side field list on those endpoints -- so projection here is
in-process: the appliance sends the whole row, this module decides what the
caller sees. That still pays for itself, because the cost this addresses is
context, not bandwidth: a traffic row is roughly sixty keys and an answer
usually needs eight.

Two invariants keep the other layers correct, and both are subtractive:

* **Selects, never renames.** The masking allowlist in ``masking/fields.py`` is
  keyed on live field names verified against 7.6.7/8.0.0 schemas. Renaming a
  key on the way out would move a value out from under its allowlist entry and
  silently unmask it. Selecting a subset can only shrink what masking must
  cover, never move it.
* **Top-level keys only.** Alerts carry nested ``subject_details`` and
  ``target[]``; selecting such a key keeps the structure whole. There is
  deliberately no dotted-path language -- that would be a second query dialect
  to learn, and ``target[]`` is one of the composite structures masking handles
  specially.

Projection runs inside the tool, so it happens *before* the masking wrapper
sees the response. A field curated away is a field masking never has to
consider.
"""

from __future__ import annotations

from typing import Any

from fortianalyzer_mcp.query.fields import get_vocabulary, resolve_field
from fortianalyzer_mcp.utils.errors import ValidationError

#: The opt-out token. ``fields=["*"]`` returns the full object as before.
ALL_FIELDS = "*"


def resolve_projection(
    vocabulary: str,
    fields: list[str] | None,
) -> tuple[frozenset[str] | None, list[str]]:
    """Decide which keys a response should carry.

    Args:
        vocabulary: The logtype or object type whose field names apply.
        fields: ``None`` for the curated default, ``["*"]`` for everything, or
            an explicit list of names (aliases accepted).

    Returns:
        ``(keys, warnings)``. ``keys`` is ``None`` when every key should
        survive -- either because the caller asked for ``["*"]`` or because the
        vocabulary has no curated set and degrading to full rows is the honest
        answer.

    Raises:
        ValidationError: on an empty list, ``"*"`` mixed with real names, or an
            unknown name in a vocabulary that enumerates its fields.
    """
    if fields is None:
        vocab = get_vocabulary(vocabulary)
        if vocab.projection:
            return vocab.projection, []
        # Name what the CALLER asked for, not vocab.name. An unregistered
        # vocabulary falls back to _GENERIC_LOG, whose name is "log", so
        # reporting vocab.name here would tell a caller who queried voip that
        # "log" has no curated set -- true of neither thing they asked about.
        return None, [
            f"no curated field set exists for {vocabulary} yet, so the full row is "
            f"returned. Pass fields=[...] to select what you need."
        ]

    if not fields:
        raise ValidationError(
            "fields was an empty list; omit it for the curated default or pass "
            'fields=["*"] for the full object.'
        )

    if ALL_FIELDS in fields:
        if len(fields) > 1:
            raise ValidationError(
                "fields cannot mix '*' with named fields. Use '*' alone for the full "
                "object, or list only the fields you want."
            )
        return None, []

    keys: set[str] = set()
    warnings: list[str] = []
    for name in fields:
        canonical, warning = resolve_field(vocabulary, name)
        if warning:
            warnings.append(warning)
        keys.add(canonical)

    return frozenset(keys), warnings


def project_rows(
    rows: list[Any],
    keys: frozenset[str] | None,
) -> list[Any]:
    """Return ``rows`` with only ``keys`` retained on each mapping.

    A key absent from a row is not invented: no null padding, because an
    absent key means the appliance did not send it and a null would claim it
    did. Non-mapping entries pass through untouched -- some FAZ endpoints
    answer with bare scalars in the data list.
    """
    if keys is None:
        return rows
    return [
        {key: value for key, value in row.items() if key in keys}
        if isinstance(row, dict)
        else row
        for row in rows
    ]


def fields_returned(
    rows: list[Any],
    keys: frozenset[str] | None,
) -> list[str]:
    """The sorted key list to echo back to the caller.

    When a projection applied, this is the projection itself -- reported even
    for a zero-row page, which is exactly when a caller most needs to know what
    is queryable next. With no projection there is nothing to report but what
    the rows actually carried, so it is the union of observed keys.
    """
    if keys is not None:
        return sorted(keys)
    observed: set[str] = set()
    for row in rows:
        if isinstance(row, dict):
            observed.update(row)
    return sorted(observed)
```

Then extend `src/fortianalyzer_mcp/query/__init__.py`. **This is an extension, not a replacement** — the file at HEAD already exports `TASK_STATE_CODES` (imported by `system_tools`) and `canonical_log_field` (imported by `masking/unmask.py`). Dropping either breaks a live import, so the block below keeps both and adds four names:

```python
from fortianalyzer_mcp.query.fields import (
    TASK_STATE_CODES,
    Vocabulary,
    canonical_log_field,
    coerce_value,
    get_vocabulary,
    has_projection,
    resolve_field,
)
from fortianalyzer_mcp.query.filters import (
    FilterCondition,
    FilterOp,
    compile_to_array,
    compile_to_string,
)
from fortianalyzer_mcp.query.shape import (
    ALL_FIELDS,
    fields_returned,
    project_rows,
    resolve_projection,
)

__all__ = [
    "ALL_FIELDS",
    "TASK_STATE_CODES",
    "FilterCondition",
    "FilterOp",
    "Vocabulary",
    "canonical_log_field",
    "coerce_value",
    "compile_to_array",
    "compile_to_string",
    "fields_returned",
    "get_vocabulary",
    "has_projection",
    "project_rows",
    "resolve_field",
    "resolve_projection",
]
```

`enum_names` is deliberately **not** re-exported: it exists at HEAD in `fields.py` but only `filters.py` uses it, and adding it here would widen the public surface for no caller.

- [ ] **Step 4: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_query_shape.py -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: all PASS, gates clean.

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/query/shape.py src/fortianalyzer_mcp/query/__init__.py \
  tests/test_query_shape.py
git commit -m "feat(query): a projection resolver for response rows

resolve_projection turns None/[\"*\"]/a name list into a key set, reusing the
filter registry so an alias means the same thing selecting as it does
filtering. project_rows applies it; fields_returned echoes it.

Selecting is subtractive on purpose. Renaming a key would move a value out
from under the masking allowlist, which is keyed on live field names, and
silently unmask it; selecting a subset can only shrink what masking covers.
Top-level keys only, so a nested subject_details or target[] survives whole
rather than being split into a second query dialect.

fields_returned reports the projection rather than the observed keys whenever
one applied, so a zero-row page still tells the caller what is queryable --
which is when that signal is worth most."
```

---

### Task 3: The cross-tool key-survival guard

**Files:**
- Create: `tests/test_projection_join_keys.py`

**Interfaces:**
- Consumes: `get_vocabulary` from Task 1. No production code changes.

**Why this is its own task:** the spec calls this obligation non-negotiable, and it is the only test that catches a curated set breaking a *different* tool. It must exist before any tool is wired, so that Tasks 4-7 cannot land a projection that severs a workflow.

- [ ] **Step 1: Write the test**

Create `tests/test_projection_join_keys.py`:

```python
"""A projection must never drop a field another tool takes as input.

These keys are how one tool's output becomes another tool's argument. Curating
`sessionid` out of the traffic projection breaks `get_pcap_by_session` with no
error that traces back to the projection -- the caller just never finds the
field to pass. Each entry below is a real hand-off in this repo, named by the
consumer that would break.
"""

from __future__ import annotations

import pytest

from fortianalyzer_mcp.query.fields import get_vocabulary

#: (vocabulary, row key, the tool that consumes it).
JOIN_KEYS = [
    ("traffic", "sessionid", "get_pcap_by_session(session_id=...)"),
    ("traffic", "policyid", "analyze_policy_traffic(policy_ids=[...])"),
    ("traffic", "dstport", "analyze_policy_traffic port breakdown"),
    ("traffic", "proto", "analyze_policy_traffic protocol breakdown"),
    ("traffic", "service", "analyze_policy_traffic ICMP type/code decoding"),
    ("attack", "pcapurl", "download_pcap_by_url(pcapurl=...)"),
    ("attack", "sessionid", "search_and_download_pcaps"),
    ("alert", "alertid", "get_alert_logs(alert_ids=[...]) / add_alert_comment"),
    ("alert", "epid", "get_endpoint_vulnerabilities(epids=[...])"),
    ("alert", "euid", "get_endusers(euids=[...])"),
    ("incident", "alertid", "get_alert_logs(alert_ids=[...])"),
    ("incident", "epid", "get_endpoint_vulnerabilities(epids=[...])"),
    ("incident", "euid", "get_endusers(euids=[...])"),
    ("endpoint", "epid", "get_endpoint_vulnerabilities(epids=[...])"),
    ("endpoint", "euid", "get_endusers(euids=[...])"),
    ("enduser", "euid", "get_endusers(euids=[...])"),
    ("enduser", "epids", "get_endpoints(epids=[...])"),
    ("report", "id", "get_report_data(...) / save_report(...)"),
    ("device", "sn", "query_logs(device=...) / get_device(...)"),
    ("device", "name", "get_device(name=...) / delete_device(device=...)"),
    ("task", "id", "get_task_status(task_id=...)"),
]


@pytest.mark.parametrize(
    "vocabulary,key,consumer",
    JOIN_KEYS,
    ids=[f"{v}.{k}" for v, k, _ in JOIN_KEYS],
)
def test_join_key_survives_the_curated_projection(
    vocabulary: str, key: str, consumer: str
) -> None:
    projection = get_vocabulary(vocabulary).projection
    assert projection, f"{vocabulary} lost its curated projection"
    assert key in projection, (
        f"{vocabulary} projection drops '{key}', which {consumer} needs. "
        "Add it back: a caller cannot pass a field the projection removed."
    )


@pytest.mark.parametrize(
    "vocabulary,key,consumer",
    JOIN_KEYS,
    ids=[f"{v}.{k}" for v, k, _ in JOIN_KEYS],
)
def test_join_key_is_a_real_field_of_its_vocabulary(
    vocabulary: str, key: str, consumer: str
) -> None:
    """Guards the guard: a typo here would make the assertion above vacuous."""
    canonical = get_vocabulary(vocabulary).canonical
    assert key in canonical, f"'{key}' is not a known {vocabulary} field"
```

- [ ] **Step 2: Run it**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_projection_join_keys.py -q --no-cov
```
Expected: all PASS against Task 1's curated sets. **If any fail, fix the projection in `query/fields.py`, not the test** — the test encodes a real hand-off, and the projection is the thing that is wrong.

- [ ] **Step 3: Run the gates and full suite**

```bash
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_projection_join_keys.py
git commit -m "test(query): assert every cross-tool join key survives projection

Twenty-one keys are how one tool's rows become another tool's arguments:
sessionid into get_pcap_by_session, pcapurl into download_pcap_by_url, alertid
into get_alert_logs, epid into get_endpoint_vulnerabilities, and so on.

Curating one of these away breaks a workflow with no error that points back at
the projection -- the caller simply never finds the field to pass. This lands
before any tool is wired so a later task cannot sever a hand-off unnoticed. A
second parametrisation checks each key is a real field of its vocabulary, so a
typo in the guard cannot make the guard vacuous."
```

---

### Task 4: `query_logs` and `fetch_more_logs` project

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/log_tools.py`
- Test: `tests/test_log_tools.py`

**Interfaces:**
- Consumes: `resolve_projection`, `project_rows`, `fields_returned` from Task 2.
- Produces: `query_logs(..., fields: list[str] | None = None)` and `fetch_more_logs(..., fields: list[str] | None = None)`. Both add `fields_returned` to the response. `query_logs` records the resolved projection in `_SEARCH_REGISTRY` so a page-2 caller who omits `fields` gets the same shape as page 1.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_log_tools.py`, inside the existing `TestQueryLogsStructuredFilters`'s file (as a new sibling class):

```python
class TestQueryLogsProjection:
    """fields selects; the response says what it selected."""

    CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"

    class _Faz:
        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

    def _install(self, monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, Any]]) -> None:
        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            return {"timed_out": False, "tid": 7, "logs": rows, "total": len(rows)}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: self._Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

    ROW = {
        "date": "2024-01-01",
        "time": "00:00:01",
        "srcip": "10.0.0.1",
        "dstport": 443,
        "sessionid": 99,
        "noise": "unused",
        "another_noise": "also unused",
    }

    async def test_default_applies_the_curated_projection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await log_tools.query_logs(logtype="traffic", time_range=self.CUSTOM_RANGE)

        assert "noise" not in result["logs"][0]
        assert result["logs"][0]["srcip"] == "10.0.0.1"
        assert "sessionid" in result["logs"][0], "join key must survive the default"

    async def test_star_returns_the_full_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, fields=["*"]
        )

        assert result["logs"][0]["noise"] == "unused"
        assert result["fields_returned"] == sorted(self.ROW)

    async def test_explicit_fields_select_exactly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, fields=["srcip", "dstport"]
        )

        assert result["logs"] == [{"srcip": "10.0.0.1", "dstport": 443}]
        assert result["fields_returned"] == ["dstport", "srcip"]

    async def test_alias_in_fields_resolves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, fields=["source_ip"]
        )

        assert result["fields_returned"] == ["srcip"]

    async def test_fields_returned_survives_a_zero_row_page(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The signal matters most when there is nothing else to go on."""
        self._install(monkeypatch, [])

        result = await log_tools.query_logs(
            logtype="traffic", time_range=self.CUSTOM_RANGE, fields=["srcip", "dstport"]
        )

        assert result["logs"] == []
        assert result["fields_returned"] == ["dstport", "srcip"]

    async def test_uncurated_logtype_returns_full_rows_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [{"a": 1, "b": 2}])

        result = await log_tools.query_logs(logtype="voip", time_range=self.CUSTOM_RANGE)

        assert result["logs"] == [{"a": 1, "b": 2}]
        assert any("fields" in w for w in result["warnings"])

    async def test_empty_fields_list_is_a_validation_error(self) -> None:
        result = await log_tools.query_logs(logtype="traffic", fields=[])

        assert result["status"] == "error"
        assert result["error"] == "validation_error"


class TestFetchMoreLogsProjection:
    """Page 2 keeps page 1's shape unless the caller asks otherwise."""

    async def test_stored_projection_is_reused_when_fields_is_omitted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [{"srcip": "10.0.0.1", "dstport": 443, "noise": "x"}]

        class _Faz:
            async def ensure_connected(self) -> None:
                return None

            async def get_system_timezone(self) -> None:
                return None

        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            return {"timed_out": False, "tid": 7, "logs": rows, "total": 50}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: _Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        first = await log_tools.query_logs(
            logtype="traffic",
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
            fields=["srcip", "dstport"],
        )
        handle = first["tid"]

        second = await log_tools.fetch_more_logs(tid=handle, offset=1)

        assert "noise" not in second["logs"][0]
        assert second["fields_returned"] == ["dstport", "srcip"]

    async def test_fields_on_the_page_call_overrides_the_stored_projection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [{"srcip": "10.0.0.1", "dstport": 443, "noise": "x"}]

        class _Faz:
            async def ensure_connected(self) -> None:
                return None

            async def get_system_timezone(self) -> None:
                return None

        async def fake_page(client: object, **kwargs: object) -> dict[str, object]:
            return {"timed_out": False, "tid": 7, "logs": rows, "total": 50}

        monkeypatch.setattr(log_tools, "get_faz_client", lambda: _Faz())
        monkeypatch.setattr(log_tools, "_run_logsearch_page", fake_page)

        first = await log_tools.query_logs(
            logtype="traffic",
            time_range="2024-01-01 00:00:00|2024-01-02 00:00:00",
            fields=["srcip"],
        )

        second = await log_tools.fetch_more_logs(tid=first["tid"], offset=1, fields=["dstport"])

        assert second["fields_returned"] == ["dstport"]
```

Add `from typing import Any` to the test file's imports if it is not already there.

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_log_tools.py -k Projection -q --no-cov
```
Expected: FAIL — `query_logs() got an unexpected keyword argument 'fields'`.

- [ ] **Step 3: Implement in `query_logs`**

Add the import to `src/fortianalyzer_mcp/tools/log_tools.py`:

```python
from fortianalyzer_mcp.query.shape import fields_returned, project_rows, resolve_projection
```

Add the parameter after `filters`:

```python
async def query_logs(
    adom: str | None = None,
    logtype: str = "traffic",
    device: str | None = None,
    time_range: str = "1-hour",
    filter: str | None = None,
    filters: list[FilterCondition] | None = None,
    fields: list[str] | None = None,
    limit: int = 100,
    offset: int = 0,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
```

Add to the docstring's `Args:`, immediately after the `filters:` entry:

```
        fields: Which keys each returned row should carry. Omit for a curated
            default (the fields that answer most questions about this logtype,
            including the ones other tools take as input); pass ["*"] for the
            full row as before; or name the fields you want. English aliases
            work here exactly as they do in `filters`.
            Example: fields=["srcip", "dstip", "action", "sentbyte"]
```

And to the `Returns:` block, after the `logs:` line:

```
            - fields_returned: The keys each row carries. Reported even for a
              zero-row page, so it still says what is queryable next.
```

Resolve the projection next to the filter compilation, so both fail before the
appliance is touched. Immediately after the `if filters:` block added in Plan 1:

```python
        projection, projection_warnings = resolve_projection(logtype, fields)
```

`resolve_projection` raises `ValidationError`, which the existing
`except ValidationError` handler already converts — no new handler.

Apply it where the response is built. Find `logs = page["logs"]` and change it to:

```python
        logs = project_rows(page["logs"], projection)
```

Extend the warnings — find the `warnings.extend(filter_warnings)` line from Plan 1 and add below it:

```python
        warnings.extend(projection_warnings)
```

Add the echo to the returned dict, beside the existing `"logs": logs` entry:

```python
            "fields_returned": fields_returned(logs, projection),
```

Record the projection on the handle so paging is consistent. Find the
`_register_search(...)` call and add `fields` to the stored context dict:

```python
                "fields": fields,
```

Store the caller's original `fields` argument rather than the resolved key set:
`fetch_more_logs` re-resolves it, which keeps one code path for resolution and
means a registry entry stays a plain JSON-ish dict.

- [ ] **Step 4: Implement in `fetch_more_logs`**

Add the parameter:

```python
async def fetch_more_logs(
    adom: str | None = None,
    tid: int = 0,
    limit: int = 100,
    offset: int = 0,
    fields: list[str] | None = None,
    timeout: int = DEFAULT_SEARCH_TIMEOUT,
) -> dict[str, Any]:
```

Add to its docstring's `Args:`:

```
        fields: Override the projection for this page. Omit to reuse the
            projection the original query_logs call resolved, so a later page
            has the same shape as the first.
```

In the body, after the stored context is retrieved and its `logtype` is known,
resolve using the stored value as the fallback:

```python
        effective_fields = fields if fields is not None else context.get("fields")
        projection, projection_warnings = resolve_projection(logtype, effective_fields)
```

Apply it to the page's rows exactly as `query_logs` does, extend `warnings` with
`projection_warnings`, and add `"fields_returned": fields_returned(logs, projection)`
to the response dict.

- [ ] **Step 5: Run the tests and the pagination/contract suites**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/test_log_tools.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_response_contract.py tests/test_log_pagination.py tests/test_logsearch_runner.py \
  tests/test_mcp_tools.py tests/test_bugfix_regressions.py -q --no-cov
```
Expected: all PASS. `tests/test_response_contract.py` asserts on response keys and may assert an exact key set — if it fails, add `fields_returned` to its expected keys; that is the contract changing on purpose.

Existing tests that assert on full row contents will now see curated rows. Where one breaks, prefer `fields=["*"]` in that test over widening the projection: the test was written before projection existed and wants the old shape.

- [ ] **Step 6: Run the gates and full suite**

```bash
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```

- [ ] **Step 7: Commit**

```bash
git add src/fortianalyzer_mcp/tools/log_tools.py tests/test_log_tools.py
git commit -m "feat(log-tools): query_logs and fetch_more_logs project their rows

fields selects which keys a row carries: omitted gives the curated default,
[\"*\"] the full row as before, a list exactly that list with aliases accepted.
fields_returned echoes the result, and is reported even for a zero-row page --
which is precisely when a caller has nothing else to tell it what is
queryable next.

The handle records the caller's fields argument, so fetch_more_logs reproduces
page one's shape without the caller restating it, and re-resolves rather than
storing the key set so resolution keeps one code path.

An uncurated logtype returns full rows and a warning, not a guessed subset."
```

---

### Task 5: The eventmgmt and incidentmgmt readers project

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/event_tools.py` (`get_alerts` at :44, `get_alert_logs` at :231)
- Modify: `src/fortianalyzer_mcp/tools/incident_tools.py` (`get_incidents` at :59)
- Test: `tests/test_event_tools.py`, `tests/test_incident_tools.py`

**Interfaces:**
- Consumes: `resolve_projection`, `project_rows`, `fields_returned` from Task 2.
- Produces: `fields` on all three tools. These return rows under the `"data"` key, not `"logs"`.

**Note on the row container:** `get_alerts` and `get_incidents` return `{"status": ..., "data": <rows>}`. `data` may be a list or, on some responses, a dict. Project only when it is a list; a dict passes through untouched and no `fields_returned` is claimed for it.

**Note on the error envelope — read before Step 4.** Neither `event_tools` nor `incident_tools` imports `error_response`; every failure path in both is the ad-hoc `except Exception as e: return {"status": "error", "message": redact(str(e))}`, with no machine-readable `error` code. `resolve_projection` raises `ValidationError` for a bad `fields`, and left alone it would fall into that generic handler and surface as an untyped message — with no machine code a caller can branch on, which is what the spec's error table exists to prevent.

So each tool this task touches gains **one** targeted handler, placed *above* the existing `except Exception`:

```python
    except ValidationError as e:
        return error_response(
            error="validation_error",
            message=e,
            operation="get_alerts",  # the tool's own name
            adom=adom,
        )
```

**Why `validation_error` and not the spec's `unknown_field`.** Every vocabulary these five tools use — `alert`, `incident`, `endpoint`, `enduser`, `report`, `event` — is `complete=False`, so `resolve_field` *passes an unknown name through with a warning* rather than raising. The only failures `resolve_projection` can actually produce here are the empty list and `"*"` mixed with names, neither of which is an unknown field. Emitting `unknown_field` would name a condition that cannot occur on these tools while mislabelling the two that can. `validation_error` is both accurate and consistent with `dvm_tools`, which already returns it.

`unknown_field` is still correct where the spec puts it — a `complete=True` vocabulary (`device`, `task`) genuinely can reject a name. If a later change flips one of these five vocabularies to `complete=True`, revisit this.

with the imports:

```python
from fortianalyzer_mcp.utils.errors import ValidationError
from fortianalyzer_mcp.utils.responses import error_response
```

This is deliberately narrow. The spec says the tools it rewrites gain the envelope while untouched modules stay as they are and converting them is a separate job — so convert **only the `ValidationError` path on the tools this plan gives `fields` to**. Do not rewrite the other failure paths in these modules, and do not touch tools this plan does not otherwise modify. The same handler is added in Task 6 to `get_endpoints`, `get_endusers`, `get_fortiview_data` and `get_report_history`, each naming its own `operation`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_event_tools.py`:

```python
class TestGetAlertsProjection:
    """Alerts project under the alert vocabulary."""

    ROW = {
        "alertid": "A-1",
        "severity": "high",
        "status": "open",
        "epid": 12,
        "euid": 34,
        "extrainfo": "verbose",
        "subject_details": {"nested": "kept whole"},
    }

    def _install(self, monkeypatch: pytest.MonkeyPatch, rows: object) -> None:
        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_alerts(self, **kwargs: object) -> object:
                return rows

        monkeypatch.setattr(event_tools, "_get_client", lambda: FakeClient())

    async def test_default_projection_trims_and_keeps_join_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await event_tools.get_alerts()

        row = result["data"][0]
        assert "extrainfo" not in row
        assert row["alertid"] == "A-1"
        assert row["epid"] == 12 and row["euid"] == 34

    async def test_star_returns_the_full_alert(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await event_tools.get_alerts(fields=["*"])

        assert result["data"][0]["extrainfo"] == "verbose"

    async def test_selecting_a_nested_key_keeps_it_whole(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await event_tools.get_alerts(fields=["alertid", "subject_details"])

        assert result["data"][0]["subject_details"] == {"nested": "kept whole"}

    async def test_fields_returned_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await event_tools.get_alerts(fields=["alertid", "severity"])

        assert result["fields_returned"] == ["alertid", "severity"]

    # REMOVED 2026-07-28 during execution — this test was a plan defect.
    #
    # It asserted that a bare-dict payload reaches the caller untouched. But
    # get_alerts and get_incidents have ALWAYS normalised `data` to a list:
    #
    #     data = result.get("data", []) if isinstance(result, dict) else result
    #     if not isinstance(data, list):
    #         data = [data] if data else []
    #
    # and the skills layer depends on that guarantee -- handlers.py:286 types
    # it `list[dict[str, Any]]` and enumerates it; :327, :527 and :542 iterate
    # it. Removing the coercion to satisfy this test makes a dict payload
    # iterate as dict KEYS in those loops: silently wrong data, and no test
    # covers the path.
    #
    # Adjudicated by the human partner: the existing code contract governs.
    # The coercion stays, this test is gone, and project_payload keeps its
    # list-only rule at the query/shape.py layer where it is still correct and
    # still tested. Do not reinstate this test against these two tools.

    async def test_an_empty_fields_list_is_a_typed_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A bad projection must carry a machine code, not just a message.

        event_tools has no error_response handler of its own, so without the
        targeted ValidationError handler this returns an untyped
        {"status": "error", "message": ...} and the caller cannot branch on it.
        """
        self._install(monkeypatch, [dict(self.ROW)])

        result = await event_tools.get_alerts(fields=[])

        assert result["status"] == "error"
        assert result["error"] == "validation_error"

    async def test_an_unknown_alert_field_warns_rather_than_erroring(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The alert vocabulary is complete=False, so it cannot reject a name.

        This is why the handler above emits validation_error rather than
        unknown_field: on this tool, an unknown name is not an error at all.
        """
        self._install(monkeypatch, [dict(self.ROW)])

        result = await event_tools.get_alerts(fields=["alertid", "mystery_field"])

        assert result["status"] == "success"
        assert "mystery_field" in result["fields_returned"]
        assert result["warnings"]
```

Add the imports the file needs:

```python
import fortianalyzer_mcp.tools.event_tools as event_tools
```

Append the mirror to `tests/test_incident_tools.py`:

```python
class TestGetIncidentsProjection:
    """Incidents project under the incident vocabulary."""

    ROW = {
        "incid": 5,
        "severity": "high",
        "status": "open",
        "alertid": "A-1",
        "epid": 12,
        "euid": 34,
        "description": "long free text",
    }

    def _install(self, monkeypatch: pytest.MonkeyPatch, rows: object) -> None:
        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_incidents(self, **kwargs: object) -> object:
                return rows

        monkeypatch.setattr(incident_tools, "_get_client", lambda: FakeClient())

    async def test_default_projection_keeps_the_join_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await incident_tools.get_incidents()

        row = result["data"][0]
        assert "description" not in row
        assert row["alertid"] == "A-1"
        assert row["epid"] == 12 and row["euid"] == 34

    async def test_star_returns_the_full_incident(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, [dict(self.ROW)])

        result = await incident_tools.get_incidents(fields=["*"])

        assert result["data"][0]["description"] == "long free text"
```

Add `import fortianalyzer_mcp.tools.incident_tools as incident_tools` to that file.

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_event_tools.py tests/test_incident_tools.py -k Projection -q --no-cov
```
Expected: FAIL — unexpected keyword argument `fields`.

- [ ] **Step 3: Add a shared helper for the `data`-shaped tools**

Three tools repeat the same five lines, so put the pattern in `query/shape.py`
rather than copying it. Append to that module:

```python
def project_payload(
    vocabulary: str,
    payload: Any,
    fields: list[str] | None,
) -> tuple[Any, list[str], list[str]]:
    """Project a response payload that may or may not be a row list.

    Several FortiAnalyzer readers answer with a list of rows under ``data``,
    but some answer with an object instead (a count, a status envelope). Only
    a list is projected; anything else passes through untouched and reports no
    ``fields_returned``, because claiming a projection that did not happen is
    worse than reporting none.

    Returns:
        ``(payload, fields_returned, warnings)``.

    Raises:
        ValidationError: from :func:`resolve_projection`.
    """
    keys, warnings = resolve_projection(vocabulary, fields)
    if not isinstance(payload, list):
        return payload, [], warnings
    rows = project_rows(payload, keys)
    return rows, fields_returned(rows, keys), warnings
```

Add `project_payload` to `query/__init__.py`'s imports and `__all__`.

- [ ] **Step 4: Wire the three tools**

In `src/fortianalyzer_mcp/tools/event_tools.py` add the import:

```python
from fortianalyzer_mcp.query.shape import project_payload
```

`get_alerts` gains the parameter after `offset`:

```python
async def get_alerts(
    adom: str | None = None,
    time_range: str = "24-hour",
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
    fields: list[str] | None = None,
) -> dict[str, Any]:
```

Docstring `Args:` entry:

```
        fields: Which keys each alert carries. Omit for a curated default
            (identity, severity, status, timing and the epid/euid/alertid join
            keys), ["*"] for the full object, or name the fields you want.
```

In the body, where the response is built as `{"status": "success", ..., "data": data}`,
replace that construction with:

```python
        data, returned, projection_warnings = project_payload("alert", data, fields)
```

and add `"fields_returned": returned` to the returned dict. If the function already
builds a `warnings` list, extend it with `projection_warnings`; if it does not,
add `"warnings": projection_warnings` to the response.

Apply the identical change to `get_alert_logs` — its rows are *logs*, not alerts,
so it uses the `"event"` vocabulary, not `"alert"`:

```python
        data, returned, projection_warnings = project_payload("event", data, fields)
```

In `src/fortianalyzer_mcp/tools/incident_tools.py`, the same with `"incident"`:

```python
from fortianalyzer_mcp.query.shape import project_payload
...
        data, returned, projection_warnings = project_payload("incident", data, fields)
```

- [ ] **Step 5: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_event_tools.py tests/test_incident_tools.py tests/test_query_shape.py -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: green. Also re-run the masking suites, since alerts carry the composite `target[]` that masking treats specially:

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_masking_leak.py tests/test_masking_wrapper.py -q --no-cov
```

- [ ] **Step 6: Commit**

```bash
git add src/fortianalyzer_mcp/query/shape.py src/fortianalyzer_mcp/query/__init__.py \
  src/fortianalyzer_mcp/tools/event_tools.py src/fortianalyzer_mcp/tools/incident_tools.py \
  tests/test_event_tools.py tests/test_incident_tools.py
git commit -m "feat(tools): projection for the alert and incident readers

get_alerts, get_alert_logs and get_incidents take fields. get_alert_logs
projects under the event vocabulary rather than alert -- its rows are the logs
that triggered an alert, not the alerts.

These three answer under a data key that is usually a row list but sometimes
an object, so project_payload projects only lists and reports no
fields_returned otherwise: claiming a projection that did not happen is worse
than reporting none.

Nested subject_details and target[] survive whole when selected, which is what
keeps the masking layer's composite handling working."
```

---

### Task 6: UEBA, FortiView and report history project

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/ueba_tools.py` (`get_endpoints` at :47, `get_endusers` at :144)
- Modify: `src/fortianalyzer_mcp/tools/fortiview_tools.py` (`get_fortiview_data` at :231)
- Modify: `src/fortianalyzer_mcp/tools/report_tools.py` (`get_report_history` at :586)
- Test: `tests/test_ueba_tools.py`, `tests/test_fortiview_tools.py`, `tests/test_report_tools.py`

Line numbers are as of `627a138` and are a hint, not an anchor — locate by name.

**Interfaces:**
- Consumes: `project_payload` from Task 5.
- Produces: `fields` on the four tools.

**All four modules need Task 5's targeted `ValidationError` handler**, for the same reason: none of `ueba_tools`, `fortiview_tools` or `report_tools` imports `error_response` either, so a bad `fields` would otherwise surface untyped. Add the same `except ValidationError` block above each tool's existing `except Exception`, naming that tool in `operation=`.

**FortiView is per-view, not per-logtype.** A FortiView row's keys depend on the
view (`top-sources` returns source rows, `policy-hits` returns policy rows), and
this plan does not curate them — the view catalogue is a spec verification item.
So `get_fortiview_data` registers no curated set and its `fields=None` path
returns full rows with the uncurated warning. An explicit `fields` list still
works, validated against the generic log vocabulary, which is permissive.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_ueba_tools.py`:

```python
class TestUebaProjection:
    """Endpoints and endusers project, keeping epid/euid."""

    async def test_endpoints_default_keeps_the_join_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        row = {"epid": 1, "euid": 2, "hostname": "h", "vulnstat": {"big": "payload"}}

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_endpoints(self, **kwargs: object) -> list[dict[str, object]]:
                return [row]

        monkeypatch.setattr(ueba_tools, "_get_client", lambda: FakeClient())

        result = await ueba_tools.get_endpoints()

        assert result["data"][0]["epid"] == 1
        assert result["data"][0]["euid"] == 2
        assert "vulnstat" not in result["data"][0]

    async def test_endusers_star_returns_everything(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        row = {"euid": 2, "username": "jdoe", "phone": "555"}

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_endusers(self, **kwargs: object) -> list[dict[str, object]]:
                return [row]

        monkeypatch.setattr(ueba_tools, "_get_client", lambda: FakeClient())

        result = await ueba_tools.get_endusers(fields=["*"])

        assert result["data"][0]["phone"] == "555"
```

Append to `tests/test_fortiview_tools.py`:

```python
class TestFortiViewProjection:
    """FortiView rows are per-view, so there is no curated default."""

    ROWS = [{"srcip": "10.0.0.1", "bandwidth": 100, "sessions": 4}]

    class FakeClient:
        """get_fortiview_data starts a task then polls fetch until 100%."""

        def __init__(self, rows: list[dict[str, object]]) -> None:
            self.rows = rows

        async def ensure_connected(self) -> None:
            return None

        async def get_system_timezone(self) -> None:
            return None

        async def fortiview_run(self, **kwargs: object) -> dict[str, object]:
            return {"tid": 4242}

        async def fortiview_fetch(self, **kwargs: object) -> dict[str, object]:
            return {"percentage": 100, "data": self.rows}

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            fortiview_tools, "_get_client", lambda: self.FakeClient(list(self.ROWS))
        )

    async def test_default_returns_full_rows_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch)

        result = await fortiview_tools.get_fortiview_data(view_name="top-sources")

        assert result["data"][0]["sessions"] == 4
        assert any("fields" in w for w in result["warnings"])

    async def test_explicit_fields_select(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install(monkeypatch)

        result = await fortiview_tools.get_fortiview_data(
            view_name="top-sources", fields=["srcip", "bandwidth"]
        )

        assert result["data"] == [{"srcip": "10.0.0.1", "bandwidth": 100}]
```

`get_fortiview_data` calls `client.fortiview_run` for a tid (`fortiview_tools.py:300`)
and then polls `client.fortiview_fetch` (`:332`) until `percentage` reaches 100 —
there is no single internal helper to patch, which is why the fake supplies both.
Both names verified at `627a138`. Read the function body (`fortiview_tools.py:284`
onward) before adapting the fake; the `_parse_time_range` call reaches
`get_system_timezone` on the client for a relative range, which is why the fake
provides it.

Append to `tests/test_report_tools.py`:

```python
class TestReportHistoryProjection:
    """Report rows project under the report vocabulary."""

    async def test_default_trims_and_keeps_the_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        row = {"id": "r-1", "title": "Weekly", "state": "done", "owner": "admin"}

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_report_history(self, **kwargs: object) -> list[dict[str, object]]:
                return [row]

        monkeypatch.setattr(report_tools, "_get_client", lambda: FakeClient())

        result = await report_tools.get_report_history()

        assert result["data"][0]["id"] == "r-1"
        assert "owner" not in result["data"][0]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_ueba_tools.py tests/test_fortiview_tools.py tests/test_report_tools.py \
  -k Projection -q --no-cov
```
Expected: FAIL — unexpected keyword argument `fields`.

- [ ] **Step 3: Wire the four tools**

Each follows the Task 5 pattern exactly. Add to each module:

```python
from fortianalyzer_mcp.query.shape import project_payload
```

`get_endpoints` — parameter after `time_range`, vocabulary `"endpoint"`:

```python
async def get_endpoints(
    adom: str | None = None,
    epids: list[int] | None = None,
    detail_level: str = "standard",
    time_range: str | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
```

```python
        data, returned, projection_warnings = project_payload("endpoint", data, fields)
```

`get_endusers` — parameter after `detail_level`, vocabulary `"enduser"`.

`get_report_history` — parameter after `title`, vocabulary `"report"`.

`get_fortiview_data` — parameter after `sort_order`, vocabulary `"fortiview"`:

```python
        data, returned, projection_warnings = project_payload("fortiview", data, fields)
```

`"fortiview"` is not a registered vocabulary, so `get_vocabulary` falls back to
the generic log vocabulary: no curated set (full rows plus the warning), and an
explicit list is accepted with a pass-through warning for unrecognised names.
That is the intended behaviour until the per-view catalogue is verified live —
**do not** add a `fortiview` entry to `_VOCABULARIES` guessing at columns.

Each tool adds `"fields_returned": returned` to its response and extends its
warnings with `projection_warnings`.

Add the docstring `Args:` entry to each, matching the wording used in Task 5 but
naming that tool's curated content. For `get_fortiview_data`, say plainly that
there is no curated default yet:

```
        fields: Which keys each row carries. FortiView columns differ per view
            and are not curated yet, so omitting this returns full rows with a
            warning. Pass the columns you want, or ["*"] to silence the warning.
```

- [ ] **Step 4: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_ueba_tools.py tests/test_fortiview_tools.py tests/test_report_tools.py -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: green. The skills layer composes several of these readers — run its suite too:

```bash
FORTIANALYZER_HOST=ci-dummy.local FAZ_SKILLS_ENABLED=true PYTHONPATH=src uv run pytest \
  tests/test_skills_handlers.py -q --no-cov
```
If a skill asserts on a field the curated set drops, the skill should pass an
explicit `fields` list naming what it needs — that is the projection working,
not a bug. Do not widen a curated set to satisfy one skill.

- [ ] **Step 5: Commit**

```bash
git add src/fortianalyzer_mcp/tools/ueba_tools.py src/fortianalyzer_mcp/tools/fortiview_tools.py \
  src/fortianalyzer_mcp/tools/report_tools.py tests/test_ueba_tools.py \
  tests/test_fortiview_tools.py tests/test_report_tools.py
git commit -m "feat(tools): projection for the UEBA, FortiView and report readers

get_endpoints, get_endusers, get_fortiview_data and get_report_history take
fields, on the same contract as the log and alert readers.

FortiView deliberately gets no curated default: its columns differ per view and
the view catalogue is still an unverified item, so omitting fields returns full
rows and a warning rather than a subset guessed from column names nobody has
confirmed. An explicit list still works."
```

---

### Task 7: `search_devices` projects natively, and the surface is documented

**Files:**
- Modify: `src/fortianalyzer_mcp/tools/dvm_tools.py` (`search_devices`)
- Modify: `src/fortianalyzer_mcp/instructions.py`
- Modify: `CHANGELOG.md`
- Test: `tests/test_dvm_tools.py`, `tests/test_server_instructions.py`

**Interfaces:**
- Consumes: `resolve_projection` from Task 2.
- Produces: `search_devices(..., fields: list[str] | None = None)` — the parameter already exists; this task changes what it *does*.

**Why this one is different, twice over.**

First, dvmdb accepts a native `fields` parameter — `list_devices` and `list_adoms`
already pass one through. Projecting in-process would still transfer the full
object. So `search_devices` resolves the names locally (for aliases and
validation) and then *sends* them.

Second — and this is the part that changed since this plan was first drafted —
**`search_devices` already takes `fields`.** PR #94 shipped it at
`dvm_tools.py:488` as a raw pass-through: the caller's list goes straight to
`client.list_devices(fields=fields)` with no alias resolution, no validation, and
no default. So this task is not "add a parameter", it is three edits to an
existing one:

| Today at `627a138` | After this task |
| --- | --- |
| `fields=["serial_number"]` reaches dvmdb verbatim and returns nothing useful | resolves to `sn` before the call |
| `fields=["not_a_field"]` reaches the appliance and fails there, or silently returns rows without it | `ValidationError` locally — `device` is `complete=True` |
| `fields` omitted returns every field (~60/device) | returns the curated set |
| no `fields_returned` in the response | `fields_returned` echoes what was sent |

The third row changes what an existing parameter does when omitted. **It is not a
released behaviour change:** `fields` on `search_devices` landed in PR #94 and
sits under `## [Unreleased]` in `CHANGELOG.md` — no tagged version has ever
carried it, so no caller can be relying on the ~60-key default and no migration
note is owed. Amend the Unreleased entry rather than filing a `### Changed` for a
behaviour nobody has. What the task *does* still owe is the docstring: it
currently promises "Omitting this returns every field the appliance defines",
which this task makes false, so it must be rewritten rather than appended to.

**Two existing tests in `tests/test_dvm_tools.py` already cover this parameter**,
inside `TestSearchDevicesStructuredFilters`:

- `test_fields_projection_is_forwarded` asserts `captured_fields == ["name", "os_ver"]`.
  It still passes — those two names resolve to themselves and `sorted()` leaves
  them in that order. Do not modify it.
- `test_validation_error_returns_the_standard_envelope` confirms `dvm_tools`
  already speaks the error envelope, which is why Step 3 adds no handler.

That class also already defines a `FakeClient` capturing both `filter` and
`fields`, plus an `_install` helper. Step 1's new test class repeats them so it
reads standalone; if you would rather reuse the existing pair, that is fine —
just keep the assertions.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_dvm_tools.py`:

```python
class TestSearchDevicesProjection:
    """Device projection is native: the field list goes to dvmdb."""

    class FakeClient:
        def __init__(self) -> None:
            self.captured_fields: list[str] | None = None

        async def list_devices(
            self,
            adom: str,
            filter: list[list[Any]] | None = None,
            fields: list[str] | None = None,
        ) -> list[dict[str, Any]]:
            self.captured_fields = fields
            return [{"name": "fgt-01", "ip": "10.0.0.1"}]

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> FakeClient:
        fake = self.FakeClient()
        monkeypatch.setattr(dvm_tools, "_get_client", lambda: fake)
        return fake

    async def test_default_sends_the_curated_field_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices()

        assert fake.captured_fields is not None
        assert "name" in fake.captured_fields
        assert "sn" in fake.captured_fields, "join key must survive"
        assert "adm_usr" not in fake.captured_fields

    async def test_star_sends_no_field_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """["*"] means the appliance default, which is every field."""
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(fields=["*"])

        assert fake.captured_fields is None

    async def test_alias_is_resolved_before_sending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(fields=["serial_number", "os_version"])

        assert fake.captured_fields is not None
        assert sorted(fake.captured_fields) == ["os_ver", "sn"]

    async def test_unknown_field_is_rejected_locally(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Unreachable:
            async def list_devices(self, **kwargs: Any) -> list[dict[str, Any]]:
                raise AssertionError("must not reach the API")

        monkeypatch.setattr(dvm_tools, "_get_client", lambda: Unreachable())

        result = await dvm_tools.search_devices(fields=["not_a_field"])

        assert result["status"] == "error"
        assert "conn_status" in result["message"]
```

Append to `tests/test_server_instructions.py`:

```python
def test_projection_surface_is_documented(instructions: str) -> None:
    """A caller who does not know `fields` exists pays for every key."""
    assert "fields" in instructions
    assert '["*"]' in instructions or '"*"' in instructions


def test_curated_default_is_described_as_a_default_not_a_limit(
    instructions: str,
) -> None:
    """The opt-out must be discoverable in the same breath as the default."""
    lowered = instructions.lower()
    assert "curated" in lowered
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_dvm_tools.py -k Projection tests/test_server_instructions.py -q --no-cov
```
Expected: FAIL — unexpected keyword argument `fields`, and the two instructions tests fail.

- [ ] **Step 3: Implement in `search_devices`**

Add the import to `src/fortianalyzer_mcp/tools/dvm_tools.py`:

```python
from fortianalyzer_mcp.query.shape import resolve_projection
```

The signature already reads as below (`dvm_tools.py:481`) — **leave it alone**:

```python
async def search_devices(
    adom: str | None = None,
    name_filter: str | None = None,
    platform_filter: str | None = None,
    os_version_filter: str | None = None,
    connection_status: str | None = None,
    filters: list[FilterCondition] | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
```

**Replace** the existing `fields:` docstring entry — the one beginning "Specific
fields to return per device" and promising that omitting it "returns every field
the appliance defines" — with:

```
        fields: Which keys each device carries. Unlike the log tools this is
            native -- the list is sent to dvmdb, so the untrimmed object never
            crosses the wire. Omit for a curated default (name, ip, sn,
            hostname, version, platform, status, vdom); pass ["*"] for every
            field the appliance defines, roughly 60 per device and mostly empty
            placeholders; or name the fields you want. English aliases work here
            exactly as they do in `filters` -- serial_number resolves to sn.
            The appliance always adds ``oid`` to each object regardless.
```

The `oid` sentence is carried over from the docstring being replaced: it is a
live-observed appliance behaviour, and losing it here would lose the only place
the repo records it.

Now change the call. Today the body reads:

```python
        devices = await client.list_devices(
            adom=adom,
            filter=entries if entries else None,
            fields=fields,
        )
```

Replace it with a resolve-then-forward:

```python
        projection, projection_warnings = resolve_projection("device", fields)
        # dvmdb projects natively, so send the names rather than trimming the
        # response: a subset chosen here would still have crossed the wire whole.
        # sorted() so the wire payload is deterministic and diffable in a trace.
        field_list = sorted(projection) if projection is not None else None

        devices = await client.list_devices(
            adom=adom,
            filter=entries if entries else None,
            fields=field_list,
        )
```

Add to the response dict, beside the existing `"filter_applied"` entry:

```python
            "fields_returned": field_list if field_list is not None else [],
            "warnings": projection_warnings,
```

`fields_returned` is `[]` rather than the observed keys when the caller passed
`["*"]`: the appliance chose the shape, so this function has nothing it can
honestly claim about it. `[]` reads as "no projection applied", which is true.

`resolve_projection` raises `ValidationError` for an unknown device field (the
`device` vocabulary is `complete=True`). Unlike the modules in Tasks 5 and 6,
`dvm_tools` **already** has the right handler — `except ValidationError` at
`dvm_tools.py:593` returning `error_response(error="validation_error", ...)` —
so no new handler is needed here. Note the code it emits is `validation_error`,
not the spec's `unknown_field`; leave it as it is. Changing it would alter the
error code of every other validation failure in `search_devices`, which is a
contract change well outside this plan.

- [ ] **Step 4: Rewrite the instructions section**

In `src/fortianalyzer_mcp/instructions.py`, insert a new section immediately
after the `## Filters` section added in Plan 1:

```
## Projection

Every read tool takes `fields`, and the default is curated rather than
complete:

  fields omitted   -> the curated set for that vocabulary
  fields=["*"]     -> the full object, exactly as before
  fields=[...]     -> those fields (English aliases work, same as in filters)

The curated set carries identity, the discriminator, the magnitude, the
human-readable summary, and every key another tool takes as input -- so
`sessionid` survives for get_pcap_by_session and `alertid` for get_alert_logs.
It is a default, not a ceiling: ask for `["*"]` whenever you need the rest.

`fields_returned` in every response lists the keys the rows carry, and is
reported even when a page comes back empty -- that is the only signal of what
is queryable next when there are no rows to inspect.

Vocabularies without a curated set yet (uncommon logtypes, FortiView views)
return full rows plus a warning naming `fields`, never a guessed subset.
list_adoms, list_devices and search_devices project on the appliance, so their
`fields` also shrinks what crosses the wire.
```

- [ ] **Step 5: Add the CHANGELOG entry**

Two entries, because this plan both adds a surface and changes a shipped one.

First, under `## [Unreleased]` in the existing `### Added` block, above the structured-filters entry:

```markdown
- **Projection (`fields`) on every read tool.** `query_logs`, `fetch_more_logs`, `get_alerts`, `get_alert_logs`, `get_incidents`, `get_endpoints`, `get_endusers`, `get_fortiview_data`, `get_report_history` and `search_devices` take `fields: list[str] | None`. Omitting it returns a **curated** subset for that vocabulary; `fields=["*"]` returns the full object exactly as before; an explicit list returns those keys, with the same English aliases the filter surface accepts. A traffic row is roughly sixty keys and a typical answer needs eight, and the cost this addresses is context rather than bandwidth — the appliance offers no server-side projection for logs, alerts, incidents or FortiView rows, so those are trimmed in-process, while `list_adoms`/`list_devices`/`search_devices` forward the list to dvmdb where it is native and the untrimmed object never crosses the wire. Every response gains `fields_returned`, reported even for a zero-row page, since that is exactly when a caller has nothing else to tell it what is queryable next. Two invariants keep the other layers correct: projection **selects, never renames** (the masking allowlist is keyed on live field names, so a rename would move a value out from under its entry and silently unmask it, whereas a subset can only shrink what masking must cover), and it selects **top-level keys only** (a nested `subject_details` or `target[]` survives whole, rather than introducing a second dotted-path query dialect over structures masking handles specially). **Curation is explicit and its absence is never silent truncation:** a vocabulary with no verified field catalogue — uncommon logtypes, and every FortiView view, whose per-view columns remain an unverified item — returns full rows plus a warning naming `fields`, which is precisely today's behaviour. A parametrised test asserts each of 21 cross-tool join keys (`sessionid`, `pcapurl`, `policyid`, `alertid`, `epid`, `euid` and the rest) survives the projection of the tool that produces it, because curating one away would break a workflow with no error that traces back to the projection.
```

Second, amend the **existing** `## [Unreleased]` → `### Changed` entry that begins "**`list_adoms` and `list_devices` document the `fields` parameter they have always had.**" — `search_devices` now behaves differently from what that entry describes. Append to it:

```markdown
`search_devices` goes further than documenting: its `fields` resolves English aliases against the `device` vocabulary (`serial_number` → `sn`), rejects an unknown name locally with the valid set named rather than letting the appliance fail on it, and defaults to the curated set instead of to every field. `fields=["*"]` still returns all ~60. Both this and the `fields` parameter it refines are unreleased, so there is nothing to migrate.
```

Do **not** open a new `### Changed` bullet claiming a breaking change: `fields` on `search_devices` has never appeared in a tagged release, so framing this as a migration would describe a break no user can experience.

- [ ] **Step 6: Run the tests, gates, and full suite**

```bash
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest \
  tests/test_dvm_tools.py tests/test_server_instructions.py -q --no-cov
FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && PYTHONPATH=src uv run mypy src/
```
Expected: green. `tests/test_dvm_tools.py` already exercises this parameter — `test_fields_projection_is_forwarded` should still pass untouched (see the Interfaces note). If any *other* pre-existing device test fails on the new curated default, fix it by passing `fields=["*"]`, which restores the shape it was written for; do not widen `_DEVICE_PROJECTION` to satisfy a test.

- [ ] **Step 7: Confirm no masking regression and commit**

```bash
MASKING_ENABLED=true FAZ_MASKING_KEY=$(python3 -c "print('0'*64)") \
  FORTIANALYZER_HOST=ci-dummy.local PYTHONPATH=src uv run pytest tests/ --ignore=tests/integration -q --no-cov
```
Expected: the same 10 pre-existing failures, no more. Projection runs before the
masking wrapper, so a curated-away field is one masking never sees — the count
must not rise.

```bash
git add src/fortianalyzer_mcp/tools/dvm_tools.py src/fortianalyzer_mcp/instructions.py \
  tests/test_dvm_tools.py tests/test_server_instructions.py CHANGELOG.md
git commit -m "feat(dvm): native projection for search_devices, and document the surface

search_devices resolves the field names locally -- so aliases work and an
unknown name is refused before the call -- then sends the list to dvmdb rather
than trimming the response, because a subset chosen in-process would still
have crossed the wire whole.

The usage guide gains a Projection section stating the three forms, that the
curated default is a default and not a ceiling, and that an uncurated
vocabulary degrades to full rows with a warning rather than to a guess."
```

---

## Self-Review

**Spec coverage.** This plan implements the spec's "Projection and curated defaults" section (Tasks 1, 2, 4-7) and guard test #1 from "Testing", cross-tool key survival (Task 3). Deliberately deferred:

| Spec section | Plan |
| --- | --- |
| `group_by`, `sample_by`, `count_only`, `GroupPlan`, derived dimensions | Plan 3 |
| Consolidation 83→71, skills handler rewrites, catalogue parity test | Plan 3 |
| Guard tests #2 (catalogue parity) and #4 (removed names are gone) | Plan 3 |
| Guard test #3 (masked-filter round-trip) | Landed in Plan 1, Task 4 |

**Two deliberate deviations from the spec, flagged for a reviewer.**

1. The spec lists curated sets for "FortiView rows per view". This plan gives FortiView **no** curated set, because the per-view column catalogue is itself an open verification item (spec items 2 and 3) and curating against unverified column names would produce exactly the silent truncation the spec forbids. `get_fortiview_data` therefore takes `fields` but degrades to full-rows-plus-warning by default. When the view catalogue is verified, adding `fortiview-<view>` vocabularies is additive.
2. The spec's curated list covers seven logtypes; all seven (`traffic`, `event`, `attack`, `virus`, `webfilter`, `app-ctrl`, `dns`) are already in `validation.VALID_LOG_TYPES:139-153`, so every curated vocabulary here is reachable. The logtypes that vocabulary set leaves uncurated — `dlp`, `emailfilter`, `utm`, `anomaly`, `voip`, `ssh`, `ssl` — take the full-rows-plus-warning path by design. Do **not** extend `VALID_LOG_TYPES` in this plan; the curated set and the accepted set are independent, and a vocabulary is allowed to exist for a logtype nobody queries.

**Placeholder scan.** No `TBD`/`TODO`. Every code step carries the actual code. Task 6's FortiView fake patches the two client methods `get_fortiview_data` actually calls — `fortiview_run` and `fortiview_fetch`, both confirmed at `627a138` — rather than an internal helper; the step still tells the implementer to read the function before adapting the fake, which is a verification instruction rather than a gap. (An earlier draft of this review named a `_run_view` helper that does not exist.)

**Type consistency.** `resolve_projection` returns `tuple[frozenset[str] | None, list[str]]` in Task 2 and is unpacked that way in Tasks 4 and 7. `project_rows` takes `frozenset[str] | None` and returns `list[Any]`. `fields_returned` takes the same key type and returns `list[str]`. `project_payload` (Task 5) returns `tuple[Any, list[str], list[str]]` and is unpacked as three values in Tasks 5 and 6. `Vocabulary.projection` is `frozenset[str]` with a `frozenset()` default, so every pre-existing construction in `fields.py` stays valid — that default is load-bearing for `_GENERIC_LOG`, which must remain uncurated.

**One risk flagged for the implementer.** Task 4 changes the default shape of `query_logs` rows, which is a breaking change to every existing test that asserts on a full row. The plan's guidance is to fix those call sites with `fields=["*"]` rather than by widening a curated set. If more than a handful need it, stop and report the count before continuing — a large number would suggest a curated set is genuinely too narrow, which is a design question rather than a mechanical fix.

## Reconciliation with HEAD (2026-07-28)

This plan was written before Plan 1 executed, and Plan 1 changed during execution
under live probing. Everything below was verified against `pr/tool-ergonomics` at
`627a138` and corrected in place. Recorded so a reader can tell which parts were
re-derived rather than assumed.

| # | What the plan said | What HEAD says | Fixed in |
| --- | --- | --- | --- |
| 1 | Predecessor is commits `749a9c7`..`c1cdffc` | Squashed to `ab60ad8` + `627a138` (PR #94); that range does not exist | Header |
| 2 | Baseline 1414 passed | **1545 passed** | Global Constraints |
| 3 | Masking suite has 9 pre-existing failures | **10** (`test_ueba_tools.py`, `test_soar_tools.py`) | Global Constraints, Task 7 Step 7 |
| 4 | `_TASK_STATE_CODES` | Public `TASK_STATE_CODES`; `system_tools` imports it | Task 1 Step 3 |
| 5 | Task 2 rewrites `query/__init__.py` from scratch | That would drop the live exports `TASK_STATE_CODES` and `canonical_log_field`, breaking `system_tools` and `masking/unmask.py` | Task 2 Step 3 |
| 6 | `search_devices` gains `fields` | It **already has** `fields`, as an unvalidated raw pass-through | Task 7 throughout |
| 7 | The uncurated warning names `vocab.name` | Falls back to `_GENERIC_LOG`, so a `voip` query would be told "log" has no curated set | Task 2 Step 3, plus a new test |
| 8 | Nothing said about the error envelope on the touched readers | None of `event_tools`, `incident_tools`, `ueba_tools`, `fortiview_tools`, `report_tools` imports `error_response`; a bad `fields` would surface with no machine code at all | New note in Task 5, applied in Task 6, plus two new tests |
| 9 | Self-review named a `_run_view` helper | Does not exist; the tool calls `client.fortiview_run` / `client.fortiview_fetch` | Task 6, self-review |
| 10 | `get_endpoints` at :46, `get_endusers` at :143 | :47 and :144 | Task 6 Files |

**Two things the audit confirmed rather than changed.** `_get_client` exists in
all seven tool modules, so every `monkeypatch.setattr(<module>, "_get_client", ...)`
target is valid. And `log_tools`' internals that Task 4 edits by name —
`_run_logsearch_page`, `_register_search`, `logs = page["logs"]` (`:609`, `:881`),
`warnings.extend(filter_warnings)` (`:631`), `"logs": logs` (`:671`, `:968`) — are
all present and spelled as the task assumes.

**Defect found during execution (Task 5).** The reconciliation above was a
static audit; this one only surfaced when the code ran. Task 5's brief mandated
`test_a_dict_payload_passes_through_unprojected`, asserting that `get_alerts`
hands a bare-dict payload back untouched. Those tools have always normalised
`data` to a list, and the skills layer depends on it (`handlers.py:286` types it
`list[dict[str, Any]]` and enumerates it; `:327`, `:527`, `:542` iterate it), so
satisfying the test meant a dict payload would iterate as dict *keys* — silently
wrong data on a path no test covers. Adjudicated by the human partner in favour
of the existing code contract: the coercion stays, the test is struck from this
plan, and `project_payload` keeps its list-only rule at the `query/shape.py`
layer, where it remains correct and tested. The lesson generalises — a plan may
assert a contract the code never had, and a mandated test is not evidence.

**One decision about error codes, recorded so it is not read as an oversight.**
The spec's error table maps an unknown name in `fields` to `unknown_field`. This
plan emits `validation_error` on every tool it touches, for two different reasons:

- On the five readers in Tasks 5 and 6, `unknown_field` names a condition that
  **cannot occur**. Their vocabularies are all `complete=False`, so an unknown
  name passes through with a warning rather than raising; the only failures
  `resolve_projection` can produce there are the empty list and `"*"` mixed with
  names. A test asserts the pass-through behaviour so this reasoning stays true.
- On `search_devices` (Task 7), `unknown_field` *would* be accurate — `device` is
  `complete=True` — but the existing handler already returns `validation_error`
  for every other validation failure in that tool, and narrowing it to one code
  for one input is a contract change this plan has no mandate for.

`unknown_field` remains the right code where the spec puts it, and Plan 3 uses it
for `sample_by` dimensions. If a future change flips `alert`/`incident`/`endpoint`/
`enduser`/`report` to `complete=True`, revisit the first bullet.
