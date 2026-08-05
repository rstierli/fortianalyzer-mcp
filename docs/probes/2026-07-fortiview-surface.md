# FortiView surface — partially measured

**Probe Status: MEASURED on 7.6.7 and 8.0.0 (2026-07-31, by @inxbit reviewing #109). NOT measured on 7.6.6.**

> **Update, 2026-08-05.** The sections below marked *not measured* were written on
> 2026-07-29 when no appliance was reachable. A reviewer subsequently probed 7.6.7
> and 8.0.0 over fixed one-hour windows and measured **two of the assumptions to be
> wrong in the direction that mattered**. The original text is kept verbatim below
> so the reasoning that shipped is still legible; the measured results and their
> consequences are recorded in "Measured results" immediately after this note.
>
> 7.6.6 is a supported version here and was **not** covered by that probe. Where
> code now depends on the measurement, that residual is stated at the code.

## Measured results (7.6.7 and 8.0.0, fixed one-hour windows)

**1. Unknown filter fields are rejected LOUDLY, not silently ignored.** This is the
opposite of the central assumption below, and it removes the failure mode the whole
refusal was built against:

```
filter='definitelynotafield==1'  -> Invalid params: filter 'definitelynotafield' not supported
filter='service zzqq DNS'        -> Invalid params: filter 'DNS' not supported
sort_by='notacolumn'             -> Server error: Missing columns: 'notacolumn'
```

Per-view filter acceptance, each accepted filter demonstrably narrowing the result
(`srcip==<ip present in window>` returned exactly that one row against three unfiltered):

| view | accepts | rejects |
| --- | --- | --- |
| top-sources | `srcip` | `service`, `dstport` |
| top-destinations | `dstip` | `service` |
| policy-hits | `policyid` | |
| top-countries | `dstcountry` | |
| top-threats | `threat` | |
| top-applications | | `app`, `appid` |
| top-websites | | `hostname` |

Consequence: `query.groups.VIEW_FILTER_FIELDS` forwards the filter for exactly these
five accepted pairs and keeps refusing everything else. `catdesc` on `top-websites`
was **not** probed, so it gets no entry either.

**2. Sort columns are rejected loudly too, so the withheld defaults were safe to
restore.** The "Per-view sort defaults (Task 2)" decision below withholds them on the
stated grounds that a nonexistent sort column "would be ignored by FortiAnalyzer, not
rejected". Measured, `sort_by='notacolumn'` returns a loud `Missing columns` error.
The reason for withholding is therefore gone, and the per-view defaults the retired
`get_top_*` wrappers carried are restored in `query.groups.VIEW_SORT_DEFAULTS`.

**3. `top-websites` does not serve hostnames at all.** It returns rows keyed
`catdesc`/`catid` with no hostname or website column, so `group_by="hostname"` was
reporting web-category buckets under the caller's dimension name with `is_exact:
true`. `top-applications` labels its rows `app_group`. Both dimensions were removed
from `LOG_GROUP_SURFACES`; `catdesc` is mapped in their place.

**Still not measured:** 7.6.6 filter and sort acceptance; `catdesc` as a
`top-websites` filter field; `site-to-site-ipsec` and `policy-line` entirely.

---

## Original document (2026-07-29), kept for the record

**Probe Status at the time: NOT RUN**

Date: 2026-07-29. Reason: No live FortiAnalyzer appliance reachable from this session. The `fortianalyzer-dev` MCP server process is spawned at session start and would exercise code as it existed then, not the code under test. A probe run from this environment would prove nothing about the current implementation.

**Every statement below is a default, not a measurement.** This document guards against confusing an untested conservative fallback with a verified capability. A later reader must not have to guess whether a design choice rested on measurements or on the absence of them.

## Why this measurement matters

`group_by` promises an exact answer — the caller asks for the top-N items across all traffic or threats, and the response marks `is_exact: true`. Task 4 forwards the caller's compiled filter to a FortiView view so that the filter applies to the population before the top-N is calculated.

FortiAnalyzer does not reject filter fields it does not know. This is the same inertness that made the `contain` operator match zero rows in earlier probing: an unknown filter field is silently ignored. Worse than an error, an unknown filter combined with a top-N query produces an **unfiltered top-N returned under `is_exact: true`** — a confident answer about the wrong population entirely, which is the worst failure this plan can ship.

Spec verification items 2, 3, and 4 all bear on this risk:
- Item 2: Per-view sort column acceptance — guards against silent selection of nonexistent sort columns.
- Item 3: The view catalogue — guards against accepting a view name the endpoint does not serve.
- Item 4: Filter acceptance per view — guards against silently ignored filters that leave the population unconstrained.

None of these can be verified from documentation. Each requires a live probe.

## Views served

Probed 2026-07-29: **not measured**.

| view_name | endpoint accepted | rows | columns on row 0 |
| --- | --- | --- | --- |
| top-sources | — not measured — | — not measured — | — not measured — |
| top-destinations | — not measured — | — not measured — | — not measured — |
| top-applications | — not measured — | — not measured — | — not measured — |
| top-websites | — not measured — | — not measured — | — not measured — |
| top-threats | — not measured — | — not measured — | — not measured — |
| top-cloud-applications | — not measured — | — not measured — | — not measured — |
| top-countries | — not measured — | — not measured — | — not measured — |
| site-to-site-ipsec | — not measured — | — not measured — | — not measured — |
| policy-hits | — not measured — | — not measured — | — not measured — |
| policy-line | — not measured — | — not measured — | — not measured — |

## Sort columns

Probed 2026-07-29: **not measured**.

Per-view sort column acceptance depends on knowledge of which columns each view returns and which names it accepts as sort keys. No probe was run, so no verdicts are available.

| view_name | accepted | rejected |
| --- | --- | --- |
| top-sources | — not measured — | — not measured — |
| top-destinations | — not measured — | — not measured — |
| top-applications | — not measured — | — not measured — |
| top-websites | — not measured — | — not measured — |
| top-threats | — not measured — | — not measured — |
| top-cloud-applications | — not measured — | — not measured — |
| top-countries | — not measured — | — not measured — |
| site-to-site-ipsec | — not measured — | — not measured — |
| policy-hits | — not measured — | — not measured — |
| policy-line | — not measured — | — not measured — |

## Filter acceptance

Probed 2026-07-29: **not measured**.

Filter acceptance was to be tested by sending known-good filter fields from the logview dialect (`srcip`, `dstport`, `service`, `app`, `policyid`) to each view, along with controls for silent inertness (nonsense operators and unknown field names), and classifying each view into one of three verdicts: filters honoured, filters rejected loudly, or filters silently ignored. No probe was run.

| view_name | field | filtered vs unfiltered | unknown field | nonsense op | verdict |
| --- | --- | --- | --- | --- | --- |
| — not measured — | — not measured — | — not measured — | — not measured — | — not measured — | — not measured — |

## What this means for the code

### `LOG_GROUP_SURFACES` scope (Task 2)

Since no probe was run and filter acceptance is unknown, the conservative approach applies:

**`LOG_GROUP_SURFACES` may contain only views already validated in `VALID_FORTIVIEW_VIEWS`.** Task 2's test `test_every_mapped_view_is_a_view_the_repo_accepts` enforces this boundary either way. The set in scope is:

```
top-sources
top-destinations
top-applications
top-websites
top-threats
top-cloud-applications
top-countries
site-to-site-ipsec
policy-hits
policy-line
```

Entries in the field map (such as any per-view sort defaults) must limit themselves to views in this set.

### Which log population each view serves (Task 2, revised)

Also not measured. Every FortiView view aggregates its own log source, so the *view* — not the caller's `logtype` — decides the population a `group_by` top-N describes. `LOG_GROUP_SURFACES` therefore records a `serves` set per entry and `resolve_group_plan` refuses a logtype the view is not known to serve, naming `sample_by` (which works for every logtype).

The `serves` sets are the conservative reading of each view's documented purpose in this repo, **not** probe results:

| view | serves | why, from this repo's own text |
| --- | --- | --- |
| top-sources, top-destinations | traffic | traffic volume per address |
| top-applications | traffic | "top applications by bandwidth", and `get_fortiview_data`'s docstring records that app-ctrl logs carry no byte counts, so a bandwidth ranking cannot be reading them |
| policy-hits | traffic | per-firewall-policy hit counts |
| top-countries | traffic | destination geo of traffic |
| top-websites | webfilter | visited sites |
| top-threats | attack | detected threats |
| top-cloud-applications | app-ctrl | Shadow IT; deliberately left unmapped — no dimension resolves to it unambiguously against top-applications |

Where a view's real source is broader than this (FortiAnalyzer's threat views may well aggregate several security logtypes), the effect of being wrong here is a refusal, not a wrong answer. Widening a `serves` set is the change a probe would license; narrowing one needs no evidence.

### Per-view sort defaults (Task 2)

No per-view sort column default may be encoded in the code until filter acceptance is probed. The defaults would fail silently — a sort column that does not exist in the view would be ignored by FortiAnalyzer, not rejected, leaving the response in an unmeasured order.

### Filter forwarding (Task 4)

**Task 4 must refuse `group_by` combined with a non-empty `filter`.** This is the conservative branch specified in the brief.

Task 4 must return `unsupported_view_filter` when both are present, with a message stating:
- That the view's filter acceptance is not yet verified.
- That the combination could produce an unfiltered top-N under `is_exact: true`.
- That `sample_by` is the filtered alternative (same query engine, applied before the view, always with measured filter semantics).

Do not forward the filter to the view. Do not guess that the filter will be honoured. Do not allow a caller to request an exact answer about an unconstrained population.

## How to close this out

When a live FortiAnalyzer is available for probing, follow steps 2–4 from the brief (skipping step 1, which recorded the environment):

### Step 2: Probe the view catalogue

For each of the ten view names in `VALID_FORTIVIEW_VIEWS` above, call:

```python
get_fortiview_data(view_name="<view>", time_range="<fixed window>", limit=5)
```

Use a fixed custom time window (e.g. `"2026-07-01|2026-07-15"`) so re-runs are comparable. Record for each view:
- Whether the *endpoint* accepted the name (status, tid presence, percentage, row count).
- The **column names present on row 0** — this is what Tasks 2 and 4 need.

Fill the "Views served" table above with the results. A view whose endpoint rejects the name is the only one that must be dropped from `LOG_GROUP_SURFACES`; a served-but-empty view stays, as it represents a data gap, not a capability gap.

### Step 3: Probe per-view sort columns

For each view that Step 2 found served, test sort column acceptance:

```python
get_fortiview_data(view_name="<view>", sort_by="<candidate>", time_range="<window>", limit=5)
```

Test candidates: `bandwidth`, `bytes`, `sessions`, and any column name Step 2 observed on row 0. Prefer column names you actually observed in the response — a column that exists is the strongest candidate.

Fill the "Sort columns" table above with acceptance/rejection verdicts per view. Encode accepted sort names in Task 2's field map.

### Step 4: Probe filter acceptance per view

For each served view and for a field the logview dialect definitely knows (`srcip`, `dstport`, `service`, `app`, `policyid`), send the filter to both the view and to `query_logs` on the same fixed window:

```python
get_fortiview_data(view_name="<view>", filter='<field>==<value>', time_range="<window>")
query_logs(logtype="traffic", filter='<field>==<value>', time_range="<window>", limit=1)
```

Include controls for silent inertness:

```python
# Nonsense operator
get_fortiview_data(view_name="<view>", filter='<field> zzqq <value>', time_range="<window>")

# Unknown field
get_fortiview_data(view_name="<view>", filter='definitelynotafield==1', time_range="<window>")
```

Classify each view into one of three verdicts:

| Verdict | Evidence | Consequence |
| --- | --- | --- |
| Filters honoured | Filtered result differs from unfiltered in expected direction, AND nonsense clause behaves differently from the real one | Forward the filter in Task 4. `unsupported_view_filter` never fires. |
| Filters rejected loudly | Endpoint returns an error for the unknown field | Forward the filter in Task 4; appliance polices it. |
| Filters silently ignored | Unknown field and nonsense clause return the same result as no filter at all | Task 4 must refuse the combination. Update the code comment above to name this view. |

Fill the "Filter acceptance" table above.

### Lab constraints and gotchas

**Two critical constraints learned in prior probing still apply:**

1. **The MCP server process is spawned at session start.** Editing source code does not change what the live tools execute. You must restart the session or exercise the new code in-process with `uv run python` to test changes.

2. **A past-hour time window still drifts.** Re-running the same query minutes later can move row counts by hundreds of rows due to late-arriving logs. Arithmetic across queries only holds *within a single burst*; quote sums as proof only when all the queries that compose them ran in quick succession.

**The estate carries one FortiGate and has had no attack/IPS logs for days.** An empty `top-threats` or `top-destinations` result is ambiguous — it may mean the view is unserved, or it may mean the view is served but carries no data. **Every verdict must rest on acceptance/rejection signals, never on row counts alone.** Use a positive control on a value known to be present (e.g. a specific source IP or destination port that appeared in recent traffic logs) wherever a count is load-bearing to the verdict.

---

*This document was generated without live appliance access on 2026-07-29. The statements above represent the conservative fallback specified in the brief, not verified measurements. When a live appliance becomes available, follow the steps above to close out this probe.*
