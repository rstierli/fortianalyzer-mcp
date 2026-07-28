# A shared query engine: structured filters, projection, and honest aggregation

> **Status, 2026-07-28.** The filter surface shipped as PR #94. Projection and
> aggregation are planned but unbuilt — `docs/superpowers/plans/`, Plans 2 and 3.
>
> Live probing during Plan 1's execution disproved two things this document
> asserts. Both are corrected inline below, and both are recorded here because
> the reasoning that produced the wrong answer is still instructive:
>
> - **`contain` does not work.** The operator table below originally compiled
>   `contains` to `f contain v`. Measured on 7.6.6, 7.6.7 and 8.0.0, both dialects
>   *accept* `contain` and match **zero rows** — and so does a nonsense operator,
>   which is what proves it inert rather than merely strict. `contains` now
>   compiles to `like` with `%` wildcards on both dialects, and `not_contains`
>   wraps the clause (`!(f like "%v%")`) because `not like`, `!like` and `nlike`
>   are each rejected outright. On the array dialect `not_contains` is refused:
>   no spelling works.
> - **The tool surface is 85, not 83**, so the consolidation below is 85 → 73
>   rather than 83 → 71.
>
> The general lesson is in the first bullet and outlives both corrections:
> **FortiAnalyzer's parser does not reject filter operators it does not
> understand.** It returns success with zero rows. So no operator claim in this
> document may rest on documentation, and any probe needs a nonsense-operator
> control to tell "no matches" from "not implemented".

## Problem

Every read tool returns whole objects and takes filters as a raw FortiAnalyzer
filter string. Three costs follow.

**Token bloat.** `query_logs` returns full log rows — a traffic row carries 60-80
keys, most of them empty or irrelevant to the question asked — and `limit`
allows 1000 of them. `get_alert_logs` defaults to `limit=1000`. `search_devices`
returns ~60 fields per device. `list_adoms`/`list_devices` accept a `fields`
projection but default to everything. Nothing else accepts one at all.

**Questions that cannot be asked.** "Top talkers on policy 42 last week" has no
tool. The LLM must page raw rows into its context and count them there, which is
both the most expensive way to get the answer and the least reliable. The three
`get_policy_*` tools do aggregate — they fetch bounded slices and `Counter()`
them in-process, which is the right shape because the rows never reach the
context — but only for policy IDs, and only for the three breakdowns they
hardcode.

**A filter surface that fails opaquely.** A wrong field name returns the
appliance's `Invalid filter` with no indication of what is valid. The grammar is
undiscoverable except through `get_log_fields`, which until recently returned
~200 definitions unfiltered. And the repo does not agree with itself on the
grammar: "contains" is spelled `attack contain X` in `log_tools.py:1347` and
`attack=*X*` in `pcap_tools.py`, "has a value" is hand-rolled as `pcapurl!=""`,
and `sanitize_filter_value` exists twice with different safe-character classes —
the `traffic_tools.py` copy omits `:` and therefore quotes every IPv6 literal.

## What the FortiAnalyzer API can and cannot do

The FNDN JSON specs are vendor-gated and unavailable, so this was established
from the maintainer's published API documentation, Fortinet's administration
guide, and working evidence in this repository. Each claim is labelled with how
well it is supported, because the design leans on the strong ones only.

| Capability | Verdict | Evidence |
| --- | --- | --- |
| `logsearch` field projection | **Not supported.** Params are `adom`, `device`, `logtype`, `filter`, `time-range`, `apiver`, `case-sensitive`, `time-order`, `limit`, `offset` | Strong: published parameter table; the fetch call documents only `limit`/`offset` |
| `logsearch` group-by | **Not supported** | Strong: same source |
| Parentheses in filter strings | **Supported**: `dstip==192.168.1.168 and ( dstport == 514 or dstport == 515 )` | Strong: administration guide, plus this repo already ships `(severity="critical" or severity="high")` |
| Filter operators | 7.0.1 unified the parser: `=` `==` `!=` `<>` `<` `>` `<=` `>=`, `and` (or `&&`), `or` (or a doubled pipe), `~` (regex), `!~`, `like` with `%`/`_`, `isnull`, `isnotnull`, quoted wildcards `f="v*"` | Documented for the Log View / event-handler parser. **`like` since proven live** on 7.6.6/7.6.7/8.0.0, both dialects, uppercase `LIKE` included. Still unproven through the API: `~`, `!~`, `isnull`, `isnotnull`, `<>`. **`contain`/`!contain` proven INERT** — accepted, matches nothing |
| FortiView `run` params | `apiver`, `case-sensitive`, `device`, `filter`, `limit`, `sort-by:[{field,order}]`, `time-range` | Strong: published payload |
| Native counts | `/eventmgmt/…/alerts/count`, `/incidentmgmt/…/count`, and `total-count` on any logsearch | Strong: in use today |
| Native grouped counts | `/eventmgmt/…/alert-incident/stats` (`type=severity｜status｜severity-timescale`), incident `stats_items`, and every FortiView view | Strong: in use today |
| dvmdb/config/task filters | Array dialect, entries implicitly ANDed. The example originally given here — `[["name","contain","fgt"],…]` — is the inert spelling; the working form is `[["name","like","%fgt%"],["conn_status","==",2]]` | Strong for the shape and for `==`; the `contain`→`like` correction is measured |

Two consequences frame everything below. **A FortiView view is the only
appliance-side GROUP BY over log data** — so native grouping means dispatching to
a view. And **projection is unavailable server-side for logs, alerts and
FortiView rows** — so projection is in-process, which costs nothing in honesty
because dropping keys from a fetched row is exact.

One footnote, so nobody "fixes" working code to match a document: the published
response example shows `total_lines` and `logs`, while the appliance returns
`total-count` and `data`, which is what `log_tools` reads. The code is right.

## Design

### Module boundaries: `query/` decides, `tools/` execute

A new package, every module of it pure — no client, no I/O, no import from
`server.py` or `tools/`:

```
query/fields.py    FIELD_MAPS: curated projections, queryable fields, aliases,
                   value coercions, derived dimensions, per-view sort columns
query/filters.py   FilterCondition; compile_to_string(); compile_to_array()
query/groups.py    plan_group() -> GroupPlan | raises
query/shape.py     project(); top_n_with_residual(); shared response fragments
```

Purity is a hard constraint, for two reasons beyond testability.

Tool modules import `mcp` from `server.py`, which is why the tool imports sit at
the bottom of that module and must not be reordered. A `query/` package that
imported a client or a tool function would add a second import-time ordering
constraint to a system that already has a fragile one.

And `_run_logsearch_page` owns the concurrency semaphore, the shared re-issue
budget and the shielded cleanup-cancel. Answering a *log* question with
`group_by` requires a *FortiView* call; if `query/` performed I/O it would need
its own runner, and the repo would have two poll loops with two recovery
policies. Instead `plan_group()` returns a `GroupPlan` dataclass and the calling
tool executes it with the runner it already has.

Tests then follow the precedent set by the sibling vsphere MCP server: the
interesting logic is pure functions over lists of dicts, verified without an
appliance.

### The filter surface

```python
class FilterCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    op: Literal["eq", "ne", "gt", "gte", "lt", "lte",
                "contains", "not_contains", "in", "not_in"]
    value: str | int | float | bool | list[str | int]
```

A Pydantic model so FastMCP emits a real JSON schema; JSON-in-a-string
parameters are where LLM input reliably goes malformed. Conditions are ANDed;
OR within one field is `in`.

Two emitters over one model:

| op | string dialect (logview, fortiview, eventmgmt, incidentmgmt) | array dialect (dvmdb, config, task) |
| --- | --- | --- |
| `eq` | `f==v` | `["f", "==", v]` |
| `ne` | `f!=v` | `["f", "!=", v]` |
| `gt`/`gte`/`lt`/`lte` | `f>v`, `f>=v`, … | `["f", ">", v]`, … |
| `contains` | ~~`f contain v`~~ → `f like "%v%"` | ~~`["f", "contain", v]`~~ → `["f", "like", "%v%"]` |
| `not_contains` | ~~`f !contain v`~~ → `!(f like "%v%")` | ~~`["f", "!contain", v]`~~ → **refused** |
| `in` | `(f==a or f==b)` | **refused** — no verified OR form |
| `not_in` | `(f!=a and f!=b)` | one `!=` entry per value (implicit AND) |

**The struck-through spellings were what this document originally specified, and
they are wrong.** Measured live on 7.6.6, 7.6.7 and 8.0.0: `contain` and
`!contain` are accepted by both dialects and match zero rows. On one fixed hour of
traffic (488,444 rows): `service==DNS` → 12,052, `service like "%DNS%"` → 12,052,
`!(service like "%DNS%")` → 476,392 — and 12,052 + 476,392 is exactly 488,444, so
the wrapped negation is a true complement rather than a match-everything. Both
`service contain DNS` and `service !contain DNS` → 0, as does a nonsense
`service zzqq DNS`. A predicate *and* its negation both returning zero is what
distinguishes inert from strict.

Negation must wrap the clause: `not like`, `!like` and `nlike` are each rejected
with `Invalid filter`, which also confirms the parser does surface genuine syntax
errors — it just does not treat an unknown operator as one.

So `like` moved from the "held back pending verification" set into the emitted
set, and it is now the *only* way `contains` compiles. The rest of the documented
set (`~`, `!~`, `isnull`, `isnotnull`, `<>`) is still held back. The op enum is
data, so adding one later remains a one-line change.

Two ops are refused on the array dialect rather than guessed. `in`'s OR-separator
syntax is documented for FortiManager but unexercised here (verification item 6),
and for `not_contains` every candidate spelling silently matches zero rows — so
there is nothing correct to emit. A `contain` over a shared prefix would be the
tempting fallback and is wrong twice over: it matches values the caller did not
ask for, and it does not match anything at all.

One further refusal the original table did not anticipate: `contains` against a
field FortiAnalyzer stores as an **enum code** (`state`, `conn_status`) is
rejected. `coerce_value` runs before the wildcards attach, so
`{"field": "state", "op": "contains", "value": "running"}` compiled to
`[["state", "like", "%1%"]]` — and since `TASK_STATE_CODES` runs 0..10, `%1%`
matches state 1 (running) *and* state 10 (unknown). There is no correct emission,
so it is refused with the valid enum names listed.

Beyond structure, the compiler buys four things:

**Local field-name validation.** The field map knows each vocabulary, so an
unknown name fails before the call with a message listing valid names. The LLM
self-corrects in one step instead of guessing at an error that contains no
information.

**Aliases.** FAZ field names are cryptic and LLMs guess English. The map maps
`source_ip`→`srcip`, `destination_port`→`dstport`, `application`→`app` and
similar. A canonical name always wins over an alias, so adding an alias can
never shadow a real field.

**Enum coercion in one place.** `search_devices` maps `"down"`→`2` inline and
`list_tasks` maps `"running"`→its code inline. Both move into the field map, so
every tool touching `conn_status` or `state` translates identically.

**One sanitiser.** The `utils/validation.py` implementation survives; the
`traffic_tools.py` copy is deleted. *(Done in PR #94.)* Values that are not plain tokens are
double-quoted rather than escaped piecemeal — quoting is what the repo's working
`severity="critical"` filters already do, and the administration guide's own
counterexample (`cfgpath=firewall.policy` needing `firewall\.policy`) shows
where per-character escaping goes wrong.

The raw `filter` string stays as an escape hatch but is **mutually exclusive**
with `filters`: supplying both errors, naming which to use. ANDing a
caller-supplied string that may contain `or` onto a compiled clause produces a
filter meaning neither side intended.

### Projection and curated defaults

`fields: list[str] | None` on every read tool, validated against the same field
map as the filters. `None` gives the curated default; `["*"]` gives the full
object exactly as today. Projection runs in-process for logs, alerts, incidents
and FortiView rows because the appliance offers nothing; `list_adoms` and
`list_devices` keep passing `fields` through to dvmdb, where it is native.

**Curation is explicit; the absence of curation is never silent truncation.**
Curated sets are defined for the vocabularies that actually get queried:
traffic, event, attack, virus, webfilter, app-ctrl and dns logs, plus alerts,
incidents, devices, adoms, tasks, endpoints, endusers, and FortiView rows per
view. An uncurated logtype returns **full rows plus a warning** naming `fields`,
degrading to today's behaviour rather than hiding a payload chosen by guesswork.
Curations are added as they are verified against live `logfields` output.

A curated set carries identity (who/where), the discriminator
(`action`/`level`/`severity`), the magnitude (`sentbyte`/`rcvdbyte`/
`sessioncount`), the human-readable summary (`msg`/`attack`/`service`/`app`) —
and, non-negotiably, the join keys:

> **A projection must never drop a field another tool takes as input.**
> `get_pcap_by_session` needs `sessionid`, `download_pcap_by_url` needs
> `pcapurl`, `search_and_download_pcaps` chains both, the policy analysis reads
> `policyid`/`dstport`/`proto`/`service`, `get_alert_logs` and
> `add_alert_comment` need `alertid`, `get_endpoint_vulnerabilities` needs
> `epid`. Curating `sessionid` out of the traffic projection breaks PCAP
> workflows with no error that traces back here. A test enumerates every tool
> parameter fed from another tool's rows and asserts the key survives its
> projection.

Two invariants protect the other layers:

- **Projection selects, never renames.** The masking allowlist is keyed on live
  field names verified against 7.6.7/8.0.0 schemas; renaming a key would
  silently unmask it. Selecting a subset can only shrink what masking must
  cover.
- **Top-level keys only.** Alerts carry nested `subject_details` and `target[]`;
  selecting that key keeps the structure whole. No dotted-path language — that
  would be a second query dialect, and `target[]` is one of the composite
  structures masking handles specially.

`fields_returned` is added to the response: ~40 tokens, and the only signal of
what is queryable next when a page returns zero rows.

### `group_by` (native, exact) and `sample_by` (bounded, labelled)

Both suppress raw rows entirely. Not every tool gets every parameter — the
surface is scoped to what each vocabulary can answer:

| Tool | `filters` | `fields` | `group_by` | `sample_by` | `count_only` |
| --- | --- | --- | --- | --- | --- |
| `query_logs`, `fetch_more_logs` | yes | yes | yes | yes | yes |
| `analyze_policy_traffic` | yes | — | — | yes | — |
| `get_fortiview_data`, `run_fortiview` | yes | yes | — | — | — |
| `get_alerts` | yes | yes | yes | — | — |
| `get_incidents` | yes | yes | yes | — | — |
| `search_ips_logs`, `get_alert_logs`, `get_endpoints`, `get_endusers` | yes | yes | — | — | — |
| `search_devices`, `list_devices`, `list_adoms`, `list_tasks`, `get_report_history` | yes | yes | — | — | — |

A FortiView view *is* a grouping, so `group_by` on the FortiView tools would be
meaningless; `count_only` is absent where a dedicated native count tool already
exists (`get_alert_count`, `get_incident_count`) and present on `query_logs`,
where logs have no count endpoint of their own.

Mode selection is explicit and validated:

| Mode | Set by | Returns |
| --- | --- | --- |
| rows | none of the three | `logs` + `fields_returned` |
| exact groups | `group_by="<dim>"` | `groups`, `group_source`, `is_exact: true` |
| bounded breakdowns | `sample_by=["<dim>", …]` | `breakdowns` + the bounded-metadata block |
| count only | `count_only=True` | `total`, `total_is_known`, `count_source` |

Any two of `group_by`, `sample_by` and `count_only` together error with
`conflicting_aggregation`. `fields` alongside any of them is inert and warns
rather than errors, since it describes a row shape no rows will be returned in.

**`group_by` resolves to a native surface or refuses.** For logs, every native
answer is a FortiView view:

| `group_by` | native surface |
| --- | --- |
| `srcip` | `top-sources` |
| `dstip` | `top-destinations` |
| `app` | `top-applications` |
| `hostname` / `website` | `top-websites` |
| `attack` / `threat` | `top-threats` |
| `policyid` | `policy-hits` |
| `dstcountry` | `top-countries` |
| cloud application | `top-cloud-applications` |

For alerts, `severity` and `status` dispatch to `/eventmgmt/…/alert-incident/
stats`; incidents use the `stats_items` vocabulary. Any other dimension raises
`unsupported_group_dimension`, and **the error names `sample_by` as the way to
ask that question** — a refusal that does not say what does work is a dead end.

Three translations the `GroupPlan` must carry, each of which silently returns
zero rows if missed:

- FortiView's all-devices group is `All_Device`, logview's is `All_FortiGate`.
  The plan translates rather than forwarding the logview default.
- The compiled filter is re-emitted against the view's own filterable
  vocabulary, which is not provably identical to logview's. Until verified, a
  `group_by` combined with a filter on a field not known to that view errors
  locally rather than silently returning an unfiltered top-N.
- The already-resolved `{start, end}` window is reused, preserving the
  "resolve the window once at tool entry" invariant across the hand-off.

**`sample_by` generalises the existing bounded machinery.** It accepts any
dimension in the field map, and takes a **list** because one row scan yields
several independent breakdowns — exactly what `get_policy_traffic_profile` does
today with ports, services and applications. Not a cross-tab; cardinality would
explode. It reuses `_build_bounded_time_slices`, the per-slice `total-count`
summation, `all_slices_exact` and `_bounded_metadata` unchanged, and reports
today's contract verbatim: `is_exact`, `analysis_mode`, `total_hits`,
`total_hits_is_known`, `total_hit_source`, `observed_hits`, `slices_scanned`,
`truncated_slices`, `log_limit_per_slice`, `recommendation`.

`top_n: int = 10`, where `0` means every bucket — `get_policy_port_analysis`
returns the complete port list today and that must survive.

**Derived dimensions preserve domain logic that consolidation would otherwise
lose.** The field map carries computed dimensions beside plain ones: `port` =
`"{proto}/{dstport}"`, and `icmp_type_code` = the `PING` / `icmp/3/3` /
`type=unknown` decoding at `traffic_tools.py:504-526`. That block encodes a real
appliance quirk — FAZ hides ICMP type and code in the `service` field, and
SD-WAN SLA probes mislabel it — and as a derived dimension it survives the merge
instead of vanishing with the tool that held it.

### Tool consolidation: 83 → 71 (in practice 85 → 73)

| Removed | Replacement |
| --- | --- |
| `get_top_sources`, `get_top_destinations`, `get_top_applications`, `get_top_threats`, `get_top_websites`, `get_top_cloud_applications`, `get_policy_hits` | `get_fortiview_data(view_name=…, fields=…)`, or `query_logs(group_by=…)` which now reaches the same views |
| `search_traffic_logs`, `search_security_logs`, `search_event_logs` | `query_logs(filters=[…])` |
| `get_policy_traffic_profile`, `get_policy_port_analysis`, `get_policy_protocol_summary` | `analyze_policy_traffic(policy_ids=…, sample_by=[…], top_n=…)` |

The boundary between the two aggregation entry points, stated so it does not
blur: `query_logs(sample_by=…)` is one query yielding one aggregate set;
`analyze_policy_traffic` fans out across up to `MAX_POLICY_IDS` policies,
enforcing `ANALYSIS_QUERY_BUDGET` and returning per-policy results.

Thirteen tools out, one in. **The arithmetic in this heading is stale:** the surface was 83 when this was written and is 85 as of `627a138`, so the result is 73, not 71. The thirteen removals are unchanged. Every removed tool's parameters are expressible on
its replacement, so no capability is lost. This is a breaking change: minor
version bump, and a CHANGELOG entry mapping each old call to its new form.

### Cross-layer obligations

Layers this change reaches into. Three are prerequisites — the change is
incorrect without them. One (the `_FILTER_CLAUSE_RE` value pattern) is a
pre-existing limitation this work documents and tests rather than fixes, for
reasons measured below.

**The skills layer calls six of the removed tools.** `run_incident_summary` and
`run_threat_intel` call `get_top_threats`; `run_app_usage` calls
`get_top_applications`, `get_top_websites` and `get_top_cloud_applications`;
`run_network_context` calls `get_top_sources` and `get_top_destinations`. All
must move to `get_fortiview_data(view_name=…)`. Because handlers import raw
tools lazily and the tests patch them at the defining module with `autospec=True`,
a missed call site fails loudly at test time rather than at runtime — the
existing test design is the safety net here.

**Masking's filter parser has a narrow pre-existing limitation, and the
compiler does not worsen it.** `masking/unmask.py::_FILTER_CLAUSE_RE` matches
values as `[^\"'\s()]+` — no spaces, even inside quotes. Two measured facts
bound what that costs. An FPE token can never contain a space: a value outside
the `a-z0-9-._~` alphabet (plus uppercase for usernames) raises `MaskingError`
and becomes an irreversible placeholder, so a token is never a multi-word
value. And a whole-value token resolves correctly today, quoted or bare —
verified against the current code: `user=="user-045f-jnhI"` and
`user==user-045f-jnhI` both unmask to `jdoe`.

What does fail is a token *embedded* in a longer quoted phrase:
`msg contain "login failed for user-045f-jnhI"` reaches the appliance with the
token intact. That fails identically before and after this change — the
compiler cannot turn a phrase into a token — and fixing it needs substring
resolution inside `resolve_scalar`, not just a regex that admits quoted spaces.
It is therefore a **hardening task, not a prerequisite**. A test freezes the
three measured behaviours (bare token resolves, quoted token resolves, embedded
token does not) so the compiler's emitted forms stay covered and the limitation
stays visible. Every tier-1 operator the compiler emits (`==`, `!=`, `<=`, `>=`,
`<`, `>`, `contain`, `!contain`) is already in that pattern.

**Structured filters need a filter-aware unmask, or masked deployments query
the wrong host.** This is a prerequisite, and the failure mode is worse than an
error. Three behaviours, each measured against the current code:

1. A masked IP is format-preserving and **unmarked** — `10.0.0.5` becomes
   `137.154.78.119`, indistinguishable from a real address. Only the *field
   name* tells the unmasker it is an IP, which is why `unmask_filter` keys its
   resolution on the field and `unmask_args` keys on the dict key.
2. In a `FilterCondition`, the field name is a *sibling* key, so the value's own
   key is the literal string `value`, carrying no type. `unmask_args({"field":
   "srcip", "op": "eq", "value": "137.154.78.119"})` returns the token
   unchanged. A marked token (`user-045f-jnhI`) still resolves; an IP or MAC
   does not.
3. `_unmask_any` handles `dict`, `list` and `str` only. A Pydantic model
   instance — which is exactly what FastMCP passes for a
   `list[FilterCondition]` parameter — falls through untouched.

Together those mean an LLM filtering on a masked IP would send a **valid but
different** address to the appliance and receive real logs for a host nobody
asked about. Not an empty result that invites a retry: a confident answer about
the wrong machine.

So `masking/unmask.py` gains filter-condition handling that types each `value`
by its sibling `field`, for both the model and its dict form, mirroring the
logic `unmask_filter` already applies to strings. Tests cover an IP (unmarked,
field-typed), a username (marked), a MAC, and a model instance nested in a
list. Accepting `list[dict]` instead of a model would sidestep points 2 and 3
by reusing the dict walk — and is rejected, because it also discards the JSON
schema and the `op` enum that stop invalid input at the boundary.

**The dynamic-mode mirror stops being able to drift.** Consolidation must touch
`server.py::register_dynamic_tools`, which keeps two hand-written structures —
`tool_catalog` for search and `tool_map` for dispatch — neither derived from
what is registered, which is why it reports `total_tools: 72` against 83. One
static catalogue constant replaces both, plus a test asserting it matches the
introspected registered tool set exactly: names, categories and count. Drift
becomes a failing suite. `find_fortianalyzer_tool` deliberately does **not**
derive the catalogue by importing tool modules — that would register every tool
on the first search call and destroy the minimal surface dynamic mode exists
for. `execute_advanced_tool` already imports them all, so its dispatch map can
be derived for free.

**`instructions.py` is wrong about the filter grammar and is corrected here.**
It tells every client that `=` and `&&` return an opaque `Invalid filter`.
Fortinet documents both as valid since 7.0.1, and this repo's own `pcap_tools`
sends `=`-with-quoted-values to logview successfully. It also needs the new
`filters`/`fields`/`group_by`/`sample_by` surface, and the consolidated tool
names. `tests/test_server_instructions.py:48` freezes the operator tuple, so the
test moves with the text.

### Error handling

Every rejection returns the existing `utils/responses.error_response` envelope,
with the valid set enumerated in `message` and a `recommendation` naming the
call that works.

| Condition | `error` code |
| --- | --- |
| unknown name in `filters`, `fields` or `sample_by` | `unknown_field` |
| `group_by` dimension with no native surface | `unsupported_group_dimension` |
| both `filter` and `filters` supplied | `conflicting_filter_input` |
| `group_by` and `sample_by` together | `conflicting_aggregation` |
| filter on a field the target FortiView view does not know | `unsupported_view_filter` |

The tools this spec rewrites gain the envelope, which shrinks the apology in
`instructions.py` that error shapes are uniform only in the log-search and
traffic families. Untouched modules stay as they are; converting them is a
separate job.

### Testing

Everything in `query/` is pure, so the load-bearing logic needs no appliance:
each operator against both emitters, aliases, enum coercion, IPv6 sanitisation,
projection with `None`/`["*"]`/unknown/nested keys, every `group_by` dimension
mapping to its expected plan, unknown dimensions producing the documented error
text, `sample_by` top-N and residual and `top_n=0`, and the derived `port` and
`icmp_type_code` dimensions including the SD-WAN-probe case.

Four tests guard what a docstring cannot:

1. **Cross-tool key survival** — every tool parameter fed from another tool's
   rows (`sessionid`, `pcapurl`, `policyid`, `alertid`, `epid`, `euid`) is
   present in the projection of the tool that produces it.
2. **Catalogue parity** — the static catalogue equals the registered tool set.
3. **Masked-filter round-trip** — every form the compiler emits survives
   `unmask_filter`: a bare token, a quoted token, and each tier-1 operator.
   The embedded-token-in-a-phrase limitation is asserted as-is, so a future
   fix has to update the test deliberately rather than by accident.
4. **Removed names are gone**, with a parametrised equivalence test per old call
   pattern against its replacement.

Baseline is 1280 passing tests. Gates stay `ruff check src/ tests/`,
`ruff format --check src/ tests/`, and `mypy src/` under strict settings.

## Verification items

Each needs a live 7.6.7/8.0.0 check. None blocks the design; each either widens
the native surface or confirms a boundary.

1. **Tier-2 operators through the API** — ~~`like`~~, `~`, `!~`, `isnull`,
   `isnotnull`, `<>`. **Partly closed.** `like` is now proven on both dialects
   and is how `contains` compiles; uppercase `LIKE` also works on 7.6.7/8.0.0.
   The rest remain unproven via JSON-RPC. `isnull`/`isnotnull` would still
   replace the hand-rolled `pcapurl!=""` idiom.
2. **FortiView per-view sort columns.** The published example sorts by `bytes`;
   this repo's wrappers default to `bandwidth`; commit `eaef437` fixed a default
   naming a column that does not exist. The field map should carry the verified
   per-view set.
3. **The FortiView view catalogue.** Public docs show five SD-WAN views and IOC
   views the allowlist does not include, while commit `9e5d091` removed three
   documented names the appliance does not serve. Each candidate needs a live
   probe before it becomes a `group_by` dimension.
4. **FortiView filterable fields** versus logview's, which decides whether
   `unsupported_view_filter` ever needs to fire.
5. **Curated projections** validated against live `logfields` output per
   logtype, so no curated name is a field the appliance does not emit.
6. **OR in the array dialect.** Still open. `search_devices` and `list_tasks`
   prove only the implicitly-ANDed form. Compiling `in` for dvmdb needs the
   explicit or-separator syntax, which is documented for FortiManager but
   unexercised here. **The conservative branch is implemented:** `in` against an
   array-dialect vocabulary raises with advice to issue one call per value. A
   `contain` clause over a shared prefix would have been the tempting fallback
   and is wrong twice over — it silently matches values the caller did not ask
   for, *and* `contain` matches nothing at all.

7. **FortiView filter acceptance per view — added after the fact, and it gates
   `group_by`.** Item 4 asks whether FortiView's filterable fields match
   logview's. The measurement matters more than it looked: because the parser
   does not reject unknown filter fields, a `group_by` that forwards a filter to
   a view which ignores it returns an **unfiltered top-N under `is_exact: true`**
   — a confident answer about a population nobody asked for. Plan 3's Task 0
   probes this before any wiring, with a nonsense-operator control, and refuses
   the combination when it cannot prove the filter is honoured.

## Rejected alternatives

- **A single polymorphic `faz_query` tool** replacing the read surface. Smallest
  catalogue, but it contradicts the one-obvious-tool-per-job reasoning behind
  consolidation, LLMs fill polymorphic schemas less reliably than they choose
  well-named tools, and it would obsolete the skills layer's composition model.
- **Helpers in `utils/` instead of a package.** Cheaper for the first tool, but
  nothing owns the query contract as a whole and the native-group dispatch has
  no clean home.
- **Bounded sampling behind `group_by`.** Rejected by decision: a top-N over a
  1000-row sample reads as fact and gets quoted as fact. The capability survives
  under a name that says what it is.
- **Curated projection by default with no opt-out.** `fields=["*"]` costs one
  parameter and keeps every existing caller viable.
- **Appliance-side projection.** Not available; see the capability table.

## Out of scope

- Converting untouched tool modules to the error envelope.
- Consolidating `run_fortiview`/`fetch_fortiview` into `get_fortiview_data`, and
  `list_available_pcaps` into `search_ips_logs(has_pcap=True, fields=…)`. Both
  are defensible follow-ups; neither was in the agreed scope.
- Report-dataset execution as an aggregation surface. FortiAnalyzer reports are
  SQL over the log database, which would be the richest possible GROUP BY, but
  no public documentation shows an ad-hoc dataset execution endpoint.
- Caching field maps or `logfields` output beyond the existing per-client cache.
- Cross-vocabulary joins ("alerts for the top 10 talkers"); the LLM composes
  those from two calls.
