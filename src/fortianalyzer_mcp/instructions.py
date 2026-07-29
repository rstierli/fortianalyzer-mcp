"""The server-level usage guide handed to every MCP client.

Why this exists as a separate artifact from the tool docstrings: a docstring
can only state a fact about *its own* tool. It has no way to warn that a
neighbouring tool spells something the same way and means something else.
Several tools here do exactly that, and the collisions are invisible from
inside any one of them.

The load-bearing case is ``tid``. Five families hand back a value under that
key and none of them are interchangeable -- one is a local pagination handle
that survives reuse, three are appliance task ids that do not, one is a UUID
string rather than an int, and one is inert. A caller that generalises from
the first to any other gets failures whose cause is nowhere in the docstring
it read. Arbitrating that is a server-level job.

Kept deliberately dense. This text ships on every client handshake, so it
buys its context budget back only by being the thing that prevents a wasted
tool call, never by being complete. Anything a single docstring can already
say correctly stays in that docstring.

``tests/test_server_instructions.py`` freezes the facts here that callers
misuse, so dropping a tid family or the filter grammar fails the suite even
though no code path breaks.
"""

SERVER_INSTRUCTIONS = """\
FortiAnalyzer JSON-RPC API exposed as MCP tools. Read-heavy SOC/log-analysis
surface: most tools read, and the write paths are device add/delete, incident
create/update, alert acknowledgement and file downloads.

## "tid" means five different things -- check this before reusing one

A tid from one family is never valid in another. Pairings:

| Started by        | Consumed by                          | What the tid is |
|-------------------|--------------------------------------|-----------------|
| query_logs        | fetch_more_logs, cancel_log_search   | int, REUSABLE pagination handle -- NOT the appliance task id |
| run_fortiview     | fetch_fortiview                      | int appliance task id, one-shot, only valid with the SAME view_name |
| run_report        | fetch_report, get_report_data        | a UUID string, not an int |
| run_ioc_rescan    | get_ioc_rescan_status                | int appliance task id, different job type |
| search_ips_logs   | nothing                              | vestigial echo of an already-reaped id -- not usable for anything |

The logsearch tid is the one that misleads. The appliance reaps its task
after the first fetch, so the int you get back is a local, reusable handle
into an in-process registry; fetch_more_logs re-runs the search at the new
offset rather than reading a cursor. Consequences you will observe and should
not treat as bugs: `total` is frozen at the page-0 baseline for the handle's
life while `page_total` carries the live per-page count, drift between them
is reported via `total_count_stability`/`total_drift_detected` instead of
being smoothed over, a handle is bound to the ADOM that created it
(`adom_mismatch`), and a `count == 0` page terminates paging.

Prefer the wrappers that hide the two-step entirely: get_fortiview_data,
run_and_wait_report, run_and_wait_ioc_rescan. Reach for the raw
run/fetch pairs only when you need to poll or cancel yourself.

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
`!=`, `<`, `>`, `<=`, `>=` and `like` with `%` wildcards, combined with
`and`/`or` and grouped with parentheses; negate a `like` by wrapping the whole
clause, `!(service like "%DNS%")`, because `not like` is rejected outright.
Prefer `filters` over hand-writing a raw `contain` clause: the parser accepts
`contain` and then matches nothing, so it fails silently rather than erroring.
FortiAnalyzer's own parser accepts more than that, but nothing beyond this set
is verified against this API here, so treat anything else as an experiment you
run through `filter`.

search_devices and list_tasks take the same `filters` parameter, with three
exceptions: `in` is rejected there (their array dialect has no verified OR
form -- issue one call per value; `not_in` works, compiled to ANDed `!=`),
`not_contains` is rejected too, because every candidate spelling silently
matches zero rows on the appliance -- use `ne` with exact values or exclude
matches yourself -- and `contains` is rejected on the code-valued fields
(`state`, `conn_status`), where a substring would compare against the stored
integer rather than the name you wrote and `%1%` would match both 1 and 10.
Filter those with `eq`/`ne` and a name; the refusal lists the accepted names.
Their field sets are small enough to enumerate, so an unknown field name there
is a hard error listing the valid names; for logtypes an unrecognised name is
passed through with a warning instead, since the appliance's catalogue is
larger than the server's list.

On these two tools the narrow parameters (`name_filter`, `platform_filter`,
`connection_status`, `filter_state`) are ANDed with `filters` rather than
overridden by it, so a condition on the same field in both places must agree
or nothing matches.

## Projection: `fields`

Twelve read tools take `fields`. Not every read tool does -- check the
docstring. They are:

  query_logs, fetch_more_logs, get_alerts, get_alert_logs, get_incidents,
  get_endpoints, get_endusers, get_report_history, get_fortiview_data,
  search_devices, list_adoms, list_devices

  fields omitted   -> the curated set for that vocabulary, where one exists
  fields=["*"]     -> the full object
  fields=[...]     -> those fields (English aliases work, same as in filters)

The curated set carries identity, the discriminator, the magnitude, the
human-readable summary, and every key another tool takes as input -- so
`sessionid` survives for get_pcap_by_session and `alertid` for get_alert_logs.
It is a default, not a ceiling: ask for `["*"]` whenever you need the rest.

Which vocabularies are curated is not uniform, and the response says which
case you got:

- Curated today: the traffic/event/attack/virus/webfilter/app-ctrl/dns
  logtypes, alerts, incidents, UEBA endpoints and end-users, devices, tasks.
  Omitting `fields` trims.
- NOT curated: uncommon logtypes (voip, icap, dlp, ...), every FortiView view,
  and report history -- there is no verified catalogue of what those emit, so
  omitting `fields` returns the FULL row plus a warning naming `fields`, never
  a guessed subset. list_adoms and list_devices have no curated default either;
  omitting `fields` there means no projection at all.

`fields_returned` in every response lists the keys the rows carry, and is
reported even when a page comes back empty -- that is the only signal of what
is queryable next when there are no rows to inspect.

Where the trim happens differs, and it matters for response size: list_adoms,
list_devices and search_devices project on the appliance, so `fields` also
shrinks what crosses the wire. Everywhere else the appliance sends the whole
row and the trim is in-process -- it saves your context, not bandwidth.

## Aggregation

Three parameters on query_logs, mutually exclusive, and the names carry the
guarantee:

  group_by="srcip"        exact. The appliance counted it.
  sample_by=["port"]      bounded. A row scan, labelled as one.
  count_only=True         just the total.

`group_by` only accepts dimensions FortiAnalyzer aggregates natively, and each
one is tied to the logtype whose logs its native surface reads:

  logtype="traffic"     srcip, dstip, app, policyid, dstcountry
  logtype="webfilter"   hostname, website
  logtype="attack"      attack, threat

Any other pairing is an error that names sample_by -- including a dimension
that works under a *different* logtype, because each surface aggregates its own
log source and answering across that boundary would describe a population the
caller did not ask about. There is no silent fallback, because a top-N over a
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

## time_range vocabularies

Two forms work everywhere: a preset token or a custom "start|end" pair
("2026-01-01 00:00:00|2026-01-02 00:00:00"). The full preset vocabulary for
the log, FortiView, event and incident families is "now" (a 5-min alias used
by FortiView), "5-min", "15-min", "30-min", "1-hour", "2-hour", "6-hour",
"12-hour", "24-hour", "1-day", "2-day", "7-day", "30-day", "90-day" -- tool
docstrings quote the subset typical for that tool, but the whole vocabulary
resolves in those families. The report tools are narrower: hour/day presets
only ("1-hour", "6-hour", "12-hour", "24-hour", "1-day", "7-day", "30-day",
"90-day"), plus the appliance's own "last-N-hours/-days/-weeks/-months"
spelling and custom pairs; sub-hour presets are a hard error there.

Relative windows are anchored on the appliance's newest ingested log, not on
your clock, because FortiAnalyzer reads naive timestamps in its own timezone.

## Response size

The biggest wins, all consequences of the Projection section above rather than
separate advice:

- list_adoms and list_devices have no curated default, so they return every
  field, most of them empty placeholders. Pass e.g. fields=["name","state"] or
  fields=["name","ip","os_ver","platform_str"] and the response shrinks by an
  order of magnitude. search_devices trims by default; these two do not.
- The uncurated vocabularies above (FortiView views, uncommon logtypes, report
  history) return full rows for the same reason. Name the columns you want.
- get_log_fields takes name_filter -- the unfiltered catalogue is hundreds of
  entries.

## Error shapes are not yet uniform

The log-search and traffic families, plus search_devices and list_tasks,
return a machine-readable envelope:
`{status, error, message, operation, retry_count}`, often with a
`recommendation` naming the tool call that recovers. The remaining tool
modules currently return only `{status: "error", message: <appliance text>}`,
so branch on `status` first and treat `error` as present-if-available.
"""

#: Appended to the guide only when masking is switched on.
#:
#: Kept out of ``SERVER_INSTRUCTIONS`` because masking is off by default: a
#: paragraph about tokens prevents no wasted call on a server that never emits
#: one, and this text ships on every handshake. See ``build_instructions``.
#:
#: The case rule is measured, not inferred. On live 7.6.6, dvmdb ``like`` is
#: case-INsensitive -- ``name_filter="datacenterfw_fg200g"`` returns the device
#: registered as ``DataCenterFw_FG200G`` -- while ``==`` is case-SENSITIVE and
#: returns ``count: 0`` with ``status: "success"``, and the ``get_device``
#: object lookup fails loudly with ``Object does not exist``. Since the hostname
#: token alphabet is lowercase by design, a round-tripped device identifier
#: survives ``contains`` and silently loses under ``eq``. That asymmetry is the
#: whole reason this section names an operator rather than just warning about
#: tokens.
MASKING_GUIDANCE = """\

## Masked values (this server has masking enabled)

Identifiers in responses -- addresses, usernames, hostnames -- are
format-preserving tokens, not the appliance's real values. A token looks like a
plausible value of its own type, so you cannot tell it apart by inspection.

Pass them back exactly as received. Do not normalise, correct, reformat or
"fix" one that looks unusual: the mapping is deterministic, so the token IS the
handle for that value, and an edited token resolves to nothing.

Filtering on a masked device name or serial: use `op: "contains"`, not `eq`.
Token alphabets are lowercase, and the appliance's exact-match comparison is
case-sensitive while its substring match is not -- so `eq` on a round-tripped
identifier returns zero rows and `status: "success"`, which is
indistinguishable from "no such device". `contains` matches regardless of case.
"""


def build_instructions(masking_enabled: bool = False) -> str:
    """The guide the client receives, tailored to what this server will emit.

    Args:
        masking_enabled: Whether the masking layer is installed. When it is,
            the client is told that identifiers are tokens and how to filter on
            one; when it is not, that text is omitted rather than shipped as
            advice about a thing that cannot happen.
    """
    if not masking_enabled:
        return SERVER_INSTRUCTIONS
    return SERVER_INSTRUCTIONS + MASKING_GUIDANCE
