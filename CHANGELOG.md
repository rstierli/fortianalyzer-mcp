# Changelog

All notable changes to FortiAnalyzer MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **SOAR indicator readers returned empty against real data (missing `time-range`).** `get_indicator_enrichment` and `get_linked_indicators` omitted the `time-range` parameter, so the FortiAnalyzer SOAR API applied its documented **7-day default window** and silently dropped older indicators — the readers returned `[]` even when the appliance held enriched indicators. Both now send an unbounded `time-range` by default (matching the GUI's "show all") and accept an optional `time_range` argument to narrow it. This shipped un-noticed because the reference estate had no populated indicators when the readers landed (#64); the first real enriched indicator exposed it. Live-validated end-to-end (a real Malicious URL now returns `enrichment-reputation`/`enrichment-confidence`/`enrichment-status`).
- **`get_indicator_enrichment` queried the wrong endpoint.** The reputation is served inline on the indicator **list** endpoint, not `/indicator/enrichment/{nil-uuid}` (which returns nothing without a real enrichment UUID). The reader now resolves the indicator by a `value`/`type` filter on the list endpoint and, for `detail_level="extended"`, follows the row's real `enrichment-uuid` to `/indicator/enrichment/{uuid}` for the raw source detail. The single-quoted filter value rejects an embedded quote up front (no IP/URL/domain legitimately contains one), closing a filter-injection vector.

### Security

- **Masking closes the remaining boundary leaks tracked in [#71](https://github.com/rstierli/fortianalyzer-mcp/issues/71).** Malformed `target` shapes and map keys now fail closed while preserving device-identity keep values, mixed-case composite siblings receive the same masking treatment as lowercase keys, and a URL with a marked host token that cannot decrypt now passes through whole instead of exposing a resolved tail beside the stale token.
- **Masking boundary hardening from the security review ([#68](https://github.com/rstierli/fortianalyzer-mcp/issues/68)).** Seven fixes around a crypto engine the review found clean:
  - Filter resolution reuses the project filter sanitizer, so a resolved URL tail that decodes to filter-significant characters is escaped and quoted (or left unresolved when it carries control characters) instead of landing bare in the clause. This closes a filter-splice path in both quoted and unquoted clauses.
  - Alert `target` entries fail closed: an unknown target name burns to an irreversible placeholder, list and dict values under a known name burn any non-scalar content, a repeated `asset_value` masks with its `value`, and the `name`/`value`/`asset_value` keys are matched case-insensitively.
  - A TEXT field delivered as a list now has each string leaf scanned for embedded IOCs; a TEXT field delivered as a dict is left to the structured pass, which already masked it, so its tokens are not masked a second time.
  - The three typed-field and device-identity lookups are case-insensitive.
  - Mask-path validation errors carry no cleartext, in the message or the chained exception cause.
  - A `url`/`referralurl` argument that carries userinfo passes through input resolution unchanged.
  - Cipher failures normalize to a masking error at the engine boundary, so input resolution never aborts a tool call on an unexpected library error while a genuine programming error still surfaces.
- **Skills: redact caller-facing `warnings` and sanitize the `triage` alert filter ([#68](https://github.com/rstierli/fortianalyzer-mcp/issues/68) M4, L5).** The skill dispatcher's success path did not route through `error_response`, so a degraded sub-call could carry raw FAZ exception text — internal hostnames and any `session=`/`token=` material — into `result.warnings` unredacted. `warnings` are now scrubbed with `redact()` both at the source (`_call`, `_fetch_attached_alerts`) and at a dispatcher chokepoint. Separately, `triage` built its `alertid==` filter from `alert_id` behind a fragile no-double-quote blocklist; it now uses `sanitize_filter_value()`, which escapes/quotes quote/operator/backslash characters so a crafted id cannot rewrite the clause (and a safe id still runs the fast filter-first lookup). Masking-core findings from the same review (filter-injection via URL tail, `_mask_target`/TEXT-list container gaps) are tracked in #68 for the masking track.

### Fixed

- **Free-text masking handles re-cased identifiers without conflating case-sensitive principals.** Hostname and domain echoes now match case-insensitively in one pass, exact username spelling retains its own reversible token, and substituted tokens are not rescanned (previously a token containing the pad character could be corrupted by a later pass, which lost the value). Case folding is ASCII-only, so an identifier is matched across ordinary upper/lower/title spellings but a lookalike that merely case-folds into it under full Unicode rules is left alone rather than being rewritten or burned. When two principals in the same response differ only in case, a third spelling belongs to neither and now fails closed to a placeholder instead of being attributed to whichever was seen first. Substitution compiles one alternation per text field instead of one regex per known value, which removes a cache cliff that made large result sets disproportionately slow; peak memory grows with the number of distinct identifiers in a response (roughly 2 KB each). Note the widened matching also rewrites ordinary prose words that happen to equal a masked identifier in another case, so an estate with usernames like `backup` or `system` will see those words tokenized in log prose.
- **Masked filter values resolve under the FAZ operators this project accepts.** Single `=`, `!~`, `~`, and spaced `!contain` clauses now resolve through the same quoting and filter-injection defenses as the existing operators.

### Added
- **`url`/`referralurl` now mask as carry-and-reverse URL tokens ([#40](https://github.com/rstierli/fortianalyzer-mcp/issues/40) later phase, design agreed on the RFC).** The host masks in place exactly like `http_url` (same token as a sibling `host_name` for hostname values; credentials in the netloc fail closed on the whole value), and the entire path+query+fragment seals into one reversible `url-<kid>-<ct>` token: the raw tail is utf-8 + lowercase-base32 encoded before FPE, so it rides the existing string cipher (base32 output is a strict subset of the alphabet and never contains the pad char) and hostile bytes (`~`, percent-encoding, mixed case, non-ASCII) round-trip byte-exact. On the way back, a masked URL handed in as a `url`/`referralurl` argument or inside a filter clause decomposes, resolves host (marked token or IP-literal) and tail, and reassembles the exact original before validators or FAZ see it; a re-masked echo reproduces the identical token. Documented residuals: scheme/port stay clear, token length reveals tail byte length (base32 is a fixed ~1.6x expansion and FF3 is length-preserving), identical tails and shared-first-chunk prefixes correlate, and substring search inside the tail (`url contain "/login"`) is an accepted loss: these fields are carry-and-reverse, not greppable. `http_url` deliberately stays host-only (GA-time call). The flag-on live round over real webfilter rows found the live `url` field arrives whole-URL percent-encoded on both 7.6.7 and 8.0.0 (no parseable host), leaking the browsed destination through the encoding; an adversarial review after the round found the same leak for every other hostless shape (`www.example.com/uri`, bare `/uri`, `example.com:8080/x` where urlsplit reads the host as the scheme). Any `url`/`referralurl` value without a parseable host now seals whole as one `url-` token and round-trips to the exact original; percent-encoded userinfo fails closed like literal credentials do. Live-verified on both versions: 0 of 5 destinations survive across 200 rows each, every sealed token resolves back to its captured raw value, zero placeholders. FAZ filter-length note: probed live up to a 512 KiB filter value with no rejection, so masked-URL growth does not hit an appliance filter cap at any realistic size.
- **SOAR indicator reader tools (Wave-2 threat-intel building blocks — [#44](https://github.com/rstierli/fortianalyzer-mcp/issues/44)).** Two additive read-only tools: `get_linked_indicators` (IOC indicators tied to an alert or incident) and `get_indicator_enrichment` (stored reputation/confidence/source for an IP/URL/domain, resolved by type+value or UUID). Read-only reads only — the add-only `/indicator/enrichment` path is not exposed. Feature-gated on SOAR being licensed. Request shapes verified live against a real appliance; the enrichment payload shape is spec-derived and not yet live-validated (the reference estate currently has no populated SOAR indicators). Base tool count 81 -> 83.
- **UEBA + alert-handler reader tools (Wave-2 skills building blocks — [#44](https://github.com/rstierli/fortianalyzer-mcp/issues/44)).** Four additive read-only tools: `get_endpoints` and `get_endpoint_vulnerabilities` (UEBA endpoint/asset profiles + CVEs), `get_endusers` (UEBA identity records; `extended` detail adds email/department/title/phone), and `get_alert_handlers` (basic/correlation detection-rule config). Feature-gated on UEBA being licensed/enabled; API paths identical on 7.6.7 and 8.0.0. These are the readers the Wave-2 skills (`asset_lookup`, `identity_lookup`, `alert_rules`, `risk_assessment`, ...) will compose; useful on their own in the meantime. Live-verified against a real appliance. Brings the base tool count to 81 (82 with the skills dispatcher).

## [2.9.1] - 2026-07-12

Patch release: fixes a startup crash when masking is configured through `.env` alone.

### Fixed
- **Masking no longer crashes on startup when `FAZ_MASKING_KEY` is set only in `.env`.** `MASKING_ENABLED` is read through pydantic-settings (which loads `.env`), but the FPE engine read `FAZ_MASKING_KEY` straight from the process environment, which does not — so enabling masking via `.env` alone (exactly as the README documents) turned masking on, failed to find the key, and aborted fail-closed. `install_masking` now bridges the key from settings/`.env` into the environment when it is not already exported (a real environment variable, e.g. a container's, still wins). Regression test added.

## [2.9.0] - 2026-07-12

Minor release: reversible data masking, RFC #40 Phases 0-2 — beta, behind `MASKING_ENABLED` (default **off**; no behavior change unless enabled; requires `FAZ_MASKING_KEY`). Flag-on live-validated on two estates across FAZ 7.6.7 and 8.0.0.

### Fixed
- **The browsed destination no longer leaks through `http_url` and `host_name` targets on webfilter alerts.** A flag-on leak sweep against a second estate found the domain that `host_name` masks surviving one key away, inside the full URL of `event_details.http_url` (`https://<domain>/`) and as a `target[]` entry named `host_name` — a target name the allowlist did not know. `host_name` targets now mask with the IP-or-host logic (same token as the flat `host_name` field), and `http_url` masks its HOST component in place while scheme, path and query stay clear — URLs with embedded credentials fail closed, and non-URL values fall back to the free-text scan. Path/query segments embedding identifiers remain a documented residual of the deferred full-URL token design.
- **Nested tool calls no longer double-mask.** Tools invoke other registered tools through their module-level names, which are the wrapped functions (`get_top_threats` -> `get_fortiview_data`), so with masking on the inner result was masked twice: no token from a nesting tool round-tripped (one unmask step yielded another token, not the value) and a second pass over a first-pass token could fail closed into an irreversible placeholder. Found by the release-gate flag-on live round: 8 of 8 fortiview threat rows arrived double-masked on both versions, 2 of them as placeholders. A context-variable boundary guard now keeps unmask/mask at the outermost wrapped call only; nested calls run bare inside the outer boundary.
- **`incident_reporter` no longer un-masks the incident reporter.** The field is polymorphic (username on manual incidents, alert id on auto-raised ones) and deliberately untyped, but on manual incidents it repeats the `reporter` value verbatim, so masking `reporter` while leaving `incident_reporter` clear leaked the username (found live on both versions, including the `"faz-mcp"` automation default). It now masks with the same token exactly when it equals the sibling `reporter` or `lastuser`; alert ids and unproven values stay untouched.
- **`target[]` entries naming the reporting appliance follow the device-identity flag.** Live 8.0.0 alerts carry the appliance serial as a `device` target; it was masked there while `devid` and `groupby1` correctly left it clear (device identity is unmasked by default), pairing the token with its own serial two keys away. Device-identity values present in the response are now pre-collected and left clear in `target[]` when `FAZ_MASK_DEVICE_IDENTITY` is off; with the flag on they mask everywhere, with the same token as `devid`.

### Added
- **`threat`/`obf_url` (fortiview `top-threats`) are masked as a domain pair, closing the browsed-destination leak.** A non-empty `obf_url` marks the row: it is populated exactly when `threat` holds a browsable web domain (as its `[dot]`-escaped twin) and empty on every signature, filename and anomaly row, verified across both reference estates on the RFC [#40](https://github.com/rstierli/fortianalyzer-mcp/issues/40) thread (`logtype` does not discriminate, and malware rows carry dotted filenames any shape test would misread). With `obf_url` set, `threat` masks as a domain and `obf_url` is unescaped, masked and re-escaped so the pair stays consistent; with it empty, `threat` keeps its analytic value. Documented fail-open residual: a build emitting a domain `threat` with an empty `obf_url` would leak that row class; the leak test carries a tripwire assertion so a counterexample fails a test instead of leaking silently.
- **Tool-argument unmasking — Phase 2 of RFC [#40](https://github.com/rstierli/fortianalyzer-mcp/issues/40).** With masking on, masked tokens the model hands back as tool arguments are resolved to real values BEFORE input validators and the FAZ API see them: marked tokens (`host-`/`user-` prefixes, domain/email suffix forms) resolve anywhere — bare arguments, list items, nested dicts (e.g. a dispatcher's `params` object), and inside filter-expression clauses — while unmarked IP/MAC tokens resolve only where the argument or filter field name identifies the type. Failure policy: a marked token that does not decrypt is passed through so the downstream validator rejects it loudly (incl. rotated-key tokens, which log the key-id mismatch); an unmarked non-decrypting value passes through as a probably-real address. Documented residual: deterministic FPE cannot distinguish a real IP typed by an operator from a token of the same shape.
- **Tool-output masking (`MASKING_ENABLED`, default off) — Phase 1 of RFC [#40](https://github.com/rstierli/fortianalyzer-mcp/issues/40).** With the flag on (requires `FAZ_MASKING_KEY`), every registered tool's result is masked before it reaches the LLM: allowlisted fields are masked by type at any nesting depth (including composite keys such as `groupby1`/`grpby`/`target`/`devvds`), then free text (`msg`, `logdesc`, echoed `filter` strings, ...) gets an IOC scan plus substitution of every value masked elsewhere in the same response. Fail-closed: unmaskable values become irreversible keyed placeholders, and a masking failure withholds the raw result behind a `masking_failed` error envelope. Device identity (`devname`, `devid`, `sn`, ...) is masked only with the separate `FAZ_MASK_DEVICE_IDENTITY` flag.
- **FPE masking engine (`fortianalyzer_mcp.masking`) — Phase 0 of the reversible data-masking RFC [#40](https://github.com/rstierli/fortianalyzer-mcp/issues/40).** Format-preserving encryption (NIST FF3-1 via the `ff3` package) with per-type deterministic, key-reversible mask/unmask for IPv4/IPv6, MAC, hostname, username, domain, and email values. Tokens carry recognizable markers where reversibility allows (`host-`/`user-` prefixes, `.masked.invalid` suffix for domains/emails), and every marked token embeds a 4-hex-char one-way key id so a token minted under a rotated key fails loudly on unmask instead of decrypting to a plausible wrong value (IP/MAC tokens cannot carry one — documented residual). Usernames use a mixed-case FF3 alphabet and round-trip case-preserved (`Admin` and `admin` are distinct principals); the other string types normalize to lowercase. Short values are padded to satisfy the FF3-1 minimum domain size and over-length values are chunked with position-varied tweaks. Two RFC deviations found during verification are documented in the module: fully reversible MAC and email tokens cannot keep a fixed reserved OUI / replacement domain, so MACs share the RFC's "IP wrinkle".

## [2.8.0] - 2026-07-12

Minor release: the skills layer, Wave 1 of RFC #44 — beta, behind `FAZ_SKILLS_ENABLED` (default **off**; no behavior change unless enabled). Live-validated on FAZ 7.6.7 and 8.0.0.

### Added
- **Skills layer refinements from the #46 review.** The per-incident attachment lookups in `incidents` now run as a bounded concurrent fan-out (5 at a time) instead of serially, and the alert window scan is deferred until an incident actually needs the linkage-key fallback — `alerts_scanned` reports 0 when attachments correlated everything. `triage` resolves an alert subject filter-first (`alertid=="<id>"` over a 30-day window, live-verified on 7.6.7 and 8.0.0) before falling back to the context-window scan, removing the degraded no-severity path for day-after triage; and an alert's related incidents are now resolved authoritatively by checking each context incident's attachments for the alert (FAZ rejects a reverse `attachsrcid` query without `incid`, and ignores `attachsrcid` as a filter — both live-verified), replacing the noisy all-incidents-in-window fallback. The dispatcher's `skill="describe"` alias for `skill="list"` is now documented, and the `skill_output_invalid` / `skill_error` dispatcher error paths are covered by tests.
- **Skills layer (beta) — Wave 1 of the skills RFC [#44](https://github.com/rstierli/fortianalyzer-mcp/issues/44).** One new dispatcher tool, `faz_skill(skill, params)`, exposing opinionated multi-tool orchestrations with pydantic-validated, versioned output schemas: `incidents` (incidents + best-effort correlated alerts), `reports` (list/fetch generated reports), `log_search` (filter-based search, verbatim rows), `triage` (alert/incident evidence bundle + deterministic severity-derived assessment), and `incident_summary` (structured incident summary with evidence logs, threat landscape, and derived timeline). `skill="list"` returns the machine-readable catalogue including each skill's parameter and output JSON schema. Feature-flagged via `FAZ_SKILLS_ENABLED` (default **off** — no behavior change unless enabled), read-only, additive only (zero edits to existing tool modules), and slot-safe (at most one logview search per invocation, bounded by the existing logsearch semaphore). Not available in `FAZ_TOOL_MODE=dynamic` (beta limitation, logged as a warning). Triage's indicator-enrichment slot reports "unavailable" until the Wave-2 SOAR reader lands.

## [2.7.3] - 2026-07-10

Patch release: the third and last of the never-validated request-shape family (#47, #49, #54) — `create_incident` had never worked against a live FAZ — plus the incident status enum it exposed. Spec-verified against the bundled 7.6.7/8.0.0 specs (which agree) and live-verified on both versions (PR #57).

### Fixed
- **`create_incident` works again: the create request now sends the required `reporter` and `endpoint` params.** `ADD /incidentmgmt/adom/{adom}/incident` requires `reporter`, `endpoint` and `category` (per the bundled 7.6.7/8.0.0 specs, which agree; confirmed live on both), but the client sent neither of the first two and the tool exposed no way to provide them, so every create had always failed. The tool now requires `endpoint` and `category` (`category` is passed through unvalidated, since the spec types it as a free string and the valid set is appliance-defined), defaults `reporter` to `"faz-mcp"`, validates `severity` against the incident enum (`high`/`medium`/`low`, narrower than the alert set), and exposes the optional spec params `status` (validated), `epid` and `euid`. `name` is absent from the spec but verified live to persist on the incident record, so it stays exposed as optional. The ADD success response carries `incid` at the top level with no `data` wrapper, asymmetric with `get_incident`; documented in the client so nobody "fixes" one to match the other. Verified live on 7.6.7 and 8.0.0. Closes [#54](https://github.com/rstierli/fortianalyzer-mcp/issues/54).
- **Incident status values match the spec enum.** `_VALID_INCIDENT_STATUSES` listed `new`/`investigating`/`contained`/`resolved`, values the appliance rejects with `not a valid enum value for 'status'` (verified live on both versions), while blocking the legal ones, so `update_incident` could never move an incident to any real non-closed state. The set is now the spec enum: `draft`/`analysis`/`response`/`closed`/`cancelled`.

## [2.7.2] - 2026-07-09

Patch release: two request-shape bugs in tools that had never worked against a live FAZ — both found by the skills-layer live validation (#44 / PR #46), spec-verified against the bundled 7.6.7/8.0.0 FNDN specs (which agree), confirmed by Roland against FNDN, and live-verified after the fix (PRs #48, #50).

### Fixed
- **`get_incident` works again: single-incident retrieval goes through the plural `incidents` endpoint.** `GET /incidentmgmt/adom/{adom}/incident/{incid}` does not exist — that path is update-only, and FAZ rejects a GET on it with `Not supported method`, so the tool had never returned data. Retrieval now uses `GET /incidentmgmt/adom/{adom}/incidents` with `incids=[incident_id]` (per the bundled 7.6.7/8.0.0 specs, which agree) at the default detail level — `extended` drops `severity`/`status` (verified live) — unwrapping the single record and raising a clear not-found error for an empty match. Verified live. Closes [#49](https://github.com/rstierli/fortianalyzer-mcp/issues/49).
- **`get_alert_details` works again: the extra-details request now sends `alertids` (plural).** `GET /eventmgmt/adom/{adom}/alerts/extra-details` requires the `alertids` array parameter (per the bundled 7.6.7 and 8.0.0 specs), but the client sent `alertid` — the key `alertlogs` uses — so FAZ rejected every call with `Invalid params: No Params.` and the tool had never returned data. Verified live. Closes [#47](https://github.com/rstierli/fortianalyzer-mcp/issues/47).

## [2.7.1] - 2026-07-04

### Fixed
- **ICMP rows with an empty `service` field are no longer omitted from the `get_policy_port_analysis` ICMP breakdown.** Follow-up to #37: proto=1 logs whose `service` field is empty or absent matched no parsing branch and were silently dropped from the `icmp` section (while still counted in `total_hits` and `protocols`), so the ICMP hit sum could undercount the proto=1 total. They are now recorded as `type=unknown`, keeping the `icmp` sum equal to the proto=1 count in `protocols`.

## [2.7.0] - 2026-07-03

Full-codebase correctness and security-hardening review: uniform identifier validation, config/env parsing fix, task-state handling, device-filter classification, report custom time windows, and deployment hardening.

### Fixed
- **ICMP entries in `get_policy_port_analysis` no longer leak the application service name into `type_code`.** When a FortiGate SD-WAN SLA health-check pings a DNS server, the ICMP (proto=1) packet is logged with `service="DNS"`; the analyzer parsed `service` for the ICMP type/code (per #9) but, for a value that is not `PING` or `icmp/T/C`, emitted `type_code: "service=DNS"` verbatim — an inconsistent, non-type/code value (verified live: policy 38 returned `service=DNS`, policy 46 correctly returned `type=3/code=3`). Unrecognized ICMP `service` values (and malformed `icmp/…` strings) now record as `type=unknown` so `type_code` always means an ICMP type/code. Closes [#37](https://github.com/rstierli/fortianalyzer-mcp/issues/37).
- **`MCP_ALLOWED_HOSTS` no longer crashes startup when set in the documented comma-separated format.** pydantic-settings JSON-decodes `list[str]` env fields, so `MCP_ALLOWED_HOSTS=faz.example.com,proxy.internal` (or even a single host) raised `SettingsError` before the server started. The field is now annotated `NoDecode` with a before-validator that accepts a comma-separated string or a JSON array. Requires pydantic-settings >= 2.3.0 (floor bumped in `pyproject.toml`).
- **`wait_for_task` / `list_tasks(filter_state=...)` handle the numeric task `state` FAZ actually returns.** `/task/task` reports `state` as an int (done=4, error=5, ...); `wait_for_task` called `.lower()` on it (AttributeError on every poll) and `list_tasks` compared the string name against the numeric field (silently empty). Both now normalize via a shared state-code map; string states keep working, and unknown `filter_state` values are rejected instead of matching nothing.
- **`build_device_filter` no longer misroutes hostnames that start with a serial prefix.** Names like `FGT-HQ-01`/`FG-BRANCH` were sent as `devid`, making every log/traffic/pcap search for that device silently return zero rows. The devid branch now requires a full serial match, including a new VM-serial form (`FMG-VM...`, `FAZ-VMTM...`).
- **FortiView tools route the device filter through `build_device_filter`.** `run_fortiview`/`get_fortiview_data` sent everything (including serials) as `devname`, silently scoping the query to nothing for serial input. The `All_Device` default is preserved.
- **Reports: custom `"start|end"` time ranges no longer silently cover the wrong period.** Previously `run_report`/`run_and_wait_report` sent `time-period: "other"` with no window, so FAZ ran the report over the layout's default period (verified live on 7.6.7 and 8.0.0). Now: `run_and_wait_report` configures the window on the layout's schedule config object (`update /config/adom/{adom}/sql-report/schedule/{layout_id}`: numeric `time-period` 16 = "other" + `period-start`/`period-end` in FortiOS timedate `"HH:MM yyyy/mm/dd"`, the format FAZ verifiably parses), verifies it by read-back (an unaccepted window aborts the run with an error), HOLDS it until generation completes — FAZ reads the schedule at generation time, not submission (verified live) — then restores the previous period. The success payload echoes `requested_window`, checks the shared schedule wasn't changed mid-run, and carries an explicit warning until generator consumption of the stored window is confirmed live (`tools/verify_custom_window.py --phase mech` discriminates the remaining run-mechanism hypotheses). `run_report` (fire-and-forget) rejects custom ranges outright, since it cannot hold the shared schedule through generation. Unknown presets (e.g. `"14-day"`) raise a validation error instead of silently becoming `last-7-days`, and the report device filter uses `build_device_filter` instead of hardcoding `devid`.
- **Progress percentages returned as strings no longer break polling.** `get_fortiview_data`, `fetch_fortiview`, and the `run_and_wait_report` wait loop coerce `percentage`/`percent` numerically (shared `coerce_num`, moved from `log_tools` to `utils.responses`) instead of comparing `"50" >= 100` (TypeError swallowed into a generic error).
- **Transient-error retries no longer replay non-idempotent writes.** A network error after FAZ accepted an ADD/SET/EXEC (e.g. `create_incident`, `add_device`) could double-execute it on retry. Transient retry is now gated to GET requests; the reconnect-once path for expired sessions stays enabled for all verbs (an expired session means the request never executed).
- **`run_fortiview` / `run_ioc_rescan` return an error when FAZ supplies no TID** instead of a success payload with `tid: null` that fails on the next call.
- **`fetch_fortiview` reports completion state** (`complete`, `percentage`, warning) so a fetch before the scan reaches 100% is no longer indistinguishable from final results (partial top-N).
- **`search_ips_logs` no longer fabricates `total` when FAZ omits the match count.** It reports `total: null` + `total_is_known: false` + a truncation warning instead of `total = len(logs)`, which made a limit-capped page look like an exact count.
- **`search_traffic_logs(policy_id=0)` now filters on the implicit-deny policy** (`if policy_id:` dropped id 0).
- **`search_devices(connection_status=...)` uses the DVMDB enum** (unknown=0, up=1, down=2) and rejects unrecognized values; `"down"` previously matched *unknown* devices.
- **`get_system_timezone` caches a definitive negative result**, eliminating one extra `/sys/status` round-trip per relative-range query on FAZ builds that don't report a parseable timezone. Probe failures (FAZ unreachable) are not cached.
- **List-form JSON-RPC results with a string `status` no longer crash `_raw_request_once`** (`AttributeError` on `"ok".get(...)`); string statuses are tolerated the same way the dict-form branch already did.
- **Repeated failed `connect()` calls no longer leak a `requests.Session` per attempt** (the half-built pyfmg instance is cleared on failure).
- **docker-compose healthcheck works again**: it invoked `curl`, which `python:3.12-slim` does not ship, overriding the image's working python healthcheck and marking the container permanently unhealthy.

### Security
- **Uniform identifier validation across all tool modules.** `adom` (and `get_adom`'s `name`) is now validated in every tool — report/event/incident/ioc/system/fortiview/log tools previously interpolated it into the JSON-RPC url path unvalidated; device names in `get_device`/`get_device_info`/`list_device_vdoms` and a new `validate_incident_id` for `get_incident`/`update_incident` close the same url-path-injection class. `fetch_fortiview` now validates `view_name` like its siblings.
- **Documented limit/offset/poll bounds are enforced**: `get_alerts`/`get_alert_logs`/`get_incidents` clamp to 1-2000 and offset >= 0; FortiView limits clamp to 1-1000; `wait_for_task` clamps `poll_interval` >= 1 (a zero/negative value tight-looped against the shared client) and all wait-loop timeouts cap at 3600s.
- **`redact()` also masks quoted-key JSON/dict forms** (`"adm_pass": "x"`), not just `key=value`.
- **docker-compose hardening**: port published on loopback by default (`MCP_BIND_ADDRESS`, new env var), `cap_drop: ALL`, `no-new-privileges`, read-only rootfs with `/tmp` tmpfs, `pids_limit`. Dockerfile pins the `uv` image to a version tag; CI workflow gets an explicit least-privilege `permissions` block.
- **Docs corrected**: `SECURITY.md` referenced `ALLOWED_OUTPUT_DIRS` (correct name: `FAZ_ALLOWED_OUTPUT_DIRS`); `docs/SECURITY_REVIEW.md` is marked as a historical document whose findings/line references predate the current codebase.
- **Bulk device add/delete responses flag their async-task semantics** — counts reflect submission; a warning points to `wait_for_task(task_id)` for per-device results.

### Added
- Regression test suites `tests/test_validation_consistency.py` and `tests/test_bugfix_regressions.py` covering every fix above.

## [2.6.0] - 2026-06-16

Real fix for the policy `total_hits` under-report ([#30](https://github.com/rstierli/fortianalyzer-mcp/issues/30), variant 2): sum the per-slice `total-count`s the breakdown already fetches instead of a separate `limit=1` whole-window logsearch. Removes the v2.4.1 clamp's reason to exist (kept as a guard) and decides exactness per slice. PR [#35](https://github.com/rstierli/fortianalyzer-mcp/pull/35) by [@inxbit](https://github.com/inxbit). Closes [#30](https://github.com/rstierli/fortianalyzer-mcp/issues/30). 559 unit tests pass. Live-verified on FAZ 7.6.7 and 8.0.0 (137 invariant checks per version).

### Fixed
- **`get_policy_traffic_profile` / `get_policy_port_analysis` / `get_policy_protocol_summary` no longer report `total_hits` below `observed_hits`, and now report it correctly when the window is fully scanned.** The total came from `_query_policy_total_count`, a `limit=1` logsearch whose `total-count` short-circuits the instant the first match is found, so it returned a tiny scanned-block count rather than the real total (observed 44 vs 4,000 on heavy policies, and as low as 37 vs 1,151 in a real audit). That function is deleted. `_query_policy_logs_bounded` now sums the `total-count` each per-slice breakdown search already returns and discards. Slices are contiguous and non-overlapping and each slice's `total-count` is at least the rows it returned, so the summed `total_hits` is `>= observed_hits` by construction. This also drops one FAZ logsearch per policy (was `slice_count + 1`, now `slice_count`).
- **`is_exact` ("complete") is decided per slice and can no longer mislabel an unproven result.** A result is exact only when every slice reported a `total-count` equal to the rows it returned and below the fetch limit, i.e. every slice was fully scanned. The previous rule was `truncated_slices == 0`, which would call a result "complete" even when a slice timed out or omitted its total (0 rows, not counted as truncated). Exactness is now computed from the raw per-slice proof, so an aggregate over/under-count cancellation cannot fabricate completeness.

### Changed
- The v2.4.1 defensive clamp (`max(authoritative, observed_hits)` at `_bounded_metadata`) is kept as a belt rather than removed: with variant 2 the summed total is `>= observed_hits` by construction so it is normally a no-op, but if a slice ever under-reports below its own rows the clamp still holds the schema contract and now logs a warning instead of silently flooring. The clamped display value is never used to decide `is_exact`.
- Tool docstrings, `README.md`, and `docs/INTERNAL_ARCHITECTURE.md` now describe `total_hits` as the sum of per-slice `total-count`s (a floor that is at least `observed_hits`), not an "authoritative whole-window" count.

## [2.5.0] - 2026-06-16

Type safety + internals refactor and a session-expired re-login signal. PRs [#33](https://github.com/rstierli/fortianalyzer-mcp/pull/33) and [#34](https://github.com/rstierli/fortianalyzer-mcp/pull/34) by [@inxbit](https://github.com/inxbit). 554 unit tests pass.

### Changed
- **Blocking `pyfmg` calls are off the asyncio event loop.** All FortiAnalyzer JSON-RPC calls (login, logout, raw POST, generic verbs) are wrapped in `asyncio.to_thread` and serialized by a per-client `asyncio.Lock`. The lock is required because `pyfmg` shares one `requests.Session` + req-id counter that is not thread-safe; one in-flight FAZ request per host matches the prior behavior, but the loop is no longer blocked. `connect()` re-checks `self._connected` inside the lock to avoid double-login on concurrent callers.
- **`ValidationError` consolidated into a single class.** The canonical type now lives in `utils.errors`, subclasses both `FortiAnalyzerError` and `ValueError`, and is re-exported from `utils.validation` so every existing import (`from utils.validation import ValidationError`) keeps working. Tools doing `except ValidationError` still match (single class, MRO correct); tools doing `except ValueError` still match too (the new class is-a `ValueError`). The FAZ `-5` error path that maps to `utils.errors.ValidationError` is now catchable by tools that previously only caught the `validation.py` variant — a strict improvement.
- **Client typing tightened.** The `_request_dict` / `_raw_request_dict` helpers add a single `cast(dict[str, Any], ...)` per shape — pure mypy hint, single cast point, no runtime assertion. Filter params widened from `list[str]` to `list[Any]` so callers can pass nested `[field, op, value]` triples that FAZ actually accepts — the prior annotation was wrong. One `# type: ignore[call-arg]` added in `config.py` for pydantic-settings env loading, commented.
- **FAZ error code `-11` now reclassified as a session-expired signal.** Long-lived clients that hit `-11` ("No permission for the resource") on FortiAnalyzer 8.0.0 — which raises it when an established session goes stale — re-login exactly once via the existing serialized `_force_reconnect` path instead of retrying the dead session. The reconnect path inherits the v2.0.1 lock + generation counter, so concurrent callers don't race. Reconnect budget is hard-coded to a single retry per request; a second `-11` after re-login raises immediately. `ERROR_CODE_MAP[-11]` updated from `TimeoutError("Task timeout")` to `PermissionError("No permission for the resource")` so the raised exception class matches the new semantics.

### Added
- `FortiVoice` (`FV`) serial prefix added to `_DEVICE_SERIAL_PREFIXES` so FV serials route through the device-name filter path. Previously, `DEVICE_SERIAL_PATTERN` accepted FV serials but `_DEVICE_SERIAL_PREFIXES` did not list `FV`, silently building a filter that matched nothing. Fix bundled with the typing PR since it lives in the same `validation.py` reach.
- `asyncio.get_event_loop()` → `asyncio.get_running_loop()` in the `log_tools` polling loop — correct for Python 3.12+.

## [2.4.1] - 2026-06-16

Defensive clamp at the policy-port-analysis response boundary so `total_hits >= observed_hits` always holds. Closes the user-facing symptom of [#30](https://github.com/rstierli/fortianalyzer-mcp/issues/30) — under-reported totals were breaking policy-audit decisions on heavy-traffic policies. 552 unit tests pass.

### Fixed
- **`get_policy_port_analysis` (and the other bounded-policy tools) no longer return `total_hits` smaller than `observed_hits`.** The authoritative total comes from a `limit=1` logsearch whose `total-count` short-circuits unreliably on heavy traffic — on a 7-day window for a busy policy we observed `total_hits: 37` while the breakdown itself counted `observed_hits: 1149`. The response-assembly site at `_bounded_metadata` now clamps `resolved_total_hits = max(authoritative, observed_hits)` so the schema contract holds. `total_hit_source` continues to report `logsearch_total-count` since that is where the value came from; the clamp only defends against the under-report failure mode. This is a defensive shim and will become a no-op once `_query_policy_total_count` is reworked to sum per-slice totals (variant 2 in the [#30](https://github.com/rstierli/fortianalyzer-mcp/issues/30) issue body).

## [2.4.0] - 2026-06-16

Security hardening + correctness fixes shipped together. PRs [#31](https://github.com/rstierli/fortianalyzer-mcp/pull/31) (security) and [#32](https://github.com/rstierli/fortianalyzer-mcp/pull/32) (correctness) by [@inxbit](https://github.com/inxbit). 552 unit tests pass.

### Security
- **DVMDB credential blobs are masked on device reads.** `list_devices`, `get_device`, `search_devices`, and `get_device_info` now route through `sanitize_for_logging` so the `adm_pass` field returns `***REDACTED***` instead of the cleartext credential blob. The blob was a leak, not a documented field — agents that previously parsed `adm_pass` will see the redaction placeholder.
- **PCAP ZIP extraction enforces a 50MB cap against crafted ZIP headers.** Decompression in `get_pcap_by_session`, `download_pcap_by_url`, and `search_and_download_pcaps` now reads with a hard `size+1` byte limit rather than trusting `ZipInfo.file_size` (which is attacker-controlled). Defends against ZIP-bomb / oversized-archive attacks at the FAZ-API boundary.
- **HTTP transport bearer-token comparison uses SHA-256 + `hmac.compare_digest`.** The previous compare leaked token length via early-exit timing. Both tokens are now hashed to 32 bytes before constant-time compare, removing the length side-channel.
- **Mutation tools validate `adom` / `device_name` / `severity` / `status` against allowlists** before reaching the FAZ. `add_device`, `delete_device`, `create_incident`, and `update_incident` reject malformed inputs at the tool boundary with a structured error envelope.

### Fixed
- **`acknowledge_ioc_events` was 100% broken** — the tool was passing `ioc_ids=` to the client method, whose signature is `event_ids=`. Every call raised `TypeError`. Corrected.
- **`get_fortiview_data` no longer returns truncated top-N data.** The old completion guard exited on the first non-empty `data` payload, before polling reached `percentage=100`. The fetch now waits for full completion; older FAZ builds that don't emit `percentage` are treated as complete (back-compat preserved).
- **`run_and_wait_report` verifies completion via `report_fetch` instead of assuming success.** Previously, any time the report tid disappeared from the running list, the wrapper returned success — including on report failure or a startup race where the tid hadn't appeared yet. Now confirms `state == "generated"` (success); `pending`/`running` keeps polling; anything else is an error.
- **`run_ioc_rescan` passes the correctly-shaped device filter.** The tool was passing a raw string where the client expected `list[dict[str, str]]` — a guaranteed type mismatch. Now routes through the shared `build_device_filter()` helper.

### Added
- `tests/test_security_regressions.py` — pins each of the four security claims with fake clients that mirror real signatures so kwarg drift fails the test.
- `tests/test_correctness_regressions.py` — pins the four correctness fixes; the IOC ack test would fail if `ioc_ids=` were reintroduced; the FortiView test explicitly asserts the fetch poll loop iterates more than once.

## [2.3.0] - 2026-06-15

New `list_report_templates` tool backed by FortiAnalyzer's dedicated `/template/list` endpoint. PR [#29](https://github.com/rstierli/fortianalyzer-mcp/pull/29). 535 unit tests pass.

### Added
- **`list_report_templates(adom)` tool.** Returns the list of report templates available in an ADOM via the spec-defined `/template/list` JSON-RPC endpoint, rather than scraping `list_report_layouts` and filtering by name. The dedicated endpoint returns templates with their canonical IDs / names / language / category, so callers building report-run workflows can pick a template by ID without first listing layouts.

## [2.2.1] - 2026-06-15

Align logsearch poll-before-fetch with the FortiAnalyzer JSON-API spec — drop the non-spec `/logsearch/count/{tid}` endpoint and non-spec `progress-percent` field. PR [#28](https://github.com/rstierli/fortianalyzer-mcp/pull/28). Closes [#27](https://github.com/rstierli/fortianalyzer-mcp/issues/27). 589 unit tests pass; cross-verified against FAZ 7.6.7 and 8.0.0 (same MCP code, both hosts produce the same shape).

### Fixed
- **Log search no longer hits a non-spec count endpoint that 8.0 rejects.** The 2.0.1 poll-before-fetch contract probed readiness via `/logsearch/count/{tid}` and the non-spec field names `progress-percent` / `total-logs` / `scanned-logs`. That endpoint is not in the FortiAnalyzer JSON-API spec — on 8.0 it returns an error which cascaded into `search_timeout`, slot exhaustion, and the FortiView fallback. Readiness now polls the standard `/logsearch/get/{tid}?limit=0` and the spec-defined `percentage` field — behavior identical on 7.6.7 and 8.0.0, confirmed end-to-end against both versions.
- **Same slot-leak fix still in force.** The shared budget, semaphore-bounded concurrency, deadline-bounded count/fetch, and shielded best-effort `logsearch_cancel` on non-delivered exits all survive — only the readiness signal changed.

### Removed
- The non-spec `/logsearch/count/{tid}` probe path (and its `count_unsupported` fallback flag), the non-spec `progress-percent` / `scanned-logs` readiness fields, and the supporting client helpers. The poll-before-fetch contract now uses only documented spec calls.

## [2.2.0] - 2026-06-12

Fail closed: the streamable-HTTP transport now refuses to start without `MCP_AUTH_TOKEN` unless the operator explicitly opts out with `MCP_ALLOW_NO_AUTH=true`. PR [#25](https://github.com/rstierli/fortianalyzer-mcp/pull/25) by [@inxbit](https://github.com/inxbit). Closes [#20](https://github.com/rstierli/fortianalyzer-mcp/issues/20). 544 unit tests pass.

### Changed
- **The HTTP transport now fails closed when `MCP_AUTH_TOKEN` is unset.** The streamable-HTTP server fronts the full tool surface (including device add/delete and PCAP download), so it previously could serve everything unauthenticated if the token was simply forgotten. `run_http()` now refuses to start without a token and exits with a message that names the fix, unless the operator explicitly opts out with `MCP_ALLOW_NO_AUTH=true` (logged at CRITICAL; intended only for a trusted, isolated bind such as 127.0.0.1 behind a gateway). **Upgrade note:** a deployment that ran on a `0.0.0.0` bind without a token must now set either `MCP_AUTH_TOKEN` or `MCP_ALLOW_NO_AUTH=true` to keep starting.

### Added
- `MCP_ALLOW_NO_AUTH` setting (default `false`) — the explicit opt-out for running HTTP without a token. 4 tests cover token-set start, no-token fail-closed, empty-token fail-closed, and the explicit opt-out.

## [2.1.1] - 2026-06-11

Security hardening: redact remaining tool error messages + warn when TLS verification is disabled. PR [#23](https://github.com/rstierli/fortianalyzer-mcp/pull/23) by [@inxbit](https://github.com/inxbit). Closes [#22](https://github.com/rstierli/fortianalyzer-mcp/issues/22). 540 unit tests pass.

### Security
- **Tool error responses no longer echo raw exception text.** The dvm/event/fortiview/incident/ioc/pcap/report/system and log tools returned `str(e)` directly in error responses, bypassing the `redact()` the log/traffic tools already applied; all such sites now route through `redact()` so echoed-back parameters and FortiAnalyzer internals (token, host, session id) cannot leak into a tool response.
- **Warning when TLS verification is disabled.** Connecting with `FORTIANALYZER_VERIFY_SSL=false` now logs a one-time `WARNING` at connect time — the FortiAnalyzer API token and all log/PCAP data are exposed to man-in-the-middle interception — pointing operators toward trusting the FAZ CA instead.

## [2.1.0] - 2026-06-10

Stable baseline `total` across pagination handles, plus drift observability and ADOM-bound handles. PR [#19](https://github.com/rstierli/fortianalyzer-mcp/pull/19) by [@inxbit](https://github.com/inxbit). 540 unit tests pass; live-verified end-to-end on a 7.6.7 appliance across 1d/7d/30d windows.

### Changed
- **`query_logs` / `fetch_more_logs` now report a stable baseline `total` for a pagination session.** A FortiAnalyzer logsearch re-runs per page over a frozen window and the appliance re-counts `total-count` between pages, so the reported `total` could wobble within one pagination session (observed on 7.6.7: 230071 → 230741). `total` is now held as the handle's first-page baseline; `has_more` is decoupled from it and pages against the best observed figure so a short page never stops paging early. See [ADR-0002](docs/adr/0002-baseline-total-for-pagination-handle.md).

### Added
- `page_total` (live per-page count), `total_count_stability` (`single_observation` | `stable` | `drifted` | `unknown`), `total_drift_detected`, `total_delta`, and `has_more_basis` on log-query responses; an `adom_mismatch` guard binding a pagination handle to its ADOM. 11 regression tests against a drift-capable fake.

## [2.0.1] - 2026-06-09

Reliability hardening for FortiAnalyzer 7.6.7. PR [#18](https://github.com/rstierli/fortianalyzer-mcp/pull/18) by [@inxbit](https://github.com/inxbit). 529 unit tests pass; live-verified end-to-end on a 7.6.7 appliance.

### Fixed
- **Log search no longer drains the appliance search-slot pool on FortiAnalyzer 7.6.7.** The shared page runner used to call `logsearch_fetch` immediately after `logsearch_start`, before the async search had finished. On 7.6.7 that premature fetch returned an incomplete page **and reaped the single-use tid**, so the runner re-issued a fresh `logsearch_start` ~once/second for 60s — no search ever completed, and the ~60 starts drained the appliance's search-slot pool (`query_logs` / `fetch_more_logs` / bounded policy slices / PCAP searches all returned zero rows / `search_timeout` / `No available slot for searching`). Replaced with a shared `_run_logsearch_page` whose contract is **poll-before-fetch**: `ensure_connected → logsearch_start → poll logsearch_count` (a cheap GET that does NOT reap the tid) until the scan is complete, then `logsearch_fetch` exactly once. Readiness is `progress-percent >= 100` OR (`total-logs > 0` AND `scanned-logs >= total-logs`) — `matched-logs` is deliberately not a readiness signal.
- **Server lifecycle no longer disconnects the shared client around every HTTP request.** `FastMCP(lifespan=...)` with `stateless_http=True` runs the lifespan per request/session, so the global `faz_client` was being connected then disconnected around every call, dropping the session out from under concurrent requests. Lifecycle ownership moved to `run_http`'s `app_lifespan` (Starlette-level) and `run_stdio`'s coroutine — a single owner for the server's lifetime.
- **Concurrent reconnects no longer race to tear down a revived session.** `_force_reconnect` is now serialized by an `asyncio.Lock` with a generation counter — when several concurrent requests all hit a dropped session, only the first re-logs in; the others observe the bumped generation and return without clearing the revived `_fmg`.
- **Relative time-range windows no longer silently miss recent logs after an upgrade.** FAZ interprets the naive `time-range` timestamps a logview search sends against its LogView ingest clock, which can drift from system "now" — notably after a version upgrade — so a relative window like `"1-hour"` anchored on system-now could land *ahead* of the newest ingested log and return zero rows even though traffic exists. Relative windows are now anchored on the appliance's LogView clock via a probe chain (`logfiles_state → logstats → faz_tz → naive`), with ±2-day / +400-day plausibility guards. Custom absolute ranges (`"start|end"`) skip the probe.

### Added
- **Bounded concurrent in-flight searches across every call site in this process.** A global `asyncio.Semaphore(LOGSEARCH_CONCURRENCY_LIMIT=4)` wraps the page runner, so `query_logs`, `fetch_more_logs`, the policy fan-out, and PCAP searches share one cap. Because a search now **holds** a slot for its whole budget (poll-before-fetch), the appliance-slot guard lives at the shared runner rather than only in the policy fan-out.
- **Shared bounded recovery budget across all reissue causes.** A single `MAX_SEARCH_REISSUES=3` budget covers invalid-tid during count, the invalid-tid race during fetch, and the "premature 100%" empty page — so a reaping appliance can spin at most `1 + MAX_SEARCH_REISSUES = 4` starts per page and is bounded by the wall-clock deadline as well. No new start or fetch is issued past the deadline.
- **Bounded `logsearch_count` and `logsearch_fetch` awaits.** Both calls are wrapped in `asyncio.wait_for` against the remaining wall-clock budget, so a stuck count/fetch cannot extend the slot hold past the search's own timeout.
- **Shielded best-effort cleanup-cancel on non-delivered exits.** Any path that leaves a started search un-fetched (count/fetch error, cancellation, deadline) issues a `logsearch_cancel` under `asyncio.shield(asyncio.wait_for(..., 2.0))` so a cancelled request still dispatches the cancel before the `CancelledError` propagates. If even the dispatch cannot run, the appliance reaps the single-use task on its own.
- **`MAX_SEARCH_TIMEOUT = 300s` upper bound on a single search's wall-clock budget.** Prevents a caller passing a huge timeout from monopolizing a concurrency slot.
- **Fallback for older builds without `logsearch/count`.** A clear unsupported-endpoint error (e.g. `Unknown URL`) falls back to a single direct fetch on the same tid and caches the per-client flag so subsequent searches skip the count probe entirely. Invalid-tid and timeout errors deliberately do NOT trigger the fallback.
- **`time_basis_source` and `clock_skew_seconds` on log-query responses.** Surfaces the LogView clock detection outcome (`logfiles_state` / `logstats` / `faz_tz` / `naive`) so callers can audit which clock anchored the window and by how much it skewed from FAZ "now".
- **`tests/test_logsearch_runner.py`** (646 lines): regression coverage that makes the fakes raise invalid-tid on fetch-before-complete, so the "exactly one start" assertions would fail against the old fetch-first runner. Pins the no-slot-exhaustion contract, the shared-budget cap, deadline behavior across 5 separate branches, leak cleanup, concurrency-cap saturation, and the count-unsupported fallback.

### Security
- **Defense-in-depth path-traversal guard on the report raw-save branch.** `save_report` now asserts the resolved output file stays within the validated output directory, mirroring the ZIP-extract guard added in 1.3.0.

## [2.0.0] - 2026-06-09

Breaking change: policy `estimated_total_hits` / `estimate_available` removed in favor of authoritative `total_hits` + `total_hits_is_known` + `total_hit_source`. See **Changed** section. PR [#17](https://github.com/rstierli/fortianalyzer-mcp/pull/17) by [@inxbit](https://github.com/inxbit).

### Fixed
- **`fetch_more_logs` no longer fails with "Invalid tid".** A FortiAnalyzer logsearch task id is single-use — the first fetch delivers the requested `offset`/`limit` slice plus `total-count`, and the appliance then reaps the task, so any second fetch on the same tid returns `Invalid tid` regardless of ADOM (verified on a live FAZ 7.4.x appliance). `fetch_more_logs` now reconstructs and re-runs the original query (same ADOM, logtype, filter, device, and absolute time window) at the requested offset, which the appliance returns in a stable order, so paging is correct and consistent. An unknown/expired pagination handle returns a structured `error="tid_invalid_or_expired"` error with a recommendation to re-run `query_logs`.
- **`total` is now accurate.** `query_logs` previously read a non-existent `total-lines` key (so `total` always equalled the page `count`); it now reads `total-count` from the fetch response and reports `total_is_known=false` when unavailable.
- **FAZ timezone detection across builds.** `get_system_timezone()` now reads the IANA name from either the `TZ` or `Time Zone` field of `/sys/status`.
- **Reliable bounded policy queries on slow searches.** The policy traffic tools now re-issue a fresh search per slice instead of re-fetching a single-use FortiAnalyzer `tid` (the same single-use-tid model as `query_logs`). Previously, if a slice — or the new whole-window total-count, most likely on large 7/30-day windows — returned incomplete on the first fetch, the next poll hit a reaped tid and failed that policy with `policy_query_failed`. Re-issues are bounded by the existing wall-clock timeout.

### Added
- **Reusable pagination handle + richer `query_logs` output.** `query_logs` returns `tid` (a reusable pagination handle), `has_more`, `next_offset`, `total`, `total_is_known`, `warnings`, `timezone`, `time_basis`, the resolved `time_range`, and echoes `adom`/`logtype`/`filter`/`device`/`offset`/`limit` for auditability. `fetch_more_logs` returns the same self-describing shape.
- **Automatic reconnect-once.** Log tools call `FortiAnalyzerClient.ensure_connected()` before issuing requests, so an idle-closed session is transparently revived instead of surfacing a raw "Not connected. Call connect() first." error.
- **Bounded transient retry.** Client requests retry transient FAZ/network errors (internal error, task timeout, network) with exponential backoff; validation and invalid-tid errors are never retried.
- **`cancel_log_search`** now releases the in-process pagination handle (the appliance task is usually already reaped, so the appliance-side cancel is best-effort).
- **One structured error envelope.** Every tool error path returns `{status:"error", error:<machine code>, message, operation, retry_count}` (plus `adom`/`logtype`/`tid` where relevant). Codes: `validation_error`, `invalid_time_range`, `invalid_tid`, `tid_invalid_or_expired`, `search_timeout`, `network_error`, `faz_operation_failed`; `retry_count` is the number of transient request retries the client performed.
- **`warnings` + `next_offset` on log queries.** `query_logs`/`fetch_more_logs` include a `warnings` list (clamped `limit`, unknown `total`, undetected timezone, or a high-volume result set that points to the bounded policy tools) and a `next_offset` to drive the next page.
- **Policy-tool audit metadata.** `get_policy_traffic_profile`/`get_policy_port_analysis`/`get_policy_protocol_summary` now return top-level `adom`, resolved `time_range`, and `timezone`, plus a per-policy `filter`; the analysis window is resolved once and shared by the bounded slices and the whole-window total-count query.
- **Authoritative policy `total_hits`.** The three policy tools now report `total_hits` from a whole-window FortiAnalyzer log-search `total-count` for the same policy/action/device/time filter, with `total_hits_is_known` and `total_hit_source` (`"logsearch_total-count"` when authoritative, `"observed_rows"` when it fell back to fetched rows). The port/protocol/service/application breakdowns and residuals still describe observed rows only. The total-count is best-effort: if it fails, the per-policy observations are still returned with `total_hit_source="observed_rows"`.
- **Custom time-range validation.** A custom `"start|end"` range is validated for `YYYY-MM-DD HH:MM:SS` format and `start <= end`, returning a clear `invalid_time_range` error instead of failing deep in slicing.

### Changed
- A completed logsearch task discovered reaped mid-poll is re-issued (bounded) so a slow search that finishes between polls still returns its results instead of failing.
- Response fields were finalized before release: `total_known` → `total_is_known`, `returned_offset`/`returned_limit` → `offset`/`limit`, and the error key `error_type` → `error` (a stable machine code). These only ever existed in pre-release builds.
- **Policy `estimated_total_hits`/`estimate_available` removed.** The optional best-effort FortiView `policy-hits` estimate (shipped through 1.3.0) is replaced by the authoritative whole-window `total_hits` above. Consumers that read `estimated_total_hits`/`estimate_available` should switch to `total_hits` + `total_hits_is_known` + `total_hit_source`.
- **`is_exact`/`analysis_mode` honest about partial breakdowns.** A policy result is `is_exact=true`/`"complete"` only when no slice was truncated **and** `total_hits == observed_hits`; when the authoritative total exceeds the observed rows the result is `"bounded_sample"` with the narrow-the-window recommendation, so a partial breakdown is never labelled complete.

### Security
- **Secret redaction in errors and logs.** Tool error messages and the logged search filter pass through a redaction-then-truncation helper, so tokens/session ids are masked and oversized internal errors are bounded before reaching a response or log. The raw `filter=` argument on `query_logs` is documented as a caller-controlled expert escape hatch (the `search_*` helpers remain validated/sanitized).

## [1.3.0] - 2026-05-29

First stable release — graduated from beta.

### Security
- **Log-query filter injection fixed** ([#16](https://github.com/rstierli/fortianalyzer-mcp/issues/16)): caller-supplied filter fields in the IPS/PCAP and traffic/security/event log search tools (`srcip`, `dstip`, `srcport`, `dstport`, `severity`, `action`, `level`, `subtype`, `cve`, `attack_name`, `session_id`) are now validated/sanitized before being interpolated into FAZ filter expressions. IPs are checked as IP/CIDR, ports as integers, enums against allowlists, and free-text fields reject quote/operator/boolean characters — preventing a caller from rewriting the filter to widen log scope. Filter operators and quoting are unchanged, so legitimate queries behave identically.
- **PCAP-by-URL validation** ([#16](https://github.com/rstierli/fortianalyzer-mcp/issues/16)): `download_pcap_by_url` / `get_pcap_file` now validate that `pcapurl` is an internal FAZ resource reference and reject arbitrary external URL schemes before forwarding to FortiAnalyzer.
- **Archive-extraction path containment** ([#16](https://github.com/rstierli/fortianalyzer-mcp/issues/16)): PCAP and report ZIP extraction now asserts each resolved path stays within the intended output directory (defense-in-depth on top of the existing basename handling).

### Changed
- **Stability promotion:** no functional changes beyond the security hardening above. Shipped example configs (`docker-compose.yml`, `.env.example`) and README now default to `FORTIANALYZER_VERIFY_SSL=true` with CA-import guidance, document a strong `MCP_AUTH_TOKEN` for HTTP mode, and warn that running HTTP transport without a token leaves all tools unauthenticated. The server's runtime defaults are unchanged (backward compatible).

## [1.2.1-beta] - 2026-05-17

### Fixed
- **Relative time-range queries no longer silently miss logs when client and FAZ have different system timezones** ([#13](https://github.com/rstierli/fortianalyzer-mcp/issues/13)). FAZ accepts naive `YYYY-MM-DD HH:MM:SS` timestamps and interprets them in its own system TZ. The MCP previously called `datetime.now()` (caller-local) and formatted naive, so when client and FAZ disagreed by N hours every relative window smaller than N silently returned zero logs. Discovered with a fresh FAZ 8.0.0 GA defaulting to US/Pacific while the client lived in CEST — `search_traffic_logs(time_range="1-hour")` was searching a window 9 hours in the future. The MCP now reads FAZ's IANA TZ from `get_system_status`, caches it on the client, and computes "now" in UTC → FAZ-local before formatting. Custom absolute ranges (`"start|end"`) skip the TZ lookup.
- **Unknown `time_range` keys now raise `ValueError` instead of silently falling back to 1-hour or 24-hour.** Typos like `"30-min"` or `"5-min"` no longer produce wrong-but-plausible windows.

### Added
- **More relative-range presets supported uniformly across all tools:** `now / 5-min / 15-min / 30-min / 1-hour / 2-hour / 6-hour / 12-hour / 24-hour / 1-day / 2-day / 7-day / 30-day / 90-day`. Previously each of the 8 tool files supported a slightly different subset.
- **FortiAnalyzer 8.0.x support** — tested against 8.0.0 GA (build 0105).
- **`FortiAnalyzerClient.get_system_timezone()`** — public async method that returns the cached FAZ IANA timezone as a `zoneinfo.ZoneInfo`.

### Changed
- **Consolidated 8 duplicate `_parse_time_range` implementations** into a single `utils/time_range.py` (single source of truth). Each tool now uses a thin async wrapper that delegates to the shared utility with the FAZ-cached TZ.

## [1.2.0-beta] - 2026-04-24

### Changed
- **Policy traffic analysis is now bounded for large windows** — traffic analysis tools scan a fixed number of log slices per request, return observed results instead of attempting unbounded raw-log reconstruction, and only set `is_exact=true` when every queried slice is below the log fetch limit
- **Port analysis metadata expanded** — policy results now include bounded-analysis metadata such as `analysis_mode`, `observed_hits`, `slices_scanned`, `truncated_slices`, `log_limit_per_slice`, and optional FortiView `estimated_total_hits`
- **`is_exact` ownership moved to `_bounded_metadata`** — `_aggregate_port_analysis` no longer computes `is_exact`; the caller sets it based on slice truncation, which is more accurate for multi-slice queries
- **FortiView estimates run concurrently** with bounded log queries instead of sequentially, reducing wall-clock time on slow FortiAnalyzer instances

### Added
- Best-effort FortiView `policy-hits` estimates as optional metadata (non-fatal if unavailable)
- Tests for `_extract_policy_hit_count` edge cases
- Tool-level bounded tests for `get_policy_traffic_profile` and `get_policy_protocol_summary`

### Credits
- Bounded slicing approach contributed by [@inxbit](https://github.com/inxbit) (PR [#11](https://github.com/rstierli/fortianalyzer-mcp/pull/11))

## [1.1.2-beta] - 2026-04-23

### Fixed
- **`is_exact` in port analysis** — `_aggregate_port_analysis` now correctly computes `is_exact` based on whether the log query hit the result limit, instead of always returning `True`

### Added
- **Usage disclaimer** in README for independent community project notice

## [1.1.1-beta] - 2026-04-15

### Added
- **Policy Traffic Analysis Tools** (3 tools) - Analyze traffic patterns per firewall policy for policy hardening
  - `get_policy_traffic_profile`: Sampled traffic summary with top ports, services, and applications
  - `get_policy_port_analysis`: Port/protocol enumeration with `is_exact` semantics
  - `get_policy_protocol_summary`: Lightweight protocol breakdown (TCP/UDP/ICMP/other)
- Input validation for filter values (`sanitize_filter_value`) and action parameters (`validate_action`)
- Concurrent policy query support with semaphore-bounded parallelism (`asyncio.Semaphore(5)`)

### Fixed
- **ICMP type/code parsing** — `_aggregate_port_analysis` now reads ICMP info from the FAZ `service` field (`PING`, `icmp/T/C`) instead of non-existent `icmptype`/`icmpcode` fields

### Changed
- Total tools increased from 74 to 77 (3 new traffic analysis tools)

## [0.4.0-beta] - 2026-01-17

### Added
- **Unit tests expanded** - 157 tests covering errors, validation, and tool modules
- **Version detection** - `_detect_version()` method and `faz_version` property for FortiAnalyzer version awareness
- **FortiView improvements** - Default to `All_Devices` device filter, case-sensitive parameter support

### Fixed
- FortiView API now defaults to All_Devices when no device specified
- Import sorting in test files (ruff compliance)
- E402 linting errors for post-dotenv imports

### Technical
- All CI checks passing
- Integration tests verified against FortiAnalyzer 7.6.2
- Total tools: 74 (unchanged)

## [0.3.0-beta] - 2025-12-22

### Added
- **FortiAnalyzer 7.6.5 Support**
- **API Rate Limiting Tools** (2 tools) - Configure API rate limits to protect FortiAnalyzer from API abuse
  - `get_api_ratelimit`: Get current API rate limiting configuration (read/write limits per second)
  - `update_api_ratelimit`: Update API rate limits (requires FAZ 7.6.5+)

### Changed
- Total tools increased from 72 to 74 (2 new API rate limiting tools)
- Updated API specifications to FortiAnalyzer 7.6.5

### Developer Tools
- Added `tools/compare_api_versions.py` - Compare FortiAnalyzer API documentation between versions
  - Detects new/removed endpoints, definitions, and tags
  - Generates markdown reports for easy review
  - Helps contributors identify required code changes

### FortiAnalyzer 7.6.5 API Changes (Not Yet Implemented)
The following new 7.6.5 features are available in the FortiAnalyzer API but not yet exposed as MCP tools.
Contributions welcome:

- **TACACS+ Accounting** (6 endpoints) - Configure TACACS+ accounting log filtering
  - `/cli/global/system/locallog/tacacs+accounting/filter`
  - `/cli/global/system/locallog/tacacs+accounting/setting`

- **Client Certificate Authentication** (11 endpoints) - Configure client certificate auth for API access
  - `/cli/global/system/log/settings/client-cert-auth`
  - `/cli/global/system/log/settings/client-cert-auth/trusted-client`

## [0.2.0-beta] - 2025-12-11

### Added
- **PCAP Tools** (5 tools) - IPS log search and PCAP download for forensic analysis
  - `search_ips_logs`: Search IPS/attack logs with advanced filtering (severity, attack name, CVE, IPs, action)
  - `get_pcap_by_session`: Download PCAP file for a specific session ID
  - `download_pcap_by_url`: Download PCAP using pcapurl from search results
  - `search_and_download_pcaps`: Search and automatically download all matching PCAPs
  - `list_available_pcaps`: List IPS events that have PCAP files available

### Security Improvements
- Log sanitization for debug output - sensitive fields (passwords, tokens, sessions) now masked
- Input validation for ADOM and device names
- Report output directory restriction with `FAZ_ALLOWED_OUTPUT_DIRS` environment variable
- ZIP extraction size limits (100MB per file, 500MB total) to prevent ZIP bomb attacks

### Changed
- Total tools increased from 67 to 72 (5 new PCAP tools)

## [0.1.0-beta] - 2025-12-04

### Added
- Initial release with 67 MCP tools
- **System Tools** (9 tools)
  - `get_system_status`, `get_ha_status`
  - `list_adoms`, `get_adom`
  - `list_devices`, `get_device`
  - `list_tasks`, `get_task`, `wait_for_task`
- **Device Management Tools** (8 tools)
  - `list_device_groups`, `list_device_vdoms`
  - `add_device`, `delete_device`
  - `add_devices_bulk`, `delete_devices_bulk`
  - `get_device_info`, `search_devices`
- **Log Tools** (12 tools)
  - `query_logs`, `get_log_search_progress`, `fetch_more_logs`, `cancel_log_search`
  - `get_log_stats`, `get_log_fields`
  - `search_traffic_logs`, `search_security_logs`, `search_event_logs`
  - `get_logfiles_state`, `get_pcap_file`
- **Report Tools** (8 tools)
  - `list_report_layouts`, `run_report`, `fetch_report`
  - `get_report_data`, `get_running_reports`, `get_report_history`
  - `run_and_wait_report`, `save_report`
- **FortiView Analytics Tools** (10 tools)
  - `run_fortiview`, `fetch_fortiview`, `get_fortiview_data`
  - `get_top_sources`, `get_top_destinations`, `get_top_applications`
  - `get_top_threats`, `get_top_websites`, `get_top_cloud_applications`
  - `get_policy_hits`
- **Event/Alert Tools** (8 tools)
  - `get_alerts`, `get_alert_count`
  - `acknowledge_alerts`, `unacknowledge_alerts`
  - `get_alert_logs`, `get_alert_details`, `add_alert_comment`
  - `get_alert_incident_stats`
- **Incident Management Tools** (6 tools)
  - `get_incidents`, `get_incident`, `get_incident_count`
  - `create_incident`, `update_incident`, `get_incident_stats`
- **IOC Tools** (6 tools)
  - `get_ioc_license_state`, `acknowledge_ioc_events`
  - `run_ioc_rescan`, `get_ioc_rescan_status`, `get_ioc_rescan_history`
  - `run_and_wait_ioc_rescan`

### Features
- Support for FortiAnalyzer 7.0.x, 7.2.x, 7.4.x, 7.6.x
- API Token authentication (recommended) and username/password support
- Full mode (all tools loaded) and Dynamic mode (discovery tools only)
- Docker deployment support
- Claude Desktop integration via stdio transport
- Comprehensive debug logging (configurable)
- Report generation with automatic schedule creation
- Report download with ZIP extraction (PDF, HTML, CSV, XML formats)

### Technical
- Built on FastMCP framework
- Uses pyfmg library for FortiAnalyzer JSON-RPC communication
- Async/await throughout for efficient resource utilization
- Type hints with Pydantic validation
- Comprehensive error handling with FortiAnalyzer-specific error codes

### Fixed
- Report API now correctly uses `schedule` parameter (string layout-id)
- Empty API responses handled gracefully (no more "Unexpected response format" errors)
- Report polling logic handles empty running reports list

## [0.0.1] - 2025-12-03

### Added
- Initial project structure
- Basic API client implementation
- Core tool modules
