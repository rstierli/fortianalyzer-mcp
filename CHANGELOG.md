# Changelog

All notable changes to FortiAnalyzer MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
