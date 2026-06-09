# Report the first-page Baseline total as a Pagination handle's `total`

**Status:** accepted

## Context

`fetch_more_logs` pages a `query_logs` result by reconstructing and **re-running** the search at a new
offset against the same frozen window (absolute `start`/`end` timestamps captured at page-0 time, using
the single-use-tid poll-before-fetch search model). FortiAnalyzer's `total-count` is authoritative
only for one completed search/page; across the independent re-run searches it can change as rows are
indexed into the fixed window after page 0. Observed live on 7.6.7: page 0 unfiltered 1-hour traffic
reported `total-count` 230071, page 1 of the same handle reported 230741.

Until now the MCP echoed each page's raw `total-count` as the response `total`, so the headline match
count wobbled between pages of one pagination session. That is a response-contract problem (which
number is "the total" for this handle?), not a row-paging failure: the window bounds are fixed and
offsets are stable.

## Decision

For a Pagination handle, the **first page's whole-window total-count is the Baseline total**, and the
MCP reports it as `total` for every page of that handle. The raw per-page `total-count` is exposed
separately as `page_total`, alongside `initial_total`, `total_count_stability`
(`single_observation` | `stable` | `drifted` | `unknown`), `total_drift_detected`, `total_delta`
(`page_total - initial_total` when both known), and `has_more_basis` — which figure `has_more` was
computed against, one of `stable_total` | `best_effort_max_observed_total` | `best_effort_page_total` |
`full_page_heuristic`.

`total` and the `has_more` paging figure are deliberately decoupled (favor completeness without
wobbling `total`):
- Drift (both totals known, differ): `total` = baseline; `has_more` paged against
  `max(initial_total, page_total)`; a warning states the broad total is non-exact and row offsets may
  also shift. A downward-drift trailing empty page self-terminates via the `count == 0` guard.
- Known baseline, this page omits `total-count`: `total` = baseline; paged against the baseline
  (`stable_total`); `stability="unknown"` (the two fields answer different questions and may differ).
- **No baseline** (page 0 had no `total-count`): `total` stays **`None`** for the whole handle — a
  baseline-less handle never promotes a later page's count into `total`. `has_more` is still paged
  against that page's own `page_total` when known (`best_effort_page_total`) so a short page does not
  stop pagination early; only with no count at all does it fall back to the full-page heuristic.

A handle is **bound to the ADOM** `query_logs` ran under: `fetch_more_logs` rejects a differing `adom`
(`adom_mismatch`) because a cross-ADOM baseline/page comparison is meaningless.

The registry stores only `initial_total`; `fetch_more_logs` is read-only on the handle context (no
observation history, no write-back) so concurrent pages on one handle cannot race. The consequence is
that `has_more` completeness is **best-effort, not guaranteed**: `max()` compares only the baseline vs
the current page, so non-monotonic drift (high→low→high) can under/over-page by a bounded amount. We
accept this over reintroducing registry mutation; the `best_effort_*` basis labels and the drift
warning make the non-exactness explicit. A persisted running max is the documented escape hatch if a
workload ever needs guaranteed completeness under non-monotonic drift.

## Consequences

- `total` is stable and auditable per handle; consumers comparing `total` across pages no longer see
  it wobble. The live per-page figure is still available as `page_total`.
- The meaning of `total` on page ≥ 1 changes from "this page's live count" to "page-0 baseline". This
  is a public response-contract change; verified safe internally (no caller reads
  `fetch_more_logs["total"]` — traffic uses its own `total_hits`, PCAP its own page total).
- We do **not** attempt a FortiAnalyzer-side immutable snapshot (the API does not offer one) and do
  **not** attempt row-level snapshot consistency (dedup/stable-sort). Broad drifting windows remain
  non-snapshot-consistent by design; for exact investigations use narrow filters and fixed absolute
  windows away from "now" rather than deep offset paging through a live high-volume window.
- `total_count_stability` and `has_more_basis` answer different questions and may legitimately differ
  (e.g. a later page omitting `total-count` is `stability="unknown"` while `has_more_basis` stays
  `stable_total` because the baseline is still available).
