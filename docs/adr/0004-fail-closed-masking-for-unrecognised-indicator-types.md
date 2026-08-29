# Fail closed on a SOAR indicator `value` whose `type` names no class the masker can mint

**Status:** accepted

## Context

`_mask_indicator_pair` types a SOAR indicator's `value` from its sibling `type`: `IP`/`Domain`/`URL` mint
a reversible token, anything else historically passed `value` through clear. That was measured live
against a licensed estate as reachable rather than theoretical — the appliance accepts `indicator-type`
values (e.g. `Mac`) outside its own documented FNDN enum, so "unrecognised type" is not a closed set we
can enumerate our way out of. Two call sites depended on the pass-through: a verbatim `record` echoed
from `get_indicator_enrichment`/`get_linked_indicators` (#130), and the `enrichment_uuid` detail path,
whose rows carry no `type` sibling at all (#133).

The obvious fix — placeholder any `value` with no recognised type — is too broad: `_mask_indicator_pair`
runs on every dict a composite handler hasn't already consumed, not only on indicator rows. Applied
unscoped, it also placeholders the groupby/breakdown bucket shape (`{"value": ..., "hits": N}`) and the
generic `{"value": "high", "type": "string"}` case, reversing deliberate #109/#124 passthrough decisions
(measured: 19 failures, 15 of them collateral damage on that surface).

## Decision

Fail closed only on a record that *proves itself* an indicator row: either it carries one of five
siblings that only an indicator row has (`indicator-uuid`, `enrichment-uuid`, `enrichment-reputation`,
`enrichment-confidence`, `enrichment-status`), or it sits under the `enrichment-detail` key (threaded via
a `ContextVar`, since `enrichment_uuid` detail rows carry no proving sibling of their own — this is what
closes #133). A proven row with an unrecognised or missing `type` now masks to a placeholder instead of
riding out clear; an unproven row (bucket, severity band, or a bare `{"record": {...}}` with no sibling)
still passes through unchanged.

`Hash` is a deliberate exception, kept readable per #129: it identifies a file, and a tokenised digest
matches nothing in threat intel, so masking it destroys utility for no safety gain. This ruling is about
types riding through *unrecognised*, not about reopening a type already chosen. (The type string is
appliance-controlled, so a row could claim `Hash` to stay readable — inherent to #129's mechanism, not
new here.)

The placeholder is recorded into the substitution mapping via `setdefault` (a reversible token minted
for the same value elsewhere keeps precedence), because the skills layer puts a skipped indicator's raw
value into `warnings` whenever the row has no `indicator-uuid` — exactly the case a proven-but-unrecognised
row hits. Without recording it, the placeholder appears under `value` while the same identifier rides out
in clear two keys away.

## Consequences

**Accepted residual, not a gap:** a live row with neither a recognised `type` nor any proving sibling
still passes through in clear on the list path (e.g. the issue's own bare `{"record": {...}}` shapes).
Closing it would mean reinstating the bucket-surface collateral damage above, to cover a shape with no
live capture. Pinned by a dedicated test so it reads as a decision rather than an oversight.

**Not live-verified:** the `enrichment-detail` enclosing-key arm that closes #133 is inferred from this
repo's fixtures, not measured against a live `enrichment_uuid` response — SOAR detail-endpoint access
wasn't available to confirm it. Accepted without further live verification; revisit if a live capture
ever contradicts the fixture shape.

Implemented in `masking/wrapper.py` (`_mask_indicator_pair`, `_indicator_row_is_proven`), landed via #136
on top of #131's handler-side gating (`matched = rows[0]` only attaches a recognised-type row; the skip
warning names the type, not the raw value).
