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

**Live-verified (2026-09-01):** the `enrichment-detail` enclosing-key arm that closes #133 was measured
against a real `enrichment_uuid` response from a licensed SOAR estate (`detail_level="extended"`, a
`Malicious`-reputation Domain indicator). The identifying value and the URL that embeds it both came back
as `masked-unrepresentable-...` — the fix holds on the live shape, not only the fixture. The live shape is
considerably richer than the fixture (`tests/test_soar_tools.py`'s `{"source": "vt", "value": "..."}`
undersells it — see #144), which surfaced a related-but-distinct gap: the same enclosing-key mechanism
also burns descriptive threat-intel classification fields (category, confidence, kill-chain phase,
timestamps) that carry no identifying risk. That over-masking question is tracked separately in #144
rather than folded into this ADR, since it's a scoping call on a live-estate-of-one sample, not a
reopening of the fail-closed decision itself.

Implemented in `masking/wrapper.py` (`_mask_indicator_pair`, `_indicator_row_is_proven`), landed via #136
on top of #131's handler-side gating (`matched = rows[0]` only attaches a recognised-type row; the skip
warning names the type, not the raw value).
