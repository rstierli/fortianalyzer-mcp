# Spec: the device-identity keep set ignores list-valued keys

FROZEN SPEC. Implement exactly. If a step is impossible as written, implement the closest
faithful version and report the deviation. Do not redesign. Do not widen scope.

## Background you need

`src/fortianalyzer_mcp/masking/wrapper.py` has `OutputMasker._device_identity_values(obj)`. It
walks a tool response and collects every device-identity value into a frozenset called `keep`.
It runs only when `FAZ_MASK_DEVICE_IDENTITY` is OFF, which is the default.

Its own docstring states the invariant it exists to hold:

    With FAZ_MASK_DEVICE_IDENTITY off these stay readable by design, so any handler that can
    reach the same value under another key (live 8.0.0 alerts carry the reporting appliance's
    serial in target[].value) must leave it clear too. Masking it in one place while devid
    shows it two keys away is not privacy, it is a token-to-serial correlation gift.

`keep` is consulted by `_burn_strings` and `_mask_target`, so a value in `keep` stays clear
inside a `target` entry instead of being masked or burned.

## The defect

The collector only handles STRING values:

    if key.lower() in DEVICE_IDENTITY_TYPES and isinstance(value, str):
        out.update(part.strip() for part in value.split(","))

`devs` is a DEVICE_IDENTITY_TYPES key whose live value is a LIST of device names (it appears on
an eventmgmt alert's `subject_details` as `{alertid, devs, epids, euids}`). A list fails the
`isinstance(value, str)` test, falls through to the `else: walk(value)` branch, and its elements
are then visited with no device key in scope, so nothing is collected.

Result, with the flag OFF and a device named ONLY under `devs`: the name stays clear under
`devs` itself, but the SAME name inside a `target` entry gets masked to a token. That is exactly
the token-to-name inconsistency the keep set exists to prevent.

Reproduced on current main (RFC placeholders, key `"0"*64`):

    payload {"devs": ["fgt-branch-01"], "target": [{"name": "device", "value": "fgt-branch-01"}]}
    _device_identity_values(payload)  ->  frozenset()          # empty; should hold the name
    masked target value               ->  a host- token         # should stay clear

Compare the string-valued sibling, which is correct today:

    payload {"devname": "fgt-branch-01", "target": [{"name": "device", "value": "fgt-branch-01"}]}
    _device_identity_values(payload)  ->  {"fgt-branch-01"}
    masked target value               ->  fgt-branch-01         # clear, correct

## What to implement

In `_device_identity_values`, make a DEVICE_IDENTITY_TYPES key whose value is a list or tuple
contribute each of its STRING elements to the keep set, applying the same comma-splitting and
`.strip()` already applied to a string value.

Constraints:
- Change ONLY `_device_identity_values`. Do not touch fields.py, do not touch `_burn_strings`,
  `_mask_target`, or any other method.
- Non-string, non-list values under a device key must keep behaving as they do now.
- Nested containers under a device key (a list of lists, a dict) must not crash. Collect string
  elements where the shape is a flat list or tuple; anything else may be ignored, but must not
  raise.
- The existing COMPOSITE_DEVICE_VDOM branch must keep working unchanged.
- Match the surrounding style. The file uses `isinstance(x, list | tuple)` elsewhere.
- Keep the docstring accurate: add one sentence noting that a device key may be list-valued.

## Tests to add

In `tests/test_masking_leak.py`, next to the existing device-identity tests. Use the module's
existing constants (`DEV_NAME`, `DEV_PEER`, `KEY`) and the existing `masker` fixture, which has
the device flag OFF.

1. A device named only under `devs` stays clear inside a `target` entry with `name: "device"`.
2. The same, for a `target` entry under an UNKNOWN name (the burn path): it stays clear rather
   than becoming a `masked-unrepresentable-` placeholder.
3. `devs` carrying TWO device names keeps both clear.
4. A device name under `devs` that does NOT appear in `target` is unaffected (no behaviour
   change for the ordinary case).
5. A regression guard: a NON-device string in the same response is still masked normally, so the
   change did not widen the keep set beyond device keys.
6. With the device flag ON (`full_masker` fixture), `devs` still masks as before. The keep set is
   not built at all in that mode, so this must be unchanged.

## Proof

Run and include full output:

    cd /tmp/wtkeep && FORTIANALYZER_HOST=faz.example.test PYTHONPATH=/tmp/wtkeep/src \
      UV_PROJECT_ENVIRONMENT=/tmp/venv75 uv run --no-sync -p 3.12 \
      pytest tests/ --ignore=tests/integration -q -p no:cacheprovider

Also run `ruff check src/ tests/` and `ruff format --check src/ tests/` with the same prefix and
report both. The suite must be green and lint clean. Baseline before your change is 1123 passed.

## Out of scope

Do not add or retype any key in fields.py. Do not change masking behaviour when the flag is ON.
Do not touch the unmask path. Do not commit anything; I will review the diff and commit.
