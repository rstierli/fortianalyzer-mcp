"""Tool-argument unmasking (RFC #40 Phase 2 prototype).

When the model sends a token back as a tool argument, the real value must
be restored *before* input validators and the FAZ API see it: a masked
token would otherwise be rejected by ``validate_ip_or_cidr`` and friends,
or would query FAZ for a value that does not exist there.

Three resolution paths, in order of confidence:

1. **Marked tokens, anywhere.** ``host-``/``user-`` prefixes and the
   ``.<mask_suffix>`` domain/email forms are self-identifying, so they are
   resolved wherever they appear: a bare string argument, an item in a
   list, a value nested in a dict, or a substring inside a filter
   expression.
2. **Unmarked tokens by argument name.** Masked IPs and MACs look like
   ordinary IPs and MACs (the "IP wrinkle"), so they can only be resolved
   where the *name* says what the value is: an argument called ``srcip``
   or a filter clause ``srcip=="..."``. The name table is the same
   allowlist used for output masking.
3. **Everything else passes through untouched.**

Failure policy mirrors the output side but inverts the default: if a
value carries a marker and does not decrypt, that is an error worth
surfacing (the caller sent a corrupted or foreign token) and the argument
is left as-is so the validator downstream rejects it loudly. If an
unmarked value in an IP/MAC-named field does not decrypt to anything
sensible, it is passed through unchanged: it is far more likely to be a
real address the user typed than a corrupted token, and passing a real
address through is correct behavior.

Known ambiguities, documented rather than papered over:

- With masking on, a user who types a *real* IP into ``srcip`` gets it
  unmasked as if it were a token, producing a different real IP.
  Deterministic FPE has no way to distinguish the two. Deployments that
  expect operators to paste raw IPs should keep masking off, or the prose
  companion should mask what the operator types on the way in.
- Hostname case is lost at *mask* time, because the hostname alphabet is
  lowercase. ``FGT-BRANCH-01`` round trips to ``fgt-branch-01``. Harmless
  for DNS names, which are case insensitive; it matters for device names
  that are not.
- A fortiview ``devvds`` value masks to ``"<token>[<vdom>]"``. Fed back as
  an argument it will not decrypt as a whole, so it passes through and the
  tool's validator rejects it. That is deliberate: a device argument wants
  a device name, and silently discarding the vdom half to salvage one
  would be guessing at what the caller meant.
"""

import logging
import re
from typing import Any

from fortianalyzer_mcp.masking.fields import FIELD_TYPES, IP, IP_OR_HOST, MAC, SKIP_VALUES
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine, MaskingError

logger = logging.getLogger(__name__)

# field==value / field!=value / field contain value, single or double quoted
_FILTER_CLAUSE_RE = re.compile(
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?P<op>==|!=|<=|>=|=~|<|>|\bcontain\b|\b!contain\b)\s*"
    r"(?P<quote>[\"']?)(?P<value>[^\"'\s()]+)(?P=quote)"
)


class ArgUnmasker:
    """Resolve masked tokens in tool arguments back to real values."""

    def __init__(self, engine: FPEEngine) -> None:
        self._engine = engine

    # -- scalar resolution ------------------------------------------------ #

    def _unmask_marked(self, value: str) -> str | None:
        """Resolve a self-identifying token, or None if it carries no marker.

        Raises MaskingError only through :meth:`resolve_scalar`, which
        decides what a bad payload means for the caller.
        """
        return self._engine.unmask_token(value)

    def _unmask_by_type(self, vtype: str, value: str) -> str:
        """Resolve an unmarked IP/MAC token; pass through on failure.

        ``IP_OR_HOST`` fields only reach here when the value carries no
        ``host-`` marker, so whatever is left must be an address.
        """
        try:
            if vtype in (IP, IP_OR_HOST):
                return self._engine.unmask_ip(value)
            if vtype == MAC:
                return self._engine.unmask_mac(value)
        except MaskingError:
            # Very likely a real address the operator typed, not a token.
            return value
        return value

    def resolve_scalar(self, value: str, vtype: str | None = None) -> str:
        """Resolve one argument value. ``vtype`` comes from the field name."""
        if not value or value.strip() in SKIP_VALUES:
            return value
        candidate = value.strip()
        try:
            marked = self._unmask_marked(candidate)
        except MaskingError:
            # Marker present but payload will not decrypt: leave it alone so
            # the downstream validator rejects it instead of us guessing.
            logger.warning("argument carries a masking marker but does not decrypt; passed through")
            return value
        if marked is not None:
            return marked
        if vtype in (IP, MAC, IP_OR_HOST):
            return self._unmask_by_type(vtype, candidate)
        return value

    # -- filter expressions ------------------------------------------------ #

    def unmask_filter(self, expression: str) -> str:
        """Resolve tokens inside a FAZ filter expression.

        ``srcip=="93.209.148.131" and user=="user-3f2a-k9x2q4"`` becomes the
        expression over real values. Field names drive IP/MAC resolution;
        marked tokens resolve regardless of the field they sit in.
        """

        def clause_sub(match: re.Match[str]) -> str:
            field = match.group("field")
            raw = match.group("value")
            vtype = FIELD_TYPES.get(field.lower())
            resolved = self.resolve_scalar(raw, vtype)
            if resolved == raw:
                return match.group(0)
            return match.group(0).replace(raw, resolved)

        return _FILTER_CLAUSE_RE.sub(clause_sub, expression)

    # -- recursive argument walk ------------------------------------------- #

    def unmask_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Resolve tokens across a tool's keyword arguments, at any depth."""
        return {key: self._unmask_entry(key, value) for key, value in args.items()}

    def _unmask_entry(self, key: str, value: Any) -> Any:
        lowered = key.lower()
        if isinstance(value, str):
            if lowered in ("filter", "filter_applied"):
                return self.unmask_filter(value)
            vtype = FIELD_TYPES.get(lowered)
            if vtype in (IP, MAC, IP_OR_HOST):
                # comma-joined multi-values, same convention as the output side
                if "," in value:
                    return ",".join(self.resolve_scalar(part, vtype) for part in value.split(","))
                return self.resolve_scalar(value, vtype)
            return self.resolve_scalar(value)
        if isinstance(value, list):
            return [
                self._unmask_entry(key, item) if isinstance(item, str) else self._unmask_any(item)
                for item in value
            ]
        if isinstance(value, dict):
            # e.g. the #44 dispatcher's nested "params" object
            return self.unmask_args(value)
        return value

    def _unmask_any(self, value: Any) -> Any:
        if isinstance(value, dict):
            return self.unmask_args(value)
        if isinstance(value, list):
            return [self._unmask_any(item) for item in value]
        if isinstance(value, str):
            return self.resolve_scalar(value)
        return value
