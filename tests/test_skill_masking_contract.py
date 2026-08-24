"""Masking contract for the skills layer (#44).

The RFC's position is that skills are tools, so their outputs flow through
masking automatically. That is true and it is not sufficient. Masking is a
flat allowlist keyed on FIELD NAME, and a skill is the one place in this
server that **invents** field names: it composes several appliance
vocabularies into one record and labels the result with names of its own
(``entity``, ``record``, ``indicators``, ``subject``). A name the skill
invents is a name no vocabulary taught the allowlist.

Two live examples of why that matters, both measured while writing this:

- ``risk_assessment`` emits ``entity`` as ``{"type", "epid"|"euid",
  "record"}``. That is safe today because ``epid``/``euid`` are internal
  numeric join keys the #80 audit deliberately left clear, and ``record``
  recurses into an audited vocabulary. Relabel either one and it stops being
  safe, silently.
- ``hunt`` and ``risk_assessment`` both carry a **verbatim** sub-record. The
  contract they publish is passthrough, so whatever the appliance adds to that
  vocabulary next arrives here unaudited.

These tests do not assert that a leak exists. They pin the conditions that
currently make composition safe, so that changing one fails loudly rather
than quietly.
"""

from typing import Any

import pytest
from pydantic import BaseModel

from fortianalyzer_mcp.masking import fields as masking_fields
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.wrapper import OutputMasker
from fortianalyzer_mcp.skills.catalog import SKILLS

KEY = "0" * 32


def _iter(value: Any) -> tuple[Any, ...]:
    try:
        return tuple(value)
    except TypeError:
        return ()


#: Every name the masking layer can type, flattened the way a lookup sees it.
KNOWN_NAMES: set[str] = (
    {k.lower() for k in masking_fields.FIELD_TYPES}
    | {k.lower() for k in getattr(masking_fields, "DEVICE_IDENTITY_TYPES", {})}
    | {
        str(entry).lower()
        for attr in dir(masking_fields)
        if attr.startswith("COMPOSITE_")
        for entry in _iter(getattr(masking_fields, attr))
    }
)


def _string_fields(model: type[BaseModel]) -> set[str]:
    """Field names anywhere in this model tree that can hold a bare string."""
    found: set[str] = set()
    seen: set[type[BaseModel]] = set()

    def walk(current: type[BaseModel]) -> None:
        if current in seen:
            return
        seen.add(current)
        for name, field in current.model_fields.items():
            annotation = field.annotation
            parts = list(getattr(annotation, "__args__", ()) or ()) + [annotation]
            if any(part is str for part in parts):
                found.add(name)
            for part in parts:
                if isinstance(part, type) and issubclass(part, BaseModel):
                    walk(part)

    walk(model)
    return found


#: Names a skill emits that hold a string but are deliberately NOT identifiers:
#: enums, labels, human prose about the finding, and internal row ids the #80
#: audit cleared by measurement. Adding a name here is a decision that it
#: cannot carry an identifier; the test below is what forces that decision to
#: be made rather than defaulted into.
NON_IDENTIFIER_STRINGS = {
    # verdict / classification enums
    "verdict",
    "reputation",
    "confidence",
    "severity",
    "status",
    "band",
    "importance",
    "anomalous",
    "available",
    "acknowledged",
    "fetched",
    "entity_type",
    "handler_class",
    "detail_level",
    "logtype",
    "type",
    "action",
    "tier",
    "id",
    "skill",
    # human prose explaining a finding, not naming one.
    #
    # NOTE what is deliberately ABSENT: description, message, reason, warnings
    # and entity_ref were here and have been removed, because masking types
    # them TEXT. They are safe because they are SCANNED, not because they are
    # inert, and listing them made a covered field look like an exempt one.
    # Worse, it was a hole in this guard: dropping "reason" from FIELD_TYPES
    # would have left this suite green. TestTheTwoSetsAreDisjoint is what
    # stops that recurring.
    "basis",
    "anomaly_basis",
    "correlation_basis",
    "behavior",
    "ttp",
    "assessment",
    "impact",
    "recommendation",
    "note",
    "notes",
    "summary",
    # windows and counters
    "time_range",
    "timestamp",
    "earliest_signal",
    "counts",
    "raw_counts",
    "vuln_stats",
    "vulnerability_counts",
    "context_stats",
    "detection_count",
    # internal row ids: #80 cleared epid/euid/alertid/incid/logid as numeric
    # join keys whose covered siblings already mint tokens
    "reference",
    "epid",
    "euid",
    "incid",
    "alertid",
    "logid",
    "task_id",
    "tid",
    # Structured containers. Their annotation admits a string somewhere in the
    # union, but what a skill actually puts in them is a dict or a list of
    # dicts, which masking recurses into and types by the INNER key. Verified
    # by the round-trip tests below rather than assumed.
    "alert",
    "incident",
    "entity",
    "record",
    "handler",
    "lateral_activity",
    # Covered contextually rather than by name: a bucket "value" is typed by
    # its sibling. See TestValueIsOnlyCoveredByItsTypeSibling, which is what
    # holds that invariant in place.
    "value",
}


class TestEverySkillStringFieldIsAccountedFor:
    """The guard: a new string field on a skill output is a decision.

    Either it names an identifier, in which case masking must know the name,
    or it does not, in which case it belongs in NON_IDENTIFIER_STRINGS with
    that judgement recorded. What must not happen is a third option where a
    field is added, carries an identifier, and nobody looked.
    """

    @pytest.mark.parametrize("skill_id", sorted(SKILLS), ids=sorted(SKILLS))
    def test_no_unclassified_string_field(self, skill_id: str) -> None:
        emitted = _string_fields(SKILLS[skill_id].output_model)
        unclassified = sorted(emitted - KNOWN_NAMES - NON_IDENTIFIER_STRINGS)

        assert not unclassified, (
            f"skill {skill_id!r} emits string field(s) {unclassified} that masking "
            "cannot type and that nothing has declared non-identifying. Either add "
            "the name to the masking tables or, if it cannot carry an identifier, "
            "to NON_IDENTIFIER_STRINGS with the reason."
        )


class TestTheTwoSetsAreDisjoint:
    """A name must not be both typed and exempt.

    Overlap is not merely redundant, it is a hole: a field masking covers
    today, also listed as exempt, keeps this suite green if its table entry is
    later removed. Five names were in exactly that state when this suite was
    first written (``description``, ``message``, ``reason``, ``warnings``,
    ``entity_ref``, all TEXT), which is how the hole was found.
    """

    def test_no_name_is_both_typed_and_exempt(self) -> None:
        overlap = sorted(NON_IDENTIFIER_STRINGS & KNOWN_NAMES)
        assert not overlap, (
            f"{overlap} are declared non-identifying AND typed by masking. "
            "Remove them from NON_IDENTIFIER_STRINGS: they are covered because "
            "they are masked, and listing them here means this suite stays "
            "green if that coverage is ever dropped."
        )


class TestTheVerbatimSubRecordStillMasks:
    """``hunt`` and ``risk_assessment`` publish a passthrough contract.

    Their ``record`` is documented "verbatim", so its keys are the appliance's
    vocabulary rather than the skill's. That is safe only while the vocabulary
    is one masking covers.
    """

    @pytest.fixture
    def masker(self) -> OutputMasker:
        return OutputMasker(FPEEngine(KEY))

    def test_a_verbatim_ueba_record_is_masked_through_the_wrapper(
        self, masker: OutputMasker
    ) -> None:
        bundle = {
            "entity": {
                "type": "enduser",
                "euid": 4471,
                "record": {
                    "srcip": "203.0.113.5",
                    "mac": "aa:bb:cc:dd:ee:11",
                    "user": "alice",
                },
            }
        }

        out = masker.mask_result(bundle)
        record = out["entity"]["record"]

        assert record["srcip"] != "203.0.113.5"
        assert record["mac"] != "aa:bb:cc:dd:ee:11"
        assert record["user"] != "alice"

    def test_the_numeric_join_key_stays_readable(self, masker: OutputMasker) -> None:
        """``euid`` is why the composed shape is safe without a new table entry.

        #80 cleared it by measurement: an internal row id whose covered
        siblings (``euname``) already mint tokens, so it confers no
        correlation power the output does not already give by design. If a
        future change types it, this fails and that decision gets revisited
        deliberately.
        """
        out = masker.mask_result({"entity": {"type": "enduser", "euid": 4471}})
        assert out["entity"]["euid"] == 4471

    def test_composition_does_not_pair_a_token_with_its_plaintext(
        self, masker: OutputMasker
    ) -> None:
        """The actual composition hazard, stated as a test.

        FPE is deterministic, so a bundle that carries one identifier under a
        covered name and the same identifier under an uncovered one publishes
        the token and the plaintext together and hands over the mapping. A
        skill is where that pairing becomes possible, because it is the only
        layer that puts several vocabularies in one record.
        """
        bundle = {
            "indicators": [{"value": "203.0.113.5", "type": "ip"}],
            "entity": {"type": "endpoint", "record": {"srcip": "203.0.113.5"}},
        }

        out = masker.mask_result(bundle)
        flat = repr(out)

        assert "203.0.113.5" not in flat, (
            "the same address survived in clear under one name while masking "
            "under another, which publishes the token-to-value mapping"
        )


class TestValueIsOnlyCoveredByItsTypeSibling:
    """``value`` is the one skill field covered by context, not by name.

    ``IndicatorSpec`` and ``IndicatorSubject`` both pair ``value`` with a
    REQUIRED ``type``, and that requirement is load-bearing: masking types a
    bucket's ``value`` from its sibling, so ``value`` alone is not a name the
    allowlist knows. Make ``type`` optional and every indicator an analyst
    submits without one rides out in clear.

    Measured with the exact literals the models declare, which are
    capitalised (``"IP"``, ``"URL"``, ``"Domain"``, ``"Hash"``) where the
    appliance vocabularies are lower case. The lookup folds case, so both
    spellings resolve.
    """

    @pytest.fixture
    def masker(self) -> OutputMasker:
        return OutputMasker(FPEEngine(KEY))

    @pytest.mark.parametrize(
        ("indicator_type", "value"),
        [
            ("IP", "203.0.113.5"),
            ("URL", "https://bad.example.com/x"),
            ("Domain", "bad.example.com"),
        ],
        ids=["IP", "URL", "Domain"],
    )
    def test_the_declared_literals_all_resolve(
        self, masker: OutputMasker, indicator_type: str, value: str
    ) -> None:
        out = masker.mask_result({"indicators": [{"value": value, "type": indicator_type}]})
        assert out["indicators"][0]["value"] != value

    def test_without_the_sibling_the_value_rides_out_in_clear(self, masker: OutputMasker) -> None:
        """The invariant stated as its failure mode.

        This is not a bug report: no skill emits this shape, because ``type``
        is required on both indicator models. It is here so that making
        ``type`` optional, or adding a third indicator model without it, turns
        a silent leak into a failing test.
        """
        out = masker.mask_result({"indicators": [{"value": "203.0.113.5"}]})
        assert out["indicators"][0]["value"] == "203.0.113.5", (
            "if this now masks, value has gained name-based coverage and the "
            "required-sibling invariant this suite protects is no longer the "
            "thing keeping indicators safe"
        )

    def test_a_file_hash_stays_readable(self, masker: OutputMasker) -> None:
        """``Hash`` is deliberately not masked, and that is not an oversight.

        A file hash identifies a FILE, not a person or an appliance, which is
        the same reasoning #80 used to leave ``srcuuid``/``dstuuid`` clear.
        Masking it would also destroy the only thing it is for: an analyst
        looks a hash up against threat intelligence, and a tokenised hash
        matches nothing anywhere.
        """
        digest = "d41d8cd98f00b204e9800998ecf8427e"
        out = masker.mask_result({"indicators": [{"value": digest, "type": "Hash"}]})
        assert out["indicators"][0]["value"] == digest
