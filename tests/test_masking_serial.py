"""Device serials mask as their own type, not as hostnames (#40).

The reason is a round-trip bug rather than taxonomy. The string alphabet is
lowercase, so a serial masked as a hostname comes back lowercased and is no
longer the serial. ``test_the_bug_this_type_exists_to_fix`` pins that, so if
anyone ever proposes folding serial back into HOSTNAME the cost is stated in
the suite rather than rediscovered.

Serial keys live in ``DEVICE_IDENTITY_TYPES``, so they only mask when the
identity flag is on. That flag is a CONSTRUCTOR ARGUMENT, not an environment
variable read inside the masker, and every test here drives the real
constructor. Each flag comparison carries ``devname`` as a control: it must
change when the flag flips, or the comparison is measuring nothing.
"""

import pytest

from fortianalyzer_mcp.masking.fields import DEVICE_IDENTITY_TYPES, FIELD_TYPES, SERIAL
from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.wrapper import _TOKEN_PREFIX_SHAPE_RE, OutputMasker

KEY = "2DE79D232DF5585D68CE47882AE256D6"

#: Invented, but real in shape: a plain appliance serial and the hyphenated
#: VM form. Both uppercase, which is the entire point -- the keep-check bug
#: on #113 shipped because every test value was lowercase.
PLAIN_SERIAL = "FGT60FTK20000001"
VM_SERIAL = "FAZ-VMTM00000000"


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY)


@pytest.fixture
def masker(engine: FPEEngine, monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    return OutputMasker(engine)


@pytest.fixture
def full_masker(engine: FPEEngine, monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    return OutputMasker(engine, mask_device_identity=True)


class TestTheReasonThisTypeExists:
    def test_the_bug_this_type_exists_to_fix(self, engine: FPEEngine):
        # Masked as a hostname, a serial round-trips to a DIFFERENT string.
        # Not cosmetic: the value that comes back is not the serial, so it
        # cannot be used to identify the appliance it came from.
        for serial in (PLAIN_SERIAL, VM_SERIAL):
            assert engine.unmask_hostname(engine.mask_hostname(serial)) != serial

    def test_the_serial_type_round_trips_byte_exact(self, engine: FPEEngine):
        for serial in (PLAIN_SERIAL, VM_SERIAL):
            assert engine.unmask_serial(engine.mask_serial(serial)) == serial

    def test_a_recased_serial_token_still_resolves(self, engine: FPEEngine):
        # A model may title-case a token in prose. Every string type but
        # username tolerates that, and serial has to as well or a re-cased
        # token stops being recognised as ours and goes to the appliance
        # as a literal.
        token = engine.mask_serial(PLAIN_SERIAL)

        assert engine.unmask_token(token.upper()) == PLAIN_SERIAL


class TestTheFlagStillGatesIt:
    def test_serials_stay_clear_with_the_flag_off(self, masker: OutputMasker):
        record = {"devname": "FW-HQ-01", "sn": PLAIN_SERIAL, "serialno": VM_SERIAL}

        out = masker.mask_result(dict(record))

        assert out == record, "device identity must stay clear by default"

    def test_serials_mask_with_the_flag_on(self, full_masker: OutputMasker):
        record = {"devname": "FW-HQ-01", "sn": PLAIN_SERIAL, "serialno": VM_SERIAL}

        out = full_masker.mask_result(dict(record))

        # The control. If devname does not move, the flag did not take and
        # the two assertions below prove nothing.
        assert out["devname"] != record["devname"]
        assert out["devname"].startswith("host-")

        assert out["sn"].startswith("sn-")
        assert out["serialno"].startswith("sn-")
        assert PLAIN_SERIAL not in repr(out)
        assert VM_SERIAL not in repr(out)

    def test_the_masked_serial_round_trips_through_the_real_path(
        self, engine: FPEEngine, full_masker: OutputMasker
    ):
        out = full_masker.mask_result({"sn": PLAIN_SERIAL, "serialno": VM_SERIAL})

        assert engine.unmask_token(out["sn"]) == PLAIN_SERIAL
        assert engine.unmask_token(out["serialno"]) == VM_SERIAL


class TestTheTypeTable:
    def test_every_serial_carrying_key_takes_the_serial_type(self):
        # csf is deliberately excluded: the Security Fabric name is an
        # operator label, not a serial. It moved to FIELD_TYPES on #80
        # (promoted to mask unconditionally rather than only with
        # FAZ_MASK_DEVICE_IDENTITY on), so it is checked there now.
        #
        # detectkey is here because the first pass missed it. It was typed
        # HOSTNAME while this very table's comment on it read "serial of the
        # detecting appliance", so it kept the round-trip bug the type was
        # added to fix. Matching on the sn- spelling was not enough.
        for key in ("sn", "serialno", "sndetected", "snclosest", "detectkey"):
            assert DEVICE_IDENTITY_TYPES[key] == SERIAL, key
        assert FIELD_TYPES["csf"] != SERIAL

    # There is deliberately NO automated check that a key whose comment says
    # "serial" is typed SERIAL, though detectkey is exactly the miss such a
    # check would be for. One was written and thrown away: it reported devid,
    # whose entry has no comment at all, because \s* matched a newline into
    # the next entry's comment block; and once that was fixed it reported
    # csf, whose comment reads "a label rather than a serial". Two runs, two
    # fabricated findings. A grep over prose cannot tell an assertion from a
    # negation, and a self-check that invents findings costs more than the
    # one real miss it would have caught. Review caught detectkey; the
    # explicit list above is what holds the line.

    def test_the_token_shape_recogniser_knows_sn_tokens(self, engine: FPEEngine):
        # This regex is what the mutating-tool gate (#108) uses to tell a
        # token from a legitimate value. If it does not know sn-, that gate
        # silently stops covering serial tokens.
        token = engine.mask_serial(PLAIN_SERIAL)

        assert _TOKEN_PREFIX_SHAPE_RE.match(token)
        # And it still does not mistake a plausible real name for a token:
        # no 4-hex key-id group.
        assert not _TOKEN_PREFIX_SHAPE_RE.match("sn-abc")
