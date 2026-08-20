"""Format-preserving encryption engine for reversible IOC masking (RFC #40).

Pseudonymises sensitive values (IPs, MACs, hostnames, usernames, domains,
emails) before they leave the MCP toward the LLM, in a way that is
deterministic (same value -> same token, so the model can correlate across
tool calls) and reversible from the key alone (no token vault; works with
``stateless_http=True``).

Token engine is NIST FF3-1 via the ``ff3`` package (Apache-2.0,
pycryptodome-backed). Each value type uses its own tweak derived from a
stable label, so the same raw string masked as e.g. a hostname and a
username yields different tokens (domain separation).

Token conventions per type (the marker doubles as a fail-safe: a missed
unmask shows an obviously fake value, and the prose companion can pattern
match it). ``<kid>`` is a 4-hex-char key id derived one-way from the
masking key: without it, decrypting a token minted under a rotated key
yields a silently wrong but plausible-looking value; with it, the
mismatch fails loudly. IP and MAC tokens have no room for a key id (the
whole address space is the codomain), so they keep that residual risk —
documented, same family as the IP wrinkle below.

    email     ``<ct-local>@<ct-domain>.<kid>.<mask_suffix>``
    domain    ``<ct>.<kid>.<mask_suffix>``
    hostname  ``host-<kid>-<ct>``
    username  ``user-<kid>-<ct>``
    url tail  ``url-<kid>-<ct>``
    ipv4/ipv6 valid-looking address, FPE over the full 32/128 bits
    mac       valid-looking MAC, FPE over the full 48 bits

URL tails (a ``url``/``referralurl`` value's path+query+fragment) are
utf-8 encoded and lowercase-base32'd before encryption: base32 output is
a strict subset of the string alphabet and never contains the pad char,
so arbitrary bytes ride the existing cipher, chunking and pad unchanged
and the round trip is byte-exact. The token length reveals the tail's
byte length (base32 is a fixed ~1.6x expansion and FF3 is
length-preserving) — a documented residual, like the chunking prefix
equality which applies to these tails too.

``mask_suffix`` defaults to ``masked.invalid`` — the ``.invalid`` TLD is
reserved (RFC 2606), so a leaked token can never resolve to a real host.

Usernames are the one case-sensitive type: ``Admin`` and ``admin`` can be
distinct principals, so the username cipher uses a mixed-case alphabet
(radix 66, single-block max 30 chars) and preserves case through the
round-trip. Residual: a model that re-cases a username token's ciphertext
in prose (e.g. title-casing it) corrupts the payload, and FF3 has no
integrity check to catch that — the other string types stay
case-insensitive and tolerate re-casing.

Two RFC deviations discovered while verifying reversibility (both are
"IP wrinkle"-class: the token carries no recognizable marker, so the
prose companion needs the session emitted-token set for these types):

- MAC: the RFC sketched ``02:1a:7f:`` (reserved OUI) + FPE tail, but
  discarding the original OUI is lossy. Reversibility requires FPE over
  all 48 bits, so a masked MAC looks like an arbitrary MAC.
- Email: the RFC sketched a fixed replacement domain, which likewise
  drops the original domain. The reversible form encrypts local part and
  domain separately and appends the suffix marker.

FF3-1 imposes a minimum domain size (radix ** length >= 1_000_000). Short
string values are padded with ``~`` (never legal in the value types we
mask) up to the cipher's minimum length; padding is stripped after
decryption. Values longer than the cipher's maximum length are encrypted
in chunks, each chunk with a position-varied tweak so identical chunks at
different positions do not produce identical ciphertext. Two equality
leaks follow from chunking, both one notch beyond the whole-value
equality deterministic FPE already discloses by design: two long values
sharing their first block produce the same first ciphertext block
(shared-prefix equality is visible), and chunk 0 shares its tweak with
unchunked values, so a short value equal to another value's first block
correlates with it.

Unmasked IPv6 addresses come back in Python's canonical compressed form
(``2001:db8::1``), not necessarily the textual form originally masked —
the same address, differently spelled; not a round-trip bug.

The key is a secret (AES-128/192/256 as hex). It must never be logged;
this module never includes key material in exceptions.
"""

import base64
import contextvars
import hashlib
import hmac
import ipaddress
import logging
import os
import re

from ff3 import FF3Cipher

# The only logging this module does is the v2 tag-verification failure. It
# is the one signal that separates a forgery grind from ordinary traffic,
# and the 32-bit tag size is only defensible while repeated failures are
# visible (#40). Nothing else here logs, and no value, token or key
# material is ever passed to it.
logger = logging.getLogger(__name__)

# Alphabet for string-typed values (hostnames, domains, email parts).
# 40 chars -> FF3-1 bounds are minLen 4 / maxLen 36. ``~`` is the pad
# sentinel and must never appear in a real value.
_STR_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-._~"
# Usernames are case-sensitive (Admin != admin), so their alphabet adds
# the uppercase letters. 66 chars -> FF3-1 bounds are minLen 4 / maxLen 30.
_USERNAME_ALPHABET = _STR_ALPHABET + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_PAD_CHAR = "~"

_KEY_ID_LEN = 4
_KEY_ID_RE = re.compile(r"^[0-9a-f]{4}$")

_HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]+$")
_VALID_KEY_LENGTHS = {32, 48, 64}  # hex chars: AES-128 / 192 / 256

#: Environment variable the key is read from (see ``FPEEngine.from_env``).
MASKING_KEY_ENV = "FAZ_MASKING_KEY"

#: Default marker suffix for domain/email tokens. ``.invalid`` is reserved
#: by RFC 2606 and can never resolve.
DEFAULT_MASK_SUFFIX = "masked.invalid"

#: Tag verifications allowed within one tool call, and failures tolerated
#: before the alarm.
#:
#: The 32-bit tag is one in 4.3 billion per blind guess, which sounds like
#: plenty until you count the right unit. The bound is per VERIFICATION,
#: not per call, and one call can carry thousands of tokens (measured:
#: 5000 in a single ``filters`` list, each resolved independently). At that
#: density 2**31 expected verifications is on the order of 10**5 calls
#: rather than 10**9, so an online grind is a day's work rather than a
#: geological era. Capping the per-call count is what puts the exponent
#: back, and it is cheap because no legitimate call comes near the cap.
#:
#: Committed to publicly on #40 alongside the tag width, so the width is
#: only defensible while this exists.
V2_VERIFY_BUDGET = 2048
V2_FAILURE_ALARM = 8

_V2_VERIFY_COUNT: contextvars.ContextVar[int] = contextvars.ContextVar("faz_v2_verify_count")
_V2_FAILURE_COUNT: contextvars.ContextVar[int] = contextvars.ContextVar("faz_v2_failure_count")


def begin_v2_verification_budget() -> None:
    """Reset the per-call verification budget. Called at the tool boundary."""
    _V2_VERIFY_COUNT.set(0)
    _V2_FAILURE_COUNT.set(0)


# Tweak labels, one per value type. These are part of the token contract:
# changing a label (or the derivation) invalidates all previously emitted
# tokens for that type, exactly like a key rotation would.
_TWEAK_LABELS = {
    "ipv4": "faz-mcp-fpe:v1:ipv4",
    "ipv6": "faz-mcp-fpe:v1:ipv6",
    "mac": "faz-mcp-fpe:v1:mac",
    "hostname": "faz-mcp-fpe:v1:hostname",
    "username": "faz-mcp-fpe:v1:username",
    "domain": "faz-mcp-fpe:v1:domain",
    "email_local": "faz-mcp-fpe:v1:email-local",
    "url_tail": "faz-mcp-fpe:v1:url-tail",
    # Serials are uppercase alphanumerics, sometimes hyphenated, which the
    # lowercase string alphabet cannot round-trip: masking one as a hostname
    # returns it lowercased, so it is not the serial any more. They take the
    # url-tail construction (base32 shield + string cipher) under their own
    # label, so serial and URL ciphertext domains stay separate.
    #
    # Byte-identical to the label that shipped on fortimanager-mcp
    # (feat/fpe-masking at 06c968b), because the token format is shared and
    # a token minted by one server is resolved by the other. Settled on #40.
    "serial": "faz-mcp-fpe:v1:serial",
}


#: Width of the v2 envelope's authentication tag, in hex characters.
#: 8 hex = 32 bits = one in 4.3 billion per blind forgery attempt. Forgery is
#: strictly online, because nothing lets an attacker test a guessed tag
#: locally.
#:
#: The bound is per VERIFICATION, not per tool call, and the difference
#: matters: one call can carry many tokens (measured, 5000 in a single
#: ``filters`` list, each resolved independently), so 2**31 expected
#: verifications is on the order of 10**5 calls rather than 10**9. Making
#: that cost real is the caller's job, not this function's -- the envelope
#: layer has to cap tokens verified per call and alarm on repeated
#: verification failures. Sizing alone does not buy the guarantee.
#:
#: Settled on #40; it is part of the format shared with fortimanager-mcp and
#: cannot be changed on one side alone.
V2_TAG_HEX = 8

#: A well-formed tag: exactly V2_TAG_HEX hex characters, checked after
#: case folding.
#: Checked before comparison because ``hmac.compare_digest`` raises on a
#: non-ASCII string instead of returning False, and the tag reaches us
#: from inside a token a model hands back.
_V2_TAG_RE = re.compile(rf"^[0-9a-f]{{{V2_TAG_HEX}}}$")

#: Value types that may appear in a v2 envelope.
#:
#: Pinned, and asserted colon-free, because the tag is computed over
#: ``faz-mcp-fpe:v2:tag:<type>:<ct>`` and that string is only injective while
#: no type name contains a colon. Add a type with a colon in it and two
#: different (type, ciphertext) pairs could authenticate each other's tokens.
#:
#: A v2 payload no longer contains a colon either, since #40 settled on hex
#: for IPv6 and MAC, so the type is not the only thing keeping the input
#: unambiguous any more. The assertion stays regardless: it costs nothing and
#: it is the property the construction actually depends on.
#:
#: ``serial`` is a full type now, with a tweak label and a cipher, and the
#: serial-carrying fields route to it. This comment previously described it
#: as a forward declaration with no cipher behind it, and described payloads
#: as colon-bearing; both were true when the tag primitive landed and neither
#: survived the same branch.
#: Envelope marker per value type. ``ip4``/``ip6``/``mac``/``sn`` are the
#: spellings that already shipped in fortimanager-mcp's reserved vocabulary
#: (``masking/tokens.py``, ``PREFIX_MARKERS``), and ``host``/``user``/``url``
#: are this server's existing v1 prefixes, reused so a v1 and a v2 token of
#: the same type share a marker and the shape gate below is what separates
#: them.
#:
#: Suffix-marked types (``domain``, ``email_local``) are deliberately absent.
#: Their v2 spelling puts the tag inside a dotted label rather than after a
#: hyphen, which is a different parse, and they already carry a marker and a
#: key id today, so they are not what the marked-IP work is blocked on.
V2_MARKERS: dict[str, str] = {
    "ipv4": "ip4",
    "ipv6": "ip6",
    "mac": "mac",
    "serial": "sn",
    "hostname": "host",
    "username": "user",
    "url_tail": "url",
}

#: Structural shape of a v2 envelope: ``<marker>-<kid>-<ct>-<tag>``.
#:
#: A ciphertext legitimately contains hyphens (the string alphabet has one),
#: so the payload/tag boundary has to be unambiguous. What makes it so is the
#: ``$`` anchor plus the fixed width of the tag group, NOT the greediness of
#: the payload: the tag is the last 8 characters or the match fails, and the
#: payload is whatever lies between the key id and that.
#:
#: Measured, because the obvious reading is that greediness carries it:
#: making the payload lazy changes nothing on any input, including a
#: ciphertext that itself ends in a hyphen and 8 hex. That mutant survives
#: the whole suite and is meant to -- it is equivalent, not uncovered.
#:
#: Matching is case-insensitive because a model may re-case a token in prose,
#: but only the marker, key id and tag are folded afterwards: the username
#: payload is case-sensitive and is kept exactly as written.
#: IGNORECASE covers the marker and the hex groups. It does NOT weaken the
#: username payload: the flag changes what matches, not what is captured, and
#: ``.+`` matches any character either way, so ``ct`` comes back exactly as
#: written. Without the flag an upper-cased ``IP4-`` failed the shape match
#: entirely, which sent a re-cased token to the appliance as a literal.
_V2_SHAPE_RE = re.compile(
    r"^(?P<marker>ip4|ip6|mac|sn|url|host|user)-(?P<kid>[0-9a-f]{4})-"
    r"(?P<ct>.+)-(?P<tag>[0-9a-f]{8})$",
    re.IGNORECASE,
)

V2_TYPES = frozenset(
    {"ipv4", "ipv6", "mac", "serial", "hostname", "username", "domain", "email_local", "url_tail"}
)


class MaskingError(Exception):
    """Raised when a value cannot be masked or a token cannot be unmasked."""


class VerificationBudgetExhausted(MaskingError):
    """The per-call tag-verification budget is spent.

    Its own type because the boundary must treat it differently from an
    ordinary unmask failure. A single token that will not decrypt is
    passed through so the downstream validator rejects it; doing that with
    budget exhaustion turns the cap into partial resolution, where the
    first tokens resolve and the rest ride out as literals with nothing
    told to the caller. That is the outcome the cap exists to prevent.
    """


def _derive_tweak(label: str, chunk_index: int = 0) -> str:
    """Derive a 56-bit FF3-1 tweak (14 hex chars) from a stable label.

    Tweaks are not secret; they provide domain separation between value
    types and between chunks of an over-length value.
    """
    material = f"{label}:{chunk_index}" if chunk_index else label
    return hashlib.sha256(material.encode()).hexdigest()[:14]


class FPEEngine:
    """Per-type reversible masking built on FF3-1.

    All ``mask_*`` / ``unmask_*`` pairs are deterministic for a given key
    and reversible from the key alone. String-typed values are normalized
    to lowercase before encryption (hostnames, domains and emails are
    case-insensitive anyway), so unmasking returns the lowercase form —
    except usernames, which are case-sensitive principals and round-trip
    with their casing preserved.
    """

    def __init__(
        self,
        key: str,
        mask_suffix: str = DEFAULT_MASK_SUFFIX,
        accept_v1_tokens: bool = True,
    ) -> None:
        """Initialize the engine.

        Args:
            key: AES key as hex (32, 48 or 64 hex chars for AES-128/192/256).
            mask_suffix: Marker suffix for domain/email tokens.

        Raises:
            MaskingError: If the key is not valid hex of a supported length.
        """
        if not _HEX_KEY_RE.match(key) or len(key) not in _VALID_KEY_LENGTHS:
            # Deliberately does not echo the offending value: the key is a secret.
            raise MaskingError("masking key must be 32, 48 or 64 hex characters (AES-128/192/256)")
        self._mask_suffix = mask_suffix.lower().lstrip(".")
        # The v1 deprecation window. Open by default for one release:
        # tokens already sitting in a live conversation have to keep
        # resolving, or closing the window silently breaks every session
        # that was mid-flight when the server restarted.
        self._accept_v1_tokens = accept_v1_tokens
        self._seen_v1_token = False
        # One-way key fingerprint carried in marked tokens so a token minted
        # under a different key fails loudly instead of decrypting to a
        # plausible wrong value. Key hex is case-normalized first: it is the
        # same AES key either way. 4 hex chars = 16 bits, plenty to tell two
        # rotation generations apart; not meant to be collision-proof.
        self._key_id = hashlib.sha256(f"faz-mcp-fpe:v1:keyid:{key.lower()}".encode()).hexdigest()[
            :_KEY_ID_LEN
        ]
        self._hex_ciphers = {
            vtype: FF3Cipher(key, _derive_tweak(label), radix=16)
            for vtype, label in _TWEAK_LABELS.items()
            if vtype in ("ipv4", "ipv6", "mac")
        }
        self._str_ciphers = {
            vtype: FF3Cipher.withCustomAlphabet(
                key,
                _derive_tweak(label),
                _USERNAME_ALPHABET if vtype == "username" else _STR_ALPHABET,
            )
            for vtype, label in _TWEAK_LABELS.items()
            if vtype not in ("ipv4", "ipv6", "mac")
        }
        self._alphabets = {
            vtype: _USERNAME_ALPHABET if vtype == "username" else _STR_ALPHABET
            for vtype in self._str_ciphers
        }
        self._tweak_labels = dict(_TWEAK_LABELS)
        # Separate subkey for the v2 authentication tag, derived from the same
        # secret rather than reusing the AES key as an HMAC key. Two
        # primitives, two keys, and the raw key is not retained on the
        # instance. The derivation string is part of the shared format.
        self._v2_tag_key = hashlib.sha256(f"faz-mcp-fpe:v2:tagkey:{key.lower()}".encode()).digest()

    @classmethod
    def from_env(
        cls,
        mask_suffix: str = DEFAULT_MASK_SUFFIX,
        accept_v1_tokens: bool = True,
    ) -> "FPEEngine":
        """Build an engine from the ``FAZ_MASKING_KEY`` environment variable.

        Raises:
            MaskingError: If the variable is unset or holds an invalid key.
        """
        key = os.environ.get(MASKING_KEY_ENV, "")
        if not key:
            raise MaskingError(f"{MASKING_KEY_ENV} is not set")
        return cls(key, mask_suffix=mask_suffix, accept_v1_tokens=accept_v1_tokens)

    @property
    def mask_suffix(self) -> str:
        """Marker suffix used for domain and email tokens."""
        return self._mask_suffix

    @property
    def key_id(self) -> str:
        """4-hex-char one-way fingerprint of the key, embedded in marked tokens."""
        return self._key_id

    # ------------------------------------------------------------------ #
    # v2 envelope authentication tag (#40)                                #
    # ------------------------------------------------------------------ #

    def v2_tag(self, vtype: str, ct: str) -> str:
        """Authentication tag for a v2 envelope payload.

        Keyed and domain-separated per type, so a token cannot be lifted from
        one value type to another and still verify. Truncated to
        :data:`V2_TAG_HEX`.

        Raises:
            MaskingError: If ``vtype`` is not a pinned v2 type. A type
                carrying a colon would break the injectivity the tag input
                relies on, so this is enforced rather than documented.
        """
        if vtype not in V2_TYPES:
            raise MaskingError(f"unknown v2 value type: {vtype!r}")
        message = f"faz-mcp-fpe:v2:tag:{vtype}:{self._v2_canonical_ct(vtype, ct)}".encode()
        return hmac.new(self._v2_tag_key, message, hashlib.sha256).hexdigest()[:V2_TAG_HEX]

    @staticmethod
    def _v2_canonical_ct(vtype: str, ct: str) -> str:
        """Canonical spelling of a payload, for tag purposes.

        The tag has to tolerate exactly what decryption tolerates, no more
        and no less. Every type but ``username`` is case-insensitive here and
        its payload is lowercased before decryption, so an upper- or
        title-cased token still round-trips; tagging the verbatim spelling
        would make a re-cased token fail verification, stop being recognised
        as ours, and be handed to the appliance as a literal.

        ``username`` is excluded because its cipher alphabet is mixed-case
        and ``Admin`` and ``admin`` can be different principals. Folding case
        there would let two distinct principals' tokens authenticate each
        other's payloads.

        ``ipv6`` had a branch here that canonicalised through
        ``ipaddress.IPv6Address``, because two spellings of one address both
        decrypted and so both had to tag alike. #40 settled that v2 payloads
        carry no colons: an IPv6 payload is plain hex inside the envelope,
        which has exactly one spelling up to case. The branch is gone rather
        than kept as insurance, because it would silently start canonicalising
        again the moment a colon-bearing payload appeared, which is the thing
        the format now forbids.

        ``serial`` needs no exception either. Its ciphertext is base32 run
        through the lowercase string cipher, so it is lowercase by
        construction and folding matches what decryption tolerates. The
        serial's own case survives inside the base32 shield, below this
        layer.
        """
        if vtype == "username":
            return ct
        return ct.lower()

    def v2_tag_ok(self, vtype: str, ct: str, tag: str) -> bool:
        """Is ``tag`` the authentic tag for this payload?

        Total over BOTH untrusted inputs, the tag and the payload, since the
        envelope parser slices both out of token text a model supplied.
        Minting (:meth:`v2_tag`) still raises on an unencodable payload,
        because there the ciphertext is one we produced.

        Total over the tag: anything that is not exactly
        :data:`V2_TAG_HEX` hex characters is False, never an exception.
        ``compare_digest`` raises TypeError on a non-ASCII string rather
        than returning False, so the shape check has to come first.

        The tag is case-folded before comparison, and the payload is folded
        by :meth:`_v2_canonical_ct`, so a re-cased token verifies exactly
        where a re-cased token still decrypts. Being stricter than the
        decrypt path would not be safer: it would turn a token we minted
        into one we no longer recognise, and hand it onward as a literal.

        ``vtype`` is NOT untrusted, and an unknown one still raises. It comes
        from this repo's own field table, so it is a bug here rather than
        something a caller can influence, and swallowing it would hide that.

        Constant-time comparison: a timing signal on the tag check would let
        an attacker recover a valid tag byte by byte and reduce forgery from
        2**32 attempts to a few hundred. The length and shape checks above
        leak nothing, since both are fixed and public.
        """
        try:
            expected = self.v2_tag(vtype, ct)
        except UnicodeEncodeError:
            # A payload that is not encodable UTF-8 (a lone surrogate, which
            # json.loads produces from a "\\ud800" escape) cannot be a
            # ciphertext we minted, and the parser slices it out of token text
            # a model supplied. Same class as an unencodable tag: refuse,
            # rather than raise out of the inbound path.
            return False
        candidate = tag.lower()
        if not _V2_TAG_RE.match(candidate):
            return False
        return hmac.compare_digest(candidate, expected)

    # ------------------------------------------------------------------ #
    # v2 envelope: mint, shape, open (#40)                                #
    # ------------------------------------------------------------------ #

    def v2_token(self, vtype: str, ct: str) -> str:
        """Wrap a ciphertext in a v2 envelope: ``<marker>-<kid>-<ct>-<tag>``.

        ``ct`` is the v1 ciphertext for ``vtype``, unchanged: the cipher,
        chunking and alphabets are untouched by v2, which only adds the
        envelope around them.
        """
        try:
            marker = V2_MARKERS[vtype]
        except KeyError:
            raise MaskingError(f"no v2 envelope for value type: {vtype!r}") from None
        payload = self._v2_payload_out(vtype, ct)
        return f"{marker}-{self._key_id}-{payload}-{self.v2_tag(vtype, payload)}"

    @staticmethod
    def is_v2_shaped(token: str) -> bool:
        """Does this text have the full shape of a v2 envelope?

        The shape gate settled on #40 rests on this predicate: a token that
        LOOKS like v2 is committed to v2 and never falls back to the v1
        path, whatever happens next. Without that, a v2 token with a flipped
        tag is still a byte-valid v1 token (the tag's hex and hyphen are both
        inside the v1 alphabet), so the v1 path would decrypt it to plausible
        garbage and forgery refusal would not hold for any of the prefix
        types until the deprecation window closed.

        The measured cost is a false refusal for a v1 token whose ciphertext
        happens to end in a hyphen plus 8 lowercase hex: 1.6e-5 per token,
        (1/40) * (16/40)**8 over the 40-character alphabet. It fails closed
        and loudly, which is the trade Roland took.
        """
        return _V2_SHAPE_RE.match(token.strip()) is not None

    def is_own_v2_token(self, value: str) -> bool:
        """Did THIS engine mint this token?

        The one predicate the output side may use, and the reason it
        exists: shape is not ownership. ``is_v2_shaped`` asks whether
        something LOOKS like a v2 envelope, which is the right question
        inbound, where a shaped token must be committed to v2 rather than
        retried on v1. Outbound it is the wrong question, because a real
        value can be shaped like a token:

            {"hostname": "host-ab12-web-01-cafe0123"}

        is a perfectly ordinary hostname and a perfectly good v2 shape,
        and a shape-only skip hands it back in clear. The key id is not
        enough either: the shape regex accepts any four hex characters, so
        the exposed surface is every kid rather than ours.

        The tag is what separates the two, and it costs one keyed hash. It
        deliberately does NOT charge the verification budget: that budget
        exists to bound an attacker grinding tags on the INBOUND path, and
        spending it on our own output would let a large response starve
        the calls that follow it.

        Total: never raises. A malformed or foreign token is simply not
        ours, which is the answer the caller needs.
        """
        match = _V2_SHAPE_RE.match(value.strip())
        if match is None:
            return False
        marker = match.group("marker").lower()
        if match.group("kid").lower() != self._key_id:
            return False
        try:
            vtype = next(t for t, m in V2_MARKERS.items() if m == marker)
        except StopIteration:  # pragma: no cover - markers are a closed set
            return False
        payload = match.group("ct") if vtype == "username" else match.group("ct").lower()
        try:
            return self.v2_tag_ok(vtype, payload, match.group("tag"))
        except Exception:
            return False

    def v2_open(self, token: str) -> str:
        """Verify and decrypt a v2 envelope, returning the real value.

        Total over untrusted text: this is handed token-shaped strings a
        model supplied.

        Raises:
            MaskingError: If the shape, key id, tag or payload is wrong. The
                caller must NOT retry such a token on the v1 path -- see
                :meth:`is_v2_shaped`. Refusal is the point; a refused token
                is recoverable in a way a silent wrong decrypt is not.
        """
        match = _V2_SHAPE_RE.match(token.strip())
        if match is None:
            raise MaskingError("not a v2 token")
        marker = match.group("marker").lower()
        vtype = next(t for t, m in V2_MARKERS.items() if m == marker)
        # Username ciphertext is case-sensitive; every other payload is
        # lowercase by construction and folding tolerates a re-cased token.
        payload = match.group("ct") if vtype == "username" else match.group("ct").lower()
        self._check_key_id(match.group("kid").lower(), token)
        self._spend_verification()
        if not self.v2_tag_ok(vtype, payload, match.group("tag")):
            # Deliberately loud: this is the only signal that distinguishes a
            # forgery grind from ordinary traffic, and the 32-bit tag is only
            # safe if repeated failures are visible. The token is not logged,
            # since it is attacker-influenced text.
            failures = _V2_FAILURE_COUNT.get(0) + 1
            _V2_FAILURE_COUNT.set(failures)
            if failures == V2_FAILURE_ALARM:
                # The alarm, distinct from the per-failure line: a handful of
                # failures in one call is not a corrupted token being echoed
                # back, it is someone trying tags.
                logger.error(
                    "v2 tag verification failed %d times in one call; possible forgery attempt",
                    failures,
                )
            else:
                # Deliberately loud: this is the only signal that distinguishes a
                # forgery grind from ordinary traffic, and the 32-bit tag is only
                # safe if repeated failures are visible. The token is not logged,
                # since it is attacker-influenced text.
                logger.warning("v2 token failed tag verification (type=%s); refused", vtype)
            raise MaskingError("tag mismatch: forged or corrupted token")
        return self._v2_decrypt(vtype, payload)

    @staticmethod
    def _spend_verification() -> None:
        """Charge one tag verification against this call's budget.

        Counted BEFORE the tag is checked, so a grind pays for its
        attempts rather than only for its successes. Refusal is a
        MaskingError like any other, so a caller that hits the cap fails
        closed on the remaining tokens instead of resolving them.
        """
        spent = _V2_VERIFY_COUNT.get(0) + 1
        _V2_VERIFY_COUNT.set(spent)
        if spent > V2_VERIFY_BUDGET:
            if spent == V2_VERIFY_BUDGET + 1:
                logger.error(
                    "v2 verification budget of %d exhausted in one call; refusing the rest",
                    V2_VERIFY_BUDGET,
                )
            raise VerificationBudgetExhausted("v2 verification budget for this call is exhausted")

    @staticmethod
    def _b32_decode(encoded: str, what: str) -> str:
        """Undo the base32 shield the serial and url-tail forms share."""
        try:
            return base64.b32decode(encoded.upper() + "=" * (-len(encoded) % 8)).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise MaskingError(f"cannot unmask {what} token: {exc}") from exc

    def _v2_decrypt(self, vtype: str, payload: str) -> str:
        """Decrypt a verified v2 payload through the existing v1 ciphers."""
        if vtype == "ipv4":
            return self.unmask_ip(payload)
        if vtype == "ipv6":
            # Only reachable behind a valid tag, so a non-hex payload here
            # means our own minting is broken rather than that someone forged
            # something. Still converted, because v2_open is documented total
            # over untrusted text and a bare ValueError out of it would make
            # that false the moment the assumption stops holding.
            try:
                return self.unmask_ip(str(ipaddress.IPv6Address(int(payload, 16))))
            except ValueError as exc:
                raise MaskingError("not a valid IPv6 payload") from exc
        if vtype == "mac":
            return self.unmask_mac(":".join(payload[i : i + 2] for i in range(0, 12, 2)))
        if vtype == "serial":
            # Decrypted directly rather than by rebuilding a v1 token and
            # calling unmask_serial. That round trip sent a v2 payload
            # through _split_key_id, which is v1 deprecation machinery:
            # closing the window would have refused the engine's OWN v2
            # serial and url tokens, and v2 traffic latched the "v1 token
            # seen" signal so it could never go quiet.
            return self._b32_decode(self._decrypt_str("serial", payload), "serial")
        if vtype == "hostname":
            return self._decrypt_str("hostname", payload)
        if vtype == "username":
            return self._decrypt_str("username", payload)
        return self._b32_decode(self._decrypt_str("url_tail", payload), "url")

    @staticmethod
    def _v2_payload_out(vtype: str, ct: str) -> str:
        """Spell a ciphertext for the envelope. Colon-free, settled on #40.

        IPv6 and MAC ciphertexts are addresses in v1 and become plain hex
        here. Colons inside a token broke three things at once: ``urlsplit``
        raises on a v2 IPv6 token used as a URL host (measured on 3.12), so a
        re-masked echo burned to an irreversible placeholder; the mint sites
        re-bracket on a colon; and the free-text ``_MAC_RE`` matched the
        address sitting inside a ``mac-`` envelope. Hex closes all three, and
        v2 gave up looking like an address the moment it grew a marker.
        """
        if vtype == "ipv6":
            try:
                address = ipaddress.IPv6Address(ct.strip())
            except ValueError as exc:
                # Mint side, so this is our own ciphertext and a bug here
                # rather than hostile input. It still leaves as a MaskingError,
                # because every caller of the mint path handles that and none
                # handles AddressValueError, and the raw ct is not echoed.
                raise MaskingError("not a valid IPv6 ciphertext") from exc
            # The width is load-bearing and part of the shared format: 32 hex
            # digits, zero-padded. One in sixteen ciphertexts has a leading
            # zero nibble, and a port that drops the padding round-trips
            # against itself perfectly while its tokens fail verification on
            # the other server and are logged as forgeries.
            return format(int(address), "032x")
        if vtype == "mac":
            return ct.replace(":", "").replace("-", "").lower()
        return ct

    # ------------------------------------------------------------------ #
    # IP addresses                                                       #
    # ------------------------------------------------------------------ #

    def mask_ip(self, value: str) -> str:
        """Mask an IPv4 or IPv6 address into another valid address.

        Note: masked IPs carry no recognizable marker (no reserved block
        can hold the full address space reversibly) — the "IP wrinkle".
        """
        addr = self._parse_ip(value)
        if addr.version == 4:
            ct = self._hex_ciphers["ipv4"].encrypt(f"{int(addr):08x}")
            return str(ipaddress.IPv4Address(int(ct, 16)))
        ct = self._hex_ciphers["ipv6"].encrypt(f"{int(addr):032x}")
        return str(ipaddress.IPv6Address(int(ct, 16)))

    def unmask_ip(self, token: str) -> str:
        """Reverse :meth:`mask_ip`.

        IPv6 comes back in canonical compressed form, which may not be the
        textual form originally masked (same address, different spelling).
        """
        addr = self._parse_ip(token)
        try:
            if addr.version == 4:
                pt = self._hex_ciphers["ipv4"].decrypt(f"{int(addr):08x}")
                return str(ipaddress.IPv4Address(int(pt, 16)))
            pt = self._hex_ciphers["ipv6"].decrypt(f"{int(addr):032x}")
            return str(ipaddress.IPv6Address(int(pt, 16)))
        except Exception as exc:
            raise MaskingError("cannot unmask IP address") from exc

    @staticmethod
    def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        try:
            return ipaddress.ip_address(value.strip())
        except ValueError:
            raise MaskingError("not a valid IP address") from None

    # ------------------------------------------------------------------ #
    # MAC addresses                                                      #
    # ------------------------------------------------------------------ #

    def mask_mac(self, value: str) -> str:
        """Mask a MAC address into another valid-looking MAC.

        FPE runs over the full 48 bits (a recognizable fixed OUI would make
        the mapping lossy), so like IPs, masked MACs carry no marker.
        Output is normalized to lowercase colon-separated form.
        """
        ct = self._hex_ciphers["mac"].encrypt(self._normalize_mac(value))
        return ":".join(ct[i : i + 2] for i in range(0, 12, 2))

    def unmask_mac(self, token: str) -> str:
        """Reverse :meth:`mask_mac`. Returns lowercase colon-separated form."""
        normalized = self._normalize_mac(token)
        try:
            pt = self._hex_ciphers["mac"].decrypt(normalized)
            return ":".join(pt[i : i + 2] for i in range(0, 12, 2))
        except Exception as exc:
            raise MaskingError("cannot unmask MAC address") from exc

    @staticmethod
    def _normalize_mac(value: str) -> str:
        digits = re.sub(r"[:.\-\s]", "", value.strip().lower())
        if not re.fullmatch(r"[0-9a-f]{12}", digits):
            raise MaskingError("not a valid MAC address")
        return digits

    # ------------------------------------------------------------------ #
    # Names, domains, emails                                             #
    # ------------------------------------------------------------------ #

    def mask_hostname(self, value: str) -> str:
        """Mask a hostname into a ``host-<kid>-<ct>`` token."""
        return f"host-{self._key_id}-{self._encrypt_str('hostname', value)}"

    def unmask_hostname(self, token: str) -> str:
        """Reverse :meth:`mask_hostname`."""
        payload = self._strip_prefix(token, "host-")
        return self._decrypt_str("hostname", self._split_key_id(payload, token))

    def mask_username(self, value: str) -> str:
        """Mask a user/login name into a ``user-<kid>-<ct>`` token (case-preserving)."""
        return f"user-{self._key_id}-{self._encrypt_str('username', value)}"

    def unmask_username(self, token: str) -> str:
        """Reverse :meth:`mask_username`.

        The ciphertext is case-sensitive (mixed-case alphabet); only the
        ``user-`` prefix and the key id tolerate re-casing.
        """
        payload = self._strip_prefix(token, "user-", lower_payload=False)
        return self._decrypt_str("username", self._split_key_id(payload, token))

    def mask_domain(self, value: str) -> str:
        """Mask a DNS domain into ``<ct>.<kid>.<mask_suffix>``."""
        return f"{self._encrypt_str('domain', value)}.{self._key_id}.{self._mask_suffix}"

    def unmask_domain(self, token: str) -> str:
        """Reverse :meth:`mask_domain`."""
        payload = self._strip_domain_suffix(token)
        return self._decrypt_str("domain", self._split_key_id_suffix(payload, token))

    def mask_email(self, value: str) -> str:
        """Mask an email address into ``<ct-local>@<ct-domain>.<kid>.<mask_suffix>``."""
        local, _, domain = value.strip().partition("@")
        if not local or not domain:
            raise MaskingError("not a valid email address")
        return (
            f"{self._encrypt_str('email_local', local)}"
            f"@{self._encrypt_str('domain', domain)}.{self._key_id}.{self._mask_suffix}"
        )

    def unmask_email(self, token: str) -> str:
        """Reverse :meth:`mask_email`."""
        local, _, domain = token.strip().lower().partition("@")
        if not local or not domain:
            raise MaskingError(f"not a masked email token: {token!r}")
        domain_ct = self._split_key_id_suffix(self._strip_domain_suffix(domain), token)
        return f"{self._decrypt_str('email_local', local)}@{self._decrypt_str('domain', domain_ct)}"

    # ------------------------------------------------------------------ #
    # URL tails                                                          #
    # ------------------------------------------------------------------ #

    def mask_url_tail(self, value: str) -> str:
        """Mask a URL tail (path+query+fragment) into a ``url-<kid>-<ct>`` token.

        The raw tail is utf-8 encoded and lowercase-base32'd before
        encryption, so arbitrary bytes (``~``, percent-encoding, mixed
        case, non-ASCII) ride the existing string cipher without touching
        its alphabet or pad conventions: base32 output (``a-z2-7``) is a
        strict subset of ``_STR_ALPHABET`` and never contains the pad char.
        """
        if not value:
            raise MaskingError("cannot mask an empty URL tail")
        encoded = base64.b32encode(value.encode()).decode("ascii").lower().rstrip("=")
        return f"url-{self._key_id}-{self._encrypt_str('url_tail', encoded)}"

    def mask_serial(self, value: str) -> str:
        """Mask a device serial into an ``sn-<kid>-<ct>`` token.

        Same construction as :meth:`mask_url_tail`, under the ``serial``
        label: base32-shield the raw bytes, then run the string cipher.
        Case survives exactly, which a hostname token cannot manage.
        Measured before this existed: ``FGT60FTK20000001`` masked as a
        hostname came back ``fgt60ftk20000001``.

        Named ``seal_serial`` on fortimanager-mcp, which follows a different
        method convention; the token both produce is the same.

        Residual, inherited from the construction: the token length reveals
        the serial's length.
        """
        if not value.strip():
            raise MaskingError("cannot mask an empty serial")
        encoded = base64.b32encode(value.strip().encode()).decode("ascii").lower().rstrip("=")
        return f"sn-{self._key_id}-{self._encrypt_str('serial', encoded)}"

    def unmask_serial(self, token: str) -> str:
        """Reverse :meth:`mask_serial`, returning the exact original serial."""
        payload = self._strip_prefix(token, "sn-")
        encoded = self._decrypt_str("serial", self._split_key_id(payload, token))
        try:
            return base64.b32decode(encoded.upper() + "=" * (-len(encoded) % 8)).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise MaskingError(f"cannot unmask serial token: {exc}") from exc

    def unmask_url_tail(self, token: str) -> str:
        """Reverse :meth:`mask_url_tail`, returning the exact original tail."""
        payload = self._strip_prefix(token, "url-")
        encoded = self._decrypt_str("url_tail", self._split_key_id(payload, token))
        try:
            raw = base64.b32decode(encoded.upper() + "=" * (-len(encoded) % 8))
            return raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            # A corrupted/re-encoded ciphertext dies here, loudly, instead
            # of decrypting to plausible garbage.
            raise MaskingError(f"cannot unmask url token: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Generic token recognition (marked types only)                      #
    # ------------------------------------------------------------------ #

    def unmask_token(self, token: str) -> str | None:
        """Unmask any token carrying a recognizable marker.

        Recognizes the ``host-`` / ``user-`` prefixes and the
        ``.<mask_suffix>`` suffix (domain and email forms). IP and MAC
        tokens carry no marker and must be unmasked explicitly by field
        context.

        Returns:
            The real value, or ``None`` if ``token`` matches no convention.

        Raises:
            MaskingError: If a marker matches but the payload does not decrypt.
        """
        # Every token form except the username ciphertext is lowercase by
        # construction, so lowercasing those is lossless and tolerates a
        # model title-casing a token in prose. The username payload must be
        # kept verbatim (mixed-case alphabet).
        stripped = token.strip()
        if self.is_v2_shaped(stripped):
            # The gate, and it has to be FIRST. A v2 hostname token also
            # starts with "host-", so asking the shape question after the
            # prefix dispatch below would never reach it, and the v1 path
            # would decrypt a forged token to plausible garbage: the tag is
            # hex and a hyphen, both inside the v1 alphabet, so a flipped
            # tag leaves a byte-valid v1 token. Ordering IS the gate.
            #
            # Committed means committed. A v2-shaped token is never retried
            # on the v1 path, whatever v2 says about it, because a fallback
            # hands the forger exactly the decrypt this refuses. v2_open
            # raises, and the caller must let that propagate.
            #
            # This is also the first route by which the IP and MAC forms
            # resolve at all: their v1 tokens carry no marker, so the
            # dispatch below never covered them and field context had to.
            return self.v2_open(stripped)
        candidate = stripped.lower()
        # Suffix first: it is the strongest marker. A domain-token payload
        # may itself start with "host-"/"user-" by chance, but a prefix
        # token ending in ".<mask_suffix>" is astronomically unlikely.
        if candidate.endswith("." + self._mask_suffix):
            if "@" in candidate:
                return self.unmask_email(candidate)
            return self.unmask_domain(candidate)
        if candidate.startswith("host-"):
            return self.unmask_hostname(candidate)
        if candidate.startswith("user-"):
            return self.unmask_username(stripped)
        if candidate.startswith("url-"):
            return self.unmask_url_tail(candidate)
        if candidate.startswith("sn-"):
            return self.unmask_serial(candidate)
        return None

    # ------------------------------------------------------------------ #
    # String FPE core (padding + chunking)                               #
    # ------------------------------------------------------------------ #

    def _encrypt_str(self, vtype: str, value: str) -> str:
        cipher = self._str_ciphers[vtype]
        alphabet = self._alphabets[vtype]
        # Usernames are case-sensitive principals; every other string type
        # is case-insensitive by definition and normalizes to lowercase.
        normalized = value.strip() if vtype == "username" else value.strip().lower()
        if not normalized:
            raise MaskingError(f"cannot mask empty {vtype} value")
        if _PAD_CHAR in normalized:
            raise MaskingError(f"{vtype} value contains the reserved pad character {_PAD_CHAR!r}")
        if any(ch not in alphabet for ch in normalized):
            raise MaskingError(f"{vtype} value contains characters outside the maskable alphabet")
        if len(normalized) < cipher.minLen:
            normalized = normalized.ljust(cipher.minLen, _PAD_CHAR)
        return self._apply_chunked(cipher, vtype, normalized, encrypt=True)

    def _decrypt_str(self, vtype: str, payload: str) -> str:
        cipher = self._str_ciphers[vtype]
        alphabet = self._alphabets[vtype]
        if not payload or any(ch not in alphabet for ch in payload):
            raise MaskingError(f"not a valid masked {vtype} token payload")
        try:
            plain = self._apply_chunked(cipher, vtype, payload, encrypt=False)
        except Exception as exc:
            raise MaskingError(f"cannot unmask {vtype} token: {exc}") from exc
        # Padding is always trailing and the pad char never occurs in real
        # values, so stripping from the right is unambiguous.
        return plain.rstrip(_PAD_CHAR)

    def _apply_chunked(self, cipher: FF3Cipher, vtype: str, text: str, encrypt: bool) -> str:
        """Encrypt/decrypt ``text``, splitting into maxLen-sized chunks.

        Chunk boundaries are deterministic (every ``maxLen`` chars), so the
        same splitting happens on both directions. Each chunk after the
        first uses a position-varied tweak. A short final chunk is padded
        (encrypt) / right-stripped by the caller (decrypt).
        """
        if len(text) <= cipher.maxLen:
            # str(): the untyped ff3 package returns Any as far as mypy knows.
            return str(cipher.encrypt(text) if encrypt else cipher.decrypt(text))

        label = self._tweak_labels[vtype]
        out: list[str] = []
        for i, start in enumerate(range(0, len(text), cipher.maxLen)):
            chunk = text[start : start + cipher.maxLen]
            if encrypt and len(chunk) < cipher.minLen:
                chunk = chunk.ljust(cipher.minLen, _PAD_CHAR)
            tweak = _derive_tweak(label, chunk_index=i)
            out.append(
                cipher.encrypt_with_tweak(chunk, tweak)
                if encrypt
                else cipher.decrypt_with_tweak(chunk, tweak)
            )
        return "".join(out)

    # ------------------------------------------------------------------ #
    # Helpers                                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _strip_prefix(token: str, prefix: str, lower_payload: bool = True) -> str:
        # The prefix always tolerates re-casing. The payload is lowercased
        # for the case-insensitive types (tokens are emitted lowercase) but
        # kept verbatim for the mixed-case username ciphertext.
        stripped = token.strip()
        if not stripped.lower().startswith(prefix):
            raise MaskingError(f"not a {prefix}* token: {token!r}")
        payload = stripped[len(prefix) :]
        return payload.lower() if lower_payload else payload

    def _strip_domain_suffix(self, token: str) -> str:
        candidate = token.strip().lower()
        suffix = "." + self._mask_suffix
        if not candidate.endswith(suffix):
            raise MaskingError(f"token does not carry the {suffix!r} marker: {token!r}")
        return candidate[: -len(suffix)]

    #: v1 minting method per enveloped type whose token is prefix-marked.
    _V1_MINTERS = {
        "hostname": "mask_hostname",
        "username": "mask_username",
        "url_tail": "mask_url_tail",
        "serial": "mask_serial",
    }

    @staticmethod
    def _v1_payload(token: str) -> str:
        """Bare ciphertext out of a ``<marker>-<kid>-<ct>`` token.

        Split from the LEFT, because a ciphertext legitimately contains
        hyphens: the string alphabet has one, and a serial payload reliably
        does. Splitting from the right truncates those silently.
        """
        return token.split("-", 2)[2]

    def mint(self, vtype: str, value: str) -> str:
        """Mask ``value`` and return it in the format this server emits.

        One mint point, on purpose. Every ``mask_*`` primitive formats its
        own v1 token inline, so switching the emitted format at each of
        them would be one decision copied seven times, and this codebase
        has already paid for that pattern twice. It also has to stay that
        way: the v1 primitives are pinned by golden vectors shared with
        fortimanager-mcp, so their output cannot change.

        ``domain`` and ``email_local`` come back v1 by an explicit branch
        rather than by falling off the end. They are suffix-marked, so
        their v2 spelling would be a different parse rather than a
        different envelope, and #40 deliberately left them for later. A
        test pins their absence; this branch is what keeps that a decision
        instead of an oversight.

        Raises:
            MaskingError: If the value cannot be masked, unchanged from the
                primitive it delegates to.
        """
        if vtype == "ip":
            # Callers that hold a field type rather than an address family
            # say "ip" and let the engine pick, because the family decides
            # the marker and the tag domain and that is format knowledge.
            vtype = "ipv6" if self._parse_ip(value).version == 6 else "ipv4"
        if vtype in ("ipv4", "ipv6"):
            # A masked IP is a valid IP, so the primitive's output IS the
            # bare ciphertext. This is also the type whose v2 payload stays
            # dotted, which is why the free-text scan needs its guard.
            return self.v2_token(vtype, self.mask_ip(value))
        if vtype == "mac":
            return self.v2_token(vtype, self.mask_mac(value))
        minter = self._V1_MINTERS.get(vtype)
        if minter is not None:
            return self.v2_token(vtype, self._v1_payload(getattr(self, minter)(value)))
        if vtype == "domain":
            return self.mask_domain(value)
        if vtype == "email_local":
            return self.mask_email(value)
        raise MaskingError(f"no minting route for value type: {vtype!r}")

    def _refuse_v1_if_window_closed(self, form: str) -> None:
        """Enforce the v1 deprecation window, or record that v1 is still in use.

        Placed on the two key-id splits rather than on ``unmask_token``'s
        dispatch, because the dispatch is bypassable: ``ArgUnmasker``
        resolves a URL tail by calling ``unmask_url_tail`` directly. Every
        marked v1 token has to pass through one of the splits, so this is
        the choke point that cannot be routed around.

        The unmarked IP and MAC forms deliberately do not reach here. They
        carry no key id and are not v1 *tokens*, they are masked values
        resolved by field context, so there is nothing to refuse.

        While the window is open this logs, because the point of the flag
        is that a deployment can tell when closing it is safe. The form and
        the key id are enough for that, and the payload is never logged,
        which is this module's standing rule.
        """
        if self._accept_v1_tokens:
            if not self._seen_v1_token:
                self._seen_v1_token = True
                logger.info(
                    "v1 masking token accepted (form=%s, key id=%s); the v1 deprecation "
                    "window is open. Close it once no client returns v1 tokens.",
                    form,
                    self._key_id,
                )
            else:
                logger.debug("v1 masking token accepted (form=%s)", form)
            return
        raise MaskingError(
            f"v1 masking token refused: the deprecation window is closed (form={form})"
        )

    def _split_key_id(self, payload: str, token: str) -> str:
        """Split ``<kid>-<ct>``, verify the key id, return the ciphertext."""
        kid, sep, ct = (
            payload[:_KEY_ID_LEN],
            payload[_KEY_ID_LEN : _KEY_ID_LEN + 1],
            payload[_KEY_ID_LEN + 1 :],
        )
        if not _KEY_ID_RE.match(kid.lower()) or sep != "-" or not ct:
            raise MaskingError(f"token carries no key id: {token!r}")
        self._check_key_id(kid.lower(), token)
        self._refuse_v1_if_window_closed("prefix")
        return ct

    def _split_key_id_suffix(self, payload: str, token: str) -> str:
        """Split ``<ct>.<kid>``, verify the key id, return the ciphertext."""
        ct, sep, kid = (
            payload[: -(_KEY_ID_LEN + 1)],
            payload[-(_KEY_ID_LEN + 1) : -_KEY_ID_LEN],
            payload[-_KEY_ID_LEN:],
        )
        if not _KEY_ID_RE.match(kid) or sep != "." or not ct:
            raise MaskingError(f"token carries no key id: {token!r}")
        self._check_key_id(kid, token)
        # Deliberately NOT gated by the v1 deprecation window. The suffix
        # form is domain and email_local, and those two have no v2 envelope
        # by design (they are suffix-marked, so a v2 spelling would be a
        # different parse, and they already carry a marker and a key id --
        # settled on #40). A suffix token is therefore not a legacy
        # encoding waiting to be retired, it is the only encoding those
        # types have ever had, and refusing it refuses this build's own
        # freshly minted output.
        #
        # Measured before changing it: with the window closed, mask_domain
        # produced a token that unmask_domain then refused, in the same
        # process with the same key. That made the window unclosable, since
        # closing it broke domain and email masking outright.
        #
        # If domain/email_local ever gain a v2 envelope, this call has to
        # come back. test_domain_and_email_local_have_no_v2_envelope is what
        # fails first in that case.
        return ct

    def _check_key_id(self, kid: str, token: str) -> None:
        if kid != self._key_id:
            # Key ids are one-way fingerprints, not secrets: naming both
            # sides makes the rotation mismatch diagnosable from the error.
            raise MaskingError(
                f"token was minted under a different masking key "
                f"(token key id {kid!r}, engine key id {self._key_id!r}): {token!r}"
            )
