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
import hashlib
import ipaddress
import os
import re

from ff3 import FF3Cipher

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
}


class MaskingError(Exception):
    """Raised when a value cannot be masked or a token cannot be unmasked."""


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

    def __init__(self, key: str, mask_suffix: str = DEFAULT_MASK_SUFFIX) -> None:
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

    @classmethod
    def from_env(cls, mask_suffix: str = DEFAULT_MASK_SUFFIX) -> "FPEEngine":
        """Build an engine from the ``FAZ_MASKING_KEY`` environment variable.

        Raises:
            MaskingError: If the variable is unset or holds an invalid key.
        """
        key = os.environ.get(MASKING_KEY_ENV, "")
        if not key:
            raise MaskingError(f"{MASKING_KEY_ENV} is not set")
        return cls(key, mask_suffix=mask_suffix)

    @property
    def mask_suffix(self) -> str:
        """Marker suffix used for domain and email tokens."""
        return self._mask_suffix

    @property
    def key_id(self) -> str:
        """4-hex-char one-way fingerprint of the key, embedded in marked tokens."""
        return self._key_id

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
        if addr.version == 4:
            pt = self._hex_ciphers["ipv4"].decrypt(f"{int(addr):08x}")
            return str(ipaddress.IPv4Address(int(pt, 16)))
        pt = self._hex_ciphers["ipv6"].decrypt(f"{int(addr):032x}")
        return str(ipaddress.IPv6Address(int(pt, 16)))

    @staticmethod
    def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        try:
            return ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise MaskingError(f"not a valid IP address: {value!r}") from exc

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
        pt = self._hex_ciphers["mac"].decrypt(self._normalize_mac(token))
        return ":".join(pt[i : i + 2] for i in range(0, 12, 2))

    @staticmethod
    def _normalize_mac(value: str) -> str:
        digits = re.sub(r"[:.\-\s]", "", value.strip().lower())
        if not re.fullmatch(r"[0-9a-f]{12}", digits):
            raise MaskingError(f"not a valid MAC address: {value!r}")
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
            raise MaskingError(f"not a valid email address: {value!r}")
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
        except ValueError as exc:
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
        return ct

    def _check_key_id(self, kid: str, token: str) -> None:
        if kid != self._key_id:
            # Key ids are one-way fingerprints, not secrets: naming both
            # sides makes the rotation mismatch diagnosable from the error.
            raise MaskingError(
                f"token was minted under a different masking key "
                f"(token key id {kid!r}, engine key id {self._key_id!r}): {token!r}"
            )
