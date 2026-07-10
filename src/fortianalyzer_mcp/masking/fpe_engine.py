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
match it):

    email     ``<ct-local>@<ct-domain>.<mask_suffix>``
    domain    ``<ct>.<mask_suffix>``
    hostname  ``host-<ct>``
    username  ``user-<ct>``
    ipv4/ipv6 valid-looking address, FPE over the full 32/128 bits
    mac       valid-looking MAC, FPE over the full 48 bits

``mask_suffix`` defaults to ``masked.invalid`` — the ``.invalid`` TLD is
reserved (RFC 2606), so a leaked token can never resolve to a real host.

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
different positions do not produce identical ciphertext.

The key is a secret (AES-128/192/256 as hex). It must never be logged;
this module never includes key material in exceptions.
"""

import hashlib
import ipaddress
import os
import re

from ff3 import FF3Cipher

# Alphabet for string-typed values (hostnames, usernames, domains, email
# parts). 40 chars -> FF3-1 bounds are minLen 4 / maxLen 36. ``~`` is the
# pad sentinel and must never appear in a real value.
_STR_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-._~"
_PAD_CHAR = "~"

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
    case-insensitive anyway), so unmasking returns the lowercase form.
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
        self._hex_ciphers = {
            vtype: FF3Cipher(key, _derive_tweak(label), radix=16)
            for vtype, label in _TWEAK_LABELS.items()
            if vtype in ("ipv4", "ipv6", "mac")
        }
        self._str_ciphers = {
            vtype: FF3Cipher.withCustomAlphabet(key, _derive_tweak(label), _STR_ALPHABET)
            for vtype, label in _TWEAK_LABELS.items()
            if vtype not in ("ipv4", "ipv6", "mac")
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
        """Reverse :meth:`mask_ip`."""
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
        """Mask a hostname into a ``host-<ct>`` token."""
        return "host-" + self._encrypt_str("hostname", value)

    def unmask_hostname(self, token: str) -> str:
        """Reverse :meth:`mask_hostname`."""
        return self._decrypt_str("hostname", self._strip_prefix(token, "host-"))

    def mask_username(self, value: str) -> str:
        """Mask a user/login name into a ``user-<ct>`` token."""
        return "user-" + self._encrypt_str("username", value)

    def unmask_username(self, token: str) -> str:
        """Reverse :meth:`mask_username`."""
        return self._decrypt_str("username", self._strip_prefix(token, "user-"))

    def mask_domain(self, value: str) -> str:
        """Mask a DNS domain into ``<ct>.<mask_suffix>``."""
        return f"{self._encrypt_str('domain', value)}.{self._mask_suffix}"

    def unmask_domain(self, token: str) -> str:
        """Reverse :meth:`mask_domain`."""
        return self._decrypt_str("domain", self._strip_domain_suffix(token))

    def mask_email(self, value: str) -> str:
        """Mask an email address into ``<ct-local>@<ct-domain>.<mask_suffix>``."""
        local, _, domain = value.strip().partition("@")
        if not local or not domain:
            raise MaskingError(f"not a valid email address: {value!r}")
        return (
            f"{self._encrypt_str('email_local', local)}"
            f"@{self._encrypt_str('domain', domain)}.{self._mask_suffix}"
        )

    def unmask_email(self, token: str) -> str:
        """Reverse :meth:`mask_email`."""
        local, _, domain = token.strip().lower().partition("@")
        if not local or not domain:
            raise MaskingError(f"not a masked email token: {token!r}")
        return (
            f"{self._decrypt_str('email_local', local)}"
            f"@{self._decrypt_str('domain', self._strip_domain_suffix(domain))}"
        )

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
        # Tokens are lowercase by construction, so lowercasing the input is
        # lossless and tolerates a model title-casing a token in prose.
        candidate = token.strip().lower()
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
            return self.unmask_username(candidate)
        return None

    # ------------------------------------------------------------------ #
    # String FPE core (padding + chunking)                               #
    # ------------------------------------------------------------------ #

    def _encrypt_str(self, vtype: str, value: str) -> str:
        cipher = self._str_ciphers[vtype]
        normalized = value.strip().lower()
        if not normalized:
            raise MaskingError(f"cannot mask empty {vtype} value")
        if _PAD_CHAR in normalized:
            raise MaskingError(f"{vtype} value contains the reserved pad character {_PAD_CHAR!r}")
        if any(ch not in _STR_ALPHABET for ch in normalized):
            raise MaskingError(f"{vtype} value contains characters outside the maskable alphabet")
        if len(normalized) < cipher.minLen:
            normalized = normalized.ljust(cipher.minLen, _PAD_CHAR)
        return self._apply_chunked(cipher, vtype, normalized, encrypt=True)

    def _decrypt_str(self, vtype: str, payload: str) -> str:
        cipher = self._str_ciphers[vtype]
        if not payload or any(ch not in _STR_ALPHABET for ch in payload):
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
    def _strip_prefix(token: str, prefix: str) -> str:
        # Lowercased for the same reason as _strip_domain_suffix: tokens are
        # emitted lowercase, so any casing we get back is safe to normalize.
        candidate = token.strip().lower()
        if not candidate.startswith(prefix):
            raise MaskingError(f"not a {prefix}* token: {token!r}")
        return candidate[len(prefix) :]

    def _strip_domain_suffix(self, token: str) -> str:
        candidate = token.strip().lower()
        suffix = "." + self._mask_suffix
        if not candidate.endswith(suffix):
            raise MaskingError(f"token does not carry the {suffix!r} marker: {token!r}")
        return candidate[: -len(suffix)]
