"""Tool-boundary output masking (RFC #40 Phase 1 prototype).

Masks every tool result before it leaves the MCP toward the LLM. There is
no central tool-registration function to hook (tool modules self-register
with module-level ``@mcp.tool(...)`` at import time), so ``install_masking``
patches ``mcp.tool`` on the shared MCPServer instance BEFORE the tool
modules are imported; every subsequently registered tool is wrapped.

Masking runs in two passes over the result, because a value is only safe
to strip out of free text once we know what it masks to:

1. **Structured pass.** Allowlisted keys are masked by type at any nesting
   depth, and composite keys are parsed and masked part by part
   (``groupby1``/``groupby2`` are ``"<field>:<value>"``, ``grpby`` is an
   embedded JSON blob, ``target`` is a list of ``{name, value}``,
   ``devvds`` is ``"<devname>[<vdom>]"``, ``breakdowns`` is
   ``{dimension: [{"value", "hits"}, ...]}`` from ``analyze_policy_traffic``
   and ``query_logs(sample_by=...)``, the dimension name typing each
   bucket's ``"value"``). Every real value masked here is recorded in a
   response-scoped raw-to-token map.
2. **Free-text pass.** ``msg``, ``logdesc``, ``subject``, ``extrainfo``,
   the echoed ``filter`` strings and friends get an in-place scan for
   embedded IPv4s, MACs and emails, then every raw value from pass 1 is
   substituted wherever it appears. That second step is what catches
   hostnames and domains inside prose: you cannot regex a hostname safely,
   but you can replace the exact strings you just masked elsewhere in the
   same response. It also removes the "masked under one key, cleartext two
   keys away" failure that a leak test over live alert records exposed.
   Two keys are handled in this pass rather than the first because their
   values name their own field and a pass-1 token would be scanned twice:
   ``filter_applied``'s compiled entries, and the buckets of a ``breakdowns``
   dimension typed TEXT.

One assumption runs through every pass here: **dict keys are strings.** Each
key-matching site calls ``key.lower()`` unguarded, which holds because a tool
result is JSON-shaped, and JSON has no other kind of key. The two breakdown
handlers do check ``isinstance(dimension, str)`` — not as defence against a
malformed response, but because those particular keys are dimension names a
tool built in-process from caller input, so they never came off the wire.

Fail-closed by construction:

- A value that cannot be masked (outside the FPE alphabet, malformed) is
  replaced with an irreversible keyed placeholder, never passed through
  raw, never logged.
- If masking a whole result fails unexpectedly, the tool returns a
  ``masking_failed`` error envelope and the raw result is withheld.

Because FPE is deterministic, a re-masked echo of an unmasked argument
yields exactly the token the caller sent, so follow-up turns stay
consistent.

This module is the OUTPUT side. Argument unmasking (Phase 2) lives in
``unmask.py`` and is applied by the same registration patch.
IPv6-in-text scanning is not yet handled. Device identity
(``devname``, ``devid``, ``sn``, ``csf``, ``fortigate``, ``devvds``,
``detectkey``) is masked only when ``FAZ_MASK_DEVICE_IDENTITY`` is set, so
by default a masked record still fingerprints the reporting device.
"""

import contextvars
import hashlib
import hmac
import inspect
import ipaddress
import json
import logging
import os
import re
from functools import wraps
from typing import Any
from urllib.parse import unquote

from fortianalyzer_mcp.masking.fields import (
    COMPOSITE_BREAKDOWNS,
    COMPOSITE_DEVICE_VDOM,
    COMPOSITE_FILTER_ENTRIES,
    COMPOSITE_ID_DEVTYPE,
    COMPOSITE_JSON,
    COMPOSITE_PREFIXED,
    COMPOSITE_SOURCE,
    COMPOSITE_TARGET,
    COMPOSITE_URL_FULL,
    COMPOSITE_URL_HOST,
    DEVICE_IDENTITY_TYPES,
    DOMAIN,
    EMAIL,
    FIELD_TYPES,
    HOSTNAME,
    IP,
    IP_HOST_OR_SERIAL,
    IP_OR_HOST,
    MAC,
    OBF_URL_KEY,
    SERIAL,
    SKIP_VALUES,
    TARGET_NAME_TYPES,
    TEXT,
    THREAT_KEY,
    USERNAME,
)
from fortianalyzer_mcp.masking.fpe_engine import (
    MASKING_KEY_ENV,
    FPEEngine,
    MaskingError,
    begin_v2_verification_budget,
)
from fortianalyzer_mcp.masking.unmask import ArgUnmasker

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: The two halves of a v2 envelope, matched around an address the IOC scan
#: found, so the scan can recognise its own output and step over it.
#:
#: A v2 IPv4 token carries its ciphertext as a dotted quad, because a masked
#: IPv4 has to stay a valid IPv4. The free-text scan therefore matches the
#: payload INSIDE the token and re-encrypts it, which leaves the tag bound to
#: a payload that is no longer there: the token stops opening at all and the
#: address is unrecoverable, by us included. IPv6 and MAC payloads went
#: colon-free hex on #40, so neither the IPv4 nor the MAC scan can see them;
#: IPv4 is the one exposed type, and that asymmetry is why this guard is
#: positional rather than a general token pattern.
#:
#: Checked around the match rather than by scanning the text for tokens
#: first: a serial or url ciphertext can itself contain a hyphen, so a
#: lazily-bounded token pattern can end at the wrong hyphen and leave the
#: tail unprotected. Position has no such ambiguity.
#:
#: Residual, and it is the same trade the shape gate already takes: a real
#: address that happens to sit between a marker plus key id and a hyphen
#: plus eight hex digits is left in clear. It has to look exactly like a v2
#: envelope to get there.
#:
#: Three things here are load-bearing, and the first version of this guard
#: got all three wrong. An adversarial pass measured each one.
#:
#: ``(?<![0-9A-Za-z])`` is the left boundary. Without it, any WORD ending in
#: a marker opens an envelope, because the head is only searched for:
#: ``myhost-1234-10.0.0.1-deadbeef`` returned with the address in clear, and
#: so did ``localhost``, ``poweruser``, ``gossip4``, ``tarmac`` and ``unsn``.
#: That is a leak, and it also put this guard at odds with
#: :meth:`FPEEngine.is_v2_shaped`, which rejects all of those. Two
#: definitions of "looks like v2" drifting apart is the bug class this
#: project keeps hitting, so a test pins them equal on whole strings.
#:
#: ``\Z`` rather than ``$``, because ``$`` also matches just before a
#: trailing newline: ``ip4-2a85-\n10.0.0.1-deadbeef`` leaked while the CRLF
#: spelling did not, which is that difference exactly. A genuine token can
#: never contain a newline, so there was nothing to gain from the laxer
#: anchor.
#:
#: Both halves are matched against a BOUNDED window rather than a slice of
#: the text. ``text[:start]`` and ``text[end:]`` each copy the input on
#: every IPv4 match, so a quad-dense log line went quadratic: 3.5 seconds
#: for four thousand addresses, per-match cost doubling on every doubling.
#: Free text is attacker-supplied, so that was a remote CPU-exhaustion
#: primitive rather than a tuning matter. The head is at most ten
#: characters, so a fixed window is all it can ever need.
#: Candidate extractors, NOT the decision. They bracket the widest thing
#: around a matched address that could be a v2 envelope; whether it IS one
#: is then answered by ``FPEEngine.is_own_v2_token``, the same predicate
#: the structured route uses.
#:
#: This shape exists because the previous version made the decision here,
#: with its own looser notion of an envelope, and that divergence leaked a
#: real address twice: the left boundary admitted a hyphen, a dot, an
#: underscore and non-ASCII, so ``my-host-2a85-10.0.0.1-deadbeef`` came
#: back with the address in clear while ``is_v2_shaped`` rejected the same
#: string. Three leaks in this cutover came from two definitions of "looks
#: like v2" drifting apart. There is one definition now, and these
#: patterns only find the text to hand it.
_V2_CANDIDATE_HEAD_RE = re.compile(
    r"(?:ip4|ip6|mac|sn|url|host|user)-[0-9a-f]{4}-\Z", re.IGNORECASE
)
_V2_CANDIDATE_TAIL_RE = re.compile(r"-[0-9a-f]{8}", re.IGNORECASE)

#: Longest head: marker (up to 4) + "-" + key id (4) + "-".
_V2_HEAD_WINDOW = 10


def _v2_envelope_around(engine: Any, text: str, start: int, end: int) -> bool:
    """Is ``text[start:end]`` the payload of a token THIS engine minted?

    Brackets the candidate and then asks the shared predicate. Boundary
    subtleties that used to decide the answer now only widen or narrow the
    candidate, and a wrong guess costs a tag check rather than an address.
    """
    head = _V2_CANDIDATE_HEAD_RE.search(text[max(0, start - _V2_HEAD_WINDOW) : start])
    if head is None:
        return False
    tail = _V2_CANDIDATE_TAIL_RE.match(text, end)
    if tail is None:
        return False
    return bool(engine.is_own_v2_token(text[start - len(head.group(0)) : tail.end()]))


_MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DEVVDS_RE = re.compile(r"^(?P<dev>[^\[\]]+)\[(?P<vdom>[^\[\]]*)\]$")

#: Values shorter than this are not substituted into free text: a two or
#: three character username would match inside unrelated words.
_MIN_SUBSTITUTION_LEN = 4

_PLACEHOLDER_MARK = "masked-unrepresentable-"

#: Dimension names whose flat key is served by a composite handler rather
#: than by a ``FIELD_TYPES`` entry. ``_mask_breakdowns`` has to consult this
#: as well as the type table: a bucket under ``url`` carries exactly what a
#: flat ``url`` carries, and typing it from ``FIELD_TYPES`` alone found
#: nothing and passed it through in clear (#109 review). ``COMPOSITE_TARGET``
#: and ``COMPOSITE_BREAKDOWNS`` are deliberately absent -- neither names a
#: log field, so neither can be a breakdown dimension.
_COMPOSITE_DIMENSIONS: frozenset[str] = frozenset(
    (
        *COMPOSITE_URL_HOST,
        *COMPOSITE_URL_FULL,
        *COMPOSITE_DEVICE_VDOM,
        *COMPOSITE_ID_DEVTYPE,
        *COMPOSITE_PREFIXED,
        *COMPOSITE_JSON,
    )
)

#: Structural shape of a prefix-marked token: ``<marker>-<4-hex-kid>-``.
#: "host-fw01" has no kid group and is a legitimate name, not a token.
#: ``sn`` joined the markers with the serial type (#40). It has to be here
#: and not only in the engine: this shape is what the mutating-tool gate
#: (#108) recognises, so leaving it out would silently stop that gate
#: covering serial tokens.
#: ``ip4``/``ip6``/``mac`` are here for the v2 envelope, which is the first
#: form those three have ever had: v1 emits them bare, so there was nothing
#: to recognise. Adding them at the same time as the format, rather than at
#: the cutover, because the failure is silent in exactly the direction that
#: matters -- the gate would keep passing while covering none of the three
#: types the envelope exists to make detectable.
_TOKEN_PREFIX_SHAPE_RE = re.compile(r"^(?:host|user|url|sn|ip4|ip6|mac)-[0-9a-f]{4}-")


#: Keys that prove a dict is a dvmdb device object, so its ``name`` is the
#: device's name rather than an ADOM's, a report layout's or a device
#: group's. Every one of these is device-only: none appears on an ADOM row
#: (``name``/``desc``/``oid``), a report layout or a group (``name``/
#: ``member``). One is enough -- a record carrying ``sn`` or ``platform_str``
#: is not something else wearing a device's clothes.
_DEVICE_SHAPE_SIBLINGS: frozenset[str] = frozenset(
    {
        "sn",
        "serialno",
        "os_ver",
        "os_type",
        "platform_str",
        "conn_status",
        "dev_status",
        "ha_mode",
        "mr",
        "patch",
    }
)


def _device_name_in(obj: dict[str, Any]) -> str | None:
    """Original spelling of a device-proving ``name`` key, or None.

    ``name`` cannot be typed key-name-globally: dvmdb uses it for a device,
    but it is equally the ADOM key, the report-layout key and the
    device-group key. Masking it everywhere under
    ``FAZ_MASK_DEVICE_IDENTITY`` tokenises ADOM names and *burns* a report
    layout ("Monthly Security Report" is not a valid hostname, so it becomes
    an irreversible placeholder), and with the flag off it would put every
    such string into the keep set, exempting arbitrary values from masking
    elsewhere. The record decides instead, the same way
    ``incident_reporter`` is decided by its siblings (#109 review).
    """
    key = _find_key(obj, "name")
    if key is None or not isinstance(obj[key], str) or not obj[key].strip():
        return None
    if not _DEVICE_SHAPE_SIBLINGS & {k.lower() for k in obj if isinstance(k, str)}:
        return None
    return key


def _find_key(obj: dict[str, Any], name: str) -> str | None:
    """Original spelling of the lowercase ``name`` in ``obj``, or None.

    The composite handlers hand ``_mask_structured`` an override dict it
    looks up with ``key in paired`` against the ORIGINAL keys, so a
    case-insensitive match must give back the key as spelled in ``obj`` or
    the override silently stops applying.
    """
    for key in obj:
        if key.lower() == name:
            return key
    return None


class OutputMasker:
    """Recursive result masker bound to one FPE engine."""

    def __init__(self, engine: FPEEngine, mask_device_identity: bool = False) -> None:
        self._engine = engine
        # Keyed so placeholders are deterministic (correlatable) but not
        # brute-forceable from a leaked transcript. The env var is present
        # because the engine was just built from it.
        self._placeholder_key = os.environ.get(MASKING_KEY_ENV, "").encode()
        self._mask_device_identity = mask_device_identity
        self._field_types = dict(FIELD_TYPES)
        if mask_device_identity:
            self._field_types.update(DEVICE_IDENTITY_TYPES)

    # -- fail-closed primitives ---------------------------------------- #

    def placeholder(self, value: str) -> str:
        """Irreversible, deterministic stand-in for an unmaskable value."""
        digest = hmac.new(self._placeholder_key, value.encode(), hashlib.sha256).hexdigest()[:10]
        return f"{_PLACEHOLDER_MARK}{digest}"

    def _mask_ip_or_host(self, value: str) -> str:
        """Mask a field that holds either an address or a name.

        The token forms stay distinguishable on the way back: a hostname
        token carries the ``host-`` prefix, an IP token parses as an IP.
        """
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            return self._engine.mint("hostname", value)
        return self._engine.mint("ip", value)

    #: FortiGate/FortiAP/FortiSwitch etc. serial shape -- byte-identical to
    #: fortimanager-mcp's DEVICE_SERIAL_PATTERN, since a serial that reaches
    #: this codepath from a live estate looks the same regardless of which
    #: MCP server observed it. Checked before HOSTNAME: real hostnames do
    #: not start with a 2-letter Fortinet product code followed by 10-20
    #: uppercase alphanumerics with no dots or hyphens, so the false-positive
    #: risk of masking a hostname as a serial is effectively nil.
    _SERIAL_SHAPE_RE = re.compile(r"^(FG|FM|FW|FA|FS|FD|FP|FC|FV|PU|PS)[A-Z0-9]{10,20}$")

    def _mask_ip_host_or_serial(self, value: str) -> str:
        """Mask a field that holds an address, a name, or a device serial.

        target[].value under name=="device" is polymorphic: measured
        fixture data shows this slot carries either an endpoint hostname or
        the device's own serial. A serial minted as a hostname loses its
        case (SERIAL exists specifically because of this -- see its
        docstring), which also breaks token correlation with the same
        device's serial appearing elsewhere in the same record under "sn".
        """
        stripped = value.strip()
        try:
            ipaddress.ip_address(stripped)
        except ValueError:
            if self._SERIAL_SHAPE_RE.match(stripped):
                return self._engine.mint("serial", value)
            return self._engine.mint("hostname", value)
        return self._engine.mint("ip", value)

    def _mask_one(self, vtype: str, value: str) -> str:
        try:
            if vtype == IP:
                return self._engine.mint("ip", value)
            if vtype == MAC:
                return self._engine.mint("mac", value)
            if vtype == IP_OR_HOST:
                return self._mask_ip_or_host(value)
            if vtype == IP_HOST_OR_SERIAL:
                return self._mask_ip_host_or_serial(value)
            if vtype == HOSTNAME:
                return self._engine.mint("hostname", value)
            if vtype == SERIAL:
                return self._engine.mint("serial", value)
            if vtype == USERNAME:
                return self._engine.mint("username", value)
            if vtype == DOMAIN:
                return self._engine.mint("domain", value)
            if vtype == EMAIL:
                # from/to are emails in virus/emailfilter logs but plain
                # labels elsewhere; only actual addresses mask as email.
                if "@" in value:
                    return self._engine.mint("email_local", value)
                return self._engine.mint("username", value)
        except MaskingError:
            return self.placeholder(value)
        except Exception:
            # Never let a masking bug leak the raw value. The value itself
            # is deliberately not logged.
            logger.exception("unexpected error masking a %s value; placeholder used", vtype)
            return self.placeholder(value)
        return self.placeholder(value)  # unknown type tag: fail closed

    def _is_kept(self, vtype: str, value: str, keep: frozenset[str]) -> bool:
        """Is ``value`` one the deployment chose to leave readable?

        Exact match first, then case-insensitively for every type except
        USERNAME. The fold is not a convenience: :meth:`FPEEngine._normalize`
        lowercases the value for every other type before encrypting, so two
        spellings of a hostname or a serial are one identity and mask to one
        token. Comparing them case-sensitively here left the token beside the
        clear name, which is the pairing the keep set exists to withhold --
        found live, where device names are routinely uppercase and
        ``urlsplit`` hands back a lowercased host.

        USERNAME is excluded because the engine does not fold it, so two
        spellings really are two principals: a device named ``ADMIN`` must
        not exempt a user called ``admin`` from masking.
        """
        if not keep:
            return False
        if value in keep:
            return True
        if vtype == USERNAME:
            return False
        folded = value.lower()
        return any(folded == kept.lower() for kept in keep)

    def _mask_scalar(
        self,
        vtype: str,
        value: str,
        mapping: dict[str, str] | None = None,
        *,
        keep: frozenset[str],
    ) -> str:
        """Mask one typed value, honouring the keep set.

        ``keep`` is required and keyword-only on purpose. It used to default
        to the empty set, which made forgetting it silent: the value masked,
        nothing raised, and the response printed a token beside the cleartext
        the keep set exists to protect. ``_mask_filter_entries`` was missed
        that way twice over. A required keyword makes the omission a mypy
        error and a TypeError instead.
        """
        if value.strip() in SKIP_VALUES:
            return value
        if vtype == DOMAIN:
            # An HTTP Host header is ``host[:port]`` and a port is not an
            # identifier, so masking the pair whole loses the host's
            # reversibility AND the port's readability: neither half survives
            # as anything useful. ``_mask_url_host`` already splits a URL's
            # host from the rest for the same reason.
            #
            # A numeric ASCII tail after the FIRST colon. Splitting on the
            # last colon was wrong and my first comment claimed a safety it
            # did not have: ``2001:db8::1`` ends in a digit, so it split into
            # a burned ``2001:db8:`` host and a stray ``:1``.
            #
            # Partitioning on the first colon rejects multi-colon values
            # indirectly rather than by counting: an IPv6 literal leaves
            # ``db8::1`` as the tail and the bracketed ``[::1]:8080`` leaves
            # ``:1]:8080``, neither of which is all digits, so both fall
            # through and are handled whole.
            #
            # ``isascii`` matters: ``str.isdigit`` alone accepts Unicode
            # digits, so an Arabic-Indic port would split and echo a tail this
            # code never validated.
            host, sep, port = value.partition(":")
            if sep and host and port.isascii() and port.isdigit() and len(port) <= 5:
                masked_host = self._mask_scalar(vtype, host, mapping, keep=keep)
                return f"{masked_host}:{port}"
        if self._engine.is_own_v2_token(value):
            # Already this layer's own output. Masking it again destroys
            # it, loudly on a typed route that cannot parse a token (an IP
            # field fails closed to an irreversible placeholder) and
            # quietly on one that can (a string cipher wraps the token in
            # another token, which opens to the wrong value). Both are
            # silent to the caller.
            #
            # By SHAPE, matching the gate decision on #40: a value that
            # looks like v2 is committed to v2. Verifying the tag instead
            # would be a third definition of v2-ness in this codebase, and
            # two definitions drifting apart has already produced one leak
            # in the free-text guard above.
            #
            # This funnel is the whole point: every pass-1 route ends here,
            # so the check cannot be forgotten by a new caller the way the
            # keep set was twice.
            return value
        if self._is_kept(vtype, value, keep):
            # A value the deployment chose to leave readable stays readable
            # under every key (#73 item 5). The check lives here rather than
            # at each call site because every pass-1 route ends up here, and
            # a route that forgot it masked the value while ``devname``
            # showed it two keys away -- the token-to-name pairing the keep
            # set exists to withhold. Checking before the mapping write also
            # keeps the value out of pass 2's substitution table.
            return value
        if "," in value:
            # FAZ packs multi-valued fields into one comma-joined string
            # (live example: the dns ``ipaddr`` answer list). Mask each
            # element; an unmaskable element still fails closed on its own.
            # Parts are checked against the keep set individually because the
            # set is itself built by splitting the comma-joined form.
            return ",".join(
                part
                if part.strip() in SKIP_VALUES or not part
                else self._mask_scalar(vtype, part, mapping, keep=keep)
                for part in value.split(",")
            )
        token = self._mask_one(vtype, value)
        if mapping is not None and token != value:
            # Fail-closed placeholders are recorded too (#73 item 4). Pass 2
            # substitutes only what pass 1 recorded, so excluding them left
            # the raw value in the prose beside its own burned key, which is
            # the "masked here, cleartext two keys away" failure the second
            # pass exists to close. A placeholder stays self-identifying by
            # its marker, so a consumer that must tell the two apart still
            # can, exactly as this method does above.
            mapping[value] = token
        return token

    # -- composite keys ------------------------------------------------- #

    def _mask_prefixed(self, value: str, mapping: dict[str, str], keep: frozenset[str]) -> str:
        """``"<fieldname>:<value>"`` (alert ``groupby1``/``groupby2``)."""
        field, sep, raw = value.partition(":")
        if not sep or not raw:
            return value
        vtype = self._field_types.get(field.lower())
        if vtype is None or vtype == TEXT:
            return value
        return f"{field}{sep}{self._mask_scalar(vtype, raw, mapping, keep=keep)}"

    def _mask_json_blob(self, value: str, mapping: dict[str, str], keep: frozenset[str]) -> str:
        """An embedded JSON string (incident ``grpby``)."""
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            # Not JSON after all: at least strip the IOCs a regex can see.
            return self.mask_text(value, mapping, keep)
        return json.dumps(self._mask_structured(parsed, mapping, keep))

    def _mask_device_vdom(self, value: str, mapping: dict[str, str], keep: frozenset[str]) -> str:
        """``"<devname>[<vdom>]"``, comma-joined (fortiview ``devvds``).

        The vdom stays clear, like the flat ``vd`` log field. Only the
        device name is estate identity, so the whole key follows
        ``FAZ_MASK_DEVICE_IDENTITY``.
        """
        if not self._mask_device_identity:
            return value
        out: list[str] = []
        for part in value.split(","):
            match = _DEVVDS_RE.match(part.strip())
            if match is None:
                # Bare device name, or a shape we have not seen: mask whole.
                out.append(self._mask_scalar(HOSTNAME, part, mapping, keep=keep))
                continue
            device = self._mask_scalar(HOSTNAME, match.group("dev"), mapping, keep=keep)
            out.append(f"{device}[{match.group('vdom')}]")
        return ",".join(out)

    def _mask_id_devtype(
        self, key: str, value: str, mapping: dict[str, str], keep: frozenset[str]
    ) -> str:
        """``"<identifier>,<devtype>,<identifier>,<devtype>,..."``
        (fortiview-sources aggregates).

        Each identifier is masked by the type this key maps to, which is
        the type its covered flat twin already uses. Each devtype is an OS
        or product string, the same class as ``srchwvendor`` and
        ``catdesc`` that ``fields.py`` declines by name, so it stays
        readable -- run through ``mask_text`` rather than back verbatim
        only to catch an identifier accidentally embedded in it, same as
        any other free-text field.

        These are aggregating fields: a row covering several endpoints
        comma-joins their pairs, per this field's own docstring in
        ``fields.py``. Only typing the first pair and handing the rest to
        ``mask_text`` -- the previous shape of this function -- caught a
        repeated MAC by accident (``mask_text`` has a MAC regex) but never
        a repeated HOSTNAME (no hostname regex exists, nor should one:
        scanning arbitrary prose for anything hostname-shaped burns
        ordinary text). Walking every pair explicitly and typing each
        identifier by position sidesteps that entirely -- it never needs a
        hostname regex, because it is never guessing which substring is an
        identifier; the comma-delimited shape already says so.

        No comma means a shape we have not seen, so the whole value is
        masked rather than returned untyped, matching what
        ``_mask_device_vdom`` does with a bare device name. An odd number
        of parts (a trailing identifier with no devtype) is the same
        situation for its last pair, so that lone identifier is masked
        as one too rather than left readable or dropped.
        """
        if not value:
            return value
        vtype = COMPOSITE_ID_DEVTYPE[key]
        parts = value.split(",")
        if len(parts) < 2:
            return self._mask_scalar(vtype, value, mapping, keep=keep)
        masked_parts = [
            self._mask_scalar(vtype, part, mapping, keep=keep)
            if i % 2 == 0
            else self.mask_text(part, mapping, keep)
            for i, part in enumerate(parts)
        ]
        return ",".join(masked_parts)

    def _mask_breakdowns(self, value: Any, mapping: dict[str, str], keep: frozenset[str]) -> Any:
        """``{dimension: [{"value": ..., "hits": N}, ...]}`` (#98).

        ``analyze_policy_traffic`` and ``query_logs(sample_by=...)`` both
        return this shape. The dimension name -- the dict key one level up
        from each bucket -- decides the type of that bucket's ``"value"``,
        the same "field decides the paired value's type" rule ``groupby1``
        already applies, just with the field name sitting one level up
        instead of packed into the string.

        Deliberately not a "burn what we do not recognise" handler like
        ``_mask_target``: ``sample_by``/``group_by`` let a caller group on
        almost any field (``port``, ``service``, ``app``, ``proto``, a
        derived dimension with no field type at all), and most of those are
        not identifiers. A dimension absent from the type table -- because
        it is not in ``FIELD_TYPES``, or is a device-identity field and
        ``FAZ_MASK_DEVICE_IDENTITY`` is off -- passes its bucket values
        through untouched rather than being burned to a placeholder. That
        table already merges in ``DEVICE_IDENTITY_TYPES`` only when the flag
        is set (see ``__init__``), so the device-identity keep-set applies to
        a dimension name exactly as it does to a flat field, with no
        separate check needed here.

        A TEXT dimension is skipped here but *not* passed through: its values
        are prose with no scalar type to mask by, so they are scanned in pass
        2 by :meth:`_mask_breakdown_text`, exactly as the same string would be
        under a flat ``msg``/``ui``/``subject`` key. Leaving them to this pass
        was the gap the #109 review found.

        The bucket ``"value"`` goes through :meth:`_mask_entry` under the
        dimension's own name rather than through a ``FIELD_TYPES`` lookup, so
        the rule above holds literally: a bucket value gets exactly what the
        same value gets under a flat key of that name. Typing it from
        ``FIELD_TYPES`` alone missed every composite-served key -- ``url``,
        ``referralurl``, ``http_url``, ``link``, ``devvds`` have no entry
        there -- and passed them through in clear beside the token the same
        host carried elsewhere in the response, with ``hits`` as the join key.
        The ``keep`` check stays wrapped around the call. Since #112
        ``_mask_entry`` refuses a kept value on its typed-scalar path itself,
        so for a typed dimension the two agree; the wrapper is load-bearing
        for a *composite* dimension, whose handlers still do not consult the
        keep set, and a value left clear under one key must never be masked
        under another.

        A shape this handler cannot type -- a non-dict bucket, or a
        ``buckets`` that is not a list -- burns when the dimension IS typed or
        composite, the same fail-closed policy ``_mask_target`` and the URL
        dict branch follow (#104). Under an untyped dimension it still passes
        through: burning there would placeholder every legitimate
        non-identifier breakdown.
        """
        if not isinstance(value, dict):
            return self._mask_structured(value, mapping, keep)
        out: dict[str, Any] = {}
        for dimension, buckets in value.items():
            lowered = dimension.strip().lower() if isinstance(dimension, str) else ""
            vtype = self._field_types.get(lowered)
            handled = (vtype is not None and vtype != TEXT) or lowered in _COMPOSITE_DIMENSIONS
            if not handled:
                out[dimension] = self._mask_structured(buckets, mapping, keep)
                continue
            if not isinstance(buckets, list):
                out[dimension] = self._burn_strings(buckets, keep)
                continue
            masked_buckets: list[Any] = []
            for bucket in buckets:
                if not isinstance(bucket, dict):
                    masked_buckets.append(self._burn_strings(bucket, keep))
                    continue
                entry: dict[str, Any] = {}
                for bkey, bvalue in bucket.items():
                    if bkey.lower() == "value" and isinstance(bvalue, str):
                        entry[bkey] = (
                            bvalue
                            if bvalue in keep
                            else self._mask_entry(lowered, bvalue, mapping, keep)
                        )
                    else:
                        # Today's producers emit only {value, hits}, but a
                        # type-specific branch must preserve the walk for the
                        # shapes it does not consume (#83's lesson): before
                        # this handler existed a typed sibling key masked via
                        # the allowlist walk, and copying it verbatim here
                        # would have quietly re-opened it. `hits` is an int
                        # and passes through _mask_entry untouched.
                        entry[bkey] = self._mask_entry(bkey, bvalue, mapping, keep)
                masked_buckets.append(entry)
            out[dimension] = masked_buckets
        return out

    def _burn_strings(self, value: Any, keep: frozenset[str]) -> Any:
        if isinstance(value, str):
            if value in keep or not value or value.strip() in SKIP_VALUES:
                return value
            return self.placeholder(value)
        if isinstance(value, list | tuple):
            return [self._burn_strings(item, keep) for item in value]
        if isinstance(value, dict):
            # A map-shaped value carries the identifier in the KEY
            # ({"<ip>": {...}}), and no later pass ever scans a key.
            return {
                self._burn_strings(key, keep): self._burn_strings(item, keep)
                for key, item in value.items()
            }
        return value

    #: Every key the schema knows, independent of the device-identity flag.
    #: ``self._field_types`` is the wrong table for the "do we recognise
    #: this name" question: it only gains DEVICE_IDENTITY_TYPES when the
    #: flag is on, so flag-off the name ``devname`` read as unknown and its
    #: KEY burned while its value stayed readable via the keep set. That is
    #: mangled schema on the majority configuration, for no gain.
    _SCHEMA_KEYS: frozenset[str] = frozenset(FIELD_TYPES) | frozenset(DEVICE_IDENTITY_TYPES)

    @staticmethod
    def _typeable(value: Any) -> bool:
        """Can ``_mask_entry`` actually type this shape?

        Its typed and composite branches are all gated on ``str`` or on a
        list of them. Anything else reaches the ``_mask_structured`` tail,
        which is the allowlist walk this whole function exists to avoid
        trusting.
        """
        if isinstance(value, str):
            return True
        return isinstance(value, list) and all(isinstance(item, str) for item in value)

    def _burn_and_record(self, value: Any, mapping: dict[str, str], keep: frozenset[str]) -> Any:
        """Burn, and record what was burned so pass 2 can follow it.

        ``_burn_strings`` takes no mapping, so a burned value's twin in a
        free-text field rode out in clear: measured, ``{"groupby1":
        {"srcuser": "walter.white"}, "msg": "blocked walter.white"}`` burned
        the map and left the name in ``msg``. Recording raw -> placeholder
        lets the pass-2 substitution replace it there too, which is the
        same principle ``_mask_scalar`` already documents.
        """
        if isinstance(value, str):
            burned = self._burn_strings(value, keep)
            if isinstance(burned, str) and burned != value:
                mapping.setdefault(value, burned)
            return burned
        if isinstance(value, list | tuple):
            return [self._burn_and_record(item, mapping, keep) for item in value]
        if isinstance(value, dict):
            return {
                self._burn_and_record(key, mapping, keep): self._burn_and_record(
                    item, mapping, keep
                )
                for key, item in value.items()
            }
        return value

    def _mask_composite_container(
        self, key: str, value: Any, mapping: dict[str, str], keep: frozenset[str]
    ) -> Any:
        """Re-enter ``_mask_entry`` under the SAME key for every element.

        For these kinds the key is the only thing that can type the
        payload, so a container must not be handed to ``_mask_structured``:
        that route walks by allowlist, knows none of these inner names,
        and has already lost the key by the time it sees the value. That
        is how a list under ``devvds`` returned device names in clear with
        ``FAZ_MASK_DEVICE_IDENTITY`` on, and the map form had no arm at
        all so it reached the same route (#73 item 1).

        Recursing rather than burning is what keeps the flag honest: the
        per-kind handlers already decide what the deployment is entitled
        to read (``_mask_device_vdom`` returns its argument untouched with
        the flag off), while ``_burn_strings`` would mask an estate name
        the flag-off deployment sees in clear under the string form of the
        same key. It also means each kind's own dict policy still applies
        one level down, so a map inside a list under ``url`` still burns.

        Keys are masked as well as values: no later pass ever scans a key,
        so a map keyed by the identifier hands it over as the key itself.

        COMPOSITE_JSON's dict form is the one exception to "re-enter under
        the same key": a native dict here can be either shape _mask_json_blob
        would otherwise have to parse out of a string -- an already-parsed
        payload, whose own field names (not the outer key) type its
        contents, or a wrapper whose values are themselves JSON-string
        blobs one level down (the same shape #117's tests keep under the
        outer key). Re-entering everything under the outer key asked
        _mask_entry to type the whole dict as e.g. "grpby", which only the
        str-only _mask_json_blob can read; every field inside a parsed
        payload fell through unmasked. Measured:
        {"grpby": [{"dstendpoint": "web-01.corp.local"}]} (a list containing
        one such dict) leaked the hostname in clear while the JSON-STRING
        form of the identical payload correctly masked it.

        Distinguishing the two shapes per inner value rather than per whole
        dict: a string value that parses as JSON is a nested blob and goes
        to _mask_json_blob (preserves #117's wrapper-of-blobs shape); any
        other value belongs to this dict's own structure and is typed by
        its own inner key via _mask_entry, not the outer composite key --
        that inner-key dispatch is what correctly masks a bare
        "dstendpoint": "web-01.corp.local" pair, typed rather than caught
        incidentally by mask_text's IP/MAC/email-only regexes. A nested
        dict/list value recurses through _mask_structured so its own keys
        keep typing it. A list of JSON-string elements is unaffected: each
        string element still re-enters under the outer key one level up
        and dispatches to _mask_json_blob exactly as before.
        """
        if isinstance(value, list | tuple):
            return [self._mask_entry(key, item, mapping, keep) for item in value]
        if key in COMPOSITE_JSON:
            out: dict[Any, Any] = {}
            for inner_key, item in value.items():
                masked_key = self._mask_entry(key, inner_key, mapping, keep)
                if isinstance(item, str):
                    try:
                        json.loads(item)
                    except (ValueError, TypeError):
                        out[masked_key] = self._mask_entry(inner_key, item, mapping, keep)
                    else:
                        out[masked_key] = self._mask_json_blob(item, mapping, keep)
                else:
                    out[masked_key] = self._mask_structured(item, mapping, keep)
            return out
        return {
            self._mask_entry(key, inner_key, mapping, keep): self._mask_entry(
                key, item, mapping, keep
            )
            for inner_key, item in value.items()
        }

    def _mask_composite_map(self, value: Any, mapping: dict[str, str], keep: frozenset[str]) -> Any:
        """Mask a map under a composite key: allowlist what it knows, burn the rest.

        A dict-shaped group-by used to fall through to the plain allowlist
        walk, on the reasoning that the walk would type it by its inner
        keys. That holds only when those keys happen to be allowlisted.
        Measured on 2.13.0 (``cfc2585``), same engine, RFC 5737 values:

            {"groupby1": {"srcip": "192.0.2.90"}}     -> masked
            {"groupby1": {"a": "srcip:192.0.2.90"}}   -> LEAK, verbatim
            {"groupby1": {"a": "192.0.2.90"}}         -> LEAK, verbatim
            {"groupby1": [{"a": "srcip:192.0.2.90"}]} -> LEAK, verbatim
            {"groupby1": {"192.0.2.90": 5}}           -> LEAK, in the key

        Recognising the key is not enough on its own. ``_mask_entry``'s
        branches are shape-gated, so a known key holding a CONTAINER fell
        straight back into the walk: ``{"srcip": {"nested": "192.0.2.90"}}``
        leaked verbatim. A known key is therefore only handed on when its
        value is a shape ``_mask_entry`` can actually type.

        The working half is kept and everything else fails closed, rather
        than burning the whole map the way the URL composites and ``target``
        do. Those have no slot their handler can type at all; a group-by map
        does for the keys the allowlist covers, and burning those would cost
        a reversible mask for nothing.
        """
        if not isinstance(value, dict):
            return self._burn_and_record(value, mapping, keep)
        out: dict[Any, Any] = {}
        for key, item in value.items():
            known = isinstance(key, str) and (
                key.lower() in self._SCHEMA_KEYS or key.lower() in _COMPOSITE_DIMENSIONS
            )
            if known and self._typeable(item):
                out[key] = self._mask_entry(key, item, mapping, keep)
            elif known:
                # Name recognised, shape not. Keep the name, burn the value.
                out[key] = self._burn_and_record(item, mapping, keep)
            else:
                # Unknown key: neither it nor its value can be typed, so
                # both burn. The key burns too because a group-by map can
                # carry the identifier there ({"192.0.2.90": 5}).
                out[self._burn_and_record(key, mapping, keep)] = self._burn_and_record(
                    item, mapping, keep
                )
        return out

    def _mask_target(
        self, value: list[Any], mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> list[Any]:
        """``[{"name": "ip", "value": "..."}]`` (alert ``target``).

        A value in ``keep`` is the reporting estate's own identity (it
        appears under a device-identity key elsewhere in this response,
        and the deployment left device identity unmasked): masking it
        here while ``devid`` shows it in clear would hand out the
        token-to-serial pair. Live 8.0.0 alerts do exactly this — the
        appliance serial arrives as a ``device`` target.

        Unknown target names fail closed by burning string content because
        there is no reliable type for reversible masking. So does a whole
        ``target`` that is not a list, an entry that is not a dict, and a
        map-shaped ``value`` whose key carries the identifier. An entry
        that IS a dict but carries neither ``name`` nor ``value`` burns
        whole for the same reason: with no slot to type it by, the
        identifier is parked in the entry's own key, which the allowlist
        walk would copy through in clear (#73).
        """
        out: list[Any] = []
        for item in value:
            if not isinstance(item, dict):
                # No name/value pair to type the entry by: burn it like an
                # unknown target name. The allowlist pass returns a bare
                # string leaf unchanged, which is fail-open here.
                out.append(self._burn_strings(item, keep))
                continue
            name: Any = ""
            raw: Any = None
            has_name = False
            has_value = False
            for key, item_value in item.items():
                lowered = key.lower()
                if lowered == "name":
                    name = item_value
                    has_name = True
                elif lowered == "value":
                    raw = item_value
                    has_value = True
            if not has_name and not has_value:
                out.append(self._burn_strings(item, keep))
                continue
            vtype = TARGET_NAME_TYPES.get(str(name).lower())
            if vtype is None:
                masked_value = self._burn_strings(raw, keep)
            elif isinstance(raw, str):
                masked_value = self._mask_scalar(vtype, raw, mapping, keep=keep)
            elif isinstance(raw, list | tuple):
                masked_value = [
                    self._mask_scalar(vtype, elem, mapping, keep=keep)
                    if isinstance(elem, str)
                    else self._burn_strings(elem, keep)
                    for elem in raw
                ]
            elif isinstance(raw, dict):
                masked_value = self._burn_strings(raw, keep)
            else:
                masked_value = raw

            entry: dict[str, Any] = {}
            for key, item_value in item.items():
                lowered = key.lower()
                if lowered == "name":
                    # A label is a short string like "ip" or "device". Any
                    # other shape is not a label, so its content is burned
                    # rather than echoed: nothing else scans this slot.
                    entry[key] = (
                        item_value
                        if isinstance(item_value, str)
                        else self._burn_strings(item_value, keep)
                    )
                elif lowered == "value":
                    entry[key] = masked_value
                elif lowered == "asset_value":
                    # asset_value repeats the identifier on some targets and
                    # carries an internal id on others. The id case is a bare
                    # number; a differing non-numeric string is a second
                    # identifier for the same asset, so it gets the entry's
                    # own type, and with no type to mask by it burns like the
                    # value did (#73). Differing containers burn whole.
                    if item_value == raw:
                        entry[key] = masked_value
                    elif isinstance(item_value, str):
                        if item_value.isdigit():
                            entry[key] = item_value
                        elif vtype is None:
                            entry[key] = self._burn_strings(item_value, keep)
                        else:
                            entry[key] = self._mask_scalar(vtype, item_value, mapping, keep=keep)
                    elif isinstance(item_value, list | tuple | dict):
                        entry[key] = self._burn_strings(item_value, keep)
                    else:
                        entry[key] = item_value
                else:
                    entry[key] = self._mask_entry(key, item_value, mapping, keep)
            out.append(entry)
        return out

    # -- free-text IOC scan --------------------------------------------- #

    def mask_text(
        self,
        text: str,
        mapping: dict[str, str] | None = None,
        keep: frozenset[str] = frozenset(),
    ) -> str:
        """Mask embedded IPv4/MAC/email IOCs, then any known raw value."""

        def ip_sub(m: re.Match[str]) -> str:
            candidate = m.group(0)
            if _v2_envelope_around(self._engine, text, m.start(), m.end()):
                # Our own output. Re-encrypting the payload would leave the
                # tag signing a value that is no longer there.
                return candidate
            try:
                ipaddress.IPv4Address(candidate)
            except ValueError:
                return candidate  # e.g. 999.1.1.1 or a dotted version string
            try:
                return self._engine.mint("ip", candidate)
            except MaskingError:
                return self.placeholder(candidate)

        def mac_sub(m: re.Match[str]) -> str:
            try:
                return self._engine.mint("mac", m.group(0))
            except MaskingError:
                return self.placeholder(m.group(0))

        def email_sub(m: re.Match[str]) -> str:
            try:
                return self._engine.mint("email_local", m.group(0))
            except MaskingError:
                return self.placeholder(m.group(0))

        out = _IPV4_RE.sub(ip_sub, text)
        out = _MAC_RE.sub(mac_sub, out)
        out = _EMAIL_RE.sub(email_sub, out)
        return self._substitute_known(out, mapping, keep)

    def _substitute_known(
        self,
        text: str,
        mapping: dict[str, str] | None,
        keep: frozenset[str] = frozenset(),
    ) -> str:
        """Replace values that were masked elsewhere in this response.

        Hostnames and domains cannot be recognized by pattern, but they can
        be recognized by identity: a value masked in a structured field of
        the same response is the same identifier wherever it appears in
        prose, and gets the same token. Longest first, so a domain is not
        partially rewritten by one of its own labels.
        Matching is case-insensitive: hostnames, domains and emails are
        case-insensitive identifiers and mask to the same token whatever
        their spelling, so an echo that re-cases one is the same value.
        The exact spelling still wins the token lookup, because usernames
        are case-sensitive principals and ``Admin``/``admin`` must keep
        their own tokens when both were masked. One alternation in one
        pass, so a token already substituted is never re-scanned.
        """
        if not mapping:
            return text
        raws = [
            raw
            for raw in sorted(mapping, key=len, reverse=True)
            # A value the deployment chose to leave readable stays readable in
            # prose too (#73 item 5). Some composite key may still have masked
            # it into ``mapping`` on the way past; substituting it here would
            # print a token for a name shown in clear two keys away, which is
            # the pairing the keep set exists to withhold.
            if len(raw) >= _MIN_SUBSTITUTION_LEN and raw not in keep
        ]
        if not raws:
            return text
        # An inexact (case-only) match may reuse a token only when exactly one
        # raw owns that folded form. Usernames are case-sensitive principals,
        # so two of them differing only in case make a third spelling
        # ambiguous, and picking either token would resolve to the wrong
        # identity. Ambiguous spellings fail closed to a placeholder instead.
        folded: dict[str, str] = {}
        ambiguous: set[str] = set()
        for raw in raws:
            key = raw.casefold()
            if key in folded and folded[key] != mapping[raw]:
                ambiguous.add(key)
            folded.setdefault(key, mapping[raw])
        # ``(?ai:...)`` scopes both flags to the alternation, and both are
        # load-bearing. Without the scoping, ``re.IGNORECASE`` also widens
        # the boundary look-arounds, because the ASCII class ``[A-Za-z]``
        # then additionally matches the characters that case-fold into it,
        # so an identifier sitting next to one is handed back in clear.
        # Without ``a``, case-insensitivity follows full Unicode folding,
        # which equates U+017F/U+212A/U+0130/U+0131 with ASCII letters: the
        # regex matches a spelling that ``casefold`` then fails to look up,
        # and a known value degrades to an irreversible placeholder. Re-casing
        # an identifier means ASCII case, so ASCII folding is what we want.
        pattern = re.compile(
            r"(?<![A-Za-z0-9._-])(?ai:"
            + "|".join(re.escape(raw) for raw in raws)
            + r")(?![A-Za-z0-9._-])"
        )

        def swap(match: re.Match[str]) -> str:
            found = match.group(0)
            exact = mapping.get(found)
            if exact is not None:
                return exact
            key = found.casefold()
            if key in ambiguous:
                return self.placeholder(found)
            return folded.get(key) or self.placeholder(found)

        return pattern.sub(swap, text)

    # -- the two passes -------------------------------------------------- #

    def mask_result(self, obj: Any) -> Any:
        """Mask a tool result: structured pass, then free-text pass."""
        mapping: dict[str, str] = {}
        keep = frozenset() if self._mask_device_identity else self._device_identity_values(obj)
        staged = self._mask_structured(obj, mapping, keep)
        return self._mask_free_text(staged, mapping, keep)

    def _device_identity_values(self, obj: Any) -> frozenset[str]:
        """Device-identity values present in this response, pre-collected.

        With ``FAZ_MASK_DEVICE_IDENTITY`` off these stay readable by
        design, so any handler that can reach the same value under another
        key (live 8.0.0 alerts carry the reporting appliance's serial in
        ``target[].value``) must leave it clear too. Masking it in one
        place while ``devid`` shows it two keys away is not privacy, it is
        a token-to-serial correlation gift.

        A device-identity key may carry a list of names rather than one
        string: ``devs`` on an alert's ``subject_details`` is list-valued,
        and until it was handled here a device named only there stayed
        clear under ``devs`` while the same name masked inside ``target``,
        which is the pairing this set exists to prevent.

        The comma split applies to the string form ONLY. A string is split
        because FAZ joins aggregated device names into one value
        (``fortigate`` on a multi-device fortiview row), and every part is
        then a device name. A list is already that split form, so
        splitting its elements again would add nothing and would widen the
        one hazard this set has: whatever lands in it is exempted from
        masking inside ``target``, so a value carrying a comma exempts each
        part independently of whether that part names a device.
        """
        out: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                shaped = _device_name_in(node)
                if shaped is not None:
                    out.add(node[shaped].strip())
                for key, value in node.items():
                    if key.lower() in DEVICE_IDENTITY_TYPES:
                        if isinstance(value, str):
                            out.update(part.strip() for part in value.split(","))
                        elif isinstance(value, list | tuple):
                            # String elements are taken whole; anything else
                            # (a dict nesting devname deeper) is walked, as
                            # every non-string value already was before the
                            # list form was handled here.
                            for item in value:
                                if isinstance(item, str):
                                    out.add(item.strip())
                                else:
                                    walk(item)
                        else:
                            walk(value)
                    elif key.lower() in COMPOSITE_DEVICE_VDOM and isinstance(value, str):
                        for part in value.split(","):
                            match = _DEVVDS_RE.match(part.strip())
                            out.add(match.group("dev") if match else part.strip())
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(obj)
        return frozenset(v for v in out if v)

    def _mask_structured(
        self, obj: Any, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> Any:
        """Pass 1: mask allowlisted and composite keys, record raw -> token."""
        if isinstance(obj, dict):
            paired = self._mask_threat_pair(obj, mapping, keep)
            paired.update(self._mask_incident_reporter(obj, mapping, keep))
            paired.update(self._mask_indicator_pair(obj, mapping, keep))
            paired.update(self._mask_device_name(obj, mapping, keep))
            return {
                key: paired[key] if key in paired else self._mask_entry(key, value, mapping, keep)
                for key, value in obj.items()
            }
        if isinstance(obj, list):
            return [self._mask_structured(item, mapping, keep) for item in obj]
        return obj

    def _mask_device_name(
        self, obj: dict[str, Any], mapping: dict[str, str], keep: frozenset[str]
    ) -> dict[str, str]:
        """``name``: masked only when the record proves it a device object.

        Device identity follows ``FAZ_MASK_DEVICE_IDENTITY``, so with the
        flag off this returns nothing and the value additionally joins the
        keep set (see :meth:`_device_identity_values`), which is what stops
        the same name masking under ``target[].value`` two keys away. With
        the flag on it carries the identical token its ``devname`` sibling
        carries, because both go through ``_mask_scalar(HOSTNAME, ...)``.

        See :func:`_device_name_in` for why the shape, not the key name,
        decides.
        """
        if not self._mask_device_identity:
            return {}
        key = _device_name_in(obj)
        if key is None:
            return {}
        return {key: self._mask_scalar(HOSTNAME, obj[key], mapping, keep=keep)}

    def _mask_incident_reporter(
        self, obj: dict[str, Any], mapping: dict[str, str], keep: frozenset[str]
    ) -> dict[str, str]:
        """``incident_reporter``: masked only when the record proves it a username.

        The field is polymorphic — a username on manually raised incidents,
        an alert id on auto-raised ones — so typing it outright would
        corrupt alert ids. But the username case is decidable from the
        record itself: when the value equals the sibling ``reporter`` or
        ``lastuser`` (both masked as usernames), it is the same principal
        and must carry the same token; leaving it clear un-masks the
        sibling verbatim (found live by the flag-on round on both boxes).
        Any other value is an id or a principal we cannot prove, and stays
        untouched as before.
        """
        key = _find_key(obj, "incident_reporter")
        if key is None:
            return {}
        value = obj[key]
        if not isinstance(value, str) or not value.strip() or value.strip() in SKIP_VALUES:
            return {}
        siblings = tuple(
            obj[sib]
            for sib in (_find_key(obj, "reporter"), _find_key(obj, "lastuser"))
            if sib is not None
        )
        if value not in siblings:
            return {}
        return {key: self._mask_scalar(USERNAME, value, mapping, keep=keep)}

    def _mask_indicator_pair(
        self, obj: dict[str, Any], mapping: dict[str, str], keep: frozenset[str]
    ) -> dict[str, str]:
        """SOAR ``value``/``type``: the IOC itself, typed by its sibling.

        ``get_indicator_enrichment`` and ``get_linked_indicators`` return
        the indicator under the key ``value``, which is far too generic to
        allowlist outright: the same name carries a severity band, a count
        and a config setting elsewhere in the API, and typing it globally
        would mask ``"high"`` as a hostname. The sibling ``type`` decides
        instead, exactly as ``obf_url`` decides for ``threat`` -- SOAR
        writes it on every indicator row and it names the value's class.

        Only IP, Domain and URL are recognised, which is the set the reader
        tools accept. Any other ``type`` (or none) leaves ``value`` alone,
        so the generic use of the name is untouched.
        """
        key = _find_key(obj, "value")
        type_key = _find_key(obj, "type")
        if key is None or type_key is None:
            return {}
        value = obj[key]
        if not isinstance(value, str) or not value.strip() or value.strip() in SKIP_VALUES:
            return {}
        kind = obj[type_key]
        if not isinstance(kind, str):
            return {}
        lowered = kind.strip().lower()
        if lowered == "ip":
            return {key: self._mask_scalar(IP, value, mapping, keep=keep)}
        if lowered == "domain":
            return {key: self._mask_scalar(DOMAIN, value, mapping, keep=keep)}
        if lowered == "url":
            return {key: self._mask_url_full(value, mapping, keep)}
        return {}

    def _mask_threat_pair(
        self, obj: dict[str, Any], mapping: dict[str, str], keep: frozenset[str]
    ) -> dict[str, str]:
        """fortiview ``threat``/``obf_url``: masked together, as domains (#40).

        ``obf_url`` is populated exactly when ``threat`` holds a browsable
        web domain (it is the ``[dot]``-escaped twin of the same value) and
        is empty on every signature, filename and anomaly row — verified
        across both reference estates on the RFC thread. The sibling, not a
        logtype table or a shape test, decides: ``logtype`` does not
        discriminate (domains arrive as traffic rows on one estate), and
        malware rows carry dotted filenames a shape test would misread.

        Non-empty ``obf_url``: mask ``threat`` as a domain, and unescape,
        mask and re-escape ``obf_url`` so the pair stays consistent
        (deterministic FPE makes the two tokens twins again). The model
        should hand the ``threat`` token back for queries; the re-escaped
        ``obf_url`` form stays display-only, like the raw field it defangs.
        Empty ``obf_url``: leave ``threat`` clear, its analytic value
        (signature or filename) intact.

        Documented residual (fail-open): a row carrying a domain ``threat``
        with an empty ``obf_url`` would leak that domain. Neither estate
        shows such a row and the field exists precisely to defang browsable
        objects; the leak test carries a tripwire assertion so a live
        counterexample fails a test instead of leaking silently.
        """
        obf_key = _find_key(obj, OBF_URL_KEY)
        if obf_key is None:
            return {}
        obf = obj[obf_key]
        if not isinstance(obf, str) or not obf.strip() or obf.strip() in SKIP_VALUES:
            return {}
        out: dict[str, str] = {}
        token = self._mask_scalar(DOMAIN, obf.replace("[dot]", "."), mapping, keep=keep)
        escaped = token.replace(".", "[dot]")
        if _PLACEHOLDER_MARK not in token and escaped != obf:
            # Catch the escaped raw form in prose too; the unescaped form
            # is already in the mapping via _mask_scalar.
            mapping[obf] = escaped
        out[obf_key] = escaped
        threat_key = _find_key(obj, THREAT_KEY)
        if threat_key is not None:
            threat = obj[threat_key]
            if isinstance(threat, str) and threat.strip() and threat.strip() not in SKIP_VALUES:
                out[threat_key] = self._mask_scalar(DOMAIN, threat, mapping, keep=keep)
        return out

    def _mask_url_host(self, value: str, mapping: dict[str, str], keep: frozenset[str]) -> str:
        """``http_url`` (alert ``event_details``): mask the HOST component only.

        Live alerts carry the browsed destination as a full URL
        (``https://mask.example.com/``) — the host is the identifier the
        flag-on estate smoke found leaking, while scheme, path and query
        are request mechanics. The host masks with the same IP-or-host
        logic as the flat ``host_name`` field on the same record, so both
        carry the same token. Path/query segments that embed identifiers
        remain a documented residual of the deferred full-URL token design.
        """
        from urllib.parse import urlsplit

        try:
            parts = urlsplit(value.strip())
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            return self.placeholder(value)
        if "@" in parts.netloc:
            # Credentials inside the URL are themselves an identifier;
            # rare enough to fail closed on the whole value.
            return self.placeholder(value)
        if not host:
            # Not a parseable URL: the free-text scan still catches
            # embedded IOCs and values masked elsewhere in this response.
            return self.mask_text(value, mapping, keep)
        if self._is_kept(IP_OR_HOST, host, keep):
            # ``urlsplit`` lowercased the host, and this handler masks nothing
            # else, so hand the value back untouched rather than a case-folded
            # copy of a name the response shows in clear elsewhere.
            return value
        masked_host = self._mask_scalar(IP_OR_HOST, host, mapping, keep=keep)
        if ":" in masked_host:  # IPv6 literal: re-bracket
            masked_host = f"[{masked_host}]"
        netloc = f"{masked_host}:{port}" if port is not None else masked_host
        return parts._replace(netloc=netloc).geturl()

    def _mask_url_full(self, value: str, mapping: dict[str, str], keep: frozenset[str]) -> str:
        """``url``/``referralurl``: host in place, tail sealed (#40 decision).

        The host masks exactly like :meth:`_mask_url_host` (same guards,
        same token as a sibling ``host_name`` for hostname values). The
        raw remainder after ``scheme://netloc`` — taken verbatim, so ``?``
        and ``#`` appear only when actually present — seals into a single
        reversible ``url-<kid>-<ct>`` path segment. A bare ``/`` goes
        through the token path so ``…/h`` and ``…/h/`` stay distinct;
        only a truly empty remainder short-circuits. Carry-and-reverse:
        substring search inside the tail is an accepted, documented loss.
        """
        from urllib.parse import unquote, urlsplit

        stripped = value.strip()
        try:
            parts = urlsplit(stripped)
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            return self.placeholder(value)
        if "@" in parts.netloc:
            # Credentials inside the URL are themselves an identifier;
            # a reversible userinfo token would hand back a recoverable
            # secret, so the whole value fails closed (#40 decision).
            return self.placeholder(value)
        if not host:
            if not stripped or stripped in SKIP_VALUES:
                return value
            # No parseable host: the live webfilter shape (whole URL
            # percent-encoded, scheme as ``%3A%2F%2F``) and the classic
            # schemeless log shapes (``www.example.com/uri``, ``/uri``,
            # ``example.com:8080/x`` where urlsplit reads the host as the
            # scheme) all land here, and the free-text fallback leaked
            # them — the flag-on live round caught the encoded form, the
            # post-open adversarial review the schemeless ones. Seal the
            # entire value as one reversible url token; percent-encoded
            # userinfo (``%40`` before the first encoded slash boundary)
            # still fails closed per the credentials decision.
            decoded_head = unquote(stripped).partition("://")[2] or unquote(stripped)
            if "@" in decoded_head.partition("/")[0]:
                return self.placeholder(value)
            try:
                return self._engine.mint("url_tail", stripped)
            except MaskingError:
                return self.placeholder(value)
        if self._is_kept(IP_OR_HOST, host, keep):
            # Host stays as the response spells it; the tail still seals.
            netloc = parts.netloc
        else:
            masked_host = self._mask_scalar(IP_OR_HOST, host, mapping, keep=keep)
            if ":" in masked_host:  # IPv6 literal: re-bracket
                masked_host = f"[{masked_host}]"
            netloc = f"{masked_host}:{port}" if port is not None else masked_host
        prefix = f"{parts.scheme}://" if parts.scheme else "//"
        # Anchor the netloc search after the ``//`` authority marker: from
        # position 0 a single-letter host matches inside the scheme
        # ("https://h") and mis-slices the tail. urlsplit also strips
        # tab/CR/LF (bpo-43882), so the parsed netloc may not exist in the
        # raw string at all; that fails closed instead of raising.
        try:
            anchor = stripped.index("//") + 2
            tail = stripped[stripped.index(parts.netloc, anchor) + len(parts.netloc) :]
        except ValueError:
            return self.placeholder(value)
        if not tail:
            return f"{prefix}{netloc}"
        try:
            token = self._engine.mint("url_tail", tail)
        except MaskingError:
            return self.placeholder(value)
        return f"{prefix}{netloc}/{token}"

    def _mask_entry(
        self, key: str, value: Any, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> Any:
        lowered = key.lower()
        if lowered in COMPOSITE_PREFIXED and isinstance(value, str):
            return self._mask_prefixed(value, mapping, keep)
        if lowered in COMPOSITE_PREFIXED and isinstance(value, list):
            # list-valued group-bys are a normal FAZ variation (#73): each
            # element gets the same prefixed treatment the string form gets.
            return [
                self._mask_prefixed(item, mapping, keep)
                if isinstance(item, str)
                else self._mask_composite_map(item, mapping, keep)
                for item in value
            ]
        if lowered in COMPOSITE_PREFIXED and isinstance(value, dict):
            return self._mask_composite_map(value, mapping, keep)
        if lowered in COMPOSITE_JSON and isinstance(value, str):
            return self._mask_json_blob(value, mapping, keep)
        if lowered in COMPOSITE_JSON and isinstance(value, list | dict):
            # A list value here used to fall through every typed branch to
            # _mask_structured with no key context, which cannot identify
            # bare strings as JSON blobs and returned them verbatim. The
            # map form had no arm at all and reached the same route.
            return self._mask_composite_container(lowered, value, mapping, keep)
        if lowered in COMPOSITE_URL_HOST and isinstance(value, str):
            return self._mask_url_host(value, mapping, keep)
        if lowered in COMPOSITE_URL_HOST and isinstance(value, list):
            # same list convention the typed fields handle below
            return self._mask_composite_container(lowered, value, mapping, keep)
        if lowered in COMPOSITE_URL_FULL and isinstance(value, str):
            return self._mask_url_full(value, mapping, keep)
        if lowered in COMPOSITE_URL_FULL and isinstance(value, list):
            # same list convention the typed fields handle below
            return self._mask_composite_container(lowered, value, mapping, keep)
        if (lowered in COMPOSITE_URL_HOST or lowered in COMPOSITE_URL_FULL) and isinstance(
            value, dict
        ):
            # A map under a URL key has no slot the URL handlers can type,
            # and the allowlist walk knows none of its inner keys, so the
            # destination would ride through in clear (#73). Fail closed on
            # the whole shape, same policy as a non-list target below. The
            # cost is the same too: any analytic structure a producer put
            # there burns rather than round-tripping.
            return self._burn_strings(value, keep)
        if (
            lowered in COMPOSITE_SOURCE
            and isinstance(value, list)
            and any(isinstance(item, dict) for item in value)
        ):
            # Gated on the ELEMENT type, not just on being a list, because
            # "source" has two live shapes and only one of them is
            # target's. The alert surface sends [{"name": ..., "value":
            # ...}], which carries an identifier. The UEBA endpoint
            # surface sends a list of bare detection-method labels, and
            # _mask_target burns every entry that is not a dict, so
            # claiming the whole list destroyed them (measured live: 152
            # of 394 endpoint records, 16 distinct label values, burned
            # irreversibly with the device-identity flag off).
            #
            # Everything else keeps the ordinary allowlist treatment, for
            # the reason in fields.py: "source" is a generic name and this
            # key cannot afford target's burn-by-default.
            return self._mask_target(value, mapping, keep)
        if lowered in COMPOSITE_TARGET:
            if isinstance(value, list):
                return self._mask_target(value, mapping, keep)
            # Any other shape has no entries to type from. A scalar would
            # reach the generic tail and be returned verbatim; a container
            # would be walked by the allowlist, which masks the keys it
            # knows and returns everything else in clear. Fail closed on
            # the whole shape rather than depend on what the allowlist
            # happens to cover. The cost is real: a container whose keys
            # are allowlisted was masked reversibly before and now burns.
            return self._burn_strings(value, keep)
        if lowered in COMPOSITE_ID_DEVTYPE and isinstance(value, str):
            return self._mask_id_devtype(lowered, value, mapping, keep)
        if lowered in COMPOSITE_ID_DEVTYPE and isinstance(value, list | dict):
            return self._mask_composite_container(lowered, value, mapping, keep)
        if lowered in COMPOSITE_DEVICE_VDOM and isinstance(value, str):
            return self._mask_device_vdom(value, mapping, keep)
        if lowered in COMPOSITE_DEVICE_VDOM and isinstance(value, list | dict):
            # same gap as COMPOSITE_JSON above: a list of device[vdom]
            # strings fell through to _mask_structured with no key
            # context and returned every device name verbatim, even with
            # mask_device_identity on. The map form had no arm at all.
            return self._mask_composite_container(lowered, value, mapping, keep)
        if lowered in COMPOSITE_BREAKDOWNS and isinstance(value, dict):
            return self._mask_breakdowns(value, mapping, keep)

        vtype = self._field_types.get(lowered)
        if vtype is not None and vtype != TEXT:
            if isinstance(value, str):
                # A value the deployment chose to leave readable (device
                # identity with the flag off) must stay readable under every
                # key, not just the device-identity ones (#73 item 5).
                # Masking it here while ``devname`` shows it two keys away
                # hands over the token-to-name pairing the keep set exists
                # to withhold. #112 put that check inline here; it now lives
                # in ``_mask_scalar``, which every pass-1 route reaches and
                # which knows the type, so the fold that applies to a
                # hostname is not applied to a username.
                return self._mask_scalar(vtype, value, mapping, keep=keep)
            if isinstance(value, list):
                # e.g. dns "ipaddr" is a list of resolved addresses. The keep
                # check is the string branch's, per element: the list form of
                # a typed key is the same key, so a kept value must survive it
                # the same way.
                return [
                    self._mask_scalar(vtype, item, mapping, keep=keep)
                    if isinstance(item, str)
                    else self._mask_structured(item, mapping, keep)
                    for item in value
                ]
        if isinstance(value, dict | list):
            return self._mask_structured(value, mapping, keep)
        return value  # TEXT values are deliberately left for pass 2

    def _mask_free_text(
        self, obj: Any, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> Any:
        """Pass 2: mask TEXT fields, now that the raw -> token map is known."""
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for key, value in obj.items():
                if key.lower() in COMPOSITE_FILTER_ENTRIES and isinstance(value, list):
                    out[key] = self._mask_filter_entries(value, mapping, keep)
                elif key.lower() in COMPOSITE_BREAKDOWNS and isinstance(value, dict):
                    out[key] = self._mask_breakdown_text(value, mapping, keep)
                elif self._field_types.get(key.lower()) == TEXT:
                    out[key] = self._mask_text_tree(value, mapping, keep)
                else:
                    out[key] = self._mask_free_text(value, mapping, keep)
            return out
        if isinstance(obj, list):
            return [self._mask_free_text(item, mapping, keep) for item in obj]
        return obj

    def _mask_breakdown_text(
        self, value: Any, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> Any:
        """``breakdowns`` in pass 2: the buckets of a TEXT dimension.

        Pass 1 types a bucket's ``"value"`` from the dimension name, which
        covers every dimension whose values *are* identifiers. A TEXT dimension
        has none to mask by -- its values are prose that may embed an identifier
        anywhere -- and prose is what this pass exists for. Under a flat
        ``msg``/``ui``/``subject`` key the scan fires because the KEY is typed
        TEXT; inside a bucket the key is a generic ``"value"``, so nothing
        reached it and the free text rode out in clear. ``sample_by`` is not
        restricted to a vocabulary, so ``sample_by=["msg"]`` is an ordinary
        call, and a hostname in that prose sat beside its own token in the same
        response.

        Only a TEXT dimension is scanned here. An identifier-typed dimension was
        already masked in pass 1 and a masked IPv4 is itself a valid IPv4, so
        re-scanning it would mask it twice and yield a token matching nothing
        else in the response -- the same hazard that puts
        ``_mask_filter_entries`` in this pass rather than the other. An untyped
        dimension keeps the passthrough :meth:`_mask_breakdowns` documents: it
        is not an identifier, and a flat key of that name is not scanned either.
        Both fall through to the ordinary walk, so behaviour there is unchanged.
        """
        out: dict[str, Any] = {}
        for dimension, buckets in value.items():
            vtype = (
                self._field_types.get(dimension.strip().lower())
                if isinstance(dimension, str)
                else None
            )
            if vtype != TEXT or not isinstance(buckets, list):
                out[dimension] = self._mask_free_text(buckets, mapping, keep)
                continue
            scanned: list[Any] = []
            for bucket in buckets:
                if not isinstance(bucket, dict):
                    # Not the shape aggregate_breakdowns writes. Treat it as the
                    # free-text leaf a flat TEXT key would have made of it.
                    scanned.append(self._mask_text_tree(bucket, mapping, keep))
                    continue
                scanned.append(
                    {
                        bkey: self._mask_scalar_text(bvalue, mapping, keep)
                        if bkey.lower() == "value" and isinstance(bvalue, str)
                        else bvalue
                        for bkey, bvalue in bucket.items()
                    }
                )
            out[dimension] = scanned
        return out

    def _mask_filter_entries(
        self, value: Any, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> Any:
        """``filter_applied`` as compiled ``[field, op, value]`` entries.

        A tool that compiles a structured filter echoes what it actually sent,
        which is the resolved value: argument unmasking runs at the wrapper
        boundary, so by the time the tool body builds its entries the token the
        caller passed is already the real identifier. Echoed untyped, that
        hands the raw value straight back to the model, and it is the caller's
        own token that unlocked it.

        TEXT alone cannot close it. Pass 2 substitutes values this response
        mapped and scans for IPv4/MAC/email shapes, so an entry survives in
        clear whenever the query matched nothing, which is exactly when the
        mapping is empty. A hostname, a username or an IPv6 address then rides
        back out untouched.

        The entry states its own type, so use it: mask the value by the type of
        the field named beside it, the inverse of the way arguments are
        resolved on the way in. This runs in pass 2 rather than pass 1
        deliberately: pass 2 is the only pass that touches a TEXT key, and a
        masked IPv4 is itself a valid IPv4, so masking in pass 1 and then
        letting the free-text scan walk the same entries would mask it twice.

        Anything that is not a three-part entry, or whose field carries no
        type, falls back to the ordinary free-text treatment rather than being
        guessed at.
        """
        out: list[Any] = []
        for entry in value:
            if not isinstance(entry, list | tuple) or len(entry) != 3:
                out.append(self._mask_text_tree(entry, mapping, keep))
                continue
            field, op, raw = entry
            vtype = self._field_types.get(field.lower()) if isinstance(field, str) else None
            if vtype is None or vtype == TEXT or not isinstance(raw, str):
                out.append(self._mask_text_tree(list(entry), mapping, keep))
                continue
            masked = self._mask_scalar(vtype, raw, mapping, keep=keep)
            out.append([field, op, masked] if isinstance(entry, list) else (field, op, masked))
        return out

    def _mask_text_tree(
        self, value: Any, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> Any:
        if isinstance(value, str):
            return self._mask_scalar_text(value, mapping, keep)
        if isinstance(value, list):
            # Free-text lines; each string leaf gets the IOC scan. Nested dicts
            # in a list were already masked in pass 1, so recursion leaves them be.
            return [self._mask_text_tree(item, mapping, keep) for item in value]
        # A dict under a TEXT key is a structured object already masked key-by-key
        # in pass 1; scanning it here would double-mask its tokens. Leave it.
        return value

    def _mask_scalar_text(
        self, value: str, mapping: dict[str, str], keep: frozenset[str] = frozenset()
    ) -> str:
        """Mask free text, looking through FortiAnalyzer's percent-encoding.

        ``msg`` arrives encoded, so a MAC reaches the scan as
        ``aa%3Abb%3A...`` and an email as ``analyst%40example.com``. The
        pass-2 regexes need the literal ``:``/``@``, so neither matched,
        and the original stayed readable beside its own masked twin in
        the structured field of the same record (#80).

        Tries the decoded form FIRST rather than only as a fallback after
        a plain-text match: ``unquote()`` only touches ``%XX`` sequences,
        so a plain-form identifier survives decoding untouched and is
        still found by the same ``mask_text`` call over the decoded
        string -- one sweep over the decoded text catches a plain IP and
        a percent-encoded MAC in the same value. Masking the plain value
        FIRST and returning immediately on any match -- the previous
        order -- meant a second identifier hiding behind an escape next
        to an already-matched plain one was never even looked at:
        ``"src=192.0.2.77 mac=aa%3Abb%3Acc%3Add%3Aee%3A11"`` masked the IP
        and left the encoded MAC verbatim, exactly the leak #80 exists to
        close.

        Decoding is a means of FINDING identifiers, not a reformatting of
        tool output, so the exact bytes FortiAnalyzer sent survive unless
        the decode actually surfaces something to mask -- what keeps
        ``"CPU 100% busy"`` and an encoded path with no identifier in it
        byte-identical to the original. Re-encoding the untouched spans
        around a substitution is not attempted: the token is not the same
        length or alphabet as what it replaced, so a faithful round trip
        is not available, and emitting a half-encoded string would be
        worse than the honest decoded one.
        """
        if value.strip() in SKIP_VALUES:
            return value
        try:
            decoded = unquote(value)
            if decoded != value:
                decoded_masked = self.mask_text(decoded, mapping, keep)
                if decoded_masked != decoded:
                    return decoded_masked
            return self.mask_text(value, mapping, keep)
        except Exception:
            logger.exception("unexpected error masking free text; placeholder used")
            return self.placeholder(value)

    # -- tool-result entry point ----------------------------------------- #

    def mask_tool_result(self, result: Any, tool_name: str) -> Any:
        try:
            return self.mask_result(result)
        except Exception:
            logger.exception("output masking failed for %s; raw result withheld", tool_name)
            return {
                "status": "error",
                "error": "masking_failed",
                "message": f"{tool_name}: output masking failed; raw result withheld (fail-closed)",
            }


#: True while a wrapped tool call is inside its masking boundary. Tools
#: call other registered tools through their module-level names (e.g.
#: ``get_top_threats`` -> ``get_fortiview_data``), and those names are the
#: WRAPPED functions, so without a guard the inner result is masked twice:
#: every token stops round-tripping (unmask yields another token) and a
#: second pass over a first-pass token can fail closed into a placeholder.
#: Found by the flag-on live round, 6 double-masked + 2 placeholder rows.
_AT_BOUNDARY: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "faz_masking_boundary", default=False
)


def install_masking(mcp: Any) -> tuple[OutputMasker, ArgUnmasker]:
    """Patch ``mcp.tool`` so every tool registered afterwards is masked.

    Wrapped tools unmask their keyword arguments on the way in (Phase 2,
    before the tool body reaches any validator) and mask their result on
    the way out (Phase 1). Argument restoration is gated on the tool's
    ``readOnlyHint`` annotation (#106): a mutating tool never restores,
    and a whole-value marked token in its arguments is refused, because
    an unauthenticated FF3 token would decrypt to a plausible wrong value
    and be written to the estate. The boundary is the OUTERMOST wrapped call
    only: a wrapped tool invoked from inside another wrapped tool runs
    bare, because the outer boundary already unmasked the arguments and
    masks the combined result exactly once.

    Must run BEFORE the tool modules are imported (they register at import
    time). Raises MaskingError at startup if ``FAZ_MASKING_KEY`` is absent
    or invalid: a deployment that asked for masking must not run without it.
    """
    from fortianalyzer_mcp.utils.config import get_settings

    settings = get_settings()
    # The engine and the placeholder key both read FAZ_MASKING_KEY from the
    # process environment. Settings additionally resolves it from .env (like
    # MASKING_ENABLED), so bridge that value into the environment here when it
    # is set there but not already exported — otherwise a deployment that put
    # both the flag and the key in .env would enable masking, fail to find the
    # key, and crash fail-closed. A real environment variable still wins.
    if settings.FAZ_MASKING_KEY and not os.environ.get(MASKING_KEY_ENV):
        os.environ[MASKING_KEY_ENV] = settings.FAZ_MASKING_KEY

    engine = FPEEngine.from_env(accept_v1_tokens=settings.FAZ_MASKING_ACCEPT_V1_TOKENS)
    masker = OutputMasker(engine, mask_device_identity=settings.FAZ_MASK_DEVICE_IDENTITY)
    unmasker = ArgUnmasker(engine)
    original_tool = mcp.tool

    def contains_marked(value: Any) -> bool:
        """True when a whole-value marked token sits anywhere in ``value``.

        Only whole-value tokens count: a token embedded in a longer string
        has nothing that would restore it, so it passes through as token
        text and cannot become a decrypted write. A marker that matches
        but does not decrypt counts only when the value is structurally a
        token: the ``<marker>-<4-hex-kid>-`` group, or the domain/email
        suffix form. A genuine name that merely starts with ``host-`` /
        ``user-`` / ``url-`` ("host-fw01") is not token-shaped, so its
        decrypt failure means "not a token", not "forged".
        """
        if isinstance(value, str):
            try:
                return engine.unmask_token(value) is not None
            except MaskingError:
                candidate = value.strip().lower()
                return bool(
                    _TOKEN_PREFIX_SHAPE_RE.match(candidate)
                    or candidate.endswith("." + engine.mask_suffix)
                )
        if isinstance(value, dict):
            return any(contains_marked(inner) for inner in value.values())
        if isinstance(value, list | tuple):
            return any(contains_marked(inner) for inner in value)
        return False

    def marked_arg_key(kwargs: dict[str, Any]) -> str | None:
        """The tool parameter whose value carries a marked token, or None.

        Reports the top-level parameter name even when the token sits in
        a nested container, so the refusal points the caller at an
        argument that actually exists on the tool.
        """
        for param, value in kwargs.items():
            if contains_marked(value):
                return param
        return None

    def refuse_restore(tool_name: str, arg_key: str) -> dict[str, Any]:
        # #106: FF3 tokens carry no integrity tag, so a stale or forged
        # token decrypts to some plausible value; restored into a write
        # surface that value is silently written to the estate. The
        # message names the argument, never the token.
        return {
            "status": "error",
            "error": "masked_token_in_mutating_args",
            "message": (
                f"{tool_name}: argument '{arg_key}' carries a masking token. "
                "This tool changes FortiAnalyzer state, so tokens are not "
                "restored here: a stale or forged token would decrypt to a "
                "plausible wrong value and be written. Re-run with the real "
                "value, obtained from a read-only tool or an operator."
            ),
        }

    def patched_tool(*args: Any, **kwargs: Any) -> Any:
        decorator = original_tool(*args, **kwargs)
        # #106: only tools that annotate themselves read-only get argument
        # restoration. Everything else, including an unannotated tool and
        # the dynamic dispatcher (whose annotation is deliberately the
        # union of everything it can reach), fails closed: no restore, and
        # a whole-value marked token is refused outright. Unmarked IP/MAC
        # tokens are indistinguishable from real addresses and pass
        # through; making them detectable is the #40 v2 envelope work.
        # The hint is read from the keyword form every tool uses today. A
        # dict-shaped annotations object is honored too; anything else
        # (positional, absent, unrecognized) computes read_only=False and
        # the tool loses restoration rather than gaining a write path.
        # Both attribute spellings are read because mcp 2.x renamed the
        # python-side field to snake_case while keeping the camelCase
        # constructor alias and the camelCase wire form. Reading only
        # ``readOnlyHint`` there is not an error -- ``getattr`` returns the
        # default -- so every read-only tool would silently lose restoration.
        # The dict branch stays camelCase: a dict is the wire spelling.
        annotations = kwargs.get("annotations")
        if isinstance(annotations, dict):
            read_only = bool(annotations.get("readOnlyHint", False))
        elif annotations is None:
            read_only = False
        else:
            read_only = bool(
                getattr(annotations, "read_only_hint", None)
                or getattr(annotations, "readOnlyHint", None)
            )

        def register(fn: Any) -> Any:
            if inspect.iscoroutinefunction(fn):

                @wraps(fn)
                async def async_wrapped(*fa: Any, **fk: Any) -> Any:
                    if _AT_BOUNDARY.get():
                        return await fn(*fa, **fk)
                    # Per-call budget, so the cap means "this call" rather
                    # than "this process". Set at the OUTERMOST boundary
                    # only: an inner tool call shares its caller's budget,
                    # or nesting would hand out a fresh one per hop.
                    begin_v2_verification_budget()
                    token = _AT_BOUNDARY.set(True)
                    try:
                        if not read_only:
                            offending = marked_arg_key(fk)
                            if offending is not None:
                                return refuse_restore(fn.__name__, offending)
                            return masker.mask_tool_result(await fn(*fa, **fk), fn.__name__)
                        return masker.mask_tool_result(
                            await fn(*fa, **unmasker.unmask_args(fk)), fn.__name__
                        )
                    finally:
                        _AT_BOUNDARY.reset(token)

                return decorator(async_wrapped)

            @wraps(fn)
            def sync_wrapped(*fa: Any, **fk: Any) -> Any:
                if _AT_BOUNDARY.get():
                    return fn(*fa, **fk)
                begin_v2_verification_budget()
                token = _AT_BOUNDARY.set(True)
                try:
                    if not read_only:
                        offending = marked_arg_key(fk)
                        if offending is not None:
                            return refuse_restore(fn.__name__, offending)
                        return masker.mask_tool_result(fn(*fa, **fk), fn.__name__)
                    return masker.mask_tool_result(fn(*fa, **unmasker.unmask_args(fk)), fn.__name__)
                finally:
                    _AT_BOUNDARY.reset(token)

            return decorator(sync_wrapped)

        return register

    mcp.tool = patched_tool
    logger.info("masking installed: tools registered from now on unmask args and mask output")
    return masker, unmasker
