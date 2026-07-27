"""What is filterable in each FortiAnalyzer vocabulary, and under what names.

A "vocabulary" is one namespace of field names: a logtype (``traffic``,
``event``, ``attack``), or an object type in the dvmdb/task family (``device``,
``task``). Each records four things:

* **canonical** -- field names FortiAnalyzer itself uses. For the dvmdb-family
  vocabularies this set is enumerable and treated as complete; for logtypes it
  deliberately is not (see below).
* **aliases** -- the English an LLM reaches for (``source_ip``,
  ``destination_port``, ``application``) mapped onto the cryptic real name. A
  canonical name always wins over an alias, so adding an alias can never shadow
  a real field.
* **coercions** -- enum names mapped to the integer codes the appliance stores.
  ``search_devices`` and ``list_tasks`` each carried their own inline copy of
  one of these; centralising them means every caller translates identically.
* **complete** -- whether ``canonical`` is the whole truth. ``False`` for
  logtypes on purpose: the appliance publishes hundreds of fields per logtype
  via ``/logview/logfields`` and this module does not reproduce that catalogue,
  so an unrecognised log field is passed through with a warning rather than
  rejected on authority this module does not have. The dvmdb-family sets are
  small and stable, so an unknown name there is a genuine error. Pass-through
  is gated on the name being *shaped* like a field name: the string dialect
  interpolates the resolved name raw, so a "field" carrying whitespace, quotes
  or operator characters is an injection attempt and is rejected outright.

Once the per-logtype catalogues are generated from a live appliance (a spec
verification item) the log vocabularies can flip to ``complete=True`` and
unknown-field rejection becomes uniform.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from fortianalyzer_mcp.utils.errors import ValidationError

# What a FortiAnalyzer field name can look like. Everything observed in the
# logview/dvmdb catalogues is lowercase alphanumerics with underscores; dot and
# hyphen are tolerated for forward compatibility. Anything else cannot be a
# field name, and since the string dialect interpolates the resolved name
# unquoted, letting it through would hand the caller the filter string.
_FIELD_NAME_RE = re.compile(r"^[a-z0-9_][a-z0-9_.-]*$")

# Fields every FortiGate log record carries, regardless of logtype. Used as the
# base of each log vocabulary and as the whole of the generic fallback.
_LOG_COMMON: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "itime",
        "eventtime",
        "devname",
        "devid",
        "vd",
        "logid",
        "type",
        "subtype",
        "level",
        "action",
        "srcip",
        "dstip",
        "msg",
        "user",
    }
)

_TRAFFIC_FIELDS: frozenset[str] = _LOG_COMMON | {
    "srcport",
    "dstport",
    "proto",
    "policyid",
    "service",
    "app",
    "appcat",
    "srcintf",
    "dstintf",
    "sentbyte",
    "rcvdbyte",
    "duration",
    "sessionid",
    "srccountry",
    "dstcountry",
    "unauthuser",
    "hostname",
    "dstname",
}

_EVENT_FIELDS: frozenset[str] = _LOG_COMMON | {
    "ui",
    "cfgpath",
    "cfgattr",
    "status",
}

# Field names proven by the IPS filters in pcap_tools.search_ips_logs.
_ATTACK_FIELDS: frozenset[str] = _LOG_COMMON | {
    "severity",
    "attack",
    "attackid",
    "srcport",
    "dstport",
    "proto",
    "service",
    "sessionid",
    "pcapurl",
    "cve",
    "ref",
    "policyid",
    "hostname",
    "url",
    "profile",
}

# Aliases shared by every log vocabulary. Kept in one dict so a name means the
# same thing in every logtype. Deliberately omitted: bare "country" and "port",
# which are ambiguous between src and dst -- an ambiguous alias silently filters
# on the wrong dimension, which is worse than an unknown-field warning.
_LOG_ALIASES: Mapping[str, str] = {
    "source_ip": "srcip",
    "src_ip": "srcip",
    "destination_ip": "dstip",
    "dest_ip": "dstip",
    "dst_ip": "dstip",
    "source_port": "srcport",
    "src_port": "srcport",
    "destination_port": "dstport",
    "dest_port": "dstport",
    "dst_port": "dstport",
    "protocol": "proto",
    "application": "app",
    "application_category": "appcat",
    "policy_id": "policyid",
    "session_id": "sessionid",
    "username": "user",
    "user_name": "user",
    "device_name": "devname",
    "device_id": "devid",
    "source_interface": "srcintf",
    "destination_interface": "dstintf",
    "bytes_sent": "sentbyte",
    "sent_bytes": "sentbyte",
    "bytes_received": "rcvdbyte",
    "received_bytes": "rcvdbyte",
    "attack_name": "attack",
    "source_country": "srccountry",
    "destination_country": "dstcountry",
    "message": "msg",
}

_DEVICE_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "ip",
        "sn",
        "hostname",
        "desc",
        "os_ver",
        "mr",
        "patch",
        "platform_str",
        "conn_status",
        "dev_status",
        "mgmt_mode",
        "adm_usr",
        "vdom",
        "hdisk_size",
        "build",
    }
)

_DEVICE_ALIASES: Mapping[str, str] = {
    "device_name": "name",
    "serial": "sn",
    "serial_number": "sn",
    "os_version": "os_ver",
    "platform": "platform_str",
    "connection_status": "conn_status",
    "description": "desc",
}

# DVMDB stores conn_status as an integer. Moved here from the inline map in
# dvm_tools.search_devices.
_CONN_STATUS_CODES: Mapping[str, int] = {"unknown": 0, "up": 1, "down": 2}

_TASK_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "title",
        "src",
        "user",
        "adom",
        "state",
        "percent",
        "num_done",
        "num_err",
        "num_lines",
        "num_warn",
        "start_tm",
        "end_tm",
    }
)

_TASK_ALIASES: Mapping[str, str] = {
    "task_id": "id",
    "status": "state",
    "progress": "percent",
}

# The single source for FAZ task-state names -> wire codes (FNDN task schema).
# system_tools derives its code->name display table from this mapping, so the
# legacy filter_state parameter and the structured filters path translate
# identically by construction.
TASK_STATE_CODES: Mapping[str, int] = {
    "pending": 0,
    "running": 1,
    "cancelling": 2,
    "cancelled": 3,
    "done": 4,
    "error": 5,
    "aborting": 6,
    "aborted": 7,
    "warning": 8,
    "to_continue": 9,
    "unknown": 10,
}

_NO_COERCIONS: Mapping[str, Mapping[str, int]] = {}


@dataclass(frozen=True)
class Vocabulary:
    """One filterable namespace and everything known about its field names."""

    name: str
    dialect: str
    canonical: frozenset[str]
    aliases: Mapping[str, str]
    coercions: Mapping[str, Mapping[str, int]]
    complete: bool


_GENERIC_LOG = Vocabulary(
    name="log",
    dialect="string",
    canonical=_LOG_COMMON,
    aliases=_LOG_ALIASES,
    coercions=_NO_COERCIONS,
    complete=False,
)

_VOCABULARIES: Mapping[str, Vocabulary] = {
    "traffic": Vocabulary(
        name="traffic",
        dialect="string",
        canonical=_TRAFFIC_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
    ),
    "event": Vocabulary(
        name="event",
        dialect="string",
        canonical=_EVENT_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
    ),
    "attack": Vocabulary(
        name="attack",
        dialect="string",
        canonical=_ATTACK_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
    ),
    "device": Vocabulary(
        name="device",
        dialect="array",
        canonical=_DEVICE_FIELDS,
        aliases=_DEVICE_ALIASES,
        coercions={"conn_status": _CONN_STATUS_CODES},
        complete=True,
    ),
    "task": Vocabulary(
        name="task",
        dialect="array",
        canonical=_TASK_FIELDS,
        aliases=_TASK_ALIASES,
        coercions={"state": TASK_STATE_CODES},
        complete=True,
    ),
}


def get_vocabulary(name: str) -> Vocabulary:
    """Return the vocabulary for a logtype or object type.

    An unregistered name falls back to the generic log vocabulary, so a logtype
    with no curated field set (``voip``, ``icap``, ``dlp``, ...) still gets
    aliases and the common-field core rather than an error.
    """
    return _VOCABULARIES.get(name.strip().lower(), _GENERIC_LOG)


def resolve_field(vocabulary: str, name: str) -> tuple[str, str | None]:
    """Resolve a caller-supplied field name to its canonical FAZ spelling.

    Returns ``(canonical_name, warning_or_None)``.

    Raises:
        ValidationError: if the vocabulary enumerates its fields
            (``complete=True``) and the name is neither canonical nor an alias,
            or if the name is not shaped like a field name at all (whitespace,
            quotes, operator characters) -- the string dialect interpolates the
            resolved name unquoted, so a malformed name is an injection
            attempt, not a spelling the appliance might know.
    """
    vocab = get_vocabulary(vocabulary)
    lowered = name.strip().lower()

    if lowered in vocab.canonical:
        return lowered, None
    if lowered in vocab.aliases:
        return vocab.aliases[lowered], None

    if vocab.complete:
        valid = ", ".join(sorted(vocab.canonical))
        raise ValidationError(f"Unknown field '{name}' for {vocab.name}. Valid fields: {valid}")

    if not _FIELD_NAME_RE.match(lowered):
        raise ValidationError(
            f"'{name}' cannot be a FortiAnalyzer field name. Field names are letters, "
            "digits, underscores, dots or hyphens; operators and quoting belong in "
            "'op' and 'value'."
        )

    return lowered, (
        f"field '{name}' is not in the known {vocab.name} field set; passing it through "
        f"to FortiAnalyzer. Confirm the spelling with "
        f'get_log_fields(logtype="{vocab.name}", name_filter="...").'
    )


def canonical_log_field(name: str) -> str:
    """Best-effort canonical spelling of a log field name, without a vocabulary.

    For callers that hold a field name but not the logtype it targets -- the
    masking layer types a structured-filter value by its sibling ``field`` key
    before any tool, and therefore any vocabulary, is known. The alias table is
    shared by every log vocabulary precisely so a name cannot change meaning
    between logtypes, which is what makes a vocabulary-less lookup safe. Names
    that are neither aliases nor known fields come back lowercased, unchanged.
    """
    lowered = name.strip().lower()
    return _LOG_ALIASES.get(lowered, lowered)


def coerce_value(vocabulary: str, canonical_field: str, value: Any) -> Any:
    """Translate an enum name to the integer code FortiAnalyzer stores.

    Values that are not strings pass through untouched, so a caller who already
    knows the code can supply it directly.

    Raises:
        ValidationError: if the field has an enum mapping and the string is not
            one of its names.
    """
    vocab = get_vocabulary(vocabulary)
    mapping = vocab.coercions.get(canonical_field)
    if mapping is None or not isinstance(value, str):
        return value

    code = mapping.get(value.strip().lower())
    if code is None:
        valid = ", ".join(sorted(mapping))
        raise ValidationError(
            f"Invalid value '{value}' for {canonical_field}. Must be one of: {valid}"
        )
    return code


def enum_names(vocabulary: str, canonical_field: str) -> tuple[str, ...] | None:
    """The accepted enum names for a field, or ``None`` if it stores free text.

    A field with an enum mapping is stored by FortiAnalyzer as an integer code,
    which is what makes substring matching over it meaningless -- see
    ``filters._reject_substring_on_enum``. Returning the names rather than a
    bare boolean lets the refusal name the values that do work.
    """
    mapping = get_vocabulary(vocabulary).coercions.get(canonical_field)
    return None if mapping is None else tuple(sorted(mapping))
