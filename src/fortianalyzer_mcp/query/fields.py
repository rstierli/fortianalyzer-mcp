"""What is filterable in each FortiAnalyzer vocabulary, and under what names.

A "vocabulary" is one namespace of field names: a logtype (``traffic``,
``event``, ``attack``), or an object type in the dvmdb/task family (``device``,
``task``). Each records five things:

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
* **projection** -- the curated subset returned when a caller passes no
  ``fields``. Empty means uncurated: the tool returns full rows plus a warning
  naming ``fields``, which is today's behaviour, rather than a payload chosen
  by guesswork. Curations are added as they are verified against live
  ``logfields`` output, so an empty set is a "not yet", not a "never".

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

# Curated projections. Each carries identity (who/where), the discriminator
# (action/level/severity), the magnitude, the human-readable summary, and --
# non-negotiably -- the join keys another tool takes as input. Dropping
# sessionid from traffic breaks get_pcap_by_session with no error that traces
# back here; tests/test_projection_join_keys.py is the guard.
_TRAFFIC_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "srcip",
        "srcport",
        "dstip",
        "dstport",
        "proto",
        "action",
        "service",
        "app",
        "policyid",
        "sentbyte",
        "rcvdbyte",
        "duration",
        "user",
        "sessionid",
        "srccountry",
        "dstcountry",
    }
)

_EVENT_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "level",
        "subtype",
        "action",
        "user",
        "ui",
        "msg",
        "status",
    }
)

_ATTACK_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "severity",
        "attack",
        "attackid",
        "srcip",
        "srcport",
        "dstip",
        "dstport",
        "proto",
        "action",
        "service",
        "policyid",
        "cve",
        "sessionid",
        "pcapurl",
        "msg",
    }
)

# The four remaining curated logtypes the spec names. Each set is the common
# core plus the fields that make that logtype worth querying; every name is
# also added to the vocabulary's canonical set so the subset test holds.
_VIRUS_FIELDS: frozenset[str] = _LOG_COMMON | {
    "virus",
    "filename",
    "url",
    "service",
    "srcport",
    "dstport",
    "proto",
    "profile",
    "eventtype",
    "filehash",
}
_VIRUS_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "action",
        "virus",
        "filename",
        "filehash",
        "url",
        "srcip",
        "dstip",
        "user",
        "service",
        "msg",
    }
)

_WEBFILTER_FIELDS: frozenset[str] = _LOG_COMMON | {
    "hostname",
    "url",
    "catdesc",
    "cat",
    "service",
    "srcport",
    "dstport",
    "proto",
    "profile",
    "eventtype",
    "reqtype",
    "sentbyte",
    "rcvdbyte",
}
_WEBFILTER_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "action",
        "hostname",
        "url",
        "catdesc",
        "srcip",
        "dstip",
        "user",
        "sentbyte",
        "rcvdbyte",
        "msg",
    }
)

_APPCTRL_FIELDS: frozenset[str] = _LOG_COMMON | {
    "app",
    "appcat",
    "apprisk",
    "hostname",
    "url",
    "service",
    "srcport",
    "dstport",
    "proto",
    "profile",
    "eventtype",
    "sentbyte",
    "rcvdbyte",
}
_APPCTRL_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "action",
        "app",
        "appcat",
        "apprisk",
        "hostname",
        "srcip",
        "dstip",
        "user",
        "sentbyte",
        "rcvdbyte",
        "msg",
    }
)

_DNS_FIELDS: frozenset[str] = _LOG_COMMON | {
    "qname",
    "qtype",
    "qclass",
    "xid",
    "srcport",
    "dstport",
    "proto",
    "profile",
    "eventtype",
    "catdesc",
}
_DNS_PROJECTION: frozenset[str] = frozenset(
    {
        "date",
        "time",
        "devname",
        "action",
        "qname",
        "qtype",
        "catdesc",
        "srcip",
        "dstip",
        "user",
        "msg",
    }
)

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

# --- non-log vocabularies -------------------------------------------------- #
# These carry no filter dialect of their own in this plan (eventmgmt and
# incidentmgmt take the string dialect, which Plan 1 already emits), but they
# need canonical sets so projection can validate names against something.

_ALERT_FIELDS: frozenset[str] = frozenset(
    {
        "alertid",
        "adom",
        "severity",
        "status",
        "alerttime",
        "firstlogtime",
        "lastlogtime",
        "count",
        "eventtype",
        "extrainfo",
        "devname",
        "devid",
        "subject",
        "subject_details",
        "triggername",
        "epid",
        "euid",
        "acknowledged",
        "comments",
        "target",
    }
)
_ALERT_PROJECTION: frozenset[str] = frozenset(
    {
        "alertid",
        "severity",
        "status",
        "alerttime",
        "lastlogtime",
        "count",
        "eventtype",
        "devname",
        "subject",
        "triggername",
        "epid",
        "euid",
        "acknowledged",
    }
)
_ALERT_ALIASES: Mapping[str, str] = {
    "alert_id": "alertid",
    "event_type": "eventtype",
    "device_name": "devname",
    "trigger": "triggername",
}

_INCIDENT_FIELDS: frozenset[str] = frozenset(
    {
        "incid",
        "adom",
        "severity",
        "status",
        "category",
        "createtime",
        "updatetime",
        "banner",
        "description",
        "assignee",
        "reporter",
        "endpoint",
        "epid",
        "euid",
        "alertid",
        "attachment",
        "connector",
        "ticket",
    }
)
_INCIDENT_PROJECTION: frozenset[str] = frozenset(
    {
        "incid",
        "severity",
        "status",
        "category",
        "createtime",
        "updatetime",
        "banner",
        "assignee",
        "reporter",
        "epid",
        "euid",
        "alertid",
    }
)
_INCIDENT_ALIASES: Mapping[str, str] = {
    "incident_id": "incid",
    "title": "banner",
    "owner": "assignee",
}


# UEBA field names, keyed to live evidence rather than the FNDN prose gloss
# ("hostname, IP, MAC, OS, department...") that produced the previous, wrong
# set. Every name below is backed by a live-verified or live-observed use
# elsewhere in this repo -- see fix-round-1 of the query-engine-projection
# plan's Task 6 report for the field-by-field citation. A field with no such
# citation was dropped rather than carried over on the strength of the old
# prose: masking a (or here, curating around a) nonexistent field is a
# silent no-op, and the point of this correction is to stop doing that.
_ENDPOINT_FIELDS: frozenset[str] = frozenset(
    {
        "epid",
        "epname",
        "epip",
        "euid",
        "user",
        "detectkey",
    }
)
_ENDPOINT_PROJECTION: frozenset[str] = frozenset(
    {
        "epid",
        "epname",
        "epip",
        "euid",
        "user",
    }
)
_ENDPOINT_ALIASES: Mapping[str, str] = {
    "endpoint_id": "epid",
    "host": "epname",
    "hostname": "epname",
    "ip": "epip",
    "username": "user",
}

_ENDUSER_FIELDS: frozenset[str] = frozenset(
    {
        "euid",
        "euname",
        "email",
        "epids",
    }
)
_ENDUSER_PROJECTION: frozenset[str] = frozenset(
    {
        "euid",
        "euname",
        "epids",
    }
)
_ENDUSER_ALIASES: Mapping[str, str] = {
    "enduser_id": "euid",
    "user": "euname",
    "username": "euname",
}

# Report rows, corrected against evidence after the first cut curated a set
# no report record has ever carried. ``id`` (the old join key), ``start-time``,
# ``end-time``, ``progress-percent``, ``template``, ``format``, ``size`` and
# ``owner`` have zero occurrences as a *response* key anywhere in this repo,
# and ``period-start``/``period-end`` are request params on the report
# schedule (api/client.py, report_tools._run_window) rather than row keys.
# What a report row demonstrably carries is the handle every downstream report
# tool consumes -- ``tid`` (report_tools' polling loop reads ``report["tid"]``,
# fetch_report/get_report_data/save_report all take it) -- plus ``title`` and
# ``state``, both of which report_get_state also filters on server-side.
_REPORT_FIELDS: frozenset[str] = frozenset(
    {
        "tid",
        "title",
        "state",
    }
)
#: Deliberately empty: **report is uncurated.** Three evidenced names are the
#: three names this repo happens to have observed, not a verified catalogue of
#: what ``/report/adom/{adom}/reports/state`` emits -- so curating to them
#: would silently drop every live key nobody here has seen yet. That is the
#: exact failure the previous set produced (it stripped ``tid``, leaving rows
#: with no usable handle). Absent a catalogue, ``get_report_history`` returns
#: full rows plus the uncurated warning, which is this module's prescribed
#: honest fallback. ``tests/test_projection_join_keys.py`` records report as
#: uncurated on purpose, so re-curating it without re-checking ``tid`` fails.
_REPORT_PROJECTION: frozenset[str] = frozenset()
_REPORT_ALIASES: Mapping[str, str] = {
    "report_id": "tid",
    # The spelling the previous curated set guessed at, and the one an LLM
    # reaches for. Kept as an alias so it lands on the real handle instead of
    # warning its way through to a key no report row carries.
    "id": "tid",
    "name": "title",
    "status": "state",
}

_DEVICE_PROJECTION: frozenset[str] = frozenset(
    {
        "name",
        "ip",
        "sn",
        "hostname",
        "os_ver",
        "mr",
        "patch",
        "platform_str",
        "conn_status",
        "dev_status",
        "vdom",
    }
)

_TASK_PROJECTION: frozenset[str] = frozenset(
    {
        "id",
        "title",
        "state",
        "percent",
        "user",
        "adom",
        "start_tm",
        "end_tm",
        "num_err",
        "num_warn",
    }
)


@dataclass(frozen=True)
class Vocabulary:
    """One filterable namespace and everything known about its field names."""

    name: str
    dialect: str
    canonical: frozenset[str]
    aliases: Mapping[str, str]
    coercions: Mapping[str, Mapping[str, int]]
    complete: bool
    projection: frozenset[str] = frozenset()


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
        projection=_TRAFFIC_PROJECTION,
    ),
    "event": Vocabulary(
        name="event",
        dialect="string",
        canonical=_EVENT_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_EVENT_PROJECTION,
    ),
    "attack": Vocabulary(
        name="attack",
        dialect="string",
        canonical=_ATTACK_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_ATTACK_PROJECTION,
    ),
    "virus": Vocabulary(
        name="virus",
        dialect="string",
        canonical=_VIRUS_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_VIRUS_PROJECTION,
    ),
    "webfilter": Vocabulary(
        name="webfilter",
        dialect="string",
        canonical=_WEBFILTER_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_WEBFILTER_PROJECTION,
    ),
    "app-ctrl": Vocabulary(
        name="app-ctrl",
        dialect="string",
        canonical=_APPCTRL_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_APPCTRL_PROJECTION,
    ),
    "dns": Vocabulary(
        name="dns",
        dialect="string",
        canonical=_DNS_FIELDS,
        aliases=_LOG_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_DNS_PROJECTION,
    ),
    "device": Vocabulary(
        name="device",
        dialect="array",
        canonical=_DEVICE_FIELDS,
        aliases=_DEVICE_ALIASES,
        coercions={"conn_status": _CONN_STATUS_CODES},
        complete=True,
        projection=_DEVICE_PROJECTION,
    ),
    "task": Vocabulary(
        name="task",
        dialect="array",
        canonical=_TASK_FIELDS,
        aliases=_TASK_ALIASES,
        coercions={"state": TASK_STATE_CODES},
        complete=True,
        projection=_TASK_PROJECTION,
    ),
    "alert": Vocabulary(
        name="alert",
        dialect="string",
        canonical=_ALERT_FIELDS,
        aliases=_ALERT_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_ALERT_PROJECTION,
    ),
    "incident": Vocabulary(
        name="incident",
        dialect="string",
        canonical=_INCIDENT_FIELDS,
        aliases=_INCIDENT_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_INCIDENT_PROJECTION,
    ),
    "endpoint": Vocabulary(
        name="endpoint",
        dialect="string",
        canonical=_ENDPOINT_FIELDS,
        aliases=_ENDPOINT_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_ENDPOINT_PROJECTION,
    ),
    "enduser": Vocabulary(
        name="enduser",
        dialect="string",
        canonical=_ENDUSER_FIELDS,
        aliases=_ENDUSER_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_ENDUSER_PROJECTION,
    ),
    "report": Vocabulary(
        name="report",
        dialect="string",
        canonical=_REPORT_FIELDS,
        aliases=_REPORT_ALIASES,
        coercions=_NO_COERCIONS,
        complete=False,
        projection=_REPORT_PROJECTION,
    ),
}


def get_vocabulary(name: str) -> Vocabulary:
    """Return the vocabulary for a logtype or object type.

    An unregistered name falls back to the generic log vocabulary, so a logtype
    with no curated field set (``voip``, ``icap``, ``dlp``, ...) still gets
    aliases and the common-field core rather than an error.
    """
    return _VOCABULARIES.get(name.strip().lower(), _GENERIC_LOG)


def has_projection(vocabulary: str) -> bool:
    """Whether this vocabulary has a curated default projection.

    ``False`` means a caller who passes no ``fields`` gets full rows and a
    warning, which is the pre-projection behaviour -- never a guessed subset.
    """
    return bool(get_vocabulary(vocabulary).projection)


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
