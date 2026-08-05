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
from fortianalyzer_mcp.utils.validation import (
    VALID_EVENT_LEVELS,
    VALID_EVENT_SUBTYPES,
    VALID_IPS_ACTIONS,
    VALID_TRAFFIC_ACTIONS,
)

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
    # top-websites aggregates web categories, not hostnames (#109 review),
    # so catdesc is the group_by dimension for webfilter. "web_category" is
    # the English spelling a caller reaches for.
    "web_category": "catdesc",
    "category_description": "catdesc",
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

# eventmgmt alert rows. Corrected against the live 7.6.7 alert fixture in
# tests/test_masking_leak.py, the live-verified allowlist in
# masking/fields.py, and the alert keys skills/handlers.py actually reads --
# the same discipline the UEBA sets were rebuilt under.
#
# Out, for want of any evidence: `firstlogtime`, `count`, `comments` and
# `adom` have zero occurrences as an alert response key anywhere in this repo.
#
# In, because the live fixture carries every one of them: the human-readable
# endpoint identity (`epname`/`epip`, and their `dstep*` peers), the composite
# group-by dimensions the masking layer already has handlers for
# (`groupby1`/`groupby2`), the nested `event_details`, and `csf`.
#
# `ackflag` is the load-bearing correction. handlers.py records that live FAZ
# alerts carry `ackflag` where this set had only `acknowledged`, so the
# curated default returned no acknowledgement state at all on a real
# appliance. Both are carried and both are projected: whichever the build
# emits survives, and project_rows never invents the absent one.
_ALERT_FIELDS: frozenset[str] = frozenset(
    {
        "alertid",
        "severity",
        "status",
        "ackflag",
        "acknowledged",
        "alerttime",
        "timestamp",
        "createtime",
        "lastlogtime",
        "eventtype",
        "alerttype",
        "triggername",
        "name",
        "logdesc",
        "description",
        "extrainfo",
        "subject",
        "subject_details",
        "devname",
        "devid",
        "csf",
        "epid",
        "epname",
        "epip",
        "euid",
        "dstepname",
        "dstepip",
        "event_details",
        "groupby1",
        "groupby2",
        "target",
    }
)
_ALERT_PROJECTION: frozenset[str] = frozenset(
    {
        "alertid",
        "alerttime",
        "lastlogtime",
        "severity",
        "status",
        "ackflag",
        "acknowledged",
        "eventtype",
        "triggername",
        "subject",
        "devname",
        "epid",
        "epname",
        "epip",
        "euid",
        "groupby1",
        "groupby2",
    }
)
_ALERT_ALIASES: Mapping[str, str] = {
    "alert_id": "alertid",
    "event_type": "eventtype",
    "device_name": "devname",
    "trigger": "triggername",
    "acknowledged_flag": "ackflag",
    "endpoint_name": "epname",
    "endpoint_ip": "epip",
    "endpoint_id": "epid",
    "enduser_id": "euid",
}

# incidentmgmt incident rows. Same sources, same discipline.
#
# Out: `banner` has zero occurrences repo-wide -- client.create_incident takes
# `name`, which the appliance persists on the record, and the conftest
# incident fixture carries `name`. `updatetime` is likewise unattested;
# handlers.py reads `lastupdate`. `assignee` is an UPDATE *request* param
# (api/client.update_incident), not a record key: the live record spells the
# workflow slots `assigned_to`/`remedy_executor`/`remedy_approver`, which is
# what masking/fields.py types. `attachment`, `connector` and `ticket` are
# unattested too -- incident/alert correlation runs through the attachments
# endpoint rather than a field on either object, and the `connector` this repo
# knows is an event subtype.
#
# In, from the live 7.6.7 incident fixture: `endpoint` (dropped by the old
# projection despite being the incident's subject), `lastuser`,
# `incident_reporter` and the composite `grpby`.
#
# `banner`, `assignee` and `owner` survive as aliases: they are the English an
# LLM reaches for, and an alias can never shadow a canonical name.
_INCIDENT_FIELDS: frozenset[str] = frozenset(
    {
        "incid",
        "name",
        "severity",
        "status",
        "category",
        "description",
        "createtime",
        "lastupdate",
        "timestamp",
        "endpoint",
        "reporter",
        "lastuser",
        "incident_reporter",
        "assigned_to",
        "remedy_executor",
        "remedy_approver",
        "grpby",
        "epid",
        "euid",
        "alertid",
    }
)
_INCIDENT_PROJECTION: frozenset[str] = frozenset(
    {
        "incid",
        "name",
        "severity",
        "status",
        "category",
        "createtime",
        "lastupdate",
        "timestamp",
        "endpoint",
        "reporter",
        "lastuser",
        "assigned_to",
        "epid",
        "euid",
        "alertid",
    }
)
_INCIDENT_ALIASES: Mapping[str, str] = {
    "incident_id": "incid",
    "title": "name",
    "banner": "name",
    "owner": "assigned_to",
    "assignee": "assigned_to",
    "endpoint_id": "epid",
    "enduser_id": "euid",
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


def resolve_field(
    vocabulary: str,
    name: str,
    *,
    enforce_complete: bool = True,
) -> tuple[str, str | None]:
    """Resolve a caller-supplied field name to its canonical FAZ spelling.

    Returns ``(canonical_name, warning_or_None)``.

    Args:
        vocabulary: The logtype or object type whose names apply.
        name: The caller's spelling; aliases are accepted.
        enforce_complete: Whether ``complete=True`` may *reject* an unknown
            name. True on the filter path, where the canonical set is a
            security boundary: the string dialect interpolates the resolved
            name unquoted, and the array dialect builds an operator clause
            around it, so a name the appliance does not define is an
            injection surface rather than a typo. False on the projection
            path, where a field name only ever selects which keys come back
            -- rejecting there blocks legitimate reads of real appliance
            fields this module's small dvmdb sets never enumerated (``oid``,
            ``ha_mode``, ``os_type``, ``last_checked``, ``devvds``), all of
            which worked before projection existed. The shape check still
            applies on both paths.

    Raises:
        ValidationError: if ``enforce_complete`` and the vocabulary enumerates
            its fields (``complete=True``) and the name is neither canonical
            nor an alias, or if the name is not shaped like a field name at
            all (whitespace, quotes, operator characters).
    """
    vocab = get_vocabulary(vocabulary)
    lowered = name.strip().lower()

    if lowered in vocab.canonical:
        return lowered, None
    if lowered in vocab.aliases:
        return vocab.aliases[lowered], None

    if vocab.complete and enforce_complete:
        valid = ", ".join(sorted(vocab.canonical))
        raise ValidationError(f"Unknown field '{name}' for {vocab.name}. Valid fields: {valid}")

    if not _FIELD_NAME_RE.match(lowered):
        raise ValidationError(
            f"'{name}' cannot be a FortiAnalyzer field name. Field names are letters, "
            "digits, underscores, dots or hyphens; operators and quoting belong in "
            "'op' and 'value'."
        )

    if vocab.complete:
        # Only reachable with enforce_complete=False. The get_log_fields hint
        # below is a logview thing and would be a dead end here.
        return lowered, (
            f"field '{name}' is not in this server's {vocab.name} field set; requesting "
            f"it from FortiAnalyzer anyway. If the appliance does not define it the key "
            f"is simply absent from each row."
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


#: Known member sets for enum fields FortiAnalyzer stores as STRINGS, per
#: vocabulary. Distinct from ``Vocabulary.coercions``, which maps enum names to
#: the integer codes the appliance stores (dvmdb ``conn_status``) and whose
#: unknown members are a hard error because the code is what goes on the wire.
#:
#: These sets came back into use after the #109 review measured the cost of
#: losing them: the retired search_* wrappers validated these arguments
#: client-side (``validate_traffic_action`` and friends, which the
#: consolidation left with zero callers), and ``filters`` validates field names
#: and operators but passes values through verbatim. So ``action==denied``
#: compiled clean and returned 0 rows with status success, where
#: ``action==deny`` returned 5833 -- a loud client-side rejection turned into a
#: confident empty answer, the exact class this release spends its work
#: closing.
_STRING_ENUM_VALUES: Mapping[str, Mapping[str, frozenset[str]]] = {
    "traffic": {"action": frozenset(VALID_TRAFFIC_ACTIONS)},
    "attack": {"action": frozenset(VALID_IPS_ACTIONS)},
    "event": {
        "level": frozenset(VALID_EVENT_LEVELS),
        "subtype": frozenset(VALID_EVENT_SUBTYPES),
    },
}


def enum_value_warning(vocabulary: str, canonical_field: str, value: Any) -> str | None:
    """Warn -- never reject -- on a value outside a string enum's known set.

    A warning rather than a ValidationError, deliberately, and for the same
    reason ``resolve_field`` warns on an unrecognised field name instead of
    refusing it: these sets are this server's knowledge, not the appliance's.
    ``VALID_TRAFFIC_ACTIONS`` has six members and FortiGate emits others
    (``client-rst``, ``server-rst``), so rejecting would turn a real value
    into an unqueryable one -- the failure 8beb7c5 had to undo for field
    names on the projection path. The caller still learns the value is
    unrecognised, and still learns the set, which is what turns a silent zero
    into a diagnosable one.
    """
    members = _STRING_ENUM_VALUES.get(vocabulary, {}).get(canonical_field)
    if members is None or not isinstance(value, str) or value.strip().lower() in members:
        return None
    return (
        f"value '{value}' is not a known '{canonical_field}' value for {vocabulary} "
        f"({', '.join(sorted(members))}); passing it through to FortiAnalyzer. "
        f"A value the appliance does not use matches no rows and returns an "
        f'empty result with status success. Confirm with get_log_fields(logtype="{vocabulary}").'
    )


def enum_names(vocabulary: str, canonical_field: str) -> tuple[str, ...] | None:
    """The accepted enum names for a field, or ``None`` if it stores free text.

    A field with an enum mapping is stored by FortiAnalyzer as an integer code,
    which is what makes substring matching over it meaningless -- see
    ``filters._reject_substring_on_enum``. Returning the names rather than a
    bare boolean lets the refusal name the values that do work.
    """
    mapping = get_vocabulary(vocabulary).coercions.get(canonical_field)
    return None if mapping is None else tuple(sorted(mapping))
