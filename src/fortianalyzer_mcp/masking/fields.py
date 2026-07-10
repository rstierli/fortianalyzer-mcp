"""Field allowlist for tool-output masking (RFC #40 Phase 1).

The log field names were verified against live FAZ 7.6.7 and 8.0.0 schemas
(``get_log_fields`` across traffic, event, attack, webfilter, dns, virus,
emailfilter and app-ctrl) — see the field-verification discussion on issue
#40. Names the RFC drafted that do not exist in any schema (src, srcaddr,
dst, dstaddr, srchost, dsthost, srcuser, remotename, email, message,
domain) are deliberately absent: masking a nonexistent field is a silent
no-op.

**Logs are not the only surface.** ``get_log_fields`` describes logview
rows. Alerts come from eventmgmt and incidents from incidentmgmt, and they
carry identifiers under different key names (``epip``, ``epname``,
``endpoint``, ``reporter``) plus composite keys that hold identifiers
inside a larger string (``groupby1``, ``grpby``, ``target[].value``). A
leak test over verbatim live records found real hostnames, domains, IPs
and usernames surviving a mask built from log names alone. Those keys are
covered below and by the composite handlers in ``wrapper.py``.

Matching is by key name at any nesting depth, so alert sub-objects
(``event_details`` carries ``src_ip``/``dst_ip``/``host_name``) and
wrapped log rows are covered by the same table.

FortiView and UEBA use yet another vocabulary: ``fortigate`` and
``detectkey`` name the reporting appliance, and ``devvds`` packs device
and vdom into ``"<devname>[<vdom>]"``. All three are device identity and
follow the ``FAZ_MASK_DEVICE_IDENTITY`` flag; ``devvds`` needs a composite
handler because the brackets fall outside the hostname alphabet, so a
plain hostname mask would burn it to an irreversible placeholder.

Out of scope here, by design:
- Device-identity fields (devname, devid, sn, csf, fortigate, devvds,
  detectkey, ...) identify the reporting estate rather than people. They
  are a separate deployment decision, so they live in
  ``DEVICE_IDENTITY_TYPES`` (plus ``COMPOSITE_DEVICE_VDOM``) and are
  masked only when ``FAZ_MASK_DEVICE_IDENTITY`` is set. Leaving them clear
  keeps the model able to reason about which appliance saw what, at the
  cost of fingerprinting the estate: a leak test still finds the firewall
  name and serial in a masked record unless the flag is on.
- ``incident_reporter`` is polymorphic: a username on a manually created
  incident, an alert id on an auto-raised one. Masking it would corrupt
  the alert id, so it is left alone pending a type-aware decision.
- ``url``/``referralurl`` need a URL-specific token design (alphabet and
  length) and are deferred with it.
- ``catdesc`` is a category label, not an identifier — masking it would
  only destroy analytic value.
- Alert-handler config (``name``, ``template-url``, ``mitre-domain``)
  carries product metadata, not customer data: live values are
  ``Default-Botnet-Communication-Detection-By-Endpoint``,
  ``/fazcfg-template/basic-handler/fgt`` and ``enterprise``. Note
  ``mitre-domain`` is an ATT&CK domain, not a DNS name; do not be tempted
  to type it as ``DOMAIN``. Only the operator-authored ``description`` is
  scanned, as free text.

Known gaps, recorded rather than guessed at:
- ``socialid`` (ueba ``endusers``) is a container, ``{"data": [...]}``, and
  is empty on every record of the reference estate. Its populated shape is
  unknown, so no type is assigned: the recursive walk descends into it and
  masks whatever allowlisted keys it turns out to hold. Revisit with a
  populated sample.
- ``threat``/``obf_url`` (fortiview ``top-threats``) hold a browsed domain
  on webfilter rows (``mask.icloud.com``, obfuscated as
  ``mask[dot]icloud[dot]com``) but a signature label on ips/virus rows,
  where a name like ``Adobe.Flash.Exploit`` is indistinguishable from a
  domain by shape alone. The sibling ``logtype`` almost certainly
  disambiguates them, but the reference estate produced no ips/virus row
  to confirm the mapping, so both are left clear rather than masked on a
  guess. This is a real leak of browsing destinations; see the RFC thread.
"""

# Value-type tags understood by the wrapper. "email" falls back to
# username masking when the value carries no "@" (the from/to fields are
# email addresses in virus/emailfilter logs but plain labels elsewhere).
IP = "ip"
MAC = "mac"
HOSTNAME = "hostname"
USERNAME = "username"
DOMAIN = "domain"
EMAIL = "email"
TEXT = "text"  # free text: embedded IOCs are masked in place
#: Holds either an address or a name depending on the record. Masks as
#: whichever it parses as; the two token forms stay distinguishable on the
#: way back (a hostname token carries the ``host-`` prefix, an IP token
#: parses as an IP), so the round trip is unambiguous.
IP_OR_HOST = "ip_or_host"

FIELD_TYPES: dict[str, str] = {
    # --- IP carriers (log fields + alert/event_details variants)
    "srcip": IP,
    "dstip": IP,
    "trueclntip": IP,
    "transip": IP,
    "tranip": IP,
    "ipaddr": IP,  # dns: resolved answer, may be a list
    "botnetip": IP,
    "ip": IP,
    "nat": IP,
    "locip": IP,
    "remip": IP,
    "assignip": IP,
    "tunnelip": IP,
    "tunnelsrcip": IP,
    "tunneldstip": IP,
    "srcremote": IP,
    "vipincomingip": IP,
    "dns_ip": IP,
    "ddnsserver": IP,
    "gateway": IP,
    "domainctrlip": IP,
    "epip": IP,
    "dstepip": IP,
    "ipv6": IP,  # event schema, new in FAZ 8.0.0
    "src_ip": IP,  # alert event_details
    "dst_ip": IP,  # alert event_details
    # --- MAC carriers
    "srcmac": MAC,
    "dstmac": MAC,
    "mastersrcmac": MAC,
    "masterdstmac": MAC,
    "mac": MAC,
    "bssid": MAC,
    "stamac": MAC,
    "tamac": MAC,
    "source_mac": MAC,
    # --- host / device-name carriers (people-adjacent, not estate identity)
    "srcname": HOSTNAME,
    "dstname": HOSTNAME,
    "hostname": HOSTNAME,
    "epname": IP_OR_HOST,
    "dstepname": IP_OR_HOST,
    "fqdn": HOSTNAME,
    "host": HOSTNAME,
    "dst_host": HOSTNAME,
    "host_name": HOSTNAME,  # alert event_details
    "dns_name": HOSTNAME,
    "servername": HOSTNAME,
    "serveraddr": HOSTNAME,
    "remotedevname": HOSTNAME,
    "domainctrlname": HOSTNAME,
    # --- username carriers
    "user": USERNAME,
    "dstuser": USERNAME,
    "unauthuser": USERNAME,
    "xauthuser": USERNAME,
    "eapuser": USERNAME,
    "useralt": USERNAME,
    "clouduser": USERNAME,
    "aiuser": USERNAME,
    "initiator": USERNAME,
    "admin": USERNAME,
    "remoteadmin": USERNAME,
    "euname": USERNAME,
    "dsteuname": USERNAME,
    "domainctrlusername": USERNAME,
    # --- domain carriers
    "qname": DOMAIN,
    "srcdomain": DOMAIN,
    "botnetdomain": DOMAIN,
    "domainctrldomain": DOMAIN,
    "scertcname": DOMAIN,
    # --- email carriers (from/to fall back to username when no "@")
    "sender": EMAIL,
    "recipient": EMAIL,
    "from": EMAIL,
    "to": EMAIL,
    "cc": EMAIL,
    "collectedemail": EMAIL,
    "dstcollectedemail": EMAIL,
    # --- free text: embedded IOCs masked in place
    "msg": TEXT,
    "logdesc": TEXT,
    "subject": TEXT,
    "extrainfo": TEXT,
    "ui": TEXT,  # event: frequently embeds the admin source IP, e.g. GUI(10.0.0.1)
    "prompt": TEXT,  # app-ctrl: GenAI prompt text
    "description": TEXT,  # eventmgmt handler config: operator-authored prose
    # --- eventmgmt / incidentmgmt object keys (NOT log fields; found by
    # leak-testing verbatim alert and incident records)
    "endpoint": IP_OR_HOST,  # incident: an address or an endpoint name
    "reporter": USERNAME,  # incident: who raised it
    "lastuser": USERNAME,  # incident: who last touched it
    "dstendpoint": IP_OR_HOST,  # inside the incident grpby JSON blob
    "srcendpoint": IP_OR_HOST,
    # --- response echo keys: tool responses reflect caller inputs at the
    # top level; a filter like srcip=="192.0.2.1" re-leaks the raw value
    # outside the log rows unless these are scanned too.
    "filter": TEXT,
    "filter_applied": TEXT,
    "device": HOSTNAME,
}

#: Composite keys whose value is a single string holding one or more
#: identifiers inside a larger structure. Name matching cannot reach them,
#: so ``wrapper.py`` parses each shape and masks the parts.
#:   groupby1/groupby2  "<fieldname>:<value>"   e.g. "dstip:192.0.2.1"
#:   grpby              JSON, e.g. '[{"dstendpoint": "192.0.2.1"}]'
#:   target             [{"name": "ip", "value": "192.0.2.1"}, ...]
COMPOSITE_PREFIXED = ("groupby1", "groupby2")
COMPOSITE_JSON = ("grpby",)
COMPOSITE_TARGET = ("target",)

#: fortiview ``devvds``: ``"<devname>[<vdom>]"``, comma-joined when a row
#: aggregates several devices. The brackets are outside the hostname
#: alphabet, so the device name must be lifted out before masking or the
#: whole string fails closed to an irreversible placeholder. Follows
#: ``FAZ_MASK_DEVICE_IDENTITY`` like the flat device keys below.
COMPOSITE_DEVICE_VDOM = ("devvds",)

#: Estate identity, not personal data. Masked only when the deployment
#: opts in via ``FAZ_MASK_DEVICE_IDENTITY``; see the module docstring.
DEVICE_IDENTITY_TYPES: dict[str, str] = {
    "devname": HOSTNAME,
    "devid": HOSTNAME,
    "sn": HOSTNAME,
    "serialno": HOSTNAME,
    "csf": HOSTNAME,
    "sndetected": HOSTNAME,
    "snclosest": HOSTNAME,
    "fortigate": HOSTNAME,  # fortiview: reporting device, comma-joined when aggregated
    "detectkey": HOSTNAME,  # ueba endpoints: serial of the detecting appliance
}

#: ``target[].name`` values, mapped to the type of the sibling ``value``.
TARGET_NAME_TYPES: dict[str, str] = {
    "ip": IP,
    "domain": DOMAIN,
    "device": IP_OR_HOST,
    "endpoint": IP_OR_HOST,
    "user": USERNAME,
}

# Values that carry no identifier and pass through unmasked.
SKIP_VALUES = frozenset({"", "N/A", "n/a", "unknown", "none", "-"})
