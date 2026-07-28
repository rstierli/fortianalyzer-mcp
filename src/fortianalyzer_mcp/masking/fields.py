"""Field allowlist for tool-output masking (RFC #40 Phase 1).

The log field names were verified against live FAZ 7.6.7 and 8.0.0 schemas
(``get_log_fields`` across traffic, event, attack, webfilter, dns, virus,
emailfilter and app-ctrl) — see the field-verification discussion on issue
#40. Names the RFC drafted that do not exist in any schema (src, srcaddr,
dst, dstaddr, srchost, dsthost, srcuser, remotename) are deliberately
absent: masking a nonexistent field is a silent no-op.

``email``, ``domain`` and ``message`` were dropped on those same grounds
and have since stopped qualifying. The logview vocabulary is not the only
one the tools read: UEBA returns ``email`` on an extended ``get_endusers``
record, FortiView names a browsed site ``domain`` on a top-websites row,
and every tool answers an error under ``message``. Absent from
``get_log_fields`` does not mean absent from a tool response, so each is
carried below with the type its real carrier uses.

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
- ``vpntunnel`` (fortiview ``site-to-site-ipsec``) names an IPsec tunnel
  and therefore the two sites it joins, and it is deliberately left clear
  for 2.10.0. Typing it would cost more than it buys: a tunnel name is a
  free-form operator label, so while ``hq-to-branch`` and
  ``site_a-site_b`` mask and round-trip, anything carrying a space or
  punctuation (``to-DC (primary)``, ``tunnel#1``) falls outside the
  hostname alphabet and burns to an irreversible placeholder, and an
  uppercase name comes back lowercased. Burning readable operator labels
  to close an off-by-default gap on a lower-sensitivity field is the
  wrong trade. Closing it properly needs the ``devvds`` treatment, a
  composite handler that lifts the maskable part out first, and that is
  a GA decision rather than a beta patch.
- Report artifacts (``get_report_data`` / ``fetch_report`` output) are
  out of masking scope: the flag masks live query surfaces, not rendered
  documents. Those tools return the report base64-encoded (PDF, HTML,
  CSV, XML), the masker walks the JSON envelope and cannot see inside an
  encoded blob, so identifiers inside report tables reach the caller
  raw, and PDF is inherently out of scope. Decoding and masking the
  text formats is a GA backlog item (#80); a partial cover would read
  as coverage while PDF still leaks.
- ``incident_reporter`` is polymorphic: a username on a manually created
  incident, an alert id on an auto-raised one, so it carries no type
  here. The username case is decided per record instead: when the value
  equals the sibling ``reporter``/``lastuser`` it masks with the same
  token (``wrapper._mask_incident_reporter``); anything else stays clear
  so alert ids survive intact.
- ``url``/``referralurl`` are carry-and-reverse (#40 decision): the host
  masks in place and the whole tail (path+query+fragment) seals into one
  reversible ``url-<kid>-<ct>`` token (``COMPOSITE_URL_FULL``,
  ``wrapper._mask_url_full``). The raw tail is base32-shielded before
  encryption so hostile bytes (``~``, percent-encoding, mixed case,
  non-ASCII) ride the existing string cipher and round-trip exactly.
  Documented residuals: scheme and port stay clear; the token length
  reveals the tail's byte length (base32 is a fixed ~1.6x expansion and
  FF3 is length-preserving); identical tails and shared-first-chunk
  prefixes correlate, the same chunking residual as every string type;
  and substring search inside the tail (``url contain "/login"``) is an
  accepted loss. One more, conservative by design: a hostless value whose
  decoded form carries a ``@`` before the first slash (an email or
  userinfo-looking fragment with no path) fails closed to an irreversible
  placeholder rather than sealing reversibly: the credentials guard
  cannot tell an innocent address from a secret, and burning the one
  value is the safe direction to err. ``http_url`` (alert ``event_details``) stays HOST-only
  by the same decision: live alerts carry a full URL whose host is the
  browsed destination, so the host masks in place
  (``COMPOSITE_URL_HOST``, ``wrapper._mask_url_host``) while path and
  query stay clear — upgrading it to the full-tail treatment is a GA-time
  call behind its own flag. Path/query identifiers in ``http_url`` remain
  its documented residual.
- ``catdesc`` is a category label, not an identifier — masking it would
  only destroy analytic value.
- Alert-handler config (``name``, ``template-url``, ``mitre-domain``)
  carries product metadata, not customer data: live values are
  ``Default-Botnet-Communication-Detection-By-Endpoint``,
  ``/fazcfg-template/basic-handler/fgt`` and ``enterprise``. Note
  ``mitre-domain`` is an ATT&CK domain, not a DNS name; do not be tempted
  to type it as ``DOMAIN``. Only the operator-authored ``description`` is
  scanned, as free text.

``threat``/``obf_url`` (fortiview ``top-threats``) are masked as a pair:
``threat`` holds a browsed web domain exactly when the sibling ``obf_url``
is non-empty (``obf_url`` is the ``[dot]``-escaped twin of the same
value), and ``obf_url`` is empty on every signature, filename and anomaly
row — verified across both reference estates on the RFC #40 thread, where
``logtype`` turned out NOT to discriminate (domains arrive under a traffic
logtype on both estates — an early webfilter-logtype sighting did not
reproduce on the same box — and malware-detected rows carry dotted
*filenames* in ``threat`` that any shape test would misread as domains;
even a live AV detection surfaces as a traffic row, never a virus
logtype). So the sibling decides: non-empty
``obf_url`` masks both as domains, empty leaves ``threat`` clear with its
analytic value intact. See ``wrapper._mask_threat_pair`` for the residual.

Known gaps, recorded rather than guessed at:
- ``socialid`` (ueba ``endusers``) is a container, ``{"data": [...]}``, and
  is empty on every record of the reference estate. Its populated shape is
  unknown, so no type is assigned: the recursive walk descends into it and
  masks whatever allowlisted keys it turns out to hold. Revisit with a
  populated sample.
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
    # fortiview top-sources/top-destinations: the resolved name for the
    # sibling srcip/dstip, or that same address again when nothing
    # resolves. Untyped, it handed back the raw address sitting beside its
    # own token, which discloses the pairing and not just the value.
    "srcip_hostname": IP_OR_HOST,
    "dstip_hostname": IP_OR_HOST,
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
    "domain": DOMAIN,  # fortiview top-websites: the site that was browsed
    # --- email carriers (from/to fall back to username when no "@")
    "sender": EMAIL,
    "recipient": EMAIL,
    "from": EMAIL,
    "to": EMAIL,
    "cc": EMAIL,
    "collectedemail": EMAIL,
    "dstcollectedemail": EMAIL,
    "email": EMAIL,  # ueba get_endusers, detail_level="extended"
    # --- free text: embedded IOCs masked in place
    "msg": TEXT,
    "logdesc": TEXT,
    "subject": TEXT,
    "extrainfo": TEXT,
    "ui": TEXT,  # event: frequently embeds the admin source IP, e.g. GUI(10.0.0.1)
    "prompt": TEXT,  # app-ctrl: GenAI prompt text
    "description": TEXT,  # eventmgmt handler config: operator-authored prose
    # --- resolved address-object labels (traffic logs). srcuuid_name /
    # dstuuid_name are the *names* of the firewall address objects that
    # matched the session's src/dst — operator-authored labels populated on
    # ~90% of live rows (230,092/256,483 on the reference estate, #80). The
    # raw uuids (srcuuid/dstuuid) carry no human content and are left out;
    # the resolved *name* is the leak. TEXT rather than HOSTNAME: an object
    # label is free-form ("Printer Floor 3", "jdoe-laptop", "all"), so
    # HOSTNAME masking would burn anything carrying a space or punctuation
    # to an irreversible placeholder. TEXT never burns and masks any
    # embedded IOC (bare IPv4/MAC/email) in place. Documented residual: a
    # plain descriptive label with no embedded IOC rides through clear —
    # accepted here as the conservative direction (a burned routing/label
    # value is worse than a readable object name); revisit at GA if a
    # burn-tolerant name type is added.
    # Round-trip residual: the traffic vocabulary is complete=False, so these
    # names pass through as structured filter fields and the appliance does
    # serve them (exact equality on a displayed label returns rows on 7.6.7
    # and 8.0.0). A label carrying an embedded IOC masks outbound but does
    # not resolve inbound: _unmask_entry passes a vtype to resolve_scalar
    # only for IP/MAC/IP_OR_HOST, so a TEXT value falls through untyped and
    # reverses only when the *whole* string is a marked token. An IP token
    # sitting mid-string is neither, so re-using a displayed label as a
    # filter value sends a plausible-but-wrong address to the appliance,
    # silently. Pre-existing to every filterable TEXT field; tracked on #73.
    "srcuuid_name": TEXT,
    "dstuuid_name": TEXT,
    # --- eventmgmt / incidentmgmt object keys (NOT log fields; found by
    # leak-testing verbatim alert and incident records)
    "endpoint": IP_OR_HOST,  # incident: an address or an endpoint name
    "reporter": USERNAME,  # incident: who raised it
    "lastuser": USERNAME,  # incident: who last touched it
    # The incident workflow slots. Same principals as reporter/lastuser,
    # and empty on an estate that does not work incidents, which is why
    # they were missed. EMAIL rather than USERNAME because it is a strict
    # superset here: a value with no "@" falls back to username masking and
    # produces the IDENTICAL token, so one analyst keeps one token across
    # all five keys, while an "@"-shaped login still masks instead of
    # burning. A domain-qualified login (DOMAIN\\user) is outside both
    # alphabets and still fails closed to a placeholder.
    "assigned_to": EMAIL,
    "remedy_executor": EMAIL,
    "remedy_approver": EMAIL,
    "dstendpoint": IP_OR_HOST,  # inside the incident grpby JSON blob
    "srcendpoint": IP_OR_HOST,
    # --- response echo keys: tool responses reflect caller inputs at the
    # top level; a filter like srcip=="192.0.2.1" re-leaks the raw value
    # outside the log rows unless these are scanned too.
    "filter": TEXT,
    "filter_applied": TEXT,
    # The projection echo. Same class of bug as filter_applied (#95): argument
    # unmasking runs at the wrapper boundary, so a tool building
    # ``fields_returned`` is holding whatever the caller's ``fields`` list
    # resolved to. ``fields`` names response KEYS rather than values, so the
    # real close is FIELD_NAME_ARGS below -- the token never becomes plaintext
    # in the first place. TEXT is the belt to that braces: it gives the echo
    # the same pass-2 substitution and IOC scan every other caller-facing
    # string gets, for any other route by which a value reaches this key.
    "fields_returned": TEXT,
    "device": HOSTNAME,
    # --- caller-facing prose: the skills layer and every tool error build
    # these strings themselves, and they name the record they are about
    # ("2 end-users match username 'jdoe'"). Pass 1 masks the record's own
    # keys, so without these the same identifier is a token under one key
    # and clear two keys away. TEXT, so pass 2 masks in place and nothing
    # here is ever burned.
    "warnings": TEXT,
    "message": TEXT,
    "reason": TEXT,
    # --- Wave-3 skill assembly keys (#89 investigate_deep, #90 hunt). Each
    # is a string the skill builds itself around an identifier the same
    # response masks under the value's own key, so leaving them untyped
    # handed over the token-to-raw pairing (the srcip_hostname class again):
    # rows[].srcip a token, pivot "srcip==<raw>" beside it. TEXT gives them
    # exactly the treatment filter/filter_applied already get: pass 2
    # substitutes any value this response mapped (closing the pairing) and
    # the IOC scan masks bare IPv4/MAC/email. They inherit filter's known
    # residuals too, unchanged and not widened here: a value that appears
    # nowhere else in the response and is not IPv4/MAC/email-shaped (a bare
    # hostname, a cold username, a bare IPv6, a quoted clause value) rides
    # through as written. Two of these keys are filter clauses, so the
    # proper close for the whole family (filter, filter_applied, pivot,
    # pivot_filter) is a clause composite that masks the RHS by the inner
    # field's type, mirroring unmask_filter; that is a GA-grade change to a
    # shipped surface and is tracked in #80, not bundled into this parity
    # fix.
    "pivot": TEXT,  # investigate_deep impact entities: 'srcip==<value>'
    "pivot_filter": TEXT,  # hunt sweep: same clause shape
    "entity_ref": TEXT,  # investigate_deep: caller's entity, may be a bare IP
    "headline": TEXT,  # skill summaries; first interpolated an identifier in #89
}

#: Tool-argument keys whose value names *fields*, not values, and which the
#: argument unmasker must therefore leave alone.
#:
#: ``resolve_scalar`` resolves any self-identifying token wherever it appears,
#: and ``query.fields.resolve_field`` passes an unknown-but-well-shaped name
#: through -- and a mask token (``host-6b7e-zwyu4i8an``) is well shaped. So a
#: token placed in ``fields`` was unmasked to plaintext, used as a projection
#: key, and echoed back under ``fields_returned``: a complete token ->
#: plaintext oracle driven entirely by the model's own token. A field name is
#: never customer data, so there is nothing here for unmasking to be right
#: about; skipping the key closes the round trip at the source rather than
#: trying to re-mask the echo afterwards.
#:
#: Structured-filter conditions are already handled this way for the same
#: reason: ``unmask_filter_conditions`` resolves only ``value`` and leaves the
#: sibling ``field`` untouched.
FIELD_NAME_ARGS = ("fields",)

#: Composite keys whose value is a single string holding one or more
#: identifiers inside a larger structure. Name matching cannot reach them,
#: so ``wrapper.py`` parses each shape and masks the parts.
#:   groupby1/groupby2  "<fieldname>:<value>"   e.g. "dstip:192.0.2.1"
#:   grpby              JSON, e.g. '[{"dstendpoint": "192.0.2.1"}]'
#:   target             [{"name": "ip", "value": "192.0.2.1"}, ...]
COMPOSITE_PREFIXED = ("groupby1", "groupby2")
COMPOSITE_JSON = ("grpby",)
COMPOSITE_TARGET = ("target",)

#: ``filter_applied`` when a tool echoes a *compiled* filter as
#: ``[[field, op, value], ...]`` rather than as one string. Argument
#: unmasking runs at the wrapper boundary, so a tool that compiles a
#: caller's structured filter is holding the RESOLVED identifier by the time
#: it builds these entries; echoing them untyped hands the raw value back to
#: the model, unlocked by the model's own token.
#:
#: TEXT is not enough on its own. Pass 2 substitutes values this response
#: mapped and scans for IPv4/MAC/email shapes, so an entry survives in clear
#: exactly when the query matched nothing and the mapping is therefore empty:
#: a hostname, a username or an IPv6 address rides straight back out. Each
#: entry names its own field, so ``wrapper._mask_filter_entries`` masks the
#: value by that field's type instead, the inverse of the way a structured
#: condition is resolved on the way in. The string form of the key keeps its
#: ordinary TEXT treatment.
COMPOSITE_FILTER_ENTRIES = ("filter_applied",)

#: fortiview ``top-threats`` pair, masked together by
#: ``wrapper._mask_threat_pair``: a non-empty ``obf_url`` marks the row as
#: a browsed-domain threat; ``obf_url`` itself is the ``[dot]``-escaped
#: twin of ``threat``.
THREAT_KEY = "threat"
OBF_URL_KEY = "obf_url"

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
    # eventmgmt alert subject_details: {alertid, devs, epids, euids}. Same
    # class as devname, and until it was listed here it defeated the flag
    # rather than following it: the device stayed clear under "devs" while
    # the sibling "devname" masked, handing over the token-to-name pairing
    # the flag exists to withhold.
    "devs": HOSTNAME,
    # fortiview policy-hits nests the reporting appliance a second time,
    # under device_info.dev_name, spelled with an underscore. Same class as
    # devname and the same failure devs had: it defeated the flag instead
    # of following it, keeping the name clear beside a masked devid.
    "dev_name": HOSTNAME,
}

#: ``target[].name`` values, mapped to the type of the sibling ``value``.
TARGET_NAME_TYPES: dict[str, str] = {
    "ip": IP,
    "domain": DOMAIN,
    "device": IP_OR_HOST,
    "endpoint": IP_OR_HOST,
    "user": USERNAME,
    # Live webfilter alerts carry the browsed destination as a host_name
    # target; IP_OR_HOST keeps its token identical to the flat
    # ``host_name`` field on the same record.
    "host_name": IP_OR_HOST,
}

#: Keys holding a full URL whose HOST component is the identifier: the
#: host is masked in place, scheme/path/query stay clear (kept host-only
#: by the #40 decision; may upgrade to the full-tail treatment at GA
#: behind its own flag).
COMPOSITE_URL_HOST = ("http_url",)

#: Keys holding a full URL treated as carry-and-reverse (#40 decision):
#: the host masks in place exactly like COMPOSITE_URL_HOST, and the whole
#: tail (path+query+fragment) seals into one reversible ``url-`` token.
#: Substring search inside the tail is an accepted, documented loss.
#: ``link`` is the SOAR reputation source's reference URL, and the source
#: puts the indicator in its query string ("...?query=<indicator>"), so the
#: sensitive part is the tail, not the public portal host. Same treatment
#: as ``url``, which keeps it reversible for anyone who wants to follow it.
COMPOSITE_URL_FULL = ("url", "referralurl", "link")

# Values that carry no identifier and pass through unmasked.
SKIP_VALUES = frozenset({"", "N/A", "n/a", "unknown", "none", "-"})
