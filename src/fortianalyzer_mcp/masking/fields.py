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
#: Device serials. Separate from HOSTNAME because the string alphabet is
#: lowercase and a serial is not: masked as a hostname, ``FGT60FTK20000001``
#: comes back ``fgt60ftk20000001``, which is no longer the serial. The serial
#: cipher base32-shields the value first, so case and the hyphen survive.
#: Settled on #40; matches the type that shipped on fortimanager-mcp.
SERIAL = "serial"
TEXT = "text"  # free text: embedded IOCs are masked in place
#: Holds either an address or a name depending on the record. Masks as
#: whichever it parses as; the two token forms stay distinguishable on the
#: way back (a hostname token carries the ``host-`` prefix, an IP token
#: parses as an IP), so the round trip is unambiguous.
IP_OR_HOST = "ip_or_host"

#: Like IP_OR_HOST, plus a device serial. Needed for target[].value under
#: name=="device": measured fixture data shows this slot carries either an
#: endpoint hostname or the device's own serial (see the "sn" field type's
#: docstring for why a serial cannot round-trip as a hostname -- case is
#: lost). Kept separate from IP_OR_HOST rather than teaching every
#: IP_OR_HOST field to also try serial-shape, since none of the others
#: (endpoint, host_name) are documented to ever carry one.
IP_HOST_OR_SERIAL = "ip_host_or_serial"

FIELD_TYPES: dict[str, str] = {
    # --- IP carriers (log fields + alert/event_details variants)
    "srcip": IP,
    "dstip": IP,
    # --- alert-handler groupby dimension names (#80) -------------------- #
    # Read out of the live handler catalogue rather than guessed: 55 distinct
    # names ship across the rules, and these carry an identifier the flat
    # allowlist did not type. COMPOSITE_PREFIXED resolves "<field>:<value>"
    # through this same table, so covering groupby3 bought nothing while the
    # name inside it was unknown. Each takes the type of the covered twin it
    # sits beside in a record, so the two spellings of one value mint the
    # same token instead of publishing the pairing.
    "attackerip": IP,  # twin of srcip
    "victimip": IP,  # twin of dstip
    "host_ip": IP,  # twin of srcip
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
    # The name form of the same wireless network whose MAC form is
    # bssid above. Masking one while the other sits beside it in clear
    # is the twin disagreement #80 is about, so these follow bssid and
    # mask regardless of the device-identity flag.
    "ssid": HOSTNAME,
    "vap": HOSTNAME,
    "stamac": MAC,
    "tamac": MAC,
    "source_mac": MAC,
    # --- host / device-name carriers (people-adjacent, not estate identity)
    "srcname": HOSTNAME,
    "dstname": HOSTNAME,
    "hostname": HOSTNAME,
    "remotename": HOSTNAME,  # groupby (#80): IPsec/dialup peer name
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
    # fortiview-sources ships this beside the covered "unauthuser"; the
    # live sweep measured 5 of 5 payload shapes riding out verbatim
    # (username, email, DOMAIN\\user, hostname, IPv4) while the twin two
    # keys away masked the identical literal (#80).
    "f_user": USERNAME,
    "dstuser": USERNAME,
    "unauthuser": USERNAME,
    "user_name": USERNAME,  # groupby (#80): twin of user
    "user_id": USERNAME,  # groupby (#80): twin of user
    "enduser": USERNAME,  # groupby (#80): twin of user/euname
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
    "dst_domain": DOMAIN,  # groupby (#80): twin of qname
    "http_host": DOMAIN,  # groupby (#80): the HTTP Host header, twin of qname
    "srcdomain": DOMAIN,
    "botnetdomain": DOMAIN,
    "domainctrldomain": DOMAIN,
    "scertcname": DOMAIN,
    "domain": DOMAIN,  # fortiview top-websites: the site that was browsed
    # --- email carriers (from/to fall back to username when no "@")
    "sender": EMAIL,
    "recipient": EMAIL,
    "from": EMAIL,
    "mail_from": EMAIL,  # groupby (#80): twin of from
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
    "net_remote_server": IP_OR_HOST,  # groupby (#80): twin of dstendpoint
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
    # #80: the Security Fabric group name, promoted OUT of
    # DEVICE_IDENTITY_TYPES rather than left there. It is the org/customer
    # name (arguably more sensitive than the device serials it used to sit
    # beside), so it masks unconditionally rather than only with
    # FAZ_MASK_DEVICE_IDENTITY on. NOT a one-line dict move on its own: csf
    # frequently equals a device's own devname (the fabric root's own
    # hostname), and _device_identity_values's keep-set walk keys off
    # DEVICE_IDENTITY_TYPES membership, so removing csf from that dict
    # without also updating the walk would have unmasked it flag-off while
    # devname masked flag-on -- and with the flag OFF (no correlation
    # concern), the two staying different would have handed over the
    # token-to-name pairing the keep set exists to withhold. The walk keys
    # csf explicitly now (see _device_identity_values), so it still resolves
    # into the keep set with the flag off, unconditional typing here
    # notwithstanding.
    "csf": HOSTNAME,
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
#:
#: Every key here names a field, a column, or a view -- never a value, so a
#: caller has no legitimate reason to put a masked identifier in one, and each
#: is echoed back somewhere:
#:   fields      -> ``fields_returned`` (the original oracle, #95's shape)
#:   group_by    -> ``query_logs``'s echoed ``group_by`` on success, and
#:                  interpolated verbatim into the ``unsupported_group_dimension``
#:                  / ``group_dimension_logtype_mismatch`` refusal messages,
#:                  which is a *guaranteed* echo for any token, since a token
#:                  can never be a mapped dimension
#:   sample_by   -> ``query_logs``'s and ``analyze_policy_traffic``'s echoed
#:                  ``sample_by``, plus every ``breakdowns`` key
#:   sort_by     -> sort column names on the FortiView tools
#:   view_name   -> echoed by ``run_fortiview``/``fetch_fortiview``/
#:                  ``get_fortiview_data`` and by ``group_source``
#: The refusal path is what makes this urgent rather than theoretical: an
#: unmapped dimension is refused, and the refusal quotes the dimension. Resolve
#: the token first and the refusal hands back the plaintext -- a token ->
#: plaintext oracle that needs no valid query at all, only a bad one.
#:
#: This closes one direction only: token -> plaintext. The opposite,
#: plaintext -> token, stays open on ``fields`` alone -- measured, not
#: assumed. Its echo ``fields_returned`` is typed TEXT and is therefore
#: scanned by pass 2, so an unresolved argument reaches the tool body
#: verbatim and comes back masked, and a caller learns ``mask()`` of any value
#: it chooses (guess, mask, compare -- a chosen-plaintext check against a
#: token it already holds). ``fields`` being a *list* is what makes it worth
#: naming: N guesses per call rather than one.
#:
#: The other four echo verbatim and are never scanned -- ``group_by``,
#: ``sample_by``, ``sort_by`` and ``view_name`` have no ``FIELD_TYPES`` entry,
#: so the direction is closed there today. Closed incidentally, though, not by
#: design: typing any of those echoes would open it, which is the thing to
#: remember when adding one.
#:
#: The oracle itself is not new and not closable from here -- an echoed
#: ``filter`` over an untyped field does the same on every release since
#: masking shipped (verified against main, not inferred: ``dstport=="<ip>"``
#: comes back with the token substituted). Only a keyed tag on tokens (#40's
#: authenticated envelope) makes a chosen-plaintext token distinguishable from
#: a real one. Recorded so the docstring neither overclaims safety nor
#: overclaims exposure.
FIELD_NAME_ARGS = ("fields", "group_by", "sample_by", "sort_by", "view_name")

#: Composite keys whose value is a single string holding one or more
#: identifiers inside a larger structure. Name matching cannot reach them,
#: so ``wrapper.py`` parses each shape and masks the parts.
#:   groupby1/groupby2  "<fieldname>:<value>"   e.g. "dstip:192.0.2.1"
#:   grpby              JSON, e.g. '[{"dstendpoint": "192.0.2.1"}]'
#:   target             [{"name": "ip", "value": "192.0.2.1"}, ...]
#: ``groupby3`` was uncovered while its two siblings were handled. The
#: shipped alert-handler catalogue puts ``qname`` in slot 3 on one
#: handler, so an allowlisted dimension rode through in clear purely
#: because of which slot it landed in (#80).
COMPOSITE_PREFIXED = ("groupby1", "groupby2", "groupby3")
#: ``auto_raise_grpby`` is the incident-surface twin of ``grpby`` and
#: carries the identical JSON payload; it was uncovered while its twin
#: masked, measured on the live estate (#80).
COMPOSITE_JSON = ("grpby", "auto_raise_grpby")
COMPOSITE_TARGET = ("target",)

#: The structural twin of ``target`` on the alert surface, same
#: ``[{"name": ..., "value": ...}]`` shape, measured carrying an endpoint
#: address in clear while five allowlisted renderings of the same asset
#: masked in the same response (#80).
#:
#: Deliberately NOT folded into ``COMPOSITE_TARGET``: that kind burns every
#: non-list shape, and ``get_endpoints`` at ``detail_level="standard"``
#: emits a bare scalar ``source``, so a blanket burn would destroy an
#: ordinary field on every endpoint read. ``target`` can afford to burn
#: because the name is specific to one surface; ``source`` is a generic
#: word and cannot. Only the list form is claimed here; every other shape
#: keeps the ordinary allowlist treatment.
COMPOSITE_SOURCE = ("source",)

#: ``analyze_policy_traffic`` and ``query_logs(sample_by=...)``:
#: ``{dimension: [{"value": "...", "hits": N}, ...]}``. The dimension name
#: (the dict key one level up) decides the type of each bucket's
#: ``"value"``, exactly the "field decides the paired value's type" shape
#: ``groupby1`` already uses, just with the field name sitting one level up
#: instead of packed into the string. Verified live to leak: a synthetic
#: ``{"breakdowns": {"srcip": [{"value": "10.1.2.3", "hits": 5}]}}`` survived
#: masking whole -- pass 1 only masks a bare ``"value"`` key when a sibling
#: ``"type"`` key exists (``_mask_indicator_pair``, SOAR-specific), and pass 2
#: only scans keys typed TEXT, which a plain ``"value"`` key never is.
#:
#: Deliberately NOT a "burn unknown dimension" handler like ``target``'s: a
#: caller may group by almost any field (``port``, ``service``, ``app``,
#: ``proto``, a derived dimension with no field type at all), and most of
#: those are not identifiers. A dimension absent from ``FIELD_TYPES`` (and
#: from ``DEVICE_IDENTITY_TYPES`` unless ``FAZ_MASK_DEVICE_IDENTITY`` is set)
#: passes its bucket values through untouched instead of being burned to a
#: placeholder -- the device-identity keep-set applies here exactly as it
#: does to a flat field, because the lookup is the same shared type table.
#:
#: A TEXT dimension (``sample_by=["msg"]``, ``["ui"]``, ``["subject"]``) is the
#: one class pass 1 cannot finish: prose has no scalar type to mask by, and the
#: generic ``"value"`` key means the sentence above applies to it too -- pass 2
#: never reached it, so the free text rode out in clear while a hostname inside
#: it sat beside its own token in a sibling row (#109 review). ``wrapper``
#: therefore handles this key in BOTH passes: identifier dimensions in pass 1,
#: TEXT dimensions in pass 2 via ``_mask_breakdown_text``, which gives a bucket
#: value the same scan the flat key of that name gets. Only TEXT, because a
#: pass-1 token is itself a valid IPv4 and a second scan would mask it again.
COMPOSITE_BREAKDOWNS = ("breakdowns",)

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

#: fortiview-sources aggregates: ``"<identifier>,<devtype>"``, where the
#: tail is an OS or product string (``"DSM 7.3-86009"``, ``"Ubuntu
#: 22.04.5"``). Each maps to the type its own head carries, which is the
#: type the covered flat spelling of the same value already uses:
#: ``mac_devtype_agg`` beside ``mac``/``dstmac``, ``dev_src_agg`` beside
#: ``hostname``/``srcname``/``device``.
#:
#: A flat ``FIELD_TYPES`` entry is the wrong fix and was rejected: it would
#: hand the whole ``"<identifier>,<devtype>"`` string to a scalar handler,
#: which fails closed to an irreversible placeholder and burns the devtype
#: with it. Same reason ``devvds`` has a handler rather than a type.
#:
#: NOT gated on ``FAZ_MASK_DEVICE_IDENTITY``, unlike the neighbouring
#: ``COMPOSITE_DEVICE_VDOM``. These carry endpoint identity, not estate
#: identity: their covered twins are ``FIELD_TYPES`` entries that mask with
#: the flag off, and masking one spelling while its twin stays readable in
#: the same record is what publishes the mapping (#80).
COMPOSITE_ID_DEVTYPE: dict[str, str] = {
    "mac_devtype_agg": MAC,
    "dev_src_agg": HOSTNAME,
}

#: Estate identity, not personal data. Masked only when the deployment
#: opts in via ``FAZ_MASK_DEVICE_IDENTITY``; see the module docstring.
DEVICE_IDENTITY_TYPES: dict[str, str] = {
    "devname": HOSTNAME,
    # groupby (#80): the logging device's own name, estate identity of the
    # same class as devname, so it follows the flag rather than masking
    # unconditionally. Measured leaking in BOTH flag states before this,
    # which is what separates it from devname reading as a leak flag-off.
    "logdev_name": HOSTNAME,
    # This repo's own tools layer documents devid as the SERIAL-carrying
    # spelling, in three places: fortiview_tools.py builds
    # [{"devid": <serial>}] for a serial-shaped value and notes that "a
    # serial under devname silently matches nothing", and report_tools.py
    # routes "serials -> devid, names -> devname". Typed HOSTNAME it kept
    # the exact round-trip bug SERIAL was added to fix: a serial came back
    # lowercased, and it minted a different token from the same serial
    # under sn on the same list_devices row.
    #
    # IP_HOST_OR_SERIAL rather than a flat SERIAL because devid is
    # polymorphic in practice, holding a device NAME on the surfaces the
    # #80 sweep sampled. Same reasoning, and the same type, as the
    # "device" target slot.
    "devid": IP_HOST_OR_SERIAL,
    # logs-event: the access point's own name, estate identity of the
    # same class as devname, so it follows the flag rather than masking
    # unconditionally the way the ssid beside it does (#80).
    "ap": HOSTNAME,
    # The serial-carrying keys take SERIAL rather than HOSTNAME, so they
    # round-trip byte-exact. Only keys already in this table move; the
    # spelling variants found in #80 (module_sn, tunnel_sn) are not added
    # here, because which table they belong in is still Roland's call.
    #
    # Safe even where one of these turns out to carry something that is not
    # a serial: the serial cipher shields arbitrary bytes through base32, so
    # it accepts strictly more than the hostname alphabet does. The visible
    # change is the token prefix, sn- instead of host-.
    "sn": SERIAL,
    "serialno": SERIAL,
    # get_system_status spells its keys Title Case With Spaces. "Hostname"
    # matched despite the capital H because every key match lowercases, but
    # "Serial Number" differs from sn by more than case and matched
    # nothing, so the serial rode out beside a masked hostname in the same
    # dict (#80). Key matching lowercases and does not strip whitespace, so
    # the alias is spelled with the space. Typed SERIAL, not HOSTNAME, for
    # the same reason sn moved: it is the identical value under an
    # alternately-spelled key, and typing the alias differently from the
    # key it aliases would reopen the exact round-trip bug that move fixed.
    "serial number": SERIAL,
    "sndetected": SERIAL,
    "snclosest": SERIAL,
    "fortigate": HOSTNAME,  # fortiview: reporting device, comma-joined when aggregated
    # This table's own comment called it a serial, and it was still typed as
    # a hostname, so it kept the exact round-trip bug the serial type was
    # added to fix. Found by review after the first pass moved only the
    # sn-spelled keys.
    "detectkey": SERIAL,  # ueba endpoints: serial of the detecting appliance
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
    "device": IP_HOST_OR_SERIAL,
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
#: ``link`` is here precisely because the reputation source puts the
#: indicator in the reference URL query string, but the raw IOC tool
#: emits ``reference_url``: ``client.py`` sets the row verbatim and
#: only the skills layer renames it, so the raw spelling was typed by
#: nothing (#80).
COMPOSITE_URL_FULL = ("url", "referralurl", "link", "reference_url")

# Values that carry no identifier and pass through unmasked.
#: ``<>`` is the SMTP null return path, carried by every bounce and DSN. It is
#: a protocol constant, not a principal, and typing ``mail_from`` (#80) turned
#: the most common value on that surface into an irreversible placeholder that
#: names nobody.
SKIP_VALUES = frozenset({"", "N/A", "n/a", "unknown", "none", "-", "<>"})
