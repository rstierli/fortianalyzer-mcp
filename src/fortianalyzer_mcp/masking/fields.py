"""Field allowlist for tool-output masking (RFC #40 Phase 1).

Every entry below was verified against live FAZ 7.6.7 and 8.0.0 schemas
(``get_log_fields`` across traffic, event, attack, webfilter, dns, virus,
emailfilter and app-ctrl, plus real rows and alert records) — see the
field-verification discussion on issue #40. Names the RFC drafted that do
not exist in any schema (src, srcaddr, dst, dstaddr, srchost, dsthost,
srcuser, remotename, email, message, domain) are deliberately absent:
masking a nonexistent field is a silent no-op.

Matching is by key name at any nesting depth, so alert sub-objects
(``event_details`` carries ``src_ip``/``dst_ip``/``host_name``) and
wrapped log rows are covered by the same table.

Out of scope here, by design:
- Device-identity fields (devname, devid, sn, csf, ...) identify the
  reporting estate rather than people; whether to mask them is a separate
  deployment decision and not part of the default allowlist.
- ``url``/``referralurl`` need a URL-specific token design (alphabet and
  length) and are deferred with it.
- ``catdesc`` is a category label, not an identifier — masking it would
  only destroy analytic value.
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
    "epname": HOSTNAME,
    "dstepname": HOSTNAME,
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
    # --- response echo keys: tool responses reflect caller inputs at the
    # top level; a filter like srcip=="10.1.2.3" re-leaks the raw value
    # outside the log rows unless these are scanned too.
    "filter": TEXT,
    "filter_applied": TEXT,
    "device": HOSTNAME,
}

# Values that carry no identifier and pass through unmasked.
SKIP_VALUES = frozenset({"", "N/A", "n/a", "unknown", "none", "-"})
