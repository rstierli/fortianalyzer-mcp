# FortiAnalyzer API Changes: 7.6.4 → 7.6.5

Generated: 2025-12-22 09:31:03

## Summary

| Metric | Value |
|--------|-------|
| Old Version | 7.6.4 |
| New Version | 7.6.5 |
| Total Modules | 19 |
| Changed Modules | 2 |
| Unchanged Modules | 17 |
| New Endpoints | +21 |
| Removed Endpoints | -1 |

---

## Detailed Changes

### Daemon Modules cli_system

**File size**: 3,805,822 → 3,895,693 bytes (+89,871 bytes)

**New Endpoints (20):**

```
/cli/global/system/locallog/tacacs+accounting/filter (get)
/cli/global/system/locallog/tacacs+accounting/filter (set)
/cli/global/system/locallog/tacacs+accounting/filter (update)
/cli/global/system/locallog/tacacs+accounting/setting (get)
/cli/global/system/locallog/tacacs+accounting/setting (set)
/cli/global/system/locallog/tacacs+accounting/setting (update)
/cli/global/system/log/api-ratelimit (get)
/cli/global/system/log/api-ratelimit (set)
/cli/global/system/log/api-ratelimit (update)
/cli/global/system/log/settings/client-cert-auth (get)
/cli/global/system/log/settings/client-cert-auth (set)
/cli/global/system/log/settings/client-cert-auth (update)
/cli/global/system/log/settings/client-cert-auth/trusted-client (add)
/cli/global/system/log/settings/client-cert-auth/trusted-client (get)
/cli/global/system/log/settings/client-cert-auth/trusted-client (set)
/cli/global/system/log/settings/client-cert-auth/trusted-client (update)
/cli/global/system/log/settings/client-cert-auth/trusted-client/{trusted-client} (delete)
/cli/global/system/log/settings/client-cert-auth/trusted-client/{trusted-client} (get)
/cli/global/system/log/settings/client-cert-auth/trusted-client/{trusted-client} (set)
/cli/global/system/log/settings/client-cert-auth/trusted-client/{trusted-client} (update)
```

**New Definitions (6):**

- `cli.system.locallog.tacacs+accounting.filter`
- `cli.system.locallog.tacacs+accounting.setting`
- `cli.system.log.api-ratelimit`
- `cli.system.log.settings.client-cert-auth`
- `cli.system.log.settings.client-cert-auth.trusted-client`
- `list.cli.system.log.settings.client-cert-auth.trusted-client`

**New Tags (5):**

- `/cli/system/locallog/tacacs+accounting/filter`
- `/cli/system/locallog/tacacs+accounting/setting`
- `/cli/system/log/api-ratelimit`
- `/cli/system/log/settings/client-cert-auth`
- `/cli/system/log/settings/client-cert-auth/trusted-client`

---

### FortiAnalyzer Modules report

**File size**: 237,183 → 240,586 bytes (+3,403 bytes)

**New Endpoints (1):**

```
/report/config/import (add)
```

**Removed Endpoints (1):**

```
/report/config-file/import (add)
```

**New Definitions (2):**

- `report.config.import.add.req`
- `report.config.import.add.resp`

**Removed Definitions (2):**

- `report.config-file.import.add.req`
- `report.config-file.import.add.resp`

**New Tags (1):**

- `/report/config/import`

**Removed Tags (1):**

- `/report/config-file/import`

---

## Unchanged Modules

The following modules have no API changes:

| Module | File Size |
|--------|-----------|
| Daemon Modules cli__meta_fields | 22,152 bytes |
| Daemon Modules cli_exec | 6,532 bytes |
| Daemon Modules cli_fmupdate | 409,917 bytes (-24 bytes) |
| Daemon Modules dvm | 72,819 bytes (+231 bytes) |
| Daemon Modules sys | 49,462 bytes |
| Daemon Modules um | 13,061 bytes |
| Device Manager Database dvmdb | 440,260 bytes (+264 bytes) |
| Device Manager Database task | 44,519 bytes |
| FortiAnalyzer Modules eventmgmt | 174,358 bytes |
| FortiAnalyzer Modules fazsys | 114,233 bytes |
| FortiAnalyzer Modules fortiview | 120,503 bytes |
| FortiAnalyzer Modules incidentmgmt | 109,815 bytes |
| FortiAnalyzer Modules ioc | 35,454 bytes |
| FortiAnalyzer Modules logview | 95,194 bytes |
| FortiAnalyzer Modules soar | 297,376 bytes |
| FortiAnalyzer Modules sql-report | 14,224 bytes |
| FortiAnalyzer Modules ueba | 81,372 bytes |
