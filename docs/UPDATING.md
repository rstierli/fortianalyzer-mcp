# Updating FortiAnalyzer MCP Server for New API Versions

This document describes the workflow for updating the MCP server when new FortiAnalyzer versions are released.

## Overview

Fortinet releases new FortiAnalyzer versions approximately every 6-8 weeks. Each release may include:
- New API endpoints
- Modified parameters for existing endpoints
- Deprecated endpoints
- Bug fixes in API behavior

## Update Workflow

### Step 1: Obtain FNDN API Definitions

1. Download the latest FNDN (Fortinet Developer Network) API specifications from:
   - FNDN Portal: https://fndn.fortinet.net/
   - Or extract from FortiAnalyzer: `System > API > Export`

2. Place them in `docs/fndn/<version>/`. That directory is **gitignored** — the
   specs are a local working copy, not part of the repo.

   The portal ships the reference as a set of **HTML** pages, roughly 45 per
   version — not the per-module JSON this document used to describe.
   `tools/compare_api_versions.py` still expects JSON and does not read the HTML.

   ```text
   docs/fndn/
   ├── 7.6.6/
   │   ├── faz_logview.htm   faz_eventmgmt.htm   faz_incidentmgmt.htm
   │   ├── faz_fortiview.htm faz_report.htm      faz_reportconfig.htm
   │   ├── faz_ioc.htm       faz_soar.htm        faz_ueba.htm  faz_fazsys.htm
   │   ├── dvmdb-*.htm  task-*.htm  sys-*.htm  cli-*.htm  um-*.htm
   │   └── index.htm    obj-index.htm  objects.htm
   └── 8.0.0/            # New version
       └── ...
   ```

> **Name the directory after the version in the page titles, not the download.**
> Every page carries `<title>FortiAnalyzer X.Y.Z (build) JSON API Reference…`.
> A bundle downloaded as "7.6.7" was found to contain 7.6.6 (build 3654) pages
> throughout. Check before trusting a directory name:
>
> ```bash
> grep -h -o '<title>[^<]*</title>' docs/fndn/<dir>/*.htm | sed 's/<[^>]*>//g' | sort -u
> ```

#### The spec under-reports — verify against an appliance

Treat FNDN as the starting point, not the authority. Two confirmed cases:

- **Log types.** The `faz_logview.htm` appendix lists 20 and the `logsearch`
  `logtype` enum fewer still; live 7.6.6 serves 29. Indices 20–28 (`dns`, `ssh`,
  `ssl`, `file-filter`, `asset`, `protocol`, `siem`, `ztna`, `security`) appear
  in neither version of the document. Read the real list by asking for an
  unrecognised logtype — the appliance answers with its whole catalogue:
  `get_log_fields(logtype="__enumerate__", name_filter="srcip")`.
- **Unknown parameters are ignored, not rejected.** A parameter an endpoint does
  not define yields a normal-looking success response. That is why the
  spec-conformance defects fixed in `tests/test_fndn_spec_conformance.py` were
  silent for so long — and why a `filter` field name cannot be validated by
  probing either.

#### How to test whether a parameter is actually applied

Only one method works, and two obvious ones do not:

- **Malformed values prove nothing.** FortiAnalyzer silently degrades a bad
  value to the default rather than erroring. Measured on 7.6.6:
  `/eventmgmt/alerts/count` with `time-range={"start":"not-a-date", ...}` returns
  the *same* counts as a valid window, on an endpoint that documents the field.
- **A wrong-shaped value proves nothing either.** `time-range="garbage"` (string
  where an object belongs) returns HTTP 503 on documented and undocumented
  endpoints alike — a shared request-parsing layer, not endpoint behaviour.
- **What works: a well-formed window over an endpoint that has data.** Compare a
  window covering the data, a window covering nothing, and the parameter
  omitted. On `/eventmgmt/alerts/count` in root that reads 15341 / 0 / 15341,
  which proves the field is applied and that omitting it means "all".

The corollary is that **an endpoint with no records cannot be tested at all** —
every window returns zero. `time-range` on `/incidentmgmt/.../incidents` is
undocumented and remains unsettled for exactly this reason; see
`api/client.get_incidents`. Re-run the three-way comparison there once a single
incident exists.

The pages also contradict themselves in places:
`/eventmgmt/.../alerts/extra-details` shows `alertid` in its request skeleton and
`alertids` in its parameter table (the table is right), and the `alerts/comment`
heading reads "Add Alert Comment" while documenting the `update` method.

### Step 2: Compare API Definitions

Use Claude Code to analyze the differences:

```
"Compare the FNDN API definitions between 7.6.4 and 7.6.5.
Identify:
1. New endpoints/operations
2. Modified parameters (added/removed/changed)
3. Deprecated endpoints
4. Changed response formats"
```

### Step 3: Review Changes

The comparison will produce a report like:

```markdown
## API Changes: 7.6.4 → 7.6.5

### New Endpoints
- POST /report/adom/{adom}/ai-summary - AI-powered report summaries
- GET /logview/adom/{adom}/threat-intelligence - New threat intel integration

### Modified Endpoints
- GET /fortiview/adom/{adom}/top-sources
  - Added parameter: `include_geo` (boolean)
  - Changed: `limit` max value 1000 → 2000

### Deprecated
- GET /report/adom/{adom}/legacy-charts (use /report/adom/{adom}/charts instead)

### Response Format Changes
- /eventmgmt/adom/{adom}/alerts now includes `mitre_attack_id` field
```

### Step 4: Update Implementation

For each change:

1. **New Endpoints**:
   - Add method to `api/client.py`
   - Add MCP tool to appropriate `tools/*.py` file
   - Update tests

2. **Modified Parameters**:
   - Update method signature in `api/client.py`
   - Update tool parameters in `tools/*.py`
   - Update docstrings

3. **Deprecated Endpoints**:
   - Add deprecation warning to existing tool
   - Create migration path if replacement exists

4. **Response Changes**:
   - Update response parsing in client
   - Update tool return types

### Step 5: Testing

```bash
# Run tests against new FortiAnalyzer version
export FORTIANALYZER_HOST=faz-test-7.6.5.example.com
pytest tests/ -v

# Test specific new features
pytest tests/test_new_features.py -v
```

### Step 6: Update Documentation

1. Update `README.md` with:
   - New tools
   - Supported version list
   - Any breaking changes

2. Update `CHANGELOG.md`

3. Update version in `pyproject.toml`

## Quick Reference: Claude Prompts for Updates

### Initial Analysis
```
Read the FNDN JSON files in docs/fndn/7.6.5/ and compare with our current
implementation in src/fortianalyzer_mcp/api/client.py.
List all endpoints we don't currently support.
```

### Detailed Comparison
```
Compare docs/fndn/7.6.4/logview.json with docs/fndn/7.6.5/logview.json.
Show me the exact changes in parameters, responses, and new endpoints.
```

### Implementation
```
Based on the FNDN definition for the new /report/adom/{adom}/ai-summary endpoint,
add the API method to client.py and create a corresponding MCP tool.
```

## Version Support Matrix

Current release: **2.9.1**. The base tools support FAZ 7.x and 8.0.x; the optional skills layer (beta) requires **FAZ 7.6.7+** with UEBA/SOAR licensed.

| FAZ Version | Base tools | Skills layer (beta) |
|-------------|-----------|---------------------|
| 7.0.x – 7.4.x | Supported | Not available (needs 7.6.7+) |
| 7.6.x (< 7.6.7) | Supported | Not available (needs 7.6.7+) |
| 7.6.7+ | Supported | Supported |
| 8.0.x | Supported | Supported |

## Automated Checks (Future Enhancement)

Consider implementing:

1. **Schema Validation Script**
   ```python
   # scripts/validate_api.py
   # Compares FNDN definitions with implemented methods
   ```

2. **CI/CD Integration**
   ```yaml
   # .github/workflows/api-check.yml
   # Runs on new FNDN file commits
   ```

3. **API Coverage Report** (illustrative format; not current figures)
   ```
   Total FNDN Endpoints: <N>
   Implemented: <M>
   ```
   The server currently exposes 77 tools (78 with the skills dispatcher); see the README for the authoritative per-category list.
