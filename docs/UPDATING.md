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

2. Place the JSON definition files in `docs/fndn/` directory:
   ```
   docs/fndn/
   ├── 7.6.4/
   │   ├── dvmdb.json
   │   ├── dvm.json
   │   ├── logview.json
   │   ├── fortiview.json
   │   ├── report.json
   │   ├── eventmgmt.json
   │   ├── incidentmgmt.json
   │   ├── ioc.json
   │   ├── sys.json
   │   └── task.json
   └── 7.6.5/           # New version
       └── ...
   ```

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
