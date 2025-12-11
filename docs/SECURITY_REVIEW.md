# FortiAnalyzer MCP Server - Security & Stability Review

**Review Date:** 2024-12-05
**Reviewer Role:** Senior QA Engineer
**Review Scope:** Security, Stability, and Reliability Analysis

---

## Executive Summary

The FortiAnalyzer MCP Server codebase demonstrates **solid security practices** with a few areas for improvement. The code follows secure design patterns and handles credentials appropriately. This review identifies findings by severity and provides actionable recommendations.

### Overall Assessment: **GOOD** (Ready for Production with Minor Fixes)

| Category | Rating | Notes |
|----------|--------|-------|
| **Credential Handling** | ✅ Good | No hardcoded secrets, environment-based config |
| **Input Validation** | ⚠️ Moderate | Some parameters lack validation |
| **Error Handling** | ✅ Good | Comprehensive exception hierarchy |
| **Connection Security** | ✅ Good | SSL verification configurable |
| **Logging Security** | ⚠️ Moderate | Potential credential exposure in debug logs |
| **Resource Management** | ✅ Good | Proper async cleanup patterns |
| **API Security** | ✅ Good | Session-based auth with token support |

---

## Security Findings

### HIGH Severity

#### 1. Credential Exposure in Debug Logs
**File:** `src/fortianalyzer_mcp/api/client.py:195-223`
**Risk:** Credentials may be exposed in debug logs

```python
# Line 196-197: Request details logged at DEBUG level
logger.debug(f"API Request: {method.upper()} {url}")
logger.debug(f"Request params: {json.dumps(params, indent=2)}")
```

**Issue:** When LOG_LEVEL=DEBUG, request parameters (which may contain sensitive data) are logged. The params dict could include filter expressions with IP addresses, device names, or other sensitive data.

**Recommendation:**
- Implement a sanitization function for log output
- Never log Authorization headers or session IDs at any level
- Consider adding a `SECURE_LOGGING` config option

**Current Mitigation:** Default LOG_LEVEL is INFO, which doesn't log params.

---

#### 2. Password Stored in Memory
**File:** `src/fortianalyzer_mcp/api/client.py:36-52`

```python
self.password = password  # Stored as plain string
```

**Issue:** Password is stored in memory as a plain string for the lifetime of the connection.

**Recommendation:**
- Consider using SecureString patterns if available
- Clear password from memory after initial authentication
- Use API token authentication instead (already recommended in docs)

**Mitigation:** Documentation recommends API token authentication.

---

### MEDIUM Severity

#### 3. No Input Validation on ADOM/Device Names
**Files:** Multiple tool files

```python
# Example from log_tools.py:168
async def query_logs(
    adom: str = "root",  # No validation
    logtype: str = "traffic",  # No validation
    ...
)
```

**Issue:** ADOM names, device names, and other string inputs are passed directly to API without validation. While the FortiAnalyzer API will reject invalid inputs, validation at the MCP layer provides better error messages and prevents unnecessary API calls.

**Recommendation:**
```python
import re

def validate_adom(adom: str) -> str:
    """Validate ADOM name format."""
    if not adom or not re.match(r'^[a-zA-Z0-9_-]{1,64}$', adom):
        raise ValueError(f"Invalid ADOM name: {adom}")
    return adom
```

---

#### 4. Directory Traversal Risk in Report Save
**File:** `src/fortianalyzer_mcp/tools/report_tools.py:696-729`

```python
@mcp.tool()
async def save_report(
    tid: str,
    output_dir: str = "~/Downloads",  # User-controlled path
    ...
):
    output_path = Path(output_dir).expanduser()
    output_path.mkdir(parents=True, exist_ok=True)  # Creates directories
```

**Issue:** User can specify arbitrary output directories, potentially writing to system directories if permissions allow.

**Recommendation:**
- Validate output_dir is within allowed directories
- Add configuration for allowed report output directories
- Consider sandboxing file operations

```python
ALLOWED_OUTPUT_DIRS = [Path.home() / "Downloads", Path.home() / "Documents"]

def validate_output_dir(path: Path) -> Path:
    """Ensure output directory is within allowed locations."""
    resolved = path.resolve()
    if not any(resolved.is_relative_to(allowed) for allowed in ALLOWED_OUTPUT_DIRS):
        raise ValueError(f"Output directory not allowed: {path}")
    return resolved
```

---

#### 5. No Rate Limiting
**Files:** All tool files

**Issue:** No rate limiting on API calls. Malicious or buggy clients could flood the FortiAnalyzer with requests.

**Recommendation:**
- Implement request rate limiting in the client
- Add configurable rate limits per tool category
- Consider exponential backoff for retries

---

### LOW Severity

#### 6. Session ID in URL Logged
**File:** `src/fortianalyzer_mcp/api/client.py:188-189`

```python
json_request = {
    ...
    "session": fmg.sid,  # Session ID included
}
```

**Issue:** Session ID is included in request payloads which may appear in debug logs.

**Recommendation:** Mask session ID in any log output.

---

#### 7. Timeout Values Not Validated
**File:** `src/fortianalyzer_mcp/tools/log_tools.py:107`

```python
async def query_logs(
    ...
    timeout: int = DEFAULT_SEARCH_TIMEOUT,  # User can specify very large values
):
```

**Issue:** Users can specify arbitrarily large timeout values, potentially holding resources.

**Recommendation:** Add max timeout configuration (current MAX is in config but not enforced in all tools).

---

#### 8. ZIP Extraction Without Size Limits
**File:** `src/fortianalyzer_mcp/tools/report_tools.py:755-793`

```python
with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
    for filename in file_list:
        content = zf.read(filename)  # No size check
```

**Issue:** ZIP bomb vulnerability - malicious report could expand to fill disk.

**Recommendation:**
```python
MAX_EXTRACT_SIZE = 100 * 1024 * 1024  # 100MB

for filename in file_list:
    info = zf.getinfo(filename)
    if info.file_size > MAX_EXTRACT_SIZE:
        raise ValueError(f"File too large: {filename} ({info.file_size} bytes)")
```

---

## Stability Findings

### Connection Management ✅ GOOD

**File:** `src/fortianalyzer_mcp/api/client.py:120-134`

```python
async def disconnect(self) -> None:
    """Disconnect and cleanup resources."""
    if not self._connected or not self._fmg:
        return
    try:
        self._fmg.logout()
    except Exception as e:
        logger.warning(f"Logout failed: {e}")
    finally:
        self._fmg = None
        self._connected = False
```

**Assessment:** Proper cleanup with exception handling in finally block. Connection state is properly tracked.

---

### Async Context Manager ✅ GOOD

**File:** `src/fortianalyzer_mcp/api/client.py:136-143`

```python
async def __aenter__(self) -> "FortiAnalyzerClient":
    await self.connect()
    return self

async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
    await self.disconnect()
```

**Assessment:** Proper async context manager pattern ensures cleanup on exceptions.

---

### Error Handling ✅ GOOD

**File:** `src/fortianalyzer_mcp/utils/errors.py`

The exception hierarchy is well-designed:
- `FortiAnalyzerError` (base)
  - `AuthenticationError`
  - `ConnectionError`
  - `APIError`
  - `ResourceNotFoundError`
  - `PermissionError`
  - `TimeoutError`
  - `ValidationError`
  - `WorkspaceError`

Error code mapping is comprehensive (lines 67-81).

---

### Potential Infinite Loop ⚠️ ATTENTION NEEDED

**Files:** Multiple tools with polling loops

```python
# log_tools.py:200-242
while True:
    elapsed = asyncio.get_event_loop().time() - start_time
    if elapsed > timeout:
        # Cancel and return
        ...
    # Fetch results...
    if percentage >= 100:
        return ...
    await asyncio.sleep(POLL_INTERVAL)
```

**Assessment:** All polling loops have timeout protection. However:

**Recommendation:**
- Add maximum iteration count as secondary safeguard
- Log warning when approaching timeout

---

### Server Startup Resilience ✅ GOOD

**File:** `src/fortianalyzer_mcp/server.py:432-436`

```python
try:
    await faz_client.connect()
    logger.info("FortiAnalyzer connection established")
except Exception as e:
    logger.warning(f"FortiAnalyzer connection failed: {e}. Server will still start.")
```

**Assessment:** Server continues even if initial FortiAnalyzer connection fails, allowing for retry.

---

## Reliability Findings

### TID Workflow ✅ GOOD

The two-step TID workflow (start → fetch) is implemented consistently across:
- Log searches (`log_tools.py`)
- FortiView queries (`fortiview_tools.py`)
- Reports (`report_tools.py`)
- IOC rescans (`ioc_tools.py`)

Each implements proper polling with timeout.

---

### Empty Response Handling ✅ GOOD

**File:** `src/fortianalyzer_mcp/api/client.py:233-237`

```python
if "result" not in result:
    # Empty response - return empty dict with data: [] for consistency
    logger.debug("Response has no 'result' field - returning empty data")
    return {"data": []}
```

**Assessment:** Graceful handling of empty API responses.

---

### Configuration Validation ✅ GOOD

**File:** `src/fortianalyzer_mcp/utils/config.py`

- Pydantic validation with proper types
- Range constraints on numeric values (`ge`, `le`)
- Host validation removes protocol prefixes
- Log directory auto-creation

---

## Recommendations Summary

### Must Fix (Before Production) - ✅ FIXED
1. ~~Implement log sanitization for debug output~~ ✅ Fixed in `utils/validation.py` and `api/client.py`
2. ~~Add input validation for ADOM/device names~~ ✅ Fixed in `utils/validation.py`, applied to log_tools.py, fortiview_tools.py, report_tools.py
3. ~~Restrict report output directory paths~~ ✅ Fixed with `validate_output_path()` and `FAZ_ALLOWED_OUTPUT_DIRS` env var

### Should Fix (Soon) - ✅ PARTIALLY FIXED
4. ~~Add ZIP extraction size limits~~ ✅ Fixed in `report_tools.py` (100MB per file, 500MB total)
5. Implement rate limiting
6. Add max iteration safeguard to polling loops

### Nice to Have
7. SecureString pattern for password handling
8. Structured logging with field masking
9. Metrics/monitoring hooks

---

## Configuration Security Checklist

For production deployment:

- [x] Use API token authentication (not username/password)
- [x] Set `FORTIANALYZER_VERIFY_SSL=true` (default)
- [x] Set `LOG_LEVEL=INFO` or higher (not DEBUG)
- [ ] Restrict `MCP_SERVER_HOST` binding (not 0.0.0.0 in production)
- [ ] Use environment variables or secrets management for credentials
- [ ] Implement network segmentation for MCP server

---

## Files Reviewed

| File | Lines | Security Issues | Stability Issues |
|------|-------|-----------------|------------------|
| `api/client.py` | 1451 | 2 | 0 |
| `utils/config.py` | 205 | 0 | 0 |
| `utils/errors.py` | 103 | 0 | 0 |
| `server.py` | 519 | 0 | 0 |
| `tools/log_tools.py` | 784 | 1 | 0 |
| `tools/report_tools.py` | 828 | 2 | 0 |
| `tools/fortiview_tools.py` | 561 | 0 | 0 |
| `tools/dvm_tools.py` | 478 | 0 | 0 |
| `tools/event_tools.py` | 398 | 0 | 0 |
| `tools/incident_tools.py` | 361 | 0 | 0 |
| `tools/ioc_tools.py` | 358 | 0 | 0 |
| `tools/system_tools.py` | 413 | 0 | 0 |

**Total:** ~6,459 lines reviewed

---

## Conclusion

The FortiAnalyzer MCP Server is **well-architected** with good security fundamentals:
- No hardcoded credentials
- Proper error handling
- Async cleanup patterns
- Configurable SSL verification

The main areas for improvement are:
1. Input validation at the MCP tool layer
2. Log sanitization for debug mode
3. File path restrictions for report saving

The codebase is **production-ready** with the recommended fixes applied. The existing mitigations (API token auth, INFO log level by default) address the most critical concerns.
