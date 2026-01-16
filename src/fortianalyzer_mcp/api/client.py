"""FortiAnalyzer API client wrapper using pyfmg library.

Based on FNDN FortiAnalyzer 7.6.5 API specifications.
"""

import json
import logging
from typing import Any

from pyFMG.fortimgr import FortiManager

from fortianalyzer_mcp.utils.config import Settings
from fortianalyzer_mcp.utils.errors import (
    APIError,
    AuthenticationError,
    ConnectionError,
    parse_faz_error,
)
from fortianalyzer_mcp.utils.validation import sanitize_json_for_logging

logger = logging.getLogger(__name__)

# API Version for FortiAnalyzer 7.6.4
API_VERSION = 3


class FortiAnalyzerClient:
    """Client for FortiAnalyzer JSON RPC API using pyfmg library.

    This client wraps the pyfmg FortiManager class which supports both
    FortiManager and FortiAnalyzer appliances via the same JSON-RPC API.

    Based on FNDN FortiAnalyzer 7.6.4 specifications.
    """

    def __init__(
        self,
        host: str,
        api_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize FortiAnalyzer client."""
        self.host = host.replace("https://", "").replace("http://", "").rstrip("/")
        self.api_token = api_token
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries

        self._fmg: FortiManager | None = None
        self._connected = False
        self._faz_version: tuple[int, int, int] | None = None  # (major, minor, patch)

        logger.info(f"Initialized FortiAnalyzer client for {self.host}")

    @classmethod
    def from_settings(cls, settings: Settings) -> "FortiAnalyzerClient":
        """Create client from settings."""
        return cls(
            host=settings.FORTIANALYZER_HOST,
            api_token=settings.FORTIANALYZER_API_TOKEN,
            username=settings.FORTIANALYZER_USERNAME,
            password=settings.FORTIANALYZER_PASSWORD,
            verify_ssl=settings.FORTIANALYZER_VERIFY_SSL,
            timeout=settings.FORTIANALYZER_TIMEOUT,
            max_retries=settings.FORTIANALYZER_MAX_RETRIES,
        )

    async def connect(self) -> None:
        """Establish connection and authenticate."""
        if self._connected:
            logger.warning("Client already connected")
            return

        logger.info("Connecting to FortiAnalyzer")

        try:
            if self.api_token:
                self._fmg = FortiManager(
                    self.host,
                    apikey=self.api_token,
                    debug=False,
                    use_ssl=True,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout,
                )
            elif self.username and self.password:
                self._fmg = FortiManager(
                    self.host,
                    self.username,
                    self.password,
                    debug=False,
                    use_ssl=True,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout,
                )
            else:
                raise AuthenticationError(
                    "No authentication provided. Set API token or username/password."
                )

            code, response = self._fmg.login()

            if code != 0:
                error_msg = response.get("status", {}).get("message", "Login failed")
                raise AuthenticationError(f"FortiAnalyzer login failed: {error_msg}")

            self._connected = True
            logger.info("Successfully connected to FortiAnalyzer")

        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            raise ConnectionError(f"Failed to connect to FortiAnalyzer: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect and cleanup resources."""
        if not self._connected or not self._fmg:
            return

        logger.info("Disconnecting from FortiAnalyzer")

        try:
            self._fmg.logout()
        except Exception as e:
            logger.warning(f"Logout failed: {e}")
        finally:
            self._fmg = None
            self._connected = False
            logger.info("Disconnected from FortiAnalyzer")

    async def __aenter__(self) -> "FortiAnalyzerClient":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.disconnect()

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected and self._fmg is not None

    @property
    def faz_version(self) -> tuple[int, int, int] | None:
        """Get cached FortiAnalyzer version tuple (major, minor, patch)."""
        return self._faz_version

    async def _detect_version(self) -> tuple[int, int, int]:
        """Detect and cache FortiAnalyzer version.

        Returns tuple of (major, minor, patch).
        """
        if self._faz_version is not None:
            return self._faz_version

        try:
            status = await self.get_system_status()
            version_str = status.get("Version", "7.0.0")
            # Version format: "v7.6.5-build3653 251215 (GA.M)"
            version_part = version_str.split("-")[0].split()[0]
            # Strip leading 'v' if present
            version_part = version_part.lstrip("v")
            parts = version_part.split(".")
            self._faz_version = (
                int(parts[0]) if len(parts) > 0 else 7,
                int(parts[1]) if len(parts) > 1 else 0,
                int(parts[2]) if len(parts) > 2 else 0,
            )
            logger.info(f"Detected FortiAnalyzer version: {self._faz_version}")
        except Exception as e:
            logger.warning(f"Failed to detect FAZ version, assuming 7.0.0: {e}")
            self._faz_version = (7, 0, 0)

        return self._faz_version

    def _ensure_connected(self) -> FortiManager:
        """Ensure client is connected and return pyfmg instance."""
        if not self._connected or not self._fmg:
            raise ConnectionError("Not connected. Call connect() first.")
        return self._fmg

    def _handle_response(self, code: int, response: Any, operation: str = "operation") -> Any:
        """Handle pyfmg response and raise appropriate exceptions."""
        if code == 0:
            return response

        if isinstance(response, dict):
            error_msg = response.get("status", {}).get("message", str(response))
        else:
            error_msg = str(response)

        raise parse_faz_error(code, error_msg, operation)

    # =========================================================================
    # Raw Request for LogView APIs
    # =========================================================================

    async def _raw_request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Execute raw JSON-RPC request for APIs with non-standard response format.

        LogView API returns responses in format: {"result": {"data": [...]}}
        instead of the standard: {"result": [{"status": {...}, "data": [...]}]}

        This method handles the LogView response format directly.
        """
        fmg = self._ensure_connected()

        # Build request payload
        params = [{"url": url}]
        params[0].update(kwargs)

        json_request = {
            "method": method,
            "params": params,
            "session": fmg.sid,
            "id": fmg.req_id + 1,
            "jsonrpc": "2.0",
        }

        # Debug logging - show what we're sending (with sensitive data masked)
        logger.debug(f"API Request: {method.upper()} {url}")
        logger.debug(f"Request params: {sanitize_json_for_logging(params, indent=2)}")

        # Set headers based on auth type
        if fmg.api_key_used:
            headers = {
                "content-type": "application/json",
                "Authorization": f"Bearer {fmg._passwd}",
            }
        else:
            headers = {"content-type": "application/json"}

        # Make request
        response = fmg.sess.post(
            fmg._url,
            data=json.dumps(json_request),
            verify=fmg.verify_ssl,
            timeout=fmg.timeout,
            headers=headers,
        )

        try:
            result = response.json()
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response: {response.text[:500]}")
            raise APIError(f"Invalid JSON response: {e}") from e

        # Debug logging - show what we received (with sensitive data masked)
        logger.debug(f"API Response: {sanitize_json_for_logging(result, indent=2)[:2000]}")

        # Check for JSON-RPC error response first
        if "error" in result:
            error = result["error"]
            code = error.get("code", -1)
            msg = error.get("message", "Unknown error")
            raise parse_faz_error(code, msg, f"{method.upper()} {url}")

        # Handle response format - some APIs return empty responses (no result field)
        # e.g., get_running_reports when no reports are running returns: {'jsonrpc': '2.0', 'id': 2}
        if "result" not in result:
            # Empty response - return empty dict with data: [] for consistency
            logger.debug("Response has no 'result' field - returning empty data")
            return {"data": []}

        res = result["result"]

        # Handle both formats: {"result": {"data": ...}} and {"result": [{"status": ..., "data": ...}]}
        if isinstance(res, list) and len(res) > 0:
            item = res[0]
            if "status" in item:
                code = item["status"].get("code", 0)
                if code != 0:
                    msg = item["status"].get("message", "Unknown error")
                    raise parse_faz_error(code, msg, f"{method.upper()} {url}")
                return item.get("data", item)
            return item
        elif isinstance(res, dict):
            # Check for error status first
            # Handle both formats: {"status": {"code": 0, "message": "ok"}} and {"status": "ok"}
            if "status" in res:
                status = res["status"]
                if isinstance(status, dict):
                    code = status.get("code", 0)
                    if code != 0:
                        msg = status.get("message", "Unknown error")
                        raise parse_faz_error(code, msg, f"{method.upper()} {url}")
                # If status is a string like "ok", it's a success indicator

            # LogView format: return the full result dict to preserve metadata
            # This includes: percentage, return-lines, total-count, data, status, tid, etc.
            return res

        # Empty result list - return empty data
        return {"data": []}

    # =========================================================================
    # Generic Operations
    # =========================================================================

    async def get(self, url: str, **kwargs: Any) -> Any:
        """Execute GET request."""
        fmg = self._ensure_connected()
        code, response = fmg.get(url, **kwargs)
        return self._handle_response(code, response, f"GET {url}")

    async def add(self, url: str, **kwargs: Any) -> Any:
        """Execute ADD request."""
        fmg = self._ensure_connected()
        code, response = fmg.add(url, **kwargs)
        return self._handle_response(code, response, f"ADD {url}")

    async def set(self, url: str, **kwargs: Any) -> Any:
        """Execute SET request."""
        fmg = self._ensure_connected()
        code, response = fmg.set(url, **kwargs)
        return self._handle_response(code, response, f"SET {url}")

    async def update(self, url: str, **kwargs: Any) -> Any:
        """Execute UPDATE request."""
        fmg = self._ensure_connected()
        code, response = fmg.update(url, **kwargs)
        return self._handle_response(code, response, f"UPDATE {url}")

    async def delete(self, url: str, **kwargs: Any) -> Any:
        """Execute DELETE request."""
        fmg = self._ensure_connected()
        code, response = fmg.delete(url, **kwargs)
        return self._handle_response(code, response, f"DELETE {url}")

    async def execute(self, url: str, **kwargs: Any) -> Any:
        """Execute EXEC request."""
        fmg = self._ensure_connected()
        code, response = fmg.execute(url, **kwargs)
        return self._handle_response(code, response, f"EXEC {url}")

    # =========================================================================
    # DVMDB - Device Manager Database (from dvmdb.json)
    # =========================================================================

    async def list_adoms(
        self,
        fields: list[str] | None = None,
        filter: list[str] | None = None,
        loadsub: int = 0,
    ) -> list[dict[str, Any]]:
        """List all ADOMs.

        FNDN: GET /dvmdb/adom
        """
        params: dict[str, Any] = {"loadsub": loadsub}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get("/dvmdb/adom", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_adom(self, name: str, loadsub: int = 0) -> dict[str, Any]:
        """Get specific ADOM.

        FNDN: GET /dvmdb/adom/{adom}
        """
        return await self.get(f"/dvmdb/adom/{name}", loadsub=loadsub)

    async def list_devices(
        self,
        adom: str = "root",
        fields: list[str] | None = None,
        filter: list[str] | None = None,
        loadsub: int = 0,
    ) -> list[dict[str, Any]]:
        """List devices in ADOM.

        FNDN: GET /dvmdb/adom/{adom}/device
        """
        params: dict[str, Any] = {"loadsub": loadsub}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/dvmdb/adom/{adom}/device", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_device(self, device: str, adom: str = "root", loadsub: int = 0) -> dict[str, Any]:
        """Get specific device.

        FNDN: GET /dvmdb/adom/{adom}/device/{device}
        """
        return await self.get(f"/dvmdb/adom/{adom}/device/{device}", loadsub=loadsub)

    async def list_device_vdoms(self, device: str, adom: str = "root") -> list[dict[str, Any]]:
        """List VDOMs for a device.

        FNDN: GET /dvmdb/adom/{adom}/device/{device}/vdom
        """
        result = await self.get(f"/dvmdb/adom/{adom}/device/{device}/vdom")
        return result if isinstance(result, list) else [result] if result else []

    async def list_device_groups(self, adom: str = "root") -> list[dict[str, Any]]:
        """List device groups.

        FNDN: GET /dvmdb/adom/{adom}/group
        """
        result = await self.get(f"/dvmdb/adom/{adom}/group")
        return result if isinstance(result, list) else [result] if result else []

    # =========================================================================
    # DVM - Device Manager Commands (from dvm.json)
    # =========================================================================

    async def add_device(
        self,
        adom: str,
        device: dict[str, Any],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add a device to FortiAnalyzer.

        FNDN: EXEC /dvm/cmd/add/device

        Args:
            adom: ADOM name
            device: Device configuration dict with:
                - name: Device name (required)
                - ip: Device IP (for real device)
                - adm_usr: Admin username
                - adm_pass: Admin password
                - sn: Serial number (for model device)
                - mgmt_mode: Management mode (faz, fmg, fmgfaz)
        """
        data: dict[str, Any] = {"adom": adom, "device": device}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/add/device", **data)

    async def delete_device(
        self,
        adom: str,
        device: str,
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Delete a device from FortiAnalyzer.

        FNDN: EXEC /dvm/cmd/del/device
        """
        data: dict[str, Any] = {"adom": adom, "device": device}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/del/device", **data)

    async def add_device_list(
        self,
        adom: str,
        devices: list[dict[str, Any]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add multiple devices.

        FNDN: EXEC /dvm/cmd/add/dev-list
        """
        data: dict[str, Any] = {"adom": adom, "add-dev-list": devices}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/add/dev-list", **data)

    async def delete_device_list(
        self,
        adom: str,
        devices: list[dict[str, Any]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Delete multiple devices.

        FNDN: EXEC /dvm/cmd/del/dev-list
        """
        data: dict[str, Any] = {"adom": adom, "del-dev-member-list": devices}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/del/dev-list", **data)

    # =========================================================================
    # LogView - Log Search Operations (from logview.json)
    # =========================================================================

    async def logsearch_start(
        self,
        adom: str,
        logtype: str,
        device: list[dict[str, str]],
        time_range: dict[str, str],
        filter: str | None = None,
        case_sensitive: bool = False,
        time_order: str = "desc",
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Start a log search task.

        FNDN: ADD /logview/adom/{adom}/logsearch

        This is a two-step operation:
        1. Start search (returns TID)
        2. Fetch results using TID

        Args:
            adom: ADOM name
            logtype: Log type (traffic, event, attack, virus, webfilter, etc.)
            device: Device filter list [{"devid": "FGT..."}, ...]
            time_range: {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}
            filter: Filter expression (e.g., "srcip==10.0.0.1")
            case_sensitive: Case sensitivity for filter
            time_order: Sort order ("asc" or "desc")
            limit: Max records (1-1000)
            offset: Record offset

        Returns:
            {"tid": 12345} - Task ID for fetching results
        """
        data: dict[str, Any] = {
            "apiver": API_VERSION,
            "device": device,
            "logtype": logtype,
            "time-range": time_range,
            "time-order": time_order,
            "limit": limit,
            "offset": offset,
            "case-sensitive": case_sensitive,
        }
        if filter:
            data["filter"] = filter

        return await self._raw_request("add", f"/logview/adom/{adom}/logsearch", **data)

    async def logsearch_fetch(
        self,
        adom: str,
        tid: int,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Fetch log search results by task ID.

        FNDN: GET /logview/adom/{adom}/logsearch/{tid}

        Args:
            adom: ADOM name
            tid: Task ID from logsearch_start
            limit: Max records per fetch (1-500)
            offset: Record offset

        Returns:
            {
                "percentage": 100,
                "return-lines": 50,
                "data": [...],
                "status": {"code": 0, "message": "..."}
            }
        """
        return await self._raw_request(
            "get",
            f"/logview/adom/{adom}/logsearch/{tid}",
            apiver=API_VERSION,
            limit=limit,
            offset=offset,
        )

    async def logsearch_count(self, adom: str, tid: int) -> dict[str, Any]:
        """Get log search count/progress.

        FNDN: GET /logview/adom/{adom}/logsearch/count/{tid}

        Returns:
            {
                "progress-percent": 100,
                "matched-logs": 1234,
                "scanned-logs": 5000,
                "total-logs": 10000
            }
        """
        return await self._raw_request(
            "get",
            f"/logview/adom/{adom}/logsearch/count/{tid}",
            apiver=API_VERSION,
        )

    async def logsearch_cancel(self, adom: str, tid: int) -> dict[str, Any]:
        """Cancel a log search task.

        FNDN: DELETE /logview/adom/{adom}/logsearch/{tid}
        """
        return await self._raw_request(
            "delete",
            f"/logview/adom/{adom}/logsearch/{tid}",
            apiver=API_VERSION,
        )

    async def get_logfields(
        self,
        adom: str,
        logtype: str,
        devtype: str = "FortiGate",
    ) -> dict[str, Any]:
        """Get available log fields for a log type.

        FNDN: GET /logview/adom/{adom}/logfields
        """
        return await self._raw_request(
            "get",
            f"/logview/adom/{adom}/logfields",
            apiver=API_VERSION,
            logtype=logtype,
            devtype=devtype,
        )

    async def get_logstats(
        self,
        adom: str,
        device: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Get log statistics.

        FNDN: GET /logview/adom/{adom}/logstats

        Returns device logging stats including:
        - Last log time
        - Log rate
        - Disk usage
        """
        params: dict[str, Any] = {"apiver": API_VERSION}
        if device:
            params["device"] = device

        return await self._raw_request("get", f"/logview/adom/{adom}/logstats", **params)

    async def get_logfiles_state(
        self,
        adom: str,
        devid: str | None = None,
        vdom: str | None = None,
        time_range: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Get log file state.

        FNDN: GET /logview/adom/{adom}/logfiles/state
        """
        params: dict[str, Any] = {"apiver": API_VERSION}
        if devid:
            params["devid"] = devid
        if vdom:
            params["vdom"] = vdom
        if time_range:
            params["time-range"] = time_range

        return await self._raw_request("get", f"/logview/adom/{adom}/logfiles/state", **params)

    async def get_logfiles_data(
        self,
        adom: str,
        devid: str,
        vdom: str,
        filename: str,
        data_type: str = "base64",
        offset: int = 0,
        length: int = 1048576,
    ) -> dict[str, Any]:
        """Get log file content.

        FNDN: GET /logview/adom/{adom}/logfiles/data

        Args:
            data_type: "base64", "csv/gzip/base64", "text/gzip/base64"
            length: Max 50MB (52428800)
        """
        return await self._raw_request(
            "get",
            f"/logview/adom/{adom}/logfiles/data",
            apiver=API_VERSION,
            devid=devid,
            vdom=vdom,
            filename=filename,
            **{"data-type": data_type},
            offset=offset,
            length=length,
        )

    async def search_logfiles(
        self,
        adom: str,
        devid: str,
        vdom: str,
        filename: str,
        logtype: str,
        filter: str | None = None,
        case_sensitive: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Search within a specific log file.

        FNDN: GET /logview/adom/{adom}/logfiles/search
        """
        params: dict[str, Any] = {
            "apiver": API_VERSION,
            "devid": devid,
            "vdom": vdom,
            "filename": filename,
            "logtype": logtype,
            "case-sensitive": case_sensitive,
            "limit": limit,
            "offset": offset,
        }
        if filter:
            params["filter"] = filter

        return await self._raw_request("get", f"/logview/adom/{adom}/logfiles/search", **params)

    async def get_pcapfile(
        self,
        key_data: str,
        key_type: str = "log-data",
    ) -> dict[str, Any]:
        """Get PCAP file associated with a log.

        FNDN: GET /logview/pcapfile

        Args:
            key_data: Log data (JSON or pcapurl)
            key_type: "log-data" or "pcapurl"
        """
        return await self._raw_request(
            "get",
            "/logview/pcapfile",
            apiver=API_VERSION,
            **{"key-data": key_data, "key-type": key_type},
        )

    # =========================================================================
    # Task Management (from task.json)
    # =========================================================================

    async def list_tasks(
        self,
        filter: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List all tasks.

        FNDN: GET /task/task
        """
        params: dict[str, Any] = {}
        if filter:
            params["filter"] = filter

        result = await self.get("/task/task", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_task(self, task_id: int) -> dict[str, Any]:
        """Get task details.

        FNDN: GET /task/task/{task_id}
        """
        return await self.get(f"/task/task/{task_id}")

    async def get_task_line(self, task_id: int) -> list[dict[str, Any]]:
        """Get task line details.

        FNDN: GET /task/task/{task_id}/line
        """
        result = await self.get(f"/task/task/{task_id}/line")
        return result if isinstance(result, list) else [result] if result else []

    # =========================================================================
    # System Status (from sys.json)
    # =========================================================================

    async def get_system_status(self) -> dict[str, Any]:
        """Get FortiAnalyzer system status.

        FNDN: GET /sys/status
        """
        return await self.get("/sys/status")

    async def get_ha_status(self) -> dict[str, Any]:
        """Get HA status.

        FNDN: GET /sys/ha/status
        """
        return await self.get("/sys/ha/status")

    # =========================================================================
    # Event Management (from eventmgmt.json)
    # =========================================================================

    async def get_alerts(
        self,
        adom: str,
        time_range: dict[str, str] | None = None,
        filter: str | None = None,
        limit: int = 100,
        offset: int = 0,
        time_order: str = "desc",
    ) -> dict[str, Any]:
        """Get alert events.

        FNDN: GET /eventmgmt/adom/{adom}/alerts

        Args:
            adom: ADOM name
            time_range: {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}
            filter: Filter expression
            limit: Max records (1-2000)
            offset: Record offset
            time_order: Sort order ("asc" or "desc")
        """
        params: dict[str, Any] = {
            "apiver": API_VERSION,
            "limit": limit,
            "offset": offset,
            "time-order": time_order,
        }
        if time_range:
            params["time-range"] = time_range
        if filter:
            params["filter"] = filter

        return await self._raw_request("get", f"/eventmgmt/adom/{adom}/alerts", **params)

    async def get_alerts_count(
        self,
        adom: str,
        time_range: dict[str, str] | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """Get alert count.

        FNDN: GET /eventmgmt/adom/{adom}/alerts/count
        """
        params: dict[str, Any] = {"apiver": API_VERSION}
        if time_range:
            params["time-range"] = time_range
        if filter:
            params["filter"] = filter

        return await self._raw_request("get", f"/eventmgmt/adom/{adom}/alerts/count", **params)

    async def acknowledge_alerts(
        self,
        adom: str,
        alert_ids: list[str],
        user: str,
    ) -> dict[str, Any]:
        """Acknowledge alert events.

        FNDN: UPDATE /eventmgmt/adom/{adom}/alerts/ack
        """
        return await self._raw_request(
            "update",
            f"/eventmgmt/adom/{adom}/alerts/ack",
            apiver=API_VERSION,
            alertid=alert_ids,
            **{"update-by": user},
        )

    async def unacknowledge_alerts(
        self,
        adom: str,
        alert_ids: list[str],
        user: str,
    ) -> dict[str, Any]:
        """Unacknowledge alert events.

        FNDN: UPDATE /eventmgmt/adom/{adom}/alerts/unack
        """
        return await self._raw_request(
            "update",
            f"/eventmgmt/adom/{adom}/alerts/unack",
            apiver=API_VERSION,
            alertid=alert_ids,
            **{"update-by": user},
        )

    async def get_alert_logs(
        self,
        adom: str,
        alert_ids: list[str],
        limit: int = 1000,
        offset: int = 0,
        time_order: str = "desc",
    ) -> dict[str, Any]:
        """Get alert event logs.

        FNDN: GET /eventmgmt/adom/{adom}/alertlogs
        """
        return await self._raw_request(
            "get",
            f"/eventmgmt/adom/{adom}/alertlogs",
            apiver=API_VERSION,
            alertid=alert_ids,
            limit=limit,
            offset=offset,
            **{"time-order": time_order},
        )

    async def get_alert_extra_details(
        self,
        adom: str,
        alert_ids: list[str],
    ) -> dict[str, Any]:
        """Get alert extra details.

        FNDN: GET /eventmgmt/adom/{adom}/alerts/extra-details
        """
        return await self._raw_request(
            "get",
            f"/eventmgmt/adom/{adom}/alerts/extra-details",
            apiver=API_VERSION,
            alertid=alert_ids,
        )

    async def add_alert_comment(
        self,
        adom: str,
        alert_id: str,
        comment: str,
        user: str,
    ) -> dict[str, Any]:
        """Add comment to alert.

        FNDN: ADD /eventmgmt/adom/{adom}/alerts/comment
        """
        return await self._raw_request(
            "add",
            f"/eventmgmt/adom/{adom}/alerts/comment",
            apiver=API_VERSION,
            alertid=alert_id,
            comment=comment,
            **{"update-by": user},
        )

    async def get_alert_incident_stats(
        self,
        adom: str,
        time_range: dict[str, str],
        stat_type: str = "severity",
    ) -> dict[str, Any]:
        """Get alert-incident statistics.

        FNDN: GET /eventmgmt/adom/{adom}/alert-incident/stats

        Args:
            stat_type: "severity", "severity-timescale", "status", etc.
        """
        return await self._raw_request(
            "get",
            f"/eventmgmt/adom/{adom}/alert-incident/stats",
            apiver=API_VERSION,
            type=stat_type,
            **{"time-range": time_range},
        )

    # =========================================================================
    # FortiView (from fortiview.json)
    # =========================================================================

    async def fortiview_run(
        self,
        adom: str,
        view_name: str,
        device: list[dict[str, str]],
        time_range: dict[str, str],
        filter: str | None = None,
        limit: int = 100,
        offset: int = 0,
        sort_by: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Start a FortiView request.

        FNDN: ADD /fortiview/adom/{adom}/{view-name}/run

        This is a two-step operation:
        1. Start FortiView request (returns TID)
        2. Fetch results using TID

        Args:
            adom: ADOM name
            view_name: FortiView name (e.g., "top-sources", "top-destinations",
                       "top-applications", "top-threats", "top-websites", etc.)
            device: Device filter list [{"devid": "FGT..."}, ...]
            time_range: {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}
            filter: Filter expression
            limit: Max records (1-1000)
            offset: Record offset
            sort_by: Sort criteria [{"field": "sessions", "order": "desc"}]

        Returns:
            {"tid": 12345} - Task ID for fetching results
        """
        params: dict[str, Any] = {
            "apiver": API_VERSION,
            "device": device,
            "time-range": time_range,
            "limit": limit,
            "offset": offset,
        }
        if filter:
            params["filter"] = filter
        if sort_by:
            params["sort-by"] = sort_by

        return await self._raw_request("add", f"/fortiview/adom/{adom}/{view_name}/run", **params)

    async def fortiview_fetch(
        self,
        adom: str,
        view_name: str,
        tid: int,
    ) -> dict[str, Any]:
        """Fetch FortiView results by task ID.

        FNDN: GET /fortiview/adom/{adom}/{view-name}/run/{tid}
        """
        return await self._raw_request(
            "get",
            f"/fortiview/adom/{adom}/{view_name}/run/{tid}",
            apiver=API_VERSION,
        )

    # =========================================================================
    # Report (from report.json)
    # =========================================================================

    async def get_report_layouts(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Get available report layouts.

        FNDN: GET /config/adom/{adom}/sql-report/layout

        Returns list of report layouts with their layout-id, title, description, etc.
        The layout-id is required for running reports.

        Args:
            adom: ADOM name
            fields: Optional list of fields to return
            filter: Optional filter criteria
        """
        params: dict[str, Any] = {
            "apiver": API_VERSION,
            "loadsub": 0,
        }
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        return await self._raw_request("get", f"/config/adom/{adom}/sql-report/layout", **params)

    async def report_run(
        self,
        adom: str,
        layout_id: int,
        time_period: str = "last-7-days",
        device: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Run a report.

        FNDN: ADD /report/adom/{adom}/run

        This is a two-step operation:
        1. Start report (returns TID)
        2. Fetch report data using TID

        Args:
            adom: ADOM name
            layout_id: Report layout ID (from get_report_layouts).
                       A schedule must exist for this layout before running.
            time_period: Time period for report. Options:
                - Predefined: "last-n-hours", "last-n-days", "last-n-weeks", "last-n-months"
                  e.g., "last-1-hours", "last-7-days", "last-30-days", "last-4-weeks"
                - "other" with custom start/end in device filter
            device: Device filter list [{"devid": "FGT..."}, ...]
        """
        # schedule parameter must be a string of the layout-id
        params: dict[str, Any] = {
            "apiver": API_VERSION,
            "schedule": str(layout_id),
            "time-period": time_period,
            "runfrom": "GUI",
        }
        if device:
            params["device"] = device

        return await self._raw_request("add", f"/report/adom/{adom}/run", **params)

    async def report_fetch(
        self,
        adom: str,
        tid: str,
    ) -> dict[str, Any]:
        """Fetch report status/results by task ID.

        FNDN: GET /report/adom/{adom}/run/{tid}

        Args:
            adom: ADOM name
            tid: Task ID (UUID string from report_run)
        """
        return await self._raw_request("get", f"/report/adom/{adom}/run/{tid}", apiver=API_VERSION)

    async def report_get_data(
        self,
        adom: str,
        tid: str,
        output_format: str = "PDF",
        data_type: str = "string",
    ) -> dict[str, Any]:
        """Get report data/download.

        FNDN: GET /report/adom/{adom}/reports/data/{tid}

        Args:
            adom: ADOM name
            tid: Task ID (UUID string from report_run)
            output_format: Output format - "PDF", "HTML", "CSV", "XML"
            data_type: Data encoding type - "string" (base64)
        """
        return await self._raw_request(
            "get",
            f"/report/adom/{adom}/reports/data/{tid}",
            apiver=API_VERSION,
            format=output_format,
            **{"data-type": data_type},
        )

    async def report_list_templates(
        self,
        adom: str,
    ) -> dict[str, Any]:
        """List available report templates.

        FNDN: GET /report/adom/{adom}/template/list
        """
        return await self._raw_request(
            "get", f"/report/adom/{adom}/template/list", apiver=API_VERSION
        )

    async def report_get_state(
        self,
        adom: str,
        time_range: dict[str, str],
        state: str = "generated",
        title: str | None = None,
    ) -> dict[str, Any]:
        """Get report state/history.

        FNDN: GET /report/adom/{adom}/reports/state

        Args:
            adom: ADOM name
            time_range: {"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"}
            state: Report state filter ("generated", "pending", "running", etc.)
            title: Optional report title filter
        """
        params: dict[str, Any] = {
            "apiver": API_VERSION,
            "state": state,
            "time-range": time_range,
        }
        if title:
            params["title"] = title

        return await self._raw_request("get", f"/report/adom/{adom}/reports/state", **params)

    async def get_report_schedules(
        self,
        adom: str,
        layout_id: int | None = None,
    ) -> dict[str, Any]:
        """Get report schedules.

        FNDN: GET /config/adom/{adom}/sql-report/schedule

        A schedule must exist for a layout before a report can be run.
        The schedule name matches the layout-id.

        Args:
            adom: ADOM name
            layout_id: Optional layout-id to filter by (schedule name == layout-id)
        """
        params: dict[str, Any] = {
            "apiver": API_VERSION,
            "loadsub": 1,
        }
        if layout_id is not None:
            params["filter"] = ["name", "==", str(layout_id)]

        return await self._raw_request("get", f"/config/adom/{adom}/sql-report/schedule", **params)

    async def create_report_schedule(
        self,
        adom: str,
        layout_id: int,
        device_filter: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Create a report schedule for a layout.

        FNDN: SET /report/adom/{adom}/config/schedule/{layout_id}

        A schedule must be created before running a report for a layout.

        Args:
            adom: ADOM name
            layout_id: Layout ID to create schedule for
            device_filter: Optional device filter list
        """
        data: dict[str, Any] = {
            "auto-hcache": 1,
            "report-layout": [{"layout-id": str(layout_id)}],
        }
        if device_filter:
            data["device"] = device_filter

        return await self._raw_request(
            "set",
            f"/report/adom/{adom}/config/schedule/{layout_id}",
            apiver=API_VERSION,
            data=data,
        )

    async def get_running_reports(
        self,
        adom: str,
    ) -> dict[str, Any]:
        """Get currently running reports.

        FNDN: GET /report/adom/{adom}/run

        Returns list of reports currently being generated.
        """
        return await self._raw_request("get", f"/report/adom/{adom}/run", apiver=API_VERSION)

    # =========================================================================
    # Incident Management (from incidentmgmt.json)
    # =========================================================================

    async def get_incidents(
        self,
        adom: str,
        time_range: dict[str, str] | None = None,
        filter: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Get incidents.

        FNDN: GET /incidentmgmt/adom/{adom}/incidents
        """
        params: dict[str, Any] = {
            "apiver": API_VERSION,
            "limit": limit,
            "offset": offset,
        }
        if time_range:
            params["time-range"] = time_range
        if filter:
            params["filter"] = filter

        return await self._raw_request("get", f"/incidentmgmt/adom/{adom}/incidents", **params)

    async def get_incident(
        self,
        adom: str,
        incident_id: str,
    ) -> dict[str, Any]:
        """Get specific incident details.

        FNDN: GET /incidentmgmt/adom/{adom}/incident/{incid}
        """
        return await self._raw_request(
            "get", f"/incidentmgmt/adom/{adom}/incident/{incident_id}", apiver=API_VERSION
        )

    async def get_incidents_count(
        self,
        adom: str,
        time_range: dict[str, str] | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """Get incident count.

        FNDN: GET /incidentmgmt/adom/{adom}/incidents/count
        """
        params: dict[str, Any] = {"apiver": API_VERSION}
        if time_range:
            params["time-range"] = time_range
        if filter:
            params["filter"] = filter

        return await self._raw_request(
            "get", f"/incidentmgmt/adom/{adom}/incidents/count", **params
        )

    async def create_incident(
        self,
        adom: str,
        name: str,
        severity: str = "medium",
        category: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Create a new incident.

        FNDN: ADD /incidentmgmt/adom/{adom}/incident
        """
        params: dict[str, Any] = {
            "apiver": API_VERSION,
            "name": name,
            "severity": severity,
        }
        if category:
            params["category"] = category
        if description:
            params["description"] = description

        return await self._raw_request("add", f"/incidentmgmt/adom/{adom}/incident", **params)

    async def update_incident(
        self,
        adom: str,
        incident_id: str,
        status: str | None = None,
        severity: str | None = None,
        assignee: str | None = None,
    ) -> dict[str, Any]:
        """Update an incident.

        FNDN: UPDATE /incidentmgmt/adom/{adom}/incident/{incid}
        """
        params: dict[str, Any] = {"apiver": API_VERSION}
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        if assignee:
            params["assignee"] = assignee

        return await self._raw_request(
            "update", f"/incidentmgmt/adom/{adom}/incident/{incident_id}", **params
        )

    async def get_incident_stats(
        self,
        adom: str,
        time_range: dict[str, str],
        stats_items: list[str] | None = None,
    ) -> dict[str, Any]:
        """Get incident statistics.

        FNDN: GET /incidentmgmt/adom/{adom}/incident/stats

        Args:
            adom: ADOM name
            time_range: {"start": "...", "end": "..."}
            stats_items: List of stats items to retrieve. Options:
                - "total": Total incident count
                - "severity": Counts by severity (high/medium/low)
                - "category": Counts by category
                - "status": Counts by status
                - "outbreak": Outbreak incidents
                Default: ["total", "severity", "status"]
        """
        if stats_items is None:
            stats_items = ["total", "severity", "status"]

        return await self._raw_request(
            "get",
            f"/incidentmgmt/adom/{adom}/incident/stats",
            apiver=API_VERSION,
            **{"time-range": time_range, "stats-item": stats_items},
        )

    # =========================================================================
    # IOC (Indicators of Compromise) (from ioc.json)
    # =========================================================================

    async def get_ioc_license_state(self) -> dict[str, Any]:
        """Get IOC license state.

        FNDN: GET /ioc/license/state
        """
        return await self._raw_request("get", "/ioc/license/state", apiver=API_VERSION)

    async def acknowledge_ioc_events(
        self,
        adom: str,
        event_ids: list[str],
        user: str,
    ) -> dict[str, Any]:
        """Acknowledge IOC events.

        FNDN: UPDATE /ioc/adom/{adom}/events/ack
        """
        return await self._raw_request(
            "update",
            f"/ioc/adom/{adom}/events/ack",
            apiver=API_VERSION,
            eventid=event_ids,
            **{"update-by": user},
        )

    async def ioc_rescan_run(
        self,
        adom: str,
        device: list[dict[str, str]],
        time_range: dict[str, str],
    ) -> dict[str, Any]:
        """Run IOC rescan.

        FNDN: ADD /ioc/adom/{adom}/rescan/run

        Returns TID for tracking.
        """
        return await self._raw_request(
            "add",
            f"/ioc/adom/{adom}/rescan/run",
            apiver=API_VERSION,
            device=device,
            **{"time-range": time_range},
        )

    async def ioc_rescan_status(
        self,
        adom: str,
        tid: int,
    ) -> dict[str, Any]:
        """Get IOC rescan status.

        FNDN: GET /ioc/adom/{adom}/rescan/run/{tid}
        """
        return await self._raw_request(
            "get", f"/ioc/adom/{adom}/rescan/run/{tid}", apiver=API_VERSION
        )

    async def get_ioc_rescan_history(
        self,
        adom: str,
    ) -> dict[str, Any]:
        """Get IOC rescan history.

        FNDN: GET /ioc/adom/{adom}/rescan/history
        """
        return await self._raw_request(
            "get", f"/ioc/adom/{adom}/rescan/history", apiver=API_VERSION
        )
