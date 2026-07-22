"""Input validation and log sanitization utilities.

Security utilities for:
- Sanitizing sensitive data from log output
- Validating ADOM, device, and other input parameters
- Path validation for file operations
"""

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

# Canonical ValidationError lives in utils.errors (also mapped from FAZ
# error code -5); re-exported here so validator callers keep importing it
# from this module.
from fortianalyzer_mcp.utils.errors import ValidationError

# Sensitive fields that should be masked in logs
SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pass",
    "adm_pass",
    "adm_passwd",
    "api_token",
    "apikey",
    "token",
    "session",
    "sid",
    "authorization",
    "auth",
    "secret",
    "key",
    "credential",
}

# Mask pattern for sensitive values
MASK_VALUE = "***REDACTED***"


def sanitize_for_logging(data: Any, depth: int = 0) -> Any:
    """Sanitize sensitive data from objects before logging.

    Recursively traverses dictionaries and lists to mask sensitive fields.

    Args:
        data: Data to sanitize (dict, list, or primitive)
        depth: Current recursion depth (prevents infinite recursion)

    Returns:
        Sanitized copy of the data with sensitive values masked

    Example:
        >>> params = {"user": "admin", "password": "secret123"}
        >>> sanitize_for_logging(params)
        {'user': 'admin', 'password': '***REDACTED***'}
    """
    if depth > 10:
        # Prevent infinite recursion
        return "<MAX_DEPTH>"

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = key.lower().replace("-", "_").replace(" ", "_")
            if any(sensitive in key_lower for sensitive in SENSITIVE_FIELDS):
                result[key] = MASK_VALUE
            else:
                result[key] = sanitize_for_logging(value, depth + 1)
        return result

    elif isinstance(data, list):
        return [sanitize_for_logging(item, depth + 1) for item in data]

    elif isinstance(data, str):
        # Check if string looks like a session ID or token (hex string > 20 chars)
        if len(data) > 20 and re.match(r"^[a-fA-F0-9]+$", data):
            return MASK_VALUE
        return data

    return data


def sanitize_json_for_logging(data: Any, indent: int | None = None) -> str:
    """Sanitize and convert data to JSON string for logging.

    Args:
        data: Data to sanitize and serialize
        indent: JSON indent level (None for compact)

    Returns:
        JSON string with sensitive values masked
    """
    sanitized = sanitize_for_logging(data)
    return json.dumps(sanitized, indent=indent, default=str)


# =============================================================================
# Input Validation
# =============================================================================

# ADOM name pattern: alphanumeric, underscore, hyphen, 1-64 chars
ADOM_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def get_default_adom() -> str:
    """Get the default ADOM from configuration.

    Returns the DEFAULT_ADOM setting from the config, or "root" if not set.

    Returns:
        Default ADOM name string
    """
    from fortianalyzer_mcp.utils.config import get_settings

    try:
        return get_settings().DEFAULT_ADOM
    except Exception:
        return "root"


# Device name pattern: alphanumeric, underscore, hyphen, dot, 1-64 chars
DEVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")

# Device serial number pattern: starts with device type prefix, alphanumeric
DEVICE_SERIAL_PATTERN = re.compile(r"^(FG|FM|FW|FA|FS|FD|FP|FC|FV)[A-Z0-9]{10,20}$")

# VM appliance serials carry a hyphen before the VM marker (e.g.
# "FMG-VM0000000001", "FAZ-VMTM23000001") and are not covered by the plain
# serial pattern above.
DEVICE_VM_SERIAL_PATTERN = re.compile(
    r"^(FG|FM|FW|FA|FS|FD|FP|FC|FV)[A-Z0-9]{0,2}-VM[A-Z0-9]{4,18}$"
)

# Log type validation
VALID_LOG_TYPES = {
    "traffic",
    "event",
    "attack",
    "virus",
    "webfilter",
    "app-ctrl",
    "dlp",
    "emailfilter",
    "utm",
    "anomaly",
    "voip",
    "dns",
    "ssh",
    "ssl",
    "file-filter",
    "icap",
    "virtual-patch",
}

# FortiView view names. Every name here is one FortiAnalyzer actually serves:
# "traffic-summary", "fortiview-traffic" and "fortiview-threats" used to be
# listed too, and all three answer "Cannot find FortiView '<name>'" on both
# 7.6.7 and 8.0.0. Accepting them only moved the failure from a clear local
# validation error to a server error one call later.
VALID_FORTIVIEW_VIEWS = {
    "top-sources",
    "top-destinations",
    "top-applications",
    "top-websites",
    "top-threats",
    "top-cloud-applications",
    "top-countries",  # Top destination countries (geo) — network_context skill
    "site-to-site-ipsec",  # Site-to-site IPsec tunnels — network_context skill
    "policy-hits",  # Per-policy hit counts (correct endpoint)
    "policy-line",  # Time-series policy data
}

# Severity levels
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Traffic log action values (FortiGate)
VALID_TRAFFIC_ACTIONS = {"accept", "deny", "close", "drop", "ip-conn", "timeout"}

# IPS/attack log action values (FortiGate UTM)
VALID_IPS_ACTIONS = {"detected", "blocked", "dropped", "reset", "pass", "clear_session"}

# Event log levels (FortiGate syslog levels)
VALID_EVENT_LEVELS = {
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "information",
    "debug",
}

# Event log subtypes
VALID_EVENT_SUBTYPES = {
    "system",
    "vpn",
    "user",
    "router",
    "wireless",
    "wad",
    "endpoint",
    "ha",
    "security-rating",
    "fortiextender",
    "connector",
    "sdwan",
}

# Safe unquoted filter value: alphanumeric, dot, hyphen, underscore, colon (IPv6).
# Anything matching this contains no quote/operator/boolean injection characters.
_SAFE_UNQUOTED_FILTER_RE = re.compile(r"^[a-zA-Z0-9._:\-]+$")

# CVE identifier pattern (e.g. CVE-2025-2945)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# FortiAnalyzer pcapurl: an internal resource reference returned by FAZ in IPS
# log entries. It is a path/token-style string, never an absolute external URL.
# Allowed characters: alphanumerics plus the URL-safe / query separators FAZ uses.
_PCAPURL_RE = re.compile(r"^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+$")
# Maximum sane length for a pcapurl reference.
_PCAPURL_MAX_LEN = 4096


def validate_adom(adom: str) -> str:
    """Validate ADOM name format.

    Args:
        adom: ADOM name to validate

    Returns:
        Validated ADOM name (stripped)

    Raises:
        ValidationError: If ADOM name is invalid
    """
    if not adom:
        raise ValidationError("ADOM name cannot be empty")

    adom = adom.strip()

    if not ADOM_PATTERN.match(adom):
        raise ValidationError(
            f"Invalid ADOM name '{adom}'. "
            "Must be 1-64 characters, alphanumeric, underscore, or hyphen only."
        )

    return adom


def validate_device_name(device: str) -> str:
    """Validate device name format.

    Args:
        device: Device name to validate

    Returns:
        Validated device name (stripped)

    Raises:
        ValidationError: If device name is invalid
    """
    if not device:
        raise ValidationError("Device name cannot be empty")

    device = device.strip()

    # Check for VDOM suffix like "device[vdom]"
    if "[" in device:
        base_name = device.split("[")[0]
        vdom_part = device.split("[")[1].rstrip("]")
        if not DEVICE_NAME_PATTERN.match(base_name):
            raise ValidationError(f"Invalid device name '{base_name}'")
        if not ADOM_PATTERN.match(vdom_part):
            raise ValidationError(f"Invalid VDOM name '{vdom_part}'")
        return device

    if not DEVICE_NAME_PATTERN.match(device):
        raise ValidationError(
            f"Invalid device name '{device}'. "
            "Must be 1-64 characters, alphanumeric, underscore, hyphen, or dot."
        )

    return device


def validate_device_serial(serial: str) -> str:
    """Validate device serial number format.

    Args:
        serial: Serial number to validate

    Returns:
        Validated serial number (uppercase, stripped)

    Raises:
        ValidationError: If serial number is invalid
    """
    if not serial:
        raise ValidationError("Serial number cannot be empty")

    serial = serial.strip().upper()

    if not DEVICE_SERIAL_PATTERN.match(serial):
        raise ValidationError(
            f"Invalid serial number '{serial}'. "
            "Must start with device type prefix (FG, FM, etc.) "
            "followed by 10-20 alphanumeric characters."
        )

    return serial


# Serial-number prefixes used to decide whether a device string is a serial
# (devid) or a device name (devname). Kept here as the single source of truth so
# every tool builds the FAZ device filter identically.


def build_device_filter(device: str | None) -> list[dict[str, str]]:
    """Build the FortiAnalyzer ``device`` filter array for a logview search.

    This is the single source of truth shared by the log, traffic, and pcap
    tools (each previously carried its own copy). The FAZ logview API requires a
    device filter; without one, searches return zero results.

    Args:
        device: Device serial number (e.g. ``"FG100FTK19001333"``), device name
            (optionally ``"name[vdom]"``), an ``"All_*"`` device group, or
            ``None`` to default to all FortiGate devices.

    Returns:
        A device-filter list, one of ``[{"devid": ...}]`` or
        ``[{"devname": ...}]``, ready to pass as the ``device`` parameter.

    Note:
        Values matching the full serial shape (hardware or VM form) and
        ``All_*`` groups are sent as ``devid``; anything else is treated as a
        ``devname``. A bare prefix match is deliberately NOT enough: hostnames
        like ``FGT-HQ-01`` start with a serial prefix, and sending them as
        ``devid`` makes FAZ silently return zero results.
    """
    if not device:
        # FAZ rejects an empty device filter with 0 results; default to all FGTs.
        return [{"devid": "All_FortiGate"}]
    if DEVICE_SERIAL_PATTERN.match(device) or DEVICE_VM_SERIAL_PATTERN.match(device):
        return [{"devid": device}]
    if device.startswith("All_"):
        return [{"devid": device}]
    return [{"devname": device}]


def validate_log_type(logtype: str) -> str:
    """Validate log type.

    Args:
        logtype: Log type to validate

    Returns:
        Validated log type (lowercase)

    Raises:
        ValidationError: If log type is invalid
    """
    if not logtype:
        raise ValidationError("Log type cannot be empty")

    logtype = logtype.strip().lower()

    if logtype not in VALID_LOG_TYPES:
        raise ValidationError(
            f"Invalid log type '{logtype}'. Valid types: {', '.join(sorted(VALID_LOG_TYPES))}"
        )

    return logtype


def validate_fortiview_view(view_name: str) -> str:
    """Validate FortiView view name.

    Args:
        view_name: View name to validate

    Returns:
        Validated view name (lowercase)

    Raises:
        ValidationError: If view name is invalid
    """
    if not view_name:
        raise ValidationError("View name cannot be empty")

    view_name = view_name.strip().lower()

    if view_name not in VALID_FORTIVIEW_VIEWS:
        raise ValidationError(
            f"Invalid FortiView view '{view_name}'. "
            f"Valid views: {', '.join(sorted(VALID_FORTIVIEW_VIEWS))}"
        )

    return view_name


def validate_severity(severity: str) -> str:
    """Validate severity level.

    Args:
        severity: Severity to validate

    Returns:
        Validated severity (lowercase)

    Raises:
        ValidationError: If severity is invalid
    """
    if not severity:
        raise ValidationError("Severity cannot be empty")

    severity = severity.strip().lower()

    if severity not in VALID_SEVERITIES:
        raise ValidationError(
            f"Invalid severity '{severity}'. "
            f"Valid severities: {', '.join(sorted(VALID_SEVERITIES))}"
        )

    return severity


# =============================================================================
# Log Filter Value Validation (injection-safe)
# =============================================================================


def validate_ip_or_cidr(value: str, field: str = "IP address") -> str:
    """Validate an IPv4/IPv6 address or CIDR network.

    Rejects anything that is not a syntactically valid IP address or
    network, blocking filter-injection payloads such as
    ``1.1.1.1" or 1==1 or "``.

    Args:
        value: IP address or CIDR string to validate.
        field: Field name used in the error message.

    Returns:
        Validated IP/CIDR string (stripped).

    Raises:
        ValidationError: If the value is not a valid IP address or network.
    """
    if not value:
        raise ValidationError(f"{field} cannot be empty")

    value = value.strip()

    # Accept a plain host address or a CIDR network.
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(
            f"Invalid {field} '{value}'. Must be a valid IPv4/IPv6 address or CIDR network."
        ) from exc

    return value


def validate_port(port: int, field: str = "port") -> int:
    """Validate a TCP/UDP port number.

    Args:
        port: Port value to validate.
        field: Field name used in the error message.

    Returns:
        Validated port integer.

    Raises:
        ValidationError: If the port is not an int in the range 1-65535.
    """
    # bool is a subclass of int; reject it explicitly.
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValidationError(f"Invalid {field} '{port}'. Must be an integer 1-65535.")
    if not 1 <= port <= 65535:
        raise ValidationError(f"Invalid {field} '{port}'. Must be in range 1-65535.")
    return port


def validate_incident_id(incident_id: str) -> str:
    """Validate a FortiAnalyzer incident ID.

    Incident IDs are interpolated into the JSON-RPC url path
    (``/incidentmgmt/adom/{adom}/incident/{incident_id}``), so restrict them
    to the same safe character class as ADOM names to prevent path injection.

    Args:
        incident_id: Incident ID to validate (e.g. "IN00000001").

    Returns:
        Validated incident ID (stripped).

    Raises:
        ValidationError: If the incident ID is empty or contains unsafe characters.
    """
    if not incident_id:
        raise ValidationError("Incident ID cannot be empty")

    incident_id = incident_id.strip()

    if not ADOM_PATTERN.match(incident_id):
        raise ValidationError(
            f"Invalid incident ID '{incident_id}'. "
            "Must be 1-64 characters, alphanumeric, underscore, or hyphen only."
        )

    return incident_id


def validate_session_id(session_id: int) -> int:
    """Validate a FortiAnalyzer session ID.

    Args:
        session_id: Session ID to validate.

    Returns:
        Validated session ID integer.

    Raises:
        ValidationError: If the session ID is not a positive integer.
    """
    if isinstance(session_id, bool) or not isinstance(session_id, int) or session_id <= 0:
        raise ValidationError(f"Invalid session ID '{session_id}'. Must be a positive integer.")
    return session_id


def validate_traffic_action(action: str) -> str:
    """Validate a traffic log action against the allowlist.

    Args:
        action: Action string to validate.

    Returns:
        Validated action (lowercase).

    Raises:
        ValidationError: If the action is not in the allowlist.
    """
    if not action:
        raise ValidationError("Action cannot be empty")
    action = action.strip().lower()
    if action not in VALID_TRAFFIC_ACTIONS:
        raise ValidationError(
            f"Invalid action '{action}'. Valid actions: {', '.join(sorted(VALID_TRAFFIC_ACTIONS))}"
        )
    return action


def validate_ips_action(action: str) -> str:
    """Validate an IPS/attack log action against the allowlist.

    Args:
        action: Action string to validate.

    Returns:
        Validated action (lowercase).

    Raises:
        ValidationError: If the action is not in the allowlist.
    """
    if not action:
        raise ValidationError("Action cannot be empty")
    action = action.strip().lower()
    if action not in VALID_IPS_ACTIONS:
        raise ValidationError(
            f"Invalid action '{action}'. Valid actions: {', '.join(sorted(VALID_IPS_ACTIONS))}"
        )
    return action


def validate_event_level(level: str) -> str:
    """Validate an event log level against the allowlist.

    Args:
        level: Level string to validate.

    Returns:
        Validated level (lowercase).

    Raises:
        ValidationError: If the level is not in the allowlist.
    """
    if not level:
        raise ValidationError("Level cannot be empty")
    level = level.strip().lower()
    if level not in VALID_EVENT_LEVELS:
        raise ValidationError(
            f"Invalid level '{level}'. Valid levels: {', '.join(sorted(VALID_EVENT_LEVELS))}"
        )
    return level


def validate_event_subtype(subtype: str) -> str:
    """Validate an event log subtype against the allowlist.

    Args:
        subtype: Subtype string to validate.

    Returns:
        Validated subtype (lowercase).

    Raises:
        ValidationError: If the subtype is not in the allowlist.
    """
    if not subtype:
        raise ValidationError("Subtype cannot be empty")
    subtype = subtype.strip().lower()
    if subtype not in VALID_EVENT_SUBTYPES:
        raise ValidationError(
            f"Invalid subtype '{subtype}'. "
            f"Valid subtypes: {', '.join(sorted(VALID_EVENT_SUBTYPES))}"
        )
    return subtype


def validate_cve(cve: str) -> str:
    """Validate a CVE identifier (e.g. CVE-2025-2945).

    Args:
        cve: CVE identifier to validate.

    Returns:
        Validated CVE identifier (uppercase).

    Raises:
        ValidationError: If the value is not a valid CVE identifier.
    """
    if not cve:
        raise ValidationError("CVE cannot be empty")
    cve = cve.strip()
    if not _CVE_RE.match(cve):
        raise ValidationError(f"Invalid CVE identifier '{cve}'. Expected format: CVE-YYYY-NNNN.")
    return cve.upper()


def sanitize_filter_value(value: str, field: str = "filter value") -> str:
    """Sanitize a free-text value for use in a FAZ log filter expression.

    Safe alphanumeric values (including dots, hyphens, underscores, and
    colons for IPv6) are returned as-is. Anything else is escaped and
    wrapped in double quotes so that quote/operator/boolean characters in
    attacker-controlled input cannot rewrite the surrounding filter.

    Args:
        value: Raw filter value.
        field: Field name used in the error message.

    Returns:
        Sanitized value safe for interpolation into a filter expression.

    Raises:
        ValidationError: If the value is empty.
    """
    if not value:
        raise ValidationError(f"{field} cannot be empty")
    value = value.strip()
    if not value:
        raise ValidationError(f"{field} cannot be empty after stripping")
    if _SAFE_UNQUOTED_FILTER_RE.match(value):
        return value
    # Escape backslashes first, then double quotes, then wrap in quotes.
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def validate_pcapurl(pcapurl: str) -> str:
    """Validate a FortiAnalyzer pcapurl reference before forwarding to FAZ.

    The ``pcapurl`` value originates from a FAZ IPS log entry and is an
    internal resource reference (a path/token-style string), not an
    arbitrary external URL. Forwarding an attacker-controlled value to
    ``/logview/pcapfile`` should be constrained: reject absolute external
    URLs (those with a scheme such as ``http://``), reject embedded control
    characters / whitespace / backslashes, and cap the length.

    Args:
        pcapurl: The pcapurl value to validate.

    Returns:
        Validated pcapurl string (stripped).

    Raises:
        ValidationError: If the value does not look like a FAZ pcapurl
            reference.
    """
    if not pcapurl:
        raise ValidationError("pcapurl cannot be empty")

    pcapurl = pcapurl.strip()

    if not pcapurl:
        raise ValidationError("pcapurl cannot be empty after stripping")

    if len(pcapurl) > _PCAPURL_MAX_LEN:
        raise ValidationError(
            f"pcapurl too long ({len(pcapurl)} chars). Maximum is {_PCAPURL_MAX_LEN}."
        )

    # Reject control characters, whitespace, and backslashes outright.
    if any(ord(ch) < 0x20 or ch in (" ", "\t", "\\") for ch in pcapurl):
        raise ValidationError("pcapurl contains illegal whitespace or control characters")

    # Reject absolute external URLs (anything with a URL scheme like http://,
    # https://, ftp://, file://, etc.). A FAZ pcapurl is a relative reference.
    if "://" in pcapurl or re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", pcapurl):
        raise ValidationError(
            f"Invalid pcapurl '{pcapurl}'. Expected a FortiAnalyzer resource reference, "
            "not an absolute URL."
        )

    if not _PCAPURL_RE.match(pcapurl):
        raise ValidationError(
            f"Invalid pcapurl '{pcapurl}'. Contains characters not permitted in a "
            "FortiAnalyzer resource reference."
        )

    return pcapurl


# =============================================================================
# Path Validation
# =============================================================================


def get_allowed_output_dirs() -> list[Path]:
    """Get list of allowed output directories.

    Returns directories from FAZ_ALLOWED_OUTPUT_DIRS env var.
    No default directories are permitted — file output must be
    explicitly configured via the environment variable.

    This follows the principle of secure-by-default: tools that
    only query data work without any output directory configuration.
    File output (PCAPs, reports) requires explicit opt-in.

    Set FAZ_ALLOWED_OUTPUT_DIRS to a comma-separated list of directories:
        FAZ_ALLOWED_OUTPUT_DIRS=~/Downloads,~/Reports

    Returns:
        List of allowed Path objects

    Raises:
        ValidationError: If no output directories are configured
    """
    env_dirs = os.environ.get("FAZ_ALLOWED_OUTPUT_DIRS", "")

    if env_dirs:
        # Parse comma-separated list from environment
        dirs = []
        for d in env_dirs.split(","):
            d = d.strip()
            if d:
                path = Path(d).expanduser().resolve()
                if path.exists() and path.is_dir():
                    dirs.append(path)
        if dirs:
            return dirs

    # Secure by default: no output directories allowed without explicit config
    raise ValidationError(
        "No output directories configured. File output is disabled by default. "
        "Set FAZ_ALLOWED_OUTPUT_DIRS environment variable to enable file output. "
        "Example: FAZ_ALLOWED_OUTPUT_DIRS=~/Downloads"
    )


def validate_output_path(output_dir: str) -> Path:
    """Validate and resolve output directory path.

    Ensures the path is within allowed directories to prevent
    directory traversal attacks.

    Args:
        output_dir: Output directory path (can include ~)

    Returns:
        Resolved Path object

    Raises:
        ValidationError: If path is not within allowed directories
    """
    if not output_dir:
        raise ValidationError("Output directory cannot be empty")

    # Expand ~ and resolve to absolute path
    path = Path(output_dir).expanduser().resolve()

    # Get allowed directories
    allowed_dirs = get_allowed_output_dirs()

    # Check if path is within any allowed directory
    for allowed in allowed_dirs:
        try:
            path.relative_to(allowed)
            return path
        except ValueError:
            continue

    # Path not in allowed directories
    allowed_str = ", ".join(str(d) for d in allowed_dirs)
    raise ValidationError(
        f"Output directory '{path}' is not within allowed directories. "
        f"Allowed: {allowed_str}. "
        "Set FAZ_ALLOWED_OUTPUT_DIRS environment variable to customize."
    )


def validate_filename(filename: str) -> str:
    """Validate filename for safe filesystem operations.

    Args:
        filename: Filename to validate

    Returns:
        Sanitized filename

    Raises:
        ValidationError: If filename is invalid or dangerous
    """
    if not filename:
        raise ValidationError("Filename cannot be empty")

    # Remove path separators and dangerous characters
    basename = os.path.basename(filename)

    # Check for hidden files or special names
    if basename.startswith("."):
        raise ValidationError(f"Hidden files not allowed: {basename}")

    # Check for dangerous patterns
    dangerous = [".", "..", "~", "*", "?", "|", "<", ">", ":", '"', "\\", "/"]
    for char in dangerous:
        if char in basename and char != ".":  # Allow single dot for extension
            raise ValidationError(f"Invalid character '{char}' in filename")

    # Validate with pattern: alphanumeric, underscore, hyphen, dot, space
    if not re.match(r"^[\w\-. ]+$", basename):
        raise ValidationError(f"Invalid filename: {basename}")

    return basename


def assert_within_directory(dest: Path, output_dir: Path) -> Path:
    """Assert that a resolved destination path stays within an output dir.

    Defense-in-depth guard for archive extraction: even when a filename has
    already been reduced with ``os.path.basename``, this verifies the fully
    resolved destination does not escape the intended output directory
    (e.g. via symlinks or unexpected basename behaviour).

    Args:
        dest: Candidate output file path.
        output_dir: The directory the file must stay within.

    Returns:
        The resolved destination path.

    Raises:
        ValidationError: If the resolved destination escapes output_dir.
    """
    resolved_dest = Path(dest).resolve()
    resolved_dir = Path(output_dir).resolve()
    try:
        resolved_dest.relative_to(resolved_dir)
    except ValueError as exc:
        raise ValidationError(
            f"Refusing to write '{resolved_dest}': path escapes output directory '{resolved_dir}'."
        ) from exc
    return resolved_dest
