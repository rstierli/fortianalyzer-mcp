"""Input validation and log sanitization utilities.

Security utilities for:
- Sanitizing sensitive data from log output
- Validating ADOM, device, and other input parameters
- Path validation for file operations
"""

import json
import os
import re
from pathlib import Path
from typing import Any

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

# FortiView view names
VALID_FORTIVIEW_VIEWS = {
    "top-sources",
    "top-destinations",
    "top-applications",
    "top-websites",
    "top-threats",
    "top-cloud-applications",
    "policy-hits",  # Per-policy hit counts (correct endpoint)
    "policy-line",  # Time-series policy data
    "traffic-summary",
    "fortiview-traffic",
    "fortiview-threats",
}

# Severity levels
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class ValidationError(ValueError):
    """Raised when input validation fails."""

    pass


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
# Path Validation
# =============================================================================


def get_allowed_output_dirs() -> list[Path]:
    """Get list of allowed output directories.

    Returns directories from FAZ_ALLOWED_OUTPUT_DIRS env var,
    or defaults to home directory subdirectories.

    Returns:
        List of allowed Path objects
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

    # Default: common subdirectories under home
    home = Path.home()
    return [
        home,
        home / "Downloads",
        home / "Documents",
        home / "Desktop",
        home / "Reports",
    ]


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
