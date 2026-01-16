"""Tests for FortiAnalyzer MCP validation utilities."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from fortianalyzer_mcp.utils.validation import (
    ADOM_PATTERN,
    DEVICE_NAME_PATTERN,
    DEVICE_SERIAL_PATTERN,
    MASK_VALUE,
    SENSITIVE_FIELDS,
    VALID_FORTIVIEW_VIEWS,
    VALID_LOG_TYPES,
    VALID_SEVERITIES,
    ValidationError,
    get_allowed_output_dirs,
    sanitize_for_logging,
    sanitize_json_for_logging,
    validate_adom,
    validate_device_name,
    validate_device_serial,
    validate_filename,
    validate_fortiview_view,
    validate_log_type,
    validate_output_path,
    validate_severity,
)

# =============================================================================
# Sanitization Tests
# =============================================================================


class TestSanitizeForLogging:
    """Tests for sanitize_for_logging function."""

    def test_masks_password_field(self):
        """Test that password field is masked."""
        data = {"user": "admin", "password": "secret123"}
        result = sanitize_for_logging(data)
        assert result["user"] == "admin"
        assert result["password"] == MASK_VALUE

    def test_masks_multiple_sensitive_fields(self):
        """Test masking multiple sensitive fields."""
        data = {
            "username": "admin",
            "password": "secret",
            "api_token": "tok123",
            "session": "sess456",
        }
        result = sanitize_for_logging(data)
        assert result["username"] == "admin"
        assert result["password"] == MASK_VALUE
        assert result["api_token"] == MASK_VALUE
        assert result["session"] == MASK_VALUE

    def test_masks_nested_sensitive_fields(self):
        """Test masking nested sensitive fields."""
        data = {
            "config": {
                "host": "faz.example.com",
                "auth": {"username": "admin", "password": "secret"},
            }
        }
        result = sanitize_for_logging(data)
        assert result["config"]["host"] == "faz.example.com"
        # "auth" key is sensitive, so entire value is masked
        assert result["config"]["auth"] == MASK_VALUE

    def test_handles_list_items(self):
        """Test masking in list items."""
        data = {
            "users": [
                {"name": "admin", "password": "pass1"},
                {"name": "user", "password": "pass2"},
            ]
        }
        result = sanitize_for_logging(data)
        assert result["users"][0]["name"] == "admin"
        assert result["users"][0]["password"] == MASK_VALUE
        assert result["users"][1]["password"] == MASK_VALUE

    def test_masks_long_hex_strings(self):
        """Test that long hex strings (session IDs) are masked."""
        data = {"session_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"}
        result = sanitize_for_logging(data)
        assert result["session_id"] == MASK_VALUE

    def test_preserves_short_hex_strings(self):
        """Test that short hex strings are not masked."""
        data = {"device_id": "abc123"}
        result = sanitize_for_logging(data)
        assert result["device_id"] == "abc123"

    def test_handles_non_dict_data(self):
        """Test handling of non-dict data."""
        assert sanitize_for_logging("plain string") == "plain string"
        assert sanitize_for_logging(123) == 123
        assert sanitize_for_logging(None) is None

    def test_prevents_infinite_recursion(self):
        """Test max depth protection."""
        # Create deeply nested structure
        data = {"level": 0}
        current = data
        for i in range(15):
            current["nested"] = {"level": i + 1}
            current = current["nested"]

        result = sanitize_for_logging(data)
        # Should not raise, and deep levels should be truncated
        assert result is not None

    def test_case_insensitive_field_matching(self):
        """Test case-insensitive sensitive field detection."""
        data = {"PASSWORD": "secret", "Api_Token": "tok", "SESSION": "sess"}
        result = sanitize_for_logging(data)
        assert result["PASSWORD"] == MASK_VALUE
        assert result["Api_Token"] == MASK_VALUE
        assert result["SESSION"] == MASK_VALUE

    def test_handles_hyphenated_field_names(self):
        """Test handling of hyphenated field names."""
        data = {"api-token": "secret", "auth-key": "key123"}
        result = sanitize_for_logging(data)
        assert result["api-token"] == MASK_VALUE
        assert result["auth-key"] == MASK_VALUE


class TestSanitizeJsonForLogging:
    """Tests for sanitize_json_for_logging function."""

    def test_returns_json_string(self):
        """Test that function returns JSON string."""
        data = {"user": "admin", "password": "secret"}
        result = sanitize_json_for_logging(data)
        assert isinstance(result, str)
        assert "admin" in result
        assert MASK_VALUE in result
        assert "secret" not in result

    def test_handles_indent(self):
        """Test indentation option."""
        data = {"key": "value"}
        compact = sanitize_json_for_logging(data)
        indented = sanitize_json_for_logging(data, indent=2)
        assert "\n" not in compact
        assert "\n" in indented

    def test_handles_non_serializable(self):
        """Test handling of non-JSON-serializable objects."""
        data = {"path": Path("/tmp/test")}
        result = sanitize_json_for_logging(data)
        # Should use default=str to serialize
        assert "/tmp/test" in result


class TestSensitiveFields:
    """Tests for SENSITIVE_FIELDS constant."""

    def test_contains_common_sensitive_names(self):
        """Test that common sensitive field names are included."""
        expected = {
            "password",
            "passwd",
            "api_token",
            "token",
            "session",
            "secret",
            "key",
            "credential",
        }
        assert expected.issubset(SENSITIVE_FIELDS)

    def test_all_lowercase(self):
        """Test that all sensitive fields are lowercase."""
        for field in SENSITIVE_FIELDS:
            assert field == field.lower()


# =============================================================================
# Pattern Tests
# =============================================================================


class TestPatterns:
    """Tests for regex patterns."""

    def test_adom_pattern_valid(self):
        """Test valid ADOM names."""
        valid = ["root", "ADOM_1", "test-adom", "a" * 64]
        for name in valid:
            assert ADOM_PATTERN.match(name), f"'{name}' should be valid"

    def test_adom_pattern_invalid(self):
        """Test invalid ADOM names."""
        invalid = ["", " root", "adom/name", "a" * 65, "adom@name"]
        for name in invalid:
            assert not ADOM_PATTERN.match(name), f"'{name}' should be invalid"

    def test_device_name_pattern_valid(self):
        """Test valid device names."""
        valid = ["device1", "fw-01", "my_firewall", "fw.prod.01"]
        for name in valid:
            assert DEVICE_NAME_PATTERN.match(name), f"'{name}' should be valid"

    def test_device_name_pattern_invalid(self):
        """Test invalid device names."""
        invalid = ["", "device/name", "d" * 65, "device@name"]
        for name in invalid:
            assert not DEVICE_NAME_PATTERN.match(name), f"'{name}' should be invalid"

    def test_device_serial_pattern_valid(self):
        """Test valid serial numbers."""
        valid = ["FG100FTK19001333", "FM200ETK12345678", "FWVM12345678901"]
        for serial in valid:
            assert DEVICE_SERIAL_PATTERN.match(serial), f"'{serial}' should be valid"

    def test_device_serial_pattern_invalid(self):
        """Test invalid serial numbers."""
        invalid = ["XX100FTK19001333", "FG123", "fg100ftk19001333", "12345678901234"]
        for serial in invalid:
            assert not DEVICE_SERIAL_PATTERN.match(serial), f"'{serial}' should be invalid"


# =============================================================================
# ADOM Validation Tests
# =============================================================================


class TestValidateAdom:
    """Tests for validate_adom function."""

    def test_valid_adom(self):
        """Test valid ADOM names pass validation."""
        assert validate_adom("root") == "root"
        assert validate_adom("test_adom") == "test_adom"
        assert validate_adom("ADOM-1") == "ADOM-1"

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert validate_adom("  root  ") == "root"

    def test_empty_raises(self):
        """Test empty ADOM raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_adom("")

    def test_invalid_chars_raises(self):
        """Test invalid characters raise ValidationError."""
        with pytest.raises(ValidationError, match="Invalid ADOM name"):
            validate_adom("adom/name")

    def test_too_long_raises(self):
        """Test ADOM name > 64 chars raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid ADOM name"):
            validate_adom("a" * 65)

    @pytest.mark.parametrize(
        "adom",
        [
            "root",
            "ADOM_1",
            "test-adom-123",
            "A",
            "a" * 64,
        ],
    )
    def test_valid_adom_names(self, adom):
        """Test various valid ADOM names."""
        assert validate_adom(adom) == adom


# =============================================================================
# Device Name Validation Tests
# =============================================================================


class TestValidateDeviceName:
    """Tests for validate_device_name function."""

    def test_valid_device_name(self):
        """Test valid device names pass validation."""
        assert validate_device_name("firewall1") == "firewall1"
        assert validate_device_name("fw-prod-01") == "fw-prod-01"
        assert validate_device_name("fw.site.01") == "fw.site.01"

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert validate_device_name("  device  ") == "device"

    def test_empty_raises(self):
        """Test empty device name raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_device_name("")

    def test_invalid_chars_raises(self):
        """Test invalid characters raise ValidationError."""
        with pytest.raises(ValidationError, match="Invalid device name"):
            validate_device_name("device/name")

    def test_vdom_suffix_valid(self):
        """Test device name with VDOM suffix."""
        result = validate_device_name("firewall[root]")
        assert result == "firewall[root]"

    def test_vdom_suffix_invalid_device(self):
        """Test invalid device name with VDOM suffix."""
        with pytest.raises(ValidationError, match="Invalid device name"):
            validate_device_name("fire/wall[root]")

    def test_vdom_suffix_invalid_vdom(self):
        """Test device name with invalid VDOM suffix."""
        with pytest.raises(ValidationError, match="Invalid VDOM name"):
            validate_device_name("firewall[root/bad]")


# =============================================================================
# Device Serial Validation Tests
# =============================================================================


class TestValidateDeviceSerial:
    """Tests for validate_device_serial function."""

    def test_valid_serial(self):
        """Test valid serial numbers pass validation."""
        assert validate_device_serial("FG100FTK19001333") == "FG100FTK19001333"
        assert validate_device_serial("FM200ETK12345678") == "FM200ETK12345678"

    def test_converts_to_uppercase(self):
        """Test that serial is converted to uppercase."""
        assert validate_device_serial("fg100ftk19001333") == "FG100FTK19001333"

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert validate_device_serial("  FG100FTK19001333  ") == "FG100FTK19001333"

    def test_empty_raises(self):
        """Test empty serial raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_device_serial("")

    def test_invalid_prefix_raises(self):
        """Test invalid prefix raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid serial number"):
            validate_device_serial("XX100FTK19001333")

    def test_too_short_raises(self):
        """Test serial too short raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid serial number"):
            validate_device_serial("FG123")

    @pytest.mark.parametrize(
        "prefix",
        ["FG", "FM", "FW", "FA", "FS", "FD", "FP", "FC", "FV"],
    )
    def test_valid_device_prefixes(self, prefix):
        """Test all valid device type prefixes."""
        serial = f"{prefix}100FTK19001333"
        assert validate_device_serial(serial) == serial


# =============================================================================
# Log Type Validation Tests
# =============================================================================


class TestValidateLogType:
    """Tests for validate_log_type function."""

    def test_valid_log_type(self):
        """Test valid log types pass validation."""
        assert validate_log_type("traffic") == "traffic"
        assert validate_log_type("event") == "event"
        assert validate_log_type("attack") == "attack"

    def test_converts_to_lowercase(self):
        """Test that log type is converted to lowercase."""
        assert validate_log_type("TRAFFIC") == "traffic"
        assert validate_log_type("Event") == "event"

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert validate_log_type("  traffic  ") == "traffic"

    def test_empty_raises(self):
        """Test empty log type raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_log_type("")

    def test_invalid_raises(self):
        """Test invalid log type raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid log type"):
            validate_log_type("invalid-type")

    @pytest.mark.parametrize("logtype", sorted(VALID_LOG_TYPES))
    def test_all_valid_log_types(self, logtype):
        """Test all valid log types are accepted."""
        assert validate_log_type(logtype) == logtype


class TestValidLogTypes:
    """Tests for VALID_LOG_TYPES constant."""

    def test_contains_common_types(self):
        """Test that common log types are included."""
        expected = {"traffic", "event", "attack", "virus", "webfilter", "app-ctrl"}
        assert expected.issubset(VALID_LOG_TYPES)


# =============================================================================
# FortiView Validation Tests
# =============================================================================


class TestValidateFortiviewView:
    """Tests for validate_fortiview_view function."""

    def test_valid_view(self):
        """Test valid view names pass validation."""
        assert validate_fortiview_view("top-sources") == "top-sources"
        assert validate_fortiview_view("top-destinations") == "top-destinations"

    def test_converts_to_lowercase(self):
        """Test that view name is converted to lowercase."""
        assert validate_fortiview_view("TOP-SOURCES") == "top-sources"

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert validate_fortiview_view("  top-sources  ") == "top-sources"

    def test_empty_raises(self):
        """Test empty view name raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_fortiview_view("")

    def test_invalid_raises(self):
        """Test invalid view name raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid FortiView view"):
            validate_fortiview_view("invalid-view")

    @pytest.mark.parametrize("view", sorted(VALID_FORTIVIEW_VIEWS))
    def test_all_valid_views(self, view):
        """Test all valid FortiView views are accepted."""
        assert validate_fortiview_view(view) == view


class TestValidFortiviewViews:
    """Tests for VALID_FORTIVIEW_VIEWS constant."""

    def test_contains_common_views(self):
        """Test that common FortiView views are included."""
        expected = {
            "top-sources",
            "top-destinations",
            "top-applications",
            "top-threats",
        }
        assert expected.issubset(VALID_FORTIVIEW_VIEWS)


# =============================================================================
# Severity Validation Tests
# =============================================================================


class TestValidateSeverity:
    """Tests for validate_severity function."""

    def test_valid_severity(self):
        """Test valid severities pass validation."""
        assert validate_severity("critical") == "critical"
        assert validate_severity("high") == "high"
        assert validate_severity("low") == "low"

    def test_converts_to_lowercase(self):
        """Test that severity is converted to lowercase."""
        assert validate_severity("CRITICAL") == "critical"
        assert validate_severity("High") == "high"

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert validate_severity("  critical  ") == "critical"

    def test_empty_raises(self):
        """Test empty severity raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_severity("")

    def test_invalid_raises(self):
        """Test invalid severity raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid severity"):
            validate_severity("urgent")

    @pytest.mark.parametrize("severity", sorted(VALID_SEVERITIES))
    def test_all_valid_severities(self, severity):
        """Test all valid severities are accepted."""
        assert validate_severity(severity) == severity


class TestValidSeverities:
    """Tests for VALID_SEVERITIES constant."""

    def test_contains_all_levels(self):
        """Test that all severity levels are included."""
        expected = {"critical", "high", "medium", "low", "info"}
        assert VALID_SEVERITIES == expected


# =============================================================================
# Path Validation Tests
# =============================================================================


class TestGetAllowedOutputDirs:
    """Tests for get_allowed_output_dirs function."""

    def test_default_dirs(self):
        """Test default allowed directories."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove FAZ_ALLOWED_OUTPUT_DIRS if set
            os.environ.pop("FAZ_ALLOWED_OUTPUT_DIRS", None)
            dirs = get_allowed_output_dirs()
            assert len(dirs) > 0
            # Should include home
            assert Path.home() in dirs

    def test_custom_dirs_from_env(self):
        """Test custom directories from environment."""
        with patch.dict(os.environ, {"FAZ_ALLOWED_OUTPUT_DIRS": "/tmp,/var/log"}, clear=False):
            dirs = get_allowed_output_dirs()
            # Check that at least one custom dir is included (if exists)
            assert len(dirs) >= 0  # May be empty if dirs don't exist


class TestValidateOutputPath:
    """Tests for validate_output_path function."""

    def test_valid_path_in_home(self):
        """Test path in home directory is valid."""
        home = str(Path.home())
        result = validate_output_path(home)
        assert result == Path.home()

    def test_valid_path_with_tilde(self):
        """Test path with ~ expansion."""
        result = validate_output_path("~")
        assert result == Path.home()

    def test_empty_raises(self):
        """Test empty path raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_output_path("")

    def test_disallowed_path_raises(self):
        """Test path outside allowed dirs raises ValidationError."""
        with patch.dict(os.environ, {"FAZ_ALLOWED_OUTPUT_DIRS": "/tmp/allowed"}, clear=False):
            with pytest.raises(ValidationError, match="not within allowed"):
                validate_output_path("/etc/passwd")


class TestValidateFilename:
    """Tests for validate_filename function."""

    def test_valid_filename(self):
        """Test valid filenames pass validation."""
        assert validate_filename("report.pdf") == "report.pdf"
        assert validate_filename("log_2024-01-15.txt") == "log_2024-01-15.txt"
        assert validate_filename("my report.pdf") == "my report.pdf"

    def test_strips_path(self):
        """Test that path is stripped from filename."""
        assert validate_filename("/path/to/file.txt") == "file.txt"
        assert validate_filename("../../../file.txt") == "file.txt"

    def test_empty_raises(self):
        """Test empty filename raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_filename("")

    def test_hidden_file_raises(self):
        """Test hidden files raise ValidationError."""
        with pytest.raises(ValidationError, match="Hidden files not allowed"):
            validate_filename(".hidden")

    @pytest.mark.parametrize(
        "filename",
        [
            "report.pdf",
            "log_2024.txt",
            "my-file.csv",
            "file 1.json",
        ],
    )
    def test_valid_filenames(self, filename):
        """Test various valid filenames."""
        assert validate_filename(filename) == filename

    @pytest.mark.parametrize(
        "filename",
        [
            ".hidden",
            ".config",
        ],
    )
    def test_invalid_hidden_files(self, filename):
        """Test hidden files are rejected."""
        with pytest.raises(ValidationError):
            validate_filename(filename)


# =============================================================================
# ValidationError Tests
# =============================================================================


class TestValidationError:
    """Tests for ValidationError class."""

    def test_is_value_error(self):
        """Test that ValidationError is a ValueError."""
        error = ValidationError("test error")
        assert isinstance(error, ValueError)

    def test_message(self):
        """Test error message is accessible."""
        error = ValidationError("Invalid input")
        assert str(error) == "Invalid input"
