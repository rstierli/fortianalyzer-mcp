"""Tests for FortiAnalyzer MCP error classes and helpers."""

import pytest

from fortianalyzer_mcp.utils.errors import (
    ERROR_CODE_MAP,
    APIError,
    AuthenticationError,
    ConnectionError,
    FortiAnalyzerError,
    PermissionError,
    ResourceNotFoundError,
    TimeoutError,
    ValidationError,
    WorkspaceError,
    parse_faz_error,
)

# =============================================================================
# Base Exception Tests
# =============================================================================


class TestFortiAnalyzerError:
    """Tests for base FortiAnalyzerError class."""

    def test_basic_instantiation(self):
        """Test basic error creation."""
        error = FortiAnalyzerError("Test error")
        assert str(error) == "Test error"
        assert error.code is None

    def test_with_error_code(self):
        """Test error with code."""
        error = FortiAnalyzerError("Test error", code=-4)
        assert str(error) == "Test error"
        assert error.code == -4

    def test_inheritance(self):
        """Test that it inherits from Exception."""
        error = FortiAnalyzerError("Test")
        assert isinstance(error, Exception)


# =============================================================================
# Specific Exception Tests
# =============================================================================


class TestSpecificExceptions:
    """Tests for specific exception classes."""

    @pytest.mark.parametrize(
        "exception_class,expected_base",
        [
            (AuthenticationError, FortiAnalyzerError),
            (ConnectionError, FortiAnalyzerError),
            (APIError, FortiAnalyzerError),
            (ValidationError, FortiAnalyzerError),
            (ResourceNotFoundError, FortiAnalyzerError),
            (PermissionError, FortiAnalyzerError),
            (TimeoutError, FortiAnalyzerError),
            (WorkspaceError, FortiAnalyzerError),
        ],
    )
    def test_inheritance(self, exception_class, expected_base):
        """Test that all exceptions inherit from base."""
        error = exception_class("Test error")
        assert isinstance(error, expected_base)
        assert isinstance(error, Exception)

    def test_authentication_error_with_code(self):
        """Test AuthenticationError with error code."""
        error = AuthenticationError("Invalid credentials", code=-20)
        assert error.code == -20
        assert "Invalid credentials" in str(error)

    def test_resource_not_found_error(self):
        """Test ResourceNotFoundError."""
        error = ResourceNotFoundError("ADOM 'test' not found", code=-4)
        assert error.code == -4

    def test_workspace_error(self):
        """Test WorkspaceError."""
        error = WorkspaceError("Workspace locked by admin", code=-8)
        assert error.code == -8


# =============================================================================
# Error Code Mapping Tests
# =============================================================================


class TestErrorCodeMapping:
    """Tests for error code mapping."""

    def test_error_code_map_contains_expected_codes(self):
        """Test that ERROR_CODE_MAP has expected codes."""
        expected_codes = [-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -20, -21]
        for code in expected_codes:
            assert code in ERROR_CODE_MAP

    @pytest.mark.parametrize(
        "code,expected_class",
        [
            (-1, APIError),
            (-2, AuthenticationError),
            (-3, PermissionError),
            (-4, ResourceNotFoundError),
            (-5, ValidationError),
            (-6, APIError),
            (-7, APIError),
            (-8, WorkspaceError),
            (-9, WorkspaceError),
            (-10, APIError),
            (-11, TimeoutError),
            (-20, AuthenticationError),
            (-21, AuthenticationError),
        ],
    )
    def test_code_to_exception_mapping(self, code, expected_class):
        """Test correct exception class for each code."""
        assert ERROR_CODE_MAP[code] == expected_class


# =============================================================================
# parse_faz_error Tests
# =============================================================================


class TestParseFazError:
    """Tests for parse_faz_error function."""

    def test_known_error_code(self):
        """Test parsing known error code."""
        error = parse_faz_error(-4, "Object not found")
        assert isinstance(error, ResourceNotFoundError)
        assert error.code == -4

    def test_unknown_error_code(self):
        """Test parsing unknown error code defaults to APIError."""
        error = parse_faz_error(-999, "Unknown error")
        assert isinstance(error, APIError)
        assert error.code == -999

    def test_with_url_context(self):
        """Test error includes URL context."""
        error = parse_faz_error(-4, "Not found", url="/dvmdb/device")
        assert "/dvmdb/device" in str(error)

    def test_auth_error_code(self):
        """Test authentication error code."""
        error = parse_faz_error(-20, "Invalid credentials")
        assert isinstance(error, AuthenticationError)

    def test_permission_error_code(self):
        """Test permission error code."""
        error = parse_faz_error(-3, "Access denied")
        assert isinstance(error, PermissionError)

    def test_workspace_error_code(self):
        """Test workspace error code."""
        error = parse_faz_error(-8, "Workspace locked")
        assert isinstance(error, WorkspaceError)

    def test_timeout_error_code(self):
        """Test timeout error code."""
        error = parse_faz_error(-11, "Task timeout")
        assert isinstance(error, TimeoutError)

    def test_validation_error_code(self):
        """Test validation error code."""
        error = parse_faz_error(-5, "Invalid parameter")
        assert isinstance(error, ValidationError)
