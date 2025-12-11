"""Custom exceptions for FortiAnalyzer MCP server."""


class FortiAnalyzerError(Exception):
    """Base exception for FortiAnalyzer operations."""

    def __init__(self, message: str, code: int | None = None) -> None:
        """Initialize FortiAnalyzer error.

        Args:
            message: Error message
            code: FortiAnalyzer error code
        """
        self.code = code
        super().__init__(message)


class AuthenticationError(FortiAnalyzerError):
    """Authentication failed."""

    pass


class ConnectionError(FortiAnalyzerError):
    """Connection to FortiAnalyzer failed."""

    pass


class APIError(FortiAnalyzerError):
    """FortiAnalyzer API returned an error."""

    pass


class ResourceNotFoundError(FortiAnalyzerError):
    """Requested resource not found."""

    pass


class PermissionError(FortiAnalyzerError):
    """Permission denied for operation."""

    pass


class TimeoutError(FortiAnalyzerError):
    """Request timed out."""

    pass


class ValidationError(FortiAnalyzerError):
    """Input validation failed."""

    pass


class WorkspaceError(FortiAnalyzerError):
    """Workspace operation failed."""

    pass


# FortiAnalyzer error code mapping
ERROR_CODE_MAP: dict[int, type[FortiAnalyzerError]] = {
    -1: APIError,  # Internal error
    -2: AuthenticationError,  # Invalid session
    -3: PermissionError,  # Permission denied
    -4: ResourceNotFoundError,  # Object not found
    -5: ValidationError,  # Invalid parameter
    -6: APIError,  # Entry already exists
    -7: APIError,  # Entry in use
    -8: WorkspaceError,  # Workspace locked
    -9: WorkspaceError,  # Workspace uncommitted changes
    -10: APIError,  # Version mismatch
    -11: TimeoutError,  # Task timeout
    -20: AuthenticationError,  # Invalid credentials
    -21: AuthenticationError,  # Token expired
}


def parse_faz_error(code: int, message: str, url: str | None = None) -> FortiAnalyzerError:
    """Parse FortiAnalyzer error code and create appropriate exception.

    Args:
        code: FortiAnalyzer error code
        message: Error message from API
        url: API endpoint URL (for context)

    Returns:
        Appropriate FortiAnalyzerError subclass
    """
    error_class = ERROR_CODE_MAP.get(code, APIError)

    # Build descriptive message
    error_msg = message
    if url:
        error_msg = f"{message} (url: {url})"

    return error_class(error_msg, code=code)
