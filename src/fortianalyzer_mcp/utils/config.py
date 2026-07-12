"""Configuration management for FortiAnalyzer MCP server."""

import json
import logging
import stat
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Compute project root (3 levels up from this file: utils -> fortianalyzer_mcp -> src -> project)
_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE) if _ENV_FILE.exists() else None,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # FortiAnalyzer Connection
    FORTIANALYZER_HOST: str = Field(
        ...,
        description="FortiAnalyzer hostname or IP address",
    )

    FORTIANALYZER_API_TOKEN: str | None = Field(
        default=None,
        description="FortiAnalyzer API token for authentication",
    )

    FORTIANALYZER_USERNAME: str | None = Field(
        default=None,
        description="FortiAnalyzer username (for session-based auth)",
    )

    FORTIANALYZER_PASSWORD: str | None = Field(
        default=None,
        description="FortiAnalyzer password (for session-based auth)",
    )

    FORTIANALYZER_VERIFY_SSL: bool = Field(
        default=True,
        description="Verify SSL certificates",
    )

    FORTIANALYZER_TIMEOUT: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Request timeout in seconds",
    )

    FORTIANALYZER_MAX_RETRIES: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum number of retry attempts",
    )

    # Default ADOM
    DEFAULT_ADOM: str = Field(
        default="root",
        description="Default ADOM for API operations",
    )

    # MCP Server Settings
    MCP_SERVER_HOST: str = Field(
        # Operator-controlled bind. 0.0.0.0 is intended for Docker / reverse-proxy
        # deployments; pair it with MCP_AUTH_TOKEN so the HTTP transport requires
        # Bearer auth on a non-loopback bind.
        default="0.0.0.0",  # nosec B104
        description="MCP server bind address",
    )

    MCP_SERVER_PORT: int = Field(
        default=8001,
        ge=1,
        le=65535,
        description="MCP server port",
    )

    # MCP Server Mode
    MCP_SERVER_MODE: Literal["http", "stdio", "auto"] = Field(
        default="auto",
        description="Server mode: 'http' for Docker/web, 'stdio' for Claude Desktop, 'auto' to detect",
    )

    # MCP HTTP Auth
    MCP_AUTH_TOKEN: str | None = Field(
        default=None,
        description="Bearer token for HTTP auth. If set, all HTTP requests (except /health) "
        "must include Authorization: Bearer <token>",
    )

    MCP_ALLOW_NO_AUTH: bool = Field(
        default=False,
        description="Explicit opt-out to run the HTTP transport WITHOUT authentication when "
        "MCP_AUTH_TOKEN is unset. Default False = fail closed: the HTTP server refuses to start "
        "without a token, so destructive tools are never exposed unauthenticated. Only enable on "
        "a trusted, isolated bind (e.g. 127.0.0.1 behind a gateway).",
    )

    # MCP Allowed Hosts (for reverse proxy / Docker deployments)
    # NoDecode: without it pydantic-settings JSON-decodes the env value for a
    # list[str] field and a plain "host1,host2" (the documented format) raises
    # SettingsError at startup before the validator below ever runs.
    MCP_ALLOWED_HOSTS: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Additional allowed Host header values for DNS rebinding protection. "
        "Comma-separated in env var (a JSON array is also accepted). "
        "localhost/127.0.0.1 always allowed by SDK.",
    )

    # Tool Loading Mode
    FAZ_TOOL_MODE: Literal["full", "dynamic"] = Field(
        default="full",
        description="Tool loading mode: 'full' loads all tools, 'dynamic' loads meta-tools only",
    )

    # Reversible data masking (RFC #40) — additive, off by default
    MASKING_ENABLED: bool = Field(
        default=False,
        description="Mask IOC/PII fields in tool outputs via FPE (requires FAZ_MASKING_KEY). "
        "Off by default; no behavior change unless enabled.",
    )
    FAZ_MASKING_KEY: str | None = Field(
        default=None,
        description="FPE key (32/48/64 hex chars) for masking. Read here so it resolves "
        "from .env consistently with MASKING_ENABLED; the masking engine otherwise reads "
        "it from the process environment (e.g. a container's environment block).",
    )
    FAZ_MASK_DEVICE_IDENTITY: bool = Field(
        default=False,
        description="Also mask device-identity fields (devname, devid, sn, csf). "
        "Off by default: these identify the reporting estate, not people, and masking "
        "them costs the model its sense of which appliance saw what.",
    )
    # Skills layer (RFC #44) — additive, off by default
    FAZ_SKILLS_ENABLED: bool = Field(
        default=False,
        description="Register the faz_skill dispatcher tool (beta). "
        "Off by default; no behavior change unless enabled.",
    )

    # Logging Configuration
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )

    LOG_FILE: Path | None = Field(
        default=None,
        description="Log file path (if file logging enabled)",
    )

    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log message format",
    )

    # Report Output Security
    FAZ_ALLOWED_OUTPUT_DIRS: str | None = Field(
        default=None,
        description="Comma-separated list of allowed output directories for reports and PCAPs. "
        "No defaults — file output is disabled until explicitly configured. "
        "Example: FAZ_ALLOWED_OUTPUT_DIRS=~/Downloads",
    )

    # Testing Configuration
    TEST_ADOM: str = Field(
        default="root",
        description="ADOM to use for integration tests",
    )

    TEST_DEVICE: str | None = Field(
        default=None,
        description="Device name for device-specific tests",
    )

    TEST_SKIP_WRITE_TESTS: bool = Field(
        default=False,
        description="Skip write operations in tests",
    )

    @field_validator("MCP_ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v: object) -> object:
        """Parse MCP_ALLOWED_HOSTS from a comma-separated string or JSON array."""
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return []
            if s.startswith("["):
                try:
                    return json.loads(s)
                except ValueError:
                    pass
            return [h.strip() for h in s.split(",") if h.strip()]
        return v

    @field_validator("FORTIANALYZER_HOST")
    @classmethod
    def validate_host(cls, v: str) -> str:
        """Validate FortiAnalyzer host."""
        if not v:
            raise ValueError("FORTIANALYZER_HOST cannot be empty")
        # Remove protocol if present
        v = v.replace("https://", "").replace("http://", "")
        # Remove trailing slash
        v = v.rstrip("/")
        return v

    @field_validator("LOG_FILE")
    @classmethod
    def validate_log_file(cls, v: Path | None) -> Path | None:
        """Ensure log directory exists."""
        if v is not None:
            v.parent.mkdir(parents=True, exist_ok=True)
        return v

    @property
    def has_token_auth(self) -> bool:
        """Check if API token authentication is configured."""
        return self.FORTIANALYZER_API_TOKEN is not None

    @property
    def has_session_auth(self) -> bool:
        """Check if session-based authentication is configured."""
        return self.FORTIANALYZER_USERNAME is not None and self.FORTIANALYZER_PASSWORD is not None

    @property
    def base_url(self) -> str:
        """Get FortiAnalyzer base URL."""
        return f"https://{self.FORTIANALYZER_HOST}/jsonrpc"

    def configure_logging(self) -> None:
        """Configure application logging based on settings."""
        # Set log level
        log_level = getattr(logging, self.LOG_LEVEL)

        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format=self.LOG_FORMAT,
            handlers=self._get_log_handlers(),
        )

        # Set httpx logging to WARNING to reduce noise
        logging.getLogger("httpx").setLevel(logging.WARNING)
        # Set pyFMG logging based on our log level
        logging.getLogger("pyFMG").setLevel(log_level)

    def _get_log_handlers(self) -> list[logging.Handler]:
        """Get configured log handlers."""
        handlers: list[logging.Handler] = []

        # Console handler (always enabled)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, self.LOG_LEVEL))
        console_handler.setFormatter(logging.Formatter(self.LOG_FORMAT))
        handlers.append(console_handler)

        # File handler (if configured)
        if self.LOG_FILE:
            file_handler = logging.FileHandler(self.LOG_FILE)
            file_handler.setLevel(getattr(logging, self.LOG_LEVEL))
            file_handler.setFormatter(logging.Formatter(self.LOG_FORMAT))
            handlers.append(file_handler)

        return handlers


def _check_env_file_permissions() -> None:
    """Warn if .env files have overly permissive permissions."""
    logger = logging.getLogger(__name__)
    for env_file in _PROJECT_ROOT.glob(".env*"):
        if env_file.is_file() and not env_file.name.endswith(".example"):
            try:
                file_stat = env_file.stat()
                mode = file_stat.st_mode
                # Warn if group or other can read
                if mode & (stat.S_IRGRP | stat.S_IROTH):
                    logger.warning(
                        f"Security: {env_file.name} is readable by group/others "
                        f"(mode {oct(mode & 0o777)}). Run: chmod 600 {env_file}"
                    )
            except OSError:
                pass


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    Returns:
        Settings instance with configuration from environment

    Raises:
        ValidationError: If required settings are missing or invalid
    """
    _check_env_file_permissions()
    # Required fields (FORTIANALYZER_HOST) come from the environment at
    # runtime; pydantic-settings raises if they are missing.
    return Settings()  # type: ignore[call-arg]
