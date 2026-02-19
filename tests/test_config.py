"""Test configuration for FortiAnalyzer MCP testing.

Defines the 3 test FortiAnalyzer environments:
- faz-764: FAZ 7.6.4 GA (Production)
- faz-800: FAZ 8.0.0 Beta (AI/Testing)
- faz-748: FAZ 7.4.8 GA (Legacy - not yet running)
"""

import os
from dataclasses import dataclass
from enum import Enum


class FAZEnvironment(Enum):
    """Available FortiAnalyzer test environments."""

    FAZ_764 = "faz-764"  # FAZ 7.6.4 GA
    FAZ_800 = "faz-800"  # FAZ 8.0.0 Beta
    FAZ_748 = "faz-748"  # FAZ 7.4.8 GA (not yet running)


@dataclass
class FAZTestConfig:
    """Configuration for a FortiAnalyzer test environment."""

    name: str
    host: str
    version: str
    api_token: str | None = None
    username: str | None = None
    password: str | None = None
    verify_ssl: bool = False
    timeout: int = 30
    is_available: bool = True
    description: str = ""

    @property
    def has_credentials(self) -> bool:
        """Check if credentials are configured."""
        return bool(self.api_token or (self.username and self.password))


# Test environment configurations
FAZ_ENVIRONMENTS: dict[FAZEnvironment, FAZTestConfig] = {
    FAZEnvironment.FAZ_764: FAZTestConfig(
        name="faz-764",
        host="faz-764.example.com",
        version="7.6.4",
        api_token=os.getenv("FAZ_PROD_764_API_TOKEN"),
        username=os.getenv("FAZ_PROD_764_USERNAME", "admin"),
        password=os.getenv("FAZ_PROD_764_PASSWORD"),
        is_available=True,
        description="FortiAnalyzer 7.6.4 GA - Production",
    ),
    FAZEnvironment.FAZ_800: FAZTestConfig(
        name="faz-800",
        host="faz-800.example.com",
        version="8.0.0",
        api_token=os.getenv("FAZ_PROD_AI_API_TOKEN"),
        username=os.getenv("FAZ_PROD_AI_USERNAME", "admin"),
        password=os.getenv("FAZ_PROD_AI_PASSWORD"),
        is_available=True,
        description="FortiAnalyzer 8.0.0 Beta - AI Testing",
    ),
    FAZEnvironment.FAZ_748: FAZTestConfig(
        name="faz-748",
        host="faz-748.example.com",
        version="7.4.8",
        api_token=os.getenv("FAZ_PROD_748_API_TOKEN"),
        username=os.getenv("FAZ_PROD_748_USERNAME", "admin"),
        password=os.getenv("FAZ_PROD_748_PASSWORD"),
        is_available=False,  # Not yet running
        description="FortiAnalyzer 7.4.8 GA - Legacy (not yet available)",
    ),
}


def get_available_environments() -> list[FAZTestConfig]:
    """Get list of available test environments."""
    return [cfg for cfg in FAZ_ENVIRONMENTS.values() if cfg.is_available]


def get_environment(env: FAZEnvironment) -> FAZTestConfig:
    """Get specific environment configuration."""
    return FAZ_ENVIRONMENTS[env]


def get_default_environment() -> FAZTestConfig:
    """Get the default test environment (7.6.4 GA)."""
    return FAZ_ENVIRONMENTS[FAZEnvironment.FAZ_764]
