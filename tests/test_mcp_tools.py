#!/usr/bin/env python3
"""Test runner for MCP tools layer.

This script tests the MCP tools (event_tools, fortiview_tools, report_tools,
incident_tools, ioc_tools) against real FortiAnalyzer environments.

Unlike run_tests.py which tests the API client directly, this tests the
actual MCP tool functions that will be exposed to MCP clients.

Usage:
    python tests/test_mcp_tools.py                     # Run all MCP tool tests
    python tests/test_mcp_tools.py --env prod-ai       # Run on specific environment
    python tests/test_mcp_tools.py --category event    # Run specific category
    python tests/test_mcp_tools.py --list              # List available tests
"""

import argparse
import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from test_config import (
    FAZ_ENVIRONMENTS,
    FAZEnvironment,
    FAZTestConfig,
)


def setup_environment_for_tools(config: FAZTestConfig):
    """Set environment variables so server module can initialize."""
    os.environ["FORTIANALYZER_HOST"] = config.host
    if config.api_token:
        os.environ["FORTIANALYZER_API_TOKEN"] = config.api_token
    if config.username:
        os.environ["FORTIANALYZER_USERNAME"] = config.username
    if config.password:
        os.environ["FORTIANALYZER_PASSWORD"] = config.password
    os.environ["FORTIANALYZER_VERIFY_SSL"] = "false"


# We need to mock the server module's get_faz_client before importing tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient

# Global client that will be used by tools
_test_client: FortiAnalyzerClient | None = None


def mock_get_faz_client():
    """Mock function to return our test client."""
    return _test_client


def mock_get_client():
    """Mock _get_client function that returns test client."""
    if _test_client is None:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return _test_client


def import_tools_with_mock(config: FAZTestConfig):
    """Import tools after setting up environment and mocking get_faz_client."""
    # Set environment variables first
    setup_environment_for_tools(config)

    # Now import server module (it will use env vars)
    import fortianalyzer_mcp.server as server_module

    # Patch the get_faz_client function in server module
    server_module.get_faz_client = mock_get_faz_client

    # Now import the tools
    from fortianalyzer_mcp.tools import (
        event_tools,
        fortiview_tools,
        log_tools,
        report_tools,
        incident_tools,
        ioc_tools,
    )

    # Patch the _get_client function in each tools module
    # This is the function that's actually called by the tool functions
    event_tools._get_client = mock_get_client
    fortiview_tools._get_client = mock_get_client
    log_tools._get_client = mock_get_client
    report_tools._get_client = mock_get_client
    incident_tools._get_client = mock_get_client
    ioc_tools._get_client = mock_get_client

    return event_tools, fortiview_tools, log_tools, report_tools, incident_tools, ioc_tools


class TestResult:
    """Container for test results."""
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.passed = False
        self.error: str | None = None
        self.result: any = None
        self.duration: float = 0.0

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        msg = f"[{status}] {self.name} ({self.duration:.2f}s)"
        if self.error:
            msg += f"\n       Error: {self.error}"
        return msg


class MCPToolsTestRunner:
    """Test runner for MCP tools layer."""

    def __init__(self, config: FAZTestConfig):
        self.config = config
        self.results: list[TestResult] = []
        # Tool modules will be set after import
        self.event_tools = None
        self.fortiview_tools = None
        self.log_tools = None
        self.report_tools = None
        self.incident_tools = None
        self.ioc_tools = None

    async def connect(self) -> bool:
        """Connect to FortiAnalyzer and import tool modules."""
        global _test_client
        print(f"\nConnecting to {self.config.name} ({self.config.host})...")

        try:
            _test_client = FortiAnalyzerClient(
                host=self.config.host,
                api_token=self.config.api_token,
                username=self.config.username,
                password=self.config.password,
                verify_ssl=self.config.verify_ssl,
                timeout=self.config.timeout,
            )
            await _test_client.connect()
            print(f"Connected to {self.config.name}")

            # Import tools with mock
            (
                self.event_tools,
                self.fortiview_tools,
                self.log_tools,
                self.report_tools,
                self.incident_tools,
                self.ioc_tools,
            ) = import_tools_with_mock(self.config)

            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False

    async def disconnect(self) -> None:
        """Disconnect from FortiAnalyzer."""
        global _test_client
        if _test_client:
            await _test_client.disconnect()
            print(f"Disconnected from {self.config.name}")
            _test_client = None

    async def run_test(self, name: str, category: str, coro) -> TestResult:
        """Run a single test and capture result."""
        result = TestResult(name, category)
        start = datetime.now()

        try:
            result.result = await coro
            # Check if the result indicates success
            if isinstance(result.result, dict):
                status = result.result.get("status", "success")
                if status == "error":
                    result.error = result.result.get("message", "Unknown error")
                    result.passed = False
                else:
                    result.passed = True
            else:
                result.passed = True
        except Exception as e:
            result.error = str(e)
            result.passed = False

        result.duration = (datetime.now() - start).total_seconds()
        self.results.append(result)
        print(result)
        return result

    # =========================================================================
    # Event Tools Tests
    # =========================================================================

    async def run_event_tools_tests(self) -> None:
        """Run all event tools tests."""
        print("\n=== Event Tools Tests ===")

        # Test get_alerts
        await self.run_test(
            "event_tools.get_alerts",
            "event",
            self.event_tools.get_alerts(adom="root", time_range="24-hour", limit=10)
        )

        # Test get_alert_count
        await self.run_test(
            "event_tools.get_alert_count",
            "event",
            self.event_tools.get_alert_count(adom="root", time_range="24-hour")
        )

        # Test get_alert_incident_stats
        await self.run_test(
            "event_tools.get_alert_incident_stats",
            "event",
            self.event_tools.get_alert_incident_stats(adom="root", time_range="7-day", stat_type="severity")
        )

    # =========================================================================
    # FortiView Tools Tests
    # =========================================================================

    async def run_fortiview_tools_tests(self) -> None:
        """Run all FortiView tools tests."""
        print("\n=== FortiView Tools Tests ===")

        # Device filter for FortiView queries
        device = "All_FortiGate"

        # Test run_fortiview (start a query)
        result = await self.run_test(
            "fortiview_tools.run_fortiview",
            "fortiview",
            self.fortiview_tools.run_fortiview(
                view_name="top-sources",
                adom="root",
                device=device,
                time_range="1-hour",
                limit=10
            )
        )

        # If we got a TID, test fetch_fortiview
        if result.passed and result.result.get("tid"):
            tid = result.result["tid"]
            await asyncio.sleep(1)  # Wait for results

            await self.run_test(
                "fortiview_tools.fetch_fortiview",
                "fortiview",
                self.fortiview_tools.fetch_fortiview(tid=tid, view_name="top-sources", adom="root")
            )

        # Test get_fortiview_data (convenience function with auto TID handling)
        await self.run_test(
            "fortiview_tools.get_fortiview_data",
            "fortiview",
            self.fortiview_tools.get_fortiview_data(
                view_name="top-sources",
                adom="root",
                device=device,
                time_range="1-hour",
                limit=5,
                timeout=30
            )
        )

        # Test get_top_sources
        await self.run_test(
            "fortiview_tools.get_top_sources",
            "fortiview",
            self.fortiview_tools.get_top_sources(adom="root", device=device, time_range="1-hour", limit=5)
        )

        # Test get_top_applications
        await self.run_test(
            "fortiview_tools.get_top_applications",
            "fortiview",
            self.fortiview_tools.get_top_applications(adom="root", device=device, time_range="1-hour", limit=5)
        )

        # Test get_top_threats
        await self.run_test(
            "fortiview_tools.get_top_threats",
            "fortiview",
            self.fortiview_tools.get_top_threats(adom="root", device=device, time_range="24-hour", limit=5)
        )

    # =========================================================================
    # Log Tools Tests
    # =========================================================================

    async def run_log_tools_tests(self) -> None:
        """Run all log tools tests."""
        print("\n=== Log Tools Tests ===")

        # Test get_log_fields - quick metadata query
        await self.run_test(
            "log_tools.get_log_fields",
            "log",
            self.log_tools.get_log_fields(adom="root", logtype="traffic")
        )

        # Test get_log_stats - quick metadata query
        await self.run_test(
            "log_tools.get_log_stats",
            "log",
            self.log_tools.get_log_stats(adom="root")
        )

        # Test query_logs - full TID workflow with traffic logs (short time range)
        result = await self.run_test(
            "log_tools.query_logs (traffic)",
            "log",
            self.log_tools.query_logs(
                adom="root",
                logtype="traffic",
                time_range="1-hour",
                limit=10,
                timeout=30
            )
        )

        # If we got results with a TID, test fetch_more_logs
        if result.passed and result.result.get("tid"):
            tid = result.result["tid"]
            await self.run_test(
                "log_tools.fetch_more_logs",
                "log",
                self.log_tools.fetch_more_logs(adom="root", tid=tid, limit=5, offset=0)
            )

        # Test search_traffic_logs convenience function
        await self.run_test(
            "log_tools.search_traffic_logs",
            "log",
            self.log_tools.search_traffic_logs(
                adom="root",
                time_range="1-hour",
                limit=10,
                timeout=30
            )
        )

        # Test search_event_logs convenience function
        await self.run_test(
            "log_tools.search_event_logs",
            "log",
            self.log_tools.search_event_logs(
                adom="root",
                time_range="1-hour",
                limit=10,
                timeout=30
            )
        )

        # Test search_security_logs (attack logs) - may return empty if no attacks
        await self.run_test(
            "log_tools.search_security_logs",
            "log",
            self.log_tools.search_security_logs(
                adom="root",
                time_range="24-hour",
                limit=10,
                timeout=30
            )
        )

    # =========================================================================
    # Report Tools Tests
    # =========================================================================

    async def run_report_tools_tests(self) -> None:
        """Run all report tools tests."""
        print("\n=== Report Tools Tests ===")

        # Test list_report_templates
        await self.run_test(
            "report_tools.list_report_templates",
            "report",
            self.report_tools.list_report_templates(adom="root")
        )

        # Test get_report_history
        await self.run_test(
            "report_tools.get_report_history",
            "report",
            self.report_tools.get_report_history(adom="root", time_range="30-day", state="generated")
        )

        # Note: We don't test run_report as it actually generates a report
        # and could take a long time / consume resources

    # =========================================================================
    # Incident Tools Tests
    # =========================================================================

    async def run_incident_tools_tests(self) -> None:
        """Run all incident tools tests."""
        print("\n=== Incident Tools Tests ===")

        # Test get_incidents
        await self.run_test(
            "incident_tools.get_incidents",
            "incident",
            self.incident_tools.get_incidents(adom="root", time_range="30-day", limit=10)
        )

        # Test get_incident_count
        await self.run_test(
            "incident_tools.get_incident_count",
            "incident",
            self.incident_tools.get_incident_count(adom="root", time_range="30-day")
        )

        # Test get_incident_stats
        await self.run_test(
            "incident_tools.get_incident_stats",
            "incident",
            self.incident_tools.get_incident_stats(adom="root", time_range="30-day")
        )

        # Note: We don't test create_incident/update_incident to avoid modifying data

    # =========================================================================
    # IOC Tools Tests
    # =========================================================================

    async def run_ioc_tools_tests(self) -> None:
        """Run all IOC tools tests."""
        print("\n=== IOC Tools Tests ===")

        # Test get_ioc_license_state
        await self.run_test(
            "ioc_tools.get_ioc_license_state",
            "ioc",
            self.ioc_tools.get_ioc_license_state()
        )

        # Test get_ioc_rescan_history
        await self.run_test(
            "ioc_tools.get_ioc_rescan_history",
            "ioc",
            self.ioc_tools.get_ioc_rescan_history(adom="root")
        )

        # Note: We don't test run_ioc_rescan as it triggers an actual rescan

    # =========================================================================
    # Run All Tests
    # =========================================================================

    async def run_all_tests(self) -> None:
        """Run all MCP tool tests."""
        await self.run_event_tools_tests()
        await self.run_fortiview_tools_tests()
        await self.run_log_tools_tests()
        await self.run_report_tools_tests()
        await self.run_incident_tools_tests()
        await self.run_ioc_tools_tests()

    def print_summary(self) -> None:
        """Print test summary."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        # Group by category
        categories = {}
        for r in self.results:
            if r.category not in categories:
                categories[r.category] = {"passed": 0, "failed": 0}
            if r.passed:
                categories[r.category]["passed"] += 1
            else:
                categories[r.category]["failed"] += 1

        print("\n" + "=" * 60)
        print(f"MCP TOOLS TEST SUMMARY: {self.config.name} ({self.config.version})")
        print("=" * 60)

        for cat, counts in categories.items():
            status = "OK" if counts["failed"] == 0 else "FAIL"
            print(f"  {cat:12} {counts['passed']}/{counts['passed'] + counts['failed']} [{status}]")

        print("-" * 60)
        print(f"Total:  {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")

        if failed > 0:
            print("\nFailed tests:")
            for r in self.results:
                if not r.passed:
                    print(f"  - {r.name}: {r.error}")

        print("=" * 60)


async def main():
    parser = argparse.ArgumentParser(
        description="MCP Tools Layer Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python test_mcp_tools.py                    # Run all MCP tool tests
    python test_mcp_tools.py --env prod-ai      # Run on FAZ 8.0.0 Beta
    python test_mcp_tools.py --category event   # Run only event tools tests
    python test_mcp_tools.py --list             # List available tests
        """
    )

    parser.add_argument(
        "--env",
        choices=["prod-764", "prod-ai", "prod-748"],
        default="prod-764",
        help="FAZ environment to test against (default: prod-764)",
    )

    parser.add_argument(
        "--category",
        choices=["all", "event", "fortiview", "log", "report", "incident", "ioc"],
        default="all",
        help="Test category to run (default: all)",
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List available test categories",
    )

    args = parser.parse_args()

    # Handle --list
    if args.list:
        print("\nMCP Tools Test Categories:")
        print("  event     - event_tools: get_alerts, get_alert_count, get_alert_incident_stats")
        print("  fortiview - fortiview_tools: run_fortiview, fetch_fortiview, get_fortiview_data,")
        print("              get_top_sources, get_top_applications, get_top_threats")
        print("  log       - log_tools: get_log_fields, get_log_stats, query_logs, fetch_more_logs,")
        print("              search_traffic_logs, search_event_logs, search_security_logs")
        print("  report    - report_tools: list_report_templates, get_report_history")
        print("  incident  - incident_tools: get_incidents, get_incident_count, get_incident_stats")
        print("  ioc       - ioc_tools: get_ioc_license_state, get_ioc_rescan_history")
        print("  all       - Run all tests")
        print("\nNote: Destructive operations (create_incident, run_ioc_rescan, etc.) are not tested")
        return

    # Map env argument to FAZEnvironment
    env_map = {
        "prod-764": FAZEnvironment.PROD_764,
        "prod-ai": FAZEnvironment.PROD_AI,
        "prod-748": FAZEnvironment.PROD_748,
    }

    env = env_map[args.env]
    config = FAZ_ENVIRONMENTS[env]

    if not config.is_available:
        print(f"Error: {config.name} is not available yet")
        sys.exit(1)

    if not config.has_credentials:
        print(f"Error: No credentials configured for {config.name}")
        print(f"Set environment variables:")
        print(f"  FAZ_PROD_764_API_TOKEN or FAZ_PROD_764_PASSWORD")
        sys.exit(1)

    # Run tests
    runner = MCPToolsTestRunner(config)

    if not await runner.connect():
        sys.exit(1)

    try:
        if args.category == "all":
            await runner.run_all_tests()
        elif args.category == "event":
            await runner.run_event_tools_tests()
        elif args.category == "fortiview":
            await runner.run_fortiview_tools_tests()
        elif args.category == "log":
            await runner.run_log_tools_tests()
        elif args.category == "report":
            await runner.run_report_tools_tests()
        elif args.category == "incident":
            await runner.run_incident_tools_tests()
        elif args.category == "ioc":
            await runner.run_ioc_tools_tests()
    finally:
        await runner.disconnect()

    runner.print_summary()

    # Exit with error code if any tests failed
    if any(not r.passed for r in runner.results):
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
