#!/usr/bin/env python3
"""Standalone test runner for FortiAnalyzer MCP server.

This script allows direct testing of MCP functions against real FortiAnalyzer
environments without requiring the full MCP server to be running.

Usage:
    python tests/run_tests.py                     # Run all tests on default FAZ
    python tests/run_tests.py --env prod-ai       # Run on specific environment
    python tests/run_tests.py --test system       # Run specific test category
    python tests/run_tests.py --list              # List available tests
    python tests/run_tests.py --status            # Check FAZ connectivity
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from test_config import (
    FAZ_ENVIRONMENTS,
    FAZEnvironment,
    FAZTestConfig,
)

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestResult:
    """Container for test results."""

    def __init__(self, name: str):
        self.name = name
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


class FAZTestRunner:
    """Test runner for FortiAnalyzer MCP functions."""

    def __init__(self, config: FAZTestConfig):
        self.config = config
        self.client: FortiAnalyzerClient | None = None
        self.results: list[TestResult] = []

    async def connect(self) -> bool:
        """Connect to FortiAnalyzer."""
        print(f"\nConnecting to {self.config.name} ({self.config.host})...")

        try:
            self.client = FortiAnalyzerClient(
                host=self.config.host,
                api_token=self.config.api_token,
                username=self.config.username,
                password=self.config.password,
                verify_ssl=self.config.verify_ssl,
                timeout=self.config.timeout,
            )
            await self.client.connect()
            print(f"Connected to {self.config.name}")
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False

    async def disconnect(self) -> None:
        """Disconnect from FortiAnalyzer."""
        if self.client:
            await self.client.disconnect()
            print(f"Disconnected from {self.config.name}")

    async def run_test(self, name: str, coro) -> TestResult:
        """Run a single test and capture result."""
        result = TestResult(name)
        start = datetime.now()

        try:
            result.result = await coro
            result.passed = True
        except Exception as e:
            result.error = str(e)
            result.passed = False

        result.duration = (datetime.now() - start).total_seconds()
        self.results.append(result)
        print(result)
        return result

    # =========================================================================
    # System Tests
    # =========================================================================

    async def test_system_status(self) -> TestResult:
        """Test: Get system status."""
        return await self.run_test("system_status", self.client.get_system_status())

    async def test_ha_status(self) -> TestResult:
        """Test: Get HA status."""
        return await self.run_test("ha_status", self.client.get_ha_status())

    # =========================================================================
    # ADOM Tests
    # =========================================================================

    async def test_list_adoms(self) -> TestResult:
        """Test: List all ADOMs."""
        return await self.run_test("list_adoms", self.client.list_adoms())

    async def test_get_adom_root(self) -> TestResult:
        """Test: Get root ADOM details."""
        return await self.run_test("get_adom_root", self.client.get_adom("root"))

    # =========================================================================
    # Device Tests
    # =========================================================================

    async def test_list_devices(self) -> TestResult:
        """Test: List devices in root ADOM."""
        return await self.run_test("list_devices", self.client.list_devices(adom="root"))

    async def test_list_device_groups(self) -> TestResult:
        """Test: List device groups."""
        return await self.run_test(
            "list_device_groups", self.client.list_device_groups(adom="root")
        )

    # =========================================================================
    # Task Tests
    # =========================================================================

    async def test_list_tasks(self) -> TestResult:
        """Test: List tasks."""
        return await self.run_test("list_tasks", self.client.list_tasks())

    # =========================================================================
    # LogView Tests
    # =========================================================================

    async def test_get_logfields(self) -> TestResult:
        """Test: Get log fields for traffic logs."""
        return await self.run_test(
            "get_logfields_traffic", self.client.get_logfields(adom="root", logtype="traffic")
        )

    async def test_get_logstats(self) -> TestResult:
        """Test: Get log statistics."""
        return await self.run_test("get_logstats", self.client.get_logstats(adom="root"))

    async def test_logsearch_workflow(self) -> TestResult:
        """Test: Full log search workflow (start -> fetch -> cancel)."""
        result = TestResult("logsearch_workflow")
        start = datetime.now()

        try:
            # Calculate time range (last 24 hours)
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=24)
            time_range = {
                "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
            }

            # Step 1: Start search
            print("       Starting log search...")
            search_result = await self.client.logsearch_start(
                adom="root",
                logtype="traffic",
                device=[{"devid": "All_FortiGate"}],
                time_range=time_range,
                limit=10,
            )

            tid = search_result.get("tid")
            if not tid:
                raise ValueError(f"No TID returned: {search_result}")

            print(f"       Got TID: {tid}")

            # Step 2: Wait and fetch results
            await asyncio.sleep(2)  # Wait for search to process

            print("       Fetching results...")
            fetch_result = await self.client.logsearch_fetch(
                adom="root",
                tid=tid,
                limit=10,
            )

            logs_found = fetch_result.get("return-lines", 0)
            print(f"       Found {logs_found} logs")

            # Step 3: Check count/progress
            count_result = await self.client.logsearch_count(adom="root", tid=tid)
            print(f"       Progress: {count_result.get('progress-percent', 0)}%")

            result.result = {
                "tid": tid,
                "logs_found": logs_found,
                "progress": count_result,
            }
            result.passed = True

        except Exception as e:
            result.error = str(e)
            result.passed = False

        result.duration = (datetime.now() - start).total_seconds()
        self.results.append(result)
        print(result)
        return result

    # =========================================================================
    # Test Categories
    # =========================================================================

    async def run_system_tests(self) -> None:
        """Run all system-related tests."""
        print("\n=== System Tests ===")
        await self.test_system_status()
        await self.test_ha_status()

    async def run_adom_tests(self) -> None:
        """Run all ADOM-related tests."""
        print("\n=== ADOM Tests ===")
        await self.test_list_adoms()
        await self.test_get_adom_root()

    async def run_device_tests(self) -> None:
        """Run all device-related tests."""
        print("\n=== Device Tests ===")
        await self.test_list_devices()
        await self.test_list_device_groups()

    async def run_task_tests(self) -> None:
        """Run all task-related tests."""
        print("\n=== Task Tests ===")
        await self.test_list_tasks()

    async def run_log_tests(self) -> None:
        """Run all log-related tests."""
        print("\n=== Log Tests ===")
        await self.test_get_logfields()
        await self.test_get_logstats()
        await self.test_logsearch_workflow()

    # =========================================================================
    # Event Management Tests
    # =========================================================================

    async def test_get_alerts(self) -> TestResult:
        """Test: Get alerts."""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)
        time_range = {
            "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return await self.run_test(
            "get_alerts", self.client.get_alerts(adom="root", time_range=time_range, limit=10)
        )

    async def test_get_alerts_count(self) -> TestResult:
        """Test: Get alerts count."""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)
        time_range = {
            "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return await self.run_test(
            "get_alerts_count", self.client.get_alerts_count(adom="root", time_range=time_range)
        )

    async def run_event_tests(self) -> None:
        """Run all event management tests."""
        print("\n=== Event Management Tests ===")
        await self.test_get_alerts()
        await self.test_get_alerts_count()

    # =========================================================================
    # FortiView Tests
    # =========================================================================

    async def test_fortiview_workflow(self) -> TestResult:
        """Test: FortiView workflow (start -> fetch)."""
        result = TestResult("fortiview_workflow")
        start = datetime.now()

        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=24)
            time_range = {
                "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
            }

            print("       Starting FortiView request...")
            fv_result = await self.client.fortiview_run(
                adom="root",
                view_name="top-sources",
                device=[{"devid": "All_FortiGate"}],
                time_range=time_range,
                limit=10,
            )

            tid = fv_result.get("tid")
            if not tid:
                raise ValueError(f"No TID returned: {fv_result}")

            print(f"       Got TID: {tid}")

            await asyncio.sleep(2)

            print("       Fetching results...")
            fetch_result = await self.client.fortiview_fetch(
                adom="root",
                view_name="top-sources",
                tid=tid,
            )

            result.result = {"tid": tid, "fetch_result": fetch_result}
            result.passed = True

        except Exception as e:
            result.error = str(e)
            result.passed = False

        result.duration = (datetime.now() - start).total_seconds()
        self.results.append(result)
        print(result)
        return result

    async def run_fortiview_tests(self) -> None:
        """Run all FortiView tests."""
        print("\n=== FortiView Tests ===")
        await self.test_fortiview_workflow()

    # =========================================================================
    # Report Tests
    # =========================================================================

    async def test_report_list_templates(self) -> TestResult:
        """Test: List report templates."""
        return await self.run_test(
            "report_list_templates", self.client.report_list_templates(adom="root")
        )

    async def test_report_get_state(self) -> TestResult:
        """Test: Get report state."""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=30)
        time_range = {
            "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return await self.run_test(
            "report_get_state", self.client.report_get_state(adom="root", time_range=time_range)
        )

    async def run_report_tests(self) -> None:
        """Run all report tests."""
        print("\n=== Report Tests ===")
        await self.test_report_list_templates()
        await self.test_report_get_state()

    # =========================================================================
    # Incident Management Tests
    # =========================================================================

    async def test_get_incidents(self) -> TestResult:
        """Test: Get incidents."""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=30)
        time_range = {
            "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return await self.run_test(
            "get_incidents", self.client.get_incidents(adom="root", time_range=time_range, limit=10)
        )

    async def test_get_incidents_count(self) -> TestResult:
        """Test: Get incidents count."""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=30)
        time_range = {
            "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return await self.run_test(
            "get_incidents_count",
            self.client.get_incidents_count(adom="root", time_range=time_range),
        )

    async def run_incident_tests(self) -> None:
        """Run all incident management tests."""
        print("\n=== Incident Management Tests ===")
        await self.test_get_incidents()
        await self.test_get_incidents_count()

    # =========================================================================
    # IOC Tests
    # =========================================================================

    async def test_ioc_license_state(self) -> TestResult:
        """Test: Get IOC license state."""
        return await self.run_test("ioc_license_state", self.client.get_ioc_license_state())

    async def run_ioc_tests(self) -> None:
        """Run all IOC tests."""
        print("\n=== IOC Tests ===")
        await self.test_ioc_license_state()

    async def run_all_tests(self) -> None:
        """Run all test categories."""
        await self.run_system_tests()
        await self.run_adom_tests()
        await self.run_device_tests()
        await self.run_task_tests()
        await self.run_log_tests()
        await self.run_event_tests()
        await self.run_fortiview_tests()
        await self.run_report_tests()
        await self.run_incident_tests()
        await self.run_ioc_tests()

    def print_summary(self) -> None:
        """Print test summary."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        print("\n" + "=" * 60)
        print(f"TEST SUMMARY: {self.config.name} ({self.config.version})")
        print("=" * 60)
        print(f"Total:  {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")

        if failed > 0:
            print("\nFailed tests:")
            for r in self.results:
                if not r.passed:
                    print(f"  - {r.name}: {r.error}")

        print("=" * 60)


async def check_connectivity() -> None:
    """Check connectivity to all FAZ environments."""
    print("\n=== FortiAnalyzer Connectivity Check ===\n")

    for _env, config in FAZ_ENVIRONMENTS.items():
        status = "AVAILABLE" if config.is_available else "NOT AVAILABLE"
        creds = "configured" if config.has_credentials else "NOT CONFIGURED"

        print(f"{config.name}:")
        print(f"  Host:        {config.host}")
        print(f"  Version:     {config.version}")
        print(f"  Status:      {status}")
        print(f"  Credentials: {creds}")
        print(f"  Description: {config.description}")

        if config.is_available and config.has_credentials:
            try:
                client = FortiAnalyzerClient(
                    host=config.host,
                    api_token=config.api_token,
                    username=config.username,
                    password=config.password,
                    verify_ssl=config.verify_ssl,
                    timeout=10,
                )
                await client.connect()
                status = await client.get_system_status()
                await client.disconnect()
                print("  Connection:  OK")
                print(f"  FAZ Version: {status.get('Version', 'unknown')}")
            except Exception as e:
                print(f"  Connection:  FAILED - {e}")

        print()


async def main():
    parser = argparse.ArgumentParser(
        description="FortiAnalyzer MCP Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_tests.py                    # Run all tests on default FAZ (7.6.4)
    python run_tests.py --env prod-ai      # Run on FAZ 8.0.0 Beta
    python run_tests.py --test system      # Run only system tests
    python run_tests.py --test log         # Run only log tests
    python run_tests.py --status           # Check FAZ connectivity
    python run_tests.py --list             # List available tests
        """,
    )

    parser.add_argument(
        "--env",
        choices=["prod-764", "prod-ai", "prod-748"],
        default="prod-764",
        help="FAZ environment to test against (default: prod-764)",
    )

    parser.add_argument(
        "--test",
        choices=[
            "all",
            "system",
            "adom",
            "device",
            "task",
            "log",
            "event",
            "fortiview",
            "report",
            "incident",
            "ioc",
        ],
        default="all",
        help="Test category to run (default: all)",
    )

    parser.add_argument(
        "--status",
        action="store_true",
        help="Check connectivity to all FAZ environments",
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List available test categories",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )

    args = parser.parse_args()

    # Handle --status
    if args.status:
        await check_connectivity()
        return

    # Handle --list
    if args.list:
        print("\nAvailable test categories:")
        print("  system    - System status, HA status")
        print("  adom      - List ADOMs, get ADOM details")
        print("  device    - List devices, device groups")
        print("  task      - List tasks")
        print("  log       - Log fields, stats, search workflow")
        print("  event     - Alerts, alert counts")
        print("  fortiview - FortiView workflow (top-sources)")
        print("  report    - Report templates, report state")
        print("  incident  - Incidents, incident counts")
        print("  ioc       - IOC license state")
        print("  all       - Run all tests")
        print("\nAvailable environments:")
        for env, cfg in FAZ_ENVIRONMENTS.items():
            status = "" if cfg.is_available else " (not available)"
            print(f"  {env.value.replace('faz-', '')}: {cfg.host} - v{cfg.version}{status}")
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
        print("Set environment variables:")
        print("  FAZ_PROD_764_API_TOKEN or FAZ_PROD_764_PASSWORD")
        sys.exit(1)

    # Run tests
    runner = FAZTestRunner(config)

    if not await runner.connect():
        sys.exit(1)

    try:
        if args.test == "all":
            await runner.run_all_tests()
        elif args.test == "system":
            await runner.run_system_tests()
        elif args.test == "adom":
            await runner.run_adom_tests()
        elif args.test == "device":
            await runner.run_device_tests()
        elif args.test == "task":
            await runner.run_task_tests()
        elif args.test == "log":
            await runner.run_log_tests()
        elif args.test == "event":
            await runner.run_event_tests()
        elif args.test == "fortiview":
            await runner.run_fortiview_tests()
        elif args.test == "report":
            await runner.run_report_tests()
        elif args.test == "incident":
            await runner.run_incident_tests()
        elif args.test == "ioc":
            await runner.run_ioc_tests()
    finally:
        await runner.disconnect()

    # Output results
    if args.json:
        results = [
            {
                "name": r.name,
                "passed": r.passed,
                "error": r.error,
                "duration": r.duration,
            }
            for r in runner.results
        ]
        print(json.dumps(results, indent=2))
    else:
        runner.print_summary()

    # Exit with error code if any tests failed
    if any(not r.passed for r in runner.results):
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
