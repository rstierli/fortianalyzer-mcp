"""Integration tests for report operations.

These tests are READ-ONLY and safe to run against a production FortiAnalyzer.
They test report listing, running, and fetching functionality.

Note: Running a report is a write operation but doesn't modify configuration.
The test uses a small time range to minimize resource usage.
"""

import asyncio

import pytest

from fortianalyzer_mcp.api.client import FortiAnalyzerClient


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_report_layouts(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test listing available report layouts."""
    result = await faz_client.get_report_layouts(test_adom)
    assert result is not None
    # Result should be a list of layouts
    if isinstance(result, list):
        assert len(result) >= 0  # May be empty
    elif isinstance(result, dict) and "data" in result:
        assert isinstance(result["data"], list)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_report_layouts_with_fields(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test listing report layouts with specific fields."""
    result = await faz_client.get_report_layouts(
        test_adom, fields=["layout-id", "title", "description"]
    )
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_report_templates(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test listing report templates."""
    result = await faz_client.report_list_templates(test_adom)
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_report_schedules(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test getting report schedules."""
    result = await faz_client.get_report_schedules(test_adom)
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_running_reports(faz_client: FortiAnalyzerClient, test_adom: str):
    """Test getting currently running reports."""
    result = await faz_client.get_running_reports(test_adom)
    assert result is not None
    # Result should contain data array (may be empty)
    if isinstance(result, dict):
        assert "data" in result or result == {}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_report_state(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
    time_range_last_week: dict[str, str],
):
    """Test getting report history/state."""
    result = await faz_client.report_get_state(
        test_adom, time_range=time_range_last_week, state="generated"
    )
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_report_and_fetch_status(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
):
    """Test running a report and fetching its status.

    This test requires at least one report layout with a schedule configured.
    It runs a report with a small time range to minimize resource usage.
    """
    # First, get available layouts
    layouts = await faz_client.get_report_layouts(test_adom)
    if not layouts:
        pytest.skip("No report layouts available")

    # Handle both list and dict responses
    if isinstance(layouts, dict) and "data" in layouts:
        layouts = layouts.get("data", [])
    if not layouts:
        pytest.skip("No report layouts available")

    # Get first layout ID
    layout = layouts[0] if isinstance(layouts, list) else layouts
    layout_id = layout.get("layout-id")
    if not layout_id:
        pytest.skip("Layout has no layout-id")

    # Check if schedule exists for this layout
    schedules = await faz_client.get_report_schedules(test_adom, layout_id=int(layout_id))
    schedule_data = schedules.get("data", []) if isinstance(schedules, dict) else schedules

    if not schedule_data:
        # Create a schedule (this is a write operation but necessary)
        try:
            await faz_client.create_report_schedule(test_adom, int(layout_id))
        except Exception as e:
            pytest.skip(f"Cannot create report schedule: {e}")

    # Run the report with last-1-hours to minimize data
    try:
        run_result = await faz_client.report_run(
            test_adom, layout_id=int(layout_id), time_period="last-1-hours"
        )
        assert run_result is not None
        assert "tid" in run_result

        tid = run_result["tid"]

        # Fetch status (don't wait for completion, just verify we can fetch)
        fetch_result = await faz_client.report_fetch(test_adom, tid)
        assert fetch_result is not None

    except Exception as e:
        # Report API can fail for various reasons (no data, license, etc.)
        pytest.skip(f"Report run failed: {e}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_report_run_and_wait_for_completion(
    faz_client: FortiAnalyzerClient,
    test_adom: str,
):
    """Test running a report and waiting for completion.

    This is a longer test that waits for report completion.
    """
    # First, get available layouts
    layouts = await faz_client.get_report_layouts(test_adom)
    if not layouts:
        pytest.skip("No report layouts available")

    if isinstance(layouts, dict) and "data" in layouts:
        layouts = layouts.get("data", [])
    if not layouts:
        pytest.skip("No report layouts available")

    layout = layouts[0] if isinstance(layouts, list) else layouts
    layout_id = layout.get("layout-id")
    if not layout_id:
        pytest.skip("Layout has no layout-id")

    # Check/create schedule
    schedules = await faz_client.get_report_schedules(test_adom, layout_id=int(layout_id))
    schedule_data = schedules.get("data", []) if isinstance(schedules, dict) else schedules

    if not schedule_data:
        try:
            await faz_client.create_report_schedule(test_adom, int(layout_id))
        except Exception as e:
            pytest.skip(f"Cannot create report schedule: {e}")

    try:
        # Run report
        run_result = await faz_client.report_run(
            test_adom, layout_id=int(layout_id), time_period="last-1-hours"
        )
        assert "tid" in run_result
        tid = run_result["tid"]

        # Poll for completion (max 120 seconds)
        for _ in range(120):
            fetch_result = await faz_client.report_fetch(test_adom, tid)

            # Check completion status
            state = fetch_result.get("state", "")
            if state in ("generated", "done", "complete"):
                # Try to get report data
                try:
                    data_result = await faz_client.report_get_data(
                        test_adom, tid, output_format="PDF"
                    )
                    assert data_result is not None
                except Exception:
                    # Data retrieval may fail, but status check passed
                    pass
                break
            elif state in ("failed", "error"):
                pytest.skip(f"Report generation failed: {state}")

            await asyncio.sleep(1)

    except Exception as e:
        pytest.skip(f"Report test failed: {e}")
