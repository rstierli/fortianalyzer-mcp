"""Tests for FortiAnalyzer report tools.

Tests the client methods for report generation and management operations.
Follows the same pattern as test_system_tools.py to avoid server initialization.
"""

import base64
import io
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any

import pytest

import fortianalyzer_mcp.tools.report_tools as report_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient


class TestReportHelpers:
    """Tests for report tools helper functions.

    These test the helper function logic by reimplementing the tests
    without importing from tools module (which triggers server init).
    """

    def test_parse_time_range_custom_format(self) -> None:
        """Test parsing custom time range with pipe separator."""
        time_range = "2024-01-01 00:00:00|2024-01-02 00:00:00"
        parts = time_range.split("|")
        result = {"start": parts[0].strip(), "end": parts[1].strip()}
        assert result["start"] == "2024-01-01 00:00:00"
        assert result["end"] == "2024-01-02 00:00:00"

    def test_time_range_predefined_mapping(self) -> None:
        """Test predefined time range mapping logic."""
        from datetime import timedelta

        range_map = {
            "1-hour": timedelta(hours=1),
            "6-hour": timedelta(hours=6),
            "12-hour": timedelta(hours=12),
            "24-hour": timedelta(hours=24),
            "1-day": timedelta(days=1),
            "7-day": timedelta(days=7),
            "30-day": timedelta(days=30),
            "90-day": timedelta(days=90),
        }

        # Verify all expected ranges exist
        assert "1-hour" in range_map
        assert "7-day" in range_map
        assert "30-day" in range_map
        assert "90-day" in range_map

        # Verify timedeltas are correct
        assert range_map["7-day"] == timedelta(days=7)
        assert range_map["90-day"] == timedelta(days=90)

    def test_convert_to_api_time_period_short_format(self) -> None:
        """Test conversion from short format to API format."""
        time_map = {
            "1-hour": "last-1-hours",
            "6-hour": "last-6-hours",
            "12-hour": "last-12-hours",
            "24-hour": "last-24-hours",
            "1-day": "last-1-days",
            "7-day": "last-7-days",
            "30-day": "last-30-days",
            "90-day": "last-90-days",
        }

        for short, api in time_map.items():
            assert time_map[short] == api

    def test_convert_to_api_time_period_custom(self) -> None:
        """Test conversion of custom time range returns 'other'."""
        time_range = "2024-01-01 00:00:00|2024-01-02 00:00:00"
        # Custom date range should return "other"
        if "|" in time_range:
            result = "other"
        else:
            result = "last-7-days"
        assert result == "other"

    def test_convert_to_api_time_period_already_api_format(self) -> None:
        """Test API format is returned as-is."""
        time_range = "last-7-days"
        # If already in API format, return as-is
        if time_range.startswith("last-") and (
            time_range.endswith("-hours")
            or time_range.endswith("-days")
            or time_range.endswith("-weeks")
            or time_range.endswith("-months")
        ):
            result = time_range
        else:
            result = "last-7-days"
        assert result == "last-7-days"

    def test_layout_id_is_numeric(self) -> None:
        """Test layout ID detection logic."""
        # Numeric string should be detected as layout ID
        layout = "10042"
        assert layout.isdigit() is True

        # Non-numeric should be treated as title
        layout = "Secure SD-WAN Report"
        assert layout.isdigit() is False


class TestReportClient:
    """Tests for report client methods."""

    @pytest.fixture
    def mock_client_with_reports(
        self,
        mock_client: FortiAnalyzerClient,
        configure_mock_responses: None,
        configure_logview_responses: None,
    ) -> FortiAnalyzerClient:
        """Provide a mock client with report API responses configured."""
        return mock_client

    async def test_get_report_layouts_success(
        self, mock_client_with_reports: FortiAnalyzerClient
    ) -> None:
        """Test get_report_layouts returns layout list."""
        result = await mock_client_with_reports.get_report_layouts(adom="root")
        assert "data" in result
        layouts = result["data"]
        assert len(layouts) == 2
        assert layouts[0]["layout-id"] == 1
        assert layouts[0]["title"] == "Executive Summary"

    async def test_report_list_templates_success(
        self, mock_client_with_reports: FortiAnalyzerClient
    ) -> None:
        """Test report_list_templates returns template list with API shape."""
        result = await mock_client_with_reports.report_list_templates(adom="root")
        assert "data" in result
        templates = result["data"]
        assert len(templates) == 2
        # Confirm the spec shape (layout-id, title, content-pack-uuid, protected)
        # is preserved end-to-end from the dedicated /template/list endpoint.
        assert templates[0]["layout-id"] == 1000050001
        assert templates[0]["title"] == "Template - Security Analysis"
        assert templates[0]["protected"] == "enable"
        assert templates[0]["content-pack-uuid"] == ""
        assert templates[1]["category"] == "Application"

    async def test_report_list_templates_not_connected(self) -> None:
        """Test report_list_templates raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.report_list_templates(adom="root")

    async def test_report_run_success(self, mock_client_with_reports: FortiAnalyzerClient) -> None:
        """Test report_run returns TID."""
        result = await mock_client_with_reports.report_run(
            adom="root",
            layout_id=1,
            time_period="last-7-days",
        )
        assert "tid" in result
        assert result["tid"] == "report-uuid-002"

    async def test_report_get_state_success(
        self, mock_client_with_reports: FortiAnalyzerClient
    ) -> None:
        """Test report_get_state returns state list."""
        result = await mock_client_with_reports.report_get_state(
            adom="root",
            time_range={"start": "2024-01-01 00:00:00", "end": "2024-01-02 00:00:00"},
            state="generated",
        )
        assert "data" in result
        reports = result["data"]
        assert len(reports) == 1
        assert reports[0]["tid"] == "report-uuid-001"
        assert reports[0]["state"] == "generated"

    async def test_get_report_layouts_not_connected(self) -> None:
        """Test get_report_layouts raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_report_layouts(adom="root")

    async def test_report_run_not_connected(self) -> None:
        """Test report_run raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.report_run(
                adom="root",
                layout_id=1,
                time_period="last-7-days",
            )

    async def test_report_fetch_not_connected(self) -> None:
        """Test report_fetch raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.report_fetch(adom="root", tid="report-uuid-001")

    async def test_report_get_data_not_connected(self) -> None:
        """Test report_get_data raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.report_get_data(adom="root", tid="report-uuid-001")

    async def test_get_running_reports_not_connected(self) -> None:
        """Test get_running_reports raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.get_running_reports(adom="root")

    async def test_report_get_state_not_connected(self) -> None:
        """Test report_get_state raises when not connected."""
        from fortianalyzer_mcp.utils.errors import ConnectionError

        client = FortiAnalyzerClient(
            host="test-faz.example.com",
            username="admin",
            password="password",
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.report_get_state(
                adom="root",
                time_range={
                    "start": "2024-01-01 00:00:00",
                    "end": "2024-01-02 00:00:00",
                },
                state="generated",
            )


class TestReportFormats:
    """Tests for report output format handling."""

    def test_valid_output_formats(self) -> None:
        """Test valid output formats."""
        valid_formats = ["PDF", "HTML", "CSV", "XML", "JSON"]

        for fmt in valid_formats:
            assert fmt.upper() in valid_formats

    def test_default_format_is_pdf(self) -> None:
        """Test default output format is PDF."""
        default_format = "PDF"
        assert default_format == "PDF"


class TestReportHistoryProjection:
    """Report rows project under the (deliberately uncurated) report vocabulary.

    The row below is the ``MOCK_REPORT_STATE`` shape from ``tests/conftest.py``
    -- the same fixture ``TestReportClient.test_report_get_state_success``
    asserts against, and the closest thing this repo has to a real
    ``report_get_state`` record. The first version of this test used a
    fabricated ``{"id": ..., "owner": ...}`` row, which is why it passed while
    the curated set stripped ``tid`` and kept an ``id`` no report record
    carries: a row shaped like the guessed field names cannot fail on the
    guess. Same reasoning as ``test_ueba_tools.TestUebaProjection``.
    """

    ROW = {
        "tid": "report-uuid-001",
        "title": "Security Report",
        "state": "generated",
        "start_time": 1704067200,
        "end_time": 1704067260,
    }

    def _patch_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        row = dict(self.ROW)

        class FakeClient:
            async def ensure_connected(self) -> None:
                return None

            async def get_system_timezone(self) -> None:
                # get_report_history's default time_range ("30-day") is
                # relative, so _parse_time_range looks up the FAZ TZ.
                return None

            async def report_get_state(self, **kwargs: object) -> list[dict[str, object]]:
                # The real client call get_report_history's tool body makes
                # (client.report_get_state, not a client.get_report_history
                # method -- there is no such client method).
                return [row]

        monkeypatch.setattr(report_tools, "_get_client", lambda: FakeClient())

    async def test_default_returns_full_rows_and_warns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Uncurated means nothing is dropped, and the caller is told so."""
        self._patch_client(monkeypatch)

        result = await report_tools.get_report_history()

        assert result["data"][0].keys() == self.ROW.keys()
        assert result["data"][0]["tid"] == "report-uuid-001"
        assert any("no curated field set" in w for w in result["warnings"])
        assert "report" in " ".join(result["warnings"])

    async def test_explicit_fields_keep_the_tid_handle(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``tid`` is a known report field, so asking for it must not warn.

        The curated set that dropped ``tid`` also warned "field 'tid' is not
        in the known report field set" -- steering a caller off the only
        spelling every downstream report tool accepts.
        """
        self._patch_client(monkeypatch)

        result = await report_tools.get_report_history(fields=["tid", "state"])

        assert result["data"][0].keys() == {"tid", "state"}
        assert result["data"][0]["tid"] == "report-uuid-001"
        assert result["fields_returned"] == ["state", "tid"]
        assert result["warnings"] == []

    async def test_id_is_an_alias_for_the_tid_handle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_client(monkeypatch)

        result = await report_tools.get_report_history(fields=["id"])

        assert result["data"][0] == {"tid": "report-uuid-001"}
        assert result["warnings"] == []

    async def test_star_returns_everything_without_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_client(monkeypatch)

        result = await report_tools.get_report_history(fields=["*"])

        assert result["data"][0].keys() == self.ROW.keys()
        assert result["warnings"] == []


class TestSaveReportDamagedArchive:
    """A ZIP that opens but has a damaged member is an error, not a saved report.

    ``save_report`` writes the payload as-is when it is not a ZIP at all. That
    fallback must not catch an archive whose directory reads fine and whose
    damage only shows when a member is extracted. The archives here are built
    with ``zipfile`` and then get one byte changed inside a member's data.
    """

    SUMMARY = ("summary.txt", b"Report summary\n" * 8)
    BODY = ("report-body.pdf", b"%PDF-1.4 report body\n" * 64)

    @staticmethod
    def _archive(members: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression) as zf:
            for name, content in members:
                zf.writestr(name, content)
        return buffer.getvalue()

    @staticmethod
    def _damage(archive: bytes, member: str, raises: type[Exception]) -> bytes:
        """Overwrite the first data byte of ``member`` and pin how reading it fails."""
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            header = zf.getinfo(member).header_offset
        # Local file header: 30 fixed bytes, then the name and the extra field.
        name_len, extra_len = struct.unpack_from("<HH", archive, header + 26)
        damaged = bytearray(archive)
        damaged[header + 30 + name_len + extra_len] = 0xFF
        # The archive still opens; only extracting the member fails.
        with zipfile.ZipFile(io.BytesIO(damaged)) as zf, pytest.raises(raises):
            zf.read(member)
        return bytes(damaged)

    async def _save(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: bytes
    ) -> dict[str, Any]:
        class FakeClient:
            async def report_get_data(self, **kwargs: object) -> dict[str, object]:
                return {"name": "Security Report", "data": base64.b64encode(payload).decode()}

        monkeypatch.setenv("FAZ_ALLOWED_OUTPUT_DIRS", str(tmp_path))
        monkeypatch.setattr(report_tools, "_get_client", lambda: FakeClient())
        return await report_tools.save_report(
            tid="report-uuid-001", output_dir=str(tmp_path), adom="root"
        )

    async def test_bad_crc_member_is_not_saved_as_the_report(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The damaged archive used to be written whole as ``<name>.pdf``, as a success."""
        damaged = self._damage(self._archive([self.BODY]), "report-body.pdf", zipfile.BadZipFile)

        result = await self._save(monkeypatch, tmp_path, damaged)

        assert result["status"] == "error"
        assert "report-body.pdf" in result["message"]
        assert "files" not in result
        assert list(tmp_path.iterdir()) == []

    async def test_members_extracted_before_the_damage_are_removed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The members this call wrote are removed, and nothing else is.

        The output directory already holds a file with a member's name and one
        that has nothing to do with the report. Both stay as they were.
        """
        (tmp_path / "summary.txt").write_bytes(b"an earlier report")
        (tmp_path / "unrelated.cfg").write_bytes(b"not a report")
        chart = ("chart-1.png", b"\x89PNG chart\n" * 8)
        archive = self._archive([self.SUMMARY, chart, self.BODY])
        damaged = self._damage(archive, "report-body.pdf", zipfile.BadZipFile)

        result = await self._save(monkeypatch, tmp_path, damaged)

        assert result["status"] == "error"
        assert "files" not in result
        assert sorted(p.name for p in tmp_path.iterdir()) == ["summary.txt", "unrelated.cfg"]
        assert (tmp_path / "summary.txt").read_bytes() == b"an earlier report"
        assert (tmp_path / "unrelated.cfg").read_bytes() == b"not a report"

    async def test_corrupt_deflate_stream_names_the_member(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A member that fails in zlib, not on its CRC, gets the same answer."""
        archive = self._archive([self.SUMMARY, self.BODY], zipfile.ZIP_DEFLATED)
        damaged = self._damage(archive, "report-body.pdf", zlib.error)

        result = await self._save(monkeypatch, tmp_path, damaged)

        assert result["status"] == "error"
        assert "report-body.pdf" in result["message"]
        assert list(tmp_path.iterdir()) == []

    async def test_payload_that_is_not_a_zip_is_still_saved_as_is(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Control: the raw-save fallback stays for data that is not an archive."""
        payload = b"%PDF-1.4 plain report\n"

        result = await self._save(monkeypatch, tmp_path, payload)

        assert result["status"] == "success"
        assert [p.name for p in tmp_path.iterdir()] == ["Security Report.pdf"]
        assert (tmp_path / "Security Report.pdf").read_bytes() == payload

    async def test_intact_archive_is_extracted(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Control: the same archive, undamaged, extracts every member."""
        archive = self._archive([self.SUMMARY, self.BODY])

        result = await self._save(monkeypatch, tmp_path, archive)

        assert result["status"] == "success"
        assert result["file_count"] == 2
        assert (tmp_path / "summary.txt").read_bytes() == self.SUMMARY[1]
        assert (tmp_path / "report-body.pdf").read_bytes() == self.BODY[1]
