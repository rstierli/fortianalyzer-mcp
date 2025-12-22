#!/usr/bin/env python3
"""
FortiAnalyzer API Version Comparison Tool

Compares two versions of FortiAnalyzer API documentation (JSON files)
and generates a markdown report of changes.

Usage:
    python tools/compare_api_versions.py docs/fndn/7.6.4 docs/fndn/7.6.5
    python tools/compare_api_versions.py docs/fndn/7.6.4 docs/fndn/7.6.5 -o CHANGES.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class ModuleChanges:
    """Tracks changes for a single API module."""

    name: str
    old_version: str = ""
    new_version: str = ""
    old_size: int = 0
    new_size: int = 0
    added_endpoints: list[str] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)
    added_definitions: list[str] = field(default_factory=list)
    removed_definitions: list[str] = field(default_factory=list)
    added_tags: list[str] = field(default_factory=list)
    removed_tags: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added_endpoints
            or self.removed_endpoints
            or self.added_definitions
            or self.removed_definitions
            or self.added_tags
            or self.removed_tags
        )

    @property
    def size_diff(self) -> int:
        return self.new_size - self.old_size

    @property
    def size_diff_str(self) -> str:
        diff = self.size_diff
        if diff > 0:
            return f"+{diff:,} bytes"
        elif diff < 0:
            return f"{diff:,} bytes"
        return "unchanged"


@dataclass
class ComparisonResult:
    """Overall comparison results."""

    old_version: str
    new_version: str
    old_dir: Path
    new_dir: Path
    modules: list[ModuleChanges] = field(default_factory=list)
    only_in_old: list[str] = field(default_factory=list)
    only_in_new: list[str] = field(default_factory=list)

    @property
    def total_added_endpoints(self) -> int:
        return sum(len(m.added_endpoints) for m in self.modules)

    @property
    def total_removed_endpoints(self) -> int:
        return sum(len(m.removed_endpoints) for m in self.modules)

    @property
    def changed_modules(self) -> list[ModuleChanges]:
        return [m for m in self.modules if m.has_changes]

    @property
    def unchanged_modules(self) -> list[ModuleChanges]:
        return [m for m in self.modules if not m.has_changes]


def extract_version_from_filename(filename: str) -> str:
    """Extract version number from filename like 'FortiAnalyzer 7.6.4 ...'"""
    match = re.search(r"FortiAnalyzer\s+(\d+\.\d+\.\d+)", filename)
    return match.group(1) if match else "unknown"


def extract_module_name(filename: str) -> str:
    """Extract module name from filename."""
    # Remove version prefix and .json suffix
    name = re.sub(r"FortiAnalyzer\s+\d+\.\d+\.\d+\s+", "", filename)
    name = re.sub(r"\.json$", "", name)
    return name


def find_matching_file(target_module: str, files: list[Path]) -> Path | None:
    """Find a file matching the module name in a list of files."""
    for f in files:
        if extract_module_name(f.name) == target_module:
            return f
    return None


def load_json_file(filepath: Path) -> dict:
    """Load and parse a JSON file."""
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def get_endpoints(data: dict) -> set[str]:
    """Extract all endpoint paths from the API spec."""
    paths = data.get("paths", {})
    return set(paths.keys())


def get_definitions(data: dict) -> set[str]:
    """Extract all definition names from the API spec."""
    definitions = data.get("definitions", {})
    return set(definitions.keys())


def get_tags(data: dict) -> set[str]:
    """Extract all tag names from the API spec."""
    tags = data.get("tags", [])
    return {tag.get("name", "") for tag in tags if tag.get("name")}


def compare_module(old_file: Path, new_file: Path) -> ModuleChanges:
    """Compare two versions of an API module."""
    module_name = extract_module_name(old_file.name)

    old_data = load_json_file(old_file)
    new_data = load_json_file(new_file)

    old_endpoints = get_endpoints(old_data)
    new_endpoints = get_endpoints(new_data)

    old_definitions = get_definitions(old_data)
    new_definitions = get_definitions(new_data)

    old_tags = get_tags(old_data)
    new_tags = get_tags(new_data)

    return ModuleChanges(
        name=module_name,
        old_version=old_data.get("info", {}).get("version", "unknown"),
        new_version=new_data.get("info", {}).get("version", "unknown"),
        old_size=old_file.stat().st_size,
        new_size=new_file.stat().st_size,
        added_endpoints=sorted(new_endpoints - old_endpoints),
        removed_endpoints=sorted(old_endpoints - new_endpoints),
        added_definitions=sorted(new_definitions - old_definitions),
        removed_definitions=sorted(old_definitions - new_definitions),
        added_tags=sorted(new_tags - old_tags),
        removed_tags=sorted(old_tags - new_tags),
    )


def compare_directories(old_dir: Path, new_dir: Path) -> ComparisonResult:
    """Compare all API modules between two version directories."""
    old_files = list(old_dir.glob("*.json"))
    new_files = list(new_dir.glob("*.json"))

    # Extract version from first file
    old_version = extract_version_from_filename(old_files[0].name) if old_files else "unknown"
    new_version = extract_version_from_filename(new_files[0].name) if new_files else "unknown"

    # Map module names to files
    old_modules = {extract_module_name(f.name): f for f in old_files}
    new_modules = {extract_module_name(f.name): f for f in new_files}

    result = ComparisonResult(
        old_version=old_version,
        new_version=new_version,
        old_dir=old_dir,
        new_dir=new_dir,
    )

    # Find modules only in one version
    result.only_in_old = sorted(set(old_modules.keys()) - set(new_modules.keys()))
    result.only_in_new = sorted(set(new_modules.keys()) - set(old_modules.keys()))

    # Compare common modules
    common_modules = sorted(set(old_modules.keys()) & set(new_modules.keys()))
    for module_name in common_modules:
        changes = compare_module(old_modules[module_name], new_modules[module_name])
        result.modules.append(changes)

    return result


def format_endpoint_list(endpoints: list[str], prefix: str = "") -> str:
    """Format a list of endpoints for markdown output."""
    if not endpoints:
        return ""
    lines = [f"{prefix}- `{ep}`" for ep in endpoints]
    return "\n".join(lines)


def generate_markdown_report(result: ComparisonResult) -> str:
    """Generate a markdown report from comparison results."""
    lines = []

    # Header
    lines.append(f"# FortiAnalyzer API Changes: {result.old_version} → {result.new_version}")
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Old Version | {result.old_version} |")
    lines.append(f"| New Version | {result.new_version} |")
    lines.append(f"| Total Modules | {len(result.modules)} |")
    lines.append(f"| Changed Modules | {len(result.changed_modules)} |")
    lines.append(f"| Unchanged Modules | {len(result.unchanged_modules)} |")
    lines.append(f"| New Endpoints | +{result.total_added_endpoints} |")
    lines.append(f"| Removed Endpoints | -{result.total_removed_endpoints} |")
    lines.append("")

    # New/removed modules
    if result.only_in_new:
        lines.append("### New Modules")
        lines.append("")
        for m in result.only_in_new:
            lines.append(f"- {m}")
        lines.append("")

    if result.only_in_old:
        lines.append("### Removed Modules")
        lines.append("")
        for m in result.only_in_old:
            lines.append(f"- {m}")
        lines.append("")

    # Detailed changes per module
    if result.changed_modules:
        lines.append("---")
        lines.append("")
        lines.append("## Detailed Changes")
        lines.append("")

        for module in result.changed_modules:
            lines.append(f"### {module.name}")
            lines.append("")
            lines.append(f"**File size**: {module.old_size:,} → {module.new_size:,} bytes ({module.size_diff_str})")
            lines.append("")

            if module.added_endpoints:
                lines.append(f"**New Endpoints ({len(module.added_endpoints)}):**")
                lines.append("")
                lines.append("```")
                for ep in module.added_endpoints:
                    lines.append(ep)
                lines.append("```")
                lines.append("")

            if module.removed_endpoints:
                lines.append(f"**Removed Endpoints ({len(module.removed_endpoints)}):**")
                lines.append("")
                lines.append("```")
                for ep in module.removed_endpoints:
                    lines.append(ep)
                lines.append("```")
                lines.append("")

            if module.added_definitions:
                lines.append(f"**New Definitions ({len(module.added_definitions)}):**")
                lines.append("")
                for d in module.added_definitions:
                    lines.append(f"- `{d}`")
                lines.append("")

            if module.removed_definitions:
                lines.append(f"**Removed Definitions ({len(module.removed_definitions)}):**")
                lines.append("")
                for d in module.removed_definitions:
                    lines.append(f"- `{d}`")
                lines.append("")

            if module.added_tags:
                lines.append(f"**New Tags ({len(module.added_tags)}):**")
                lines.append("")
                for t in module.added_tags:
                    lines.append(f"- `{t}`")
                lines.append("")

            if module.removed_tags:
                lines.append(f"**Removed Tags ({len(module.removed_tags)}):**")
                lines.append("")
                for t in module.removed_tags:
                    lines.append(f"- `{t}`")
                lines.append("")

            lines.append("---")
            lines.append("")

    # Unchanged modules
    if result.unchanged_modules:
        lines.append("## Unchanged Modules")
        lines.append("")
        lines.append("The following modules have no API changes:")
        lines.append("")
        lines.append("| Module | File Size |")
        lines.append("|--------|-----------|")
        for module in result.unchanged_modules:
            size_note = f"{module.new_size:,} bytes"
            if module.size_diff != 0:
                size_note += f" ({module.size_diff_str})"
            lines.append(f"| {module.name} | {size_note} |")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Compare FortiAnalyzer API versions and generate a change report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python tools/compare_api_versions.py docs/fndn/7.6.4 docs/fndn/7.6.5
    python tools/compare_api_versions.py docs/fndn/7.6.4 docs/fndn/7.6.5 -o CHANGES.md
    python tools/compare_api_versions.py docs/fndn/7.6.4 docs/fndn/7.6.5 --stdout
        """,
    )
    parser.add_argument("old_dir", type=Path, help="Directory containing old version JSON files")
    parser.add_argument("new_dir", type=Path, help="Directory containing new version JSON files")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file path (default: API_CHANGES_<old>_to_<new>.md)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print report to stdout instead of file",
    )

    args = parser.parse_args()

    # Validate directories
    if not args.old_dir.is_dir():
        print(f"Error: {args.old_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    if not args.new_dir.is_dir():
        print(f"Error: {args.new_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    # Run comparison
    print(f"Comparing {args.old_dir} vs {args.new_dir}...")
    result = compare_directories(args.old_dir, args.new_dir)

    # Generate report
    report = generate_markdown_report(result)

    if args.stdout:
        print(report)
    else:
        # Determine output path
        if args.output:
            output_path = args.output
        else:
            output_path = Path(f"API_CHANGES_{result.old_version}_to_{result.new_version}.md")

        output_path.write_text(report, encoding="utf-8")
        print(f"Report written to: {output_path}")

    # Print summary
    print(f"\nSummary: {len(result.changed_modules)} modules changed, "
          f"+{result.total_added_endpoints} endpoints added, "
          f"-{result.total_removed_endpoints} endpoints removed")


if __name__ == "__main__":
    main()
