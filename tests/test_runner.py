"""
CLI Test Runner
===============
A Rich-powered command-line test runner that displays colored results
for all SQL injection detection scenarios.

Usage:
    python tests/test_runner.py                   # run all tests
    python tests/test_runner.py --unit-only        # skip integration tests
    python tests/test_runner.py --integration-only # skip unit tests
    python tests/test_runner.py --verbose          # show stdout of each test

This script is a wrapper around pytest that adds coloured summary output.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box

console = Console()


def run_tests(args: argparse.Namespace) -> int:
    """Run pytest with the specified filters and return the exit code."""
    cmd = [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"]

    if args.unit_only:
        cmd += ["-m", "not integration"]
        console.print("[cyan]Running UNIT TESTS only (no Docker required)[/cyan]")
    elif args.integration_only:
        cmd += ["-m", "integration"]
        console.print("[cyan]Running INTEGRATION TESTS only (Docker stack required)[/cyan]")
    else:
        console.print("[cyan]Running ALL tests[/cyan]")

    if args.verbose:
        cmd += ["-s"]

    if args.failfast:
        cmd += ["-x"]

    # JSON report for parsing
    cmd += ["--json-report", "--json-report-file=.test_report.json"]

    console.rule("[bold cyan]🧪 SQL Injection Detection Agent — Test Runner[/bold cyan]")
    console.print(f"[dim]Command: {' '.join(cmd)}[/dim]\n")

    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=False)
    elapsed = time.monotonic() - start

    console.print()
    console.rule()

    # Try to parse JSON report for a nice summary table
    try:
        import json
        with open(".test_report.json") as f:
            report = json.load(f)

        _print_summary_table(report, elapsed)
    except Exception:
        # Fall back to simple exit code message
        if result.returncode == 0:
            console.print(f"[bold green]✅  All tests passed in {elapsed:.1f}s[/bold green]")
        else:
            console.print(f"[bold red]❌  Tests failed (exit code {result.returncode})[/bold red]")

    return result.returncode


def _print_summary_table(report: dict, elapsed: float) -> None:
    """Print a Rich table summarizing test results."""
    summary = report.get("summary", {})
    tests   = report.get("tests", [])

    passed  = summary.get("passed",  0)
    failed  = summary.get("failed",  0)
    skipped = summary.get("skipped", 0)
    errors  = summary.get("error",   0)
    total   = summary.get("total",   0)

    # Header panel
    status_color = "green" if failed == 0 and errors == 0 else "red"
    status_icon  = "✅" if failed == 0 and errors == 0 else "❌"
    header = (
        f"{status_icon} [bold {status_color}]{'ALL PASSED' if failed == 0 else 'SOME FAILED'}[/bold {status_color}]\n"
        f"[dim]Total: {total} | Passed: {passed} | Failed: {failed} | "
        f"Skipped: {skipped} | Duration: {elapsed:.1f}s[/dim]"
    )
    console.print(Panel(header, border_style=status_color, padding=(0, 2)))

    # Results table
    table = Table(
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold white on #21262d",
        show_lines=True,
        title="Test Results",
    )
    table.add_column("Status",   width=8,  justify="center")
    table.add_column("Test",     width=70)
    table.add_column("Duration", width=10, justify="right")

    for t in tests:
        outcome  = t.get("outcome", "unknown")
        nodeid   = t.get("nodeid", "")
        duration = t.get("duration", 0.0)

        if outcome == "passed":
            icon  = "[bold green]PASS[/bold green]"
        elif outcome == "failed":
            icon  = "[bold red]FAIL[/bold red]"
        elif outcome == "skipped":
            icon  = "[bold yellow]SKIP[/bold yellow]"
        else:
            icon  = "[dim]???[/dim]"

        # Shorten the node id for display
        short_id = nodeid.split("::")[-1] if "::" in nodeid else nodeid

        table.add_row(icon, short_id, f"{duration:.3f}s")

    console.print(table)

    if failed > 0 or errors > 0:
        console.print(
            f"\n[bold red]⚠  {failed + errors} test(s) failed. "
            "Run with --verbose for detailed output.[/bold red]"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SQL Injection Detection Agent — CLI Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--unit-only",        action="store_true", help="Run only unit tests (no Docker)")
    parser.add_argument("--integration-only", action="store_true", help="Run only integration tests")
    parser.add_argument("--verbose",          action="store_true", help="Show test stdout")
    parser.add_argument("--failfast",         action="store_true", help="Stop on first failure")
    args = parser.parse_args()

    sys.exit(run_tests(args))


if __name__ == "__main__":
    main()
