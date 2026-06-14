"""
HTML + JSON Vulnerability Report Generator
==========================================
Produces two report artefacts after each agent scan:
  1. A machine-readable JSON report (<scan_id>.json)
  2. A rich terminal table (printed via Rich)
  3. A styled HTML report (<scan_id>.html) for sharing

Usage (standalone):
    reporter = Reporter(output_dir="./reports")
    reporter.finalize(scan_result)     # writes JSON + HTML
    reporter.print_terminal_table()    # prints Rich table

⚠️  FOR AUTHORIZED SECURITY TESTING ONLY.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Severity colour mapping (Rich markup)
# ──────────────────────────────────────────────
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
    "INFO":     "bold cyan",
    "NONE":     "dim",
}

HTML_SEVERITY_CLASSES: dict[str, str] = {
    "CRITICAL": "#ff3333",
    "HIGH":     "#ff7700",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#33cc33",
    "INFO":     "#3399ff",
}

# ──────────────────────────────────────────────
# HTML template
# ──────────────────────────────────────────────
HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>SQL Injection Scan Report — {scan_id}</title>
  <style>
    :root {{
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #c9d1d9; --accent: #58a6ff;
      --critical: #ff3333; --high: #ff7700;
      --medium: #e3b341; --low: #3fb950; --info: #58a6ff;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
    h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: .25rem; }}
    .subtitle {{ color: #8b949e; margin-bottom: 2rem; font-size: .9rem; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }}
    .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.5rem; text-align: center; }}
    .stat-card .label {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; color: #8b949e; }}
    .stat-card .value {{ font-size: 2rem; font-weight: 700; margin-top: .25rem; }}
    .stat-card.critical .value {{ color: var(--critical); }}
    .stat-card.high    .value {{ color: var(--high); }}
    .stat-card.medium  .value {{ color: var(--medium); }}
    .stat-card.low     .value {{ color: var(--low); }}
    .stat-card.total   .value {{ color: var(--accent); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }}
    th {{ background: #21262d; padding: .75rem 1rem; text-align: left; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; color: #8b949e; }}
    td {{ padding: .75rem 1rem; border-top: 1px solid var(--border); font-size: .875rem; vertical-align: top; }}
    tr:hover td {{ background: #21262d; }}
    .badge {{ display: inline-block; padding: .2rem .6rem; border-radius: 4px; font-size: .75rem; font-weight: 700; color: #fff; }}
    .badge.CRITICAL {{ background: var(--critical); }}
    .badge.HIGH     {{ background: var(--high); }}
    .badge.MEDIUM   {{ background: var(--medium); color: #000; }}
    .badge.LOW      {{ background: var(--low); color: #000; }}
    code {{ background: #21262d; padding: .1rem .4rem; border-radius: 3px; font-family: monospace; font-size: .8rem; word-break: break-all; }}
    .remediation {{ color: #8b949e; font-size: .8rem; max-width: 300px; }}
    footer {{ margin-top: 3rem; text-align: center; color: #484f58; font-size: .8rem; }}
    .disclaimer {{ margin-top: 2.5rem; background: #2d1b1b; border: 1px solid #ff3333; border-radius: 6px; padding: 1rem 1.5rem; color: #ff9999; font-size: .85rem; }}
  </style>
</head>
<body>
  <h1>🔍 SQL Injection Scan Report</h1>
  <div class="subtitle">Scan ID: {scan_id} &nbsp;|&nbsp; Target: {target} &nbsp;|&nbsp; {timestamp}</div>

  <div class="summary-grid">
    <div class="stat-card total">  <div class="label">Total Findings</div><div class="value">{total}</div></div>
    <div class="stat-card critical"><div class="label">Critical</div>      <div class="value">{critical}</div></div>
    <div class="stat-card high">   <div class="label">High</div>           <div class="value">{high}</div></div>
    <div class="stat-card medium"> <div class="label">Medium</div>         <div class="value">{medium}</div></div>
    <div class="stat-card low">    <div class="label">Low</div>            <div class="value">{low}</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Endpoint</th><th>Parameter</th>
        <th>Payload Type</th><th>Payload</th><th>Evidence</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <div class="disclaimer">
    ⚠️ <strong>SECURITY DISCLAIMER</strong>:
    This report was generated by an automated SQL injection detection agent for
    <em>authorized security testing purposes only</em>. Unauthorized testing is
    illegal. The target API is intentionally vulnerable — findings are expected
    and are used solely for educational research.
  </div>

  <footer>Generated by SQL Injection Detection Agent · {timestamp}</footer>
</body>
</html>
"""


class Reporter:
    """Generates JSON and HTML vulnerability reports from agent scan results."""

    def __init__(self, output_dir: str = "./reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.console = Console()
        self._scan_id: str = ""
        self._report: dict[str, Any] = {}

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def build_report(
        self,
        target: str,
        vulnerabilities: list[dict[str, Any]],
        scan_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Construct the full report dict from raw vulnerability findings.

        Args:
            target:          Base URL of the scanned API.
            vulnerabilities: List of finding dicts (from generate_report tool).
            scan_metadata:   Optional extra fields (e.g. scan_duration_seconds).

        Returns:
            The full report dict (also stored as self._report).
        """
        self._scan_id = str(uuid.uuid4())[:8].upper()
        counts = self._count_severities(vulnerabilities)

        self._report = {
            "scan_id":    self._scan_id,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "target":     target,
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total":    len(vulnerabilities),
                "critical": counts.get("CRITICAL", 0),
                "high":     counts.get("HIGH", 0),
                "medium":   counts.get("MEDIUM", 0),
                "low":      counts.get("LOW", 0),
                "info":     counts.get("INFO", 0),
            },
            **(scan_metadata or {}),
        }
        return self._report

    def finalize(self, report: dict[str, Any] | None = None) -> dict[str, str]:
        """
        Write JSON and HTML reports to disk.

        Args:
            report: Override report dict (uses self._report if None).

        Returns:
            dict with 'json_path' and 'html_path'.
        """
        data = report or self._report
        if not data:
            raise ValueError("No report data to write. Call build_report() first.")

        scan_id = data.get("scan_id", "scan")
        json_path = self.output_dir / f"{scan_id}.json"
        html_path = self.output_dir / f"{scan_id}.html"

        # JSON
        json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("JSON report written to %s", json_path)

        # HTML
        html_path.write_text(self._render_html(data), encoding="utf-8")
        logger.info("HTML report written to %s", html_path)

        return {"json_path": str(json_path), "html_path": str(html_path)}

    def print_terminal_table(self, report: dict[str, Any] | None = None) -> None:
        """Print a Rich-formatted vulnerability table to the terminal."""
        data = report or self._report
        if not data:
            self.console.print("[yellow]No report data to display.[/yellow]")
            return

        vuln_list: list[dict] = data.get("vulnerabilities", [])
        summary: dict = data.get("summary", {})

        # ── Header panel ────────────────────────────────────────────────────
        header = (
            f"[bold cyan]SQL Injection Scan Report[/bold cyan]\n"
            f"[dim]Scan ID:[/dim] [white]{data.get('scan_id', 'N/A')}[/white]  "
            f"[dim]Target:[/dim] [white]{data.get('target', 'N/A')}[/white]\n"
            f"[dim]Time:[/dim]    [white]{data.get('timestamp', 'N/A')}[/white]"
        )
        self.console.print(Panel(header, border_style="cyan", padding=(0, 2)))

        # ── Summary stats ────────────────────────────────────────────────────
        stats = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        stats.add_column("", style="dim")
        stats.add_column("")

        stats.add_row("Total Findings", f"[bold white]{summary.get('total', 0)}[/bold white]")
        stats.add_row("Critical",       f"[bold red]{summary.get('critical', 0)}[/bold red]")
        stats.add_row("High",           f"[bold orange1]{summary.get('high', 0)}[/bold orange1]")
        stats.add_row("Medium",         f"[bold yellow]{summary.get('medium', 0)}[/bold yellow]")
        stats.add_row("Low",            f"[bold green]{summary.get('low', 0)}[/bold green]")
        self.console.print(stats)

        if not vuln_list:
            self.console.print("\n[bold green]✅  No vulnerabilities found.[/bold green]\n")
            return

        # ── Findings table ───────────────────────────────────────────────────
        table = Table(
            title="[bold red][!] Confirmed SQL Injection Vulnerabilities[/bold red]",
            box=box.ROUNDED,
            border_style="red",
            header_style="bold white on #21262d",
            show_lines=True,
        )
        table.add_column("#",          style="dim",         width=4)
        table.add_column("Severity",   justify="center",    width=10)
        table.add_column("CVSS",       justify="center",    width=6)
        table.add_column("Endpoint",   style="cyan",        no_wrap=True)
        table.add_column("Parameter",  style="yellow",      width=12)
        table.add_column("Type",       style="magenta",     width=20)
        table.add_column("Indicators", style="white",       width=30)
        table.add_column("Evidence",   style="dim",         width=40)

        for i, vuln in enumerate(vuln_list, start=1):
            sev = vuln.get("severity", "INFO").upper()
            color = SEVERITY_COLORS.get(sev, "white")
            indicators = "\n".join(f"* {ind}" for ind in vuln.get("indicators", []))
            table.add_row(
                str(i),
                Text(sev, style=color),
                str(vuln.get("cvss_score", "N/A")),
                vuln.get("endpoint", ""),
                vuln.get("parameter", ""),
                vuln.get("payload_type", ""),
                indicators,
                vuln.get("evidence", "")[:120],
            )

        self.console.print(table)
        self.console.print(
            "\n[dim italic][!] FOR AUTHORIZED SECURITY TESTING ONLY[/dim italic]\n"
        )

    # ──────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────

    @staticmethod
    def _count_severities(vulnerabilities: list[dict]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in vulnerabilities:
            sev = v.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _render_html(self, data: dict[str, Any]) -> str:
        """Render the HTML report string from the report dict."""
        summary = data.get("summary", {})
        vulns   = data.get("vulnerabilities", [])

        rows_html = ""
        for i, v in enumerate(vulns, start=1):
            sev   = v.get("severity", "INFO").upper()
            color = HTML_SEVERITY_CLASSES.get(sev, "#aaa")
            rows_html += (
                f"<tr>"
                f"<td>{i}</td>"
                f"<td><span class='badge {sev}'>{sev}</span></td>"
                f"<td><code>{v.get('endpoint','')}</code></td>"
                f"<td><code>{v.get('parameter','')}</code></td>"
                f"<td>{v.get('payload_type','')}</td>"
                f"<td><code>{v.get('payload','')[:80]}</code></td>"
                f"<td>{v.get('evidence','')[:200]}</td>"
                f"<td class='remediation'>{v.get('remediation','')[:200]}</td>"
                f"</tr>\n"
            )

        return HTML_TEMPLATE.format(
            scan_id   = data.get("scan_id", "N/A"),
            target    = data.get("target", "N/A"),
            timestamp = data.get("timestamp", "N/A"),
            total     = summary.get("total", 0),
            critical  = summary.get("critical", 0),
            high      = summary.get("high", 0),
            medium    = summary.get("medium", 0),
            low       = summary.get("low", 0),
            rows      = rows_html,
        )
