"""
Gemini API SQL Injection Detection & Classification Launcher
============================================================
Starts the SQLite-backed vulnerable target API and runs the Gemini-powered
detection and classification agents against it.

Usage:
    python run_gemini_scan.py                    # full scan
    python run_gemini_scan.py --fast             # fast scan (2 payloads/category)
    python run_gemini_scan.py --verbose          # verbose scanner outputs
    python run_gemini_scan.py --endpoint /api/users  # test only one endpoint

Requirements:
    - GEMINI_API_KEY set in .env
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import subprocess
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)

# Ensure project root is importable
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from agent.gemini_agents import GeminiClient, SQLiDetectionAgent, SQLiClassifierAgent, EndpointSpec
from agent.tools import probe_endpoint
from agent.payloads import ALL_PAYLOADS
from agent.reporter import Reporter

load_dotenv()
console = Console()


def build_catalogue(base_url: str) -> list[EndpointSpec]:
    base = base_url.rstrip("/")
    return [
        EndpointSpec(
            path=f"{base}/api/users",
            method="GET",
            parameters=["id"],
            baseline_params={"id": "1"},
            payload_categories=["classic_error_based", "union_based", "blind_boolean"],
            description="User lookup - classic error-based SQLi target",
        ),
        EndpointSpec(
            path=f"{base}/api/products",
            method="GET",
            parameters=["category"],
            baseline_params={"category": "electronics"},
            payload_categories=["union_based", "classic_error_based"],
            description="Product listing - UNION-based SQLi target",
        ),
        EndpointSpec(
            path=f"{base}/api/login",
            method="POST",
            parameters=["username", "password"],
            baseline_params={},
            baseline_body={"username": "nonexistent_xyz", "password": "wrongpass123"},
            payload_categories=["auth_bypass"],
            description="Login - authentication bypass SQLi target",
        ),
        EndpointSpec(
            path=f"{base}/api/orders",
            method="GET",
            parameters=["user_id", "status"],
            baseline_params={"user_id": "1", "status": "paid"},
            payload_categories=["blind_boolean", "classic_error_based"],
            description="Orders - blind boolean SQLi target",
            extra_params={"user_id": "1", "status": "paid"},
        ),
        EndpointSpec(
            path=f"{base}/api/search",
            method="GET",
            parameters=["q"],
            baseline_params={"q": "laptop"},
            payload_categories=["time_based", "classic_error_based"],
            description="Search - time-based blind SQLi target",
        ),
        EndpointSpec(
            path=f"{base}/api/admin/users",
            method="GET",
            parameters=["role"],
            baseline_params={"role": "admin"},
            payload_categories=["stacked_queries", "classic_error_based"],
            description="Admin users - stacked queries SQLi target",
        ),
        EndpointSpec(
            path=f"{base}/api/reports",
            method="GET",
            parameters=["from", "to"],
            baseline_params={"from": "2024-01-01", "to": "2099-12-31"},
            payload_categories=["classic_error_based", "union_based", "blind_boolean"],
            description="Reports - SAFE parameterized endpoint (control)",
            extra_params={"from": "2024-01-01", "to": "2099-12-31"},
        ),
    ]


def _get_baseline(ep: EndpointSpec, verbose: bool) -> dict[str, Any] | None:
    """Probe the endpoint with clean params to get the baseline response."""
    if ep.method == "POST":
        result = probe_endpoint(ep.path, method="POST", body=ep.baseline_body)
    else:
        result = probe_endpoint(ep.path, method="GET", params=ep.baseline_params)

    if result.get("error"):
        console.print(f"    [red][FAIL] Baseline failed:[/red] {result['error']}")
        return None

    if verbose:
        console.print(
            f"    [dim]Baseline -> HTTP {result['status_code']} "
            f"| {result['content_length']} bytes "
            f"| {result['response_time_ms']:.0f}ms[/dim]"
        )
    return result


def wait_for_api(url: str, timeout: float = 20.0) -> bool:
    """Poll the target API health check until online."""
    import urllib.request
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=2):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def start_server(port: int) -> subprocess.Popen:
    """Launch the local vulnerable SQLite Flask API in a subprocess."""
    server_script = ROOT / "target_api" / "app_sqlite.py"
    env = os.environ.copy()
    env["FLASK_PORT"] = str(port)
    env["FLASK_HOST"] = "127.0.0.1"

    proc = subprocess.Popen(
        [sys.executable, str(server_script)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc


def run_gemini_scan(
    target_url: str,
    gemini_key: str,
    endpoint_filter: str | None = None,
    output_dir: str = "./reports",
    verbose: bool = False,
    fast_mode: bool = False,
) -> int:
    # 1. Initialize Agents & Client
    try:
        client = GeminiClient(api_key=gemini_key)
        detector = SQLiDetectionAgent(gemini_client=client)
        classifier = SQLiClassifierAgent(gemini_client=client)
    except Exception as e:
        console.print(f"[bold red]Initialization Error:[/bold red] {e}")
        return 1

    catalogue = build_catalogue(target_url)
    if endpoint_filter:
        catalogue = [ep for ep in catalogue if endpoint_filter in ep.path]

    # Count parameters & categories for the progress tracking
    total_endpoints = len(catalogue)

    console.print(Panel(
        f"[bold cyan]Gemini SQL Injection Security Agents[/bold cyan]\n"
        f"[dim]Target REST API:[/dim] [cyan]{target_url}[/cyan]\n"
        f"[dim]Gemini Model:[/dim]   [green]gemini-2.5-flash[/green]\n"
        f"[dim]Scan Speed:[/dim]     {'[yellow]Quick (2 payloads/category)[/yellow]' if fast_mode else '[green]Full (all payloads)[/green]'}",
        border_style="cyan",
        padding=(0, 2),
    ))

    scan_start = time.monotonic()
    vulnerabilities = []
    endpoints_tested = 0
    parameters_tested = 0
    payloads_injected = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=35),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        scan_task = progress.add_task("Scanning...", total=total_endpoints)

        for ep in catalogue:
            progress.update(scan_task, description=f"[cyan]Testing {ep.path.split('/')[-1]}[/cyan]")
            console.print(f"\n  [bold white]>[/bold white] [cyan]{ep.method}[/cyan] {ep.path}")
            console.print(f"  [dim]{ep.description}[/dim]")

            # Get clean baseline
            baseline = _get_baseline(ep, verbose)
            if baseline is None:
                progress.advance(scan_task)
                continue

            endpoints_tested += 1

            # Test each parameter
            for param in ep.parameters:
                parameters_tested += 1
                if verbose:
                    console.print(f"    [bold]Parameter:[/bold] [yellow]{param}[/yellow]")

                param_vulnerable = False

                for category in ep.payload_categories:
                    if param_vulnerable:
                        break  # stop testing parameter if already found vulnerable

                    payloads = ALL_PAYLOADS.get(category, [])
                    if fast_mode:
                        payloads = payloads[:2]  # limit payloads to run faster

                    for payload in payloads:
                        if param_vulnerable:
                            break

                        payloads_injected += 1
                        
                        # Detect SQLi
                        det_res = detector.detect_vulnerability(
                            endpoint=ep,
                            parameter=param,
                            baseline=baseline,
                            payload=payload,
                            category=category,
                        )

                        if verbose and det_res.get("injected"):
                            status = "[red]Anomalous[/red]" if det_res.get("is_vulnerable") else "[dim]clean[/dim]"
                            console.print(
                                f"      [{status}] {category} | "
                                f"payload: [yellow]{payload[:45]}[/yellow]"
                            )

                        if det_res.get("is_vulnerable"):
                            # Run Classifier Agent
                            console.print(f"    [bold yellow][DETECTION AGENT][/bold yellow] confirmed anomaly. Invoking Classifier Agent...")
                            
                            classification = classifier.classify_vulnerability(
                                endpoint=ep.path,
                                parameter=param,
                                payload=payload,
                                detection_reason=det_res.get("reason", ""),
                                baseline=baseline,
                                injected=det_res["injected"],
                                indicators=det_res["analysis"]["indicators"],
                            )

                            sev_color = {
                                "CRITICAL": "bold red",
                                "HIGH":     "bold orange1",
                                "MEDIUM":   "bold yellow",
                                "LOW":      "bold green",
                            }.get(classification.get("severity", "HIGH").upper(), "white")

                            console.print(
                                f"    [bold red][CLASSIFIER AGENT][/bold red] "
                                f"[[{sev_color}]{classification.get('severity', 'HIGH')}[/{sev_color}]] "
                                f"[magenta]{classification.get('sqli_type', 'SQL Injection')}[/magenta] identified on parameter: [yellow]{param}[/yellow]"
                            )
                            console.print(f"       Evidence: [dim]{classification.get('evidence', '')[:120]}[/dim]")

                            finding = {
                                "endpoint": ep.path,
                                "parameter": param,
                                "payload": payload,
                                "payload_type": classification.get("sqli_type", category),
                                "severity": classification.get("severity", "HIGH").upper(),
                                "cvss_score": classification.get("cvss_score", 7.5),
                                "indicators": det_res["analysis"]["indicators"],
                                "evidence": classification.get("evidence", ""),
                                "remediation": classification.get("remediation", ""),
                            }
                            vulnerabilities.append(finding)
                            param_vulnerable = True

            progress.advance(scan_task)

    scan_duration = time.monotonic() - scan_start
    console.print()
    console.rule("[bold cyan]Scan Complete[/bold cyan]")
    console.print(f"  Endpoints tested:  {endpoints_tested}")
    console.print(f"  Parameters tested: {parameters_tested}")
    console.print(f"  Payloads injected: {payloads_injected}")
    console.print(f"  Duration:          {scan_duration:.1f}s")
    console.print()

    # Generate Reports
    reporter = Reporter(output_dir=output_dir)
    report = reporter.build_report(
        target=target_url,
        vulnerabilities=vulnerabilities,
        scan_metadata={
            "scan_duration_seconds": round(scan_duration, 2),
            "endpoints_tested":      endpoints_tested,
            "parameters_tested":     parameters_tested,
            "payloads_injected":     payloads_injected,
            "mode":                  "gemini_agents",
        },
    )
    paths = reporter.finalize(report)
    reporter.print_terminal_table(report)

    console.print(f"\n[bold green]JSON report:[/bold green] {paths['json_path']}")
    console.print(f"[bold green]HTML report:[/bold green] {paths['html_path']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SQL Injection Detection & Classification Agents Launcher (Gemini API)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target",   "-t", default=None,         help="Override target URL (skips auto-starting Flask)")
    parser.add_argument("--endpoint", "-e", default=None,         help="Scan only this endpoint path e.g. /api/users")
    parser.add_argument("--output",   "-o", default="./reports",  help="Report output directory")
    parser.add_argument("--port",           default=5000, type=int, help="Port for local Flask server (default: 5000)")
    parser.add_argument("--verbose",  "-v", action="store_true",  help="Show detailed injection attempts")
    parser.add_argument("--fast",           action="store_true",  help="Fast mode: 2 payloads per category")
    parser.add_argument("--no-server",      action="store_true",  help="Don't start the local Flask server (already running)")
    args = parser.parse_args()

    # Get Gemini key
    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key or gemini_key == "your_gemini_api_key_here":
        console.print("[bold red]Error: GEMINI_API_KEY is not set in environment or .env file.[/bold red]")
        console.print("Please set the GEMINI_API_KEY key before running the scan.")
        return 1

    target_url = args.target or f"http://127.0.0.1:{args.port}"
    server_proc: subprocess.Popen | None = None

    if not args.no_server and args.target is None:
        console.print("\n[bold cyan]>> Starting SQLite-backed vulnerable Flask API...[/bold cyan]")
        server_proc = start_server(args.port)

        console.print(f"[dim]  Waiting for API on {target_url}/health ...[/dim]")
        if not wait_for_api(target_url, timeout=20.0):
            console.print("[bold red]X Server failed to start within 20 s. Check for port conflicts.[/bold red]")
            if server_proc:
                server_proc.terminate()
            return 1

        console.print(f"[green][OK] API is up![/green]  {target_url}/health\n")

    try:
        exit_code = run_gemini_scan(
            target_url=target_url,
            gemini_key=gemini_key,
            endpoint_filter=args.endpoint,
            output_dir=args.output,
            verbose=args.verbose,
            fast_mode=args.fast,
        )
        return exit_code
    except KeyboardInterrupt:
        console.print("\n[bold yellow][Interrupted by user][/bold yellow]")
        return 130
    finally:
        if server_proc is not None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()


if __name__ == "__main__":
    sys.exit(main())
