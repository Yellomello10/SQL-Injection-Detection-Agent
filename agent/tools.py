"""
Agent Tools — HTTP probing, payload injection, and response analysis.

These functions are called by the Anthropic tool_use agentic loop.
Each public function maps 1-to-1 with a tool definition in sql_injection_agent.py.

⚠️  FOR AUTHORIZED SECURITY TESTING ONLY.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────
DEFAULT_TIMEOUT: float = 30.0
MAX_RETRIES: int = 3
RETRY_DELAY: float = 1.0
TIME_BASED_THRESHOLD_MS: float = 3000.0  # 3 seconds

# MySQL error patterns (case-insensitive)
DB_ERROR_PATTERNS: list[re.Pattern] = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql", re.I),
    re.compile(r"mysql.*error", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"sqlstate", re.I),
    re.compile(r"syntax error.*sql", re.I),
    re.compile(r"odbc.*sql", re.I),
    re.compile(r"sql.*exception", re.I),
    re.compile(r"pymysql", re.I),
    re.compile(r"operationalerror", re.I),
    re.compile(r"programmingerror", re.I),
    re.compile(r"integrity.*error", re.I),
    re.compile(r"1064.*sql", re.I),      # MySQL error code 1064
    re.compile(r"1054.*unknown column", re.I),
    re.compile(r"division by zero", re.I),
    re.compile(r"extractvalue.*xpath", re.I),
    re.compile(r"updatexml.*xpath", re.I),
]

# Patterns indicating data exfiltration (information leakage)
LEAK_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b\d+\.\d+\.\d+\b"),          # Version string e.g. 8.0.33
    re.compile(r"secret_token", re.I),
    re.compile(r"password", re.I),
    re.compile(r"information_schema", re.I),
    re.compile(r"root@", re.I),
    re.compile(r"sqli_testdb", re.I),
    re.compile(r"mysql\.user", re.I),
]


# ──────────────────────────────────────────────
# Helper — create an httpx client
# ──────────────────────────────────────────────
def _make_client(timeout: float = DEFAULT_TIMEOUT) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=5.0),
        follow_redirects=True,
        verify=False,  # target is on localhost/Docker; skip TLS
    )


# ══════════════════════════════════════════════
# TOOL 1 — probe_endpoint
# ══════════════════════════════════════════════
def probe_endpoint(
    url: str,
    method: str = "GET",
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_retries: int | None = None,
) -> dict[str, Any]:
    """
    Make an HTTP request to *url* and return rich metadata about the response.

    Retries up to MAX_RETRIES times on transient connection errors.

    Args:
        url:     Fully-qualified URL to probe.
        method:  HTTP method (GET, POST, PUT, DELETE).
        params:  Query-string parameters (merged with any already in the URL).
        headers: Additional request headers.
        body:    JSON body (for POST/PUT requests).
        timeout: Request timeout in seconds.
        max_retries: Maximum attempts to try.

    Returns:
        dict with keys:
            status_code, response_body, response_time_ms,
            headers, content_length, error (if any)
    """
    method = method.upper()
    headers = headers or {}
    
    if max_retries is None:
        max_retries = MAX_RETRIES

    for attempt in range(1, max_retries + 1):
        try:
            with _make_client(timeout) as client:
                start = time.monotonic()
                response = client.request(
                    method,
                    url,
                    params=params,
                    headers=headers,
                    json=body if body else None,
                )
                elapsed_ms = (time.monotonic() - start) * 1000

            resp_text = response.text[:5000]  # cap at 5 KB to avoid token bloat
            return {
                "status_code":      response.status_code,
                "response_body":    resp_text,
                "response_time_ms": round(elapsed_ms, 2),
                "headers":          dict(response.headers),
                "content_length":   len(response.content),
                "error":            None,
            }

        except httpx.TimeoutException as exc:
            logger.warning("Probe timeout (attempt %d/%d): %s", attempt, max_retries, exc)
            if attempt == max_retries:
                return {
                    "status_code":      None,
                    "response_body":    "",
                    "response_time_ms": timeout * 1000,
                    "headers":          {},
                    "content_length":   0,
                    "error":            f"Timeout after {timeout}s: {exc}",
                }
            time.sleep(RETRY_DELAY * attempt)

        except httpx.RequestError as exc:
            logger.warning("Probe error (attempt %d/%d): %s", attempt, max_retries, exc)
            if attempt == max_retries:
                return {
                    "status_code":      None,
                    "response_body":    "",
                    "response_time_ms": 0,
                    "headers":          {},
                    "content_length":   0,
                    "error":            str(exc),
                }
            time.sleep(RETRY_DELAY * attempt)

    # Should never reach here
    return {"error": "Unknown error", "status_code": None, "response_body": ""}


# ══════════════════════════════════════════════
# TOOL 2 — inject_payload
# ══════════════════════════════════════════════
def inject_payload(
    endpoint_url: str,
    parameter: str,
    payload: str,
    method: str = "GET",
    extra_params: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Inject *payload* into *parameter* of *endpoint_url* and return the response.

    For GET requests the payload is appended to the query string.
    For POST requests the payload is embedded in the JSON body.

    Args:
        endpoint_url: Target URL (without injected query string).
        parameter:    Name of the parameter to inject into.
        payload:      SQLi payload string.
        method:       HTTP method (GET or POST).
        extra_params: Additional baseline parameters to include in the request.
        timeout:      Request timeout in seconds.

    Returns:
        dict with all probe_endpoint fields plus:
            injected_parameter, injected_payload
    """
    method = method.upper()
    extra_params = extra_params or {}

    if method == "GET":
        params = {**extra_params, parameter: payload}
        result = probe_endpoint(endpoint_url, method="GET", params=params, timeout=timeout)
    elif method == "POST":
        body = {**extra_params, parameter: payload}
        result = probe_endpoint(endpoint_url, method="POST", body=body, timeout=timeout)
    else:
        result = probe_endpoint(
            endpoint_url,
            method=method,
            params={**extra_params, parameter: payload},
            timeout=timeout,
        )

    result["injected_parameter"] = parameter
    result["injected_payload"]   = payload
    return result


# ══════════════════════════════════════════════
# TOOL 3 — analyze_response
# ══════════════════════════════════════════════
def analyze_response(
    original_response: dict[str, Any],
    injected_response: dict[str, Any],
    payload_type: str,
) -> dict[str, Any]:
    """
    Compare *original_response* with *injected_response* to detect SQLi indicators.

    Returns a structured analysis with detected indicators and a confidence score.
    Requires ≥ 2 independent indicators to flag as a confirmed vulnerability.

    Args:
        original_response: Result of probe_endpoint on the clean baseline request.
        injected_response: Result of inject_payload with the SQLi payload.
        payload_type:      Category string from payloads.py (e.g. 'time_based').

    Returns:
        dict with keys:
            is_vulnerable, confidence, indicators, indicator_count,
            payload_type, evidence_summary
    """
    indicators: list[str] = []
    evidence: list[str] = []

    orig_body  = (original_response.get("response_body") or "").lower()
    inj_body   = (injected_response.get("response_body") or "").lower()
    orig_status = original_response.get("status_code") or 0
    inj_status  = injected_response.get("status_code") or 0
    orig_time   = original_response.get("response_time_ms") or 0.0
    inj_time    = injected_response.get("response_time_ms") or 0.0
    orig_length = original_response.get("content_length") or 0
    inj_length  = injected_response.get("content_length") or 0

    # ── Indicator 1: DB error messages in injected response ──────────────────
    if any(p.search(injected_response.get("response_body", "")) for p in DB_ERROR_PATTERNS):
        indicators.append("db_error_exposed")
        evidence.append("Database error message detected in response body")

    # ── Indicator 2: Status code change (e.g. 200 → 500) ────────────────────
    if orig_status != inj_status and inj_status in (500, 503):
        indicators.append("status_code_change")
        evidence.append(f"HTTP status changed: {orig_status} -> {inj_status}")

    # ── Indicator 3: Response body size differs significantly ────────────────
    if orig_length > 0:
        size_ratio = abs(inj_length - orig_length) / orig_length
        if size_ratio > 0.25:
            indicators.append("response_size_anomaly")
            evidence.append(
                f"Response size changed by {size_ratio:.0%} "
                f"({orig_length} -> {inj_length} bytes)"
            )

    # ── Indicator 4: Time-based detection (SLEEP/WAITFOR) ───────────────────
    if payload_type in ("time_based",) and inj_time >= TIME_BASED_THRESHOLD_MS:
        if inj_time > orig_time * 2:  # must be significantly slower than baseline
            indicators.append("time_delay_detected")
            evidence.append(
                f"Response time {inj_time:.0f}ms vs baseline {orig_time:.0f}ms "
                f"(threshold: {TIME_BASED_THRESHOLD_MS:.0f}ms)"
            )

    # ── Indicator 5: Data leakage patterns ───────────────────────────────────
    for pat in LEAK_PATTERNS:
        if pat.search(injected_response.get("response_body", "")) and not pat.search(
            original_response.get("response_body", "")
        ):
            indicators.append("data_leakage")
            evidence.append(f"Sensitive data pattern leaked: '{pat.pattern}'")
            break  # one leakage indicator is enough

    # ── Indicator 6: Authentication bypass ───────────────────────────────────
    if payload_type == "auth_bypass":
        inj_body_raw = injected_response.get("response_body", "")
        orig_body_raw = original_response.get("response_body", "")
        inj_lower = inj_body_raw.lower()
        orig_lower = orig_body_raw.lower()
        # Flask JSON returns `true` (lowercase); Python `True` becomes `true` in JSON
        auth_in_injected = (
            '"authenticated": true' in inj_lower
            or '"authenticated":true' in inj_lower
            or ('"user"' in inj_lower and '"role"' in inj_lower and 'authenticated' in inj_lower)
        )
        auth_in_original = 'authenticated' in orig_lower
        if auth_in_injected and not auth_in_original:
            indicators.append("auth_bypass_success")
            evidence.append("Authentication bypass: server returned authenticated user without valid credentials")

    # ── Indicator 7: Boolean blind — different data for true vs false ─────────
    if payload_type == "blind_boolean":
        # If original had data but injected is empty (or vice versa)
        orig_has_data = '"data": []' not in orig_body and '"data"' in orig_body
        inj_has_data  = '"data": []' not in inj_body  and '"data"'  in inj_body
        if orig_has_data != inj_has_data:
            indicators.append("boolean_response_diff")
            evidence.append(
                "Boolean-based differential: "
                f"original returned {'data' if orig_has_data else 'empty'}, "
                f"injected returned {'data' if inj_has_data else 'empty'}"
            )

    # ── Indicator 8: UNION columns visible in response ────────────────────────
    if payload_type == "union_based" and "null" in inj_body and "null" not in orig_body:
        indicators.append("union_null_columns")
        evidence.append("UNION SELECT NULL columns visible in injected response")

    # ── Confidence scoring ────────────────────────────────────────────────────
    indicator_count = len(indicators)
    if indicator_count == 0:
        confidence = "none"
    elif indicator_count == 1:
        confidence = "low"
    elif indicator_count == 2:
        confidence = "medium"
    elif indicator_count == 3:
        confidence = "high"
    else:
        confidence = "critical"

    is_vulnerable = indicator_count >= 2  # require ≥ 2 indicators to confirm

    return {
        "is_vulnerable":    is_vulnerable,
        "confidence":       confidence,
        "indicators":       indicators,
        "indicator_count":  indicator_count,
        "payload_type":     payload_type,
        "evidence_summary": " | ".join(evidence) if evidence else "No indicators found",
    }


# ══════════════════════════════════════════════
# TOOL 4 — generate_report
# ══════════════════════════════════════════════
def generate_report(
    vulnerabilities_found: list[dict[str, Any]],
    endpoint: str,
    severity: str,
) -> dict[str, Any]:
    """
    Record a confirmed vulnerability and return a structured finding record.

    This tool is called by the agent once a vulnerability has been confirmed
    by analyze_response (≥ 2 indicators).

    Args:
        vulnerabilities_found: List of existing vulnerability dicts (accumulator).
        endpoint:              The vulnerable endpoint URL.
        severity:              Severity level: CRITICAL | HIGH | MEDIUM | LOW | INFO.

    Returns:
        dict summarising the finding that was appended to *vulnerabilities_found*.
    """
    severity = severity.upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity = "HIGH"

    # The last item in the list contains the just-confirmed finding details
    finding = vulnerabilities_found[-1] if vulnerabilities_found else {}

    remediation_map = {
        "CRITICAL": (
            "IMMEDIATE ACTION REQUIRED: "
            "Use parameterized queries / prepared statements for ALL database interactions. "
            "Never concatenate user input into SQL strings. "
            "Apply the principle of least privilege to DB accounts. "
            "Deploy a WAF as defence-in-depth."
        ),
        "HIGH": (
            "Use parameterized queries or an ORM. "
            "Validate and sanitize all user-supplied input. "
            "Implement strict input allowlisting where possible."
        ),
        "MEDIUM": (
            "Apply input validation and output encoding. "
            "Consider using stored procedures with parameter binding."
        ),
        "LOW": (
            "Review and harden input validation. "
            "Monitor for anomalous query patterns in application logs."
        ),
    }

    remediation = remediation_map.get(severity, remediation_map["HIGH"])

    report_entry: dict[str, Any] = {
        "endpoint":     endpoint,
        "severity":     severity,
        "parameter":    finding.get("parameter", "unknown"),
        "payload":      finding.get("payload", "unknown"),
        "payload_type": finding.get("payload_type", "unknown"),
        "indicators":   finding.get("indicators", []),
        "evidence":     finding.get("evidence_summary", ""),
        "remediation":  remediation,
        "cvss_score":   _severity_to_cvss(severity),
    }

    return {
        "recorded": True,
        "finding":  report_entry,
        "message":  f"Vulnerability recorded: [{severity}] {endpoint}",
    }


def _severity_to_cvss(severity: str) -> float:
    """Map severity label to approximate CVSS 3.1 base score."""
    return {
        "CRITICAL": 9.8,
        "HIGH":     7.5,
        "MEDIUM":   5.0,
        "LOW":      3.1,
        "INFO":     0.0,
    }.get(severity.upper(), 5.0)
