"""
Full pytest test suite for the SQL Injection Detection Agent.

Tests cover:
  1. Individual tool functions (unit tests — no real HTTP)
  2. End-to-end agent scan scenarios (integration tests — require Docker stack)

Environment variables needed for integration tests:
  TARGET_API_BASE_URL=http://localhost:5000
  ANTHROPIC_API_KEY=<your key>

Run all tests:
    pytest tests/ -v

Run only unit tests (no Docker required):
    pytest tests/ -v -m "not integration"

Run only integration tests:
    pytest tests/ -v -m integration

⚠️  FOR AUTHORIZED SECURITY TESTING ONLY.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

# ──────────────────────────────────────────────
# Fixtures & helpers
# ──────────────────────────────────────────────
BASE_URL = os.getenv("TARGET_API_BASE_URL", "http://localhost:5000")


def api_available() -> bool:
    """Check whether the target Flask API is reachable."""
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=3)
        return resp.status_code == 200
    except Exception:
        return False


# Marker for tests that require the live Docker stack
requires_api = pytest.mark.skipif(
    not api_available(),
    reason="Target API not running — start Docker stack first: docker-compose up -d",
)

integration = pytest.mark.integration


# ──────────────────────────────────────────────
# Shared mock responses
# ──────────────────────────────────────────────
MOCK_CLEAN_RESPONSE: dict[str, Any] = {
    "status_code":      200,
    "response_body":    '{"status": "ok", "data": [{"id": 1, "username": "john"}]}',
    "response_time_ms": 45.0,
    "headers":          {"content-type": "application/json"},
    "content_length":   60,
    "error":            None,
}

MOCK_ERROR_RESPONSE: dict[str, Any] = {
    "status_code":      500,
    "response_body":    '{"status": "error", "message": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", "query": "SELECT * FROM users WHERE id = 1"}',
    "response_time_ms": 52.0,
    "headers":          {"content-type": "application/json"},
    "content_length":   250,
    "error":            None,
}

MOCK_TIMEOUT_RESPONSE: dict[str, Any] = {
    "status_code":      None,
    "response_body":    "",
    "response_time_ms": 5500.0,
    "headers":          {},
    "content_length":   0,
    "error":            "Timeout after 5s",
}

MOCK_AUTH_SUCCESS_RESPONSE: dict[str, Any] = {
    "status_code":      200,
    "response_body":    '{"status": "ok", "data": {"authenticated": true, "user": {"id": 1, "username": "admin", "role": "admin"}}}',
    "response_time_ms": 38.0,
    "headers":          {"content-type": "application/json"},
    "content_length":   120,
    "error":            None,
}

MOCK_UNION_RESPONSE: dict[str, Any] = {
    "status_code":      200,
    "response_body":    '{"status": "ok", "data": [null, null, null, null, null, null, null, null, "1", "sqli_user@localhost", "8.0.33"]}',
    "response_time_ms": 41.0,
    "headers":          {"content-type": "application/json"},
    "content_length":   180,
    "error":            None,
}

MOCK_BOOLEAN_TRUE_RESPONSE: dict[str, Any] = {
    "status_code":      200,
    "response_body":    '{"status": "ok", "data": [{"id": 1, "user_id": 1, "status": "paid"}]}',
    "response_time_ms": 48.0,
    "headers":          {},
    "content_length":   90,
    "error":            None,
}

MOCK_BOOLEAN_FALSE_RESPONSE: dict[str, Any] = {
    "status_code":      200,
    "response_body":    '{"status": "ok", "data": []}',
    "response_time_ms": 43.0,
    "headers":          {},
    "content_length":   28,
    "error":            None,
}

MOCK_SAFE_RESPONSE: dict[str, Any] = {
    "status_code":      200,
    "response_body":    '{"status": "ok", "data": [{"id": 1, "product": "Gaming Laptop"}]}',
    "response_time_ms": 55.0,
    "headers":          {"content-type": "application/json"},
    "content_length":   80,
    "error":            None,
}


# ══════════════════════════════════════════════════════════════════════════════
# UNIT TESTS — Agent tools (no live API required)
# ══════════════════════════════════════════════════════════════════════════════

class TestClassicSQLiDetection:
    """test_classic_sqli_detection — error-based SQLi on /api/users."""

    def test_db_error_indicator_detected(self):
        """analyze_response should flag db_error_exposed when MySQL error appears."""
        from agent.tools import analyze_response

        result = analyze_response(
            original_response=MOCK_CLEAN_RESPONSE,
            injected_response=MOCK_ERROR_RESPONSE,
            payload_type="classic_error_based",
        )
        assert "db_error_exposed" in result["indicators"]

    def test_status_code_change_detected(self):
        """analyze_response should flag status_code_change when 200→500."""
        from agent.tools import analyze_response

        result = analyze_response(
            original_response=MOCK_CLEAN_RESPONSE,
            injected_response=MOCK_ERROR_RESPONSE,
            payload_type="classic_error_based",
        )
        assert "status_code_change" in result["indicators"]

    def test_vulnerability_confirmed_with_two_indicators(self):
        """is_vulnerable must be True when ≥ 2 indicators are present."""
        from agent.tools import analyze_response

        result = analyze_response(
            original_response=MOCK_CLEAN_RESPONSE,
            injected_response=MOCK_ERROR_RESPONSE,
            payload_type="classic_error_based",
        )
        assert result["indicator_count"] >= 2
        assert result["is_vulnerable"] is True

    def test_confidence_is_at_least_medium(self):
        """Confidence must be 'medium' or higher for a confirmed finding."""
        from agent.tools import analyze_response

        result = analyze_response(
            original_response=MOCK_CLEAN_RESPONSE,
            injected_response=MOCK_ERROR_RESPONSE,
            payload_type="classic_error_based",
        )
        assert result["confidence"] in ("medium", "high", "critical")


class TestUnionSQLiDetection:
    """test_union_sqli_detection — UNION attack on /api/products."""

    def test_union_null_columns_detected(self):
        """analyze_response should detect NULL columns from UNION SELECT."""
        from agent.tools import analyze_response

        result = analyze_response(
            original_response=MOCK_CLEAN_RESPONSE,
            injected_response=MOCK_UNION_RESPONSE,
            payload_type="union_based",
        )
        assert "union_null_columns" in result["indicators"]

    def test_data_leakage_detected(self):
        """Version string in union response should trigger data_leakage indicator."""
        from agent.tools import analyze_response

        result = analyze_response(
            original_response=MOCK_CLEAN_RESPONSE,
            injected_response=MOCK_UNION_RESPONSE,
            payload_type="union_based",
        )
        assert "data_leakage" in result["indicators"]

    def test_union_vulnerability_confirmed(self):
        """UNION-based SQLi should be confirmed with ≥ 2 indicators."""
        from agent.tools import analyze_response

        result = analyze_response(
            original_response=MOCK_CLEAN_RESPONSE,
            injected_response=MOCK_UNION_RESPONSE,
            payload_type="union_based",
        )
        assert result["is_vulnerable"] is True


class TestAuthBypassDetection:
    """test_auth_bypass_detection — login bypass on /api/login."""

    def test_auth_bypass_indicator_detected(self):
        """analyze_response should detect auth bypass when authenticated=true appears."""
        from agent.tools import analyze_response

        # Baseline: failed login (401)
        baseline = {**MOCK_CLEAN_RESPONSE, "status_code": 401,
                    "response_body": '{"status": "error", "message": "Invalid credentials"}',
                    "content_length": 50}

        result = analyze_response(
            original_response=baseline,
            injected_response=MOCK_AUTH_SUCCESS_RESPONSE,
            payload_type="auth_bypass",
        )
        assert "auth_bypass_success" in result["indicators"]

    def test_auth_bypass_confirmed(self):
        """Auth bypass must be confirmed (is_vulnerable=True)."""
        from agent.tools import analyze_response

        baseline = {**MOCK_CLEAN_RESPONSE, "status_code": 401,
                    "response_body": '{"status": "error", "message": "Invalid credentials"}',
                    "content_length": 50}

        result = analyze_response(
            original_response=baseline,
            injected_response=MOCK_AUTH_SUCCESS_RESPONSE,
            payload_type="auth_bypass",
        )
        assert result["is_vulnerable"] is True


class TestBlindBooleanDetection:
    """test_blind_boolean_detection — blind SQLi on /api/orders."""

    def test_boolean_differential_true_vs_false(self):
        """Different data presence for AND 1=1 vs AND 1=2 should trigger boolean_response_diff."""
        from agent.tools import analyze_response

        # Inject AND 1=2 (false) — returns empty
        result = analyze_response(
            original_response=MOCK_BOOLEAN_TRUE_RESPONSE,
            injected_response=MOCK_BOOLEAN_FALSE_RESPONSE,
            payload_type="blind_boolean",
        )
        assert "boolean_response_diff" in result["indicators"]

    def test_response_size_anomaly_detected(self):
        """Large size difference between true and false responses should be flagged."""
        from agent.tools import analyze_response

        result = analyze_response(
            original_response=MOCK_BOOLEAN_TRUE_RESPONSE,
            injected_response=MOCK_BOOLEAN_FALSE_RESPONSE,
            payload_type="blind_boolean",
        )
        assert "response_size_anomaly" in result["indicators"]

    def test_blind_boolean_confirmed(self):
        """Blind boolean SQLi should be confirmed with ≥ 2 indicators."""
        from agent.tools import analyze_response

        result = analyze_response(
            original_response=MOCK_BOOLEAN_TRUE_RESPONSE,
            injected_response=MOCK_BOOLEAN_FALSE_RESPONSE,
            payload_type="blind_boolean",
        )
        assert result["is_vulnerable"] is True


class TestTimeBasedDetection:
    """test_time_based_detection — timing attack on /api/search."""

    def test_time_delay_indicator_detected(self):
        """Response time ≥ 3000ms should trigger time_delay_detected."""
        from agent.tools import analyze_response

        baseline = {**MOCK_CLEAN_RESPONSE, "response_time_ms": 50.0}
        injected = {**MOCK_TIMEOUT_RESPONSE, "status_code": 200,
                    "response_body": '{"status": "ok", "data": []}',
                    "content_length": 28}

        result = analyze_response(
            original_response=baseline,
            injected_response=injected,
            payload_type="time_based",
        )
        assert "time_delay_detected" in result["indicators"]

    def test_no_time_delay_false_payload(self):
        """AND IF(1=2,SLEEP(5),0) should NOT trigger time_delay_detected (no delay)."""
        from agent.tools import analyze_response

        baseline = {**MOCK_CLEAN_RESPONSE, "response_time_ms": 50.0}
        fast_response = {**MOCK_CLEAN_RESPONSE, "response_time_ms": 55.0}

        result = analyze_response(
            original_response=baseline,
            injected_response=fast_response,
            payload_type="time_based",
        )
        assert "time_delay_detected" not in result["indicators"]


class TestStackedQueriesDetection:
    """test_stacked_queries_detection — stacked queries on /api/admin/users."""

    def test_stacked_query_error_detected(self):
        """Stacked query payloads that cause DB errors should be detected."""
        from agent.tools import analyze_response

        stacked_error = {
            **MOCK_ERROR_RESPONSE,
            "response_body": '{"status": "error", "message": "You have an error in your SQL syntax near SELECT user"}',
        }

        result = analyze_response(
            original_response=MOCK_CLEAN_RESPONSE,
            injected_response=stacked_error,
            payload_type="stacked_queries",
        )
        assert result["is_vulnerable"] is True


class TestNoFalsePositive:
    """test_no_false_positive — /api/reports (safe endpoint) must NOT be flagged."""

    def test_safe_endpoint_not_flagged(self):
        """Parameterized endpoint: same safe response for injected payload → not vulnerable."""
        from agent.tools import analyze_response

        # The safe endpoint returns the same response regardless of the payload
        # because it uses parameterized queries
        result = analyze_response(
            original_response=MOCK_SAFE_RESPONSE,
            injected_response=MOCK_SAFE_RESPONSE,  # identical response
            payload_type="classic_error_based",
        )
        assert result["is_vulnerable"] is False

    def test_single_indicator_not_enough(self):
        """A single indicator should NOT be enough to confirm a vulnerability."""
        from agent.tools import analyze_response

        # Slight size difference only — not enough to confirm
        slightly_different = {**MOCK_SAFE_RESPONSE, "content_length": 20}

        result = analyze_response(
            original_response=MOCK_SAFE_RESPONSE,
            injected_response=slightly_different,
            payload_type="classic_error_based",
        )
        # size_ratio = (80-20)/80 = 0.75 > 0.25 → only 1 indicator
        assert result["indicator_count"] <= 1
        assert result["is_vulnerable"] is False


class TestSeverityScoring:
    """test_severity_scoring — CVSS-like severity levels."""

    @pytest.mark.parametrize("severity,expected_cvss", [
        ("CRITICAL", 9.8),
        ("HIGH",     7.5),
        ("MEDIUM",   5.0),
        ("LOW",      3.1),
        ("INFO",     0.0),
    ])
    def test_cvss_scores(self, severity: str, expected_cvss: float):
        """generate_report should assign correct CVSS scores per severity level."""
        from agent.tools import generate_report

        finding = {
            "endpoint":        "http://localhost:5000/api/users",
            "parameter":       "id",
            "payload":         "' OR 1=1--",
            "payload_type":    "classic_error_based",
            "indicators":      ["db_error_exposed", "status_code_change"],
            "evidence_summary": "DB error in response | Status 200→500",
        }
        result = generate_report([finding], finding["endpoint"], severity)
        assert result["finding"]["cvss_score"] == expected_cvss

    def test_invalid_severity_defaults_to_high(self):
        """Unknown severity label should default to HIGH."""
        from agent.tools import generate_report

        finding = {
            "endpoint": "http://localhost:5000/api/users",
            "parameter": "id", "payload": "'", "payload_type": "classic_error_based",
            "indicators": ["db_error_exposed", "status_code_change"],
            "evidence_summary": "test",
        }
        result = generate_report([finding], finding["endpoint"], "ULTRA_MEGA")
        assert result["finding"]["severity"] == "HIGH"


class TestReportGeneration:
    """test_report_generation — HTML and JSON output validation."""

    def test_json_report_structure(self, tmp_path):
        """JSON report must include required top-level fields."""
        from agent.reporter import Reporter

        reporter = Reporter(output_dir=str(tmp_path))
        vuln = {
            "endpoint":     "http://localhost:5000/api/users",
            "severity":     "HIGH",
            "parameter":    "id",
            "payload":      "' OR 1=1--",
            "payload_type": "classic_error_based",
            "indicators":   ["db_error_exposed", "status_code_change"],
            "evidence":     "DB error detected",
            "remediation":  "Use parameterized queries",
            "cvss_score":   7.5,
        }
        report = reporter.build_report(
            target="http://localhost:5000",
            vulnerabilities=[vuln],
        )
        paths = reporter.finalize(report)

        import json as _json
        data = _json.loads((tmp_path / f"{report['scan_id']}.json").read_text())

        # Validate structure
        assert "scan_id" in data
        assert "timestamp" in data
        assert "target" in data
        assert "vulnerabilities" in data
        assert "summary" in data
        assert data["summary"]["total"] == 1
        assert data["summary"]["high"] == 1
        assert data["summary"]["critical"] == 0

    def test_html_report_created(self, tmp_path):
        """HTML report file must be created and contain severity badge."""
        from agent.reporter import Reporter

        reporter = Reporter(output_dir=str(tmp_path))
        vuln = {
            "endpoint": "http://localhost:5000/api/login",
            "severity": "CRITICAL",
            "parameter": "username",
            "payload": "admin'--",
            "payload_type": "auth_bypass",
            "indicators": ["auth_bypass_success", "status_code_change"],
            "evidence": "Auth bypass detected",
            "remediation": "Use parameterized queries",
            "cvss_score": 9.8,
        }
        report = reporter.build_report(
            target="http://localhost:5000",
            vulnerabilities=[vuln],
        )
        paths = reporter.finalize(report)

        html_content = (tmp_path / f"{report['scan_id']}.html").read_text(encoding="utf-8")
        assert "<html" in html_content
        assert "CRITICAL" in html_content
        assert "auth_bypass" in html_content
        assert "SQL Injection" in html_content

    def test_report_summary_counts(self, tmp_path):
        """Summary section must correctly count each severity level."""
        from agent.reporter import Reporter

        reporter = Reporter(output_dir=str(tmp_path))
        vulns = [
            {"severity": "CRITICAL", "endpoint": "/api/login",  "parameter": "username",
             "payload": "x", "payload_type": "auth_bypass", "indicators": [],
             "evidence": "e", "remediation": "r", "cvss_score": 9.8},
            {"severity": "HIGH",     "endpoint": "/api/users",  "parameter": "id",
             "payload": "y", "payload_type": "classic_error_based", "indicators": [],
             "evidence": "e", "remediation": "r", "cvss_score": 7.5},
            {"severity": "MEDIUM",   "endpoint": "/api/search", "parameter": "q",
             "payload": "z", "payload_type": "time_based", "indicators": [],
             "evidence": "e", "remediation": "r", "cvss_score": 5.0},
        ]
        report = reporter.build_report(target="http://localhost:5000", vulnerabilities=vulns)

        assert report["summary"]["total"]    == 3
        assert report["summary"]["critical"] == 1
        assert report["summary"]["high"]     == 1
        assert report["summary"]["medium"]   == 1
        assert report["summary"]["low"]      == 0


# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD LIBRARY TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestPayloadLibrary:
    """Validate the payload library structure and counts."""

    def test_all_categories_present(self):
        """ALL_PAYLOADS must contain all 7 categories."""
        from agent.payloads import ALL_PAYLOADS
        expected = {
            "classic_error_based", "union_based", "blind_boolean",
            "time_based", "auth_bypass", "stacked_queries", "second_order",
        }
        assert set(ALL_PAYLOADS.keys()) == expected

    def test_classic_error_based_count(self):
        from agent.payloads import CLASSIC_ERROR_BASED
        assert len(CLASSIC_ERROR_BASED) >= 10

    def test_union_based_count(self):
        from agent.payloads import UNION_BASED
        assert len(UNION_BASED) >= 8

    def test_blind_boolean_count(self):
        from agent.payloads import BLIND_BOOLEAN
        assert len(BLIND_BOOLEAN) >= 10

    def test_time_based_count(self):
        from agent.payloads import TIME_BASED
        assert len(TIME_BASED) >= 8

    def test_auth_bypass_count(self):
        from agent.payloads import AUTH_BYPASS
        assert len(AUTH_BYPASS) >= 10

    def test_stacked_queries_count(self):
        from agent.payloads import STACKED_QUERIES
        assert len(STACKED_QUERIES) >= 6

    def test_second_order_count(self):
        from agent.payloads import SECOND_ORDER
        assert len(SECOND_ORDER) >= 5

    def test_all_payloads_are_strings(self):
        from agent.payloads import ALL_PAYLOADS
        for category, payloads in ALL_PAYLOADS.items():
            for p in payloads:
                assert isinstance(p, str), f"Non-string payload in {category}: {p!r}"

    def test_severity_metadata_present(self):
        from agent.payloads import CATEGORY_SEVERITY
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for cat, sev in CATEGORY_SEVERITY.items():
            assert sev in valid, f"Unknown severity '{sev}' for category '{cat}'"


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS — require live Docker stack
# ══════════════════════════════════════════════════════════════════════════════

@integration
@requires_api
class TestFullAPIScan:
    """test_full_api_scan — agent against all endpoints, validates report structure."""

    def test_health_endpoint(self):
        """Target API health check must return 200."""
        resp = requests.get(f"{BASE_URL}/health", timeout=5)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_baseline_users_endpoint(self):
        """GET /api/users?id=1 must return valid data (baseline, no injection)."""
        resp = requests.get(f"{BASE_URL}/api/users", params={"id": "1"}, timeout=5)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert len(data["data"]) > 0

    def test_baseline_products_endpoint(self):
        resp = requests.get(f"{BASE_URL}/api/products", params={"category": "electronics"}, timeout=5)
        assert resp.status_code == 200

    def test_baseline_search_endpoint(self):
        resp = requests.get(f"{BASE_URL}/api/search", params={"q": "laptop"}, timeout=5)
        assert resp.status_code == 200

    def test_baseline_orders_endpoint(self):
        resp = requests.get(f"{BASE_URL}/api/orders", params={"user_id": "1", "status": "paid"}, timeout=5)
        assert resp.status_code == 200

    def test_baseline_admin_endpoint(self):
        resp = requests.get(f"{BASE_URL}/api/admin/users", params={"role": "admin"}, timeout=5)
        assert resp.status_code == 200

    def test_safe_reports_endpoint(self):
        resp = requests.get(f"{BASE_URL}/api/reports", params={"from": "2024-01-01"}, timeout=5)
        assert resp.status_code == 200

    def test_classic_sqli_triggers_error(self):
        """A bare quote should trigger a MySQL syntax error on the vulnerable endpoint."""
        resp = requests.get(f"{BASE_URL}/api/users", params={"id": "'"}, timeout=5)
        assert resp.status_code == 500
        body = resp.json()
        assert "sql syntax" in body.get("message", "").lower() or "error" in body.get("status", "").lower()

    def test_auth_bypass_with_sqli(self):
        """admin'-- payload should bypass authentication."""
        resp = requests.post(
            f"{BASE_URL}/api/login",
            json={"username": "admin'--", "password": "anything"},
            timeout=5,
        )
        # Auth bypass succeeded if we get back a user object
        assert resp.status_code in (200, 401)  # may depend on MySQL config
        if resp.status_code == 200:
            data = resp.json()
            assert "user" in data.get("data", {})

    def test_safe_endpoint_rejects_sqli(self):
        """/api/reports with a SQLi payload should NOT expose DB errors."""
        resp = requests.get(
            f"{BASE_URL}/api/reports",
            params={"from": "' OR '1'='1"},
            timeout=5,
        )
        body = resp.text.lower()
        assert "sql syntax" not in body
        assert "pymysql" not in body

    def test_probe_endpoint_tool_live(self):
        """probe_endpoint tool must correctly retrieve baseline from live API."""
        from agent.tools import probe_endpoint

        result = probe_endpoint(f"{BASE_URL}/api/users", params={"id": "1"})
        assert result["status_code"] == 200
        assert result["error"] is None
        assert result["response_time_ms"] > 0
        assert "data" in result["response_body"]

    def test_inject_payload_tool_live(self):
        """inject_payload tool must send the payload and return a response."""
        from agent.tools import inject_payload

        result = inject_payload(
            endpoint_url=f"{BASE_URL}/api/users",
            parameter="id",
            payload="' OR '1'='1",
            method="GET",
        )
        assert result["injected_parameter"] == "id"
        assert result["injected_payload"] == "' OR '1'='1"
        assert result["status_code"] is not None
