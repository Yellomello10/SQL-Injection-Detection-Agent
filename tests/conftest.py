"""
pytest conftest.py — shared fixtures and configuration for the test suite.

Provides:
  - `base_url`     : the target API base URL (from env or default)
  - `reporter`     : a fresh Reporter instance backed by a tmp directory
  - `sample_vuln`  : a realistic vulnerability dict for report tests
  - `sample_report`: a pre-built report dict for reporter tests
"""
from __future__ import annotations

import os
from typing import Any

import pytest

from agent.reporter import Reporter


# ──────────────────────────────────────────────
# Session-scoped fixtures
# ──────────────────────────────────────────────

@pytest.fixture(scope="session")
def base_url() -> str:
    """Return the target API base URL."""
    return os.getenv("TARGET_API_BASE_URL", "http://localhost:5000")


# ──────────────────────────────────────────────
# Function-scoped fixtures
# ──────────────────────────────────────────────

@pytest.fixture
def reporter(tmp_path) -> Reporter:
    """Return a fresh Reporter writing to a temporary directory."""
    return Reporter(output_dir=str(tmp_path))


@pytest.fixture
def sample_vuln() -> dict[str, Any]:
    """Return a realistic vulnerability finding dict."""
    return {
        "endpoint":     "http://localhost:5000/api/users",
        "severity":     "HIGH",
        "parameter":    "id",
        "payload":      "' OR 1=1--",
        "payload_type": "classic_error_based",
        "indicators":   ["db_error_exposed", "status_code_change"],
        "evidence":     "MySQL syntax error detected | HTTP status 200 → 500",
        "remediation":  (
            "Use parameterized queries / prepared statements. "
            "Never concatenate user input into SQL strings."
        ),
        "cvss_score":   7.5,
    }


@pytest.fixture
def sample_report(reporter: Reporter, sample_vuln: dict) -> dict[str, Any]:
    """Return a pre-built report dict from the reporter."""
    return reporter.build_report(
        target="http://localhost:5000",
        vulnerabilities=[sample_vuln],
        scan_metadata={"scan_duration_seconds": 42.0, "iterations": 10},
    )
