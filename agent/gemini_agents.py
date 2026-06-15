from __future__ import annotations

import json
import os
import logging
from typing import Any, Optional

import httpx

from dataclasses import dataclass, field

from agent.tools import inject_payload, analyze_response, probe_endpoint

logger = logging.getLogger(__name__)


@dataclass
class EndpointSpec:
    path: str
    method: str
    parameters: list[str]
    baseline_params: dict[str, str]
    payload_categories: list[str]
    description: str
    baseline_body: dict[str, str] | None = None
    extra_params: dict[str, str] = field(default_factory=dict)


class GeminiClient:
    """Wrapper client for the Gemini API using direct HTTP POST requests."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key or self.api_key == "your_gemini_api_key_here":
            raise ValueError(
                "GEMINI_API_KEY is not set. Please add your key to the .env file."
            )
        self.client = httpx.Client(timeout=30.0)
        self.url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

    def generate(self, prompt: str, json_mode: bool = False) -> str:
        """Send prompt to Gemini 2.5 Flash and return the generated text content."""
        headers = {"Content-Type": "application/json"}
        params = {"key": self.api_key}
        
        data = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        if json_mode:
            data["generationConfig"] = {"responseMimeType": "application/json"}

        response = self.client.post(self.url, headers=headers, params=params, json=data)
        if response.status_code != 200:
            raise RuntimeError(f"Gemini API returned error ({response.status_code}): {response.text}")
        
        resp_json = response.json()
        try:
            text = resp_json["candidates"][0]["content"]["parts"][0]["text"]
            return text.strip()
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"Unexpected response payload structure from Gemini API: {resp_json}") from e


class SQLiDetectionAgent:
    """Agent that handles payload injection and determines if an endpoint parameter is vulnerable."""

    def __init__(self, gemini_client: GeminiClient) -> None:
        self.client = gemini_client

    def detect_vulnerability(
        self,
        endpoint: EndpointSpec,
        parameter: str,
        baseline: dict[str, Any],
        payload: str,
        category: str,
        timeout: float = 8.0,
    ) -> dict[str, Any]:
        """
        Injects the payload, runs local indicator heuristics, and uses Gemini to verify if
        the responses confirm a SQL injection vulnerability.
        """
        # Compute query parameters / request body (omitting the tested parameter baseline value)
        if endpoint.method == "GET":
            extra = {k: v for k, v in endpoint.baseline_params.items() if k != parameter}
        else:
            extra = {k: v for k, v in (endpoint.baseline_body or {}).items() if k != parameter}

        # 1. Inject payload
        injected = inject_payload(
            endpoint_url=endpoint.path,
            parameter=parameter,
            payload=payload,
            method=endpoint.method,
            extra_params=extra if extra else None,
            timeout=timeout,
        )

        # 2. Perform baseline diff heuristics
        analysis = analyze_response(
            original_response=baseline,
            injected_response=injected,
            payload_type=category,
        )

        # If no indicators or anomalies are triggered, class it as clean immediately to save API calls
        if not analysis["indicators"]:
            return {
                "is_vulnerable": False,
                "reason": "No anomalies or indicators detected in response",
                "analysis": analysis,
                "injected": injected,
            }

        # 3. Leverage Gemini to perform intelligent verification of the difference
        prompt = f"""
You are a SQL Injection Detection Agent. Analyze the difference between a baseline HTTP response and an injected response to confirm if a SQL injection vulnerability exists.

Endpoint: {endpoint.method} {endpoint.path}
Parameter tested: {parameter}
Payload injected: {payload}
SQLi Category: {category}

Baseline Response:
- Status Code: {baseline.get('status_code')}
- Content Length: {baseline.get('content_length')} bytes
- Response Time: {baseline.get('response_time_ms')}ms
- Response Snippet: {baseline.get('response_body', '')[:800]}

Injected Response:
- Status Code: {injected.get('status_code')}
- Content Length: {injected.get('content_length')} bytes
- Response Time: {injected.get('response_time_ms')}ms
- Response Snippet: {injected.get('response_body', '')[:800]}
- Error Details: {injected.get('error')}

Scanner Analysis Indicators:
- Indicators: {analysis.get('indicators')}
- Evidence Summary: {analysis.get('evidence_summary')}

Does this evidence confirm a SQL injection vulnerability on the tested parameter?
Return JSON format matching the schema:
{{
  "is_vulnerable": boolean,
  "reason": "Clear explanation of why this is or is not a SQL injection vulnerability based on the evidence."
}}
"""
        try:
            result_str = self.client.generate(prompt, json_mode=True)
            res = json.loads(result_str)
            res["analysis"] = analysis
            res["injected"] = injected
            return res
        except Exception as e:
            logger.warning("Gemini detection call failed, fallback to local heuristics: %s", e)
            return {
                "is_vulnerable": analysis["is_vulnerable"],
                "reason": f"Fallback to scanner heuristics (Gemini call failed: {e})",
                "analysis": analysis,
                "injected": injected,
            }


class SQLiClassifierAgent:
    """Agent that analyzes a confirmed vulnerability to identify its subtype, severity, and remediation."""

    def __init__(self, gemini_client: GeminiClient) -> None:
        self.client = gemini_client

    def classify_vulnerability(
        self,
        endpoint: str,
        parameter: str,
        payload: str,
        detection_reason: str,
        baseline: dict[str, Any],
        injected: dict[str, Any],
        indicators: list[str],
    ) -> dict[str, Any]:
        """
        Asks Gemini to analyze the vulnerability context and identify its exact type, CVSS, and custom remediation.
        """
        prompt = f"""
You are a SQL Injection Classification and Remediation Agent. Your job is to classify the specific subtype of SQL injection vulnerability found, assign a CVSS score, severity, and write remediation guidance.

Vulnerability Information:
- Endpoint: {endpoint}
- Parameter: {parameter}
- Successful Payload: {payload}
- Detection Reason: {detection_reason}
- Scanner Indicators: {indicators}

Baseline Response Snippet:
{baseline.get('response_body', '')[:400]}

Injected Response Snippet:
{injected.get('response_body', '')[:400]}

Based on this, please determine:
1. The type of SQL Injection (e.g. Classic Error-Based, UNION-Based, Blind Boolean-Based, Time-Based Blind, Stacked Queries, Auth Bypass).
2. The severity (CRITICAL, HIGH, MEDIUM, LOW).
3. A fair CVSS v3 score (e.g. 9.8 for critical, 7.5 for high, etc.).
4. The key indicators observed.
5. Remediation advice.

Return JSON format matching the schema:
{{
  "sqli_type": "The exact SQL Injection type",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "cvss_score": number,
  "evidence": "Detailed explanation of the exploit evidence",
  "remediation": "Actionable instructions to fix this vulnerability"
}}
"""
        try:
            result_str = self.client.generate(prompt, json_mode=True)
            return json.loads(result_str)
        except Exception as e:
            logger.warning("Gemini classification call failed: %s", e)
            return {
                "sqli_type": "SQL Injection",
                "severity": "HIGH",
                "cvss_score": 8.5,
                "evidence": f"Vulnerability detected on parameter '{parameter}'. Classification failed: {e}",
                "remediation": "Use parameterized queries or prepared statements for all database queries."
            }
