"""
Gemini API integration for Linux security analysis.
Handles API calls, JSON parsing, and error recovery.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import google.generativeai as genai

from agent.prompts import (
    CHAT_PROMPT,
    FINAL_REPORT_PROMPT,
    SECURITY_AUDIT_PROMPT,
    VERIFICATION_PROMPT,
)

logger = logging.getLogger(__name__)


class GeminiAnalyzerError(Exception):
    """Raised when Gemini API analysis fails."""

    def __init__(self, message: str, error_type: str = "gemini_error"):
        super().__init__(message)
        self.error_type = error_type


class GeminiAnalyzer:
    """Wrapper for Google Gemini API security analysis."""

    def __init__(self, api_key: str, model_name: str = "gemini-2.0-flash"):
        if not api_key:
            raise GeminiAnalyzerError(
                "Gemini API key is not configured. Set GEMINI_API_KEY in your environment.",
                error_type="missing_api_key",
            )

        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)
        self.model_name = model_name

    def _call_gemini(self, prompt: str) -> str:
        """Execute a Gemini API call with error handling."""
        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.2,
                    max_output_tokens=8192,
                ),
            )
            text = response.text if hasattr(response, "text") else str(response)
            if not text:
                raise GeminiAnalyzerError(
                    "Gemini returned an empty response.",
                    error_type="empty_response",
                )
            return text.strip()
        except GeminiAnalyzerError:
            raise
        except Exception as exc:
            logger.exception("Gemini API call failed")
            raise GeminiAnalyzerError(
                f"Gemini API failure: {exc}",
                error_type="api_failure",
            ) from exc

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        """Parse JSON from Gemini response, handling markdown fences."""
        cleaned = text.strip()

        # Remove markdown code fences if present
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if fence_match:
            cleaned = fence_match.group(1).strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Attempt to find JSON object in response
            brace_match = re.search(r"\{[\s\S]*\}", cleaned)
            if brace_match:
                try:
                    return json.loads(brace_match.group(0))
                except json.JSONDecodeError as exc:
                    raise GeminiAnalyzerError(
                        f"Failed to parse Gemini JSON response: {exc}",
                        error_type="json_parse_error",
                    ) from exc

            raise GeminiAnalyzerError(
                "Failed to parse Gemini response as JSON.",
                error_type="json_parse_error",
            )

    def analyze_security(self, audit_data: dict[str, Any]) -> dict[str, Any]:
        """
        Step 2: Analyze security risks from audit data.
        """
        prompt = SECURITY_AUDIT_PROMPT.format(
            audit_data=json.dumps(audit_data, indent=2)
        )
        raw = self._call_gemini(prompt)
        result = self._extract_json(raw)
        return self._normalize_analysis(result)

    def verify_recommendations(
        self,
        audit_data: dict[str, Any],
        initial_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Step 4: Verify and refine AI recommendations.
        """
        prompt = VERIFICATION_PROMPT.format(
            audit_data=json.dumps(audit_data, indent=2),
            initial_analysis=json.dumps(initial_analysis, indent=2),
        )
        raw = self._call_gemini(prompt)
        result = self._extract_json(raw)
        return self._normalize_analysis(result, include_verification=True)

    def generate_final_report(self, verified_analysis: dict[str, Any]) -> dict[str, Any]:
        """
        Step 5: Produce executive final report metadata.
        """
        prompt = FINAL_REPORT_PROMPT.format(
            verified_analysis=json.dumps(verified_analysis, indent=2)
        )
        raw = self._call_gemini(prompt)
        return self._extract_json(raw)

    def chat_with_context(
        self,
        question: str,
        audit_context: dict[str, Any],
        report_context: dict[str, Any],
    ) -> str:
        """Bonus: Chat with audit results using Gemini."""
        prompt = CHAT_PROMPT.format(
            audit_context=json.dumps(audit_context, indent=2),
            report_context=json.dumps(report_context, indent=2),
            question=question,
        )
        return self._call_gemini(prompt)

    @staticmethod
    def _normalize_analysis(
        data: dict[str, Any],
        include_verification: bool = False,
    ) -> dict[str, Any]:
        """Validate and normalize analysis JSON structure."""
        score = data.get("security_score", 50)
        try:
            score = max(0, min(100, int(score)))
        except (TypeError, ValueError):
            score = 50

        findings_raw = data.get("findings", [])
        if not isinstance(findings_raw, list):
            findings_raw = []

        normalized_findings: list[dict[str, str]] = []
        for item in findings_raw:
            if not isinstance(item, dict):
                continue

            severity = str(item.get("severity", "Low")).capitalize()
            if severity not in ("High", "Medium", "Low"):
                severity = "Low"

            normalized_findings.append(
                {
                    "issue_name": str(item.get("issue_name", "Unknown Issue")),
                    "severity": severity,
                    "explanation": str(item.get("explanation", "")),
                    "fix_command": str(item.get("fix_command", "")),
                    "recommendation": str(item.get("recommendation", "")),
                }
            )

        result: dict[str, Any] = {
            "security_score": score,
            "summary": str(data.get("summary", "")),
            "findings": normalized_findings,
            "findings_by_severity": GeminiAnalyzer._classify_findings(
                normalized_findings
            ),
        }

        if include_verification:
            result["verification_notes"] = str(data.get("verification_notes", ""))

        return result

    @staticmethod
    def _classify_findings(
        findings: list[dict[str, str]],
    ) -> dict[str, list[dict[str, str]]]:
        """Step 3: Classify risks by severity category."""
        classified: dict[str, list[dict[str, str]]] = {
            "High": [],
            "Medium": [],
            "Low": [],
        }
        for finding in findings:
            severity = finding.get("severity", "Low")
            if severity in classified:
                classified[severity].append(finding)
        return classified

    @staticmethod
    def generate_fix_script(findings: list[dict[str, str]]) -> str:
        """Generate downloadable fix.sh bash script from findings."""
        lines = [
            "#!/bin/bash",
            "# Linux Hardening Fix Script",
            "# Generated by AI-Powered Linux Hardening Assistant",
            "# Review all commands before executing on production systems.",
            "",
            "set -euo pipefail",
            "",
            'echo "Starting Linux hardening remediation..."',
            "",
        ]

        seen_commands: set[str] = set()
        for finding in findings:
            cmd = finding.get("fix_command", "").strip()
            if not cmd or cmd in seen_commands:
                continue
            seen_commands.add(cmd)
            issue = finding.get("issue_name", "Fix")
            lines.append(f"# Fix: {issue}")
            lines.append(cmd)
            lines.append("")

        lines.extend(
            [
                'echo "Remediation script completed."',
                'echo "Please reboot or restart affected services if required."',
            ]
        )

        return "\n".join(lines) + "\n"
