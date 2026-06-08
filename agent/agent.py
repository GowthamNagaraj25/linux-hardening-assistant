"""
AI Agent workflow for Linux Hardening Assistant.

Agent Loop (Mandatory):
  1. Collect Data
  2. Analyze
  3. Generate Fixes
  4. Verify Recommendations
  5. Produce Final Report
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agent.analyzer import GeminiAnalyzer, GeminiAnalyzerError
from ssh.ssh_client import SSHClient, SSHConnectionError

logger = logging.getLogger(__name__)


@dataclass
class AgentStepResult:
    """Result of a single agent workflow step."""

    step: str
    status: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class AgentReport:
    """Complete output from the hardening agent workflow."""

    success: bool
    security_score: int
    summary: str
    findings: list[dict[str, str]]
    findings_by_severity: dict[str, list[dict[str, str]]]
    fix_script: str
    audit_data: dict[str, Any]
    executive_summary: str
    priority_actions: list[str]
    compliance_notes: str
    workflow_steps: list[dict[str, Any]]
    verification_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize report for API responses."""
        return {
            "success": self.success,
            "security_score": self.security_score,
            "summary": self.summary,
            "findings": self.findings,
            "findings_by_severity": self.findings_by_severity,
            "fix_script": self.fix_script,
            "audit_data": self.audit_data,
            "executive_summary": self.executive_summary,
            "priority_actions": self.priority_actions,
            "compliance_notes": self.compliance_notes,
            "verification_notes": self.verification_notes,
            "workflow_steps": self.workflow_steps,
        }


class HardeningAgent:
    """
    Orchestrates the full AI-powered Linux hardening audit workflow.

    Workflow:
        Collect Data -> Analyze -> Generate Fixes -> Verify -> Final Report
    """

    def __init__(
        self,
        gemini_api_key: str,
        gemini_model: str = "gemini-2.0-flash",
        ssh_timeout: int = 15,
        ssh_command_timeout: int = 30,
    ):
        self.analyzer = GeminiAnalyzer(gemini_api_key, gemini_model)
        self.ssh_timeout = ssh_timeout
        self.ssh_command_timeout = ssh_command_timeout
        self.workflow_steps: list[AgentStepResult] = []

    def _record_step(
        self, step: str, status: str, message: str, data: dict[str, Any] | None = None
    ) -> None:
        """Record a workflow step for transparency in the dashboard."""
        self.workflow_steps.append(
            AgentStepResult(
                step=step,
                status=status,
                message=message,
                data=data or {},
            )
        )
        logger.info("Agent step [%s] %s: %s", step, status, message)

    def collect_data(
        self,
        host: str,
        username: str,
        password: str,
        existing_audit: dict[str, Any] | None = None,
        ssh_client: SSHClient | None = None,
    ) -> dict[str, Any]:
        """
        Step 1: Collect audit data via SSH or use pre-collected audit payload.
        """
        if existing_audit:
            self._record_step(
                "collect_data",
                "success",
                "Using pre-collected audit data.",
                {"source": "provided"},
            )
            return existing_audit

        client = ssh_client or SSHClient(
            host=host,
            username=username,
            password=password,
            timeout=self.ssh_timeout,
            command_timeout=self.ssh_command_timeout,
        )

        try:
            if not client.is_connected():
                client.connect()

            audit_data = client.run_audit()
            self._record_step(
                "collect_data",
                "success",
                f"Collected audit data from {host}.",
                {"commands_run": len(audit_data.get("audit_results", {}))},
            )
            return audit_data
        except SSHConnectionError as exc:
            self._record_step("collect_data", "failed", str(exc))
            raise

    def analyze(self, audit_data: dict[str, Any]) -> dict[str, Any]:
        """
        Step 2 & 3: Analyze security risks and classify by severity.
        """
        if not audit_data or not audit_data.get("audit_results"):
            self._record_step(
                "analyze",
                "failed",
                "Missing audit data. Run an audit first.",
            )
            raise ValueError("Missing audit data. Run an audit before analysis.")

        try:
            analysis = self.analyzer.analyze_security(audit_data)
            self._record_step(
                "analyze",
                "success",
                f"Identified {len(analysis.get('findings', []))} findings.",
                {
                    "security_score": analysis.get("security_score"),
                    "high": len(analysis.get("findings_by_severity", {}).get("High", [])),
                    "medium": len(
                        analysis.get("findings_by_severity", {}).get("Medium", [])
                    ),
                    "low": len(analysis.get("findings_by_severity", {}).get("Low", [])),
                },
            )
            return analysis
        except GeminiAnalyzerError as exc:
            self._record_step("analyze", "failed", str(exc))
            raise

    def generate_fixes(self, analysis: dict[str, Any]) -> str:
        """
        Step 3 (continued): Generate remediation fix script from findings.
        """
        findings = analysis.get("findings", [])
        fix_script = self.analyzer.generate_fix_script(findings)

        self._record_step(
            "generate_fixes",
            "success",
            f"Generated fix script with {len(findings)} remediation entries.",
            {"script_lines": fix_script.count("\n")},
        )
        return fix_script

    def verify_recommendations(
        self,
        audit_data: dict[str, Any],
        analysis: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Step 4: Verify AI recommendations against raw audit data.
        """
        try:
            verified = self.analyzer.verify_recommendations(audit_data, analysis)
            self._record_step(
                "verify_recommendations",
                "success",
                "Verified and refined recommendations.",
                {
                    "security_score": verified.get("security_score"),
                    "verification_notes": verified.get("verification_notes", ""),
                },
            )
            return verified
        except GeminiAnalyzerError as exc:
            self._record_step("verify_recommendations", "failed", str(exc))
            raise

    def produce_final_report(self, verified_analysis: dict[str, Any]) -> dict[str, Any]:
        """
        Step 5: Produce executive final report.
        """
        try:
            report_meta = self.analyzer.generate_final_report(verified_analysis)
            self._record_step(
                "produce_final_report",
                "success",
                "Final executive report generated.",
                report_meta,
            )
            return report_meta
        except GeminiAnalyzerError as exc:
            # Fallback report if final summary generation fails
            self._record_step(
                "produce_final_report",
                "partial",
                f"Using fallback report: {exc}",
            )
            return {
                "executive_summary": verified_analysis.get("summary", ""),
                "priority_actions": [
                    f.get("issue_name", "")
                    for f in verified_analysis.get("findings", [])[:3]
                ],
                "compliance_notes": "Review all findings and apply recommended fixes.",
            }

    def run_full_workflow(
        self,
        host: str,
        username: str,
        password: str,
        existing_audit: dict[str, Any] | None = None,
        ssh_client: SSHClient | None = None,
    ) -> AgentReport:
        """
        Execute the complete agent loop end-to-end.

        Collect Data -> Analyze -> Generate Fixes -> Verify -> Final Report
        """
        self.workflow_steps = []

        # Step 1: Collect Data
        audit_data = self.collect_data(
            host=host,
            username=username,
            password=password,
            existing_audit=existing_audit,
            ssh_client=ssh_client,
        )

        # Step 2 & 3: Analyze and Classify
        analysis = self.analyze(audit_data)

        # Step 3: Generate Fixes
        fix_script = self.generate_fixes(analysis)

        # Step 4: Verify Recommendations
        verified = self.verify_recommendations(audit_data, analysis)

        # Regenerate fix script from verified findings
        verified_fix_script = self.analyzer.generate_fix_script(
            verified.get("findings", [])
        )

        # Step 5: Produce Final Report
        final_meta = self.produce_final_report(verified)

        return AgentReport(
            success=True,
            security_score=verified.get("security_score", 0),
            summary=verified.get("summary", ""),
            findings=verified.get("findings", []),
            findings_by_severity=verified.get("findings_by_severity", {}),
            fix_script=verified_fix_script or fix_script,
            audit_data=audit_data,
            executive_summary=final_meta.get("executive_summary", ""),
            priority_actions=final_meta.get("priority_actions", []),
            compliance_notes=final_meta.get("compliance_notes", ""),
            verification_notes=verified.get("verification_notes", ""),
            workflow_steps=[step.__dict__ for step in self.workflow_steps],
        )

    def chat(
        self,
        question: str,
        audit_data: dict[str, Any],
        report: dict[str, Any],
    ) -> str:
        """Bonus feature: Chat with audit results."""
        if not question.strip():
            raise ValueError("Question cannot be empty.")
        if not audit_data:
            raise ValueError("Missing audit data for chat context.")

        return self.analyzer.chat_with_context(
            question=question,
            audit_context=audit_data,
            report_context=report,
        )
