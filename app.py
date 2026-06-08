"""
Flask application entry point for AI-Powered Linux Hardening Assistant.

Provides REST API endpoints and serves the dashboard UI.
"""

from __future__ import annotations

import io
import logging
import uuid
from datetime import datetime
from typing import Any

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file,
    session,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from agent.agent import HardeningAgent
from agent.analyzer import GeminiAnalyzerError
from config import Config
from database.models import AuditDatabase
from demo.demo_data import build_demo_report
from ssh.ssh_client import SSHClient, SSHConnectionError

# Load environment variables from .env file
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# In-memory store for active SSH sessions and latest analysis results
_ssh_sessions: dict[str, SSHClient] = {}
_analysis_cache: dict[str, dict[str, Any]] = {}

db = AuditDatabase(Config.DATABASE_PATH)


def _get_session_id() -> str:
    """Ensure each browser session has a unique identifier."""
    if "session_id" not in session:
        session["session_id"] = str(uuid.uuid4())
    return session["session_id"]


def _get_ssh_client() -> SSHClient | None:
    """Retrieve the SSH client for the current browser session."""
    session_id = _get_session_id()
    return _ssh_sessions.get(session_id)


def _get_agent() -> HardeningAgent:
    """Create a configured HardeningAgent instance."""
    return HardeningAgent(
        gemini_api_key=Config.GEMINI_API_KEY,
        gemini_model=Config.GEMINI_MODEL,
        ssh_timeout=Config.SSH_TIMEOUT,
        ssh_command_timeout=Config.SSH_COMMAND_TIMEOUT,
    )


def _error_response(message: str, error_type: str = "error", status: int = 400):
    """Standard JSON error response."""
    return jsonify({"success": False, "error": message, "error_type": error_type}), status


@app.route("/")
def index():
    """Serve the main dashboard."""
    return render_template("index.html")


@app.route("/connect", methods=["POST"])
def connect():
    """
    POST /connect
    Establish SSH connection to a Linux server.
    """
    data = request.get_json(silent=True) or {}

    host = (data.get("host") or data.get("ip") or "").strip()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not host or not username or not password:
        return _error_response(
            "Host, username, and password are required.",
            "validation_error",
        )

    session_id = _get_session_id()

    # Disconnect existing session if any
    if session_id in _ssh_sessions:
        _ssh_sessions[session_id].disconnect()

    client = SSHClient(
        host=host,
        username=username,
        password=password,
        timeout=Config.SSH_TIMEOUT,
        command_timeout=Config.SSH_COMMAND_TIMEOUT,
    )

    try:
        result = client.connect()
        _ssh_sessions[session_id] = client

        # Store connection info in Flask session (not the password)
        session["ssh_host"] = host
        session["ssh_username"] = username

        return jsonify({"success": True, **result})
    except SSHConnectionError as exc:
        return _error_response(str(exc), exc.error_type, 401 if exc.error_type == "auth_error" else 503)


@app.route("/audit", methods=["POST"])
def audit():
    """
    POST /audit
    Run read-only security audit commands on the connected server.
    """
    client = _get_ssh_client()
    if client is None or not client.is_connected():
        return _error_response(
            "Not connected to any server. Use /connect first.",
            "not_connected",
            400,
        )

    try:
        audit_data = client.run_audit()
        session_id = _get_session_id()

        # Cache audit data for subsequent analyze step
        _analysis_cache.setdefault(session_id, {})["audit_data"] = audit_data

        return jsonify({"success": True, "audit": audit_data})
    except SSHConnectionError as exc:
        return _error_response(str(exc), exc.error_type, 503)


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    POST /analyze
    Run the full AI agent workflow on collected audit data.
    """
    if not Config.GEMINI_API_KEY:
        return _error_response(
            "Gemini API key is not configured. Set GEMINI_API_KEY environment variable.",
            "missing_api_key",
            500,
        )

    data = request.get_json(silent=True) or {}
    session_id = _get_session_id()
    cache = _analysis_cache.get(session_id, {})

    audit_data = data.get("audit_data") or cache.get("audit_data")
    if not audit_data:
        return _error_response(
            "No audit data available. Run /audit first.",
            "missing_audit_data",
            400,
        )

    client = _get_ssh_client()
    host = session.get("ssh_host") or audit_data.get("host", "unknown")
    username = session.get("ssh_username") or audit_data.get("username", "")

    try:
        agent = _get_agent()
        report = agent.run_full_workflow(
            host=host,
            username=username,
            password="",  # Not needed when audit data is provided
            existing_audit=audit_data,
            ssh_client=client,
        )

        report_dict = report.to_dict()

        # Save fix script to reports directory
        script_path = Config.REPORTS_DIR / f"fix_{session_id[:8]}.sh"
        script_path.write_text(report.fix_script, encoding="utf-8")

        report_dict["fix_script_path"] = str(script_path.name)
        _analysis_cache[session_id] = {
            "audit_data": audit_data,
            "report": report_dict,
            "fix_script": report.fix_script,
        }

        # Persist to SQLite audit history
        audit_id = db.save_audit(
            server_ip=host,
            security_score=report.security_score,
            findings=report.findings,
            username=username,
            server_info=audit_data.get("server_info", {}),
            audit_data=audit_data,
            report_summary=report.executive_summary or report.summary,
        )
        report_dict["audit_id"] = audit_id

        return jsonify({"success": True, "report": report_dict})
    except ValueError as exc:
        return _error_response(str(exc), "missing_audit_data", 400)
    except GeminiAnalyzerError as exc:
        return _error_response(str(exc), exc.error_type, 502)
    except SSHConnectionError as exc:
        return _error_response(str(exc), exc.error_type, 503)


@app.route("/demo", methods=["POST"])
def demo_mode():
    """
    POST /demo
    Load sample audit data and a pre-built security report.
    No SSH connection or Gemini API required.
    """
    session_id = _get_session_id()
    payload = build_demo_report()

    audit_data = payload["audit"]
    report_dict = payload["report"]
    fix_script = report_dict["fix_script"]

    # Mark session as demo for PDF export and UI state
    session["demo_mode"] = True
    session["ssh_host"] = f"{audit_data['host']} (Demo)"
    session["ssh_username"] = audit_data["username"]

    script_path = Config.REPORTS_DIR / f"fix_demo_{session_id[:8]}.sh"
    script_path.write_text(fix_script, encoding="utf-8")

    _analysis_cache[session_id] = {
        "audit_data": audit_data,
        "report": report_dict,
        "fix_script": fix_script,
        "demo_mode": True,
    }

    # Persist demo run to history so trend chart updates
    audit_id = db.save_audit(
        server_ip=audit_data["host"],
        security_score=report_dict["security_score"],
        findings=report_dict["findings"],
        username=audit_data["username"],
        server_info=audit_data.get("server_info", {}),
        audit_data=audit_data,
        report_summary=report_dict["executive_summary"],
    )
    report_dict["audit_id"] = audit_id

    logger.info("Demo mode loaded for session %s", session_id[:8])

    return jsonify(
        {
            "success": True,
            "demo_mode": True,
            "audit": audit_data,
            "report": report_dict,
        }
    )


@app.route("/history", methods=["GET"])
def history():
    """
    GET /history
    Return audit history from SQLite database.
    """
    limit = request.args.get("limit", 50, type=int)
    records = db.get_history(limit=min(limit, 100))
    trend = db.get_trend_data(limit=20)

    return jsonify(
        {
            "success": True,
            "history": records,
            "trend": trend,
        }
    )


@app.route("/download-fix-script", methods=["GET"])
def download_fix_script():
    """
    GET /download-fix-script
    Download the generated fix.sh remediation script.
    """
    session_id = _get_session_id()
    cache = _analysis_cache.get(session_id, {})

    fix_script = cache.get("fix_script")
    if not fix_script:
        return _error_response(
            "No fix script available. Run analysis first.",
            "missing_fix_script",
            404,
        )

    buffer = io.BytesIO(fix_script.encode("utf-8"))
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/x-sh",
        as_attachment=True,
        download_name="fix.sh",
    )


@app.route("/export-pdf", methods=["GET"])
def export_pdf():
    """
    Bonus: Export the current audit report as a PDF document.
    """
    session_id = _get_session_id()
    cache = _analysis_cache.get(session_id, {})
    report = cache.get("report")

    if not report:
        return _error_response(
            "No report available. Run analysis first.",
            "missing_report",
            404,
        )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=12,
        spaceAfter=6,
    )

    host = session.get("ssh_host", "Unknown")
    elements.append(Paragraph("Linux Security Audit Report", title_style))
    elements.append(
        Paragraph(
            f"Server: {host} | Score: {report.get('security_score', 'N/A')}/100 | "
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(Paragraph("Executive Summary", heading_style))
    elements.append(
        Paragraph(
            report.get("executive_summary") or report.get("summary", "N/A"),
            styles["Normal"],
        )
    )

    for severity in ("High", "Medium", "Low"):
        findings = report.get("findings_by_severity", {}).get(severity, [])
        if not findings:
            continue

        elements.append(Paragraph(f"{severity} Risk Findings", heading_style))
        table_data = [["Issue", "Fix Command", "Recommendation"]]
        for f in findings:
            table_data.append(
                [
                    f.get("issue_name", ""),
                    f.get("fix_command", ""),
                    f.get("recommendation", ""),
                ]
            )

        table = Table(table_data, colWidths=[1.5 * inch, 2.5 * inch, 2.5 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212529")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 0.15 * inch))

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"security_report_{host.replace('.', '_')}.pdf",
    )


@app.route("/chat", methods=["POST"])
def chat():
    """
    Bonus: Chat with audit results using Gemini AI.
    """
    if not Config.GEMINI_API_KEY:
        return _error_response(
            "Gemini API key is not configured.",
            "missing_api_key",
            500,
        )

    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()

    if not question:
        return _error_response("Question is required.", "validation_error")

    session_id = _get_session_id()
    cache = _analysis_cache.get(session_id, {})
    audit_data = cache.get("audit_data")
    report = cache.get("report")

    if not audit_data or not report:
        return _error_response(
            "No audit report available. Connect, audit, and analyze first.",
            "missing_context",
            400,
        )

    try:
        agent = _get_agent()
        answer = agent.chat(question, audit_data, report)
        return jsonify({"success": True, "answer": answer})
    except ValueError as exc:
        return _error_response(str(exc), "validation_error")
    except GeminiAnalyzerError as exc:
        return _error_response(str(exc), exc.error_type, 502)


@app.route("/disconnect", methods=["POST"])
def disconnect():
    """Disconnect the active SSH session or clear demo mode."""
    session_id = _get_session_id()
    client = _ssh_sessions.pop(session_id, None)
    if client:
        client.disconnect()

    _analysis_cache.pop(session_id, None)
    session.pop("demo_mode", None)
    session.pop("ssh_host", None)
    session.pop("ssh_username", None)

    return jsonify({"success": True, "message": "Disconnected."})


@app.errorhandler(404)
def not_found(_error):
    return _error_response("Endpoint not found.", "not_found", 404)


@app.errorhandler(500)
def internal_error(_error):
    logger.exception("Internal server error")
    return _error_response("Internal server error.", "server_error", 500)


if __name__ == "__main__":
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
    )
