"""
Sample audit data and pre-built security report for Demo Mode.

Allows the dashboard to run without SSH or Gemini API access.
"""

from __future__ import annotations

from typing import Any

from agent.analyzer import GeminiAnalyzer

DEMO_HOST = "192.168.1.50"
DEMO_USERNAME = "demo"


def get_sample_audit_data() -> dict[str, Any]:
    """Return realistic sample Linux audit command output."""
    return {
        "host": DEMO_HOST,
        "username": DEMO_USERNAME,
        "server_info": {
            "os_name": "Ubuntu 22.04.4 LTS",
            "os_version": "22.04",
            "kernel": "Linux demo-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
        },
        "audit_results": {
            "permit_root_login": {
                "description": "SSH root login configuration",
                "command": 'grep "^PermitRootLogin" /etc/ssh/sshd_config',
                "output": "PermitRootLogin yes",
                "exit_code": "0",
            },
            "password_authentication": {
                "description": "SSH password authentication setting",
                "command": 'grep "^PasswordAuthentication" /etc/ssh/sshd_config',
                "output": "PasswordAuthentication yes",
                "exit_code": "0",
            },
            "ufw_status": {
                "description": "Uncomplicated Firewall status",
                "command": "ufw status",
                "output": "Status: inactive",
                "exit_code": "0",
            },
            "open_ports": {
                "description": "Listening network ports",
                "command": "ss -tuln",
                "output": (
                    "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                    "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\n"
                    "tcp   LISTEN 0      128          0.0.0.0:80        0.0.0.0:*\n"
                    "tcp   LISTEN 0      128          0.0.0.0:3306      0.0.0.0:*\n"
                    "tcp   LISTEN 0      128          0.0.0.0:6379      0.0.0.0:*\n"
                    "tcp   LISTEN 0      128                *:8080            *:*"
                ),
                "exit_code": "0",
            },
            "root_password_status": {
                "description": "Root account password status",
                "command": "passwd -S root",
                "output": "root P 01/15/2024 0 99999 7 -1",
                "exit_code": "0",
            },
            "ssh_service_enabled": {
                "description": "SSH service enabled state",
                "command": "systemctl is-enabled ssh",
                "output": "enabled",
                "exit_code": "0",
            },
            "os_release": {
                "description": "Operating system release information",
                "command": "cat /etc/os-release",
                "output": (
                    'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
                    'NAME="Ubuntu"\n'
                    'VERSION_ID="22.04"\n'
                    'ID=ubuntu'
                ),
                "exit_code": "0",
            },
            "kernel_info": {
                "description": "Kernel and system information",
                "command": "uname -a",
                "output": "Linux demo-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
                "exit_code": "0",
            },
        },
        "errors": [],
    }


def get_sample_findings() -> list[dict[str, str]]:
    """Pre-built findings covering High, Medium, and Low severity."""
    return [
        {
            "issue_name": "Root SSH Login Enabled",
            "severity": "High",
            "explanation": (
                "PermitRootLogin is set to 'yes', allowing direct root access over SSH. "
                "This increases the blast radius of credential compromise and brute-force attacks."
            ),
            "fix_command": (
                "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "
                "/etc/ssh/sshd_config && sudo systemctl restart ssh"
            ),
            "recommendation": (
                "Disable root SSH login and use sudo for privileged operations "
                "with individual user accounts."
            ),
        },
        {
            "issue_name": "SSH Password Authentication Enabled",
            "severity": "High",
            "explanation": (
                "PasswordAuthentication is enabled, exposing SSH to brute-force "
                "and credential-stuffing attacks."
            ),
            "fix_command": (
                "sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "
                "/etc/ssh/sshd_config && sudo systemctl restart ssh"
            ),
            "recommendation": (
                "Use SSH key-based authentication and disable password auth after "
                "confirming key access works."
            ),
        },
        {
            "issue_name": "Firewall Disabled",
            "severity": "Medium",
            "explanation": (
                "UFW is inactive, leaving all listening services exposed to the network "
                "without host-level filtering."
            ),
            "fix_command": "sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable",
            "recommendation": (
                "Enable UFW with a default-deny inbound policy and allow only required ports "
                "(e.g., 22/tcp for SSH)."
            ),
        },
        {
            "issue_name": "MySQL Exposed on All Interfaces",
            "severity": "Medium",
            "explanation": (
                "Port 3306 is listening on 0.0.0.0, potentially exposing the database "
                "to untrusted networks."
            ),
            "fix_command": (
                "sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "
                "/etc/mysql/mysql.conf.d/mysqld.cnf && sudo systemctl restart mysql"
            ),
            "recommendation": (
                "Bind database services to localhost or a private network interface "
                "and restrict access with firewall rules."
            ),
        },
        {
            "issue_name": "Redis Exposed Without Authentication",
            "severity": "Medium",
            "explanation": (
                "Port 6379 is listening on all interfaces. Unauthenticated Redis instances "
                "are a common target for remote code execution."
            ),
            "fix_command": (
                "sudo sed -i 's/^# requirepass.*/requirepass YOUR_STRONG_PASSWORD/' "
                "/etc/redis/redis.conf && sudo sed -i 's/^bind .*/bind 127.0.0.1/' "
                "/etc/redis/redis.conf && sudo systemctl restart redis"
            ),
            "recommendation": (
                "Bind Redis to localhost, require authentication, and disable dangerous commands."
            ),
        },
        {
            "issue_name": "Unnecessary HTTP Service on Port 80",
            "severity": "Low",
            "explanation": (
                "An HTTP service is listening on port 80. If not required, it expands "
                "the attack surface."
            ),
            "fix_command": "sudo systemctl disable --now apache2 || sudo systemctl disable --now nginx",
            "recommendation": (
                "Disable unused web services or place them behind a reverse proxy with TLS."
            ),
        },
        {
            "issue_name": "Development Server on Port 8080",
            "severity": "Low",
            "explanation": (
                "Port 8080 is open and may indicate a development server running in production."
            ),
            "fix_command": "sudo systemctl stop demo-app && sudo systemctl disable demo-app",
            "recommendation": (
                "Remove development services from production hosts or restrict access "
                "to trusted IP ranges."
            ),
        },
    ]


def build_demo_report() -> dict[str, Any]:
    """
    Build a complete demo report with audit data, findings, score, and fix script.
    """
    audit_data = get_sample_audit_data()
    findings = get_sample_findings()
    findings_by_severity = GeminiAnalyzer._classify_findings(findings)
    security_score = 58

    fix_script = GeminiAnalyzer.generate_fix_script(findings)

    workflow_steps = [
        {
            "step": "collect_data",
            "status": "success",
            "message": "Loaded sample audit data (demo mode — no SSH).",
            "data": {"source": "demo"},
        },
        {
            "step": "analyze",
            "status": "success",
            "message": f"Identified {len(findings)} findings from sample data.",
            "data": {
                "security_score": security_score,
                "high": len(findings_by_severity["High"]),
                "medium": len(findings_by_severity["Medium"]),
                "low": len(findings_by_severity["Low"]),
            },
        },
        {
            "step": "generate_fixes",
            "status": "success",
            "message": "Generated remediation fix script from sample findings.",
            "data": {"script_lines": fix_script.count("\n")},
        },
        {
            "step": "verify_recommendations",
            "status": "success",
            "message": "Verified sample recommendations against audit output.",
            "data": {"verification_notes": "Demo mode uses pre-validated sample findings."},
        },
        {
            "step": "produce_final_report",
            "status": "success",
            "message": "Demo security report ready.",
            "data": {},
        },
    ]

    summary = (
        "The demo server has several critical SSH misconfigurations and an inactive firewall. "
        "Multiple services are exposed on all network interfaces. Immediate hardening is recommended."
    )

    return {
        "success": True,
        "demo_mode": True,
        "audit": audit_data,
        "report": {
            "success": True,
            "demo_mode": True,
            "security_score": security_score,
            "summary": summary,
            "executive_summary": (
                "Security assessment of the demo Ubuntu 22.04 server reveals a score of 58/100. "
                "Critical issues include enabled root SSH login and password authentication. "
                "The host firewall is disabled and database/cache services are network-exposed."
            ),
            "findings": findings,
            "findings_by_severity": findings_by_severity,
            "fix_script": fix_script,
            "audit_data": audit_data,
            "priority_actions": [
                "Disable root SSH login",
                "Disable SSH password authentication",
                "Enable UFW firewall with default-deny policy",
            ],
            "compliance_notes": (
                "Demo findings align with CIS Benchmark recommendations for SSH hardening "
                "and network service exposure."
            ),
            "verification_notes": "Demo mode uses pre-validated sample findings.",
            "workflow_steps": workflow_steps,
        },
    }
