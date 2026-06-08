"""
Paramiko-based SSH client for connecting to Linux servers
and executing read-only security audit commands.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from typing import Any

import paramiko

logger = logging.getLogger(__name__)


class SSHConnectionError(Exception):
    """Raised when SSH connection or command execution fails."""

    def __init__(self, message: str, error_type: str = "connection_error"):
        super().__init__(message)
        self.error_type = error_type


@dataclass
class AuditCommand:
    """Definition of a read-only audit command."""

    key: str
    command: str
    description: str


# Read-only audit commands executed on the target Linux host
AUDIT_COMMANDS: list[AuditCommand] = [
    AuditCommand(
        "permit_root_login",
        'grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null || echo "NOT_FOUND"',
        "SSH root login configuration",
    ),
    AuditCommand(
        "password_authentication",
        'grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null || echo "NOT_FOUND"',
        "SSH password authentication setting",
    ),
    AuditCommand(
        "ufw_status",
        "ufw status 2>/dev/null || echo 'UFW_NOT_INSTALLED'",
        "Uncomplicated Firewall status",
    ),
    AuditCommand(
        "open_ports",
        "ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo 'SS_NOT_AVAILABLE'",
        "Listening network ports",
    ),
    AuditCommand(
        "root_password_status",
        "passwd -S root 2>/dev/null || echo 'PASSWD_CHECK_FAILED'",
        "Root account password status",
    ),
    AuditCommand(
        "ssh_service_enabled",
        "systemctl is-enabled ssh 2>/dev/null || systemctl is-enabled sshd 2>/dev/null || echo 'UNKNOWN'",
        "SSH service enabled state",
    ),
    AuditCommand(
        "os_release",
        "cat /etc/os-release 2>/dev/null || echo 'OS_RELEASE_NOT_FOUND'",
        "Operating system release information",
    ),
    AuditCommand(
        "kernel_info",
        "uname -a 2>/dev/null || echo 'UNAME_FAILED'",
        "Kernel and system information",
    ),
]


@dataclass
class SSHClient:
    """Wrapper around Paramiko for SSH connectivity and audit execution."""

    host: str
    username: str
    password: str
    timeout: int = 15
    command_timeout: int = 30
    _client: paramiko.SSHClient | None = field(default=None, repr=False)

    def connect(self) -> dict[str, Any]:
        """
        Establish SSH connection to the target host.

        Returns:
            dict with connection metadata on success.

        Raises:
            SSHConnectionError: On authentication, timeout, or network failure.
        """
        self.disconnect()

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.host,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException as exc:
            logger.warning("SSH authentication failed for %s@%s", self.username, self.host)
            raise SSHConnectionError(
                "Invalid SSH credentials. Please verify username and password.",
                error_type="auth_error",
            ) from exc
        except paramiko.SSHException as exc:
            logger.error("SSH protocol error for %s: %s", self.host, exc)
            raise SSHConnectionError(
                f"SSH protocol error: {exc}",
                error_type="ssh_error",
            ) from exc
        except socket.timeout as exc:
            logger.error("SSH connection timeout for %s", self.host)
            raise SSHConnectionError(
                f"Connection timed out after {self.timeout} seconds.",
                error_type="timeout",
            ) from exc
        except socket.gaierror as exc:
            logger.error("DNS resolution failed for %s", self.host)
            raise SSHConnectionError(
                f"Unable to resolve host '{self.host}'. Check the IP/hostname.",
                error_type="dns_error",
            ) from exc
        except OSError as exc:
            logger.error("Network error connecting to %s: %s", self.host, exc)
            raise SSHConnectionError(
                f"Network error: {exc}",
                error_type="network_error",
            ) from exc

        self._client = client
        logger.info("SSH connected to %s@%s", self.username, self.host)

        return {
            "connected": True,
            "host": self.host,
            "username": self.username,
            "message": f"Successfully connected to {self.host}",
        }

    def disconnect(self) -> None:
        """Close the active SSH connection if open."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def is_connected(self) -> bool:
        """Return True if an active transport exists."""
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    def execute_command(self, command: str) -> dict[str, str]:
        """
        Execute a single command over SSH.

        Returns:
            dict with stdout, stderr, exit_code, and command fields.
        """
        if not self.is_connected():
            raise SSHConnectionError(
                "Not connected to SSH server. Please connect first.",
                error_type="not_connected",
            )

        assert self._client is not None

        try:
            stdin, stdout, stderr = self._client.exec_command(
                command, timeout=self.command_timeout
            )
            del stdin  # read-only commands do not need stdin

            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()
        except socket.timeout as exc:
            raise SSHConnectionError(
                f"Command timed out after {self.command_timeout}s: {command}",
                error_type="command_timeout",
            ) from exc
        except Exception as exc:
            raise SSHConnectionError(
                f"Failed to execute command: {exc}",
                error_type="command_error",
            ) from exc

        return {
            "command": command,
            "stdout": out,
            "stderr": err,
            "exit_code": str(exit_code),
        }

    def run_audit(self) -> dict[str, Any]:
        """
        Execute all read-only audit commands and return structured JSON.

        Returns:
            Structured audit payload with server info and command outputs.
        """
        if not self.is_connected():
            raise SSHConnectionError(
                "Not connected to SSH server. Please connect first.",
                error_type="not_connected",
            )

        results: dict[str, Any] = {}
        errors: list[str] = []

        for audit_cmd in AUDIT_COMMANDS:
            try:
                output = self.execute_command(audit_cmd.command)
                results[audit_cmd.key] = {
                    "description": audit_cmd.description,
                    "command": audit_cmd.command,
                    "output": output["stdout"] or output["stderr"] or "(empty)",
                    "exit_code": output["exit_code"],
                }
            except SSHConnectionError as exc:
                errors.append(f"{audit_cmd.key}: {exc}")
                results[audit_cmd.key] = {
                    "description": audit_cmd.description,
                    "command": audit_cmd.command,
                    "output": f"ERROR: {exc}",
                    "exit_code": "-1",
                }

        # Parse server information from audit results
        server_info = self._parse_server_info(results)

        return {
            "host": self.host,
            "username": self.username,
            "server_info": server_info,
            "audit_results": results,
            "errors": errors,
        }

    @staticmethod
    def _parse_server_info(audit_results: dict[str, Any]) -> dict[str, str]:
        """Extract human-readable server metadata from audit output."""
        os_release_raw = audit_results.get("os_release", {}).get("output", "")
        kernel_raw = audit_results.get("kernel_info", {}).get("output", "")

        os_name = "Unknown"
        os_version = "Unknown"

        for line in os_release_raw.splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("VERSION_ID=") and os_version == "Unknown":
                os_version = line.split("=", 1)[1].strip().strip('"')

        return {
            "os_name": os_name,
            "os_version": os_version,
            "kernel": kernel_raw,
        }
