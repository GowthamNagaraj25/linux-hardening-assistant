"""SSH package for Linux Hardening Assistant."""

from ssh.ssh_client import SSHClient, SSHConnectionError

__all__ = ["SSHClient", "SSHConnectionError"]
