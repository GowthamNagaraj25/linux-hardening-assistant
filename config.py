"""
Application configuration for Linux Hardening Assistant.
Loads settings from environment variables with sensible defaults.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Flask application configuration."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me-in-production")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

    # SQLite database path
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH", str(BASE_DIR / "database" / "audits.db")
    )

    # SSH connection settings
    SSH_TIMEOUT = int(os.environ.get("SSH_TIMEOUT", "15"))
    SSH_COMMAND_TIMEOUT = int(os.environ.get("SSH_COMMAND_TIMEOUT", "30"))

    # Reports directory for generated fix scripts
    REPORTS_DIR = BASE_DIR / "reports"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Flask settings
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
    PORT = int(os.environ.get("FLASK_PORT", "5000"))
