"""
SQLite database models and operations for storing audit history.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator


class AuditDatabase:
    """Manages SQLite persistence for security audit records."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create tables if they do not exist."""
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    server_ip TEXT NOT NULL,
                    username TEXT,
                    security_score INTEGER NOT NULL,
                    server_info TEXT,
                    findings TEXT NOT NULL,
                    audit_data TEXT,
                    report_summary TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_server_ip
                ON audit_history (server_ip)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_created_at
                ON audit_history (created_at)
                """
            )

    def save_audit(
        self,
        server_ip: str,
        security_score: int,
        findings: list[dict[str, Any]],
        username: str = "",
        server_info: dict[str, Any] | None = None,
        audit_data: dict[str, Any] | None = None,
        report_summary: str = "",
    ) -> int:
        """
        Persist an audit record and return its database ID.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_history
                (created_at, server_ip, username, security_score,
                 server_info, findings, audit_data, report_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    server_ip,
                    username,
                    security_score,
                    json.dumps(server_info or {}),
                    json.dumps(findings),
                    json.dumps(audit_data or {}),
                    report_summary,
                ),
            )
            return int(cursor.lastrowid)

    def get_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent audit records for the dashboard history panel."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, server_ip, username, security_score,
                       server_info, findings, report_summary
                FROM audit_history
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        history: list[dict[str, Any]] = []
        for row in rows:
            findings = json.loads(row["findings"])
            server_info = json.loads(row["server_info"]) if row["server_info"] else {}

            history.append(
                {
                    "id": row["id"],
                    "date": row["created_at"],
                    "server_ip": row["server_ip"],
                    "username": row["username"],
                    "security_score": row["security_score"],
                    "server_info": server_info,
                    "findings_count": {
                        "high": sum(1 for f in findings if f.get("severity") == "High"),
                        "medium": sum(1 for f in findings if f.get("severity") == "Medium"),
                        "low": sum(1 for f in findings if f.get("severity") == "Low"),
                    },
                    "findings": findings,
                    "report_summary": row["report_summary"],
                }
            )

        return history

    def get_audit_by_id(self, audit_id: int) -> dict[str, Any] | None:
        """Fetch a single audit record by ID."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM audit_history WHERE id = ?
                """,
                (audit_id,),
            ).fetchone()

        if row is None:
            return None

        return {
            "id": row["id"],
            "date": row["created_at"],
            "server_ip": row["server_ip"],
            "username": row["username"],
            "security_score": row["security_score"],
            "server_info": json.loads(row["server_info"]) if row["server_info"] else {},
            "findings": json.loads(row["findings"]),
            "audit_data": json.loads(row["audit_data"]) if row["audit_data"] else {},
            "report_summary": row["report_summary"],
        }

    def get_trend_data(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return score trend data for chart visualization."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT created_at, server_ip, security_score
                FROM audit_history
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            {
                "date": row["created_at"],
                "server_ip": row["server_ip"],
                "score": row["security_score"],
            }
            for row in rows
        ]
