import logging
import sqlite3
from pathlib import Path
from typing import List

from Domain.file_under_investigation import FileUnderInvestigation

logger = logging.getLogger(__name__)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS forensic_report (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL,
    size             INTEGER NOT NULL,
    path             TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    modified_at      TEXT    NOT NULL,
    last_accessed_at TEXT    NOT NULL,
    sha256           TEXT    NOT NULL,
    md5              TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'unknown',
    recorded_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""

_INSERT_SQL = """
INSERT INTO forensic_report
    (name, size, path, created_at, modified_at, last_accessed_at, sha256, md5, status)
VALUES
    (:name, :size, :path, :created_at, :modified_at, :last_accessed_at, :sha256, :md5, :status);
"""

_SELECT_ALL_SQL = "SELECT * FROM forensic_report ORDER BY recorded_at DESC;"


class MySQLiteOutboundAdapter:
    """
    Persists FileUnderInvestigation entries to a local SQLite database.

    The database file is created automatically on first use.
    Default path: <project_root>/forensic_report.db
    """

    def __init__(self, db_path: str = "forensic_report.db") -> None:
        self.db_path = Path(db_path)
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create the forensic_report table if it does not exist yet."""
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE_SQL)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(self, file: FileUnderInvestigation) -> None:
        """Persist a single FileUnderInvestigation entry."""
        with self._connect() as conn:
            conn.execute(
                _INSERT_SQL,
                {
                    "name":             file.name,
                    "size":             file.size,
                    "path":             file.path,
                    "created_at":       file.created_at.isoformat(),
                    "modified_at":      file.modified_at.isoformat(),
                    "last_accessed_at": file.last_accessed_at.isoformat(),
                    "sha256":           file.sha256,
                    "md5":              file.md5,
                    "status":           file.status,
                },
            )
        logger.info("Stored in DB: %s (sha256=%s… status=%s)", file.name, file.sha256[:12], file.status)

    def fetch_all(self) -> List[dict]:
        """Return every stored entry as a list of dicts (most recent first)."""
        with self._connect() as conn:
            rows = conn.execute(_SELECT_ALL_SQL).fetchall()
        return [dict(row) for row in rows]

