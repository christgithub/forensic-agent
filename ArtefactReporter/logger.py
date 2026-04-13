import csv
import logging
from abc import ABC, abstractmethod
from pathlib import Path

from Domain.file_under_investigation import FileUnderInvestigation
from ArtefactReporter.mysqliteOutboundAdapter import MySQLiteOutboundAdapter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CSV column order — mirrors FileUnderInvestigation field declaration order
# ---------------------------------------------------------------------------
_CSV_FIELDS = [
    "name",
    "size",
    "path",
    "created_at",
    "modified_at",
    "last_accessed_at",
    "sha256",
    "md5",
    "status",
]


# ---------------------------------------------------------------------------
# Abstract strategy
# ---------------------------------------------------------------------------

class LoggingStrategy(ABC):
    """Contract that every concrete logging strategy must satisfy."""

    @abstractmethod
    def log(self, file: FileUnderInvestigation) -> None:
        """Persist / emit a single analysed-file record."""


# ---------------------------------------------------------------------------
# Concrete strategy 1 — CSV
# ---------------------------------------------------------------------------

class CsvLoggingStrategy(LoggingStrategy):
    """
    Appends one row per analysed file to a CSV report.

    The file is created with a header on first write; subsequent calls
    append rows without rewriting the header.
    """

    def __init__(self, csv_path: str = "forensic_report.csv") -> None:
        self.csv_path = Path(csv_path)

    def _header_is_valid(self) -> bool:
        """Return True if the CSV file already has the correct header row."""
        try:
            with self.csv_path.open(mode="r", newline="", encoding="utf-8") as fh:
                existing = next(csv.reader(fh), [])
            return existing == _CSV_FIELDS
        except (OSError, StopIteration):
            return False

    def log(self, file: FileUnderInvestigation) -> None:
        file_exists_and_nonempty = self.csv_path.exists() and self.csv_path.stat().st_size > 0

        # If the file exists but has a stale header (e.g. schema changed),
        # remove it so it is recreated with the correct header below.
        if file_exists_and_nonempty and not self._header_is_valid():
            self.csv_path.unlink()
            file_exists_and_nonempty = False

        write_header = not file_exists_and_nonempty

        with self.csv_path.open(mode="a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS)

            if write_header:
                writer.writeheader()

            writer.writerow({
                "name":             file.name,
                "size":             file.size,
                "path":             file.path,
                "created_at":       file.created_at.isoformat(),
                "modified_at":      file.modified_at.isoformat(),
                "last_accessed_at": file.last_accessed_at.isoformat(),
                "sha256":           file.sha256,
                "md5":              file.md5,
                "status":           file.status,
            })

        logger.info(
            "CSV logged: %s | size=%d | sha256=%s | md5=%s | path=%s | "
            "created=%s | modified=%s | accessed=%s | status=%s",
            file.name, file.size, file.sha256, file.md5, file.path,
            file.created_at.isoformat(), file.modified_at.isoformat(),
            file.last_accessed_at.isoformat(), file.status,
        )


# ---------------------------------------------------------------------------
# Concrete strategy 2 — MySQLite
# ---------------------------------------------------------------------------

class MySQLiteLoggingStrategy(LoggingStrategy):
    """
    Inserts one row per analysed file into the SQLite database managed by
    MySQLiteOutboundAdapter.
    """

    def __init__(self, db_path: str = "forensic_report.db") -> None:
        self._adapter = MySQLiteOutboundAdapter(db_path)

    def log(self, file: FileUnderInvestigation) -> None:
        self._adapter.store(file)
        logger.info(
            "SQLite inserted: %s | size=%d | sha256=%s | md5=%s | path=%s | "
            "created=%s | modified=%s | accessed=%s | status=%s",
            file.name, file.size, file.sha256, file.md5, file.path,
            file.created_at.isoformat(), file.modified_at.isoformat(),
            file.last_accessed_at.isoformat(), file.status,
        )


# ---------------------------------------------------------------------------
# Logger façade
# ---------------------------------------------------------------------------

class Logger:
    """
    Façade that delegates to whichever LoggingStrategy is injected at
    construction time.

    Usage
    -----
    # Log to CSV
    logger = Logger(CsvLoggingStrategy("reports/forensic.csv"))

    # Log to SQLite
    logger = Logger(MySQLiteLoggingStrategy("forensic.db"))

    logger.log(file_under_investigation)
    """

    def __init__(self, strategy: LoggingStrategy) -> None:
        self._strategy = strategy

    @property
    def strategy(self) -> LoggingStrategy:
        return self._strategy

    @strategy.setter
    def strategy(self, strategy: LoggingStrategy) -> None:
        """Swap the strategy at runtime if needed."""
        self._strategy = strategy

    def log(self, file: FileUnderInvestigation) -> None:
        """Delegate logging to the active strategy."""
        self._strategy.log(file)
