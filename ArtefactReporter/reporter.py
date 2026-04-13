import logging

from Domain.file_under_investigation import FileUnderInvestigation
from ArtefactReporter.logger import CsvLoggingStrategy
from ArtefactReporter.mysqliteOutboundAdapter import MySQLiteOutboundAdapter

logger = logging.getLogger(__name__)

_DEFAULT_CSV_PATH = "forensic_report.csv"
_DEFAULT_DB_PATH  = "forensic_report.db"


class Reporter:
    """
    Appends every investigated file to two persistent stores:

      1. forensic_report.csv  — one new row per file (via CsvLoggingStrategy)
      2. forensic_report.db   — one new row per file (via MySQLiteOutboundAdapter)

    Both outputs share the same column set, mirroring every field of
    FileUnderInvestigation:
        name | size | path | created_at | modified_at | last_accessed_at | sha256 | md5
    """

    def __init__(
        self,
        csv_path: str = _DEFAULT_CSV_PATH,
        db_path:  str = _DEFAULT_DB_PATH,
    ) -> None:
        self._csv     = CsvLoggingStrategy(csv_path)
        self._adapter = MySQLiteOutboundAdapter(db_path)

    def report(self, file: FileUnderInvestigation) -> None:
        """
        Persist *file* to both the CSV report and the SQLite database.
        Called once per identified file, regardless of whether the type
        is known or unknown.
        """
        # --- CSV: append new row ---
        self._csv.log(file)

        # --- SQLite: insert new row ---
        self._adapter.store(file)

        logger.info(
            "Report appended: %s | size=%d | sha256=%s | md5=%s | path=%s | "
            "created=%s | modified=%s | accessed=%s",
            file.name, file.size, file.sha256, file.md5, file.path,
            file.created_at.isoformat(), file.modified_at.isoformat(),
            file.last_accessed_at.isoformat(),
        )
