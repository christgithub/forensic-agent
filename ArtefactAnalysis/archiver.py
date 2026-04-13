import asyncio
import logging
import zipfile
from datetime import datetime
from pathlib import Path

from Domain.file_under_investigation import FileUnderInvestigation

logger = logging.getLogger(__name__)

_DEFAULT_ARCHIVE_DIR = "archives"


class Archiver:
    """
    Compresses a single file into a timestamped ZIP archive.

    Archive naming:
        <archive_dir>/<stem>_<sha256[:8]>_<YYYYMMDD_HHMMSS>.zip

    The original file is stored inside the ZIP under its own name so the
    archive is self-describing when opened on any platform.
    """

    def __init__(self, archive_dir: str = _DEFAULT_ARCHIVE_DIR) -> None:
        self.archive_dir = Path(archive_dir)
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    def archive(self, file: FileUnderInvestigation) -> dict:
        """
        Compress *file* into a ZIP archive.

        Returns
        -------
        dict with keys:
            archive_path  – absolute path of the created ZIP
            archive_size  – size of the ZIP in bytes
            original_name – original filename
            sha256        – hash of the original file
            md5           – hash of the original file
            archived_at   – ISO-8601 timestamp
        """
        source = Path(file.path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"{source.stem}_{file.sha256[:8]}_{timestamp}.zip"
        archive_path = self.archive_dir / archive_name

        with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(source, arcname=source.name)

            checksum_content = (
                f"File    : {source.name}\n"
                f"SHA-256 : {file.sha256}\n"
                f"MD5     : {file.md5}\n"
            )
            zf.writestr("checksum.txt", checksum_content)

        logger.info(
            "Archived: %s → %s  (original: %d bytes, archive: %d bytes)",
            source.name,
            archive_path,
            file.size,
            archive_path.stat().st_size,
        )

        return {
            "archive_path":  str(archive_path.absolute()),
            "archive_size":  archive_path.stat().st_size,
            "original_name": file.name,
            "sha256":        file.sha256,
            "md5":           file.md5,
            "archived_at":   datetime.now().isoformat(),
        }


class ArchiverWorker:
    """
    Async queue consumer that sits between IdentifierWorker and the Analyzer.

    Routing logic
    -------------
    • is_valid == False  → unknown file type  → compress with Archiver
    • is_valid == True   → known file type    → forward to *output_queue*

    Input item shape  (produced by IdentifierWorker):
        {
            "file":           FileUnderInvestigation,
            "identification": { ..., "is_valid": bool, ... },
        }

    Output item shape (forwarded to Analyzer):
        same dict, unchanged
    """

    def __init__(
        self,
        input_queue: asyncio.Queue,
        output_queue: asyncio.Queue,
        archive_dir: str = _DEFAULT_ARCHIVE_DIR,
    ) -> None:
        self.input_queue = input_queue
        self.output_queue = output_queue
        self._archiver = Archiver(archive_dir)

    async def start(self) -> None:
        logger.info("ArchiverWorker started.")

        while True:
            item: dict | None = await self.input_queue.get()
            try:
                if item is None:
                    await self.output_queue.put(None)
                    continue

                file: FileUnderInvestigation = item["file"]
                identification: dict = item["identification"]

                if not identification["is_valid"]:
                    logger.warning(
                        "Unknown type for '%s' (ext='%s', mime='%s') — archiving.",
                        file.name,
                        identification['extension'],
                        identification['detected_mime'],
                    )
                    await asyncio.to_thread(self._archiver.archive, file)
                else:
                    await self.output_queue.put(item)

            finally:
                self.input_queue.task_done()

