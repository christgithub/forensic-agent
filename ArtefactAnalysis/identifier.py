import asyncio
import logging
from pathlib import Path
import magic

from Domain.file_under_investigation import FileUnderInvestigation
from Domain.allowed_extensions import ALLOWED_EXTENSIONS
from ArtefactAnalysis.archiver import Archiver
from ArtefactReporter.reporter import Reporter


logger = logging.getLogger(__name__)


class Identifier:
    def __init__(self):
        self.allowed_extensions = ALLOWED_EXTENSIONS

    def identify_file(self, file_path: str, sha256: str = "", md5: str = "") -> dict:
        path = Path(file_path)
        extension = path.suffix.lower()

        # We open the file in read-only mode, preventing any write access to the evidence
        with open(path, "rb") as fh:
            data = fh.read()

        expected_mime = self.allowed_extensions.get(extension)
        detected_mime = magic.from_buffer(data, mime=True)
        detected_description = magic.from_buffer(data)

        extension_allowed = expected_mime is not None
        header_matches = expected_mime == detected_mime if expected_mime else False

        return {
            "file": str(path),
            "extension": extension,
            "expected_mime": expected_mime,
            "detected_mime": detected_mime,
            "description": detected_description,
            "extension_allowed": extension_allowed,
            "header_matches": header_matches,
            "is_valid": extension_allowed and header_matches,
            "sha256": sha256,
            "md5": md5,
        }


class IdentifierWorker:
    def __init__(
        self,
        input_queue: asyncio.Queue,
        output_queue: asyncio.Queue,
        archiver: Archiver | None = None,
        reporter: Reporter | None = None,
    ) -> None:
        self.input_queue = input_queue
        self.output_queue = output_queue
        self._identifier = Identifier()
        self._archiver = archiver or Archiver()
        self._reporter = reporter or Reporter()

    async def start(self) -> None:
        logger.info("IdentifierWorker started.")

        while True:
            file_investigated: FileUnderInvestigation = await self.input_queue.get()
            try:
                if file_investigated is None:
                    await self.output_queue.put(None)
                    continue

                result = await asyncio.to_thread(
                    self._identifier.identify_file,
                    file_investigated.path,
                    sha256=file_investigated.sha256,
                    md5=file_investigated.md5,
                )

                logger.info(
                    "Identified: %s  extension=%s  mime=%s  sha256=%s  md5=%s  valid=%s",
                    result['file'],
                    result['extension'],
                    result['detected_mime'],
                    result['sha256'],
                    result['md5'],
                    result['is_valid'],
                )

                await asyncio.to_thread(self._reporter.report, file_investigated)

                if not result["is_valid"]:
                    logger.warning("Unknown type — archiving '%s'", file_investigated.name)
                    await asyncio.to_thread(self._archiver.archive, file_investigated)
                else:
                    await self.output_queue.put({
                        "file":           file_investigated,
                        "identification": result,
                    })

            finally:
                self.input_queue.task_done()
