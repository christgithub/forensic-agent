import asyncio
import hashlib
import logging
from pathlib import Path

from Domain.file_under_investigation import FileUnderInvestigation

logger = logging.getLogger(__name__)


async def hash_file(file_path: Path) -> dict:
    logger.info("Hashing file: %s", file_path)
    try:
        def compute_hashes():
            with open(file_path, 'rb') as f:
                data = f.read()

            sha256_hash = hashlib.sha256(data)
            md5_hash = hashlib.md5(data)

            return {
                'sha256': sha256_hash.hexdigest(),
                'md5': md5_hash.hexdigest()
            }

        loop = asyncio.get_event_loop()
        hashes = await loop.run_in_executor(None, compute_hashes)

        return {
            'file_path': str(file_path),
            'hashes': hashes,
            'status': 'success'
        }

    except Exception as e:
        return {
            'file_path': str(file_path),
            'error': str(e),
            'status': 'failed'
        }


class Hasher:
    def __init__(self, input_queue: asyncio.Queue, output_queue: asyncio.Queue):
        self.input_queue = input_queue
        self.output_queue = output_queue

    async def start(self):
        while True:
            file_path = await self.input_queue.get()
            file_investigated = None
            try:
                result = await hash_file(Path(file_path))

                if result['status'] == 'success':
                    logger.info(
                        "Hashed: %s  SHA-256: %s  MD5: %s",
                        result['file_path'],
                        result['hashes']['sha256'],
                        result['hashes']['md5'],
                    )

                    file_investigated = FileUnderInvestigation.from_path(
                        Path(result['file_path']),
                        sha256=result['hashes']['sha256'],
                        md5=result['hashes']['md5']
                    )
                    await self.output_queue.put(file_investigated)
                else:
                    logger.error(
                        "Failed to hash '%s' — file will NOT appear in the report: %s",
                        result['file_path'], result['error'],
                    )

            finally:
                self.input_queue.task_done()
