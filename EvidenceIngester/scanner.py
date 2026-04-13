import asyncio
import logging
from watchfiles import awatch, Change

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, watch_path: str, queue: asyncio.Queue):
        self.watch_path = watch_path
        self.queue = queue

    async def start(self):
        logger.info("Scanner started. Watching: %s", self.watch_path)

        async for changes in awatch(self.watch_path):
            await self._handle_changes(changes)

    async def _handle_changes(self, changes):
        for change, file_path in changes:

            if change == Change.added:
                logger.info("New file detected: %s", file_path)
                await self.queue.put(file_path)
