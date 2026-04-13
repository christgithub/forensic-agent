import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from watchfiles import Change

from EvidenceIngester.scanner import Scanner


def _make_scanner(watch_path: str = "/watched") -> tuple[Scanner, asyncio.Queue]:
    queue = asyncio.Queue()
    scanner = Scanner(watch_path, queue)
    return scanner, queue


async def _drain(queue: asyncio.Queue) -> list:
    """Return all items currently in the queue without blocking."""
    items = []
    while not queue.empty():
        items.append(await queue.get())
    return items


class TestScannerInit:

    def test_watch_path_is_stored(self):
        scanner, _ = _make_scanner("/evidence")
        assert scanner.watch_path == "/evidence"

    def test_queue_is_stored(self):
        queue = asyncio.Queue()
        scanner = Scanner("/evidence", queue)
        assert scanner.queue is queue


# ---------------------------------------------------------------------------
# We only care about file added event
# ---------------------------------------------------------------------------

class TestHandleChanges:

    @pytest.mark.asyncio
    async def test_added_file_is_put_on_queue(self):
        scanner, queue = _make_scanner()

        await scanner._handle_changes({(Change.added, "/watched/evidence.txt")})

        items = await _drain(queue)
        assert items == ["/watched/evidence.txt"]

    @pytest.mark.asyncio
    async def test_modified_file_is_not_put_on_queue(self):
        scanner, queue = _make_scanner()

        await scanner._handle_changes({(Change.modified, "/watched/evidence.txt")})

        assert queue.empty()

    @pytest.mark.asyncio
    async def test_deleted_file_is_not_put_on_queue(self):
        scanner, queue = _make_scanner()

        await scanner._handle_changes({(Change.deleted, "/watched/evidence.txt")})

        assert queue.empty()

    @pytest.mark.asyncio
    async def test_multiple_added_files_all_queued(self):
        scanner, queue = _make_scanner()

        await scanner._handle_changes({
            (Change.added, "/watched/file_a.txt"),
            (Change.added, "/watched/file_b.pdf"),
        })

        items = await _drain(queue)
        assert sorted(items) == sorted(["/watched/file_a.txt", "/watched/file_b.pdf"])

    @pytest.mark.asyncio
    async def test_mixed_changes_only_added_is_queued(self):
        scanner, queue = _make_scanner()

        await scanner._handle_changes({
            (Change.added, "/watched/new.txt"),
            (Change.modified, "/watched/existing.txt"),
            (Change.deleted, "/watched/old.txt"),
        })

        items = await _drain(queue)
        assert items == ["/watched/new.txt"]

    @pytest.mark.asyncio
    async def test_empty_changeset_leaves_queue_empty(self):
        scanner, queue = _make_scanner()

        await scanner._handle_changes(set())

        assert queue.empty()

    @pytest.mark.asyncio
    async def test_added_file_path_is_exact_string(self):
        """Queue entry must be the exact path string from the change event."""
        scanner, queue = _make_scanner()
        path = "/watched/subdir/report.pdf"

        await scanner._handle_changes({(Change.added, path)})

        item = await queue.get()
        assert item == path


class TestScannerStart:

    @pytest.mark.asyncio
    async def test_start_logs_watch_path(self):
        scanner, _ = _make_scanner("/evidence")

        async def _fake_awatch(*args, **kwargs):
            return
            yield  # make it an async generator

        with patch("EvidenceIngester.scanner.awatch", _fake_awatch), \
                patch("EvidenceIngester.scanner.logger") as mock_logger:
            await scanner.start()

        mock_logger.info.assert_called_once_with(
            "Scanner started. Watching: %s", "/evidence"
        )

    @pytest.mark.asyncio
    async def test_start_calls_awatch_with_watch_path(self):
        scanner, _ = _make_scanner("/evidence")
        captured = []

        async def _fake_awatch(path, **kwargs):
            captured.append(path)
            return
            yield

        with patch("EvidenceIngester.scanner.awatch", _fake_awatch):
            await scanner.start()

        assert captured == ["/evidence"]

    @pytest.mark.asyncio
    async def test_start_processes_changes_from_awatch(self):
        scanner, queue = _make_scanner("/watched")

        async def _fake_awatch(*args, **kwargs):
            yield {(Change.added, "/watched/evidence.txt")}

        with patch("EvidenceIngester.scanner.awatch", _fake_awatch):
            await scanner.start()

        items = await _drain(queue)
        assert items == ["/watched/evidence.txt"]

    @pytest.mark.asyncio
    async def test_start_processes_multiple_batches(self):
        scanner, queue = _make_scanner("/watched")

        async def _fake_awatch(*args, **kwargs):
            yield {(Change.added, "/watched/file1.txt")}
            yield {(Change.added, "/watched/file2.pdf")}

        with patch("EvidenceIngester.scanner.awatch", _fake_awatch):
            await scanner.start()

        items = await _drain(queue)
        assert sorted(items) == sorted(["/watched/file1.txt", "/watched/file2.pdf"])

    @pytest.mark.asyncio
    async def test_start_ignores_modified_and_deleted_events(self):
        scanner, queue = _make_scanner("/watched")

        async def _fake_awatch(*args, **kwargs):
            yield {
                (Change.modified, "/watched/existing.txt"),
                (Change.deleted, "/watched/old.txt"),
            }

        with patch("EvidenceIngester.scanner.awatch", _fake_awatch):
            await scanner.start()

        assert queue.empty()
