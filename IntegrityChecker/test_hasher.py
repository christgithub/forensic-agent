import asyncio
import hashlib
import tempfile
import pytest
import pytest_asyncio
from pathlib import Path

from IntegrityChecker.hasher import hash_file, Hasher


class TestHashFile:
    """Tests for the hash_file function."""

    @pytest.mark.asyncio
    async def test_hash_file_success(self):
        """Test successful hashing of a file."""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            content = b"Test content for hashing"
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            # Hash the file
            result = await hash_file(tmp_path)

            # Verify result structure
            assert result['status'] == 'success'
            assert result['file_path'] == str(tmp_path)
            assert 'hashes' in result
            assert 'sha256' in result['hashes']
            assert 'md5' in result['hashes']

            # Verify hash values are correct
            expected_sha256 = hashlib.sha256(content).hexdigest()
            expected_md5 = hashlib.md5(content).hexdigest()

            assert result['hashes']['sha256'] == expected_sha256
            assert result['hashes']['md5'] == expected_md5

        finally:
            # Cleanup
            tmp_path.unlink()

    @pytest.mark.asyncio
    async def test_hash_file_nonexistent(self):
        """Test hashing a non-existent file."""
        fake_path = Path("/nonexistent/file.txt")
        result = await hash_file(fake_path)

        assert result['status'] == 'failed'
        assert result['file_path'] == str(fake_path)
        assert 'error' in result

    @pytest.mark.asyncio
    async def test_hash_empty_file(self):
        """Test hashing an empty file."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            result = await hash_file(tmp_path)

            assert result['status'] == 'success'

            # Empty file hashes
            expected_sha256 = hashlib.sha256(b"").hexdigest()
            expected_md5 = hashlib.md5(b"").hexdigest()

            assert result['hashes']['sha256'] == expected_sha256
            assert result['hashes']['md5'] == expected_md5

        finally:
            tmp_path.unlink()

    @pytest.mark.asyncio
    async def test_hash_large_file(self):
        """Test hashing a larger file."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            # Create 1MB file
            content = b"A" * (1024 * 1024)
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            result = await hash_file(tmp_path)

            assert result['status'] == 'success'

            expected_sha256 = hashlib.sha256(content).hexdigest()
            expected_md5 = hashlib.md5(content).hexdigest()

            assert result['hashes']['sha256'] == expected_sha256
            assert result['hashes']['md5'] == expected_md5

        finally:
            tmp_path.unlink()


class TestHasher:
    """Tests for the Hasher class."""

    @pytest.mark.asyncio
    async def test_hasher_processes_file(self):
        """Test that Hasher picks up files from queue and produces results."""
        input_queue = asyncio.Queue()
        output_queue = asyncio.Queue()

        # Create test file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            content = b"Test content"
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            # Create hasher and start it
            hasher = Hasher(input_queue, output_queue)
            hasher_task = asyncio.create_task(hasher.start())

            # Add file to input queue
            await input_queue.put(str(tmp_path))

            # Wait for processing
            await asyncio.sleep(0.5)

            # Get result from output queue
            assert not output_queue.empty()
            result = await asyncio.wait_for(output_queue.get(), timeout=1.0)

            # Verify result
            assert result is not None
            assert result.path == str(tmp_path.absolute())
            assert result.sha256 == hashlib.sha256(content).hexdigest()
            assert result.md5 == hashlib.md5(content).hexdigest()

            # Cancel hasher task
            hasher_task.cancel()
            await asyncio.gather(hasher_task, return_exceptions=True)

        finally:
            tmp_path.unlink()

    @pytest.mark.asyncio
    async def test_hasher_processes_multiple_files(self):
        """Test that Hasher processes multiple files."""
        input_queue = asyncio.Queue()
        output_queue = asyncio.Queue()

        # Create multiple test files
        test_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                content = f"Test content {i}".encode()
                tmp.write(content)
                test_files.append((Path(tmp.name), content))

        try:
            # Create hasher and start it
            hasher = Hasher(input_queue, output_queue)
            hasher_task = asyncio.create_task(hasher.start())

            # Add files to input queue
            for file_path, _ in test_files:
                await input_queue.put(str(file_path))

            # Wait for processing
            await asyncio.sleep(1.0)

            # Verify all files were processed
            results = []
            while not output_queue.empty():
                result = await output_queue.get()
                results.append(result)

            assert len(results) == 3

            # Verify each result
            for result in results:
                assert result is not None
                assert result.sha256 is not None
                assert result.md5 is not None

            # Cancel hasher task
            hasher_task.cancel()
            await asyncio.gather(hasher_task, return_exceptions=True)

        finally:
            for file_path, _ in test_files:
                file_path.unlink()

    @pytest.mark.asyncio
    async def test_hasher_handles_invalid_file(self):
        """Test that Hasher handles invalid files gracefully.

        When hashing fails the file is silently skipped (error is logged) and
        nothing is pushed onto the output queue — callers should never receive
        a None sentinel for a failed hash.
        """
        input_queue = asyncio.Queue()
        output_queue = asyncio.Queue()

        hasher = Hasher(input_queue, output_queue)
        hasher_task = asyncio.create_task(hasher.start())

        # Add non-existent file to queue
        await input_queue.put("/nonexistent/file.txt")

        # Wait for processing
        await asyncio.sleep(0.5)

        # Nothing should have been pushed — the failed file is dropped silently
        assert output_queue.empty(), (
            "Output queue should be empty when hashing fails; "
            "failed files must not propagate None sentinels downstream"
        )

        # The hasher must still be running (it must not have crashed)
        assert not hasher_task.done(), "Hasher task must survive a hashing failure"

        # Cancel hasher task
        hasher_task.cancel()
        await asyncio.gather(hasher_task, return_exceptions=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
