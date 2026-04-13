import hashlib
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

import pytest

from ArtefactAnalysis.archiver import Archiver
from Domain.file_under_investigation import FileUnderInvestigation


def _make_file(tmp_dir: Path, name: str, content: bytes) -> FileUnderInvestigation:
    """Write *content* to *tmp_dir/name* and return a FileUnderInvestigation."""
    path = tmp_dir / name
    path.write_bytes(content)
    return FileUnderInvestigation.from_path(
        path,
        sha256=hashlib.sha256(content).hexdigest(),
        md5=hashlib.md5(content).hexdigest(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestArchiverInit:

    def test_archive_dir_is_created_when_missing(self, tmp_path):
        """Archiver should create the archive directory if it does not exist."""
        archive_dir = tmp_path / "new_archives"
        assert not archive_dir.exists()

        Archiver(str(archive_dir))

        assert archive_dir.exists()
        assert archive_dir.is_dir()

    def test_archive_dir_already_exists_does_not_raise(self, tmp_path):
        """Archiver should not raise if the archive directory already exists."""
        archive_dir = tmp_path / "existing"
        archive_dir.mkdir()

        Archiver(str(archive_dir))  # must not raise


class TestArchiverArchive:

    @pytest.fixture
    def setup(self, tmp_path):
        """Provide a temp source dir, archive dir, and a populated Archiver."""
        source_dir = tmp_path / "source"
        archive_dir = tmp_path / "archives"
        source_dir.mkdir()
        archiver = Archiver(str(archive_dir))
        return source_dir, archive_dir, archiver

    # --- return value -------------------------------------------------------

    def test_returns_dict_with_all_keys(self, setup):
        source_dir, archive_dir, archiver = setup
        file = _make_file(source_dir, "evidence.bin", b"binary content")

        result = archiver.archive(file)

        assert set(result.keys()) == {
            "archive_path", "archive_size", "original_name",
            "sha256", "md5", "archived_at",
        }

    def test_return_original_name(self, setup):
        source_dir, _, archiver = setup
        file = _make_file(source_dir, "report.bin", b"data")

        result = archiver.archive(file)

        assert result["original_name"] == "report.bin"

    def test_return_sha256_and_md5_match_source(self, setup):
        source_dir, _, archiver = setup
        content = b"forensic content"
        file = _make_file(source_dir, "sample.bin", content)

        result = archiver.archive(file)

        assert result["sha256"] == hashlib.sha256(content).hexdigest()
        assert result["md5"] == hashlib.md5(content).hexdigest()

    def test_return_archive_size_is_positive(self, setup):
        source_dir, _, archiver = setup
        file = _make_file(source_dir, "data.bin", b"some bytes")

        result = archiver.archive(file)

        assert result["archive_size"] > 0

    def test_return_archived_at_is_iso_format(self, setup):
        source_dir, _, archiver = setup
        file = _make_file(source_dir, "data.bin", b"bytes")

        result = archiver.archive(file)

        # Should parse without raising
        datetime.fromisoformat(result["archived_at"])

    # --- archive file on disk -----------------------------------------------

    def test_zip_is_created_on_disk(self, setup):
        source_dir, archive_dir, archiver = setup
        file = _make_file(source_dir, "evidence.bin", b"content")

        result = archiver.archive(file)

        assert Path(result["archive_path"]).exists()

    def test_archive_path_is_inside_archive_dir(self, setup):
        source_dir, archive_dir, archiver = setup
        file = _make_file(source_dir, "evidence.bin", b"content")

        result = archiver.archive(file)

        assert Path(result["archive_path"]).parent == archive_dir

    def test_archive_name_contains_stem_and_sha256_prefix(self, setup):
        source_dir, _, archiver = setup
        content = b"predictable"
        file = _make_file(source_dir, "payload.bin", content)
        sha_prefix = hashlib.sha256(content).hexdigest()[:8]

        result = archiver.archive(file)

        archive_name = Path(result["archive_path"]).name
        assert archive_name.startswith(f"payload_{sha_prefix}_")
        assert archive_name.endswith(".zip")

    def test_archive_is_valid_zip(self, setup):
        source_dir, _, archiver = setup
        file = _make_file(source_dir, "data.bin", b"zip me")

        result = archiver.archive(file)

        assert zipfile.is_zipfile(result["archive_path"])

    # --- ZIP contents --------------------------------------------------------

    def test_zip_contains_original_file(self, setup):
        source_dir, _, archiver = setup
        file = _make_file(source_dir, "evidence.bin", b"original")

        result = archiver.archive(file)

        with zipfile.ZipFile(result["archive_path"]) as zf:
            assert "evidence.bin" in zf.namelist()

    def test_zip_original_file_content_is_intact(self, setup):
        source_dir, _, archiver = setup
        content = b"must survive compression"
        file = _make_file(source_dir, "evidence.bin", content)

        result = archiver.archive(file)

        with zipfile.ZipFile(result["archive_path"]) as zf:
            assert zf.read("evidence.bin") == content

    def test_zip_contains_checksum_txt(self, setup):
        source_dir, _, archiver = setup
        file = _make_file(source_dir, "evidence.bin", b"data")

        result = archiver.archive(file)

        with zipfile.ZipFile(result["archive_path"]) as zf:
            assert "checksum.txt" in zf.namelist()

    def test_checksum_txt_contains_sha256(self, setup):
        source_dir, _, archiver = setup
        content = b"hash me"
        file = _make_file(source_dir, "evidence.bin", content)
        expected_sha256 = hashlib.sha256(content).hexdigest()

        result = archiver.archive(file)

        with zipfile.ZipFile(result["archive_path"]) as zf:
            checksum = zf.read("checksum.txt").decode()
        assert expected_sha256 in checksum

    def test_checksum_txt_contains_md5(self, setup):
        source_dir, _, archiver = setup
        content = b"hash me"
        file = _make_file(source_dir, "evidence.bin", content)
        expected_md5 = hashlib.md5(content).hexdigest()

        result = archiver.archive(file)

        with zipfile.ZipFile(result["archive_path"]) as zf:
            checksum = zf.read("checksum.txt").decode()
        assert expected_md5 in checksum

    def test_checksum_txt_contains_filename(self, setup):
        source_dir, _, archiver = setup
        file = _make_file(source_dir, "evidence.bin", b"data")

        result = archiver.archive(file)

        with zipfile.ZipFile(result["archive_path"]) as zf:
            checksum = zf.read("checksum.txt").decode()
        assert "evidence.bin" in checksum

    def test_zip_has_exactly_two_entries(self, setup):
        """Each archive should contain exactly the original file + checksum.txt."""
        source_dir, _, archiver = setup
        file = _make_file(source_dir, "evidence.bin", b"data")

        result = archiver.archive(file)

        with zipfile.ZipFile(result["archive_path"]) as zf:
            assert len(zf.namelist()) == 2

    # --- multiple archives ---------------------------------------------------

    def test_two_different_files_produce_two_separate_archives(self, setup):
        source_dir, archive_dir, archiver = setup
        file_a = _make_file(source_dir, "file_a.bin", b"content A")
        file_b = _make_file(source_dir, "file_b.bin", b"content B")

        result_a = archiver.archive(file_a)
        result_b = archiver.archive(file_b)

        assert result_a["archive_path"] != result_b["archive_path"]
        assert len(list(archive_dir.glob("*.zip"))) == 2

    def test_same_file_archived_twice_produces_two_archives(self, setup):
        """Timestamp in the name prevents collisions on repeated archiving."""
        import time
        source_dir, archive_dir, archiver = setup
        file = _make_file(source_dir, "evidence.bin", b"repeat")

        result_a = archiver.archive(file)
        time.sleep(1)  # ensure different timestamp
        result_b = archiver.archive(file)

        assert result_a["archive_path"] != result_b["archive_path"]
        assert len(list(archive_dir.glob("*.zip"))) == 2
