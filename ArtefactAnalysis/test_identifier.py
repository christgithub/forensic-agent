import pytest
from pathlib import Path
from unittest.mock import patch

from ArtefactAnalysis.identifier import Identifier


class TestIdentifier:
    def setup_method(self):
        self.identifier = Identifier()

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _make_file(tmp_path: Path, name: str, content: bytes = b"data") -> Path:
        p = tmp_path / name
        p.write_bytes(content)
        return p

    # -----------------------------------------------------------------------
    # Tests
    # -----------------------------------------------------------------------

    @patch("ArtefactAnalysis.identifier.magic.from_buffer")
    def test_identify_file_returns_expected_structure(self, mock_from_buffer, tmp_path):
        mock_from_buffer.side_effect = ["text/plain", "ASCII text"]
        path = self._make_file(tmp_path, "evidence.txt")

        result = self.identifier.identify_file(str(path))

        assert set(result.keys()) == {
            "file", "extension", "expected_mime", "detected_mime",
            "description", "extension_allowed", "header_matches",
            "is_valid", "sha256", "md5",
        }

    @patch("ArtefactAnalysis.identifier.magic.from_buffer")
    def test_identify_file_valid_allowed_extension(self, mock_from_buffer, tmp_path):
        mock_from_buffer.side_effect = ["application/pdf", "PDF document"]
        path = self._make_file(tmp_path, "report.pdf")

        result = self.identifier.identify_file(str(path))

        assert result["file"] == str(path)
        assert result["extension"] == ".pdf"
        assert result["expected_mime"] == "application/pdf"
        assert result["detected_mime"] == "application/pdf"
        assert result["description"] == "PDF document"
        assert result["extension_allowed"] is True
        assert result["header_matches"] is True
        assert result["is_valid"] is True

    @patch("ArtefactAnalysis.identifier.magic.from_buffer")
    def test_identify_file_spoofed_file_mime_mismatch(self, mock_from_buffer, tmp_path):
        mock_from_buffer.side_effect = ["application/x-executable", "ELF executable"]
        path = self._make_file(tmp_path, "fake.txt")

        result = self.identifier.identify_file(str(path))

        assert result["extension"] == ".txt"
        assert result["expected_mime"] == "text/plain"
        assert result["detected_mime"] == "application/x-executable"
        assert result["extension_allowed"] is True
        assert result["header_matches"] is False
        assert result["is_valid"] is False

    @patch("ArtefactAnalysis.identifier.magic.from_buffer")
    def test_identify_file_unknown_extension_is_invalid(self, mock_from_buffer, tmp_path):
        mock_from_buffer.side_effect = ["application/octet-stream", "data"]
        path = self._make_file(tmp_path, "archive.rar")

        result = self.identifier.identify_file(str(path))

        assert result["extension"] == ".rar"
        assert result["expected_mime"] is None
        assert result["extension_allowed"] is False
        assert result["header_matches"] is False
        assert result["is_valid"] is False

    @patch("ArtefactAnalysis.identifier.magic.from_buffer")
    def test_identify_file_no_extension_is_invalid(self, mock_from_buffer, tmp_path):
        mock_from_buffer.side_effect = ["application/octet-stream", "data"]
        path = self._make_file(tmp_path, "no_extension")

        result = self.identifier.identify_file(str(path))

        assert result["extension"] == ""
        assert result["expected_mime"] is None
        assert result["extension_allowed"] is False
        assert result["header_matches"] is False
        assert result["is_valid"] is False

    @patch("ArtefactAnalysis.identifier.magic.from_buffer")
    def test_identify_file_normalizes_uppercase_extension(self, mock_from_buffer, tmp_path):
        mock_from_buffer.side_effect = ["image/jpeg", "JPEG image data"]
        path = self._make_file(tmp_path, "PHOTO.JPG")

        result = self.identifier.identify_file(str(path))

        assert result["extension"] == ".jpg"
        assert result["expected_mime"] == "image/jpeg"
        assert result["is_valid"] is True

    @patch("ArtefactAnalysis.identifier.magic.from_buffer")
    def test_identify_file_calls_from_buffer_twice(self, mock_from_buffer, tmp_path):
        mock_from_buffer.side_effect = ["text/plain", "ASCII text"]
        path = self._make_file(tmp_path, "evidence.txt", b"hello")

        self.identifier.identify_file(str(path))

        assert mock_from_buffer.call_count == 2
        # first call: mime=True; second call: no mime kwarg
        calls = mock_from_buffer.call_args_list
        assert calls[0].kwargs.get("mime") is True
        assert "mime" not in calls[1].kwargs

    @patch("ArtefactAnalysis.identifier.magic.from_buffer")
    def test_identify_file_passes_sha256_and_md5_through(self, mock_from_buffer, tmp_path):
        mock_from_buffer.side_effect = ["text/plain", "ASCII text"]
        path = self._make_file(tmp_path, "evidence.txt")
        sha = "abc123"
        md5 = "def456"

        result = self.identifier.identify_file(str(path), sha256=sha, md5=md5)

        assert result["sha256"] == sha
        assert result["md5"] == md5

    @patch("ArtefactAnalysis.identifier.magic.from_buffer")
    def test_identify_file_opens_file_in_read_only_mode(self, mock_from_buffer, tmp_path):
        """Verify the file is opened with 'rb' (read-only binary)."""
        mock_from_buffer.side_effect = ["text/plain", "ASCII text"]
        path = self._make_file(tmp_path, "evidence.txt", b"content")

        with patch("builtins.open", wraps=open) as mock_open:
            self.identifier.identify_file(str(path))
            mock_open.assert_called_once_with(path, "rb")
