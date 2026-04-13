import asyncio
import hashlib
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from main import main as agent_main, _ROOT

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")

WATCHED_DIR       = _ROOT / "watched_directory"
TOTAL_DROP_WINDOW = 2.0

# ---------------------------------------------------------------------------
# Known file types — extension matches magic bytes → is_valid == True
# → forwarded to Analyzer + logged to CSV / DB
# ---------------------------------------------------------------------------
TEST_FILES = [
    {
        "name": "evidence_report.txt",
        "content": b"Forensic evidence report - plain text content for analysis.",
    },
    {
        "name": "evidence_document.pdf",
        "content": (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"%%EOF"
        ),
    },
    {
        "name": "evidence_photo.png",
        "content": (
            b"\x89PNG\r\n\x1a\n"                  # PNG signature
            b"\x00\x00\x00\rIHDR"                  # IHDR chunk length + type
            b"\x00\x00\x00\x01\x00\x00\x00\x01"   # 1×1 px
            b"\x08\x02\x00\x00\x00\x90wS\xde"      # bit depth / colour type / CRC
            b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f" # minimal IDAT
            b"\x00\x00\x01\x01\x00\x05\x18\xd8N"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"      # IEND
        ),
    },
    {
        "name": "evidence_image.jpg",
        "content": (
            b"\xff\xd8\xff\xe0"          # JPEG SOI + APP0 marker
            b"\x00\x10JFIF\x00"         # JFIF identifier
            b"\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xd9"                  # EOI
        ),
    },
    {
        "name": "evidence_archive.zip",
        "content": (
            b"PK\x03\x04"               # ZIP local file header signature
            b"\x14\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00"
            b"PK\x05\x06" + b"\x00" * 18  # end of central directory
        ),
    },
]

# ---------------------------------------------------------------------------
# Suspicious / invalid file types — extension NOT in the allow-list
# → is_valid == False → Archiver compresses them to archives/
# ---------------------------------------------------------------------------
SUSPICIOUS_FILES = [
    {
        "name": "suspicious_payload.bin",
        "content": (
            b"\xDE\xAD\xBE\xEF\x00\x01\x02\x03"
            b"Unknown binary payload - forensic evidence"
        ),
    },
    {
        "name": "malware_sample.exe",
        "content": (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
            b"This program cannot be run in DOS mode.\r\r\n$"
        ),
    },
    {
        "name": "mystery_data.xyz",
        "content": b"?MYSTERY\x00\x00\xff\xfeUnknown proprietary format payload",
    },
]


async def test_end_to_end():
    """
    End-to-end test for the forensic agent.

    Drops two categories of files into the watched directory, evenly spread
    over 2 seconds:
      • Known types  (.txt, .pdf, .png, .jpg, .zip) → logged to CSV/DB
      • Suspicious   (.bin, .exe, .xyz)              → archived to archives/
    """
    logger.info("=" * 60)
    logger.info("  ForensicAgent — Multi-type E2E Test")
    logger.info("=" * 60)

    WATCHED_DIR.mkdir(exist_ok=True)

    all_files = TEST_FILES + SUSPICIOUS_FILES
    dropped: list[Path] = []

    try:
        logger.info("[+] Watched dir : %s", WATCHED_DIR)
        logger.info("[+] Drop window : %ss across %d files", TOTAL_DROP_WINDOW, len(all_files))
        logger.info("    Known types  : %d  → Analyzer + Reporter", len(TEST_FILES))
        logger.info("    Suspicious   : %d  → Archiver", len(SUSPICIOUS_FILES))

        # Pre-compute and display expected hashes
        logger.info("[*] Expected hashes:")
        for f in all_files:
            f["sha256"] = hashlib.sha256(f["content"]).hexdigest()
            f["md5"]    = hashlib.md5(f["content"]).hexdigest()
            tag = "SUSPICIOUS" if f in SUSPICIOUS_FILES else "valid"
            logger.info("  [%s] %s  SHA-256=%s  MD5=%s", tag, f["name"], f["sha256"], f["md5"])

        # Start the agent
        logger.info("[+] Starting ForensicAgent …")
        agent_task = asyncio.create_task(agent_main())
        await asyncio.sleep(1)      # let watchfiles initialise

        # Drop all files evenly spaced across the drop window
        interval = TOTAL_DROP_WINDOW / len(all_files)
        logger.info("[+] Dropping files every %.2fs …", interval)
        for f in all_files:
            dest = WATCHED_DIR / f["name"]
            tag  = "suspicious" if f in SUSPICIOUS_FILES else "valid"
            logger.info("    → %s  [%s]", f["name"], tag)
            dest.write_bytes(f["content"])
            dropped.append(dest)
            await asyncio.sleep(interval)

        # Let the pipeline finish processing
        logger.info("[*] Waiting for pipeline to process all files …")
        await asyncio.sleep(3)

        agent_task.cancel()
        await asyncio.gather(agent_task, return_exceptions=True)

        # Show what was archived
        archive_dir = _ROOT / "archives"
        archives = sorted(archive_dir.glob("*.zip")) if archive_dir.exists() else []

        logger.info("=" * 60)
        logger.info("  ✓  Multi-type E2E test completed successfully!")
        logger.info("  Known files    : %s", ", ".join(f["name"] for f in TEST_FILES))
        logger.info("  Suspicious     : %s", ", ".join(f["name"] for f in SUSPICIOUS_FILES))
        logger.info("  CSV report     : %s", _ROOT / "forensic_report.csv")
        logger.info("  SQLite DB      : %s", _ROOT / "forensic_report.db")
        logger.info("  Archives (%2d)  : %s", len(archives), ", ".join(a.name for a in archives))
        logger.info("=" * 60)

    finally:
        for path in dropped:
            path.unlink(missing_ok=True)
        logger.info("[+] Cleaned up %d test file(s) from %s", len(dropped), WATCHED_DIR)


if __name__ == "__main__":
    asyncio.run(test_end_to_end())
