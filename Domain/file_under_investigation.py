from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class FileUnderInvestigation:
    name: str
    size: int
    path: str
    created_at: datetime
    modified_at: datetime
    last_accessed_at: datetime
    sha256: str
    md5: str

    @classmethod
    def from_path(cls, file_path: Path, sha256: str, md5: str) -> 'FileUnderInvestigation':
        stat = file_path.stat()

        return cls(
            name=file_path.name,
            size=stat.st_size,
            path=str(file_path.absolute()),
            created_at=datetime.fromtimestamp(stat.st_ctime),
            modified_at=datetime.fromtimestamp(stat.st_mtime),
            last_accessed_at=datetime.fromtimestamp(stat.st_atime),
            sha256=sha256,
            md5=md5
        )
