"""Application-wide configuration and path resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
    """Runtime configuration for the downloader.

    Paths default to a `data/` directory adjacent to the repo root so that
    research artefacts stay together with the project. They can be overridden
    via the CLI for users who prefer external storage.
    """

    data_dir: Path = field(default_factory=lambda: Path("data").resolve())
    user_agent: str = (
        "wpforge/0.1 (+security-research; "
        "https://github.com/moritakaaz/wpforge)"
    )
    concurrency: int = 6
    request_timeout: float = 60.0
    max_retries: int = 5

    @property
    def plugins_dir(self) -> Path:
        return self.data_dir / "plugins"

    @property
    def extracted_dir(self) -> Path:
        return self.data_dir / "extracted"

    @property
    def vulndb_dir(self) -> Path:
        return self.data_dir / "vulndb"

    @property
    def catalog_db(self) -> Path:
        return self.data_dir / "catalog.db"

    def ensure_dirs(self) -> None:
        for path in (self.plugins_dir, self.extracted_dir, self.vulndb_dir):
            path.mkdir(parents=True, exist_ok=True)
