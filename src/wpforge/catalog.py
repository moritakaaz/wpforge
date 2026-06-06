"""SQLite-backed catalog of downloaded plugin versions.

The catalog records every successful download together with file hashes,
release metadata, and the local archive path. It enables:

- Idempotent re-runs (skip already-downloaded versions).
- Fast lookup for the differ and vuln cross-reference modules.
- A single source of truth that survives across runs.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS plugins (
    slug          TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    homepage      TEXT,
    last_updated  TEXT,
    fetched_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS versions (
    slug          TEXT NOT NULL,
    version       TEXT NOT NULL,
    download_url  TEXT NOT NULL,
    archive_path  TEXT,
    sha256        TEXT,
    size_bytes    INTEGER,
    downloaded_at TEXT,
    extracted_at  TEXT,
    PRIMARY KEY (slug, version),
    FOREIGN KEY (slug) REFERENCES plugins(slug) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    slug          TEXT NOT NULL,
    source        TEXT NOT NULL,         -- 'wordfence' | 'wpscan' | 'manual'
    source_id     TEXT NOT NULL,
    title         TEXT,
    cve           TEXT,
    severity      TEXT,
    fixed_in      TEXT,
    affected      TEXT,                  -- JSON: version constraints
    raw_json      TEXT,
    UNIQUE (source, source_id)
);

CREATE INDEX IF NOT EXISTS idx_versions_slug ON versions(slug);
CREATE INDEX IF NOT EXISTS idx_vulns_slug    ON vulnerabilities(slug);
"""


@dataclass(frozen=True)
class VersionRecord:
    slug: str
    version: str
    download_url: str
    archive_path: str | None
    sha256: str | None
    size_bytes: int | None
    downloaded_at: str | None
    extracted_at: str | None


class Catalog:
    """Tiny SQLite wrapper. Synchronous on purpose; the DB is local and small."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- plugins -----------------------------------------------------------

    def upsert_plugin(
        self, *, slug: str, name: str, homepage: str | None, last_updated: str | None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO plugins (slug, name, homepage, last_updated)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    name = excluded.name,
                    homepage = excluded.homepage,
                    last_updated = excluded.last_updated,
                    fetched_at = datetime('now')
                """,
                (slug, name, homepage, last_updated),
            )

    # ---- versions ----------------------------------------------------------

    def register_version(self, *, slug: str, version: str, download_url: str) -> None:
        """Insert a version row if missing, without touching download metadata."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO versions (slug, version, download_url)
                VALUES (?, ?, ?)
                ON CONFLICT(slug, version) DO UPDATE SET
                    download_url = excluded.download_url
                """,
                (slug, version, download_url),
            )

    def mark_downloaded(
        self,
        *,
        slug: str,
        version: str,
        archive_path: Path,
        sha256: str,
        size_bytes: int,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE versions
                   SET archive_path = ?, sha256 = ?, size_bytes = ?,
                       downloaded_at = datetime('now')
                 WHERE slug = ? AND version = ?
                """,
                (str(archive_path), sha256, size_bytes, slug, version),
            )

    def mark_extracted(self, *, slug: str, version: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE versions SET extracted_at = datetime('now')"
                " WHERE slug = ? AND version = ?",
                (slug, version),
            )

    def get_version(self, slug: str, version: str) -> VersionRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM versions WHERE slug = ? AND version = ?",
                (slug, version),
            ).fetchone()
        return _row_to_version(row) if row else None

    def list_versions(self, slug: str) -> list[VersionRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM versions WHERE slug = ? ORDER BY version",
                (slug,),
            ).fetchall()
        return [_row_to_version(r) for r in rows]

    def is_downloaded(self, slug: str, version: str) -> bool:
        rec = self.get_version(slug, version)
        return bool(rec and rec.archive_path and rec.sha256)

    # ---- vulnerabilities ---------------------------------------------------

    def upsert_vulnerability(
        self,
        *,
        slug: str,
        source: str,
        source_id: str,
        title: str | None,
        cve: str | None,
        severity: str | None,
        fixed_in: str | None,
        affected: str | None,
        raw_json: str | None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vulnerabilities
                    (slug, source, source_id, title, cve, severity,
                     fixed_in, affected, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source, source_id) DO UPDATE SET
                    slug = excluded.slug,
                    title = excluded.title,
                    cve = excluded.cve,
                    severity = excluded.severity,
                    fixed_in = excluded.fixed_in,
                    affected = excluded.affected,
                    raw_json = excluded.raw_json
                """,
                (slug, source, source_id, title, cve, severity, fixed_in, affected, raw_json),
            )

    def vulnerabilities_for(self, slug: str) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM vulnerabilities WHERE slug = ? ORDER BY severity DESC",
                (slug,),
            ).fetchall()


def _row_to_version(row: sqlite3.Row) -> VersionRecord:
    return VersionRecord(
        slug=row["slug"],
        version=row["version"],
        download_url=row["download_url"],
        archive_path=row["archive_path"],
        sha256=row["sha256"],
        size_bytes=row["size_bytes"],
        downloaded_at=row["downloaded_at"],
        extracted_at=row["extracted_at"],
    )
