"""Smoke tests for the catalog SQLite schema and basic operations."""

from __future__ import annotations

from pathlib import Path

from wpforge.catalog import Catalog


def test_register_and_mark_downloaded(tmp_path: Path) -> None:
    catalog = Catalog(tmp_path / "catalog.db")
    catalog.upsert_plugin(
        slug="example",
        name="Example",
        homepage="https://example.com",
        last_updated="2024-01-01 00:00:00",
    )
    catalog.register_version(
        slug="example", version="1.0", download_url="https://example/1.0.zip"
    )

    assert not catalog.is_downloaded("example", "1.0")

    archive = tmp_path / "example.1.0.zip"
    archive.write_bytes(b"fake")
    catalog.mark_downloaded(
        slug="example",
        version="1.0",
        archive_path=archive,
        sha256="deadbeef",
        size_bytes=4,
    )

    assert catalog.is_downloaded("example", "1.0")
    rec = catalog.get_version("example", "1.0")
    assert rec is not None
    assert rec.sha256 == "deadbeef"
    assert rec.size_bytes == 4
