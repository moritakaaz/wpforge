"""Safe extraction of plugin zip archives.

Plugin archives from WordPress.org are well-formed in practice, but since we
ingest them for security research we still defend against zip-slip and
absolute-path entries. Extraction is deterministic: each zip lands in
`<extracted_dir>/<slug>/<version>/`.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from .catalog import Catalog
from .config import Config


class UnsafeArchiveError(RuntimeError):
    """Raised when an archive entry would escape the extraction root."""


class Extractor:
    def __init__(self, *, config: Config, catalog: Catalog) -> None:
        self._config = config
        self._catalog = catalog

    def extract(self, slug: str, version: str, archive: Path) -> Path:
        """Extract `archive` into `<extracted>/<slug>/<version>/` and return it."""
        dest = self._config.extracted_dir / slug / version
        if dest.exists() and any(dest.iterdir()):
            # Already extracted in a previous run.
            self._catalog.mark_extracted(slug=slug, version=version)
            return dest

        dest.mkdir(parents=True, exist_ok=True)
        dest_resolved = dest.resolve()

        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                # zip-slip guard: any entry must stay inside dest.
                if dest_resolved not in target.parents and target != dest_resolved:
                    raise UnsafeArchiveError(
                        f"Refusing to extract entry escaping root: {member.filename!r}"
                    )
                zf.extract(member, dest)

        self._catalog.mark_extracted(slug=slug, version=version)
        return dest
