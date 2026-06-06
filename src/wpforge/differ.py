"""Diff helper for comparing two extracted plugin versions.

Useful for spotting silent security patches: pick a version known to be
vulnerable and the next stable release, then look at the file-level changes.

We deliberately keep this thin: the heavy lifting is delegated to the
stdlib `difflib` and `filecmp` modules so there are no extra dependencies.
For binary or large diffs, callers can use the returned `DiffSummary` to
pipe individual file paths into their preferred external diff tool.
"""

from __future__ import annotations

import filecmp
from dataclasses import dataclass, field
from difflib import unified_diff
from pathlib import Path

from .config import Config

# File extensions worth diffing inline. Anything else is reported as
# "binary or non-text" without dumping bytes into the terminal.
TEXT_EXTENSIONS = {
    ".php",
    ".js",
    ".ts",
    ".css",
    ".html",
    ".htm",
    ".txt",
    ".md",
    ".json",
    ".yml",
    ".yaml",
    ".xml",
    ".sql",
    ".po",
    ".pot",
}


@dataclass
class DiffSummary:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)


class Differ:
    def __init__(self, config: Config) -> None:
        self._config = config

    def _root_for(self, slug: str, version: str) -> Path:
        # Plugin zips usually contain a single top-level directory named after
        # the slug. Resolve to that if present so paths align across versions.
        base = self._config.extracted_dir / slug / version
        candidate = base / slug
        return candidate if candidate.is_dir() else base

    def summarise(self, slug: str, version_a: str, version_b: str) -> DiffSummary:
        """Return added/removed/modified file lists between two versions."""
        a_root = self._root_for(slug, version_a)
        b_root = self._root_for(slug, version_b)
        if not a_root.is_dir() or not b_root.is_dir():
            raise FileNotFoundError(
                "Both versions must be extracted before diffing: "
                f"{a_root} / {b_root}"
            )

        summary = DiffSummary()
        self._walk(a_root, b_root, Path("."), summary)
        return summary

    def _walk(
        self,
        a_root: Path,
        b_root: Path,
        rel: Path,
        summary: DiffSummary,
    ) -> None:
        cmp = filecmp.dircmp(a_root / rel, b_root / rel)
        for name in cmp.right_only:
            summary.added.append(str((rel / name).as_posix()))
        for name in cmp.left_only:
            summary.removed.append(str((rel / name).as_posix()))
        for name in cmp.diff_files:
            summary.modified.append(str((rel / name).as_posix()))
        for name in cmp.common_dirs:
            self._walk(a_root, b_root, rel / name, summary)

    def unified(
        self,
        slug: str,
        version_a: str,
        version_b: str,
        relative_path: str,
    ) -> str:
        """Return a unified diff for a single text file across two versions."""
        a_root = self._root_for(slug, version_a)
        b_root = self._root_for(slug, version_b)
        a_file = a_root / relative_path
        b_file = b_root / relative_path

        if a_file.suffix.lower() not in TEXT_EXTENSIONS:
            return f"<{relative_path}: binary or non-text, skipping inline diff>"

        a_lines = _read_text(a_file)
        b_lines = _read_text(b_file)
        diff = unified_diff(
            a_lines,
            b_lines,
            fromfile=f"{slug}@{version_a}/{relative_path}",
            tofile=f"{slug}@{version_b}/{relative_path}",
            lineterm="",
        )
        return "\n".join(diff)


def _read_text(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
