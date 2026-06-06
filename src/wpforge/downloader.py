"""Concurrent, resumable downloader for plugin zip archives.

Design choices
--------------
- Streamed downloads to a `*.part` file, atomically renamed on success.
- SHA256 computed during the stream so we never re-read the file.
- Idempotent: if the catalog already records a hash for (slug, version),
  we skip without hitting the network.
- Bounded concurrency via an `anyio.Semaphore`, which keeps the WordPress.org
  CDN happy and avoids local file-descriptor exhaustion.
- Failures retry with exponential backoff; permanent 404s short-circuit so
  yanked versions don't block the batch.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import anyio
import httpx
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from .api import PluginVersion
from .catalog import Catalog
from .config import Config

CHUNK_SIZE = 64 * 1024


def _is_retryable(exc: BaseException) -> bool:
    """Retry on transport hiccups and 5xx, but not on 4xx client errors.

    404s are handled explicitly upstream (yanked versions) so we don't want
    tenacity to keep hammering them.
    """
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return False


@dataclass(frozen=True)
class DownloadResult:
    slug: str
    version: str
    path: Path
    sha256: str
    size_bytes: int
    skipped: bool = False
    missing: bool = False  # 404 / yanked from WordPress.org


class Downloader:
    """Coordinates concurrent downloads of multiple plugin versions."""

    def __init__(self, *, config: Config, catalog: Catalog) -> None:
        self._config = config
        self._catalog = catalog
        self._sem = anyio.Semaphore(config.concurrency)

    async def download_all(
        self,
        versions: list[PluginVersion],
        *,
        progress: Progress | None = None,
    ) -> list[DownloadResult]:
        """Download every version in `versions`. Returns one result per item."""
        results: list[DownloadResult] = []

        async with httpx.AsyncClient(
            headers={"User-Agent": self._config.user_agent},
            timeout=self._config.request_timeout,
            http2=True,
            follow_redirects=True,
        ) as client:

            async def _run(pv: PluginVersion) -> None:
                async with self._sem:
                    result = await self._download_one(client, pv, progress=progress)
                    results.append(result)

            async with anyio.create_task_group() as tg:
                for pv in versions:
                    tg.start_soon(_run, pv)

        return results

    async def _download_one(
        self,
        client: httpx.AsyncClient,
        pv: PluginVersion,
        *,
        progress: Progress | None,
    ) -> DownloadResult:
        target_dir = self._config.plugins_dir / pv.slug
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / f"{pv.slug}.{pv.version}.zip"

        # Idempotent skip: catalog says it's already done and the file is present.
        if self._catalog.is_downloaded(pv.slug, pv.version) and target.exists():
            existing = self._catalog.get_version(pv.slug, pv.version)
            assert existing and existing.sha256 and existing.size_bytes is not None
            return DownloadResult(
                slug=pv.slug,
                version=pv.version,
                path=target,
                sha256=existing.sha256,
                size_bytes=existing.size_bytes,
                skipped=True,
            )

        task_id: TaskID | None = None
        if progress is not None:
            task_id = progress.add_task(
                f"{pv.slug} {pv.version}",
                total=None,
                start=True,
            )

        try:
            async for attempt in AsyncRetrying(
                retry=retry_if_exception(_is_retryable),
                stop=stop_after_attempt(self._config.max_retries),
                wait=wait_exponential(multiplier=1, min=1, max=30),
                reraise=True,
            ):
                with attempt:
                    return await self._stream_to_disk(
                        client, pv, target, progress=progress, task_id=task_id
                    )
        except httpx.HTTPStatusError as exc:
            # Some historical versions are yanked; record but don't fail the batch.
            if exc.response is not None and exc.response.status_code == 404:
                if progress is not None and task_id is not None:
                    progress.update(task_id, description=f"{pv.slug} {pv.version} (404)")
                return DownloadResult(
                    slug=pv.slug,
                    version=pv.version,
                    path=target,
                    sha256="",
                    size_bytes=0,
                    missing=True,
                )
            raise
        finally:
            if progress is not None and task_id is not None:
                progress.remove_task(task_id)

        # Should not reach here; AsyncRetrying with reraise either returns or raises.
        raise RuntimeError("unreachable")

    async def _stream_to_disk(
        self,
        client: httpx.AsyncClient,
        pv: PluginVersion,
        target: Path,
        *,
        progress: Progress | None,
        task_id: TaskID | None,
    ) -> DownloadResult:
        part = target.with_suffix(target.suffix + ".part")
        sha = hashlib.sha256()
        size = 0

        async with client.stream("GET", pv.download_url) as response:
            response.raise_for_status()
            total = int(response.headers.get("Content-Length", 0)) or None
            if progress is not None and task_id is not None and total:
                progress.update(task_id, total=total)

            with part.open("wb") as fh:
                async for chunk in response.aiter_bytes(CHUNK_SIZE):
                    if not chunk:
                        continue
                    fh.write(chunk)
                    sha.update(chunk)
                    size += len(chunk)
                    if progress is not None and task_id is not None:
                        progress.update(task_id, advance=len(chunk))

        # Atomic rename: avoids leaving a half-written zip on crash.
        part.replace(target)

        digest = sha.hexdigest()
        self._catalog.mark_downloaded(
            slug=pv.slug,
            version=pv.version,
            archive_path=target,
            sha256=digest,
            size_bytes=size,
        )
        return DownloadResult(
            slug=pv.slug,
            version=pv.version,
            path=target,
            sha256=digest,
            size_bytes=size,
        )


def make_progress() -> Progress:
    """Standard progress bar layout used by the CLI."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeElapsedColumn(),
        transient=False,
    )
