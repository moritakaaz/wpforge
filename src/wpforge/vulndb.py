"""Cross-reference downloaded plugin versions with public vuln feeds.

Primary source: Wordfence Intelligence v3 (free tier requires registration).
  https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production

The previous v2 endpoint that worked without authentication was retired
(returns 410 Gone). v3 needs a Bearer token. The token is loaded from the
`WORDFENCE_API_KEY` environment variable so we never persist it on disk.

The feed is a single JSON document keyed by vulnerability UUID. We download
it once (cached on disk under `data/vulndb/`), filter to the slugs we care
about, and upsert into the `vulnerabilities` table for fast lookup.

WPScan is intentionally out of scope here because it also requires an API
token and is paid; add it later behind an opt-in flag if we wire one up.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from .catalog import Catalog
from .config import Config

WORDFENCE_FEED_URL = (
    "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
)
API_KEY_ENV = "WORDFENCE_API_KEY"


class VulnDBAuthError(RuntimeError):
    """Raised when the Wordfence feed cannot be fetched due to missing/invalid credentials."""


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return False


class VulnDB:
    """Fetches and queries the Wordfence Intelligence production feed."""

    def __init__(
        self,
        *,
        config: Config,
        catalog: Catalog,
        api_key: str | None = None,
    ) -> None:
        self._config = config
        self._catalog = catalog
        # Explicit arg wins; otherwise fall back to env var. Never read from disk.
        self._api_key = api_key or os.environ.get(API_KEY_ENV)
        self._cache_path: Path = config.vulndb_dir / "wordfence-production.json"

    @property
    def cache_path(self) -> Path:
        return self._cache_path

    def has_credentials(self) -> bool:
        return bool(self._api_key)

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, min=1, max=20),
        reraise=True,
    )
    def refresh(self, *, force: bool = False) -> Path:
        """Download and cache the Wordfence feed. Returns the cache path.

        Raises VulnDBAuthError if no API key is configured or the API rejects it.
        """
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        if self._cache_path.exists() and not force:
            return self._cache_path

        if not self._api_key:
            raise VulnDBAuthError(
                "Wordfence Intelligence v3 requires an API key. "
                f"Set the {API_KEY_ENV} environment variable. "
                "Generate one at https://www.wordfence.com/account/integrations"
            )

        headers = {
            "User-Agent": self._config.user_agent,
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
        }
        with httpx.Client(
            headers=headers,
            timeout=self._config.request_timeout,
            follow_redirects=True,
        ) as client:
            response = client.get(WORDFENCE_FEED_URL)
            if response.status_code in (401, 403):
                raise VulnDBAuthError(
                    f"Wordfence API rejected the supplied key ({response.status_code}). "
                    "Verify the value of WORDFENCE_API_KEY."
                )
            response.raise_for_status()
            self._cache_path.write_bytes(response.content)
        return self._cache_path

    def import_for_slugs(self, slugs: Iterable[str]) -> int:
        """Filter the feed to the given slugs and upsert. Returns rows touched.

        If the cache is missing this will attempt a refresh first, which may
        raise VulnDBAuthError when no API key is configured.
        """
        slugs_set = {s.lower() for s in slugs}
        if not self._cache_path.exists():
            self.refresh()

        with self._cache_path.open("r", encoding="utf-8") as fh:
            feed: Any = json.load(fh)

        # v3 wraps the data in {"data": [...]} or returns a dict keyed by UUID.
        # Normalise both shapes into an iterable of (id, entry) pairs.
        entries: list[tuple[str, dict[str, Any]]] = []
        if isinstance(feed, dict) and isinstance(feed.get("data"), list):
            for entry in feed["data"]:
                if isinstance(entry, dict):
                    eid = str(entry.get("id") or entry.get("uuid") or "")
                    entries.append((eid, entry))
        elif isinstance(feed, dict):
            entries = [(k, v) for k, v in feed.items() if isinstance(v, dict)]
        elif isinstance(feed, list):
            for entry in feed:
                if isinstance(entry, dict):
                    eid = str(entry.get("id") or entry.get("uuid") or "")
                    entries.append((eid, entry))

        touched = 0
        for vuln_id, entry in entries:
            for software in entry.get("software") or []:
                if software.get("type") != "plugin":
                    continue
                slug = (software.get("slug") or "").lower()
                if slug not in slugs_set:
                    continue

                affected = software.get("affected_versions") or {}
                fixed_in: Any = software.get("patched_versions") or software.get(
                    "remediation"
                )
                if isinstance(fixed_in, list):
                    fixed_in = ", ".join(str(v) for v in fixed_in)

                # CVE may live under several shapes across schema revisions.
                cve_field = entry.get("cve") or entry.get("cves") or []
                if isinstance(cve_field, str):
                    cve = cve_field
                elif isinstance(cve_field, list) and cve_field:
                    cve = (
                        cve_field[0]
                        if isinstance(cve_field[0], str)
                        else cve_field[0].get("id") or cve_field[0].get("cve")
                    )
                else:
                    cve = None

                cvss_block = entry.get("cvss") or {}
                severity = (
                    cvss_block.get("rating")
                    if isinstance(cvss_block, dict)
                    else None
                ) or entry.get("severity")

                self._catalog.upsert_vulnerability(
                    slug=slug,
                    source="wordfence",
                    source_id=vuln_id or f"{slug}:{entry.get('title', '')}",
                    title=entry.get("title"),
                    cve=cve,
                    severity=severity,
                    fixed_in=str(fixed_in) if fixed_in else None,
                    affected=json.dumps(affected) if affected else None,
                    raw_json=json.dumps(entry),
                )
                touched += 1
        return touched
