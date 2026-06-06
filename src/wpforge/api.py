"""Client for the public WordPress.org Plugin API.

Endpoints used:
- https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug=<slug>
  Returns plugin metadata including the `versions` map (version -> zip URL).
- https://downloads.wordpress.org/plugin/<slug>.<version>.zip
  Stable URL pattern when the API does not list a specific version.

The API is unauthenticated and rate-limited only loosely, but we still apply
retry/backoff to be a good citizen.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)


def _is_retryable_http_error(exc: BaseException) -> bool:
    """Retry transport errors and 5xx responses, but not 4xx client errors."""
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return False

PLUGIN_INFO_URL = "https://api.wordpress.org/plugins/info/1.2/"
DOWNLOAD_URL_TEMPLATE = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"


@dataclass(frozen=True)
class PluginVersion:
    """A single downloadable version of a plugin."""

    slug: str
    version: str
    download_url: str


@dataclass(frozen=True)
class PluginInfo:
    """Metadata returned by the plugin_information endpoint."""

    slug: str
    name: str
    current_version: str
    last_updated: str | None
    homepage: str | None
    versions: list[PluginVersion]
    raw: dict[str, Any]


class PluginNotFoundError(LookupError):
    """Raised when the WordPress.org API has no record of the plugin."""


class WordPressAPI:
    """Thin async wrapper over the WordPress.org plugins API."""

    def __init__(self, *, user_agent: str, timeout: float = 60.0) -> None:
        self._client = httpx.AsyncClient(
            headers={"User-Agent": user_agent, "Accept": "application/json"},
            timeout=timeout,
            http2=True,
            follow_redirects=True,
        )

    async def __aenter__(self) -> "WordPressAPI":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    @retry(
        retry=retry_if_exception(_is_retryable_http_error),
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=1, max=30),
        reraise=True,
    )
    async def fetch_plugin_info(self, slug: str) -> PluginInfo:
        """Fetch metadata for a plugin slug.

        The plugin_information action already returns the historical `versions`
        map by default; we don't need to request extra fields explicitly.

        Raises PluginNotFoundError if the API responds with `error` payload,
        which is how WordPress.org signals "unknown slug".
        """
        params = {
            "action": "plugin_information",
            "slug": slug,
        }
        response = await self._client.get(PLUGIN_INFO_URL, params=params)
        response.raise_for_status()
        payload = response.json()

        if isinstance(payload, dict) and payload.get("error"):
            raise PluginNotFoundError(f"Plugin not found on WordPress.org: {slug}")

        versions_map: dict[str, str] = payload.get("versions") or {}
        # The API includes a "trunk" pseudo-version; keep it last and only if useful.
        versions = [
            PluginVersion(slug=slug, version=ver, download_url=url or _default_url(slug, ver))
            for ver, url in versions_map.items()
            if ver  # filter empty keys
        ]

        # Fallback: at least the current stable version is always reachable.
        if not versions and payload.get("version"):
            current = payload["version"]
            versions = [
                PluginVersion(slug=slug, version=current, download_url=_default_url(slug, current))
            ]

        return PluginInfo(
            slug=slug,
            name=payload.get("name", slug),
            current_version=payload.get("version", ""),
            last_updated=payload.get("last_updated"),
            homepage=payload.get("homepage"),
            versions=versions,
            raw=payload,
        )


def _default_url(slug: str, version: str) -> str:
    """Build the canonical zip URL when the API omits one for a version."""
    return DOWNLOAD_URL_TEMPLATE.format(slug=slug, version=version)
