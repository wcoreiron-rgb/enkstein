"""Compare the running runtime against the latest published GitHub Release.
Enkstein is not a single binary. The desktop bundle is a thin host process and
the runtime it talks to is a pair of container images pinned by APP_VERSION, so
"an update is available" has to be answered by the runtime itself rather than
by the host app alone. This module owns that answer and caches it, because the
console asks on every load and the public GitHub API allows only 60
unauthenticated requests an hour per address.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# Fixed host. The repository is configurable so a fork can point at its own
# releases, but the endpoint is never taken from a request, which keeps this
# from becoming a way to make the backend fetch an arbitrary URL.
_GITHUB_API = "https://api.github.com"
_DEFAULT_REPOSITORY = "wcoreiron-rgb/enkstein"
_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

_CACHE_TTL_SECONDS = 6 * 60 * 60
_FAILURE_TTL_SECONDS = 15 * 60
_REQUEST_TIMEOUT_SECONDS = 10.0

_VERSION_PATTERN = re.compile(r"^\d+(\.\d+)*$")


@dataclass
class _CacheEntry:
    payload: dict
    expires_at: float


_cache: _CacheEntry | None = None
_lock = asyncio.Lock()


def _repository() -> str | None:
    raw = (os.getenv("ENKSTEIN_GITHUB_REPOSITORY") or _DEFAULT_REPOSITORY).strip()
    if not _REPOSITORY_PATTERN.match(raw):
        logger.warning("Ignoring malformed update repository: %r", raw)
        return None
    return raw


def _normalise(version: str) -> str:
    return version.strip().lstrip("vV").strip()


def compare_versions(latest: str, current: str) -> int:
    """Return 1 when latest is newer, -1 when older, 0 when equal or unknown.
    Compares numerically per segment so 0.8.10 sorts above 0.8.9, which a
    lexicographic comparison gets wrong. Anything that is not a plain dotted
    numeric version is treated as not-newer rather than guessed at, so a
    prerelease or a malformed tag never prompts a user to reinstall.
    """
    left, right = _normalise(latest), _normalise(current)
    if not _VERSION_PATTERN.match(left) or not _VERSION_PATTERN.match(right):
        return 0

    left_parts = [int(p) for p in left.split(".")]
    right_parts = [int(p) for p in right.split(".")]
    width = max(len(left_parts), len(right_parts))
    left_parts += [0] * (width - len(left_parts))
    right_parts += [0] * (width - len(right_parts))

    if left_parts > right_parts:
        return 1
    if left_parts < right_parts:
        return -1
    return 0


def _asset_url(release: dict, latest: str, tag: str, suffix: str) -> str | None:
    candidates = {
        f"Enkstein-{suffix}",
        f"Enkstein-{latest}-{suffix}",
        f"Enkstein-{tag}-{suffix}",
    }
    for asset in release.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        if asset.get("name") in candidates:
            url = asset.get("browser_download_url")
            if isinstance(url, str) and url.startswith("https://"):
                return url
    return None


def _unavailable(reason: str, current: str) -> dict:
    return {
        "update_available": False,
        "current_version": _normalise(current),
        "latest_version": None,
        "status": "unavailable",
        "reason": reason,
        "release_url": None,
        "macos_download_url": None,
        "windows_download_url": None,
        "published_at": None,
    }


async def check_for_update(current_version: str, *, force: bool = False) -> dict:
    """Report whether a newer published release exists.
    Never raises: an update check that fails should degrade to "we do not
    know", not surface an error banner in a security console.
    """
    global _cache

    now = time.monotonic()
    async with _lock:
        if not force and _cache is not None and _cache.expires_at > now:
            return dict(_cache.payload)

        repository = _repository()
        if repository is None:
            payload = _unavailable("no_release_feed", current_version)
            _cache = _CacheEntry(payload, now + _FAILURE_TTL_SECONDS)
            return dict(payload)

        url = f"{_GITHUB_API}/repos/{repository}/releases/latest"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Enkstein-Runtime",
        }

        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
                response = await client.get(url, headers=headers)
            if response.status_code == 404:
                payload = _unavailable("no_published_release", current_version)
                _cache = _CacheEntry(payload, now + _FAILURE_TTL_SECONDS)
                return dict(payload)
            response.raise_for_status()
            release = response.json()
        except Exception as exc:
            # Offline and air-gapped installs are normal for this product, so a
            # failed check is expected rather than exceptional.
            logger.debug("Update check failed for %s: %s", repository, exc)
            payload = _unavailable("check_failed", current_version)
            _cache = _CacheEntry(payload, now + _FAILURE_TTL_SECONDS)
            return dict(payload)

        tag = release.get("tag_name") if isinstance(release, dict) else None
        if not isinstance(tag, str) or not tag:
            payload = _unavailable("no_published_release", current_version)
            _cache = _CacheEntry(payload, now + _FAILURE_TTL_SECONDS)
            return dict(payload)

        latest = _normalise(tag)
        newer = compare_versions(latest, current_version) > 0
        release_url = release.get("html_url")

        payload = {
            "update_available": newer,
            "current_version": _normalise(current_version),
            "latest_version": latest,
            "status": "update_available" if newer else "current",
            "reason": None,
            "release_url": release_url if isinstance(release_url, str) else None,
            "macos_download_url": _asset_url(release, latest, tag, "macos.pkg"),
            "windows_download_url": _asset_url(
                release, latest, tag, "windows-x64-setup.exe"
            ),
            "published_at": release.get("published_at"),
        }
        _cache = _CacheEntry(payload, now + _CACHE_TTL_SECONDS)
        return dict(payload)


def reset_cache() -> None:
    """Clear the cached result. Used by tests."""
    global _cache
    _cache = None
