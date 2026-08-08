"""Update-availability checks for the desktop relaunch/update prompt."""
import httpx
import pytest

from app.core import update_check
from app.core.update_check import check_for_update, compare_versions, reset_cache


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_cache()
    yield
    reset_cache()


def _release(tag: str, assets: list[dict] | None = None) -> dict:
    return {
        "tag_name": tag,
        "html_url": f"https://github.com/wcoreiron-rgb/enkstein/releases/tag/{tag}",
        "published_at": "2026-08-07T22:00:00Z",
        "assets": assets if assets is not None else [
            {
                "name": f"Enkstein-{tag.lstrip('v')}-macos.pkg",
                "browser_download_url": "https://github.com/x/y/releases/download/a/b.pkg",
            },
            {
                "name": "Enkstein-windows-x64-setup.exe",
                "browser_download_url": "https://github.com/x/y/releases/download/a/c.exe",
            },
        ],
    }


def _patch_transport(monkeypatch, handler):
    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, headers=None):
            return handler(url, headers)

    monkeypatch.setattr(update_check.httpx, "AsyncClient", _Client)


def _ok(payload: dict, status: int = 200):
    return lambda url, headers: httpx.Response(
        status, json=payload, request=httpx.Request("GET", url)
    )


# 0.8.10 must sort above 0.8.9. A lexicographic comparison gets this wrong and
# would silently stop offering updates after the ninth patch of a series.
def test_double_digit_patch_is_newer_than_single_digit():
    assert compare_versions("0.8.10", "0.8.9") == 1
    assert compare_versions("0.8.9", "0.8.10") == -1


def test_equal_versions_are_not_newer():
    assert compare_versions("0.8.3", "0.8.3") == 0
    assert compare_versions("v0.8.3", "0.8.3") == 0


def test_non_numeric_versions_never_prompt_an_update():
    assert compare_versions("0.9.0-rc1", "0.8.3") == 0
    assert compare_versions("nightly", "0.8.3") == 0


@pytest.mark.asyncio
async def test_reports_update_when_release_is_newer(monkeypatch):
    _patch_transport(monkeypatch, _ok(_release("v0.9.0")))
    result = await check_for_update("0.8.3")
    assert result["update_available"] is True
    assert result["latest_version"] == "0.9.0"
    assert result["status"] == "update_available"
    assert result["macos_download_url"].startswith("https://")


@pytest.mark.asyncio
async def test_reports_current_when_versions_match(monkeypatch):
    _patch_transport(monkeypatch, _ok(_release("v0.8.3")))
    result = await check_for_update("0.8.3")
    assert result["update_available"] is False
    assert result["status"] == "current"


@pytest.mark.asyncio
async def test_never_prompts_downgrade_when_running_ahead_of_release(monkeypatch):
    _patch_transport(monkeypatch, _ok(_release("v0.8.0")))
    result = await check_for_update("0.8.3")
    assert result["update_available"] is False


@pytest.mark.asyncio
async def test_offline_failure_degrades_to_unavailable(monkeypatch):
    def _boom(url, headers):
        raise httpx.ConnectError("offline", request=httpx.Request("GET", url))

    _patch_transport(monkeypatch, _boom)
    result = await check_for_update("0.8.3")
    assert result["update_available"] is False
    assert result["status"] == "unavailable"
    assert result["reason"] == "check_failed"


@pytest.mark.asyncio
async def test_repository_without_releases_is_not_an_error(monkeypatch):
    _patch_transport(monkeypatch, _ok({}, status=404))
    result = await check_for_update("0.8.3")
    assert result["status"] == "unavailable"
    assert result["reason"] == "no_published_release"


@pytest.mark.asyncio
async def test_result_is_cached_between_calls(monkeypatch):
    calls = {"n": 0}

    def _counting(url, headers):
        calls["n"] += 1
        return httpx.Response(
            200, json=_release("v0.9.0"), request=httpx.Request("GET", url)
        )

    _patch_transport(monkeypatch, _counting)
    await check_for_update("0.8.3")
    await check_for_update("0.8.3")
    await check_for_update("0.8.3")
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_force_bypasses_the_cache(monkeypatch):
    calls = {"n": 0}

    def _counting(url, headers):
        calls["n"] += 1
        return httpx.Response(
            200, json=_release("v0.9.0"), request=httpx.Request("GET", url)
        )

    _patch_transport(monkeypatch, _counting)
    await check_for_update("0.8.3")
    await check_for_update("0.8.3", force=True)
    assert calls["n"] == 2


# A configurable repository must not become a way to make the backend fetch an
# arbitrary host on behalf of whoever can set the environment.
@pytest.mark.asyncio
async def test_malformed_repository_is_refused_without_any_request(monkeypatch):
    monkeypatch.setenv("ENKSTEIN_GITHUB_REPOSITORY", "evil.example.com/../../x")
    called = {"n": 0}

    def _tracking(url, headers):
        called["n"] += 1
        return httpx.Response(200, json={}, request=httpx.Request("GET", url))

    _patch_transport(monkeypatch, _tracking)
    result = await check_for_update("0.8.3")
    assert called["n"] == 0
    assert result["reason"] == "no_release_feed"


@pytest.mark.asyncio
async def test_endpoint_exposes_update_status(client, monkeypatch):
    _patch_transport(monkeypatch, _ok(_release("v0.9.0")))
    response = await client.get("/api/v1/runtime/update")
    assert response.status_code == 200
    body = response.json()
    assert body["update_available"] is True
    assert body["latest_version"] == "0.9.0"
    assert "current_version" in body
