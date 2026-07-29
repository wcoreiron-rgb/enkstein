"""
Enkstein CLI — HTTP client
All API calls go through here. Reads ENKSTEIN_API_URL from env (default: localhost:8000).
"""
import os
import json
import sys
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

BASE_URL = os.environ.get("ENKSTEIN_API_URL", "http://localhost:8000").rstrip("/")
PREFIX = "/api/v1"


def _headers() -> dict:
    """Attach a Bearer token if ENKSTEIN_TOKEN is set (required when the
    server runs with DEBUG=false). In DEBUG mode the server bypasses auth."""
    token = os.environ.get("ENKSTEIN_TOKEN", "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _client() -> "httpx.Client":
    if httpx is None:
        print("Error: httpx is not installed. Run: pip install httpx")
        sys.exit(1)
    timeout = float(os.environ.get("ENKSTEIN_TIMEOUT", "30"))
    return httpx.Client(base_url=BASE_URL, timeout=timeout, headers=_headers())


def _handle(r) -> Any:
    """Raise friendly errors instead of raw tracebacks."""
    if r.status_code == 401:
        print("Error: unauthorized. Set ENKSTEIN_TOKEN to a valid JWT "
              "(get one from POST /api/v1/auth/token).", file=sys.stderr)
        sys.exit(1)
    if r.status_code == 403:
        print("Error: forbidden — your token lacks permission for this action.", file=sys.stderr)
        sys.exit(1)
    if r.status_code >= 400:
        detail = ""
        try:
            detail = r.json().get("detail", "")
        except Exception:
            detail = r.text[:200]
        print(f"Error {r.status_code}: {detail}", file=sys.stderr)
        sys.exit(1)
    try:
        return r.json()
    except Exception:
        return {}


def _request(method: str, path: str, **kw) -> Any:
    if httpx is None:
        print("Error: httpx is not installed. Run: pip install httpx", file=sys.stderr)
        sys.exit(1)
    try:
        with _client() as c:
            r = c.request(method, PREFIX + path, **kw)
            return _handle(r)
    except httpx.ConnectError:
        print(f"Error: cannot reach Enkstein at {BASE_URL}. "
              f"Set ENKSTEIN_API_URL or start the server.", file=sys.stderr)
        sys.exit(1)


def get(path: str, params: dict | None = None) -> Any:
    return _request("GET", path, params=params)


def post(path: str, body: dict | None = None) -> Any:
    return _request("POST", path, json=body or {})


def patch(path: str, body: dict) -> Any:
    return _request("PATCH", path, json=body)


def delete(path: str) -> Any:
    return _request("DELETE", path)
