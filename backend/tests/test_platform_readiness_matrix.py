"""
Exercises every platform GET route the way the console loads it.

Capability Nodes are only half the product; the operator surfaces around them
— approvals, channels, swarm, remote agents, memory, exchange, trust fabric —
are what make it a platform. A route that 500s on an empty tenant is a broken
first-run experience, which is exactly the state a beta tester arrives in.
"""
import pytest

from main import app

_SKIP_SEGMENTS = ("/ws", "/stream", "/sse", "/events/subscribe")


def _get_routes() -> list[str]:
    paths = set()
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", None) or set()
        if "GET" not in methods or not path.startswith("/api/v1"):
            continue
        # Path parameters need a real object to be meaningful; collection
        # endpoints are what the console loads on first paint.
        if "{" in path or any(s in path for s in _SKIP_SEGMENTS):
            continue
        paths.add(path)
    return sorted(paths)


ROUTES = _get_routes()


@pytest.mark.parametrize("path", ROUTES, ids=ROUTES)
@pytest.mark.asyncio
async def test_platform_route_loads_on_an_empty_tenant(client, path):
    response = await client.get(path)
    assert response.status_code < 500, (
        f"{path} -> {response.status_code}: {response.text[:300]}"
    )
