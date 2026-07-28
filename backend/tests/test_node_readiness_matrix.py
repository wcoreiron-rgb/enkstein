"""
Exercises every Capability Node the way an operator does: open the page, run
the scan, ask for findings, stats and providers. A node that only imports
cleanly is not ready; a node that answers all five calls without a server
error is.
"""
import os
import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLAWS = os.path.join(BASE, "app", "claws")
_SKIP = {"__init__.py", "__pycache__", "adapters", "provenance.py", "rest_adapter.py"}

NODES = sorted(
    d for d in os.listdir(CLAWS)
    if d not in _SKIP and os.path.isdir(os.path.join(CLAWS, d))
)


@pytest.mark.parametrize("node", NODES)
@pytest.mark.asyncio
async def test_node_answers_every_core_call(client, node):
    prefix = f"/api/v1/{node}"
    failures = []

    for path in ("/findings", "/stats", "/providers"):
        r = await client.get(prefix + path)
        if r.status_code >= 500:
            failures.append(f"GET {path} -> {r.status_code} {r.text[:180]}")

    r = await client.post(prefix + "/scan")
    if r.status_code >= 500:
        failures.append(f"POST /scan -> {r.status_code} {r.text[:180]}")

    r = await client.post(prefix + "/task", json={"input": {}})
    if r.status_code >= 500:
        failures.append(f"POST /task -> {r.status_code} {r.text[:180]}")

    assert not failures, f"{node}: " + " | ".join(failures)
