from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core.modelclaw import routes
from app.core.modelclaw.schemas import CortexTaskGraphRequest, CortexTaskGraphResponse


PROJECT_ID = "11111111-1111-1111-1111-111111111111"


def _payload(**updates):
    data = {
        "objective": "Review one bounded workspace task",
        "nodes": [{"id": "review", "role": "reviewer", "instruction": "Review evidence"}],
        "tenant_id": "tenant-a",
        "workspace_id": PROJECT_ID,
    }
    data.update(updates)
    return CortexTaskGraphRequest(**data)


class _Result:
    def __init__(self, *, scalar=None, values=None):
        self._scalar = scalar
        self._values = values or []

    def scalar_one_or_none(self):
        return self._scalar

    def scalars(self):
        return SimpleNamespace(all=lambda: self._values)


class _Db:
    def __init__(self, project, classifications=None):
        self._results = iter([
            _Result(scalar=project),
            _Result(values=classifications or []),
        ])

    async def execute(self, _query):
        return next(self._results)


@pytest.mark.asyncio
async def test_task_graph_route_validates_workspace_owner_and_effective_classification(monkeypatch):
    project = SimpleNamespace(
        id=PROJECT_ID, tenant_id="tenant-a", owner_id="owner-a",
        classification="confidential", status="active",
    )
    captured = {}

    async def execute(_db, payload, requester):
        captured["payload"] = payload
        captured["requester"] = requester
        return CortexTaskGraphResponse(status="completed", results=[], execution_order=[])

    monkeypatch.setattr(routes, "execute_task_graph", execute)
    await routes.run_cortex_task_graph(
        _payload(data_classification="internal"),
        db=_Db(project, ["restricted"]),
        user={"sub": "owner-a", "role": "operator", "tenant_id": "tenant-a"},
    )
    assert captured["payload"].data_classification == "restricted"
    assert captured["payload"].workspace_id == PROJECT_ID
    assert captured["requester"].subject == "owner-a"
    assert captured["requester"].role == "operator"
    assert captured["requester"].tenant_id == "tenant-a"


@pytest.mark.asyncio
async def test_task_graph_route_rejects_workspace_owned_by_another_subject(monkeypatch):
    project = SimpleNamespace(
        id=PROJECT_ID, tenant_id="tenant-a", owner_id="owner-b",
        classification="internal", status="active",
    )
    monkeypatch.setattr(routes, "execute_task_graph", lambda *_args: pytest.fail("graph must not execute"))
    with pytest.raises(HTTPException) as exc:
        await routes.run_cortex_task_graph(
            _payload(),
            db=_Db(project),
            user={"sub": "owner-a", "role": "operator", "tenant_id": "tenant-a"},
        )
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_task_graph_route_hides_unknown_or_cross_tenant_workspace(monkeypatch):
    monkeypatch.setattr(routes, "execute_task_graph", lambda *_args: pytest.fail("graph must not execute"))
    with pytest.raises(HTTPException) as exc:
        await routes.run_cortex_task_graph(
            _payload(),
            db=_Db(None),
            user={"sub": "owner-a", "role": "operator", "tenant_id": "tenant-a"},
        )
    assert exc.value.status_code == 404
