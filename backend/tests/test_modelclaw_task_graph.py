import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.core.modelclaw import gateway, task_graph
from app.core.modelclaw.schemas import CortexGatewayRequest, CortexTaskGraphRequest


def _requester():
    return task_graph.TaskGraphRequester(
        subject="owner-123",
        role="operator",
        tenant_id="tenant-a",
        workspace_id="11111111-1111-1111-1111-111111111111",
    )


def _decision(allowed: bool = True):
    return SimpleNamespace(
        allowed=allowed,
        outcome=SimpleNamespace(value="allowed" if allowed else "blocked"),
        policy_name="Task graph policy",
        reason="approved" if allowed else "peer data denied",
    )


class _SessionContext:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *args):
        return False


def _payload(**updates):
    body = {
        "objective": "Implement and verify one bounded change",
        "nodes": [
            {"id": "plan", "role": "planner", "instruction": "Create the plan", "sources": ["codex_subscription"]},
            {
                "id": "review",
                "role": "reviewer",
                "instruction": "Review the plan",
                "depends_on": ["plan"],
                "sources": ["claude_subscription", "profile:ollama_local_fallback"],
            },
        ],
    }
    body.update(updates)
    return CortexTaskGraphRequest(**body)


def test_task_graph_rejects_cycles():
    with pytest.raises(ValidationError, match="acyclic"):
        _payload(nodes=[
            {"id": "one", "role": "planner", "instruction": "one", "depends_on": ["two"]},
            {"id": "two", "role": "reviewer", "instruction": "two", "depends_on": ["one"]},
        ])


def test_gateway_audit_record_preserves_task_graph_attribution(monkeypatch):
    captured = {}
    monkeypatch.setattr(gateway, "record_model_call", lambda row: captured.update(row))
    gateway._record_gateway_call(
        CortexGatewayRequest(
            messages=[{"role": "user", "content": "bounded task"}],
            tenant_id="tenant-a",
            workspace_id=_requester().workspace_id,
            context={
                "requester_subject": "owner-123",
                "requester_role": "operator",
                "orchestrator_identity": "task-graph-orchestrator",
                "specialist_identity": "reviewer-agent",
                "validated_workspace_id": _requester().workspace_id,
                "dependency_evidence_ids": ["plan"],
            },
        ),
        "profile:ollama_local_fallback",
        {"provider": "ollama", "model": "qwen", "counted": True},
        {"outcome": "allowed", "policy_name": "test", "reason": "approved"},
        5,
    )
    assert captured["requester_subject"] == "owner-123"
    assert captured["requester_role"] == "operator"
    assert captured["orchestrator_identity"] == "task-graph-orchestrator"
    assert captured["specialist_identity"] == "reviewer-agent"
    assert captured["workspace_id"] == _requester().workspace_id
    assert captured["dependency_evidence_ids"] == ["plan"]


@pytest.mark.asyncio
async def test_task_graph_orders_dependencies_and_fallbacks(monkeypatch):
    monkeypatch.setattr(task_graph, "AsyncSessionLocal", lambda: _SessionContext())
    monkeypatch.setattr(task_graph, "enforce", lambda *a, **k: _awaitable(_decision()))
    calls = []

    async def gateway(_db, request):
        calls.append(request)
        if request.source == "claude_subscription":
            return {
                "status": "unavailable",
                "governance": {"outcome": "unavailable", "reason": "Claude is offline"},
                "routing": {"reason": "explicit"},
            }
        return {
            "status": "completed",
            "response": "reviewed" if request.capability == "reviewer" else "planned",
            "source": request.source,
            "provider": "test",
            "model": "test-model",
            "governance": {"outcome": "allowed", "reason": "approved"},
            "routing": {"reason": "ordered specialist route"},
        }

    monkeypatch.setattr(task_graph, "execute_cortex_gateway", gateway)
    result = await task_graph.execute_task_graph(object(), _payload(), _requester())

    assert result.status == "completed"
    assert result.execution_order == ["plan", "review"]
    assert [call.source for call in calls] == [
        "codex_subscription", "claude_subscription", "profile:ollama_local_fallback"
    ]
    assert result.results[1].evidence_from == ["plan"]
    assert result.results[1].fallback_reason == "Claude is offline"
    assert "[plan] planned" in calls[-1].messages[0].content
    attribution = calls[-1].context
    assert attribution["requester_subject"] == "owner-123"
    assert attribution["requester_role"] == "operator"
    assert attribution["orchestrator_identity"] == "task-graph-orchestrator"
    assert attribution["specialist_identity"] == "reviewer-agent"
    assert attribution["validated_workspace_id"] == _requester().workspace_id
    assert attribution["dependency_evidence_ids"] == ["plan"]


@pytest.mark.asyncio
async def test_task_graph_peer_denial_skips_dependent_execution(monkeypatch):
    monkeypatch.setattr(task_graph, "AsyncSessionLocal", lambda: _SessionContext())
    decisions = iter([_decision(), _decision(), _decision(False)])
    monkeypatch.setattr(task_graph, "enforce", lambda *a, **k: _awaitable(next(decisions)))

    async def gateway(_db, request):
        return {
            "status": "completed", "response": "planned", "source": request.source,
            "governance": {"outcome": "allowed"}, "routing": {"reason": "explicit"},
        }

    monkeypatch.setattr(task_graph, "execute_cortex_gateway", gateway)
    result = await task_graph.execute_task_graph(object(), _payload(), _requester())
    assert result.status == "partial"
    assert result.results[1].status == "blocked"
    assert result.results[1].policy["reason"] == "peer data denied"


@pytest.mark.asyncio
async def test_task_graph_propagates_cancellation(monkeypatch):
    monkeypatch.setattr(task_graph, "AsyncSessionLocal", lambda: _SessionContext())
    monkeypatch.setattr(task_graph, "enforce", lambda *a, **k: _awaitable(_decision()))

    async def cancelled(_db, _request):
        raise asyncio.CancelledError

    monkeypatch.setattr(task_graph, "execute_cortex_gateway", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await task_graph.execute_task_graph(object(), _payload(nodes=[
            {"id": "plan", "role": "planner", "instruction": "Create the plan"}
        ]), _requester())


async def _ready(value):
    return value


def _awaitable(value):
    return _ready(value)
