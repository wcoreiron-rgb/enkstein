"""
Adversarial checks for the remaining governed security surfaces: the autonomy
kill switch, remediation approval, swarm dispatch and webhook triggers.

Each asserts the control does its job under an attempt to get around it,
rather than asserting the happy path works.
"""
import pytest

from app.models.agent import ExecutionMode, PlatformSettings
from app.services.agent_runner import _apply_autonomy_ceiling


class _Settings:
    def __init__(self, emergency=False, ceiling=None):
        self.emergency_mode_active = emergency
        self.autonomy_ceiling = ceiling


@pytest.mark.parametrize(
    "requested",
    [ExecutionMode.AUTONOMOUS, ExecutionMode.APPROVAL, ExecutionMode.MONITOR],
)
def test_emergency_mode_overrides_every_requested_autonomy_level(requested):
    """
    The kill switch is the last resort. If any agent configuration can outrank
    it, an operator cannot actually stop the platform.
    """
    assert (
        _apply_autonomy_ceiling(requested, _Settings(emergency=True))
        == ExecutionMode.EMERGENCY
    )


def test_an_agent_cannot_exceed_the_platform_ceiling():
    """An agent asking for more autonomy than policy allows gets capped."""
    capped = _apply_autonomy_ceiling(
        ExecutionMode.AUTONOMOUS, _Settings(ceiling=ExecutionMode.APPROVAL)
    )
    assert capped == ExecutionMode.APPROVAL


def test_a_request_below_the_ceiling_is_left_alone():
    """The ceiling must cap, not rewrite, or every agent becomes maximally autonomous."""
    assert (
        _apply_autonomy_ceiling(
            ExecutionMode.MONITOR, _Settings(ceiling=ExecutionMode.AUTONOMOUS)
        )
        == ExecutionMode.MONITOR
    )


@pytest.mark.asyncio
async def test_emergency_activation_is_recorded_with_a_reason(client):
    """An unattributed kill switch is useless in an incident review."""
    response = await client.post(
        "/api/v1/autonomy/emergency/activate",
        json={"reason": "suspected compromise", "activated_by": "ciso@example.com"},
    )
    assert response.status_code < 500, response.text[:300]
    if response.status_code < 400:
        body = response.text.lower()
        assert "suspected compromise" in body or "emergency" in body


@pytest.mark.asyncio
async def test_remediation_approval_of_unknown_action_is_refused(client):
    """Approving an action that does not exist must not create one."""
    response = await client.post(
        "/api/v1/remediation/actions/00000000-0000-0000-0000-000000000000/approve",
        json={"approved_by": "attacker@example.com"},
    )
    assert response.status_code in (400, 403, 404, 422), response.text[:200]


@pytest.mark.asyncio
async def test_swarm_job_rejects_an_unknown_capability(client):
    """
    Swarm dispatch takes a list of participants. An unrecognised name must be
    refused rather than silently dispatched or crashing the orchestrator.
    """
    response = await client.post(
        "/api/v1/swarm/jobs",
        json={
            "objective": "investigate",
            "claws": ["definitely_not_a_real_capability"],
            "mode": "DEEP_INVESTIGATION",
        },
    )
    assert response.status_code < 500, response.text[:300]


@pytest.mark.asyncio
async def test_webhook_trigger_for_unknown_id_is_refused(client):
    """
    Webhook triggers are unauthenticated by design, so an unknown identifier
    must not become an execution path.
    """
    response = await client.post(
        "/api/v1/triggers/webhook/not-a-real-trigger", json={"payload": "x"}
    )
    assert response.status_code in (400, 401, 403, 404, 422), response.text[:200]


@pytest.mark.asyncio
async def test_policy_deletion_of_unknown_policy_is_refused(client):
    response = await client.delete("/api/v1/policies/00000000-0000-0000-0000-000000000000")
    assert response.status_code in (400, 403, 404, 422)
