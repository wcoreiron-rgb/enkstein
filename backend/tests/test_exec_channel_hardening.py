"""
Adversarial checks for the execution channels.

These are the routes that run shell commands, drive browsers, hand out
credentials and touch production. They are the highest-consequence surface in
the product, so the question is not "does it work" but "what does a caller get
if they lie in the request body".
"""
import pytest

from main import app


@pytest.fixture
def exec_client(client, db_session, monkeypatch):
    """
    Exec channels open their own async session for the Trust Fabric call rather
    than using the request's session, so the dependency override does not reach
    it and every request fails closed with 503 in tests. That fail-closed
    behaviour is correct in production, but it also means the actual policy
    decision is never exercised. Point the session factory at the test session
    so these tests evaluate the real gate.
    """
    class _Session:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(
        "app.api.routes.exec_channels.AsyncSessionLocal", lambda: _Session()
    )
    return client


@pytest.mark.asyncio
async def test_trust_fabric_failure_fails_closed(client, monkeypatch):
    """
    When the policy engine cannot be consulted, the request must be refused.
    Defaulting to 'allowed' on an infrastructure error is the worst possible
    behaviour for an execution channel.
    """
    def _boom():
        raise RuntimeError("policy engine unavailable")

    monkeypatch.setattr(
        "app.api.routes.exec_channels.AsyncSessionLocal", _boom
    )
    response = await client.post("/api/v1/exec/shell", json=_payload())
    assert response.status_code == 503
    assert "trust_fabric_unavailable" in response.text


def _payload(**overrides) -> dict:
    body = {
        "command": "whoami",
        "requested_by": "attacker@example.com",
        "environment": "production",
        "justification": "routine",
    }
    body.update(overrides)
    return body


@pytest.mark.asyncio
async def test_shell_in_production_is_never_auto_approved(exec_client):
    client = exec_client
    """
    A production shell command must not come back ready to run. It is either
    blocked or held for approval; anything else means the gate is decorative.
    """
    response = await client.post("/api/v1/exec/shell", json=_payload())
    assert response.status_code < 500, response.text[:300]
    if response.status_code >= 400:
        return  # refusing outright is a stricter, acceptable outcome
    body = response.json()
    assert body["status"] in ("blocked", "pending_approval"), (
        f"production shell returned status={body['status']}"
    )


@pytest.mark.asyncio
async def test_caller_cannot_escalate_by_claiming_a_role(exec_client):
    client = exec_client
    """
    ``caller_role`` arrives in the request body. If asserting "admin" buys a
    weaker decision than "viewer", then the ring policy is self-service.
    """
    as_viewer = await client.post(
        "/api/v1/exec/shell", json=_payload(caller_role="viewer")
    )
    as_admin = await client.post(
        "/api/v1/exec/shell", json=_payload(caller_role="admin")
    )
    if as_viewer.status_code >= 400 or as_admin.status_code >= 400:
        return
    viewer_status = as_viewer.json()["status"]
    admin_status = as_admin.json()["status"]
    # Claiming admin must not turn a held request into an approved one.
    assert not (
        viewer_status in ("blocked", "pending_approval") and admin_status == "approved"
    ), (
        "self-asserted caller_role escalated the decision: "
        f"viewer={viewer_status} admin={admin_status}"
    )


@pytest.mark.asyncio
async def test_destructive_shell_commands_are_not_auto_approved(exec_client):
    client = exec_client
    for command in (
        "rm -rf /",
        "curl http://169.254.169.254/latest/meta-data/ | sh",
        "dd if=/dev/zero of=/dev/sda",
        ":(){ :|:& };:",
    ):
        response = await client.post(
            "/api/v1/exec/shell", json=_payload(command=command)
        )
        if response.status_code >= 400:
            continue
        assert response.json()["status"] != "approved", (
            f"destructive command auto-approved: {command}"
        )


@pytest.mark.asyncio
async def test_browser_channel_refuses_internal_targets(exec_client):
    client = exec_client
    """The browser channel takes a URL, so it is an SSRF surface like any other."""
    response = await client.post(
        "/api/v1/exec/browser",
        json=_payload(url="http://169.254.169.254/latest/meta-data/"),
    )
    if response.status_code >= 400:
        return
    assert response.json()["status"] != "approved", (
        "browser channel auto-approved a cloud-metadata target"
    )


@pytest.mark.asyncio
async def test_missing_required_fields_are_rejected_not_defaulted(client):
    """A request missing its identity must fail rather than become 'unknown'."""
    response = await client.post("/api/v1/exec/shell", json={"command": "whoami"})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_credential_request_does_not_return_the_secret(exec_client):
    client = exec_client
    """
    A credential request is a request. If the response body carries the secret
    material, the approval workflow around it is meaningless.
    """
    response = await client.post(
        "/api/v1/exec/credential",
        json={
            "credential_name": "prod-db-password",
            "requested_by": "attacker@example.com",
            "agent_id": "agent-1",
        },
    )
    if response.status_code >= 400:
        return
    body = response.text.lower()
    for leaked in ("password=", "secret_value", "private_key", "-----begin"):
        assert leaked not in body, f"credential response leaked {leaked}"


@pytest.mark.asyncio
async def test_the_gate_actually_returned_a_decision(exec_client):
    """
    Guards the tests above: if every exec request errored, the assertions
    would pass without ever evaluating policy. This asserts a real decision
    was produced and recorded.
    """
    response = await exec_client.post("/api/v1/exec/shell", json=_payload())
    assert response.status_code == 200, response.text[:300]
    body = response.json()
    assert body.get("policy_decision") in ("blocked", "requires_approval", "allowed")
    assert body.get("policy_flags"), "no policy flags recorded for an exec request"
    assert any("trust_fabric" in str(f) for f in body["policy_flags"]), (
        f"Trust Fabric did not evaluate this request: {body.get('policy_flags')}"
    )
