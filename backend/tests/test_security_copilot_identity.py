import pytest

from app.claws.arcclaw import security_agent


@pytest.mark.asyncio
async def test_identity_request_forces_governed_detection_receipt(monkeypatch):
    calls = []

    async def _execute(name, inputs, db):
        calls.append((name, inputs))
        return {
            "task_id": "identity-task-test",
            "status": "completed",
            "data_source": "no_data_source",
            "connector_state": "unconfigured",
            "execution_outcome": "identity_connector_required",
            "findings": [],
        }

    async def _simple(messages, provider, api_key, system, model=None, db=None, initial_tool_calls=None):
        return {
            "response": "No approved identity connector is configured.",
            "tool_calls": initial_tool_calls or [],
            "steps": 1,
            "error": None,
        }

    monkeypatch.setattr(security_agent, "_execute_tool", _execute)
    monkeypatch.setattr(security_agent, "_run_simple_agent", _simple)

    result = await security_agent.run_security_agent(
        messages=[{"role": "user", "content": "Automate identity detection for [REDACTED]"}],
        provider="ollama",
        api_key="",
        db=object(),
    )

    assert calls[0][0] == "run_identity_detection"
    assert result["tool_calls"][0]["tool"] == "run_identity_detection"
    assert result["tool_calls"][0]["result"]["data_source"] == "no_data_source"
    assert result["tool_calls"][0]["input"]["focus"] == "[REDACTED REQUEST CONTEXT]"


@pytest.mark.asyncio
async def test_non_identity_question_does_not_force_identity_detection(monkeypatch):
    async def _execute(name, inputs, db):
        raise AssertionError("identity detection should not execute")

    async def _simple(messages, provider, api_key, system, model=None, db=None, initial_tool_calls=None):
        return {"response": "Hello", "tool_calls": initial_tool_calls or [], "steps": 1, "error": None}

    monkeypatch.setattr(security_agent, "_execute_tool", _execute)
    monkeypatch.setattr(security_agent, "_run_simple_agent", _simple)

    result = await security_agent.run_security_agent(
        messages=[{"role": "user", "content": "Explain least privilege"}],
        provider="ollama",
        api_key="",
        db=object(),
    )
    assert result["tool_calls"] == []
