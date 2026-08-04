"""Control verdicts and remediation candidates may only use caller-tenant evidence."""
from __future__ import annotations

import pytest

from app.models.control import Control
from app.models.finding import Finding, FindingSeverity
from app.services.control_evaluation import evaluate_controls
from app.services import control_remediation


@pytest.mark.asyncio
async def test_foreign_live_finding_cannot_fail_or_remediate_a_tenant_control(db_session):
    control = Control(
        control_id="ENKSTEIN-TENANT-TEST-1",
        source="authored",
        title="Scoped control",
        zt_pillar="identity",
        claw="identityclaw",
        severity="high",
        evaluator_key="identity.entra",
        remediation_action="revoke_sessions",
        recommendation_only=False,
        status="active",
    )
    foreign = Finding(
        tenant_id="tenant-b",
        claw="identityclaw",
        provider="entra_id",
        title="Foreign high-risk sign-in",
        severity=FindingSeverity.HIGH,
        risk_score=88,
        control_id=control.control_id,
        data_origin="live",
    )
    db_session.add_all([control, foreign])
    await db_session.commit()

    tenant_a = await evaluate_controls(db_session, claw="identityclaw", tenant_id="tenant-a")
    row_a = next(row for row in tenant_a["results"] if row["control_id"] == control.control_id)
    assert row_a["verdict"] == "not_assessed"

    tenant_b = await evaluate_controls(db_session, claw="identityclaw", tenant_id="tenant-b")
    row_b = next(row for row in tenant_b["results"] if row["control_id"] == control.control_id)
    assert row_b["verdict"] == "fail"

    proposal = await control_remediation.remediate_control(
        db_session, control_id=control.control_id, tenant_id="tenant-a"
    )
    assert proposal["status"] == "not_failing"
