"""Control evaluation: turn connector evidence into per-control verdicts.

A scan produces findings, which only ever say what is wrong. An assessment
must also say what is *right*, and must distinguish "this control passed" from
"nothing has looked at this control yet". Those are three different operator
answers and collapsing them is how posture dashboards start lying.

The rules here are deliberate:

* PASS requires a collector to have actually run and returned no violation.
  Silence is never success.
* FAIL requires an open finding mapped to the control.
* NOT_ASSESSED is the honest default and is reported, not hidden, so coverage
  gaps stay visible instead of inflating a compliance score.
* A control with no evaluator can never be PASS. It is NOT_APPLICABLE for
  scoring and surfaces as a recommendation.
"""
from __future__ import annotations

import enum
import logging
from datetime import datetime, timedelta
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.control import Control
from app.models.finding import Finding

logger = logging.getLogger("controls.evaluation")

# Evidence older than this is stale: it describes a system state that may no
# longer hold, so it downgrades to NOT_ASSESSED rather than a stale PASS.
EVIDENCE_FRESHNESS = timedelta(days=7)


class Verdict(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_ASSESSED = "not_assessed"
    # No deterministic evaluator exists, so the control is guidance only.
    RECOMMENDATION = "recommendation"
    ERROR = "error"


def _status(finding: Finding) -> str:
    value = finding.status
    return value.value if hasattr(value, "value") else str(value)


def _severity(finding: Finding) -> str:
    value = finding.severity
    return value.value if hasattr(value, "value") else str(value)


def _fresh(moment: datetime | None) -> bool:
    if moment is None:
        return False
    reference = moment.replace(tzinfo=None) if moment.tzinfo else moment
    return datetime.utcnow() - reference <= EVIDENCE_FRESHNESS


def verdict_for(control: Control, findings: Iterable[Finding], collector_ran: bool) -> dict[str, Any]:
    """Decide one control's verdict from its evidence."""
    rows = list(findings)
    # Demonstration data explains an empty screen; it must never become a
    # compliance verdict. Only live evidence can fail a control.
    live_rows = [row for row in rows if str(getattr(row, "data_origin", "")) == "live"]
    open_rows = [row for row in live_rows if _status(row) == "open"]

    if control.evaluator_key is None:
        return {
            "verdict": Verdict.RECOMMENDATION.value,
            "reason": "No deterministic evaluator is attached; this control is guidance only.",
            "evidence_count": len(rows),
        }
    if open_rows:
        worst = max(open_rows, key=lambda row: row.risk_score or 0)
        return {
            "verdict": Verdict.FAIL.value,
            "reason": f"{len(open_rows)} open finding(s) violate this control.",
            "evidence_count": len(rows),
            "worst_severity": _severity(worst),
            "worst_risk_score": worst.risk_score,
            "example_finding_id": str(worst.id),
        }
    if not collector_ran:
        return {
            "verdict": Verdict.NOT_ASSESSED.value,
            "reason": "No collector has produced evidence for this control yet.",
            "evidence_count": len(rows),
        }
    if live_rows and not any(_fresh(row.last_seen) for row in live_rows):
        return {
            "verdict": Verdict.NOT_ASSESSED.value,
            "reason": "Evidence exists but is older than the freshness window.",
            "evidence_count": len(rows),
        }
    return {
        "verdict": Verdict.PASS.value,
        "reason": "The collector ran and returned no violation of this control.",
        "evidence_count": len(rows),
    }


async def evaluate_controls(
    db: AsyncSession,
    *,
    claw: str | None = None,
    control_id: str | None = None,
    collectors_ran: set[str] | None = None,
) -> dict[str, Any]:
    """Evaluate a control set and return verdicts plus an honest score."""
    from app.services.control_collectors import collector_ready, configured_connectors

    active = await configured_connectors(db)
    statement = select(Control)
    if claw:
        statement = statement.where(Control.claw == claw)
    if control_id:
        statement = statement.where(Control.control_id == control_id)
    controls = (await db.execute(statement)).scalars().all()

    finding_statement = select(Finding)
    if claw:
        finding_statement = finding_statement.where(Finding.claw == claw)
    findings = (await db.execute(finding_statement)).scalars().all()

    by_control: dict[str, list[Finding]] = {}
    for row in findings:
        if row.control_id:
            by_control.setdefault(row.control_id, []).append(row)

    results = []
    counts: dict[str, int] = {}
    for control in controls:
        # PASS requires two independent facts: the collector's connector is
        # actually configured, and that node produced fresh evidence. Recent
        # findings alone are not enough, because demonstration data and
        # findings from an unrelated provider would otherwise manufacture a
        # pass for a control nothing ever looked at.
        ready = control.evaluator_key in (collectors_ran or set()) or collector_ready(
            control.evaluator_key, active
        )
        observed = any(
            row.claw == control.claw
            and _fresh(row.last_seen)
            and str(getattr(row, "data_origin", "")) == "live"
            for row in findings
        )
        collector_ran = bool(ready and observed)
        outcome = verdict_for(control, by_control.get(control.control_id, []), collector_ran)
        counts[outcome["verdict"]] = counts.get(outcome["verdict"], 0) + 1
        results.append({
            "control_id": control.control_id,
            "title": control.title,
            "claw": control.claw,
            "zt_pillar": control.zt_pillar,
            "severity": control.severity,
            "source": control.source,
            "evaluator_key": control.evaluator_key,
            "remediation_action": control.remediation_action,
            **outcome,
        })

    assessed = counts.get(Verdict.PASS.value, 0) + counts.get(Verdict.FAIL.value, 0)
    return {
        "claw": claw,
        "control_id": control_id,
        "evaluated": len(results),
        "counts": counts,
        "assessed": assessed,
        # Scored only over controls that were actually assessed. Unassessed
        # controls are reported separately instead of counting as passes.
        "pass_rate": round(100 * counts.get(Verdict.PASS.value, 0) / assessed, 1) if assessed else None,
        "assessment_coverage": round(100 * assessed / len(results), 1) if results else 0.0,
        "results": sorted(results, key=lambda item: (item["verdict"] != "fail", item["control_id"])),
        "evaluated_at": datetime.utcnow().isoformat(),
    }
