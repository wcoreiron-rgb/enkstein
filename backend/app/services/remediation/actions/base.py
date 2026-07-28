"""
Base classes and shared data structures for remediation action modules.

Every action module must expose:
  SUPPORTED_ACTIONS: list[str]
  async def execute(action_type, target_id, params, credentials) -> ActionResult
  async def rollback(action_type, target_id, rollback_data, credentials) -> ActionResult
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ActionResult:
    """Result returned from every action execute/rollback call."""
    success: bool
    message: str
    rollback_data: dict = field(default_factory=dict)
    output: dict = field(default_factory=dict)
    error: str | None = None


def not_configured(action_type: str, target_id: str, extra: dict | None = None) -> ActionResult:
    """Fail an action that cannot reach its provider.

    This previously returned ``success=True`` with a "Simulated:" message, so
    the engine recorded the action as COMPLETED. An operator reviewing the
    queue saw a disabled account or an isolated host that had never actually
    been touched, and the audit trail agreed with them. An action that does not
    execute is not a successful action, so it now fails with the reason.
    """
    return ActionResult(
        success=False,
        message=(
            f"Cannot execute '{action_type}' on '{target_id}': no credentials are "
            f"configured for this provider. Configure and approve its connector first."
        ),
        error="provider_not_configured",
        rollback_data=extra or {},
        output={"executed": False, "reason": "provider_not_configured",
                "action_type": action_type, "target_id": target_id},
    )
