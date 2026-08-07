"""
CoreOS — Policy Engine
Deterministic policy evaluation. Every action is checked before execution.
"""
import json
from dataclasses import dataclass
from typing import Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.policy import Policy, PolicyAction, PolicyScope


class PolicyResult:
    def __init__(self, action: PolicyAction, policy_name: str, reason: str):
        self.action = action
        self.policy_name = policy_name
        self.reason = reason
        self.allowed = action in (PolicyAction.ALLOW, PolicyAction.MONITOR)

    def __repr__(self):
        return f"<PolicyResult action={self.action} policy={self.policy_name}>"


@dataclass(frozen=True)
class PolicyCatalogResult:
    """Cross-module policy result with proof of catalog coverage.

    CoreOS is first-match-wins for enforcement, but Guard is a cross-cutting
    caller: a prompt, write, or command may implicate Identity, Data, Dev, AI
    Security, or several Arms at once. The Guard evaluator therefore checks
    every active policy condition across every scope, records the complete
    coverage count, then enforces the highest-priority match.
    """

    result: PolicyResult
    catalog_total: int
    policies_evaluated: int
    policies_matched: int
    invalid_conditions: int


OPERATORS = {
    "eq": lambda field_val, val: field_val == val,
    "neq": lambda field_val, val: field_val != val,
    "in": lambda field_val, val: field_val in val,
    "not_in": lambda field_val, val: field_val not in val,
    "contains": lambda field_val, val: val in str(field_val),
    "startswith": lambda field_val, val: str(field_val).startswith(val),
    "gt": lambda field_val, val: float(field_val) > float(val),
    "lt": lambda field_val, val: float(field_val) < float(val),
    "gte": lambda field_val, val: float(field_val) >= float(val),
    "lte": lambda field_val, val: float(field_val) <= float(val),
}


def _evaluate_condition(condition: dict, context: dict[str, Any]) -> bool:
    """Evaluate a single condition against context. Returns True if condition matches."""
    field = condition.get("field", "")
    operator = condition.get("op", "eq")
    value = condition.get("value")

    field_val = context.get(field)
    if field_val is None:
        return False

    evaluator = OPERATORS.get(operator)
    if evaluator is None:
        return False

    try:
        return evaluator(field_val, value)
    except Exception:
        return False


async def evaluate_action(
    db: AsyncSession,
    context: dict[str, Any],
    module: Optional[str] = None,
) -> PolicyResult:
    """
    Evaluate all active policies in priority order against the given context.
    Returns the first matching policy result.
    Default: ALLOW if no policy matches.
    """
    stmt = (
        select(Policy)
        .where(Policy.is_active == True)
        .order_by(Policy.priority.asc())
    )
    result = await db.execute(stmt)
    policies = result.scalars().all()

    for policy in policies:
        # Scope filtering
        if policy.scope == PolicyScope.MODULE and policy.scope_target != module:
            continue

        try:
            condition = json.loads(policy.condition_json)
        except (json.JSONDecodeError, TypeError):
            continue

        if _evaluate_condition(condition, context):
            return PolicyResult(
                action=policy.action,
                policy_name=policy.name,
                reason=f"Matched policy '{policy.name}' (priority {policy.priority})"
            )

    # Default: allow
    return PolicyResult(
        action=PolicyAction.ALLOW,
        policy_name="default",
        reason="No matching policy — default allow"
    )


async def evaluate_policy_catalog(
    db: AsyncSession,
    context: dict[str, Any],
) -> PolicyCatalogResult:
    """Evaluate the complete active CoreOS catalog for Enkstein Guard.

    Unlike module execution, Guard spans all modules, connector scopes, and
    identity scopes. Scope is still preserved as policy metadata; it simply
    does not remove a policy from consideration. Conditions whose evidence is
    absent return false, so a Cloud or Identity policy cannot fire merely
    because Guard evaluated it.
    """
    stmt = (
        select(Policy)
        .where(Policy.is_active == True)
        .order_by(Policy.priority.asc(), Policy.name.asc())
    )
    result = await db.execute(stmt)
    policies = result.scalars().all()

    first: PolicyResult | None = None
    evaluated = 0
    matched = 0
    invalid = 0

    for item in policies:
        try:
            condition = json.loads(item.condition_json)
        except (json.JSONDecodeError, TypeError):
            invalid += 1
            continue
        if not isinstance(condition, dict):
            invalid += 1
            continue

        evaluated += 1
        if not _evaluate_condition(condition, context):
            continue

        matched += 1
        if first is None:
            first = PolicyResult(
                action=item.action,
                policy_name=item.name,
                reason=(
                    f"Matched policy '{item.name}' (priority {item.priority}; "
                    f"scope {item.scope.value}"
                    f"{':' + item.scope_target if item.scope_target else ''})"
                ),
            )

    selected = first or PolicyResult(
        action=PolicyAction.ALLOW,
        policy_name="default",
        reason="No matching policy — default allow",
    )
    return PolicyCatalogResult(
        result=selected,
        catalog_total=len(policies),
        policies_evaluated=evaluated,
        policies_matched=matched,
        invalid_conditions=invalid,
    )
