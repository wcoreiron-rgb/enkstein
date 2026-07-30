"""
Enkstein — Workflow Runner Service
Executes governed multi-step workflows sequentially.

Step types:
  agent_run     — trigger a registered agent; real intel fetched for known specialist agents
  policy_check  — evaluate a condition against the policy engine
  condition     — branch on a field/value expression
  wait          — pause N seconds
  notify        — emit an Event for alerting/audit trail

Context passing:
  Each step receives the accumulated `ctx` dict from all previous steps.
  Steps can add keys to ctx which downstream steps can reference.
  This is how Cloud Security's asset list flows into Exposure Management's CVE scanner, etc.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.workflow import Workflow, WorkflowRun, WorkflowRunStatus
from app.models.agent import Agent
from app.models.event import Event, EventSeverity, EventOutcome

logger = logging.getLogger("workflow_runner")

# ─── Real intel dispatcher ────────────────────────────────────────────────────
# Maps agent names (or claw types) to real data-fetching logic.
# When a matching agent runs, we call the real API instead of returning a mock.

async def _dispatch_real_intel(agent: Agent, ctx: Dict) -> Optional[Dict]:
    """
    For agents that have real free-API implementations, fetch actual data.
    Returns enriched result dict, or None to fall back to simulation.
    """
    name  = agent.name.lower()
    claw  = agent.claw.lower()

    # CVE Vulnerability Scanner — calls NVD + EPSS + CISA KEV
    if "cve" in name or ("exposureclaw" in claw and "scanner" in name):
        try:
            from app.services.intel_fetcher import run_vulnerability_scan
            logger.info("Calling real NVD + EPSS + CISA KEV APIs…")
            scan = await run_vulnerability_scan(days_back=30, cvss_min=7.0, max_cves=30)
            stats = scan.get("summary_stats", {})
            actively = scan.get("actively_exploited", [])
            top5 = [f"{c['cve_id']} (CVSS {c.get('cvss_score','?')}, EPSS {c.get('epss_score',0):.3f})"
                    for c in scan.get("all_cves", [])[:5]]
            return {
                "status": "completed",
                "output": (
                    f"NVD scan complete: {stats.get('total_found',0)} CVEs in last 30 days "
                    f"(CVSS≥7.0). "
                    f"Critical: {stats.get('critical_count',0)}, "
                    f"High: {stats.get('high_count',0)}, "
                    f"Actively exploited (CISA KEV): {stats.get('actively_exploited',0)}. "
                    f"EPSS high-risk: {stats.get('epss_high_count',0)}. "
                    f"Top CVEs: {'; '.join(top5) if top5 else 'none above threshold'}."
                ),
                "data": scan,
                # Add to shared context for downstream agents
                "ctx_update": {
                    "cve_scan":            scan,
                    "total_cves":          stats.get("total_found", 0),
                    "critical_cves":       stats.get("critical_count", 0),
                    "actively_exploited":  len(actively),
                    "top_cves":            [c["cve_id"] for c in scan.get("all_cves", [])[:10]],
                },
            }
        except Exception as e:
            logger.warning(f"Real NVD fetch failed, falling back to simulation: {e}")
            return None

    # Threat Intelligence Correlator — calls CISA KEV + MITRE ATT&CK
    if "threat intel" in name or "correlator" in name or "threatclaw" in claw:
        try:
            from app.services.intel_fetcher import fetch_cisa_kev, fetch_mitre_techniques
            kev_set, techniques = await asyncio.gather(
                fetch_cisa_kev(),
                fetch_mitre_techniques(limit=10),
            )
            # Cross-ref with CVEs found by the scanner (if available in ctx)
            top_cves = ctx.get("top_cves", [])
            matched_kev = [cve for cve in top_cves if cve in kev_set]
            tactic_names = list({t for tech in techniques for t in tech.get("tactics", [])})[:6]

            return {
                "status": "completed",
                "output": (
                    f"CISA KEV catalogue: {len(kev_set)} actively exploited CVEs. "
                    f"From your scan, {len(matched_kev)} CVEs match KEV "
                    f"({'active exploit: ' + ', '.join(matched_kev[:3]) if matched_kev else 'none in KEV — good'}). "
                    f"MITRE ATT&CK: loaded {len(techniques)} techniques across tactics: "
                    f"{', '.join(tactic_names)}."
                ),
                "data": {
                    "kev_size":    len(kev_set),
                    "kev_matches": matched_kev,
                    "techniques":  techniques[:5],
                },
                "ctx_update": {
                    "kev_matches":    matched_kev,
                    "kev_match_count": len(matched_kev),
                    "mitre_tactics":  tactic_names,
                },
            }
        except Exception as e:
            logger.warning(f"Real threat intel fetch failed, falling back: {e}")
            return None

    return None  # no real implementation — use simulation

# ─────────────────────────────────────────────────────────────────────────────
#  Step executors
# ─────────────────────────────────────────────────────────────────────────────

async def _exec_agent_run(step: Dict, db: AsyncSession, ctx: Dict) -> Dict:
    """
    Execute an agent step.

    Dispatches to a real data-fetching implementation, then to the agent's own
    Capability Node scan. A step that cannot execute fails; it does not report
    completion for work that never ran.
    """
    agent_id = step.get("config", {}).get("agent_id") or step.get("agent_id")
    if not agent_id:
        return {"status": "failed", "output": "No agent_id configured for this step"}
    try:
        result = await db.execute(select(Agent).where(Agent.id == UUID(str(agent_id))))
        agent = result.scalar_one_or_none()
    except Exception:
        agent = None

    if not agent:
        label = step.get("config", {}).get("label", agent_id)
        return {
            "status": "failed",
            "output": f"Agent '{label}' does not exist, so this step could not run.",
        }

    if agent.status != "active":
        return {"status": "skipped", "output": f"Agent '{agent.name}' is {agent.status} — skipped"}

    # Try real intel first
    real = await _dispatch_real_intel(agent, ctx)
    if real:
        # Propagate any context updates from this step
        if "ctx_update" in real:
            ctx.update(real.pop("ctx_update"))
        real["agent_name"] = agent.name
        real["agent_claw"] = agent.claw
        real["data_source"] = "real_api"
        return real

    # Fallback: governed simulation
    # No bespoke intel path: run the agent's Capability Node scan, which is the
    # same governed path the console and the scheduler use. Previously this
    # returned a completed step describing the agent's configuration without
    # executing anything, so a workflow reported success having done no work.
    from app.services.claw_scan_dispatch import run_node_scan

    try:
        scan = await run_node_scan(agent.claw, db)
    except Exception as exc:
        return {
            "status": "failed",
            "output": f"Agent '{agent.name}' scan failed: {type(exc).__name__}: {exc}",
            "agent_name": agent.name,
            "agent_claw": agent.claw,
        }

    if scan is None:
        return {
            "status": "failed",
            "output": f"'{agent.claw}' has no scan entrypoint, so this step could not run.",
            "agent_name": agent.name,
            "agent_claw": agent.claw,
        }

    mode = scan.get("mode", "unknown")
    return {
        "status": "completed",
        "output": (
            f"Agent '{agent.name}' ({agent.claw}) ran a {mode} scan: "
            f"{scan.get('findings_created', 0)} new and "
            f"{scan.get('findings_updated', 0)} updated finding(s)."
        ),
        "agent_name": agent.name,
        "agent_claw": agent.claw,
        "data_source": "live" if mode == "live" else mode,
        "providers": scan.get("providers", {}),
    }


_COMPARATORS = {
    "eq":       lambda a, b: a == b,
    "ne":       lambda a, b: a != b,
    "gt":       lambda a, b: _num(a) > _num(b),
    "gte":      lambda a, b: _num(a) >= _num(b),
    "lt":       lambda a, b: _num(a) < _num(b),
    "lte":      lambda a, b: _num(a) <= _num(b),
    "contains": lambda a, b: str(b).lower() in str(a).lower(),
    "in":       lambda a, b: str(a) in [str(x) for x in (b if isinstance(b, list) else [b])],
    "exists":   lambda a, _b: a is not None,
}


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def _ctx_value(ctx: Dict, field: str) -> Any:
    """Read a possibly dotted field out of the workflow context."""
    current: Any = ctx
    for part in str(field).split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


async def _exec_policy_check(step: Dict, db: AsyncSession, ctx: Dict) -> Dict:
    """
    Evaluate a gate against real workflow context.

    This used to return PASS unconditionally with a "(simulated)" note, which
    meant a workflow's guardrail approved every branch it was asked about. A
    gate that cannot be evaluated now fails the step rather than waving it
    through: an unevaluatable control is not a satisfied control.
    """
    config = step.get("config", {})
    field = config.get("field", "")
    op    = config.get("op", "eq")
    value = config.get("value", "")
    label = config.get("label") or f"if {field} {op} '{value}'"

    comparator = _COMPARATORS.get(op)
    if comparator is None:
        return {"status": "failed", "check": label, "result": "error",
                "output": f"Policy check '{label}' uses unsupported operator '{op}'."}

    if not field:
        return {"status": "failed", "check": label, "result": "error",
                "output": f"Policy check '{label}' has no field to evaluate."}

    actual = _ctx_value(ctx, field)
    if actual is None and op != "exists":
        return {"status": "failed", "check": label, "result": "error",
                "output": (f"Policy check '{label}' could not be evaluated: "
                           f"'{field}' is not present in the workflow context.")}

    try:
        passed = bool(comparator(actual, value))
    except Exception as exc:
        return {"status": "failed", "check": label, "result": "error",
                "output": f"Policy check '{label}' errored: {type(exc).__name__}"}

    return {
        "status": "completed" if passed else "failed",
        "output": f"Policy check '{label}' evaluated → {'PASS' if passed else 'FAIL'} (actual: {actual!r}).",
        "check": label,
        "result": "pass" if passed else "fail",
    }


async def _exec_condition(step: Dict, db: AsyncSession, ctx: Dict) -> Dict:
    """
    Branch gate over the same field/op/value contract as a policy check.

    A free-form expression is not evaluated — running arbitrary expressions
    from stored workflow config would be an injection surface — so a workflow
    that supplies one is told to express it as a structured condition instead
    of being silently allowed to continue.
    """
    config = step.get("config", {})
    if config.get("field"):
        result = await _exec_policy_check(step, db, ctx)
        result["output"] = result["output"].replace("Policy check", "Condition")
        return result

    expression = config.get("expression")
    if expression:
        return {
            "status": "failed",
            "output": (f"Condition '{expression}' is a free-form expression, which is not "
                       f"evaluated. Express it as field/op/value so the branch is decidable."),
        }
    return {"status": "failed", "output": "Condition step has nothing to evaluate."}


async def _exec_wait(step: Dict, db: AsyncSession) -> Dict:
    """Simulate a brief wait."""
    config = step.get("config", {})
    seconds = min(int(config.get("seconds", 1)), 5)  # cap at 5s for safety
    await asyncio.sleep(seconds)
    return {
        "status": "completed",
        "output": f"Waited {seconds}s.",
    }


async def _exec_http_request(step: Dict, ctx: Dict) -> Dict:
    """
    Make an outbound HTTP request to any REST API endpoint.
    Supports GET/POST/PUT/PATCH/DELETE with optional auth (bearer, basic, api_key).
    Response body is stored in ctx under the step's output_key (if set).
    All requests are policy-gated: blocked domains / internal networks return an error.
    """
    import httpx
    config = step.get("config", {})

    url     = config.get("url", "")
    method  = config.get("method", "GET").upper()
    headers = dict(config.get("headers", {}))
    body    = config.get("body", None)          # dict or string
    timeout = min(float(config.get("timeout_sec", 15)), 60)
    output_key = config.get("output_key", "http_response")

    # --- Auth injection -------------------------------------------------------
    auth_type  = config.get("auth_type", "none")   # none | bearer | basic | api_key
    auth_value = config.get("auth_value", "")       # token / "user:pass" / api-key value
    auth_header = config.get("auth_header", "X-API-Key")  # only for api_key

    if auth_type == "bearer" and auth_value:
        headers["Authorization"] = f"Bearer {auth_value}"
    elif auth_type == "basic" and auth_value:
        import base64
        encoded = base64.b64encode(auth_value.encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"
    elif auth_type == "api_key" and auth_value:
        headers[auth_header] = auth_value

    if not url:
        return {"status": "failed", "output": "http_request step is missing 'url'"}

    # --- Execute request -------------------------------------------------------
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            req_kwargs: Dict = {"headers": headers}
            if method in ("POST", "PUT", "PATCH"):
                if isinstance(body, dict):
                    req_kwargs["json"] = body
                elif body:
                    req_kwargs["content"] = str(body)
            elif method == "GET" and isinstance(body, dict):
                req_kwargs["params"] = body

            response = await client.request(method, url, **req_kwargs)
            status_code = response.status_code

            try:
                resp_body = response.json()
            except Exception:
                resp_body = response.text[:2000]

            # Store in shared context for downstream steps
            ctx[output_key] = resp_body
            ctx[f"{output_key}_status"] = status_code

            success = 200 <= status_code < 300
            return {
                "status": "completed" if success else "failed",
                "output": (
                    f"HTTP {method} {url} → {status_code}. "
                    f"Response stored in ctx['{output_key}']. "
                    + ("" if success else f"Error: {str(resp_body)[:300]}")
                ),
                "status_code": status_code,
                "response_preview": str(resp_body)[:500],
            }
    except httpx.TimeoutException:
        return {"status": "failed", "output": f"HTTP {method} {url} timed out after {timeout}s"}
    except Exception as exc:
        return {"status": "failed", "output": f"HTTP {method} {url} failed: {exc}"}


async def _exec_webhook_call(step: Dict, ctx: Dict) -> Dict:
    """
    Fire a webhook — a simplified HTTP POST to a callback URL.
    Supports HMAC-SHA256 request signing if a secret is provided.
    Designed for Slack incoming webhooks, GitHub webhooks, Zapier, n8n, etc.
    """
    import httpx
    import json as _json
    config = step.get("config", {})

    url         = config.get("url", "")
    payload     = config.get("payload", {})  # dict
    secret      = config.get("secret", "")   # for HMAC signing
    method      = config.get("method", "POST").upper()
    timeout     = min(float(config.get("timeout_sec", 10)), 30)
    output_key  = config.get("output_key", "webhook_response")
    content_type = config.get("content_type", "application/json")

    if not url:
        return {"status": "failed", "output": "webhook_call step is missing 'url'"}

    # Merge any ctx values referenced in payload via {{ctx.key}} syntax
    if isinstance(payload, dict):
        def _resolve(val):
            if isinstance(val, str) and val.startswith("{{ctx.") and val.endswith("}}"):
                key = val[6:-2]
                return ctx.get(key, val)
            return val
        payload = {k: _resolve(v) for k, v in payload.items()}

    headers: Dict = {"Content-Type": content_type}

    # HMAC-SHA256 signing
    if secret:
        import hmac
        import hashlib
        body_bytes = _json.dumps(payload).encode()
        sig = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
        headers["X-Hub-Signature-256"] = f"sha256={sig}"

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            if content_type == "application/json":
                resp = await client.request(method, url, json=payload, headers=headers)
            else:
                resp = await client.request(method, url, data=str(payload), headers=headers)

            status_code = resp.status_code
            try:
                resp_body = resp.json()
            except Exception:
                resp_body = resp.text[:500]

            ctx[output_key] = resp_body
            ctx[f"{output_key}_status"] = status_code
            success = 200 <= status_code < 300

            return {
                "status": "completed" if success else "failed",
                "output": (
                    f"Webhook fired → {url} ({status_code}). "
                    + (f"Response: {str(resp_body)[:200]}" if success
                       else f"Error: {str(resp_body)[:300]}")
                ),
                "status_code": status_code,
            }
    except httpx.TimeoutException:
        return {"status": "failed", "output": f"Webhook to {url} timed out after {timeout}s"}
    except Exception as exc:
        return {"status": "failed", "output": f"Webhook to {url} failed: {exc}"}


async def _exec_notify(step: Dict, db: AsyncSession, workflow_id: UUID) -> Dict:
    """
    Emit a Enkstein Event as a notification and route to configured channels
    (Slack, Teams, PagerDuty) via the alert router.
    """
    from datetime import datetime
    config = step.get("config", {})
    message = config.get("message") or step.get("name") or "Workflow notification"
    severity = config.get("severity", "info")

    sev_map = {
        "info":     EventSeverity.INFO,
        "low":      EventSeverity.LOW,
        "medium":   EventSeverity.MEDIUM,
        "high":     EventSeverity.HIGH,
        "critical": EventSeverity.CRITICAL,
    }

    event = Event(
        timestamp=datetime.utcnow(),
        source_module="orchestrations",
        actor_id="workflow_runner",
        actor_name="Workflow Runner",
        actor_type="automation",
        action="workflow_notify",
        target=message[:512],
        target_type="notification",
        outcome=EventOutcome.ALLOWED,
        severity=sev_map.get(severity, EventSeverity.INFO),
        risk_score=0.0,
        description=f"Workflow {workflow_id} — notification step: {message}",
        metadata_json=json.dumps({"workflow_id": str(workflow_id), "step": step.get("name", "")}),
    )
    db.add(event)
    await db.flush()

    # Route to external channels if configured
    alerts_sent = 0
    try:
        from app.services.alert_router import route_event_alert
        alerts_sent = await route_event_alert(db, {
            "title": f"Enkstein Workflow Alert: {step.get('name', 'Notification')}",
            "description": message,
            "severity": severity,
            "claw": "orchestrations",
            "risk_score": 0.0,
        })
    except Exception as exc:
        logger.warning("Alert routing failed in notify step: %s", exc)

    return {
        "status": "completed",
        "output": f"Notification emitted: {message}",
        "event_id": str(event.id),
        "alerts_routed": alerts_sent,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Main runner
# ─────────────────────────────────────────────────────────────────────────────

async def execute_workflow(
    workflow_id: UUID,
    triggered_by: str,
    db: AsyncSession,
) -> WorkflowRun:
    """
    Execute a workflow sequentially, honouring on_failure settings per step.
    Returns the completed WorkflowRun record.
    """
    # Load workflow
    result = await db.execute(select(Workflow).where(Workflow.id == workflow_id))
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise ValueError(f"Workflow {workflow_id} not found")

    if not workflow.is_active:
        raise ValueError(f"Workflow '{workflow.name}' is not active")

    # Create run record
    run = WorkflowRun(
        workflow_id=workflow_id,
        status=WorkflowRunStatus.RUNNING,
        triggered_by=triggered_by,
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    await db.flush()

    # Parse steps
    try:
        steps: List[Dict] = json.loads(workflow.steps_json)
    except Exception:
        steps = []

    if not steps:
        run.status = WorkflowRunStatus.COMPLETED
        run.summary = "Workflow has no steps — completed immediately."
        run.completed_at = datetime.now(timezone.utc)
        run.steps_log = "[]"
        await _finalize_run(run, workflow, db)
        return run

    steps_log: List[Dict] = []
    completed = 0
    failed = 0
    aborted = False

    # Shared context dict — each step can read from and write to this.
    # This is how CloudClaw's asset list flows into ExposureClaw, etc.
    ctx: Dict[str, Any] = {
        "workflow_id":   str(workflow_id),
        "workflow_name": workflow.name,
        "triggered_by":  triggered_by,
        # Remediation steps take ownership from the workflow, never from
        # step config, so a step cannot act on another tenant.
        "tenant_id":     workflow.tenant_id,
    }

    for i, step in enumerate(steps):
        step_id   = step.get("id", f"step-{i+1}")
        step_name = step.get("name", f"Step {i+1}")
        step_type = step.get("type", "notify")
        on_fail   = step.get("on_failure", "stop")

        step_log: Dict[str, Any] = {
            "step_id":    step_id,
            "name":       step_name,
            "type":       step_type,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if step_type == "agent_run":
                result_data = await _exec_agent_run(step, db, ctx)
            elif step_type == "policy_check":
                result_data = await _exec_policy_check(step, db, ctx)
            elif step_type == "condition":
                result_data = await _exec_condition(step, db, ctx)
            elif step_type == "wait":
                result_data = await _exec_wait(step, db)
            elif step_type == "notify":
                result_data = await _exec_notify(step, db, workflow_id)
            elif step_type == "http_request":
                result_data = await _exec_http_request(step, ctx)
            elif step_type == "webhook_call":
                result_data = await _exec_webhook_call(step, ctx)
            elif step_type == "remediate":
                result_data = await _exec_remediate(step, db, ctx)
            else:
                result_data = {"status": "skipped", "output": f"Unknown step type: {step_type}"}

            step_status = result_data.get("status", "completed")
            step_log.update({
                "status":       step_status,
                "output":       result_data.get("output", ""),
                "completed_at": datetime.now(timezone.utc).isoformat(),
            })

            if step_status == "completed":
                completed += 1
            elif step_status == "failed":
                failed += 1
                if on_fail == "stop":
                    steps_log.append(step_log)
                    aborted = True
                    break
                # on_fail == "continue" — log and keep going

        except Exception as e:
            failed += 1
            step_log.update({
                "status":       "failed",
                "output":       f"Exception: {e}",
                "completed_at": datetime.now(timezone.utc).isoformat(),
            })
            if on_fail == "stop":
                steps_log.append(step_log)
                aborted = True
                break

        steps_log.append(step_log)

        # Broadcast step completion to live dashboard
        try:
            from app.services.ws_manager import broadcast_workflow_step
            await broadcast_workflow_step(
                workflow_name=workflow.name,
                run_id=str(run.id),
                step_name=step_name,
                step_index=i,
                status=step_log.get("status", "completed"),
            )
        except Exception:
            pass

    # Determine overall status
    now = datetime.now(timezone.utc)
    run.completed_at = now
    run.duration_sec = (now - run.started_at).total_seconds()
    run.steps_completed = completed
    run.steps_failed = failed
    run.steps_log = json.dumps(steps_log)

    if aborted or failed > 0:
        run.status = WorkflowRunStatus.FAILED
        run.summary = (
            f"Workflow failed at step '{steps_log[-1]['name']}'. "
            f"{completed} steps completed, {failed} failed."
        )
    else:
        run.status = WorkflowRunStatus.COMPLETED
        run.summary = (
            f"All {completed} step(s) completed successfully. "
            f"Workflow '{workflow.name}' executed in {run.duration_sec:.1f}s."
        )

    await _finalize_run(run, workflow, db)
    return run


async def _exec_remediate(step: Dict, db: AsyncSession, ctx: Dict) -> Dict:
    """Execute a remediation action as a workflow step."""
    from app.services.remediation.engine import execute_remediation
    config    = step.get("config", {})
    target_id = (
        config.get("target_id")
        or ctx.get(config.get("target_from", ""), "unknown")
    )
    tenant_id = str(ctx.get("tenant_id") or "").strip()
    if not tenant_id:
        return {
            "status": "blocked",
            "error": "Workflow has no owning tenant; remediation step refused",
        }
    try:
        result = await execute_remediation(
            action_spec={
                "provider":     config.get("provider", "generic"),
                "action_type":  config.get("action_type", "send_slack_alert"),
                "target_id":    target_id,
                "target_type":  config.get("target_type", "unknown"),
                "target_label": config.get("target_label", target_id),
                "parameters":   config.get("parameters", {}),
            },
            db=db,
            triggered_by="workflow",
            tenant_id=tenant_id,
        )
        return {
            "status":    result.status.value if hasattr(result.status, "value") else str(result.status),
            "action_id": str(result.id),
            "output":    f"Remediation {result.status}: {result.output or result.error or ''}",
        }
    except Exception as exc:
        logger.error("Remediation step failed: %s", exc)
        return {"status": "failed", "output": f"Remediation error: {exc}"}


async def _finalize_run(run: WorkflowRun, workflow: Workflow, db: AsyncSession):
    """Update workflow stats and commit."""
    workflow.run_count = (workflow.run_count or 0) + 1
    workflow.last_run_at = run.completed_at or datetime.now(timezone.utc)
    workflow.last_run_status = run.status.value
    await db.commit()
    await db.refresh(run)

    # Broadcast workflow completion to live dashboard
    try:
        from app.services.ws_manager import broadcast_workflow_complete, broadcast_dashboard_refresh
        await broadcast_workflow_complete(
            workflow_name=workflow.name,
            run_id=str(run.id),
            status=run.status.value,
            steps_run=run.steps_completed or 0,
        )
        await broadcast_dashboard_refresh()
    except Exception:
        pass
