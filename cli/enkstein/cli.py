"""
Enkstein CLI — Main entrypoint
Usage:  enkstein <group> <command> [options]
"""
import sys
import json
from typing import Optional
import typer
from . import client, fmt

app = typer.Typer(
    name="enkstein",
    help="Enkstein Zero Trust Ecosystem — CLI",
    add_completion=False,
    no_args_is_help=True,
)

# ─────────────────────────────────────────────
# run  — trigger & inspect workflow runs
# ─────────────────────────────────────────────
run_app = typer.Typer(help="Trigger and inspect workflow runs.", no_args_is_help=True)
app.add_typer(run_app, name="run")


@run_app.command("workflow")
def run_workflow(
    workflow_id: str = typer.Argument(..., help="Workflow ID to trigger"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Trigger a workflow run."""
    fmt.header(f"Triggering workflow {workflow_id}")
    try:
        result = client.post(f"/orchestrations/{workflow_id}/run")
        if json_flag:
            fmt.json_out(result)
        else:
            fmt.success(f"Run started: {result.get('run_id', result.get('id', '?'))}")
            fmt.kv("Status",  result.get("status", "—"))
            fmt.kv("Started", result.get("started_at", "—"))
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@run_app.command("agent")
def run_agent(
    agent_id: str  = typer.Argument(..., help="Agent ID to trigger"),
    input_json: str = typer.Option("{}", "--input", "-i", help="JSON input payload"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Trigger an agent run."""
    fmt.header(f"Triggering agent {agent_id}")
    try:
        body   = json.loads(input_json)
        result = client.post(f"/agents/{agent_id}/run", body)
        if json_flag:
            fmt.json_out(result)
        else:
            fmt.success(f"Run started: {result.get('run_id', result.get('id', '?'))}")
            fmt.kv("Status",  result.get("status", "—"))
            fmt.kv("Started", result.get("started_at", "—"))
    except json.JSONDecodeError as e:
        fmt.error(f"Invalid JSON input: {e}"); raise typer.Exit(1)
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@run_app.command("status")
def run_status(
    run_id: str  = typer.Argument(..., help="Run ID to inspect"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Check the status of a specific run."""
    fmt.header(f"Run {run_id}")
    try:
        result = client.get(f"/orchestrations/runs/{run_id}/replay")
        if json_flag:
            fmt.json_out(result)
            return
        run = result.get("run", result)
        fmt.kv("ID",         run.get("id", run_id))
        fmt.kv("Workflow",   run.get("workflow_id", "—"))
        fmt.kv("Status",     run.get("status", "—"),     fmt._status_color(run.get("status", "")))
        fmt.kv("Started",    run.get("started_at", "—"))
        fmt.kv("Completed",  run.get("completed_at") or "—")
        fmt.kv("Triggered by", run.get("triggered_by", "—"))
        steps = result.get("steps", [])
        if steps:
            fmt.header("Steps")
            fmt.table(
                steps,
                [("step_index", "#"), ("name", "Step"), ("status", "Status"),
                 ("started_at", "Started"), ("completed_at", "Completed")],
            )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@run_app.command("recent")
def run_recent(
    limit: int  = typer.Option(10, "--limit", "-n", help="Number of recent runs"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """List recent workflow runs."""
    fmt.header("Recent Runs")
    try:
        runs = client.get("/orchestrations/runs/recent", {"limit": str(limit)})
        if json_flag:
            fmt.json_out(runs); return
        fmt.table(
            runs,
            [("id", "Run ID"), ("workflow_id", "Workflow"), ("status", "Status"),
             ("triggered_by", "Triggered By"), ("started_at", "Started")],
        )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


# ─────────────────────────────────────────────
# status — platform health at a glance
# ─────────────────────────────────────────────
status_app = typer.Typer(help="Platform health and dashboard overview.", no_args_is_help=True)
app.add_typer(status_app, name="status")


@status_app.command("dashboard")
def status_dashboard(
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Show platform dashboard summary."""
    fmt.header("Enkstein — Platform Dashboard")
    try:
        data = client.get("/dashboard")
        if json_flag:
            fmt.json_out(data); return
        fmt.kv("Active Agents",     data.get("active_agents", "—"))
        fmt.kv("Running Workflows", data.get("running_workflows", "—"))
        fmt.kv("Open Incidents",    data.get("open_incidents", "—"))
        fmt.kv("Policy Count",      data.get("policy_count", "—"))
        fmt.kv("Connector Count",   data.get("connector_count", "—"))
        fmt.kv("Risk Level",        data.get("risk_level", "—"),
               fmt._risk_color(data.get("risk_level", "")))
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@status_app.command("connectors")
def status_connectors(
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Show connector health summary."""
    fmt.header("Connector Health")
    try:
        data = client.get("/connectors/health-summary")
        if json_flag:
            fmt.json_out(data); return
        fmt.kv("Total",        data.get("total", "—"))
        fmt.kv("Healthy",      data.get("healthy", "—"), fmt.C_GREEN)
        fmt.kv("Configured",   data.get("configured", "—"))
        fmt.kv("Unconfigured", data.get("unconfigured", "—"))
        fmt.kv("Blocked",      data.get("blocked", "—"),
               fmt.C_RED if data.get("blocked", 0) > 0 else fmt.C_GRAY)
        connectors = data.get("connectors", [])
        if connectors:
            fmt.header("Connectors")
            fmt.table(
                connectors,
                [("name", "Name"), ("connector_type", "Type"), ("health", "Health"),
                 ("trust_score", "Trust"), ("risk_level", "Risk")],
            )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@status_app.command("agents")
def status_agents(
    status_filter: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by status"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """List all agents and their current status."""
    fmt.header("Agents")
    try:
        params = {}
        if status_filter:
            params["status"] = status_filter
        agents = client.get("/agents", params or None)
        if json_flag:
            fmt.json_out(agents); return
        fmt.table(
            agents,
            [("id", "ID"), ("name", "Name"), ("claw_type", "Claw"),
             ("mode", "Mode"), ("status", "Status"), ("last_run_at", "Last Run")],
        )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


# ─────────────────────────────────────────────
# policies — manage security policies
# ─────────────────────────────────────────────
policies_app = typer.Typer(help="Manage security policies.", no_args_is_help=True)
app.add_typer(policies_app, name="policies")


@policies_app.command("list")
def policies_list(
    claw: Optional[str] = typer.Option(None, "--claw", "-c", help="Filter by claw type"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """List all policies."""
    fmt.header("Policies")
    try:
        policies = client.get("/policies")
        if claw:
            policies = [p for p in policies if p.get("claw_type", "").lower() == claw.lower()]
        if json_flag:
            fmt.json_out(policies); return
        fmt.table(
            policies,
            [("id", "ID"), ("name", "Name"), ("claw_type", "Claw"),
             ("severity", "Severity"), ("enabled", "Enabled")],
        )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@policies_app.command("get")
def policies_get(
    policy_id: str  = typer.Argument(..., help="Policy ID"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Show details for a specific policy."""
    fmt.header(f"Policy {policy_id}")
    try:
        policies = client.get("/policies")
        policy   = next((p for p in policies if str(p.get("id")) == policy_id), None)
        if not policy:
            fmt.error(f"Policy {policy_id} not found"); raise typer.Exit(1)
        if json_flag:
            fmt.json_out(policy); return
        fmt.kv("ID",          policy.get("id"))
        fmt.kv("Name",        policy.get("name"))
        fmt.kv("Claw",        policy.get("claw_type"))
        fmt.kv("Severity",    policy.get("severity"),   fmt._risk_color(policy.get("severity", "")))
        fmt.kv("Enabled",     str(policy.get("enabled")))
        fmt.kv("Description", policy.get("description", "—"))
    except typer.Exit:
        raise
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@policies_app.command("enable")
def policies_enable(policy_id: str = typer.Argument(..., help="Policy ID to enable")):
    """Enable a policy."""
    try:
        client.patch(f"/policies/{policy_id}", {"enabled": True})
        fmt.success(f"Policy {policy_id} enabled")
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@policies_app.command("disable")
def policies_disable(policy_id: str = typer.Argument(..., help="Policy ID to disable")):
    """Disable a policy."""
    try:
        client.patch(f"/policies/{policy_id}", {"enabled": False})
        fmt.success(f"Policy {policy_id} disabled")
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@policies_app.command("delete")
def policies_delete(
    policy_id: str = typer.Argument(..., help="Policy ID to delete"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Delete a policy."""
    if not yes:
        typer.confirm(f"Delete policy {policy_id}?", abort=True)
    try:
        client.delete(f"/policies/{policy_id}")
        fmt.success(f"Policy {policy_id} deleted")
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


# ─────────────────────────────────────────────
# connectors — manage connectors
# ─────────────────────────────────────────────
connectors_app = typer.Typer(help="Manage platform connectors.", no_args_is_help=True)
app.add_typer(connectors_app, name="connectors")


@connectors_app.command("list")
def connectors_list(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """List all connectors."""
    fmt.header("Connectors")
    try:
        connectors = client.get("/connectors")
        if category:
            connectors = [c for c in connectors
                          if (c.get("category") or "").lower() == category.lower()]
        if json_flag:
            fmt.json_out(connectors); return
        fmt.table(
            connectors,
            [("id", "ID"), ("name", "Name"), ("connector_type", "Type"),
             ("category", "Category"), ("status", "Status")],
        )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@connectors_app.command("health")
def connectors_health(
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Show connector health summary."""
    status_connectors(json_flag)


@connectors_app.command("test")
def connectors_test(
    connector_id: str  = typer.Argument(..., help="Connector ID to test"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Test a connector's live connection."""
    fmt.header(f"Testing connector {connector_id}")
    try:
        result = client.post(f"/connectors/{connector_id}/test")
        if json_flag:
            fmt.json_out(result); return
        if result.get("success"):
            fmt.success(result.get("message", "Test passed"))
        else:
            fmt.error(result.get("message", "Test failed"))
        fmt.kv("Latency ms", result.get("latency_ms", "—"))
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


# ─────────────────────────────────────────────
# approvals — manage pending approvals
# ─────────────────────────────────────────────
approvals_app = typer.Typer(help="Manage agent action approvals.", no_args_is_help=True)
app.add_typer(approvals_app, name="approvals")


@approvals_app.command("list")
def approvals_list(
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """List pending approval requests."""
    fmt.header("Pending Approvals")
    try:
        approvals = client.get("/identityclaw/approvals", {"status": "pending"})
        if json_flag:
            fmt.json_out(approvals); return
        if not approvals:
            fmt.warn("No pending approvals."); return
        fmt.table(
            approvals,
            [("id", "ID"), ("identity_id", "Identity"), ("request_type", "Type"),
             ("status", "Status"), ("requested_at", "Requested"), ("requested_by", "By")],
        )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@approvals_app.command("approve")
def approvals_approve(
    agent_id: str   = typer.Argument(..., help="Agent ID"),
    run_id:   str   = typer.Argument(..., help="Run ID"),
    action_id: str  = typer.Argument(..., help="Action ID to approve"),
    note: str = typer.Option("", "--note", "-n", help="Approval note"),
):
    """Approve a pending agent action."""
    fmt.header(f"Approving action {action_id}")
    try:
        result = client.post(
            f"/agents/{agent_id}/runs/{run_id}/approve",
            {"action_id": action_id, "decision": "approved", "note": note},
        )
        fmt.success(f"Action {action_id} approved")
        fmt.kv("Status", result.get("status", "—"))
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@approvals_app.command("deny")
def approvals_deny(
    agent_id:  str = typer.Argument(..., help="Agent ID"),
    run_id:    str = typer.Argument(..., help="Run ID"),
    action_id: str = typer.Argument(..., help="Action ID to deny"),
    reason:    str = typer.Option("", "--reason", "-r", help="Denial reason"),
):
    """Deny a pending agent action."""
    fmt.header(f"Denying action {action_id}")
    try:
        result = client.post(
            f"/agents/{agent_id}/runs/{run_id}/approve",
            {"action_id": action_id, "decision": "denied", "reason": reason},
        )
        fmt.warn(f"Action {action_id} denied")
        fmt.kv("Status", result.get("status", "—"))
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


# ─────────────────────────────────────────────
# evidence — compliance evidence collection
# ─────────────────────────────────────────────
evidence_app = typer.Typer(help="Collect and export compliance evidence.", no_args_is_help=True)
app.add_typer(evidence_app, name="evidence")


@evidence_app.command("collect")
def evidence_collect(
    incident_id: str   = typer.Argument(..., help="Incident ID to collect evidence for"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON to file"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Collect all evidence for an incident (logs, events, audit trail, asset context)."""
    fmt.header(f"Collecting evidence for incident {incident_id}")
    try:
        incident = client.get(f"/memory/incidents/{incident_id}")
        audit    = client.get("/audit", {"compliance_only": "false"})
        events   = client.get("/events", {"limit": "100"})

        # Filter audit + events to incident timeframe if possible
        incident_time = incident.get("created_at", "")
        closed_time   = incident.get("closed_at") or ""

        evidence_pkg = {
            "incident":       incident,
            "audit_trail":    audit[:50],
            "related_events": events[:50],
            "collected_at":   __import__("datetime").datetime.utcnow().isoformat(),
        }

        if json_flag or output:
            if output:
                with open(output, "w") as f:
                    json.dump(evidence_pkg, f, indent=2, default=str)
                fmt.success(f"Evidence saved to {output}")
            else:
                fmt.json_out(evidence_pkg)
            return

        fmt.kv("Incident ID",  incident.get("id"))
        fmt.kv("Title",        incident.get("title"))
        fmt.kv("Severity",     incident.get("severity"),
               fmt._risk_color(incident.get("severity", "")))
        fmt.kv("Status",       incident.get("status"))
        fmt.kv("Created",      incident.get("created_at", "—"))
        fmt.kv("Closed",       incident.get("closed_at") or "—")
        fmt.kv("MTTR (min)",   str(incident.get("mttr_minutes") or "—"))

        timeline = incident.get("timeline_json") or []
        if isinstance(timeline, str):
            try:   timeline = json.loads(timeline)
            except Exception: timeline = []
        if timeline:
            fmt.header("Timeline")
            fmt.table(
                timeline,
                [("ts", "Time"), ("actor", "Actor"), ("action", "Action"), ("detail", "Detail")],
            )

        fmt.header("Audit Trail")
        fmt.table(
            audit[:20],
            [("id", "ID"), ("action", "Action"), ("actor", "Actor"),
             ("resource_type", "Resource"), ("created_at", "Time")],
        )

        fmt.success(f"Evidence package ready. Use --json or --output to export.")

    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@evidence_app.command("audit")
def evidence_audit(
    compliance_only: bool = typer.Option(False, "--compliance", "-c",
                                         help="Show only compliance-tagged entries"),
    limit: int  = typer.Option(50, "--limit", "-n", help="Number of entries"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Show the platform audit log."""
    fmt.header("Audit Log")
    try:
        logs = client.get("/audit", {"compliance_only": str(compliance_only).lower()})
        logs = logs[:limit]
        if json_flag:
            fmt.json_out(logs); return
        fmt.table(
            logs,
            [("id", "ID"), ("action", "Action"), ("actor", "Actor"),
             ("resource_type", "Resource"), ("resource_id", "Res ID"),
             ("outcome", "Outcome"), ("created_at", "Time")],
        )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


# ─────────────────────────────────────────────
# incidents — memory / incident commands
# ─────────────────────────────────────────────
incidents_app = typer.Typer(help="Manage security incidents.", no_args_is_help=True)
app.add_typer(incidents_app, name="incidents")


@incidents_app.command("list")
def incidents_list(
    status_filter: Optional[str] = typer.Option(None, "--status", "-s",
                                                 help="Filter: open|investigating|closed"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """List security incidents."""
    fmt.header("Incidents")
    try:
        params = {}
        if status_filter:
            params["status"] = status_filter
        incidents = client.get("/memory/incidents", params or None)
        if json_flag:
            fmt.json_out(incidents); return
        fmt.table(
            incidents,
            [("id", "ID"), ("title", "Title"), ("severity", "Severity"),
             ("status", "Status"), ("source_claw", "Claw"),
             ("assigned_to", "Assignee"), ("created_at", "Created")],
        )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@incidents_app.command("get")
def incidents_get(
    incident_id: str  = typer.Argument(..., help="Incident ID"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """Show incident details."""
    fmt.header(f"Incident {incident_id}")
    try:
        inc = client.get(f"/memory/incidents/{incident_id}")
        if json_flag:
            fmt.json_out(inc); return
        fmt.kv("ID",          inc.get("id"))
        fmt.kv("Title",       inc.get("title"))
        fmt.kv("Severity",    inc.get("severity"),
               fmt._risk_color(inc.get("severity", "")))
        fmt.kv("Status",      inc.get("status"),
               fmt._status_color(inc.get("status", "")))
        fmt.kv("Source Claw", inc.get("source_claw", "—"))
        fmt.kv("Assigned To", inc.get("assigned_to") or "—")
        fmt.kv("MITRE Tactics",    inc.get("mitre_tactics") or "—")
        fmt.kv("MITRE Techniques", inc.get("mitre_techniques") or "—")
        fmt.kv("MTTR (min)",       str(inc.get("mttr_minutes") or "—"))
        fmt.kv("Created",     inc.get("created_at", "—"))
        fmt.kv("Closed",      inc.get("closed_at") or "—")
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@incidents_app.command("close")
def incidents_close(
    incident_id: str = typer.Argument(..., help="Incident ID to close"),
    root_cause: str  = typer.Option(..., "--root-cause", "-r", help="Root cause description"),
    closed_by: str   = typer.Option("cli_user", "--by", help="Who is closing"),
):
    """Close an incident with a root cause."""
    fmt.header(f"Closing incident {incident_id}")
    try:
        result = client.post(
            f"/memory/incidents/{incident_id}/close",
            {"root_cause": root_cause, "closed_by": closed_by},
        )
        fmt.success(f"Incident {incident_id} closed")
        fmt.kv("MTTR (min)", str(result.get("mttr_minutes") or "—"))
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


# ─────────────────────────────────────────────
# skill-packs — manage skill packs
# ─────────────────────────────────────────────
skillpacks_app = typer.Typer(help="Manage skill packs.", no_args_is_help=True)
app.add_typer(skillpacks_app, name="skill-packs")


@skillpacks_app.command("list")
def skillpacks_list(
    installed: bool = typer.Option(False, "--installed", "-i", help="Show only installed packs"),
    json_flag: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
):
    """List skill packs."""
    fmt.header("Skill Packs")
    try:
        params = {"installed": "true"} if installed else {}
        packs  = client.get("/skill-packs", params or None)
        if isinstance(packs, dict):
            packs = packs.get("packs", packs.get("results", []))
        if json_flag:
            fmt.json_out(packs); return
        fmt.table(
            packs,
            [("id", "ID"), ("name", "Name"), ("category", "Category"),
             ("version", "Version"), ("is_installed", "Installed"), ("is_active", "Active")],
        )
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@skillpacks_app.command("install")
def skillpacks_install(
    pack_id: str   = typer.Argument(..., help="Skill pack ID to install"),
    by: str = typer.Option("cli_user", "--by", help="Installer identity"),
):
    """Install a skill pack."""
    fmt.header(f"Installing skill pack {pack_id}")
    try:
        result = client.post(f"/skill-packs/{pack_id}/install", {"installed_by": by})
        fmt.success(result.get("message", f"Skill pack {pack_id} installed"))
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@skillpacks_app.command("activate")
def skillpacks_activate(pack_id: str = typer.Argument(..., help="Skill pack ID to activate")):
    """Activate an installed skill pack."""
    try:
        result = client.post(f"/skill-packs/{pack_id}/activate")
        fmt.success(result.get("message", f"Skill pack {pack_id} activated"))
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


@skillpacks_app.command("deactivate")
def skillpacks_deactivate(pack_id: str = typer.Argument(..., help="Skill pack ID to deactivate")):
    """Deactivate a skill pack."""
    try:
        result = client.post(f"/skill-packs/{pack_id}/deactivate")
        fmt.warn(result.get("message", f"Skill pack {pack_id} deactivated"))
    except Exception as e:
        fmt.error(str(e)); raise typer.Exit(1)


# ─────────────────────────────────────────────
# version
# ─────────────────────────────────────────────
@app.command()
def version():
    """Show CLI version."""
    fmt.header("Enkstein CLI")
    fmt.kv("Version", "0.8.2")
    fmt.kv("API URL", client.BASE_URL)


def main():
    app()


if __name__ == "__main__":
    main()
