"""
Enkstein — Natural Language Workflow Generator
Translates a plain-English security intent into a structured workflow draft,
evaluates it against active policies inline, and returns it for human approval.

No external LLM required — uses a curated pattern library for deterministic,
auditable NL parsing. Designed to be extended with LLM back-ends later.
"""
import json
import uuid
import re
from datetime import datetime
from typing import Any


# ─── Intent patterns → (step_type, label) ────────────────────────────────────
# Ordered by specificity (more specific first)
_INTENT_PATTERNS: list[tuple[str, str, str]] = [
    # ── Security-domain intents ───────────────────────────────────────────────
    (r"\b(rotate|reset)\b.{0,30}(credential|password|key|secret|token)",
     "agent_run", "Rotate Credentials"),
    (r"\b(disable|suspend|lock|deactivate|block)\b.{0,20}\b(user|account|identity|principal)\b",
     "agent_run", "Disable Account"),
    (r"\b(revoke|remove|strip)\b.{0,20}\b(access|permission|privilege|role|token)\b",
     "agent_run", "Revoke Access"),
    (r"\b(enrich|lookup|correlate)\b.{0,20}\b(threat|ioc|indicator|intel|hash|ip)\b",
     "agent_run", "Enrich Threat Intel"),
    (r"\b(block|isolate|quarantine|contain|sandbox)\b",
     "agent_run", "Isolate / Contain"),
    (r"\b(patch|remediat|fix|mitigat)\b",
     "agent_run", "Remediate"),
    (r"\b(scan|scanning|sweep)\b",
     "agent_run", "Scan"),
    (r"\b(monitor|watch|observe|track|detect)\b",
     "agent_run", "Monitor"),
    (r"\b(investigate|analys|inspect|triage|review)\b",
     "agent_run", "Investigate"),
    (r"\b(check|verify|validate|assess|evaluat)\b",
     "agent_run", "Assess"),
    (r"\b(report|summary|generate report|document)\b",
     "agent_run", "Generate Report"),
    (r"\b(escalat)\b",
     "notify", "Escalate"),
    (r"\b(audit)\b",
     "agent_run", "Audit"),
    (r"\b(collect|gather|harvest|ingest)\b",
     "agent_run", "Collect Evidence"),
    (r"\b(restore|recover|rollback|revert)\b",
     "agent_run", "Restore / Recover"),

    # ── General automation intents (non-security) ─────────────────────────────
    # HTTP / API calls
    (r"\b(call|invoke|hit|fetch|request|poll)\b.{0,20}\b(api|endpoint|rest|url|webhook|service)\b",
     "http_request", "Call API"),
    (r"\b(post|send|push|submit)\b.{0,20}\b(api|endpoint|rest|request|json|payload)\b",
     "http_request", "POST to API"),
    (r"\b(get|fetch|retrieve|pull|download)\b.{0,20}\b(data|record|result|response|list|json)\b",
     "http_request", "Fetch Data"),
    (r"\b(webhook|outbound|callback|trigger url)\b",
     "webhook_call", "Fire Webhook"),

    # Messaging & notifications (general)
    (r"\b(slack|teams|discord|telegram)\b.{0,30}\b(send|post|notify|message|ping|alert)\b",
     "webhook_call", "Send Slack / Teams Message"),
    (r"\b(send|post|push)\b.{0,20}\b(message|notification|alert|ping)\b.{0,30}\b(slack|teams|discord|channel)\b",
     "webhook_call", "Send Channel Message"),
    (r"\b(email|mail|smtp|sendgrid|mailgun)\b.{0,20}\b(send|notify|deliver|dispatch)\b",
     "http_request", "Send Email"),
    (r"\b(pagerduty|opsgenie|page|on.?call|incident)\b.{0,20}\b(create|trigger|open|escalat)\b",
     "webhook_call", "Trigger On-Call Alert"),
    (r"\b(alert|notify|page|ping|message)\b",
     "notify", "Send Alert"),

    # CRM / ticketing
    (r"\b(crm|salesforce|hubspot|pipedrive|zoho)\b.{0,20}\b(create|update|log|sync|add)\b",
     "http_request", "Update CRM"),
    (r"\b(jira|github|linear|asana|clickup|trello|basecamp)\b.{0,20}\b(create|open|ticket|issue|task)\b",
     "http_request", "Create Ticket / Issue"),
    (r"\b(create|open|log|file)\b.{0,20}\b(ticket|issue|task|bug|incident)\b",
     "http_request", "Create Ticket"),

    # Database / data
    (r"\b(query|select|insert|update|delete)\b.{0,20}\b(database|db|sql|postgres|mysql|mongo|redis)\b",
     "http_request", "Query Database"),
    (r"\b(sync|replicate|mirror|export|import)\b.{0,20}\b(data|record|row|table)\b",
     "http_request", "Sync Data"),
    (r"\b(transform|map|convert|parse|normaliz|format)\b.{0,20}\b(data|record|payload|json|csv)\b",
     "http_request", "Transform Data"),

    # Cloud / infrastructure
    (r"\b(deploy|release|publish|ship|push)\b.{0,20}\b(code|app|service|image|container|function)\b",
     "http_request", "Deploy / Release"),
    (r"\b(scale|resize|provision|spin.?up|tear.?down)\b",
     "http_request", "Scale Infrastructure"),
    (r"\b(restart|reboot|bounce|recycle)\b.{0,20}\b(service|container|pod|instance|server)\b",
     "http_request", "Restart Service"),

    # Scheduling / orchestration meta
    (r"\b(schedule|queue|defer|delay|throttle)\b",
     "wait", "Schedule / Wait"),
    (r"\b(wait|sleep|pause|hold|delay)\b.{0,20}\b(\d+|until|for)\b",
     "wait", "Wait"),
]

# ─── Domain patterns → (claw_id, claw_label) ──────────────────────────────────
_CLAW_PATTERNS: list[tuple[str, str, str]] = [
    # ── Security claws ────────────────────────────────────────────────────────
    (r"\b(endpoint|laptop|workstation|device|host|machine|desktop|malware|ransomware|edr)\b",
     "endpointclaw", "Endpoint Security"),
    (r"\b(identity|user|account|mfa|password|credential|active directory|okta|entra|azure ad|ldap|sso)\b",
     "identityclaw", "Identity Security"),
    (r"\b(cloud|aws|azure|gcp|s3|bucket|iam|ec2|resource group|subscription|storage|rds)\b",
     "cloudclaw", "Cloud Security"),
    (r"\b(network|traffic|firewall|port|ip address|subnet|vpn|dns|packet|ndr|nac)\b",
     "netclaw", "Network Security"),
    (r"\b(threat intel|ioc|indicator|cti|stix|taxii|mitre att&ck|reputation|ttps)\b",
     "intelclaw", "Threat Intelligence"),
    (r"\b(vulnerabilit|cve|exploit|exposure|cvss|patch level|nvd|tenable|qualys)\b",
     "exposureclaw", "Exposure Management"),
    (r"\b(log|siem|splunk|event|audit trail|log source|elastic|chronicle|sentinel)\b",
     "logclaw", "Security Telemetry"),
    (r"\b(access|privilege|rbac|role|permission|entitlement|pam|cyberark|jump)\b",
     "accessclaw", "Privileged Access"),
    (r"\b(data|pii|sensitive|classification|dlp|exfiltration|data loss)\b",
     "dataclaw", "Data Security"),
    (r"\b(compliance|gdpr|hipaa|pci.?dss|iso 27001|soc 2|regulation|audit|control|framework)\b",
     "complianceclaw", "Compliance Assurance"),
    (r"\b(misconfigur|config drift|hardening|baseline|cis benchmark|dsc)\b",
     "configclaw", "Configuration Security"),
    (r"\b(saas|salesforce|m365|microsoft 365|google workspace|slack|zendesk|dropbox)\b",
     "saasclaw", "SaaS Security"),
    (r"\b(app|application|appsec|owasp|api security|web app|waf)\b",
     "appclaw", "Application Security"),
    (r"\b(vendor|third.?party|supplier|partner|external|supply chain)\b",
     "vendorclaw", "Vendor Risk"),
    (r"\b(insider|employee behaviour|ueba|abnormal|user behaviour)\b",
     "insiderclaw", "Insider Risk"),
    (r"\b(recover|restore|backup|dr|disaster recovery|business continuity|rto|rpo|resilience)\b",
     "recoveryclaw", "Recovery Readiness"),
    (r"\b(attack path|lateral movement|privilege escalation|kill chain|blast radius)\b",
     "attackpathclaw", "Attack Path Analysis"),
    (r"\b(dev|devsecops|code|repo|github|pipeline|secret.?leak|ci.?cd|sast|dast|dependency)\b",
     "devclaw", "Developer Security"),
    (r"\b(automation|orchestration|runbook|playbook|soar)\b",
     "automationclaw", "Security Automation"),
    (r"\b(threat|malicious|attacker|actor|apt|campaign|indicator)\b",
     "threatclaw", "Threat Analysis"),

    # ── General automation domains (non-security) ─────────────────────────────
    # Messaging / communication platforms
    (r"\b(slack|slack channel|slack workspace)\b",
     "customclaw", "Slack"),
    (r"\b(microsoft teams|ms teams|teams channel)\b",
     "customclaw", "Microsoft Teams"),
    (r"\b(discord|telegram|whatsapp)\b",
     "customclaw", "Messaging Platform"),
    (r"\b(email|smtp|sendgrid|mailgun|mailchimp|ses)\b",
     "customclaw", "Email Service"),

    # Ticketing / project management
    (r"\b(jira|jira cloud|jira software|atlassian)\b",
     "customclaw", "Jira"),
    (r"\b(github issues|github|gitlab issues|bitbucket)\b",
     "customclaw", "GitHub"),
    (r"\b(linear|asana|clickup|monday|trello|basecamp|notion)\b",
     "customclaw", "Project Management"),
    (r"\b(servicenow|freshdesk|zendesk|helpdesk|support ticket)\b",
     "customclaw", "Service Desk"),

    # CRM / sales
    (r"\b(salesforce|sfdc|hubspot|pipedrive|zoho crm|dynamics 365)\b",
     "customclaw", "CRM"),
    (r"\b(lead|contact|deal|opportunity|account)\b.{0,20}\b(crm|salesforce|hubspot)\b",
     "customclaw", "CRM"),

    # Data / analytics / BI
    (r"\b(database|postgres|mysql|mongodb|redis|sqlite|snowflake|bigquery)\b",
     "customclaw", "Database"),
    (r"\b(tableau|looker|metabase|grafana|power bi|data studio|dbt)\b",
     "customclaw", "Analytics / BI"),
    (r"\b(spreadsheet|google sheets|excel|airtable)\b",
     "customclaw", "Spreadsheet"),
    (r"\b(etl|data pipeline|airflow|prefect|dagster|mage)\b",
     "customclaw", "Data Pipeline"),

    # Infrastructure / DevOps
    (r"\b(kubernetes|k8s|helm|pod|deployment|namespace)\b",
     "customclaw", "Kubernetes"),
    (r"\b(docker|container|image|registry|dockerfile)\b",
     "customclaw", "Docker"),
    (r"\b(terraform|ansible|puppet|chef|pulumi|infra.?as.?code)\b",
     "customclaw", "IaC"),
    (r"\b(jenkins|github actions|gitlab ci|circleci|travis|buildkite|tekton)\b",
     "customclaw", "CI/CD Pipeline"),
    (r"\b(monitoring|prometheus|grafana|datadog|new relic|dynatrace|sentry)\b",
     "customclaw", "Monitoring"),
    (r"\b(on.?call|pagerduty|opsgenie|victorops|incident\.io)\b",
     "customclaw", "Incident Management"),

    # Automation / integration platforms
    (r"\b(zapier|make\.com|n8n|workato|tray\.io|automate\.io)\b",
     "customclaw", "Integration Platform"),
    (r"\b(webhook|rest api|graphql|grpc|soap)\b",
     "customclaw", "API Integration"),

    # Finance / billing
    (r"\b(stripe|braintree|paypal|billing|invoice|payment|subscription)\b",
     "customclaw", "Billing / Payments"),
    (r"\b(quickbooks|xero|netsuite|sage|finance)\b",
     "customclaw", "Finance / Accounting"),

    # HR / people
    (r"\b(workday|bamboohr|rippling|gusto|adp|hr|onboard|offboard)\b",
     "customclaw", "HR / People Ops"),
]

# ─── High-risk action patterns ───────────────────────────────────────────────
_HIGH_RISK_PATTERNS = [
    r"\b(block|isolate|quarantine|disable|revoke|delete|terminate|kill|stop service|shut down)\b",
    r"\b(rotate|reset|change)\b.{0,20}\b(password|credential|key|secret)\b",
    r"\b(patch|modify|update|change)\b.{0,20}\b(production|prod|live|critical)\b",
    r"\b(emergency|breach|compromise|incident|active attack|ongoing)\b",
    r"\b(deploy|push|release|rollback)\b.{0,20}\b(production|prod|live)\b",
]

# ─── Trigger type hints ───────────────────────────────────────────────────────
_TRIGGER_HINTS: list[tuple[str, str]] = [
    (r"\b(every|daily|weekly|hourly|monthly|scheduled|recurring|cron)\b", "schedule"),
    (r"\b(when|if|on alert|triggered by|upon|whenever|as soon as)\b",     "event"),
]

# ─── In-memory draft store ────────────────────────────────────────────────────
# Keyed by draft_id — cleared on restart (ephemeral by design).
_DRAFT_STORE: dict[str, dict] = {}


# ─── Parsing helpers ──────────────────────────────────────────────────────────

def _detect_claws(text: str) -> list[dict[str, str]]:
    """Return ordered, de-duped list of {claw_id, label} detected in text."""
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    lower = text.lower()
    for pattern, claw_id, label in _CLAW_PATTERNS:
        if re.search(pattern, lower):
            if claw_id not in seen:
                seen.add(claw_id)
                result.append({"claw_id": claw_id, "label": label})
    # If only customclaw hits fired, keep them — that means it's a general automation
    # If zero matches, fall back to AI Security (catch-all security AI)
    if not result:
        result.append({"claw_id": "arcclaw", "label": "AI Security"})
    return result


def _is_general_automation(claws: list[dict]) -> bool:
    """Return True if the detected domain is purely general automation (no security claws)."""
    return all(c["claw_id"] == "customclaw" for c in claws)


def _detect_intents(text: str) -> list[tuple[str, str]]:
    """Return list of (step_type, label) from intent patterns (de-duped)."""
    lower = text.lower()
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for pattern, stype, label in _INTENT_PATTERNS:
        if re.search(pattern, lower):
            if label not in seen:
                seen.add(label)
                result.append((stype, label))
    if not result:
        result = [("agent_run", "Investigate"), ("notify", "Send Alert")]
    return result


def _is_high_risk(text: str) -> bool:
    lower = text.lower()
    return any(re.search(p, lower) for p in _HIGH_RISK_PATTERNS)


def _detect_trigger_type(text: str) -> str:
    lower = text.lower()
    for pattern, ttype in _TRIGGER_HINTS:
        if re.search(pattern, lower):
            return ttype
    return "manual"


def _build_steps(
    intents: list[tuple[str, str]],
    claws: list[dict[str, str]],
) -> list[dict]:
    """
    Assemble step list:
      1) policy_check gate (always first)
      2) agent/notify steps — map intents × claws (up to 6 steps total)
      3) a final notify if none was generated
    """
    steps: list[dict] = []
    idx = 1

    # Step 1: policy gate
    steps.append({
        "id": str(uuid.uuid4()),
        "index": idx,
        "name": "Policy Gate",
        "type": "policy_check",
        "config": {"scope": "all", "block_on_violation": True},
        "on_failure": "abort",
    })
    idx += 1

    added_notify = False

    # If multiple claws, run the first intent across all claws
    if len(claws) > 1 and len(intents) == 1:
        stype, label = intents[0]
        for claw in claws[:5]:
            is_notify = stype == "notify"
            if is_notify:
                added_notify = True
            steps.append(_make_step(idx, stype, label, claw, is_notify))
            idx += 1
    else:
        # Pair each intent with its closest claw
        for i, (stype, label) in enumerate(intents[:6]):
            claw = claws[min(i, len(claws) - 1)]
            is_notify = stype == "notify"
            if is_notify:
                added_notify = True
            steps.append(_make_step(idx, stype, label, claw, is_notify))
            idx += 1

    # Always end with a notify
    if not added_notify:
        steps.append({
            "id": str(uuid.uuid4()),
            "index": idx,
            "name": "Notify Security Team",
            "type": "notify",
            "config": {"channel": "default", "severity": "medium"},
            "on_failure": "continue",
        })

    return steps


def _make_step(
    idx: int,
    stype: str,
    label: str,
    claw: dict[str, str],
    is_notify: bool,
) -> dict:
    if is_notify:
        return {
            "id": str(uuid.uuid4()),
            "index": idx,
            "name": f"{label} via {claw['label']}",
            "type": "notify",
            "config": {"channel": "default", "severity": "high", "claw": claw["claw_id"]},
            "on_failure": "continue",
        }
    if stype == "http_request":
        return {
            "id": str(uuid.uuid4()),
            "index": idx,
            "name": f"{label} — {claw['label']}",
            "type": "http_request",
            "config": {
                "url": "",          # user fills in before saving
                "method": "GET",
                "headers": {},
                "auth_type": "none",
                "output_key": f"step_{idx}_response",
                "claw": claw["claw_id"],
                "_hint": f"Configure the URL for {claw['label']} before running",
            },
            "on_failure": "continue",
        }
    if stype == "webhook_call":
        return {
            "id": str(uuid.uuid4()),
            "index": idx,
            "name": f"{label} — {claw['label']}",
            "type": "webhook_call",
            "config": {
                "url": "",          # user fills in before saving
                "method": "POST",
                "payload": {},
                "output_key": f"step_{idx}_response",
                "claw": claw["claw_id"],
                "_hint": f"Configure the webhook URL for {claw['label']} before running",
            },
            "on_failure": "continue",
        }
    if stype == "wait":
        return {
            "id": str(uuid.uuid4()),
            "index": idx,
            "name": f"{label}",
            "type": "wait",
            "config": {"seconds": 5},
            "on_failure": "continue",
        }
    return {
        "id": str(uuid.uuid4()),
        "index": idx,
        "name": f"{label} — {claw['label']}",
        "type": "agent_run",
        "config": {
            "claw": claw["claw_id"],
            "action": label.lower().replace(" ", "_").replace("/", "_").replace(" ", "_"),
        },
        "on_failure": "continue",
    }


# ─── Public API ───────────────────────────────────────────────────────────────

def generate_workflow_draft(
    prompt: str,
    requested_by: str = "copilot",
) -> dict[str, Any]:
    """
    Parse `prompt` and return a complete workflow draft dict.
    Stores the draft in _DRAFT_STORE under draft_id for later approval.
    """
    claws   = _detect_claws(prompt)
    intents = _detect_intents(prompt)
    high_risk    = _is_high_risk(prompt)
    trigger_type = _detect_trigger_type(prompt)
    steps        = _build_steps(intents, claws)

    # ─ Workflow metadata ─────────────────────────────────────────────────────
    general_automation = _is_general_automation(claws)
    primary_intent = intents[0][1] if intents else "Integrate"
    primary_claw   = claws[0]["label"] if claws else ("Custom Integration" if general_automation else "AI Security")
    name           = f"{primary_intent} via {primary_claw}"
    domain_note    = "general automation" if general_automation else f"{len(claws)} capability node(s)"
    description    = (
        f'Auto-generated from: "{prompt[:120]}". '
        f"Covers {domain_note} with {len(steps)} steps."
    )

    # ─ Inline policy evaluation ──────────────────────────────────────────────
    policy_flags: list[dict] = []
    requires_approval = False

    if high_risk:
        policy_flags.append({
            "rule": "HIGH_RISK_ACTION",
            "severity": "high",
            "message": (
                "Workflow contains destructive or write actions — "
                "explicit approval required before execution."
            ),
        })
        requires_approval = True

    if len(claws) > 3:
        policy_flags.append({
            "rule": "BROAD_SCOPE",
            "severity": "medium",
            "message": (
                f"Workflow spans {len(claws)} capability nodes — "
                "confirm the scope is intentional."
            ),
        })

    if trigger_type in ("event", "schedule"):
        policy_flags.append({
            "rule": "AUTO_TRIGGER",
            "severity": "low",
            "message": (
                "Workflow will execute automatically — "
                "confirm trigger conditions before saving."
            ),
        })

    policy_decision = (
        "require_approval" if requires_approval
        else ("warn" if policy_flags else "allow")
    )

    # ─ Assemble draft ────────────────────────────────────────────────────────
    draft_id = str(uuid.uuid4())
    now      = datetime.utcnow().isoformat() + "Z"

    draft = {
        "draft_id":    draft_id,
        "created_at":  now,
        "requested_by": requested_by,
        "prompt":      prompt,
        # The workflow payload (ready to POST to /workflows when approved)
        "workflow": {
            "name":        name,
            "description": description,
            "trigger_type": trigger_type,
            "status":      "draft",
            "category":    "AI-Generated",
            "tags":        ",".join(c["claw_id"] for c in claws),
            "steps_json":  json.dumps(steps),
            "step_count":  len(steps),
            "created_by":  requested_by,
        },
        "policy_evaluation": {
            "decision":           policy_decision,
            "flags":              policy_flags,
            "requires_approval":  requires_approval,
            "risk_level": (
                "high"   if high_risk
                else "medium" if len(claws) > 3
                else "low"
            ),
        },
        "explanation": {
            "detected_claws":   claws,
            "detected_intents": [{"type": t, "label": l} for t, l in intents],
            "step_count":       len(steps),
            "high_risk":        high_risk,
            "trigger_type":     trigger_type,
        },
        # pending_approval → requires human sign-off before run
        # ready            → safe to run immediately (or with one click)
        "status": "pending_approval" if requires_approval else "ready",
    }

    _DRAFT_STORE[draft_id] = draft
    return draft


def get_draft(draft_id: str) -> dict | None:
    return _DRAFT_STORE.get(draft_id)


def list_drafts() -> list[dict]:
    return list(_DRAFT_STORE.values())


def discard_draft(draft_id: str) -> bool:
    if draft_id in _DRAFT_STORE:
        del _DRAFT_STORE[draft_id]
        return True
    return False


def patch_draft_workflow(draft_id: str, updates: dict) -> dict | None:
    """Allow the UI to tweak the draft (name, steps, etc.) before approval."""
    draft = _DRAFT_STORE.get(draft_id)
    if draft is None:
        return None
    draft["workflow"].update(updates)
    draft["updated_at"] = datetime.utcnow().isoformat() + "Z"
    return draft
