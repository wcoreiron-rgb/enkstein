from __future__ import annotations

from app.core.marcellus.schemas import (
    ArchitectureSnapshot,
    AuthorityCeiling,
    CapabilityNode,
    CortexComponent,
    ExtensionContract,
    Heart,
    ImplementationState,
    PlexusContract,
    ReflexContract,
    RegenerationContract,
    SecurityArm,
    SecurityArmId,
    Terminology,
)


def _node(
    node_id: str,
    name: str,
    arm_id: SecurityArmId,
    purpose: str,
    legacy_module: str,
    route_slug: str,
    capabilities: tuple[str, ...],
    authority: AuthorityCeiling = AuthorityCeiling.RECOMMEND,
) -> CapabilityNode:
    route = f"/api/v1/{route_slug}"
    return CapabilityNode(
        id=node_id,
        name=name,
        arm_id=arm_id,
        purpose=purpose,
        legacy_module=legacy_module,
        legacy_route=route,
        task_route=f"{route}/task",
        capabilities=capabilities,
        authority_ceiling=authority,
        plexus_ready=True,
    )


_ARM_DEFINITIONS: tuple[tuple[SecurityArmId, str, str], ...] = (
    (
        SecurityArmId.THREAT_EXPOSURE,
        "Threat Intelligence and Exposure",
        "Continuously observe adversaries, vulnerabilities, telemetry, and attack paths.",
    ),
    (
        SecurityArmId.IDENTITY_HUMAN_RISK,
        "Identity and Human Risk",
        "Govern identities, privileges, behavior, and insider-risk signals.",
    ),
    (
        SecurityArmId.CLOUD_INFRASTRUCTURE,
        "Cloud and Infrastructure",
        "Secure cloud posture, configuration, infrastructure as code, and infrastructure recovery.",
    ),
    (
        SecurityArmId.NETWORK_ENDPOINT,
        "Network and Endpoint",
        "Protect network boundaries, workloads, devices, and endpoint execution.",
    ),
    (
        SecurityArmId.APPLICATION_DELIVERY,
        "Application and Software Delivery",
        "Govern code, application security, CI/CD, and production releases.",
    ),
    (
        SecurityArmId.DATA_PRIVACY_SAAS,
        "Data, Privacy, and SaaS",
        "Protect sensitive data, privacy obligations, and SaaS control planes.",
    ),
    (
        SecurityArmId.GOVERNANCE_RESILIENCE,
        "Governance, Risk, and Resilience",
        "Correlate controls, third-party risk, compliance evidence, and recovery readiness.",
    ),
    (
        SecurityArmId.AI_AUTONOMOUS_OPERATIONS,
        "AI and Autonomous Operations",
        "Govern AI systems, bounded automation, and tenant-defined specialist capabilities.",
    ),
)


_CAPABILITY_NODES: tuple[CapabilityNode, ...] = (
    _node(
        "threat-analysis",
        "Threat Analysis",
        SecurityArmId.THREAT_EXPOSURE,
        "Analyze active threats, indicators, campaigns, and response priorities.",
        "ThreatClaw",
        "threatclaw",
        ("threat-analysis", "indicator-correlation", "response-recommendation"),
    ),
    _node(
        "threat-intelligence",
        "Threat Intelligence",
        SecurityArmId.THREAT_EXPOSURE,
        "Collect and enrich intelligence from commercial and open intelligence sources.",
        "IntelClaw",
        "intelclaw",
        ("ioc-enrichment", "campaign-tracking", "intelligence-correlation"),
    ),
    _node(
        "exposure-management",
        "Exposure Management",
        SecurityArmId.THREAT_EXPOSURE,
        "Prioritize externally visible weaknesses and exploitable exposure.",
        "ExposureClaw",
        "exposureclaw",
        ("exposure-discovery", "exploitability-analysis", "risk-prioritization"),
    ),
    _node(
        "attack-path-analysis",
        "Attack Path Analysis",
        SecurityArmId.THREAT_EXPOSURE,
        "Correlate assets, identities, and weaknesses into reachable attack paths.",
        "AttackPathClaw",
        "attackpathclaw",
        ("graph-analysis", "blast-radius-analysis", "choke-point-identification"),
    ),
    _node(
        "security-telemetry",
        "Security Telemetry",
        SecurityArmId.THREAT_EXPOSURE,
        "Normalize and investigate security logs and detection telemetry.",
        "LogClaw",
        "logclaw",
        ("log-analysis", "detection-correlation", "timeline-construction"),
    ),
    _node(
        "identity-security",
        "Identity Security",
        SecurityArmId.IDENTITY_HUMAN_RISK,
        "Investigate identities, authentication risk, and account compromise.",
        "IdentityClaw",
        "identityclaw",
        ("identity-investigation", "authentication-risk", "account-correlation"),
    ),
    _node(
        "privileged-access",
        "Privileged Access",
        SecurityArmId.IDENTITY_HUMAN_RISK,
        "Evaluate privileged access, entitlement, and least-privilege controls.",
        "AccessClaw",
        "accessclaw",
        ("entitlement-review", "privilege-analysis", "access-recommendation"),
    ),
    _node(
        "user-risk",
        "User Risk",
        SecurityArmId.IDENTITY_HUMAN_RISK,
        "Analyze user behavior and security awareness risk.",
        "UserClaw",
        "userclaw",
        ("behavior-analysis", "user-risk-scoring", "awareness-recommendation"),
    ),
    _node(
        "insider-risk",
        "Insider Risk",
        SecurityArmId.IDENTITY_HUMAN_RISK,
        "Correlate anomalous access, data movement, and insider-risk indicators.",
        "InsiderClaw",
        "insiderclaw",
        ("insider-risk-analysis", "anomaly-correlation", "case-recommendation"),
    ),
    _node(
        "cloud-security",
        "Cloud Security",
        SecurityArmId.CLOUD_INFRASTRUCTURE,
        "Assess cloud posture, workloads, permissions, and provider-native findings.",
        "CloudClaw",
        "cloudclaw",
        ("cloud-posture", "cloud-finding-analysis", "cloud-remediation"),
    ),
    _node(
        "configuration-security",
        "Configuration Security",
        SecurityArmId.CLOUD_INFRASTRUCTURE,
        "Detect insecure configuration and control drift across environments.",
        "ConfigClaw",
        "configclaw",
        ("configuration-audit", "drift-detection", "baseline-comparison"),
    ),
    _node(
        "terraform-governance",
        "Terraform Governance",
        SecurityArmId.CLOUD_INFRASTRUCTURE,
        "Review, generate, and gate infrastructure as code before deployment.",
        "TerraClaw",
        "terraclaw",
        ("iac-review", "secure-generation", "plan-analysis"),
        AuthorityCeiling.APPROVAL_GATED_ACTION,
    ),
    _node(
        "network-security",
        "Network Security",
        SecurityArmId.NETWORK_ENDPOINT,
        "Analyze segmentation, reachability, network policy, and traffic risk.",
        "NetClaw",
        "netclaw",
        ("network-posture", "segmentation-analysis", "reachability-analysis"),
    ),
    _node(
        "endpoint-security",
        "Endpoint Security",
        SecurityArmId.NETWORK_ENDPOINT,
        "Investigate endpoint detections, device posture, and containment options.",
        "EndpointClaw",
        "endpointclaw",
        ("endpoint-investigation", "device-posture", "containment-recommendation"),
        AuthorityCeiling.APPROVAL_GATED_ACTION,
    ),
    _node(
        "application-security",
        "Application Security",
        SecurityArmId.APPLICATION_DELIVERY,
        "Investigate application vulnerabilities and secure design controls.",
        "AppClaw",
        "appclaw",
        ("application-review", "vulnerability-analysis", "secure-design"),
    ),
    _node(
        "developer-security",
        "Developer Security",
        SecurityArmId.APPLICATION_DELIVERY,
        "Analyze repositories, dependencies, secrets, and software supply-chain findings.",
        "DevClaw",
        "devclaw",
        ("repository-analysis", "dependency-risk", "secret-detection"),
    ),
    _node(
        "release-governance",
        "Release Governance",
        SecurityArmId.APPLICATION_DELIVERY,
        "Preflight and authorize CI/CD, GitOps, script, and application deployments.",
        "ReleaseClaw",
        "releaseclaw",
        ("deployment-preflight", "release-evidence", "execution-handoff"),
        AuthorityCeiling.APPROVAL_GATED_ACTION,
    ),
    _node(
        "data-security",
        "Data Security",
        SecurityArmId.DATA_PRIVACY_SAAS,
        "Discover sensitive data exposure and recommend protection controls.",
        "DataClaw",
        "dataclaw",
        ("data-discovery", "classification-analysis", "data-protection"),
    ),
    _node(
        "privacy-governance",
        "Privacy Governance",
        SecurityArmId.DATA_PRIVACY_SAAS,
        "Map data handling to privacy obligations and privacy risk.",
        "PrivacyClaw",
        "privacyclaw",
        ("privacy-impact", "data-rights", "privacy-control-mapping"),
    ),
    _node(
        "saas-security",
        "SaaS Security",
        SecurityArmId.DATA_PRIVACY_SAAS,
        "Assess SaaS posture, sharing, permissions, and application risk.",
        "SaaSClaw",
        "saasclaw",
        ("saas-posture", "sharing-analysis", "saas-risk"),
    ),
    _node(
        "compliance-assurance",
        "Compliance Assurance",
        SecurityArmId.GOVERNANCE_RESILIENCE,
        "Map evidence and findings to control frameworks and assurance requirements.",
        "ComplianceClaw",
        "complianceclaw",
        ("control-mapping", "evidence-analysis", "compliance-impact"),
    ),
    _node(
        "vendor-risk",
        "Vendor Risk",
        SecurityArmId.GOVERNANCE_RESILIENCE,
        "Assess third-party security posture, concentration, and control gaps.",
        "VendorClaw",
        "vendorclaw",
        ("third-party-risk", "vendor-posture", "supply-chain-analysis"),
    ),
    _node(
        "recovery-readiness",
        "Recovery Readiness",
        SecurityArmId.GOVERNANCE_RESILIENCE,
        "Evaluate backup, restoration, continuity, and incident recovery readiness.",
        "RecoveryClaw",
        "recoveryclaw",
        ("recovery-assessment", "continuity-analysis", "restore-readiness"),
    ),
    _node(
        "ai-security",
        "AI Security",
        SecurityArmId.AI_AUTONOMOUS_OPERATIONS,
        "Assess AI events, prompts, models, tools, and agentic risk.",
        "ArcClaw",
        "arcclaw",
        ("ai-event-analysis", "prompt-risk", "agentic-governance"),
    ),
    _node(
        "security-automation",
        "Security Automation",
        SecurityArmId.AI_AUTONOMOUS_OPERATIONS,
        "Plan and execute bounded security automation through governed channels.",
        "AutomationClaw",
        "automationclaw",
        ("workflow-automation", "response-orchestration", "ticket-drafting"),
        AuthorityCeiling.APPROVAL_GATED_ACTION,
    ),
    _node(
        "custom-capability",
        "Custom Capability",
        SecurityArmId.AI_AUTONOMOUS_OPERATIONS,
        "Host tenant-defined security capabilities behind the same governance contract.",
        "CustomClaw",
        "customclaw",
        ("custom-analysis", "custom-provider", "tenant-extension"),
    ),
)


_CORTEX: tuple[CortexComponent, ...] = (
    CortexComponent(
        id="core-os",
        name="CoreOS",
        purpose="Maintain platform state, workflows, schedules, and system coordination.",
        implementation_state=ImplementationState.EXISTING,
        legacy_components=("CoreOS", "orchestrations", "schedules", "triggers"),
    ),
    CortexComponent(
        id="command-cortex",
        name="Command Cortex",
        purpose="Normalize operator intent and route commands into governed execution.",
        implementation_state=ImplementationState.EXISTING,
        legacy_components=("CommandClaw", "Channel Gateway", "Remote Agent Control"),
    ),
    CortexComponent(
        id="coordination-cortex",
        name="Coordination Cortex",
        purpose="Plan multi-node work, arbitrate results, and escalate conflicts.",
        implementation_state=ImplementationState.EXISTING,
        legacy_components=("SwarmClaw", "Swarm Planner", "Swarm Judge"),
    ),
    CortexComponent(
        id="model-cortex",
        name="Model Cortex",
        purpose="Select governed model profiles and provide bounded reasoning support.",
        implementation_state=ImplementationState.PARTIAL,
        legacy_components=("ModelClaw", "Model Router"),
    ),
)


_HEARTS: tuple[Heart, ...] = (
    Heart(
        id="trust-heart",
        name="Trust Heart",
        purpose="Circulate identity, policy, approval, and containment decisions through every action.",
        implementation_state=ImplementationState.EXISTING,
        components=("Trust Fabric", "Policy Engine", "Ring Policy", "Approvals", "Containment"),
    ),
    Heart(
        id="memory-heart",
        name="Memory Heart",
        purpose="Preserve governed memory, evidence, provenance, and decision history.",
        implementation_state=ImplementationState.PARTIAL,
        components=("Memory Runtime", "Audit", "Evidence", "Findings", "Compliance Mapping"),
    ),
    Heart(
        id="runtime-heart",
        name="Runtime Heart",
        purpose="Maintain execution health, schedules, budgets, queues, and recoverability.",
        implementation_state=ImplementationState.PARTIAL,
        components=("SRE Engine", "Schedules", "Execution Channels", "Remote Agents", "Resource Budgets"),
    ),
)


def _build_arms() -> tuple[SecurityArm, ...]:
    return tuple(
        SecurityArm(
            id=arm_id,
            name=name,
            purpose=purpose,
            node_ids=tuple(node.id for node in _CAPABILITY_NODES if node.arm_id == arm_id),
            implementation_state=ImplementationState.EXISTING,
        )
        for arm_id, name, purpose in _ARM_DEFINITIONS
    )


_ARMS = _build_arms()


def _validate_registry() -> None:
    arm_ids = {arm.id for arm in _ARMS}
    if arm_ids != set(SecurityArmId):
        raise RuntimeError("Enkstein arm registry does not cover every SecurityArmId")

    node_ids = [node.id for node in _CAPABILITY_NODES]
    legacy_modules = [node.legacy_module for node in _CAPABILITY_NODES]
    task_routes = [node.task_route for node in _CAPABILITY_NODES]
    for label, values in (
        ("node id", node_ids),
        ("legacy module", legacy_modules),
        ("task route", task_routes),
    ):
        if len(values) != len(set(values)):
            raise RuntimeError(f"Duplicate Enkstein {label} detected")

    assigned = {node_id for arm in _ARMS for node_id in arm.node_ids}
    if assigned != set(node_ids):
        raise RuntimeError("Every capability node must belong to exactly one Security Arm")


_validate_registry()


_SNAPSHOT = ArchitectureSnapshot(
    name="Enkstein Plexus Architecture",
    version="0.5.9",
    source_lineage="Independent compatibility-first evolution of RegentClaw",
    compatibility_mode="Legacy route and module names remain available while new contracts are introduced",
    thesis="The Cortex may be bypassed for delegated routine coordination; Trust Fabric may never be bypassed.",
    terminology=Terminology(
        cortex="Strategy, command normalization, planning, arbitration, and governed model reasoning.",
        three_hearts="Independent trust, memory, and runtime control planes that keep the organism viable.",
        security_arms="Stable cybersecurity pillars that own bounded domains and outcomes.",
        capability_nodes="Specialized governed capabilities attached to exactly one Security Arm.",
        skills="Versioned behaviors a Capability Node may invoke within its declared authority.",
        connectors="Scoped interfaces through which a Capability Node senses or acts on external systems.",
        reflexes="Event-driven low-risk actions that may run locally inside a pre-authorized policy envelope.",
        plexus="Tenant-isolated peer communication between Capability Nodes without mandatory Cortex relay.",
        regeneration="Verified restoration of a failed Capability Node from signed configuration and governed state.",
    ),
    cortex=_CORTEX,
    hearts=_HEARTS,
    arms=_ARMS,
    capability_nodes=_CAPABILITY_NODES,
    extensions=ExtensionContract(
        skills="Skills declare inputs, outputs, required connectors, model needs, and action authority.",
        connectors="Connectors declare identity, tenant scope, data classes, operations, and credential boundaries.",
        invariant="Installing a Skill or Connector never expands a Capability Node's authority without policy approval.",
    ),
    reflexes=ReflexContract(
        implementation_state=ImplementationState.EXISTING,
        purpose="Respond to well-defined events without waiting for central planning.",
        existing_foundation=(
            "Typed event conditions",
            "Trust Fabric evaluation",
            "Ring Policy authority gates",
            "Rate limits and cooldowns",
            "Approval-held executions",
        ),
        invariants=(
            "Every reflex has an owner, tenant, expiry, and authority ceiling.",
            "Trust Fabric evaluates every reflex before side effects.",
            "A reflex escalates when confidence, policy, or impact exceeds its envelope.",
        ),
    ),
    plexus=PlexusContract(
        implementation_state=ImplementationState.EXISTING,
        purpose="Allow direct, attributable collaboration between Capability Nodes.",
        current_transport="Encrypted, Ed25519-signed tenant mailboxes with policy decisions, TTL, and replay protection",
        target_transport="Optional per-node managed keys and remote transport adapters behind the same envelope",
        invariants=(
            "Every message is tenant-scoped, attributable, and auditable.",
            "Peer communication cannot grant new authority.",
            "Conflicts and high-impact decisions escalate to the Cortex.",
        ),
    ),
    regeneration=RegenerationContract(
        implementation_state=ImplementationState.PARTIAL,
        purpose="Restore failed or contained Capability Nodes without restoring compromised state.",
        recovery_sequence=("contain", "checkpoint", "recreate", "verify", "rehydrate", "rejoin"),
        invariants=(
            "Only signed manifests and approved memory may be restored.",
            "Credentials are reissued rather than copied from the failed runtime.",
            "A regenerated node remains quarantined until health and policy checks pass.",
        ),
    ),
    invariants=(
        "Trust Fabric enforcement is body-wide and cannot be bypassed by the Cortex, Arms, or Nodes.",
        "Every Capability Node belongs to exactly one Security Arm and has an explicit authority ceiling.",
        "Cross-tenant memory, messages, credentials, and actions are denied by default.",
        "Local autonomy is bounded by policy, confidence, resource budgets, and escalation rules.",
        "Adaptive changes are versioned, tested, approved, observable, and reversible.",
    ),
)


def get_architecture_snapshot() -> ArchitectureSnapshot:
    return _SNAPSHOT.model_copy(deep=True)


def list_security_arms() -> list[SecurityArm]:
    return [arm.model_copy(deep=True) for arm in _ARMS]


def list_capability_nodes(arm_id: SecurityArmId | None = None) -> list[CapabilityNode]:
    return [
        node.model_copy(deep=True)
        for node in _CAPABILITY_NODES
        if arm_id is None or node.arm_id == arm_id
    ]


def get_capability_node(node_id: str) -> CapabilityNode | None:
    return next(
        (node.model_copy(deep=True) for node in _CAPABILITY_NODES if node.id == node_id),
        None,
    )
