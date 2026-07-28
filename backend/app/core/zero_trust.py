"""
CISA Zero Trust Maturity Model taxonomy.

Every control Enkstein evaluates is tagged to exactly one CISA pillar, which
is what makes per-pillar maturity scoring possible. NIST SP 800-207 tenets are
carried alongside as optional references: they explain *why* a control is zero
trust, but they classify poorly because a single control usually satisfies
several at once.

Pillar assignment belongs to the control, not to the Capability Node that
found it. A Terraform control enforcing encryption at rest is a Data control
regardless of which node evaluated it, and binding the pillar to the node
would force a re-tag the first time a node grows past its original scope.

Reference: CISA Zero Trust Maturity Model v2.0 (April 2023).
"""
from __future__ import annotations

import enum


class ZTPillar(str, enum.Enum):
    """The five CISA pillars plus three cross-cutting capabilities."""

    IDENTITY = "identity"
    DEVICES = "devices"
    NETWORKS = "networks"
    APPLICATIONS = "applications"
    DATA = "data"
    # Cross-cutting capabilities span all five pillars.
    VISIBILITY = "visibility"
    AUTOMATION = "automation"
    GOVERNANCE = "governance"


PILLAR_LABELS: dict[str, str] = {
    ZTPillar.IDENTITY: "Identity",
    ZTPillar.DEVICES: "Devices",
    ZTPillar.NETWORKS: "Networks",
    ZTPillar.APPLICATIONS: "Applications & Workloads",
    ZTPillar.DATA: "Data",
    ZTPillar.VISIBILITY: "Visibility & Analytics",
    ZTPillar.AUTOMATION: "Automation & Orchestration",
    ZTPillar.GOVERNANCE: "Governance",
}

CROSS_CUTTING = frozenset({ZTPillar.VISIBILITY, ZTPillar.AUTOMATION, ZTPillar.GOVERNANCE})


class ZTMaturity(str, enum.Enum):
    """CISA maturity stages, in ascending order."""

    TRADITIONAL = "traditional"
    INITIAL = "initial"
    ADVANCED = "advanced"
    OPTIMAL = "optimal"


MATURITY_ORDER: list[str] = [
    ZTMaturity.TRADITIONAL,
    ZTMaturity.INITIAL,
    ZTMaturity.ADVANCED,
    ZTMaturity.OPTIMAL,
]


# NIST SP 800-207 tenets, carried as optional cross-references.
NIST_207_TENETS: dict[str, str] = {
    "T1": "All data sources and computing services are considered resources.",
    "T2": "All communication is secured regardless of network location.",
    "T3": "Access to individual enterprise resources is granted on a per-session basis.",
    "T4": "Access is determined by dynamic policy, including observable client identity, "
          "application/service, and the requesting asset, and may include behavioral and "
          "environmental attributes.",
    "T5": "The enterprise monitors and measures the integrity and security posture of all "
          "owned and associated assets.",
    "T6": "All resource authentication and authorization are dynamic and strictly enforced "
          "before access is allowed.",
    "T7": "The enterprise collects as much information as possible about the current state "
          "of assets, network infrastructure, and communications, and uses it to improve "
          "its security posture.",
}


# Default pillar for each Capability Node. This seeds a control's pillar when
# an author does not state one; it is a starting point, never an override.
NODE_DEFAULT_PILLAR: dict[str, str] = {
    "identityclaw": ZTPillar.IDENTITY,
    "accessclaw": ZTPillar.IDENTITY,
    "userclaw": ZTPillar.IDENTITY,
    "insiderclaw": ZTPillar.IDENTITY,
    "endpointclaw": ZTPillar.DEVICES,
    "netclaw": ZTPillar.NETWORKS,
    "exposureclaw": ZTPillar.NETWORKS,
    "cloudclaw": ZTPillar.APPLICATIONS,
    "appclaw": ZTPillar.APPLICATIONS,
    "devclaw": ZTPillar.APPLICATIONS,
    "terraclaw": ZTPillar.APPLICATIONS,
    "configclaw": ZTPillar.APPLICATIONS,
    "releaseclaw": ZTPillar.APPLICATIONS,
    "arcclaw": ZTPillar.APPLICATIONS,
    "customclaw": ZTPillar.APPLICATIONS,
    "dataclaw": ZTPillar.DATA,
    "privacyclaw": ZTPillar.DATA,
    "saasclaw": ZTPillar.DATA,
    "logclaw": ZTPillar.VISIBILITY,
    "threatclaw": ZTPillar.VISIBILITY,
    "intelclaw": ZTPillar.VISIBILITY,
    "attackpathclaw": ZTPillar.VISIBILITY,
    "automationclaw": ZTPillar.AUTOMATION,
    "recoveryclaw": ZTPillar.AUTOMATION,
    "complianceclaw": ZTPillar.GOVERNANCE,
    "vendorclaw": ZTPillar.GOVERNANCE,
    "modelclaw": ZTPillar.APPLICATIONS,
}


def default_pillar(claw: str) -> str:
    """Seed pillar for a node, defaulting to Governance when unmapped."""
    return NODE_DEFAULT_PILLAR.get(claw, ZTPillar.GOVERNANCE)
