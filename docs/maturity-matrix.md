# RegentClaw Maturity Matrix (2026)

**Date:** 2026-05-31  
**Purpose:** Public, conservative status tracking for platform security/runtime maturity.

Status legend:
- **Shipped**: in mainline runtime with verifiable behavior.
- **In Progress**: partially implemented or feature-flagged; not complete.
- **Planned**: scoped, not yet implemented.

| Capability Area | Status | Current Evidence | Gaps to Close |
|---|---|---|---|
| Cryptographic agent identity mesh | In Progress | Ed25519 inter-agent signing + verify endpoint | Full attestation mesh (SPIFFE-like), key lifecycle/rotation policy |
| Hard execution isolation model | In Progress | Ring policy + Trust Fabric ring decisions + route-level convergence in exec/remediation + fail-closed execution/approval behavior when Trust Fabric unavailable | Full OS sandbox guarantees across all execution channels |
| Formal SRE governance layer | In Progress | Error-budget + circuit-breaker primitives, SRE API/status endpoints | Published SLO docs, error-budget policy packs, richer telemetry/export |
| OWASP Agentic Top 10 evidence mapping | In Progress | Dedicated ASI mapping markdown + linked controls | Per-category adversarial tests and deeper evidence anchors |
| Inter-agent secure messaging (prod default) | In Progress | Feature-flagged signed secure channel in swarm task paths + verify endpoint | Default-on rollout + key governance + replay resistance policy |
| Policy test harness strength | In Progress | Ring tests + trust-fabric regressions + policy-pack allow/deny + replay regressions | Chaos/replay expansion and CI policy gates tied to policy diffs |
| Multi-tenant hardening proof | In Progress | Tenant isolation suite + scaffold tests + boundary documentation | Enforced owner/tenant scoping across all list/get paths and secrets retrieval |
| Connector trust/provenance verification | In Progress | Gateway scan/policy checks on installs | Signed provenance and checksum verification chain |
| Command/channel control plane convergence | In Progress | CommandClaw remote-agent routes + channel ingress normalized to unified command contract (`POST /api/v1/commands`) with policy outcome propagation, simulate-path parity, remote dispatch guardrails (tenant/kill-switch/intent allowlist), webhook/email/CLI ingress adapters, command pending/approve/reject/bulk-review/timeline/status/approval-policy endpoints, frontend pending-command approve/reject UX + timeline/status views + source/risk filters + approval-threshold controls + multi-select bulk actions, and persisted multi-operator approval state (self/duplicate guards + approvals progress) | Expand policy-state durability beyond event metadata and introduce richer approval delegation controls |
| Operator-grade executive reporting | In Progress | Trust Fabric dashboard + probes + status panels + Swarm live event stream + Swarm ticket draft + compliance impact rollup + Create Ticket handoff | Executive risk rollups linked to broader evidence/compliance controls across more Claws |
| Swarm runtime maturity | In Progress | Bounded parallel execution + real `/task` routing for Identity/Cloud/Threat/Arc/Access/Data/Dev/Endpoint/App/Log/Net/Compliance/Intel/Recovery/SaaS/Privacy/User/Insider/Vendor/AttackPath/Automation/Config/Exposure/Custom + SSE stream + connector-backed task paths for Cloud/Endpoint/Dev + trigger/schedule-driven swarm launches (`START_SWARM`/`FIRE_SWARM`/`SWARM_JOB`) + pre-execution approval gating and approve-to-run flow + Sprint 6 suspicious-identity preset workflow + remediation ticket handoff tests | Broaden connector-backed execution across additional claw providers and reduce simulation fallback usage in provider adapters |
| Model routing maturity (ModelClaw) | In Progress | ModelClaw governed route/profile/provider/call-audit endpoints + tenant-scoped profile/call filtering + persisted runtime state file | DB-backed provider/profile storage + richer provider adapters + per-tenant policy packs |
| Public maturity transparency | In Progress | This matrix + OWASP split docs | Keep matrix synced with code and tests each release |

---

## Reference Documents

- `docs/owasp-agentic-mapping.md` (LLM Top 10 mapping)
- `docs/owasp-asi-mapping.md` (Agentic ASI Top 10 mapping)
- `backend/app/trust_fabric/enforcement.py`
- `backend/app/services/sre_policy.py`
- `backend/app/services/ring_policy.py`
- `backend/app/core/swarm/orchestrator.py`
- `backend/app/core/swarm/routes.py`
- `backend/app/core/modelclaw/routes.py`
