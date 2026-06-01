# RegentClaw Maturity Matrix (2026)

**Date:** 2026-05-31  
**Purpose:** Public, conservative status tracking for platform security/runtime maturity.

Status legend:
- **Shipped**: in mainline runtime with verifiable behavior.
- **In Progress**: partially implemented or feature-flagged; not complete.
- **Planned**: scoped, not yet implemented.

| Capability Area | Status | Current Evidence | Gaps to Close |
|---|---|---|---|
| Cryptographic agent identity mesh | In Progress | Ed25519 inter-agent signing + verify endpoint + remote-agent signed enrollment tokens + public-key fingerprint tracking + key rotation endpoint | Full attestation mesh (SPIFFE-like), hardware-backed attestation, and production key lifecycle policy |
| Hard execution isolation model | In Progress | Ring policy + Trust Fabric ring decisions + route-level convergence in exec/remediation + fail-closed execution/approval behavior when Trust Fabric unavailable | Full OS sandbox guarantees across all execution channels |
| Formal SRE governance layer | In Progress | Error-budget + circuit-breaker primitives, SRE API/status endpoints | Published SLO docs, error-budget policy packs, richer telemetry/export |
| OWASP Agentic Top 10 evidence mapping | In Progress | Dedicated ASI mapping markdown + linked controls | Per-category adversarial tests and deeper evidence anchors |
| Inter-agent secure messaging (prod default) | In Progress | Feature-flagged signed secure channel in swarm task paths + verify endpoint | Default-on rollout + key governance + replay resistance policy |
| Policy test harness strength | In Progress | Ring tests + trust-fabric regressions + policy-pack allow/deny + replay regressions | Chaos/replay expansion and CI policy gates tied to policy diffs |
| Multi-tenant hardening proof | In Progress | Tenant isolation suite + scaffold tests + boundary documentation + MemoryClaw runtime only injects short redacted context and blocks secret/prompt-injection-like memory writes | Enforced owner/tenant scoping across all list/get paths and secrets retrieval |
| Connector trust/provenance verification | In Progress | Gateway scan/policy checks on installs + AGT scan paths constrained to repo scope for requirements/package/module scans + exchange install checksum integrity gate (`x-package-sha256` + manifest hash match) | Signed provenance chain and full `scan.is_safe` hard-gating beyond exchange path |
| Command/channel control plane convergence | In Progress | CommandClaw remote-agent routes + signed enrollment token issuance + remote-agent key rotation + capability inventory + channel ingress normalized to unified command contract (`POST /api/v1/commands`) with policy outcome propagation, simulate-path parity, remote dispatch guardrails (tenant/kill-switch/intent allowlist), webhook/email/CLI ingress adapters, command pending/approve/reject/bulk-review/timeline/status/approval-policy endpoints, frontend pending-command approve/reject UX + timeline/status views + source/risk filters + approval-threshold controls + multi-select bulk actions, persisted multi-operator approval state (self/duplicate guards + approvals progress), chat-ops review verbs (`approve <command_id>` / `reject <command_id>`) routed through the same governed approval APIs, Slack/Teams outbound response delivery through configured channel webhooks with persisted `response_sent` state, and Control Center v2 summary backend (`GET /api/v1/dashboard/control-center-summary`) powering unified operator cockpit cards | Expand policy-state durability beyond event metadata, add richer approval delegation controls, and add native interactive Slack/Teams cards beyond incoming-webhook response delivery |
| Operator-grade executive reporting | In Progress | Trust Fabric dashboard + probes + status panels + Swarm live event stream + Swarm ticket draft + compliance impact rollup + Create Ticket handoff with strict remediation payload guardrails (`provider=jira`, `target_type=ticket`, key/length validation) | Executive risk rollups linked to broader evidence/compliance controls across more Claws |
| Swarm runtime maturity | In Progress | Bounded parallel execution + real `/task` routing for Identity/Cloud/Threat/Arc/Access/Data/Dev/Endpoint/App/Log/Net/Compliance/Intel/Recovery/SaaS/Privacy/User/Insider/Vendor/AttackPath/Automation/Config/Exposure/Custom + SSE stream + connector-backed task paths for Identity/Entra, Cloud, Endpoint, and Dev + standardized connector-state/data-source metadata surfaced across all current swarm-routed claw task outputs + trigger/schedule-driven swarm launches (`START_SWARM`/`FIRE_SWARM`/`SWARM_JOB`) + pre-execution approval gating and approve-to-run flow + Sprint 6 suspicious-identity preset workflow + Microsoft identity incident preset workflow + remediation ticket handoff tests | Broaden connector-backed execution across additional claw providers and reduce simulation fallback usage in provider adapters |
| Model routing maturity (ModelClaw) | In Progress | ModelClaw governed route/profile/provider/call-audit endpoints + tenant-scoped profile/call filtering + persisted runtime state file | DB-backed provider/profile storage + richer provider adapters + per-tenant policy packs |
| MemoryClaw runtime integration | In Progress | Swarm task input gets safe redacted memory context; task outputs expose `memory_context_loaded`; high-risk Swarm Judge results create proposed incident memory entries after safety scan | Add analyst approval workflow for memory commits, version/rollback UI, tenant-scoped memory tables |
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
