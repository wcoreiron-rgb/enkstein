# RegentClaw Maturity Matrix (2026)

**Date:** 2026-06-04  
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
| Connector trust/provenance verification | In Progress | Gateway scan/policy checks on installs + AGT scan paths constrained to repo scope for requirements/package/module scans + exchange install checksum integrity gate (`x-package-sha256` + manifest hash match) + Skill Pack Exchange preview/upgrade/rollback lifecycle endpoints with scoped diff and rollback metadata + Skill Packs UI controls for install scan path, update preview, upgrade, rollback availability, and rollback execution | Signed provenance chain, full `scan.is_safe` hard-gating beyond exchange path, and signed upgrade provenance UI |
| Command/channel control plane convergence | In Progress | CommandClaw remote-agent routes + signed enrollment token issuance + remote-agent key rotation + capability inventory + channel ingress normalized to unified command contract (`POST /api/v1/commands`) with policy outcome propagation, simulate-path parity, remote dispatch guardrails (tenant/kill-switch/intent allowlist), webhook/email/CLI ingress adapters, command pending/approve/reject/bulk-review/timeline/status/approval-policy endpoints, frontend pending-command approve/reject UX + timeline/status views + source/risk filters + approval-threshold controls + multi-select bulk actions, persisted multi-operator approval state (self/duplicate guards + approvals progress), chat-ops review verbs (`approve <command_id>` / `reject <command_id>`) routed through the same governed approval APIs, Slack/Teams outbound response delivery through configured channel webhooks with persisted `response_sent` state, Slack thread metadata, Slack Block Kit / Teams MessageCard approval action metadata, outbound card/detail visibility, and Control Center v2 summary backend (`GET /api/v1/dashboard/control-center-summary`) powering unified operator cockpit cards including outbound reply health | Expand policy-state durability beyond event metadata, add signed/native channel app interactions beyond incoming-webhook card metadata, and add richer approval delegation controls |
| Operator-grade executive reporting | In Progress | Trust Fabric dashboard + probes + status panels + Swarm live event stream + Swarm ticket draft + compliance impact rollup + Create Ticket handoff with strict remediation payload guardrails (`provider=jira`, `target_type=ticket`, key/length validation) + Trust Fabric-governed ComplianceClaw evidence export with framework rollups and SHA-256 chain-of-custody hash | Executive risk rollups linked to broader evidence/compliance controls across more Claws and polished PDF/export UX |
| Swarm runtime maturity | In Progress | Bounded parallel execution + real `/task` routing for Identity/Cloud/Threat/Arc/Access/Data/Dev/Endpoint/App/Log/Net/Compliance/Intel/Recovery/SaaS/Privacy/User/Insider/Vendor/AttackPath/Automation/Config/Exposure/Custom + SSE stream + connector-backed task paths for Identity/Entra, Cloud, Endpoint, and Dev + standardized connector-state/data-source metadata surfaced across all current swarm-routed claw task outputs + trigger/schedule-driven swarm launches (`START_SWARM`/`FIRE_SWARM`/`SWARM_JOB`) + pre-execution approval gating and approve-to-run flow + Sprint 6 suspicious-identity preset workflow + Microsoft identity incident preset workflow + remediation ticket handoff tests | Broaden connector-backed execution across additional claw providers and reduce simulation fallback usage in provider adapters |
| Model routing maturity (ModelClaw) | In Progress | ModelClaw governed route/profile/provider/call-audit endpoints + tenant-scoped profile/call filtering + persisted runtime state file | DB-backed provider/profile storage + richer provider adapters + per-tenant policy packs |
| MemoryClaw runtime integration | In Progress | Swarm task input gets safe redacted memory context; task outputs expose `memory_context_loaded`; high-risk Swarm Judge results create proposed incident memory entries after safety scan; proposal queue supports approve/reject endpoints; incident memory rollback marks excluded memory with audit timeline; Memory UI exposes proposal review and rollback controls | Add richer version history/diff UI, tenant-scoped memory tables, and scheduled memory consolidation review |
| Release/deployment governance | In Progress | ReleaseClaw API/UI ships a universal deployment preflight contract for GitHub Actions, GitLab CI, Jenkins, Azure DevOps, ArgoCD, Terraform Cloud, cloud SDK/CLI, Kubernetes/Helm/Docker, Bash/PowerShell/Python/Node/Ansible, full-stack releases, and AI service stacks. Preflight runs through Trust Fabric, blocks unsafe plans, rejects self-approval, returns execution handoff metadata, exposes `/task`, and generates SHA-256 evidence bundles. | Persist deployment gates in DB, add real CI/CD execution adapters, attach deployment evidence to compliance-control tables, and add native runner callbacks for execution status |
| Terraform/IaC governance | In Progress | TerraClaw ships FastAPI/UI surfaces for Terraform HCL review, secure Terraform generation, Terraform plan risk analysis, seeded/persisted findings, provider status for Terraform Cloud/tfsec/Checkov/Infracost, normalized 0-100 risk scores, `/scan`, `/task`, connector registry mapping, and Swarm dispatcher routing. Review/generate/plan actions are Trust Fabric-gated and map findings to CIS, NIST, SOC 2, ISO 27001, PCI-DSS, and OWASP sensitive-data controls. | Add deeper live provider-backed ingestion for Terraform Cloud/checkov/tfsec/Infracost, persisted review/plan history, CI runner callbacks, and attach TerraClaw evidence directly to ReleaseClaw deployment gates |
| Public maturity transparency | In Progress | This matrix + OWASP split docs | Keep matrix synced with code and tests each release |
| Production deployment readiness | In Progress | Baseline production deployment guide covering TLS, secrets, database/Redis posture, Trust Fabric fail-closed expectations, CI security, backup/restore checklist, and ReleaseClaw governed preflight/evidence gates | Cloud-specific deployment examples, HA sizing, disaster recovery runbooks, DB-backed ReleaseClaw history, and upgrade playbooks |

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
- `backend/app/claws/releaseclaw/routes.py`
- `docs/production-deployment.md`
