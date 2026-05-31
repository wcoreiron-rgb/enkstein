<p align="center">
  <img src="frontend/public/logo.png" alt="RegentClaw" width="120" />
</p>

<h1 align="center">RegentClaw — Zero Trust Security Ecosystem</h1>

<p align="center">Modular, governed security ecosystem with Zero Trust enforcement across every module, agent, and workflow.</p>

<p align="center">
  <a href="https://wcoreiron-rgb.github.io/regentclaw/">
    <img src="https://img.shields.io/badge/Documentation-1f2937?style=for-the-badge&logo=gitbook&logoColor=white" alt="Documentation" />
  </a>
  <a href="https://wcoreiron-rgb.github.io/regentclaw/docs.html">
    <img src="https://img.shields.io/badge/Technical%20Docs-2563eb?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Technical Docs" />
  </a>
  <a href="http://localhost:3000">
    <img src="https://img.shields.io/badge/Dashboard%20(local)-0f766e?style=for-the-badge&logo=vercel&logoColor=white" alt="Dashboard (local)" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/wcoreiron-rgb/regentclaw/projects">
    <img src="https://img.shields.io/badge/Roadmap%202026-7c3aed?style=for-the-badge&logo=githubprojects&logoColor=white" alt="Roadmap 2026" />
  </a>
  <a href="https://github.com/wcoreiron-rgb/regentclaw/issues/new?labels=bug&title=%5BBug%5D+">
    <img src="https://img.shields.io/badge/Report%20Bug-dc2626?style=for-the-badge&logo=github&logoColor=white" alt="Report Bug" />
  </a>
  <a href="https://github.com/wcoreiron-rgb/regentclaw/issues/new?labels=enhancement&title=%5BFeature%5D+">
    <img src="https://img.shields.io/badge/Request%20Feature-2563eb?style=for-the-badge&logo=github&logoColor=white" alt="Request Feature" />
  </a>
  <a href="https://github.com/wcoreiron-rgb/regentclaw/discussions">
    <img src="https://img.shields.io/badge/GitHub%20Discussions-0f766e?style=for-the-badge&logo=github&logoColor=white" alt="GitHub Discussions" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/wcoreiron-rgb/regentclaw/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/wcoreiron-rgb/regentclaw/ci.yml?branch=main&label=Build%20and%20Test%20(Unit%20%2B%20E2E)" alt="Build and Test (Unit + E2E)" />
  </a>
  <a href="https://codecov.io/gh/wcoreiron-rgb/regentclaw">
    <img src="https://img.shields.io/codecov/c/github/wcoreiron-rgb/regentclaw?label=codecov" alt="codecov" />
  </a>
</p>

<p align="center"><strong>Full Documentation</strong></p>
<p align="center">
  <a href="https://wcoreiron-rgb.github.io/regentclaw/">
    <img src="https://img.shields.io/badge/Quick%20Start-f59e0b?style=for-the-badge&logo=rocket&logoColor=white" alt="Quick Start" />
  </a>
  <a href="https://wcoreiron-rgb.github.io/regentclaw/docs.html#architecture">
    <img src="https://img.shields.io/badge/Specifications-0891b2?style=for-the-badge&logo=bookstack&logoColor=white" alt="Specifications" />
  </a>
  <a href="https://wcoreiron-rgb.github.io/regentclaw/changelog.html">
    <img src="https://img.shields.io/badge/Changelog-4f46e5?style=for-the-badge&logo=readme&logoColor=white" alt="Changelog" />
  </a>
</p>

<p align="center"><strong>Languages</strong></p>
<p align="center">
  <img src="https://img.shields.io/badge/Python-62.8%25-3776AB?logo=python&logoColor=white" alt="Python 62.8%" />
  <img src="https://img.shields.io/badge/TypeScript-36.5%25-3178C6?logo=typescript&logoColor=white" alt="TypeScript 36.5%" />
  <img src="https://img.shields.io/badge/Shell-0.4%25-121011?logo=gnubash&logoColor=white" alt="Shell 0.4%" />
  <img src="https://img.shields.io/badge/CSS-0.3%25-1572B6?logo=css3&logoColor=white" alt="CSS 0.3%" />
  <img src="https://img.shields.io/badge/JavaScript-0.0%25-F7DF1E?logo=javascript&logoColor=black" alt="JavaScript 0.0%" />
  <img src="https://img.shields.io/badge/Mako-0.0%25-8B5CF6" alt="Mako 0.0%" />
</p>

## Architecture

```
RegentClaw/
├── backend/           FastAPI — CoreOS, Trust Fabric, ArcClaw, IdentityClaw
├── frontend/          Next.js — Platform UI dashboard
├── docker-compose.yml Full local stack
```

## Security Compliance

RegentClaw maintains an honest, evidence-backed self-assessment against the **OWASP Top 10 for LLM/Agentic AI Applications (2025)**.

| Document | Format |
|---|---|
| [OWASP Evidence Matrix (Interactive)](https://wcoreiron-rgb.github.io/regentclaw/owasp-agentic.html) | Interactive HTML |
| [LLM Top 10 Mapping (Markdown)](docs/owasp-agentic-mapping.md) | Markdown |
| [Agentic ASI Top 10 Mapping (Markdown)](docs/owasp-asi-mapping.md) | Markdown |
| [Platform Maturity Matrix (Markdown)](docs/maturity-matrix.md) | Markdown |

**Current posture (2026-05-31):**

| Category | Status |
|---|---|
| LLM01 Prompt Injection | Shipped — 12-vector AGT audit on every AI event |
| LLM02 Insecure Output Handling | Partially Shipped — input scanning only; output re-scan not yet applied |
| LLM03 Training Data Poisoning | N/A — uses provider APIs, no training pipeline |
| LLM04 Model Denial of Service | In Progress — auth rate limiting exists; AI endpoint limits planned |
| LLM05 Supply-Chain Vulnerabilities | In Progress — encrypted credentials, pinned deps, AGT supply-chain scan test coverage; no SBOM yet |
| LLM06 Sensitive Information Disclosure | Shipped — Fernet encryption, DLP scanner, masked credential hints |
| LLM07 Insecure Plugin Design | Partially Shipped — ring policy + SSRF protection shipped; OS sandbox not yet |
| LLM08 Excessive Agency | Shipped — 4-ring privilege isolation, dual-approval gates, self-approval blocked |
| LLM09 Overreliance | Partially Shipped — risk scores visible; no override audit trail yet |
| LLM10 Model Theft | N/A — no hosted weights; API keys encrypted at rest |

> This is a vendor self-assessment. Independent audit recommended before compliance reliance.

## Quick Start

### Prerequisites
- Docker + Docker Compose installed
- 4GB RAM available

### Run locally

```bash
cd RegentClaw
docker-compose up --build
```

Then open:
- **Frontend UI**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Health check**: http://localhost:8000/health

### First steps after launch

1. Open http://localhost:3000/dashboard
2. Go to **Connectors** → click any connector → enter your own API credentials
   - Credentials are encrypted at rest (Fernet AES-128) and never stored in plaintext
   - Each deployment auto-generates its own encryption key in `backend/.secrets/` (gitignored)
3. Go to **Policies** → add preset policies (Block Shell Execution, etc.)
4. Go to **ArcClaw** → submit a test prompt (try including an API key to test detection)
5. Watch the **Events** and **Audit** log populate
6. Go to **IdentityClaw** → check identity inventory

> **Security note:** Never commit `backend/.secrets/` — it contains your encryption key and stored credentials. This directory is gitignored by default. Each deployer gets their own isolated key.

### Connecting your own tools

Every Claw module supports real integrations. Go to **Connectors** and add credentials for the tools you use:

| Category | Supported integrations |
|---|---|
| Cloud | AWS (Security Hub), Azure (Defender), GCP (Security Command Center) |
| Endpoint | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne |
| Identity | Okta, Microsoft Entra ID, AWS IAM |
| AI/LLM | Anthropic, OpenAI, Azure OpenAI, Ollama (local) |
| Code | GitHub (secret scanning, code review) |
| Log/SIEM | Splunk |
| Custom | Any REST API via CustomClaw |

Without credentials, all modules run on realistic simulated findings so the platform is fully usable for demos and evaluation.

## API Reference

Full interactive docs at: http://localhost:8000/docs

Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/dashboard | Platform stats |
| POST | /api/v1/arcclaw/events | Submit AI event for inspection |
| GET | /api/v1/arcclaw/stats | ArcClaw risk summary |
| GET | /api/v1/identityclaw/identities | Identity inventory |
| GET | /api/v1/identityclaw/orphaned | Orphaned identities |
| GET | /api/v1/policies | List policies |
| POST | /api/v1/policies | Create policy |
| GET | /api/v1/events | All events |
| GET | /api/v1/events/anomalies | Anomalies only |
| GET | /api/v1/audit | Audit log |

## Security Design Principles

1. **Every component has identity** — No anonymous modules or connectors
2. **Every action is authorized** — Policy evaluated before execution
3. **Every runtime is monitored** — Behavior tracked, not just access
4. **Every workflow is attributable** — Maps to a human owner
5. **Every risk is containable** — Isolation, revocation, kill switch
6. **Every module is governed** — Plug-and-play = plug-and-governed

## AGT + Multi-Agent Governance (New)

RegentClaw now exposes AGT rollout through a provider boundary instead of direct Claw coupling:

- Adapter boundary: `backend/app/fabric/providers/agt/`
- Feature flags (opt-in): `AGT_ENABLE_MCP_GATEWAY`, `AGT_ENABLE_E2E_MESSAGING`, `AGT_ENABLE_AGENT_MESH`, `AGT_ENABLE_SHADOW_DISCOVERY`
- Trust Fabric APIs:
  - `GET /api/v1/trust-fabric/multi-agent/status`
  - `POST /api/v1/trust-fabric/mcp/scan`

Detailed rollout plan: `docs/agt-3.2-regentclaw-plan.md`

## Latest Updates (May 31, 2026)

- Command and channel control-plane convergence:
  - Channel gateway ingress (`/channel-gateway/slack/events`, `/channel-gateway/teams/webhook`, `/channel-gateway/message`) now normalizes inbound requests into CommandClaw contract payloads.
  - Normalized channel commands execute through the same policy-governed command path used by `POST /api/v1/commands`.
  - Channel responses now include `command_result` metadata with command id, intent, target, and policy outcome.
  - Added fallback behavior for unavailable command backend (`outcome: unavailable`) so channel ingestion remains non-breaking.
  - `/channel-gateway/simulate` now mirrors the same command normalization path and returns `command_result` for parity testing.
  - Added channel ingress adapters for generic webhook and email:
    - `POST /api/v1/channel-gateway/webhook`
    - `POST /api/v1/channel-gateway/email/inbound`
    Both routes now normalize to the same CommandClaw contract and return `command_result`.
  - Added CLI ingress adapter:
    - `POST /api/v1/channel-gateway/cli/command`
    with optional `tenant_id` for tenant-scoped command normalization.
  - Remote-agent dispatch now enforces tenant match, kill-switch state, and per-agent allowed command intents.
  - Added approval workflow APIs for command outcomes:
    - `GET /api/v1/commands/pending`
    - `POST /api/v1/commands/{command_id}/approve`
    - `POST /api/v1/commands/{command_id}/reject`
    - `POST /api/v1/commands/bulk-review`
    - `GET /api/v1/commands/{command_id}/timeline`
    - `GET /api/v1/commands/{command_id}/status`
    - `POST /api/v1/commands/{command_id}/approval-policy`
  - Command approval flow now supports persisted multi-operator state:
    - approval progress (`approvals_received` / `required_approvals`) exposed in pending API
    - self-approval blocked
    - duplicate approver blocked
    - approver principal is now JWT-bound (display name is informational only)
    - final command allow only after required approvals are met
    - explicit rejection path that marks pending command as blocked with reviewer reason
    - command timeline endpoint for full approval/rejection audit trail
    - pending list filters (`source`, `requester`, `min_risk`) for tighter triage views
    - approval delegation control to raise/lower required approvals (within guardrails)
  - Channel Gateway UI now includes:
    - `Pending Commands` approval tab wired to CommandClaw approval APIs
    - multi-select + bulk approve/reject controls for pending command batches
    - bulk review outcome summary with per-command error visibility for partial-failure cases
    - per-command timeline view for operator audit context
    - timeline focus filters (All/Approvals/Rejections) for faster approval audit review
    - timeline export actions (copy JSON, download JSON) for audit handoff
    - pending command search + source/min-risk filters + consolidated status preview
    - inline required-approvals selector for pending command delegation
    - quick-ingest actions for CLI/Webhook/Email adapters
    - expanded message detail with normalized `command_result` metadata
  - Remediation ticket handoff validation now enforces stricter `create_jira_ticket` payload guardrails:
    - `project_key` must be uppercase alphanumeric (dashes/underscores allowed)
    - minimum summary/description length checks before queueing remediation action
  - Added Playwright E2E coverage for Channel Gateway bulk pending-command approve flow.
- Swarm runtime:
  - Swarm background execution now uses bounded parallelism (Semaphore + gather) instead of sequential task loops.
  - Dispatcher now routes supported claws to real focused task handlers (`/task`) with deterministic fallback for unsupported claws.
  - Added live SSE stream endpoint: `GET /api/v1/swarm/jobs/{id}/stream` with `job_snapshot`, `task_started`, `task_completed`, and `job_completed` events.
- Core claw task contract:
  - Added `POST /task` for:
    - `/api/v1/identityclaw/task`
    - `/api/v1/cloudclaw/task`
    - `/api/v1/threatclaw/task`
    - `/api/v1/arcclaw/task`
    - `/api/v1/accessclaw/task`
    - `/api/v1/dataclaw/task`
    - `/api/v1/devclaw/task`
    - `/api/v1/endpointclaw/task`
    - `/api/v1/appclaw/task`
    - `/api/v1/logclaw/task`
    - `/api/v1/netclaw/task`
    - `/api/v1/complianceclaw/task`
    - `/api/v1/intelclaw/task`
    - `/api/v1/recoveryclaw/task`
  - Standard task response fields now align with Swarm Task Contract (`risk_score`, `confidence`, `recommended_actions`, `policy_decisions`, `execution_time_ms`, etc.).
- ModelClaw scaffold:
  - Added `ModelClaw` module at `backend/app/core/modelclaw/` with providers, profiles, routed calls, and call audit surfaces.
  - New endpoints:
    - `GET /api/v1/modelclaw/providers`
    - `GET /api/v1/modelclaw/profiles`
    - `POST /api/v1/modelclaw/profiles`
    - `POST /api/v1/modelclaw/route`
    - `GET /api/v1/modelclaw/calls`
  - Model routes are enforced through Trust Fabric decisions before response.
  - Added tenant-scoped profile/call filtering (`tenant_id`) and persisted runtime state for profiles/call audit (`backend/.state/modelclaw_state.json`).
- Swarm Judge synthesis:
  - Added dedicated `swarm_judge_profile`.
  - Swarm Judge now attempts ModelClaw-routed synthesis and falls back to deterministic summary when denied/unavailable.
- Sprint 5 trigger/schedule swarm support:
  - Added `start_swarm` / `fire_swarm` trigger execution path with profile-aware defaults and optional pre-execution approval gating.
  - Added schedule swarm execution support for `SWARM_JOB`, `START_SWARM`, and `FIRE_SWARM` notes types.
  - Added `/swarm/jobs/{id}/approve` behavior for both approval phases:
    - pre-execution approval now starts/runs the job
    - post-judge approval now finalizes the job
  - Added shared swarm profile defaults (`FAST_TRIAGE`, `DEEP_INVESTIGATION`, `INCIDENT_RESPONSE`, `AUTONOMOUS_LOW_RISK`, `EMERGENCY_CONTAINMENT`) applied to trigger/schedule launches.
- Sprint 6 operator workflow:
  - Added one-click preset endpoint for **Suspicious Identity Investigation Swarm**:
    - `POST /api/v1/swarm/jobs/presets/suspicious-identity`
  - Preset launches Identity/Threat/Cloud/Data/Compliance/Automation participants with incident-response defaults and approval gate.
  - Swarm UI now includes quick-launch controls for the preset and richer judge output context (root cause, blast radius, next steps) on job detail.
  - Swarm job detail now generates a live ticket draft and compliance impact rollup from judge/task evidence.
  - Added direct **Create Ticket** handoff from Swarm detail to `POST /api/v1/remediation/trigger` using `create_jira_ticket` action specs.
  - Remediation trigger now validates ticket action payload shape (`project_key`, `summary`, `description`) before queuing/executing.
  - Added Playwright E2E coverage for the Swarm Create Ticket flow:
    - `cd frontend && npm run test:e2e -- e2e/swarm-create-ticket.spec.ts`
    - Local sandbox note: E2E requires the dev server to bind to `127.0.0.1:3100`.

## Platform Modules (26 Security Claws + Core Engines)

### Security Domain Claws (24)

| Module | Description |
|--------|-------------|
| 🤖 ArcClaw | AI & LLM Security — prompt injection detection (12-vector AGT audit), NVIDIA NIM, Claude, OpenAI, Ollama |
| 🪪 IdentityClaw | Identity Governance — human & non-human identity risk scoring, Okta, Entra ID |
| ☁️ CloudClaw | Cloud Security Posture — AWS, Azure, GCP, real-time findings |
| 🌐 ExposureClaw | External Attack Surface Management — CVE lookup, CISA KEV, MITRE ATT&CK |
| 🛡️ EndpointClaw | EDR — CrowdStrike, Defender, SentinelOne, quarantine/unquarantine |
| 🔍 ThreatClaw | Threat Intelligence & Detection — MITRE ATT&CK mapping, automated triage |
| 📋 LogClaw | Log Management & SIEM coverage |
| 🌉 NetClaw | Network Security & segmentation — Palo Alto, Fortinet, Cisco |
| 🔑 AccessClaw | Access Control & IAM governance — Okta, Entra ID, CyberArk |
| 🗂️ DataClaw | Data Loss Prevention — Varonis, Purview, Macie |
| 📱 AppClaw | Application Security — SAST, SCA, Snyk, Veracode |
| ☁️ SaasClaw | SaaS Security Posture Management — Netskope, Zscaler |
| ⚙️ ConfigClaw | Configuration Compliance — AWS Config, Azure Policy |
| ✅ ComplianceClaw | SOC2, PCI-DSS, ISO 27001, HIPAA, GDPR, CIS — control mappings + evidence |
| 🔒 PrivacyClaw | Privacy & GDPR enforcement — OneTrust, TrustArc |
| 🏢 VendorClaw | Third-Party & Supply Chain Risk — BitSight, SecurityScorecard |
| 👤 UserClaw | User Behavior Analytics — UEBA, anomaly detection |
| 🔎 InsiderClaw | Insider Threat Detection — Proofpoint, Purview |
| ⚡ AutomationClaw | Automation & CI/CD Security — ServiceNow, Jira, SOAR |
| 🗺️ AttackPathClaw | Attack Path Analysis — XM Cyber, Orca, Tenable |
| 💻 DevClaw | DevSecOps & Secret Scanning — GitHub Advanced Security, Snyk |
| 🧠 IntelClaw | Threat Intelligence Feeds — Recorded Future, MISP |
| 🔄 RecoveryClaw | Incident Recovery & Runbooks — Veeam, Rubrik |
| 🔌 CustomClaw | User-defined REST API integrations — no-code builder |

### New Core Platform Modules (2)

| Module | Description |
|--------|-------------|
| 🧩 ModelClaw | AI Model Governance — policy-governed model routing, tenant-scoped profiles, call audit, ModelClaw Judge synthesis |
| ⚡ CommandClaw | Multi-channel Command Ingestion — Teams, Slack, webhook, email, CLI → unified policy-governed command contract with multi-operator approval |

### Platform Engines (always-on)

| Engine | Description |
|--------|-------------|
| 🛡️ Trust Fabric | Central zero-trust enforcement — policy eval, risk scoring, audit for every action |
| 🔄 Swarm Orchestration | Multi-agent parallel investigation — planner, dispatcher, judge, SSE stream, ticket handoff |
| 🚨 Autonomous Remediation | Finding → playbook → action → approval gate → rollback. 5 built-in playbooks, 4 provider integrations |
| 💍 Ring Policy | 4-tier execution isolation (ring0 blocked → ring3 auto-allow). Deterministic `execution_ring_violation` deny |
| 📡 Channel Gateway | Multi-channel ingress normalization with approval workflow, bulk review, timeline audit |
| 🔐 External Agent Control | Remote agent registration, heartbeat, dispatch, tenant enforcement, kill-switch |
| 📦 Skill Pack Exchange | Signed marketplace for skills, policies, playbooks — provenance-verified at install |
| 🏥 SRE Engine | Circuit breaker, error budget, SLO enforcement for all governed modules |

## Tech Stack

- **Backend**: FastAPI + SQLAlchemy (async) + PostgreSQL + Redis
- **Frontend**: Next.js 14 + TypeScript + Tailwind CSS
- **Infra**: Docker Compose

## Development

### Backend only
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend only
```bash
cd frontend
npm install
npm run dev
```
