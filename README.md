<p align="center">
  <img src="frontend/public/logo.png" alt="Enkstein" width="120" />
</p>

<h1 align="center">Enkstein</h1>

<p align="center"><b>Govern every AI you use.</b></p>

<p align="center">
  Use Codex, Claude, Gemini, and local Ollama models from one open-source desktop app.<br />
  Keep sensitive work local, control which files and tools AI can touch, approve consequential<br />
  actions, and keep an audit trail of what left your machine and what did not.
</p>

<p align="center">
  <a href="https://github.com/wcoreiron-rgb/enkstein/releases/latest/download/Enkstein-macos.pkg">
    <img src="https://img.shields.io/badge/Download%20for-macOS-000000?style=for-the-badge&logo=apple&logoColor=white" alt="Download for macOS" />
  </a>
  &nbsp;
  <a href="https://github.com/wcoreiron-rgb/enkstein/releases/latest/download/Enkstein-windows-x64-setup.exe">
    <img src="https://img.shields.io/badge/Download%20for-Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Download for Windows" />
  </a>
</p>

<p align="center">
  <sub>
    <b>Current release: v0.8.3</b> &nbsp;&middot;&nbsp; macOS 14+ (Apple silicon &amp; Intel), Developer ID signed and notarized &nbsp;&middot;&nbsp;
    Windows 10/11 x64, currently unsigned &mdash; SmartScreen shows a publisher warning &nbsp;&middot;&nbsp;
    <a href="https://github.com/wcoreiron-rgb/enkstein/releases/latest">All downloads &amp; checksums</a>
  </sub>
</p>

<h3 align="center">Before you launch</h3>

<p align="center">
  <b>Required &mdash; <a href="https://www.docker.com/products/docker-desktop/">Docker Desktop</a>.</b><br />
  <sub>Enkstein runs its governed services locally. Every launch checks Docker Desktop before starting anything, opens it when stopped, and waits for <code>docker info</code> to succeed. If Docker is missing, the official Docker installation flow opens and Enkstein keeps checking until the engine is ready. Allow 4&nbsp;GB RAM.</sub>
</p>

<p align="center">
  <b>Optional &mdash; <a href="https://ollama.com/download">Ollama</a>, for free local Brains.</b><br />
  <sub>Without it Enkstein still runs; you supply your own model access instead (Codex or Claude subscription, or an API key). With it, Chat, Cowork, and Security work offline at no cost. Enkstein discovers whatever models you have pulled.</sub>
</p>

<p align="center">
  <sub>Prefer to run it yourself? See <a href="#quick-start">Quick Start</a> for the self-hosted bundle, and the <a href="docs/testing-guide.md">Testing Guide</a> for what to try first.</sub>
</p>

---

## Enkstein is not another AI model

It is the local control plane around the models you already pay for.

Codex and Claude Code are excellent at writing code. Neither can tell you
whether a secret reached a cloud provider, which model saw your customer data,
or what an agent changed on disk while you were away. Enkstein sits in front of
them and answers those questions.

- **Route safely.** Pick models by data sensitivity, cost, and capability.
  `restricted` and `top_secret` work is pinned to local models and never leaves
  the machine.
- **Approve actions.** Bound which files, commands, and connectors an AI may
  reach. Consequential changes wait for you.
- **Verify results.** Every reply carries provenance: which model answered, what
  policy decided, what was redacted, and which files changed.

Bring your own Brains — a Codex or Claude subscription, an API key, or local
models through Ollama. Enkstein's control plane runs on your hardware. Content
leaves the device only when you select a cloud, subscription, or browser Brain,
subject to the active policy and redaction decision.

<p align="center">
  <img src="https://img.shields.io/badge/status-v0.x%20preview-f59e0b?style=flat-square" alt="v0.x preview" />
  <img src="https://img.shields.io/badge/deployment-self--hosted-2563eb?style=flat-square" alt="self-hosted" />
  <img src="https://img.shields.io/badge/evidence-origin-always%20labelled-7c3aed?style=flat-square" alt="evidence origin is labelled" />
  <img src="https://img.shields.io/badge/audit-not%20yet%20independently%20audited-64748b?style=flat-square" alt="not yet audited" />
</p>

> [!NOTE]
> **Early preview (v0.x).** Enkstein is under active development. Security mode
> includes clearly labelled demonstration paths for local evaluation; live
> assessment requires a configured and verified connector. Some legacy Node
> workflows still use labelled simulation fallback, while the Identity Incident
> Mission and control verdicts fail closed without eligible evidence. Enkstein
> has **not had an independent third-party audit**,
> so it is built for evaluation and feedback rather than unmonitored production.
> See the [Maturity Matrix](docs/maturity-matrix.md) for what is shipped versus
> in progress, and the [OWASP Agentic self-assessment](https://wcoreiron-rgb.github.io/enkstein/owasp-agentic.html).

## How it works

You point Enkstein at a project or a security question. Before any model sees
it, Enkstein classifies the data, decides which model is permitted, redacts
what should not travel, and records the decision.

1. **Chat** — governed conversation with any connected model.
2. **Cowork** — file-assisted work in a project folder you select. Answering
   models are advisors; Enkstein performs the writes, inside your approved
   folder, with a diff you approve.
3. **Security** — 26 capability areas covering cloud posture, identity,
   endpoint, threat intel, and DevSec, plus AI-specific governance like
   prompt-injection detection and DLP.

Governed execution paths apply Trust Fabric policy, risk scoring, privilege
tiers, human approval for high-risk actions, and an attributable audit record.
The [Maturity Matrix](docs/maturity-matrix.md) identifies legacy and in-progress
surfaces that do not yet carry the same assurance level.

**The problem it solves:** how do you let AI agents do real work without handing
them unbounded power over your environment?

### First workflow: Identity Incident Mission

Enter a suspicious user or principal in **Identity Security** and start an
Identity Incident Mission. Enkstein correlates approved identity, endpoint,
cloud, log, threat, and compliance evidence; shows the source of every task as
live, recorded, demo, or unavailable; then produces a confidence, blast-radius,
ticket draft, and recommended actions. The investigation is read/analyze/
recommend only. Any session revocation, account containment, device isolation,
or ticket action remains a separate Trust Fabric approval.

By default, the mission does **not** use seeded or simulated findings. The
operator may explicitly enable labeled demo evidence for a local walkthrough.
See [Identity Incident Mission](docs/identity-incident-mission.md) for the
evidence policy, connector requirements, and action limits.

Internally the architecture is organism-inspired — a Cortex that routes, Three
Hearts for trust, memory, and execution, Security Arms, Capability Nodes, and a
peer Plexus. You do not need any of that vocabulary to use the app; see
[Architecture](docs/marcellus-architecture.md) and the
[Runtime Reference](docs/runtime-reference.md) if you want it.

## Screenshots

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/cowork.png" alt="Cowork workspace" /><br/><sub><b>Cowork</b> — governed file work in a project folder you select. Pick the runtime group, executor, and whether changes auto-apply or wait for approval.</sub></td>
    <td width="50%"><img src="docs/screenshots/brains.png" alt="Brain Connections" /><br/><sub><b>Brain Connections</b> — Codex, Claude, browser sessions, and local Ollama models side by side. Cookies and account tokens never enter Enkstein.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/security.png" alt="Security mode" /><br/><sub><b>Security</b> — Mission Control and the Capability Nodes, grouped into Arms that stay collapsed until you open them.</sub></td>
    <td width="50%"><img src="docs/screenshots/trust-fabric.png" alt="Trust Fabric" /><br/><sub><b>Trust Fabric</b> — the policy decision behind every model call, tool invocation, and remediation, with the audit record.</sub></td>
  </tr>
</table>

> More views: [Chat](docs/screenshots/chat.png) · [Platform Overview](docs/screenshots/dashboard.png) · [Swarm](docs/screenshots/swarm.png) · [Remediation](docs/screenshots/remediation.png) · [Zero Trust coverage](docs/screenshots/zero-trust.png) · [Connectors](docs/screenshots/connectors.png)

### Product Tour

<p align="center">
  <a href="docs/demo/enkstein-tour.webm">
    <img src="docs/demo/enkstein-tour.gif" alt="Enkstein tour: Cowork, Brain Connections, Light, and Liquid Glass" width="720" />
  </a>
</p>

<p align="center"><sub>Click the preview to watch the full tour.</sub></p>

### Themes

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/cowork-light.png" alt="Cowork in light theme" /><br/><sub><b>Light</b> — a clean opaque workspace for long sessions and bright environments.</sub></td>
    <td width="50%"><img src="docs/screenshots/cowork-liquid.png" alt="Cowork in Liquid Glass theme" /><br/><sub><b>Liquid Glass</b> — a translucent native-material workspace. This web capture uses a representative backdrop; the desktop app composites your own wallpaper behind it.</sub></td>
  </tr>
</table>

The theme picker is in the sidebar footer: Dark, Light, and Liquid Glass.

## Where Enkstein Fits

Enkstein does not replace the model, agent CLI, or security products you
already use. It provides the local workspace and policy boundary around them.

| Tool category | Primary strength | Enkstein's role |
|---|---|---|
| Model and coding assistants | Reasoning, generation, and coding | Route requests to an approved Brain and record provider provenance |
| Agent frameworks | Tool composition and custom workflows | Apply tenant, policy, approval, and audit controls around execution |
| Security products and SOAR | Product-specific telemetry and response | Normalize connector evidence and govern cross-product investigation or remediation |
| Local models | Private, offline inference | Handle eligible work without sending content to a cloud provider |

The distinguishing workflow is evidence-to-action: collect evidence from
configured tools, analyze it with one or more Brains, propose a bounded action,
apply policy and approval gates, then record the outcome. Availability and
assurance depend on the configured connectors and the maturity status of the
selected surface; see the [Maturity Matrix](docs/maturity-matrix.md).

## Architecture

```
Enkstein/
├── backend/           FastAPI — CoreOS, Trust Fabric, AI Security, Identity Security
├── frontend/          Next.js — Platform UI dashboard
├── docker-compose.yml Full local stack
```

Deeper reading:

- [Architecture](docs/marcellus-architecture.md) — the Cortex, Hearts, Arms, and Plexus model.
- [Runtime Reference](docs/runtime-reference.md) — Missions, Reflexes, Regeneration, Brain runtime groups, and Brain Bridges.
- [Maturity Matrix](docs/maturity-matrix.md) — what is shipped versus in progress.
- [Testing Guide](docs/testing-guide.md) — which connectors work without a paid account.
- [Evidence and Connector Contract](docs/evidence-and-connector-contract.md) — what configured, verified, live, recorded, demo, and unavailable mean.

## Security Compliance

Security claims are documented as a vendor self-assessment and tied to source or
tests. Enkstein has not completed an independent third-party audit; do not use
the self-assessment as compliance certification.

- [Interactive OWASP evidence matrix](https://wcoreiron-rgb.github.io/enkstein/owasp-agentic.html)
- [OWASP LLM mapping](docs/owasp-agentic-mapping.md)
- [OWASP Agentic ASI mapping](docs/owasp-asi-mapping.md)
- [Maturity Matrix](docs/maturity-matrix.md)
- [Production Deployment Guide](docs/production-deployment.md)

## Quick Start

> **Evaluating Enkstein or testing connectors?** Start with the
> [Testing Guide](docs/testing-guide.md). It lists which connectors work
> without a paid account, what a passing connector test does and does not
> prove, how to tell live findings from demonstration data, and the gaps worth
> knowing before you file an issue.

### Download a release package

The easiest installation path is a versioned bundle from
[GitHub Releases](https://github.com/wcoreiron-rgb/enkstein/releases). Release
assets include a `.tar.gz` self-hosted bundle, Python package artifacts, and
`SHA256SUMS` integrity checks.

```bash
tar -xzf enkstein-VERSION.tar.gz
cd enkstein-VERSION
./install.sh
```

The installer validates Docker Compose, creates a private `.env` with unique
random secrets, and tries to pull the versioned backend and frontend images. If
either image is unavailable, it builds both locally before starting Enkstein.
It never overwrites an existing `.env`. See
[installation details](docs/installation.md).

### Desktop installers

Native launcher assets use these names when they are included in a release:

- **macOS:** install `Enkstein-VERSION-macos.pkg`; setup creates
  `/Applications/Enkstein.app` and launches a native Intel/Apple Silicon
  desktop window after installation.
- **Windows x64:** run `Enkstein-VERSION-windows-x64-setup.exe`; setup creates
  Start Menu and optional desktop shortcuts and launches `Enkstein.exe`.

Both launchers start Docker Desktop when necessary, generate unique local
secrets, and start the Enkstein services. The macOS app displays startup
progress, waits for the Cortex and UI health checks, and embeds the governed UI
inside its own WebKit window instead of opening the browser. Docker Desktop is
required. The launcher tries published images first; if they are unavailable,
the local build can take many minutes because the backend installs Prowler and
its dependency tree. Connector credentials are added afterward through the
Connectors UI and remain encrypted in persistent local volumes. See
[native installer details](docs/native-installers.md).

### Local owner authentication and background runtime

The first desktop launch requires creation of a local owner password and TOTP
enrollment with an RFC-compatible Authenticator application. Enkstein displays
the QR secret only during enrollment and returns ten one-time recovery codes.
Later owner sessions require both the password and current Authenticator code;
email-code viewer access remains optional after an Email/SMTP connector is
configured.

The operator console locks after 30 minutes without interaction. Locking,
closing, or quitting the console does not stop the Compose runtime: monitoring,
schedules, active Swarms, and policy-authorized Reflexes continue, while actions
that require human approval remain queued. On macOS, the menu-bar control can
reopen or lock the console. Authentication endpoints are under
`/api/v1/auth/owner/*`; TOTP secrets and recovery-code hashes are encrypted in
the persistent local secret volume.

### Prerequisites
- Desktop installers: Docker Desktop
- Portable bundle: Docker Desktop or Docker Engine with Docker Compose v2
- 4GB RAM available

### Run locally

```bash
cd enkstein
docker-compose up --build
```

Then open:
- **Frontend UI**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Health check**: http://localhost:8000/health

The Docker frontend runs as a production Next.js server. The image builds the UI with `npm run build`, starts it with `npm run start`, and proxies browser `/api/v1/*` calls to `http://backend:8000` inside Docker.

### First steps after launch

1. Open http://localhost:3000/dashboard
2. Go to **Connectors** → click any connector → enter your own API credentials
   - Credentials are encrypted at rest (Fernet AES-128) and never stored in plaintext
   - Each deployment auto-generates its own encryption key in `backend/.secrets/` (gitignored)
3. Go to **Policies** → review the policies seeded at startup and add or update
   policies as needed
4. Go to **AI Security** → submit a test prompt (try including an API key to test detection)
5. Watch the **Events** and **Audit** log populate
6. Go to **Identity Security** → check identity inventory

> **Security note:** Never commit `backend/.secrets/` — it contains your encryption key and stored credentials. This directory is gitignored by default. Each deployer gets their own isolated key.

### Connecting your own tools

Capability Nodes use real integrations only after their connector is configured and passes a read-only verification. Go to **Connectors** and add credentials for the tools you use:

| Category | Supported integrations |
|---|---|
| Cloud | AWS (Security Hub), Azure (Defender), GCP (Security Command Center) |
| Cloud posture | Prowler CLI (read-only AWS, Azure, GCP, Kubernetes, and GitHub checks) |
| Endpoint | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne |
| Identity | Okta, Microsoft Entra ID, AWS IAM |
| AI/LLM | Anthropic, OpenAI, Azure OpenAI, Ollama (local) |
| Code | GitHub (secret scanning, code review) |
| Log/SIEM | Splunk |
| Custom | Any REST API via Custom Capability |

Live control verdicts require eligible connector evidence. Some legacy Node
workflows still expose clearly labelled demonstration fallback for evaluation;
the Identity Incident Mission, connector control standing, and control verdicts
do not treat demonstration data as live evidence or a passing assessment.

Every finding records a **data origin** so the two are never confused once you connect a real
connector. Findings are labelled `live` (returned by an authenticated provider, with the source
connector named), `simulated` (locally generated demonstration data), or `unknown`. An adapter
that supplies no origin is recorded as `unknown` rather than `live`, so nothing can be presented
as verified estate data by omission. Filter with `GET /api/v1/findings?data_origin=live`, or use
the data-origin filter in the Findings console.

Prowler ships inside the backend image in its own virtual environment, so its dependency tree cannot collide with
the backend's pinned requirements. Register the Prowler Cloud Posture connector, choose a provider, and run
Cloud Security. Enkstein invokes Prowler without a shell, passes cloud secrets through the child environment rather
than command arguments, caps execution time and output, and labels results with a stable Prowler control ID. A
missing executable or failed run is reported honestly; demonstration findings are not substituted for a failed scan.

### Zero Trust control plane

Enkstein measures posture against a control catalog of 1,426 controls: 324 from the NIST SP 800-53 Rev 5 OSCAL
catalog, 1,038 from Prowler's AWS/Azure/GCP/Kubernetes/GitHub checks, and 64 authored for Capability Nodes.
Controls are grouped by CISA Zero Trust Maturity Model pillar and retain their source, version, automation state,
and remediation metadata.

Each Security Arm carries its own tailored profile rather than sharing one flat pool, so its coverage percentage is
measured against controls it can actually produce evidence for. A control passes only when a collector ran and
returned no violation: silence is never success, demonstration data never produces a verdict, and stale evidence
downgrades to NOT ASSESSED. Failing controls propose the remediation they declare through the governed remediation
engine, which keeps its own risk classification and approval gate.

See [Zero Trust controls](docs/zero-trust-controls.md) for the full API surface and verdict rules.

### Which Capability Nodes return live data

Seven nodes call a provider API when a connector is configured: **Cloud Posture** (AWS Security
Hub, Azure Defender for Cloud, GCP SCC), **Endpoint** (CrowdStrike, Defender, SentinelOne),
**Developer Security** (GitHub), **Identity** and **Privileged Access** (Entra ID, Okta),
**Security Telemetry** (Splunk), and **AI Governance**.

Some marketplace connectors are action targets or still require a provider-specific adapter.
Enkstein reports these as unavailable or `no_adapter`; it does not substitute a simulated estate
in production. Connector Health separates **configured**, **approved**, and **verified** so an
operator can see exactly what still needs setup.

### Connecting Microsoft without an app registration

Entra ID, Azure, Defender, and Sentinel connectors support **interactive sign-in** using the
OAuth device authorization grant. Enkstein shows a code, you approve it once on Microsoft's own
sign-in page, and Enkstein receives a refresh token — no app registration and no client secret.
Access tokens renew automatically so scheduled scans keep working.

This is a documented provider flow, not browser-session reuse: no cookies, page automation, or
vendor session tokens are involved, and you can revoke the grant from Microsoft's consent screen
at any time. Device sign-in passes the same Trust Fabric policy gate as manual credential entry.

GitHub device sign-in requires your own OAuth app; set `GITHUB_OAUTH_CLIENT_ID` to enable it.
Every other connector continues to use credential configuration, because `client_credentials`
with a scoped app registration is the correct posture for unattended scanning.

## Use it from your terminal & editor

### Guard your AI coding agent

The fastest way to try Enkstein. Blocks secrets and destructive commands **before**
Claude Code or Codex CLI runs them — no account, no backend, no Docker.

```bash
claude plugin marketplace add wcoreiron-rgb/enkstein
claude plugin install enkstein-guard@enkstein
```

For Codex, use `codex plugin marketplace add` and `codex plugin add` with the same names.

An AWS key headed for a config file, a `curl … | sh`, an `rm -rf /`, a `--force`
push, a read of `~/.aws/credentials` — the tool call never executes, and the agent
is told why so it corrects itself:

```text
Enkstein blocked this action.
AWS access key (line 1): AKIA3Z…OPAS
Rule: secret.aws_access_key (standalone policy)
```

It stays quiet about things that only look dangerous: `rm -rf ./build`,
`git push --force-with-lease`, and placeholder credentials in an `.env.example`
all pass without comment.

It governs what you type, too. A credential pasted into chat is out of your
control the moment the turn is sent, so Guard scans the prompt itself and stops
the message before it leaves your machine.

Runs fully local by default with 30 tuned public rules. Your private 60-policy
pack stays outside Git and currently contributes 228 local detections. Set
`ENKSTEIN_API_URL` and Guard also evaluates all 270 active CoreOS policies,
across every scope, preserving priority and first-match behavior. Raw prompts,
source, commands, paths, and working directories never enter that request;
Trust Fabric receives only classifications, policy IDs, lengths, and digests.
The tiers combine strictest-wins, so connecting can only add enforcement.
→ [plugin docs](plugins/enkstein-guard/README.md)

### Server-backed tools

The forms below talk to your running Enkstein server, so the **Trust Fabric governs every call** — policy, risk scoring, and audit apply server-side.

### MCP integration

Let the AI agent in your editor call governed security tools — scan code for secrets, check posture, launch investigations.

```bash
pip install ./enkstein_mcp-0.8.3-py3-none-any.whl
```

Add to `~/.cursor/mcp.json` (or your Claude Desktop / VS Code MCP config):

```json
{
  "mcpServers": {
    "enkstein": {
      "command": "enkstein-mcp",
      "env": { "ENKSTEIN_API_URL": "http://localhost:8000" }
    }
  }
}
```

Restart Cursor, then just ask:

> *"Scan the file I have open for hardcoded secrets."*
> *"What's my current security posture?"*
> *"Investigate suspicious identity activity for user@corp.com."*

Tools exposed: `scan_text_for_secrets` · `get_security_posture` · `list_findings` · `list_connectors` · `run_swarm_investigation` · `terraclaw_generate_secure_terraform` · `terraclaw_review_hcl` · `terraclaw_analyze_plan`. → [full MCP docs](mcp-server/README.md)

### CLI

```bash
pip install ./enkstein_cli-0.8.3-py3-none-any.whl
export ENKSTEIN_API_URL=http://localhost:8000
enkstein status dashboard
enkstein connectors test okta
enkstein evidence collect --framework soc2
```
→ [full CLI docs](cli/README.md)

### Python governance library

Drop Enkstein's enforcement primitives into your own scripts, agents, or pre-commit hooks — runs in-process, only depends on `cryptography`.

```bash
pip install ./enkstein_core-0.8.3-py3-none-any.whl
```
```python
from enkstein_core import classify_ring, evaluate_ring, scan_text, verify_package
```
→ [full core docs](enkstein-core/README.md)

## API Reference

With Enkstein running, the generated OpenAPI documentation is available at
[http://localhost:8000/docs](http://localhost:8000/docs). It is the
authoritative method, path, and schema reference for the installed version.

Operational guidance lives in the [documentation site](docs/docs.html), the
[Runtime Reference](docs/runtime-reference.md), and the
[agent workflow guide](docs/agent-workflow.md).

## Release History

Enkstein ships versioned macOS packages and self-hosted bundles. The
authoritative, per-release record of what changed — including the root cause
behind each fix — lives in two places:

- [Changelog](docs/changelog.html) — every released version, newest first.
- [GitHub Releases](https://github.com/wcoreiron-rgb/enkstein/releases) — downloadable installers and `SHA256SUMS`.

For where the platform is strong versus still maturing, see the
[Maturity Matrix](docs/maturity-matrix.md) and the *Known gaps* section of the
[Testing Guide](docs/testing-guide.md).

## Platform Map

- **Chat and Cowork:** governed conversation, project context, file proposals,
  local execution, and Multi-Brain routing.
- **Security:** 26 capability areas for identity, cloud, endpoint, application,
  data, network, threat, compliance, and AI security workflows.
- **Control surfaces:** Trust Fabric, Model Cortex, approvals, remediation,
  Swarm orchestration, connector health, and audit records.

See the [documentation site](docs/docs.html) for the module catalog and API
details, and the [Maturity Matrix](docs/maturity-matrix.md) for current assurance
and known limitations.

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
