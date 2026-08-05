# Enkstein Runtime Reference

Detailed behavior of the Enkstein runtime: Plexus, Reflexes, Regeneration,
Missions, the governed AI workspace, Brain runtime groups, and Brain Bridges.

For an overview of what Enkstein is and how to install it, see the
[README](../README.md). For the architectural model, see
[Enkstein Architecture](marcellus-architecture.md).

---

## Distributed Runtime

Enkstein `0.7.10` provides three governed runtime paths on top of the compatibility platform:

| Layer | Shipped behavior | Maturity |
|---|---|---|
| **Plexus** | Tenant-scoped peer mailboxes, Fernet-encrypted payloads, Ed25519-signed envelopes, TTL, idempotency, acknowledgements, and Trust Fabric decisions | Shipped |
| **Reflexes** | Typed conditions, owner/tenant binding, authority ceilings, cooldowns, hourly budgets, Trust Fabric and Ring Policy evaluation, and independent approval for action Reflexes | Shipped |
| **Regeneration** | Signed encrypted checkpoints, manifest/state verification, secret rejection, quarantine, six-stage restoration, health verification, and approval-gated rejoin | Partial |

The Regeneration implementation recreates the persisted logical Capability Node runtime. A host, process, container, or remote worker adapter is still required before it can replace an external runtime instance.

The operator console is available at [`/marcellus`](http://localhost:3000/marcellus). Runtime endpoints are under `/api/v1/marcellus/plexus`, `/api/v1/marcellus/reflexes`, and `/api/v1/marcellus/regeneration`. See [Enkstein Plexus Architecture](docs/marcellus-architecture.md) for endpoint and security details.

### Persistent Missions and governed Memory

Security mode now opens with **Mission Control**, where an operator can create,
pause, resume, and run persistent security Missions. Each Mission launches the
existing bounded-parallel Swarm runtime on a manual, hourly, six-hour, daily,
or weekly cadence. Mission tasks have a fixed `read`, `analyze`, and `recommend`
authority ceiling; they cannot silently gain remediation privileges.

Mission objectives, observations, and overnight briefs are encrypted at rest;
Swarm records hold only a tenant-bound Mission reference and integrity digest.
Completed runs produce tenant-scoped memory proposals that are scanned for
sensitive content and prompt-injection risk, evaluated by Trust Fabric, and
held for an independent approve/reject decision. Only approved observations are
loaded into later tasks for that same tenant and Mission. The 12-hour overnight
brief summarizes active Missions, material changes, decisions needed, running
Arms, recent Reflex metadata, blocked activity, and Security Twin health without
copying raw Reflex event bodies into the report.

The API is under `/api/v1/marcellus/missions`; see
[Enkstein Architecture](docs/marcellus-architecture.md#persistent-missions-and-governed-memory)
for the route list and current limitations.

### Governed AI workspace

The `/marcellus` console now presents three first-class work modes:

- **Chat** for general governed conversation.
- **Cowork** for file-assisted planning, analysis, writing, and review.
- **Security** for the Cortex, Three Hearts, Arms, Plexus, Reflex, and Regeneration controls.

Chat and Cowork call `POST /api/v1/modelclaw/gateway`. The Cortex Gateway scans
the complete conversation, redacts detected sensitive values, audits prompt
injection risk, obtains a Trust Fabric decision for each Brain, invokes only an
allowed source, scans the output, and writes model-call audit metadata. Users
can select automatic routing, Codex or Claude subscription bridges, a configured
NVIDIA NIM or Gemini API profile, a local Brain, or multi-Brain consensus. Auto
routing is mode-aware, records its candidate order and selection reason, and
falls through only to a policy-approved available Brain. `restricted` and
`top_secret` automatic requests are forced to the local profile.

Model Cortex hardens the profile, audit, direct
Brain, consensus, and compatibility model routes are tenant-bound; profile
mutation requires an operator identity; and Multi-Brain calls use bounded
per-tenant/per-source concurrency with safe timeouts.

Version `0.7.10` keeps a paired Browser Companion marked ready while it is
submitting, streaming, or completing a long provider turn, and routes workspace
SSE through a dedicated streaming proxy rather than the generic API rewrite.
This prevents an active signed-in ChatGPT, Claude, or Gemini tab from being
reported as disconnected or a healthy multi-minute response from being marked
stalled merely because it is busy producing an answer.

For Cowork implementation requests, every answering Brain is an advisor, not a
filesystem authority. When Browser Companion, Hybrid-local, or other supported
profile output returns an architecture or ordinary code answer without a safe
project-relative manifest, Enkstein sends a bounded copy to its dedicated local
Qwen file author. The author receives its own output budget and can recover
complete file entries even if its final JSON fence is cut off. Trust Fabric then
governs proposal or Auto-apply writes into the operator-selected project root.
A planning response is never represented as local execution.

Security Arm pages also include an **AI analysis and remediation plan** after
the deterministic assessment. It summarizes failing controls and findings,
groups likely root causes, and orders advisory remediation steps with control
IDs and evidence counts. The panel can report a clean assessment or an
unavailable Brain honestly; it cannot change a verdict, score, or remediation
gate. The same advisory surface is available from Zero Trust control coverage.

The console has three persisted themes: **Dark**, **Light**, and **Liquid
Glass**. Liquid Glass uses neutral clear-glass surfaces and slate accents, and
ships with a matching clear-glass Enkstein icon for the portal and Browser
Companion.

Browser Brain handoffs are capped to a compact, continuity-preserving context
instead of replaying an entire conversation into a provider message editor.
Cowork accepts the strict Enkstein manifest as well as the safe equivalent JSON
forms emitted by local models (for example `type`/`file_path`), then applies the
same tenant-scoped path validation, Trust Fabric decision, and approved-folder
write boundary before any local file changes.

The Chat, Cowork, and Security workspaces are separate mounted state
containers. Their URL hash, browser history, and remembered mode stay aligned;
Chat never loads project state, while Cowork scopes conversations and encrypted
artifacts to the selected tenant-owned Project. Conversation create, open,
rename, archive, and project move operations update immediately.

Assistant responses in Chat and Cowork render as safe GitHub-flavored Markdown —
headings, paragraphs, lists, tables, links (opened with `rel="noopener noreferrer"`),
inline code, blockquotes, and citations — with raw HTML never enabled and dangerous
URL protocols stripped. Fenced code blocks show a language label, light/dark styling,
exact whitespace with horizontal scrolling for long PowerShell/Python/Terraform, and
an accessible Copy button. Change proposals, Codex approvals, and terminal
failed/timeout/interrupted turns render as compact operational blocks rather than raw
JSON; a terminal turn offers **Retry** (replays the preserved message as a fresh turn,
which is safe because a failed turn rolls back server-side) and **Continue** (returns
the message to the composer), preserving the draft and conversation without duplicate
submission. Each assistant reply carries a compact provenance record —
source/provider/model, runtime group, policy outcome, latency, confidence,
input/output redaction, and fallback reason.
For Cowork turns that propose, apply, skip, or block local project changes, that
same durable record now includes an expandable **Files changed** ledger with
the relative path, create/update/delete operation, and final outcome. The
ledger is content-free, survives reopening the conversation, and never turns a
planning response into claimed execution.

### Brain runtime groups

Chat, Cowork, Security, and Model Cortex consensus expose three governed groups:

- **Local** permits only the approved Ollama/local-profile boundary and fails
  closed when no capable local model is ready.
- **Hybrid** tries approved local Brains first, then policy-approved CLI/API
  sources in ordered fallback sequence.
- **Cloud** permits approved subscription CLI/API sources and never adds a
  desktop or browser session implicitly.

`restricted` and `top_secret` adaptive requests are pinned to Local before the
selected group is evaluated. Trust Fabric evaluates Brain readiness discovery
and every attempted source. Failed, unavailable, and policy-denied votes remain
visible but never count toward consensus.

Runtime-group selection is currently carried on every request and remembered
locally by the console. It is **not yet persisted per conversation or Project**:
the existing database schema has no compatible field and this release was not
authorized to add a migration. Tenant-owned role-route configuration for
persisted operator presets remains planned. `POST /api/v1/modelclaw/task-graph`
now executes an explicit acyclic graph of bounded specialist roles through the
existing Cortex Gateway. It validates any supplied Project against the resolved
tenant and requester, applies Trust Fabric to graph admission, peer evidence,
and every ordered provider fallback, and uses isolated database sessions for at
most three parallel nodes. Timeouts and dependency skipping are bounded; caller
cancellation stops local waiting, but provider-side cancellation is not claimed.
Results record actual provider attempts plus model, policy, latency, requester,
specialist, workspace, and dependency-evidence attribution.

For Chat/Cowork turns and native Codex operations, effective classification is
the highest of the request, conversation, Project, and every included active
artifact. The covered runtime paths deny external Brains for `restricted` and
`top_secret` data and fail closed when no approved local Brain is available.
This is a tested application-layer boundary for those paths, not a blanket
certification of every legacy connector or data flow in the compatibility
platform.

Chat and Cowork now persist encrypted, tenant-scoped conversation history.
Cowork adds named Projects, encrypted versioned text artifacts, searchable
history, persistent project-file context, conversation organization, and a
real desktop folder bridge. A macOS operator can explicitly grant one local
folder to a project; Enkstein receives an opaque grant, synchronizes bounded
text files, and can create, edit, rename, move, or recoverably trash files in
that folder. Browser Cowork retains an import-copy fallback. Raw host paths are
never exposed to the container or web UI. Content is path-bounded, DLP-scanned,
treated as untrusted context, and every mutation is tenant-scoped and authorized
through Trust Fabric. The
**Investigate** action creates an approval-gated Security
Swarm from an encrypted conversation reference and digest. Bounded context is
decrypted and redacted only in memory when Security tasks execute.

The Swarm Judge uses the same gateway with `swarm_judge_profile`. Existing Arc
tool sessions retain their specialized tool adapter and their established DLP
and Trust Fabric checks; migrating tool-session execution into the shared
gateway is tracked separately so tool capability is not silently reduced.

### Governed Brain Bridges and consensus

Enkstein `0.2.15` can use supported model runtimes already authenticated on
the desktop without copying subscription tokens into Docker:

- **Codex Subscription Bridge:** detects the official Codex runtime, verifies
  that it is authenticated with ChatGPT, and runs ephemeral, read-only,
  reasoning-only invocations. Desktop Cowork Agent tools instead use one
  resumable official `codex app-server` thread per governed project/conversation
  scope, with streamed events, one-shot command/file approvals, deny-only
  permission expansion, cancellation, and interrupted-session recovery.
- **Claude Agent SDK Bridge:** detects an authenticated Claude Code/Agent SDK
  host runtime and invokes it with tools disabled. It remains unavailable until
  the official host runtime is installed and authenticated.
- **Desktop Session Bridge:** can use a compatible visible ChatGPT or Claude
  macOS app after explicit Accessibility permission and a live message-field
  compatibility check. Incompatible vendor builds fail closed.
- **Browser Session Bridge:** pairs the narrowly scoped Enkstein Browser
  Companion with visible signed-in ChatGPT, Claude, or Gemini tabs. It never
  reads cookies or account tokens and is selected explicitly rather than by
  silent automatic routing. Tenant-scoped conversation affinity reuses one
  provider tab per Enkstein chat instead of creating a new thread per turn.
- **Brain Consensus:** consults selected subscription, approved API, and local
  model profiles concurrently. Unavailable, policy-denied, failed, and
  simulated responses never count as votes.

The Browser Companion ships inside the macOS and Windows packages. Press
**Download companion** in Brain Connections to get it as a zip, unzip it, then
load it in Chrome or Edge through Extensions → Developer mode → Load unpacked,
and press **Pair browser**. The download works from any browser that can reach
the console, including one on a different machine from the runtime.

Every invocation is evaluated by Trust Fabric, tenant/profile constraints are
rechecked, model output is rescanned and redacted, and call provenance is
written to the Model Cortex audit. The host bridge uses a random per-install
secret, accepts only local/private peers, and never returns vendor credentials.
It deliberately exposes no unrestricted terminal or tool execution path.

Endpoints include `GET /api/v1/modelclaw/brains/status`, `POST
/api/v1/modelclaw/brains/invoke`, `POST /api/v1/modelclaw/consensus`, and the
authenticated desktop/browser setup routes under `/api/v1/modelclaw/brains/`. See
[Brain Bridges](docs/brain-bridges.md) for setup, trust boundaries, and vendor
account limitations.

<p align="center">
  <a href="https://wcoreiron-rgb.github.io/enkstein/">
    <img src="https://img.shields.io/badge/Documentation-1f2937?style=for-the-badge&logo=gitbook&logoColor=white" alt="Documentation" />
  </a>
  <a href="https://wcoreiron-rgb.github.io/enkstein/docs.html">
    <img src="https://img.shields.io/badge/Technical%20Docs-2563eb?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Technical Docs" />
  </a>
  <a href="http://localhost:3000">
    <img src="https://img.shields.io/badge/Dashboard%20(local)-0f766e?style=for-the-badge&logo=vercel&logoColor=white" alt="Dashboard (local)" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/wcoreiron-rgb/enkstein/projects">
    <img src="https://img.shields.io/badge/Roadmap%202026-7c3aed?style=for-the-badge&logo=githubprojects&logoColor=white" alt="Roadmap 2026" />
  </a>
  <a href="https://github.com/wcoreiron-rgb/enkstein/issues/new?labels=bug&title=%5BBug%5D+">
    <img src="https://img.shields.io/badge/Report%20Bug-dc2626?style=for-the-badge&logo=github&logoColor=white" alt="Report Bug" />
  </a>
  <a href="https://github.com/wcoreiron-rgb/enkstein/issues/new?labels=enhancement&title=%5BFeature%5D+">
    <img src="https://img.shields.io/badge/Request%20Feature-2563eb?style=for-the-badge&logo=github&logoColor=white" alt="Request Feature" />
  </a>
  <a href="https://github.com/wcoreiron-rgb/enkstein/discussions">
    <img src="https://img.shields.io/badge/GitHub%20Discussions-0f766e?style=for-the-badge&logo=github&logoColor=white" alt="GitHub Discussions" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/wcoreiron-rgb/enkstein/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/wcoreiron-rgb/enkstein/ci.yml?branch=main&label=Build%20and%20Test%20(Unit%20%2B%20E2E)" alt="Build and Test (Unit + E2E)" />
  </a>
  <a href="https://codecov.io/gh/wcoreiron-rgb/enkstein">
    <img src="https://img.shields.io/codecov/c/github/wcoreiron-rgb/enkstein?label=codecov" alt="codecov" />
  </a>
</p>

<p align="center"><strong>Full Documentation</strong></p>
<p align="center">
  <a href="https://wcoreiron-rgb.github.io/enkstein/">
    <img src="https://img.shields.io/badge/Quick%20Start-f59e0b?style=for-the-badge&logo=rocket&logoColor=white" alt="Quick Start" />
  </a>
  <a href="https://wcoreiron-rgb.github.io/enkstein/docs.html#architecture">
    <img src="https://img.shields.io/badge/Specifications-0891b2?style=for-the-badge&logo=bookstack&logoColor=white" alt="Specifications" />
  </a>
  <a href="https://wcoreiron-rgb.github.io/enkstein/changelog.html">
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
