# Enkstein Plexus Architecture

Status: Runtime contract 0.2.0  
Working name: Enkstein
Lineage: Independent compatibility-first evolution of Enkstein

## Thesis

Enkstein is an octopus-inspired distributed security architecture. It combines a strategic Cortex with stable Security Arms and specialized Capability Nodes. Nodes may resolve delegated routine work locally or collaborate directly, but Trust Fabric remains mandatory for every message and action.

> The Cortex may be bypassed for delegated routine coordination. Trust Fabric may never be bypassed.

The biological language is an organizing model, not a claim that software reproduces octopus biology.

## Architecture

```text
Operator / Event / Schedule / Channel
                  |
             Enkstein Cortex
       command | plan | arbitrate | judge
                  |
      +-----------+-----------+
      |           |           |
 Trust Heart  Memory Heart  Runtime Heart
      |           |           |
      +-----------+-----------+
                  |
            Trust Fabric
                  |
       +----------+----------+
       |   Security Arms     |
       |  + Capability Nodes |
       +----------+----------+
                  |
      Skills + Connectors + Reflexes
                  |
          External environments

Capability Node <---- governed Plexus ----> Capability Node
       |                                      |
       +------- checkpoint / Regeneration ----+
```

Trust Fabric is body-wide. It is not merely a Cortex component. The Cortex can plan and arbitrate, but it cannot grant itself or another component an exception from identity, tenant, policy, approval, audit, or containment controls.

## Vocabulary

| Term | Meaning |
|---|---|
| Cortex | Strategy, command normalization, planning, arbitration, and governed model reasoning |
| Three Hearts | Independent trust, memory, and runtime control planes |
| Security Arm | Stable cybersecurity pillar with bounded responsibility |
| Capability Node | Specialized governed capability attached to one Security Arm |
| Skill | Versioned behavior a Node can invoke within declared authority |
| Connector | Scoped external interface used by a Node to sense or act |
| Reflex | Event-driven, low-risk local action within a pre-authorized envelope |
| Plexus | Tenant-isolated peer communication between Nodes |
| Regeneration | Verified restoration of a Node from signed configuration and governed state |

The circular elements along each visual Arm represent Capability Nodes. They may visually reference an octopus arm without being called "suckers" in product language.

## Cortex

The Cortex owns system-level intent and arbitration, not every operational decision.

### Cortex Gateway

`POST /api/v1/modelclaw/gateway` is the common reasoning boundary for the
Enkstein Chat and Cowork workspaces and for Swarm Judge synthesis. Its request
contract carries the work mode, conversation, Brain source, data classification,
tenant, capability, and optional workspace context. Before inference it:

1. treats the conversation and attached text as untrusted input;
2. performs DLP redaction and prompt-injection auditing;
3. obtains a Trust Fabric decision independently for each candidate Brain;
4. prevents restricted or top-secret data from reaching subscription Brains;
5. records model-call outcome metadata without logging raw prompts; and
6. scans provider output before returning it to the workspace.

Automatic routing is mode- and runtime-group-aware. Local retains only approved
local profiles, Hybrid stable-partitions local profiles before CLI/API
fallbacks, and Cloud excludes local, desktop, and browser sources. Restricted
and top-secret work remains pinned to the approved local profile before group
selection. Every result records the
candidate order, attempted sources, selected source, and routing reason.
Consensus mode invokes multiple independently governed sources and reports vote
availability, confidence, and agreement.

`POST /api/v1/modelclaw/task-graph` extends the same Gateway with an explicit
acyclic execution contract rather than a model group chat. A graph can assign
router, context-worker, planner, coder, researcher, security-reviewer,
test-reviewer, reviewer, and final-judge work. Trust Fabric governs graph
admission, each peer-evidence handoff, and each Gateway provider attempt.
Dependencies execute in layers with at most three concurrent specialists; each
parallel node uses an isolated database session. A supplied Project id is
resolved server-side and checked against the authenticated tenant and owner.
Requester subject/role, orchestrator, specialist, validated Project,
classification, and dependency evidence ids accompany Trust Fabric and model
call audit records. Ordered fallbacks, timeouts, blocked dependencies, evidence
identifiers, route and fallback reasons, provider/model, policy, and latency are
normalized in the result. Caller cancellation stops local waiting; the graph
does not claim provider-side cancellation propagation.
Persisted operator role presets and automatic risk-driven graph construction
remain planned.

Brain readiness discovery is itself a Trust Fabric action. The host bridge uses
official Codex and Claude authentication status commands; an installed binary
alone is never ready. Explicit refresh and console focus bypass the bounded
negative cache. Host prompts use stdin with read-only/tool-disabled execution.

Native Cowork can additionally use the official Codex App Server as a
long-lived root-bound agent transport. Scope is derived server-side from the
tenant, owner, Project, conversation, and opaque native-folder grant. The
browser never receives raw paths, thread ids, or grant tokens. Only bounded
allowlisted stream events are retained transiently. Agent deltas, plans, diffs,
approval commands/reasons, and other free text are DLP-scanned,
secret-redacted, checked as untrusted output, and stripped of absolute native
paths before reaching the client; only aggregate scan metadata is returned.
Command/file approvals are one-shot and general permission requests are
deny-only. Effective restricted/top-secret Projects deny start, turn, status,
approval, and cancel bridge invocations.

Chat, Cowork, and Security are separate mounted workspaces synchronized through
URL history and remembered mode. Chat does not load Project state. Cowork
requires a selected tenant-owned Project before project conversations, files,
artifacts, proposals, or native-folder controls are active. Runtime-group choice
is sent with each turn, but 0.5.9 does not persist it per conversation/Project
because no compatible database field exists and no migration was authorized.

Cowork persists a content-free per-turn file-result ledger alongside its
existing context provenance. Each entry records only a project-relative path,
the requested create/update/delete operation, and its final `applied`,
`proposed`, `skipped`, or `blocked` outcome. The web console renders it as an
expandable **Files changed** section after the response, so it is available on
both live and reopened conversations without exposing generated file content in
governance metadata.

Encrypted tenant-scoped Projects hold persistent Chat/Cowork conversations and
versioned text artifacts. Folder access is explicit. In the desktop shell, the
operator grants a local folder and the native bridge stores its path behind an
opaque grant token. The container can list, create, edit, rename, move, and send
bounded text files to `.marcellus-trash`, but never receives the host path.
Symlink traversal, protected directories, oversized files, unsupported file
types, and cross-project access are rejected. Browser Cowork imports a bounded
copy instead. Active project files remain bounded Cowork context by default;
every mutation is tenant-scoped and Trust Fabric authorized. Conversation
branches preserve provenance. A Cortex conversation can be
handed to Security as a real approval-gated Swarm job; the handoff stores only
the tenant-bound source reference and digest. The dispatcher decrypts and
redacts bounded context in memory when the Security tasks execute.

The legacy Arc tool agent still uses its specialized provider/tool loop. It is
already protected by DLP and Trust Fabric, but is not yet implemented through
the Cortex Gateway because the subscription bridge intentionally runs without
host tools. This is a compatibility boundary, not a policy bypass.

| Component | Current foundation | Responsibility |
|---|---|---|
| CoreOS | CoreOS, workflows, schedules, triggers | Platform state and coordination |
| Command Cortex | Command, channels, remote control | Normalize and authorize operator intent |
| Coordination Cortex | Swarm planner, dispatcher, Judge | Plan multi-node work and reconcile results |
| Model Cortex | Model Cortex and model router | Govern model selection and reasoning support |

## Three Hearts

### Trust Heart

Identity, Trust Fabric, policy, ring authority, approvals, containment, and kill switches. A Trust Heart failure causes sensitive operations to fail closed.

### Memory Heart

Governed memory, evidence, audit, finding provenance, and compliance mappings. Memory is never treated as trusted merely because it was written by another Node.

### Runtime Heart

SRE policy, schedules, queues, execution channels, remote-agent health, model budgets, connector health, and recovery coordination.

## Security Arms and Capability Nodes

| Security Arm | Capability Nodes | Legacy modules |
|---|---|---|
| Threat Intelligence and Exposure | Threat Analysis, Threat Intelligence, Exposure Management, Attack Path Analysis, Security Telemetry | ThreatClaw, IntelClaw, ExposureClaw, AttackPathClaw, LogClaw |
| Identity and Human Risk | Identity Security, Privileged Access, User Risk, Insider Risk | IdentityClaw, AccessClaw, UserClaw, InsiderClaw |
| Cloud and Infrastructure | Cloud Security, Configuration Security, Terraform Governance | CloudClaw, ConfigClaw, TerraClaw |
| Network and Endpoint | Network Security, Endpoint Security | NetClaw, EndpointClaw |
| Application and Software Delivery | Application Security, Developer Security, Release Governance | AppClaw, DevClaw, ReleaseClaw |
| Data, Privacy, and SaaS | Data Security, Privacy Governance, SaaS Security | DataClaw, PrivacyClaw, SaaSClaw |
| Governance, Risk, and Resilience | Compliance Assurance, Vendor Risk, Recovery Readiness | ComplianceClaw, VendorClaw, RecoveryClaw |
| AI and Autonomous Operations | AI Security, Security Automation, Custom Capability | ArcClaw, AutomationClaw, CustomClaw |

Every Capability Node has one owning Arm, a focused task contract, an authority ceiling, and an explicit implementation status. Skills and Connectors cannot silently expand that authority.

## Reflexes

A Reflex is a local action triggered by an event rather than a central plan. The shipped runtime includes:

- tenant and owner
- typed event fields and operators
- Node authority ceilings
- expiry, cooldown, and hourly execution budgets
- encrypted event persistence and event idempotency
- Trust Fabric and Ring Policy decisions
- independent approval for approval-gated actions
- generic error responses without event-body logging

Every Reflex passes through Trust Fabric before side effects. Anything outside the envelope escalates to the Cortex or human approval.

## Plexus

The Plexus is direct Node-to-Node communication. The shipped mailbox transport provides:

- platform Ed25519 envelope signatures
- encrypted payload storage and tenant binding
- message ID, trace ID, TTL, and replay protection
- declared purpose and requested capability
- data classification and redaction state
- Trust Fabric policy outcome and risk score
- recipient acknowledgement with signature and digest verification
- participant-only decrypted payload reads
- independent approval for held messages

Peer messages may share evidence or request work. They may not grant privileges. The current signer is platform-managed; per-Node managed keys and remote transports remain a hardening target.

## Regeneration

Regeneration restores a failed or contained Node through this sequence:

```text
contain -> checkpoint -> recreate -> verify -> rehydrate -> rejoin
```

Only signed manifests and governed state are restored. Checkpoints containing credential-like fields are rejected and credentials are never copied. The recovered logical Node runtime remains quarantined until signature, digest, identity, state-integrity, and tenant-binding checks pass.

The current implementation restores a persisted logical Capability Node runtime. Recreating a process, container, or remote worker requires a future Runtime Heart adapter, so Regeneration remains marked `partial`.

## Persistent Missions and governed Memory

A Mission is a long-lived security objective owned by one tenant and operator.
It is not a free-running remediation agent. Each run creates a bounded-parallel
Swarm with a fixed `read`, `analyze`, and `recommend` action envelope. Trust
Fabric evaluates Mission creation, updates, launches, memory proposals, and
memory review decisions.

Supported cadences are `manual`, `hourly`, `every_6h`, `daily`, and `weekly`.
The background scheduler claims at most ten due Missions per cycle and advances
their next-run time even when policy blocks execution. A failed scheduler cycle
does not expose Mission payloads in logs.

Mission objectives, observation summaries, and generated overnight briefs are
encrypted at rest. Swarm jobs persist only an authenticated Mission reference
and objective digest; the dispatcher resolves and redacts the objective in
memory after tenant and integrity validation. A completed run creates a reviewable observation only after
sensitive-data scanning, prompt-injection auditing, and a Trust Fabric decision.
`proposed` observations are excluded from runtime context. Only `approved`
observations from the same tenant and Mission can be loaded by participating
Capability Nodes. Operators can reject proposals without deleting their audit
history.

The overnight brief is an encrypted point-in-time report containing:

- active Missions and their next run
- material approved or proposed changes
- pending memory decisions
- currently running Arms
- policy/result metadata for recent Reflexes
- blocked or failed Mission activity
- Security Twin health derived from approved observations

The brief deliberately excludes decrypted Reflex event bodies. It is an
operator summary, not an independent compliance attestation.

### Mission API

```text
POST  /api/v1/marcellus/missions
GET   /api/v1/marcellus/missions
PATCH /api/v1/marcellus/missions/{mission_id}
POST  /api/v1/marcellus/missions/{mission_id}/run
GET   /api/v1/marcellus/missions/memory/observations
POST  /api/v1/marcellus/missions/memory/observations/{observation_id}/review
POST  /api/v1/marcellus/missions/overnight-brief
```

Non-administrative users see only their own Missions and observations. Tenant
claims remain authoritative. Approval identity is derived from the authenticated
session and Mission memory cannot self-approve.

## Migration Rules

1. Enkstein remains untouched as the stable source repository.
2. Enkstein evolves in a separate Git repository with push access to Enkstein disabled.
3. Existing route prefixes and module names remain available during compatibility migration.
4. Public terminology changes before physical package and database names.
5. New runtime behavior must be real and tested before its status changes from `contract_only` or `partial`.
6. No mass rename may alter migrations, external contracts, or evidence lineage without a versioned compatibility plan.

## Discovery API

The architecture is machine-readable:

```text
GET /api/v1/marcellus/architecture
GET /api/v1/marcellus/arms
GET /api/v1/marcellus/nodes
GET /api/v1/marcellus/nodes?arm_id=cloud_infrastructure
GET /api/v1/marcellus/nodes/{node_id}
```

These endpoints describe current mappings and implementation maturity. They do not imply that peer autonomy or Regeneration is already complete.

## Runtime API

### Plexus

```text
POST /api/v1/marcellus/plexus/messages
GET  /api/v1/marcellus/plexus/messages
GET  /api/v1/marcellus/plexus/inbox/{node_id}
GET  /api/v1/marcellus/plexus/messages/{message_id}
POST /api/v1/marcellus/plexus/messages/{message_id}/approve
POST /api/v1/marcellus/plexus/messages/{message_id}/ack
```

### Reflexes

```text
POST /api/v1/marcellus/reflexes
GET  /api/v1/marcellus/reflexes
POST /api/v1/marcellus/reflexes/evaluate
GET  /api/v1/marcellus/reflexes/executions
POST /api/v1/marcellus/reflexes/executions/{execution_id}/approve
```

### Regeneration

```text
POST /api/v1/marcellus/regeneration/checkpoints
GET  /api/v1/marcellus/regeneration/checkpoints
POST /api/v1/marcellus/regeneration/checkpoints/{checkpoint_id}/verify
POST /api/v1/marcellus/regeneration/runs
GET  /api/v1/marcellus/regeneration/runs
POST /api/v1/marcellus/regeneration/runs/{run_id}/approve
GET  /api/v1/marcellus/regeneration/runtimes
```

All routes require authentication outside debug mode. Tenant claims are authoritative, decrypted peer payloads are limited to message participants and security administrators, and high-impact approvals reject self-approval. Approval execution uses atomic status claims so only one operator can consume a held action. Runtime ciphertext uses `MARCELLUS_DATA_ENCRYPTION_KEY` when configured; local preview mode otherwise creates an owner-only key under `backend/.secrets/`.

The models are registered with SQLAlchemy development `create_all`. A versioned production migration is intentionally still required before production deployment.
