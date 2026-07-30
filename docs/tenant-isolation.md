# Enkstein Tenant Isolation

Enkstein scopes user-facing security records by a tenant claim in the signed
access token. A tenant-bound caller can only list, retrieve, stream, mutate, or
use credentials for its own records. An unscoped administrator may view legacy
records created before tenant ownership existed.

## Enforced Records

| Record | Tenant anchor | Enforced paths |
|---|---|---|
| Findings | `findings.tenant_id` | list, statistics, create, update |
| Audit logs | `audit_logs.tenant_id` | list |
| Connectors | `connectors.tenant_id` | list, health, get, configure, test, device/browser auth, credential removal |
| Credentials | encrypted store sidecar binding | store, get, delete |
| Incidents | `incident_memory.tenant_id` | list, detail, update, timeline, close, proposal review, rollback |
| Assets | `asset_memory.tenant_id` | list, get, upsert |
| Swarm jobs | `swarm_jobs.tenant_id` | create, presets, list, detail, tasks, SSE stream, cancel, approve |
| Remediation actions | `remediation_actions.tenant_id` | list, detail, approve, reject, rollback, trigger, stats |
| Schedules | `schedules.tenant_id` | list, create, detail, patch, delete, run, run-swarm, run history |
| Event triggers | `event_triggers.tenant_id` | list, create, detail, patch, delete, test, stats, webhook dispatch |
| Agent runs | `agent_runs.tenant_id` | schedule run history |
| Agents | `agents.tenant_id` | Control Center counts, remote dispatch |
| Events | `events.tenant_id` | Trust Fabric enforcement records, Control Center counts |
| Tenant memory | `tenant_memory.tenant_id` | posture summary, refresh, notes, trends, snapshots |
| Risk snapshots | `risk_trend_snapshots.tenant_id` | trend charts, manual snapshots |
| Channel messages | `channel_messages.tenant_id` | list, detail, stats, Control Center counts |
| Channel identities | `channel_identities.tenant_id` | list, upsert |
| Channel configs | `channel_configs.tenant_id` | list, create, patch, outbound webhook delivery |
| Execution requests | `exec_requests.tenant_id` | list, detail, approve, reject, execute, stats, Control Center counts |
| Credential broker | `credential_broker.tenant_id` | list, register, patch, delete, rotate, rotation due, credential channel |
| Production gates | `production_gates.tenant_id` | list, detail, approve, reject, execute, rollback |

Migrations `0005` through `0011` add the columns, indexes, and constraints.
Existing rows are deliberately left unowned: they remain available only to an
unscoped administrator. Enkstein does not infer ownership from free-text actor
names because a wrong backfill would be a data leak.

`0005` resolves the `asset_memory.asset_id` uniqueness by inspection rather
than by a hard-coded constraint name, because deployments express it either as
a unique constraint or a unique index. `0009` gives `tenant_memory.id` a
sequence: it was previously a single-row table pinned to `id=1`, so every
tenant shared one posture summary.

`0011` uses the same inspection approach to replace global uniqueness on
`channel_configs.channel_id` and `credential_broker.name` with per-tenant
composite constraints. Global uniqueness there was itself a cross-tenant
signal: the first tenant to register a channel or credential name locked
every other tenant out of it, and the insert conflict revealed that the name
already existed somewhere else.

## Execution Context Is The Only Source Of Ownership

Ownership is resolved from the authenticated identity, the owning connector,
the schedule owner, the swarm job, or the stored trigger. It is never read from
a request body, so a crafted payload cannot claim another tenant.

Writes fail closed. Finding ingestion raises without tenant context, swarm job
creation requires one, asset-memory upserts refuse an unowned write, and
remediation refuses to execute without an owner. Background work is explicit
too: the auto-scanner resolves the connector's tenant before scanning, and the
scheduled sweep iterates each tenant that owns a connector rather than running
once globally.

Channel ingress is the one unauthenticated entry point, so it cannot take
ownership from the caller at all. Slack, Teams, webhook, email, and CLI
messages inherit the tenant of the channel config an operator registered for
that channel id. A message arriving on an unregistered channel stays unowned
and is visible only to an unscoped administrator, rather than defaulting into
a tenant. The `tenant_id` field accepted in the CLI body is used for identity
bootstrap metadata only and never sets record ownership. Outbound replies are
matched to a config in the message's own tenant, so one tenant's response can
never be delivered through another tenant's webhook.

## Credential Boundary

Connector secrets are encrypted at rest and indexed with the owning tenant in
the encrypted store. A connector UUID alone is not sufficient to retrieve,
replace, or delete another tenant's credential. A mismatch raises an internal
`CrossTenantCredentialAccess` error; HTTP callers receive an undiscoverable
not-found response for records outside their scope.

## Native Workspace Boundary

Codex App Server sessions are derived from tenant, owner, Project, conversation,
and an opaque native-folder grant. Native workspace operations resolve the
Project inside the authenticated tenant before Trust Fabric or Bridge execution.

## Verification

`backend/tests/test_tenancy.py` covers claim enforcement, undiscoverable
cross-tenant records, and legacy-admin access. `test_tenant_isolation.py`
covers the credential-store boundary, while connector, Memory, and Swarm suites
exercise the corresponding routes.

`test_cross_tenant_access.py` is the adversarial suite: it asserts that
findings, swarm jobs, schedules, triggers, run history, and Control Center
counts all exclude another tenant, that single-record lookups return 404 rather
than 403, and that an unscoped non-admin identity is refused instead of shown
everything. `test_finding_tenant_ingestion.py` proves the same external id in
two tenants creates two rows and that one tenant cannot update another's
finding. `test_tenant_memory_scope.py` proves posture summaries and risk trends
are per-tenant. `test_audit_tenant_scope.py` proves audit trails do not mix.

`test_channel_exec_tenant_scope.py` covers the two highest-consequence
surfaces: it proves a foreign execution request cannot be read, approved,
rejected, or executed, that an approved foreign request is still not run, that
credential broker entries and their secret paths are not listable or
rotatable across tenants, that the same credential name may exist in two
tenants, that production gates are undiscoverable, that channel messages,
configs, and identities are scoped, that a `tenant_id` in an identity upsert
body cannot adopt or elevate another tenant's mapping, and that unowned
ingress is hidden from tenant-bound callers.

Migrations `0005`–`0011` were verified on PostgreSQL 16 through a full
upgrade → downgrade → upgrade cycle against a schema clone. SQLite is used for
the test suite only; migration support there is not claimed.

The remaining historical `xfail` cases document a typed organization/user
foreign-key model, which is still string-keyed today.

## Defense in Depth

Application-level scoping is shipped. A production multi-tenant deployment
should additionally enable PostgreSQL Row-Level Security once the deployment
sets a transaction-local tenant value for every request. That prevents an
accidental future unscoped query from bypassing the application boundary.

`NODE_TLS_REJECT_UNAUTHORIZED=0` must never be set in production. Enkstein does
not set it; it appears only when a developer shell exports it, and it disables
TLS certificate verification for every Node process.
