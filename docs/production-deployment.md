# RegentClaw Production Deployment Guide

**Status:** baseline hardening guide, not a hosted-service certification.

Use this guide when moving RegentClaw from local Docker development into a production-like environment.

## Required Controls

| Area | Requirement |
|---|---|
| TLS | Terminate HTTPS at a trusted reverse proxy or ingress. Do not expose backend HTTP directly to the internet. |
| Secrets | Set production secrets through your secret manager. Do not commit `.env`, Fernet keys, remote-agent enrollment secrets, API keys, or connector credentials. |
| Database | Use managed PostgreSQL or a backed-up PostgreSQL service. Enable automated backups and test restore before production use. |
| Redis | Require network isolation and authentication where supported. Treat Redis as sensitive runtime state. |
| Authentication | Require real JWT/OIDC identity in front of operator routes. Do not rely on local development defaults. |
| Trust Fabric | Keep policy evaluation fail-closed for execution, remediation, model calls, connector calls, and evidence exports. |
| CI security | Keep SBOM and dependency audit jobs enabled. Use `security/supply_chain_baseline.json` only for time-boxed accepted legacy findings. |
| Release gates | Run production deployments through ReleaseClaw preflight before CI/CD, GitOps, cloud CLI/SDK, script, full-stack, or AI-stack execution handoff. |
| Terraform/IaC gates | Run TerraClaw build/review/plan analysis before Terraform applies. Treat BLOCK decisions as release blockers unless explicitly overridden through governed approval. |
| Frontend runtime | Build the Next.js frontend into the container image and serve it with `npm run start`; do not mount `.next` or run `next dev` in the production Compose path. |

## Minimum Environment Checklist

- `DATABASE_URL` points to production PostgreSQL.
- `REDIS_URL` points to a private Redis endpoint.
- `FERNET_KEY` or equivalent secrets encryption key is generated and stored outside git.
- `REMOTE_AGENT_ENROLLMENT_SECRET` is set to a high-entropy value.
- Model provider keys are tenant-scoped where possible.
- Connector credentials are configured through the connector UI/API and encrypted at rest.
- CORS allows only approved frontend origins.
- Reverse proxy enforces TLS, request size limits, and sane timeouts.
- Backend logs redact request bodies and secrets.
- ReleaseClaw preflight templates are reviewed for the target deployment path.
- Production release handoff is approved by someone other than the requester.
- Rollback plans/artifacts exist before non-dry-run deployments.
- Terraform modules generated or reviewed by TerraClaw are checked before apply.
- The frontend container is rebuilt before deployment so `INTERNAL_API_URL=http://backend:8000` is baked into Next.js rewrites for Docker-internal API proxying.

## TerraClaw Terraform/IaC Gates

For Terraform-backed releases, run TerraClaw first:

```http
POST /api/v1/terraclaw/build
POST /api/v1/terraclaw/review
POST /api/v1/terraclaw/generate
POST /api/v1/terraclaw/plan
```

Use `build` when an operator wants a secure Terraform module from plain
English. Use `generate` for the TerraClaw agent/MCP path, which returns
Terraform module output, artifacts, applied controls, Trust Fabric metadata, and
security-review evidence. Use `review` for existing `.tf` content. Use `plan`
before apply to detect risky creates, deletes, replacements, public network
exposure, weak data protection, hardcoded secrets, excessive IAM, missing
diagnostics, and other high-risk IaC changes.

Attach the build/generate, review, and plan decisions to the ReleaseClaw preflight
evidence for Terraform Cloud, GitOps, CI/CD, or CLI-driven applies. TerraClaw
identifies public network exposure, excessive IAM, hardcoded secrets,
data-protection misconfiguration, missing diagnostics, and risky
replacement/delete operations; ReleaseClaw then gates the execution handoff.

External coding agents can use the RegentClaw MCP server tools
`terraclaw_generate_secure_terraform`, `terraclaw_review_hcl`, and
`terraclaw_analyze_plan`; the MCP server forwards to the backend API and does
not execute Terraform locally or hold provider credentials.

## ReleaseClaw Deployment Gates

ReleaseClaw is the deployment governance layer for production changes. It
normalizes deployment paths such as GitHub Actions, GitLab CI, Jenkins, Azure
DevOps, ArgoCD, Terraform Cloud, AWS/Azure/GCP CLIs, Kubernetes/Helm/Docker,
Bash, PowerShell, Python, Node, Ansible, webhooks, full-stack application
rollouts, and AI service stacks.

```http
POST /api/v1/releaseclaw/preflight
```

ReleaseClaw checks:

- source adapter and execution channel
- target environment and data classification
- required controls from deployment templates
- rollback plan/artifact presence
- AI-stack model profile and model-call governance expectations
- risky script/cloud operations before execution handoff
- Trust Fabric policy decision, ring-policy posture, and audit event creation

ReleaseClaw does not directly execute arbitrary scripts. A successful preflight
returns a governed handoff plan for CI/CD, GitOps, cloud runners, or
ExecChannels, plus a SHA-256 evidence hash.

## Backup And Restore

1. Take a PostgreSQL backup before every migration.
2. Restore the backup into a staging environment before production rollout.
3. Run backend tests and a smoke test against staging.
4. Apply migrations during a maintenance window when table sizes are large.

## Compliance Evidence Export

ComplianceClaw provides an audit-ready JSON export:

```http
POST /api/v1/complianceclaw/evidence/export
```

Request:

```json
{
  "requested_by": "compliance-admin",
  "frameworks": ["SOC 2", "ISO 27001"],
  "include_findings": true,
  "include_audit_logs": true,
  "max_audit_logs": 100,
  "classification": "confidential"
}
```

The export is Trust Fabric-governed and includes:

- policy decision metadata
- linked findings
- compliance-relevant audit logs
- per-framework evidence counts
- SHA-256 chain-of-custody hash

Exports are vendor-generated evidence bundles. Independent audit review is still required before compliance reliance.
