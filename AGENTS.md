# Marcellus Agent Operating Guide

## Repository Boundary
- This is the independent Marcellus architecture repository at `/Users/wcoreiron/Desktop/Marcellus`.
- The sibling `/Users/wcoreiron/Desktop/RegentClaw` repository is a stable source and must not be modified from this project.
- Legacy RegentClaw names and routes remain compatibility contracts until a versioned migration explicitly replaces them.

## Project Purpose
Marcellus is an octopus-inspired distributed security action engine built from the RegentClaw compatibility baseline. It organizes governed capabilities into a Cortex, Three Hearts, Security Arms, Capability Nodes, Skills, Connectors, Reflexes, a peer Plexus, and Regeneration workflows.

## Stack
- Backend: FastAPI, SQLAlchemy async, PostgreSQL, Redis
- Frontend: Next.js 14, TypeScript, Tailwind
- Tooling: pytest, Docker Compose

## Architecture Overview
- `backend/app/trust_fabric/`: policy enforcement, anomaly scoring, containment
- `backend/app/core/swarm/`: parallel swarm orchestration, aggregation, judging
- `backend/app/core/marcellus/`: Cortex/Heart/Arm/Node registry plus Plexus, Reflex, and Regeneration runtimes
- `backend/app/claws/*/`: Claw modules with routes/providers
- `backend/app/api/routes/`: platform APIs
- `frontend/src/app/`: platform pages and module views

## Commands
- Backend dev: `cd backend && uvicorn main:app --reload`
- Frontend dev: `cd frontend && npm run dev`
- Frontend lint: `cd frontend && npm run lint`
- Frontend build: `cd frontend && npm run build`
- Backend tests: `cd backend && pytest`
- Full stack: `docker-compose up --build`

## Coding Conventions
- Keep diffs surgical and localized.
- Follow existing file/module patterns before adding abstractions.
- Keep UI consistent with existing design system and nav model.
- Avoid introducing new dependencies unless clearly necessary.

## Security Requirements
- Route security-sensitive actions through Trust Fabric checks.
- No bypass of policy evaluation for model, connector, or remediation actions.
- Local autonomy and peer communication never bypass Trust Fabric.
- Skills and Connectors cannot expand a Capability Node's authority implicitly.
- Preserve auditability for decisions and containment outcomes.
- Do not log raw secrets, tokens, or sensitive tenant payloads.

## Data Protection / Tenant Isolation
- Treat cross-tenant data mixing as a critical bug.
- Keep connector credentials scoped and encrypted.
- Redact or avoid sensitive values in errors and telemetry.

## Logging Rules
- Log outcome, reason, and identifiers; avoid sensitive body dumps.
- Prefer structured payloads over free-form debug logs.

## Do-Not-Touch Without Approval
- `backend/alembic/versions/` existing migrations
- secrets/key material under ignored local secret paths
- broad refactors of shared policy/runtime core outside scoped task

## Definition Of Done
- Feature works end-to-end with graceful failure handling.
- Existing tests/lint/build still pass for impacted layers.
- Any new route/page is discoverable and documented.
- Security implications and guardrails are preserved.

## PR / Review Expectations
- Include what changed, why, and verification steps.
- Call out limitations, TODOs, and risk areas explicitly.
- Keep unrelated churn out of the diff.
