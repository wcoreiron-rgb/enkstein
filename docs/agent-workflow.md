# Enkstein Agent Workflow

This project uses a repo-scoped agent operating structure to reduce drift and improve repeatability.

## Files Added
- `AGENTS.md`
- `.agents/skills/*`
- `.codex/agents/*`
- `.codex/config.example.toml`

## Day-to-Day Flow
1. Start with `investigate` for unclear bugs.
2. Use `new-feature` for implementation work.
3. Run `security-review` before finalizing risky changes.
4. Use `test-backfill` when behavior needs stronger coverage.
5. Use `docs-update` for route/flag/UI changes.
6. Use `open-pr` when preparing merge-ready output.

## Detected Commands
- Frontend: `npm run dev`, `npm run lint`, `npm run build`
- Backend: `uvicorn main:app --reload`, `pytest`
- Full stack: `docker-compose up --build`

## MCP Guidance
Enable MCP only when task-specific value exists:
- GitHub MCP: PR/issue workflows
- Playwright/browser MCP: UI behavior validation
- Docs MCP: API/framework lookup
- Postgres MCP: schema/data inspection
- Figma MCP: design system/page handoff

Keep disabled by default to avoid context/tooling bloat.

## Human Approval Boundaries
Always require explicit approval for:
- destructive git/file operations
- migration rewrites and schema-risk changes
- policy bypass or trust-fabric behavior changes
- production credential/connectivity changes
- cross-tenant data handling changes

