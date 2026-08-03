# Security Policy

Enkstein is an early-preview (v0.x) project. It has **not** had an independent
third-party security audit. Please treat it as evaluation software.

## Reporting a vulnerability

Report security issues privately through
[GitHub Security Advisories](https://github.com/wcoreiron-rgb/enkstein/security/advisories/new).
Do not open a public issue for a vulnerability.

Please include:

- what the issue is and where it lives (file, route, or component);
- the steps or request needed to reproduce it;
- what an attacker gains — data access, privilege escalation, policy bypass;
- the version you tested, from the app footer or `frontend/package.json`.

I read reports as a single maintainer, so expect a first response within about
a week rather than the same day. I will confirm what I could reproduce, say
plainly what I intend to fix and what I do not, and credit you in the release
notes unless you would rather stay anonymous.

## What is in scope

- Trust Fabric policy bypass — any path reaching a model, connector, tool, or
  remediation without a policy decision.
- Cross-tenant data access.
- Restricted or top-secret data reaching a non-local model.
- Credential, token, or secret exposure in logs, errors, telemetry, or the
  browser companion.
- Writes escaping an approved project folder.
- Authentication or approval bypass, including self-approval of a gated action.

## What is out of scope

- Findings that require an attacker to already have local root or your unlocked
  session.
- The development `docker-compose.yml`, which intentionally ships weak defaults
  for local work. The packaged runtime refuses to start with them; see
  `validate_security()` in `backend/app/core/config.py`.
- Simulated demonstration findings being unrealistic.
- Missing hardening on features the [Maturity Matrix](docs/maturity-matrix.md)
  already lists as in progress.

## Supported versions

Only the latest release receives fixes. Earlier v0.x versions are not
maintained.
