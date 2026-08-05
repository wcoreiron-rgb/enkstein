# Evidence And Connector Contract

Enkstein separates three questions that security consoles often blur:

1. Is a connector configured with encrypted credentials?
2. Has Enkstein completed a read-only provider-specific verification?
3. Has a Capability Node produced evidence from that provider?

Only the third can describe the current environment. Only the second can display as **Verified** in Connector Health. Policy approval is separate from both.

## Evidence States

| State | Meaning | Eligible for controls/remediation |
|---|---|---|
| `live` / `live_connector` | Read from an authenticated provider during a scan or task | Yes, subject to Trust Fabric and approval policy |
| `persisted_db` | Previously collected tenant-scoped evidence | Analysis only; freshness rules apply |
| `demo` / `seeded_fallback` | Explicit local walkthrough data | No |
| `unavailable` / `no_data_source` | No authenticated source returned usable evidence | No |

Production defaults to `REQUIRE_LIVE_DATA=true`. A Node without a verified source returns an unavailable outcome rather than sample findings. Setting the flag to `false` is for a clearly labelled local demo only.

## Connector Health

Connector Health is a recorded status page, not a synthetic network monitor:

- **Verified** means a successful provider-specific credential/service test is recorded.
- **Needs Verification** means the connector is configured and approved but has not completed a qualifying read-only test.
- **Not Configured**, **Pending Approval**, **Restricted**, and **Blocked** retain their literal policy meanings.

Every test is read-only. A failed verification stores only Enkstein's bounded safe failure message, never raw provider responses or credentials.

## Action Boundary

AI summaries are advisory. Deterministic controls and live evidence decide verdicts. Any remediation remains a governed proposal, passes Trust Fabric, and requires the policy-defined approval before execution. A successful action is not a passing control; Enkstein requires a later fresh evaluation.

## Connector Coverage

Marketplace adapters provide a common bounded, SSRF-protected read path. A connector is not represented as a live source until an operator configures it and its own read-only test succeeds against that tenant. API access, scopes, vendor configuration, and network egress remain deployment-specific and are intentionally surfaced as unavailable rather than simulated.

## Control Scope Per Connector

A connector's controls are answered in two layers, because the two questions have different homes:

- **Catalog scope** is which controls a connector type could ever prove. It comes from the collector bindings in `app/services/control_collectors.py` and is stable reference material.
- **Live standing** is which of those controls passed, failed, or were never assessed in one tenant. Only the deployment knows this, so it is served in-app and never published.

`GET /api/v1/controls/connector-scope` returns per-connector counts, and `GET /api/v1/controls/connector-scope/{connector_type}` returns one connector's collectors and controls with this tenant's verdicts. Both resolve adapter aliases, so a tenant that configured `azure_ad` sees the same scope as `entra_id`.

Verdicts are read from the deterministic control evaluator rather than recomputed, so this view cannot disagree with a Capability Node's own page. A collector can be satisfied by any one of several connectors, so `ready` may be true through a sibling connector while this connector itself is unconfigured; both facts are reported separately rather than merged. A connector bound to no collector reports an explicit reason instead of an empty list.

## Connector Coverage Of Controls

Every connector with a working read adapter is bound to at least one evidence collector. A connector that could return findings but assessed nothing was a silent gap: it looked functional and proved no control. A packaging test now asserts that no reporting adapter is left unbound.

Connectors that legitimately assess nothing say which kind they are rather than implying a gap that will close later:

- **Model provider** (`openai`, `azure_openai`, `anthropic`, `gemini`, `ollama`, `nvidia_nim`) is a Brain used for reasoning. Its governance is Model Cortex and Trust Fabric, not a control verdict.
- **Notification channel** (`email`) delivers messages and reports no system state.
- **Action only** (`pagerduty`, `tfsec`, `checkov`, `infracost`, `terraform_mcp`) acts or runs locally rather than reporting posture.

Installing the baseline pack binds its collectors in the same operation. Adding controls without binding them leaves each one permanently `NOT_ASSESSED` and every connector feeding that node reporting an empty scope, so `POST /api/v1/controls/bootstrap` returns `evaluators_attached` alongside `added`. The binding is idempotent.
