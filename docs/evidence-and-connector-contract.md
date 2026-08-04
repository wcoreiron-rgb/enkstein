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
