# Prowler Integration

Prowler is an optional local scanner. Enkstein does not vendor the executable or cloud credentials.

## Setup

Install Prowler using its official installation instructions, then verify locally with prowler --version.
Register the Prowler Cloud Posture connector and choose aws, azure, gcp, kubernetes, or github as the provider.
Prefer the host cloud identity chain or profile. Credentials supplied through Enkstein are encrypted at rest and
passed to the child process through environment variables; they are never placed in argv or logs.

## Execution contract

Cloud Security invokes Prowler in read-only mode with JSON OCSF output in a temporary directory. Shell execution is
disabled, executable names are allowlisted, execution is timeout-bounded, and output files are size-capped. A
non-zero Prowler exit without parseable output is a failed scan and is never converted into a simulated success.

Each normalized result carries data_origin=live, control_source=prowler, control_id=prowler:provider:check_id, a
CISA pillar, and Prowler compliance requirement references when present. The first observed result materializes a
control row in control_catalog.

## Coverage boundary

Prowler improves cloud, Kubernetes, and GitHub posture coverage. It does not replace Entra or Okta identity checks,
endpoint EDR APIs, SIEM ingestion, SaaS governance, or remediation providers. Those require their own adapters and
controls. A Prowler scan is read-only assessment; remediation remains a separate Trust Fabric-gated workflow.

Prowler compliance metadata may reference third-party frameworks. Enkstein stores identifiers and factual references,
not copied benchmark prose. Pin the Prowler version used for release verification and keep its license and notices
with distributions that include it.
