# Zero Trust Control Plane

Enkstein measures posture against a control catalog, not just a finding list.
A finding says something is wrong. A control says what *should* be true, and
exists whether or not anything has scanned yet. That distinction is what lets
a Security Arm answer "42 controls, 3 failing, 39 passing" instead of only
ever listing failures.

## Catalog sources

| Source | Controls | Licence | What it contributes |
| --- | --- | --- | --- |
| NIST SP 800-53 Rev 5 | 324 | Public domain | Control objectives imported from the official OSCAL catalog |
| Prowler | 1,038 | Apache-2.0 | Executable cloud posture checks for AWS, Azure, GCP, Kubernetes, GitHub |
| Enkstein authored | 64 | — | Node objectives, TerraClaw IaC rules, ArcClaw AI patterns |

Only factual fields are imported: identifier, title, severity, service,
resource type, remediation recommendation, and reference URL. Framework prose
is never copied into a finding.

## CISA pillars

Every control is tagged to exactly one CISA Zero Trust Maturity Model v2.0
pillar, because that is the axis maturity is scored on. NIST SP 800-207 tenets
are carried as optional cross-references; they explain *why* a control is zero
trust but classify poorly, since one control usually satisfies several at once.

Pillar assignment belongs to the control, not to the node that found it. An
encryption-at-rest rule is a Data control regardless of whether TerraClaw or
CloudClaw evaluated it.

## Per-Arm profiles

A catalog is not a profile. Presenting all 1,426 controls under every
Capability Node would claim Identity Security is accountable for physical
facility access, which is false and makes coverage meaningless.

OSCAL calls the selected subset a *profile*. `control_profiles.py` is that
layer: each Arm declares the NIST families it can plausibly produce evidence
for, and inherits only those. An Arm's denominator is its own.

```
GET /api/v1/controls/profiles/coverage    per-Arm matrix
GET /api/v1/controls/profiles/{claw}      one Arm's tailored profile
```

## Evidence collectors

A control is only assessable when something can observe the state it asserts.
`control_collectors.py` binds each control to the connector types capable of
producing its evidence. An Arm's real coverage is the share of its controls
whose collector has a configured connector; a control whose connector is
absent reports NOT_ASSESSED rather than silently counting as a pass.

```
GET  /api/v1/controls/collectors          readiness, and what each one needs
POST /api/v1/controls/collectors/attach   bind collectors to baseline controls
```

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `pass` | The collector ran and returned no violation |
| `fail` | An open, live finding violates the control |
| `not_assessed` | No collector has produced fresh evidence yet |
| `recommendation` | No deterministic evaluator exists; guidance only |

Three rules keep this honest:

1. Silence is never success. PASS requires a collector to have actually run.
2. Demonstration data never produces a verdict. Only live evidence can fail a
   control, so labelled demo findings cannot manufacture a compliance result.
3. Evidence older than seven days downgrades to NOT_ASSESSED rather than
   standing as a stale PASS.

The pass rate is scored only over controls that were actually assessed.
Unassessed controls are reported separately instead of inflating the score.

```
GET /api/v1/controls/evaluation?claw=identityclaw
```

## Remediation and verification

A control that can only report FAIL is an alert, not a control. A failing
control proposes the remediation action its definition declares, that action
runs through the existing governed remediation engine with its own risk
classification and approval gate, and the control is then re-evaluated.

Enkstein never infers a destructive action from a finding's text; a control
only proposes an action it explicitly declares. An executed action is not
evidence that the control now passes, so verification is a fresh evaluation
after a rescan.

```
GET  /api/v1/controls/remediation/proposals
POST /api/v1/controls/remediation/execute
POST /api/v1/controls/remediation/verify
```

## Prowler

Prowler is installed into `/opt/prowler-venv` so its large dependency tree
cannot conflict with the backend's pinned requirements. It is treated as a
read-only local scanner: no shell, allowlisted executables, credentials passed
through the child environment rather than argv, timeout-bounded execution, and
capped output. A non-zero exit without parseable results is a failure, never a
clean scan.

When Prowler is absent, readiness reports it honestly and cloud posture
controls are unavailable rather than silently empty.

```
GET  /api/v1/controls/prowler/status
POST /api/v1/controls/sync/prowler
```

## AI analysis and Swarm

Cross-node correlation runs through the Cortex Gateway under the `swarm_judge`
capability, so it inherits the profile's policy, redaction, and injection
checks. It tries the tenant's configured judge Brain first and falls back to
the local runtime, so a deployment with no cloud provider key still gets
analysis rather than an empty result.

```
POST /api/v1/controls/analyze
POST /api/v1/controls/investigate/swarm
POST /api/v1/controls/evidence/export
```
