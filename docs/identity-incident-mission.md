# Identity Incident Mission

The Identity Incident Mission is Enkstein's first guided security workflow. It
turns a suspicious identity alert into evidence, a policy-controlled decision,
and a reviewable action plan.

## What it does

1. The operator enters an affected identity and evidence window in **Identity
   Security**.
2. Enkstein launches the Microsoft identity incident Swarm: Identity, Cloud,
   Endpoint, Log, Threat, Compliance, and Automation Capability Nodes.
3. Each task reports its evidence source: `live connector`, `recorded tenant
   evidence`, `demo evidence`, or `evidence unavailable`.
4. The Swarm judge produces the confidence, probable cause, blast radius,
   recommended actions, compliance impact, and ticket draft.
5. Any consequential follow-up — account disablement, session revocation,
   containment, or a ticket handoff — goes through its own Trust Fabric
   approval. Investigating never grants remediation authority.

## Evidence policy

Normal missions accept live connector data and recorded tenant evidence. Seeded
and simulated results are removed before they reach the Swarm judge, so they
cannot create a score or recommendation that looks operational.

For a local walkthrough only, an operator may choose **Allow labeled demo
evidence**. The task table then shows `demo evidence`; it is never presented as
a live connector result.

## Required connectors for live investigation

The Microsoft preset prefers Microsoft Entra ID, Defender for Cloud, Defender
for Endpoint, and Microsoft Sentinel. Each missing or failed source is shown as
unavailable rather than synthesized. Configure and test the connector in
**Connectors** before relying on a mission result.

## Limits

The mission can create a governed ticket action and propose identity
remediation. It does not silently execute containment. Live Entra or endpoint
remediation requires an approved connector with the needed provider scopes and
an explicit Enkstein approval.
