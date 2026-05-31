# OWASP Top 10 for Agentic Applications (ASI 2026) — RegentClaw Evidence Matrix

**Date:** 2026-05-31  
**Version:** 2.1  
**Scope:** RegentClaw Zero Trust Security Platform (self-hosted)

> **Disclaimer:** This is a vendor self-assessment. Status values below are deliberately conservative and mapped to currently shipped code paths and automated tests. An independent third-party security assessment is recommended before relying on this document for compliance purposes.

---

## Summary Table

| ASI | Category | Status | Evidence Anchor | Automated Test |
|---|---|---|---|---|
| ASI-01 | Agent Goal Hijack | **Partially Shipped** | Trust Fabric policy + ArcClaw prompt audit | `test_owasp_asi_evidence.py::test_asi01_prompt_injection_flagged_by_audit` |
| ASI-02 | Tool Misuse & Exploitation | **Partially Shipped** | Ring policy + Trust Fabric action mediation | `test_owasp_asi_evidence.py::test_asi02_viewer_role_denied_ring1_action` |
| ASI-03 | Identity & Privilege Abuse | **In Progress** | JWT identity + role checks + ring gates | `test_owasp_asi_evidence.py::test_asi03_viewer_role_cannot_approve_via_self_approval` |
| ASI-04 | Agentic Supply Chain Compromise | **In Progress** | AGT supply-chain scan routes + connector policy gates | `test_owasp_asi_evidence.py::test_asi04_supply_chain_scan_returns_result`, `test_owasp_asi_evidence.py::test_asi04_tampered_hash_blocked_on_install` (xfail: install gate not yet wired) |
| ASI-05 | Unexpected Code Execution | **Partially Shipped** | Exec policy blocking + ring0 denial + approvals | `test_owasp_asi_evidence.py::test_asi05_ring0_always_blocked_regardless_of_role_or_trust` |
| ASI-06 | Memory & Context Poisoning | **Partially Shipped** | Memory API field validation via Pydantic schemas | `test_owasp_asi_evidence.py::test_asi06_memory_write_rejects_oversized_title` |
| ASI-07 | Insecure Inter-Agent Communication | **Partially Shipped** | Ed25519 signed inter-agent envelopes + verify endpoint | `test_owasp_asi_evidence.py::test_asi07_tampered_envelope_fails_verification` |
| ASI-08 | Cascading Agent Failures | **In Progress** | SRE error budget + circuit breaker primitives | `test_owasp_asi_evidence.py::test_asi08_circuit_breaker_trips_after_error_budget_exceeded` |
| ASI-09 | Human-Agent Trust Exploitation | **Partially Shipped** | Dual approvals + no self-approval + audit trail | `test_owasp_asi_evidence.py::test_asi09_self_approval_is_blocked` |
| ASI-10 | Rogue Agents | **In Progress** | Containment probe routes + suspend/isolate/block actions | `test_owasp_asi_evidence.py::test_asi10_containment_probe_passes_and_records_outcome` |

---

## ASI-01 — Agent Goal Hijack

**Description:** Adversarial manipulation of an agent's goals, instructions, or prompt context to redirect its actions away from intended behavior. Includes direct prompt injection, indirect injection via retrieved content, and jailbreak techniques.

**RegentClaw Status:** Partially Shipped

**Evidence:**

- `backend/app/trust_fabric/agt_bridge.py::audit_prompt()`: AGT PromptDefenseEvaluator runs a 12-vector injection audit on every submitted prompt. The keyword-based fallback (`_fallback_prompt_audit`) provides deterministic coverage when AGT is unavailable.
- `backend/app/claws/arcclaw/routes.py` (lines 69–109): Every `POST /api/v1/arcclaw/events` and `POST /api/v1/arcclaw/chat` submission runs both the AGT audit and RegentClaw's pattern scanner before any tool execution.
- Events with `is_injection_risk=True` and `risk_score >= 50` are set to `AIEventOutcome.BLOCKED` before being stored — the raw injection payload is never executed.
- Injection findings are persisted to the AI Governance audit log with vector detail and risk score.

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi01_prompt_injection_flagged_by_audit` — calls `audit_prompt()` directly with a canonical "ignore previous instructions" payload and asserts `is_injection_risk=True`, `risk_score >= 20`, and at least one finding.
- `backend/tests/test_owasp_asi_evidence.py::test_asi01_benign_prompt_not_flagged` — verifies the control does not over-block benign security operations queries.

**Known Limitations:**
- The AGT PromptDefenseEvaluator reports findings for every prompt (including benign ones), so the blocking decision falls back to the keyword scanner rather than AGT's raw `is_injection_risk` flag. This is intentional and documented in `agt_bridge.py`.
- Indirect injection (e.g., malicious content in retrieved documents that the agent reads) is detected via pattern matching only — semantic detection would require an LLM-as-judge layer.
- No red-team test suite is included in the repository.

---

## ASI-02 — Tool Misuse & Exploitation

**Description:** Agents invoking tools with unintended parameters, accessing tool interfaces outside their privilege tier, or exploiting tool APIs to escalate privileges or exfiltrate data.

**RegentClaw Status:** Partially Shipped

**Evidence:**

- `backend/app/services/ring_policy.py`: Ring-based privilege isolation. Every action_type and exec channel maps to ring0..ring3. Viewer, readonly, guest, and monitor roles are explicitly blocked from ring1 (privileged) actions via `_RING1_BLOCKED_ROLES`.
- `backend/app/api/routes/exec_channels.py`: Ring policy check (`evaluate_exec_request` + Trust Fabric `enforce`) runs before any execution is queued.
- `backend/app/services/connector_tester.py`: SSRF protection on connector test URLs (private IP blocklist).

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi02_viewer_role_denied_ring1_action` — calls `evaluate_ring("ring1", trust_score=95.0, caller_role="viewer")` and asserts `allowed=False`, `policy_name="execution_ring_violation"`, and that the deny reason names the role.
- `backend/tests/test_owasp_asi_evidence.py::test_asi02_ring1_blocked_for_all_low_privilege_roles` — covers all low-privilege roles (viewer, readonly, guest, monitor).
- `backend/tests/test_ring_policy.py` — 32 additional ring policy tests including `test_ring0_always_blocked`, `test_ring1_requires_two_approvals`, and per-action classification coverage.

**Known Limitations:**
- Tool parameters passed to agents are not schema-validated against a strict allowlist — callers can supply arbitrary JSON to some endpoints.
- The ring policy covers exec channels and remediation approvals, but not all tool invocation paths in ArcClaw's security agent.

---

## ASI-03 — Identity & Privilege Abuse

**Description:** Agents or users claiming false identities, abusing delegated credentials, or exploiting role misconfigurations to perform actions beyond their authorization level.

**RegentClaw Status:** In Progress

**Evidence:**

- `backend/app/core/deps.py`: `get_current_user` dependency extracts identity and role from JWT — client-supplied identity fields are ignored in approval flows.
- `backend/app/api/routes/exec_channels.py::approve_request` (line ~389): `approver = current_user.get("sub", "unknown")` — the approver is always the authenticated JWT identity, never the client-supplied body field.
- `backend/app/api/routes/remediation.py::approve_action`: Trust Fabric ring policy is evaluated against `caller_role` from the JWT before `approve_remediation` is called. Blocked decisions return HTTP 403.
- JWT tokens use HS256 with a per-deployment `SECRET_KEY` validated at startup (`settings.validate_security()`).

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi03_viewer_role_cannot_approve_via_self_approval` — submits a shell request with `requested_by="test-user"` (the JWT identity), then attempts to approve it as the same identity, asserting HTTP 403 with a "self-approval" error message.

**Known Limitations:**
- Role-based access control at the route level is partial — not all routes enforce role checks via a consistent dependency.
- No dedicated test for a viewer-role JWT attempting to approve a ring1 remediation action via the remediation route (the Trust Fabric check fires, but the HTTP assertion is not yet in the test suite).
- Token revocation is not yet implemented — a compromised JWT remains valid until expiry.

---

## ASI-04 — Agentic Supply Chain Compromise

**Description:** Malicious or tampered skills, plugins, connectors, model weights, or dependencies introduced into the agent supply chain, causing agents to execute attacker-controlled code.

**RegentClaw Status:** In Progress

**Evidence:**

- `backend/app/trust_fabric/agt_bridge.py::scan_requirements()`: AGT SupplyChainGuard checks `requirements.txt` for typosquatting hits, outdated packages, and known-vulnerable versions on every Trust Fabric status check.
- `backend/app/api/routes/trust_fabric.py::get_trust_fabric_status`: Supply chain scan result is returned in the status response, surfacing issues to operators.
- `backend/app/api/routes/trust_fabric.py::scan_mcp_skill_path`: `POST /api/v1/trust-fabric/mcp/scan` exposes a path-level security scan via AGT's SecurityScanner.
- Connector install approval via the ZT policy "Block Connector Install Without Approval".
- `requirements.txt`: PyJWT pinned to 2.9.0 (patched); `python-multipart` pinned to 0.0.12 (patched for CVE-2024-53498).

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi04_supply_chain_scan_returns_result` — calls `scan_requirements()` with a non-existent path and verifies the result has `is_safe` and `risk_score` fields with no crash.
- `backend/tests/test_owasp_asi_evidence.py::test_asi04_tampered_hash_blocked_on_install` — **xfail** (strict=False): documents the intent to block tampered-hash installs, but the install route does not yet gate on `scan.is_safe`.

**Known Limitations:**
- The supply chain scan result is informational only — the skill pack/connector install path does not currently block on `is_safe=False`. This is the primary coverage gap.
- No automated dependency vulnerability scanning (Trivy, Snyk, pip-audit) is integrated into CI.
- No SBOM generation in the build pipeline.

---

## ASI-05 — Unexpected Code Execution

**Description:** Agents executing arbitrary system-level commands, loading kernel modules, modifying boot sequences, or bypassing execution sandboxes through privilege escalation.

**RegentClaw Status:** Partially Shipped

**Evidence:**

- `backend/app/services/ring_policy.py`: ring0 is unconditionally blocked with no approval path and no role exception. The `evaluate_ring` function returns `allowed=False`, `approvals_required=0`, `policy_name="execution_ring_violation"` for all ring0 requests.
- ring0 actions include: `kernel_exec`, `system_call`, `load_kernel_module`, `raw_socket`, `ptrace`, `modify_boot`.
- `backend/app/api/routes/exec_channels.py::execute_request`: Re-checks Trust Fabric decision before execution — ring policy is re-evaluated at execution time, not just at submission time.
- `backend/app/services/exec_policy.py::evaluate_exec_request()`: Blocks commands matching destructive/credential-access patterns via regex.

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi05_ring0_always_blocked_regardless_of_role_or_trust` — calls `evaluate_ring("ring0", ...)` for all privileged and low-privilege roles with `trust_score=100` and asserts unconditional denial with `execution_ring_violation`.
- `backend/tests/test_owasp_asi_evidence.py::test_asi05_all_ring0_action_types_are_classified` — verifies every ring0 action in `ACTION_RING_MAP` resolves to ring0 via `classify_ring()`.
- `backend/tests/test_ring_policy.py::test_ring0_always_blocked` — parallel coverage from the ring policy test suite.
- `backend/tests/test_ring_policy.py::test_ring0_blocked_regardless_of_role` — same control verified across all roles.

**Known Limitations:**
- ring0 enforcement is at the policy layer — hard OS sandbox guarantees (seccomp, container isolation) are not yet fully proven for all execution paths.
- The re-check at `execute_request` time uses Trust Fabric, not the ring policy directly — if Trust Fabric fails open, the execution gate could be bypassed.

---

## ASI-06 — Memory & Context Poisoning

**Description:** Injection of malicious or oversized data into agent memory stores, context windows, or retrieval systems to manipulate future agent behavior or degrade platform integrity.

**RegentClaw Status:** Partially Shipped

**Evidence:**

- `backend/app/api/routes/memory.py::IncidentCreate`: Pydantic schema enforces `title: str = Field(..., min_length=3, max_length=255)` — rejects empty, too-short, or oversized titles with HTTP 422.
- `backend/app/services/memory_service.py`: `append_incident_timeline` validates incident existence before appending — prevents orphaned timeline injection.
- `backend/app/claws/arcclaw/scanner.py::scan_text()`: Applied to all submitted prompts before they can be stored as AI events — redacts secrets and PII before persistence.
- Incident memory records require a minimum title length (prevents blank/null-title poisoning) and cap at 255 chars (prevents memory-exhaustion via oversized records).

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi06_memory_write_rejects_oversized_title` — posts an incident with a 300-char title (exceeds max_length=255) and asserts HTTP 422.
- `backend/tests/test_owasp_asi_evidence.py::test_asi06_memory_write_rejects_too_short_title` — posts an incident with a 2-char title (below min_length=3) and asserts HTTP 422.
- `backend/tests/test_owasp_asi_evidence.py::test_asi06_valid_memory_write_accepted` — confirms the control does not over-block valid writes.

**Known Limitations:**
- Memory field validation is schema-level (Pydantic) only — no semantic validation of timeline content for malicious instructions embedded in text fields.
- The `timeline_json` and `description` fields accept arbitrary text with no injection scanning applied to their content before storage.
- No per-tenant memory quota enforcement — a high-volume writer could exhaust storage without being circuit-broken.

---

## ASI-07 — Insecure Inter-Agent Communication

**Description:** Agent-to-agent messages without cryptographic authentication, integrity protection, or replay prevention — enabling impersonation, man-in-the-middle, or message injection attacks.

**RegentClaw Status:** Partially Shipped

**Evidence:**

- `backend/app/fabric/security/agent_identity.py::AgentSigner`: Ed25519 private key signing and verification. Key is loaded from `AGENT_SIGNING_PRIVATE_KEY_PEM` env var or auto-generated and persisted to `.secrets/`.
- `AgentSigner.sign(message: bytes) -> str`: Returns base64-encoded Ed25519 signature.
- `AgentSigner.verify(message, signature_b64, key_id)`: Returns `False` on `InvalidSignature` or key_id mismatch — does not raise, always returns a boolean.
- `backend/app/api/routes/trust_fabric.py::verify_multi_agent_message`: `POST /api/v1/trust-fabric/multi-agent/verify` exposes envelope verification as an API endpoint.

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi07_valid_signed_envelope_verifies` — signs a message and verifies it returns `True`.
- `backend/tests/test_owasp_asi_evidence.py::test_asi07_tampered_envelope_fails_verification` — signs a message, tampers the content, asserts verification returns `False`.
- `backend/tests/test_owasp_asi_evidence.py::test_asi07_fabricated_signature_is_rejected` — random 64-byte signature is rejected.
- `backend/tests/test_owasp_asi_evidence.py::test_asi07_wrong_key_id_is_rejected` — valid signature with mismatched key_id returns `False`.

**Known Limitations:**
- Full SPIFFE/X.509-based attestation-grade mesh is not implemented — identity is signer-key based, not tied to a workload attestation authority.
- Replay prevention (nonce/timestamp validation) is not implemented — a captured valid envelope could be replayed.
- Message encryption (confidentiality) is not implemented — only integrity is protected.

---

## ASI-08 — Cascading Agent Failures

**Description:** A failure in one agent propagating to downstream agents, overwhelming shared infrastructure, or exhausting error budgets in ways that destabilize the platform.

**RegentClaw Status:** In Progress

**Evidence:**

- `backend/app/services/sre_policy.py::SREPolicyEngine`: Sliding-window error budget tracking per module. When `error_rate >= SRE_CIRCUIT_BREAKER_THRESHOLD` (default 50%) and `total >= SRE_MIN_SAMPLES` (default 5), the circuit opens for `SRE_CIRCUIT_BREAKER_OPEN_SECONDS` (default 120 seconds).
- `SREPolicyEngine.check_circuit(module)`: Returns `(False, reason)` when circuit is open — callers in `evaluate_trust_action` return a 200 response with `outcome="blocked"` to the caller.
- `backend/app/api/routes/trust_fabric.py::evaluate_trust_action`: Checks circuit before routing to Trust Fabric `enforce()`, and records outcome after each decision.
- `SREPolicyEngine.reset(module)`: Allows operators to manually clear circuit state for a module.

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi08_circuit_breaker_trips_after_error_budget_exceeded` — creates an isolated `SREPolicyEngine` instance, records enough failures to exceed `SRE_MIN_SAMPLES` at 100% error rate, and asserts `check_circuit()` returns `(False, reason)`.
- `backend/tests/test_owasp_asi_evidence.py::test_asi08_circuit_breaker_stays_closed_on_success` — records 10 successes and asserts circuit remains closed.

**Known Limitations:**
- The SRE policy engine state is per-process in-memory (with optional Redis persistence). Multiple worker processes may have divergent state without Redis.
- No SLO dashboards or error budget burn-rate alerts are implemented — operators must poll `GET /api/v1/trust-fabric/sre/status`.
- Module-level granularity only — no per-agent or per-action granularity within a module.

---

## ASI-09 — Human-Agent Trust Exploitation

**Description:** Attacks that exploit human-in-the-loop approval mechanisms — including social engineering approvers, exploiting trust relationships, or using self-approval to bypass governance gates.

**RegentClaw Status:** Partially Shipped

**Evidence:**

- `backend/app/api/routes/exec_channels.py::approve_request` (line ~392): `if approver == r.requested_by: raise HTTPException(403, "Self-approval not permitted")`. Approver identity always comes from `current_user["sub"]` (JWT), never the client body.
- `backend/app/api/routes/exec_channels.py::approve_request` (line ~396): Duplicate approver check — `if approver in (r.approved_by_1, r.approved_by_2): raise HTTPException(400, "You have already approved")`.
- Shell, browser, and credential channels require 2 independent approvals (`PRODUCTION_APPROVALS_REQUIRED = 2`) for `approved` status.
- `backend/app/api/routes/remediation.py::approve_action`: Approver always taken from JWT sub, not the request body (`ApproveRequest.approved_by` is ignored).
- `backend/app/models/exec_channels.py::ProductionGate`: `approvals_required` and `approvals_received` fields track multi-party sign-off.

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi09_self_approval_is_blocked` — submits a shell request as `test-user`, then calls approve as `test-user` (same JWT identity), asserting HTTP 403.
- `backend/tests/test_owasp_asi_evidence.py::test_asi03_viewer_role_cannot_approve_via_self_approval` — overlapping coverage; also confirms 403 and "self-approval" in the response.

**Known Limitations:**
- No test currently covers the duplicate-approver check (same user approving twice after the first approval).
- Social engineering of a second approver is an out-of-scope human problem, not a technical one the platform can fully prevent.
- The remediation route's self-approval guard relies on the upstream `approve_remediation` service function — a gap if that function is called directly (bypassing the route).

---

## ASI-10 — Rogue Agents

**Description:** Agents that deviate from their defined scope, perform unauthorized actions, persist after their authorization has expired, or resist containment actions.

**RegentClaw Status:** In Progress

**Evidence:**

- `backend/app/trust_fabric/__init__.py::isolate_module()`: Sets `module.status = ModuleStatus.QUARANTINED` and commits.
- `backend/app/trust_fabric/__init__.py::suspend_identity()`: Sets `identity.status = IdentityStatus.SUSPENDED` and commits.
- `backend/app/trust_fabric/__init__.py::block_connector()`: Sets `connector.status = ConnectorStatus.BLOCKED` and commits.
- `backend/app/api/routes/trust_fabric.py::run_containment_probe`: Non-destructive smoke test that exercises all three containment functions and verifies status transitions, then cleans up temporary records.
- Policy engine (`backend/app/services/policy_engine.py`): AGT/Swarm governance policies enforce containment gates.

**Automated Test:**

- `backend/tests/test_owasp_asi_evidence.py::test_asi10_containment_probe_passes_and_records_outcome` — calls `POST /api/v1/trust-fabric/containment-probe` and asserts `passed=True`, verifies each sub-action (`isolate_module`, `suspend_identity`, `block_connector`) has `executed=True` and the correct status string.
- `backend/tests/test_owasp_asi_evidence.py::test_asi10_containment_probe_results_are_auditable` — verifies each result entry includes a `target` identifier for forensic traceability.

**Known Limitations:**
- Containment is synchronous and in-database only — a rogue agent that has already dispatched external side-effects (webhooks, API calls) is not rolled back.
- No agent behavior baseline exists — rogue detection is policy-driven (explicit deny rules) rather than anomaly-based.
- No dead-man switch: an agent whose auth token expires is not automatically suspended — it simply fails to authenticate on the next call.

---

## Coverage Gaps

The following controls have no fully wired automated test as of this version. Each entry explains the gap honestly.

| Gap | Reason | Tracked In |
|---|---|---|
| ASI-04 hash-pinning install gate | `scan_requirements()` is called but the skill pack/exchange install route does not block on `is_safe=False`. The xfail test `test_asi04_tampered_hash_blocked_on_install` documents the intent. | `test_owasp_asi_evidence.py` (xfail) |
| ASI-03 viewer-JWT ring1 remediation block | The HTTP path (viewer JWT → approve ring1 remediation) is asserted at the service layer via ring policy tests, but there is no end-to-end HTTP integration test for the remediation route. | Future work |
| ASI-09 duplicate-approver check | The guard `if approver in (r.approved_by_1, r.approved_by_2)` has no automated test exercising the HTTP path. Partially exercised by manual testing only. | Future work |
| ASI-07 replay prevention | No nonce/timestamp validation is implemented — a valid captured envelope could be replayed. No test exists because the control does not exist. | Known gap |
| ASI-06 semantic memory poisoning | Malicious instructions embedded in valid-length text fields (description, timeline entries) are not scanned. No injection scanning is applied to memory text content. | Known gap |
| ASI-08 multi-process SRE state | Redis-backed SRE state is code-complete but not tested under multi-process conditions. | Known gap |

---

## Notes on Scope and Gaps

1. **Cryptographic mesh** is started (Ed25519 signed envelopes), but full SPIFFE/attestation-grade mesh is not complete. Replay prevention is absent.
2. **Execution isolation** is policy-strong at the ring layer, but hard OS sandbox guarantees (seccomp, container isolation) are not yet verified for all action paths.
3. **SRE primitives** are implemented and tested, but full SLO/error-budget governance dashboards and alerting are still maturing.
4. **Supply chain enforcement** is the largest gap — the scan capability exists but the install gate is advisory-only.

---

## Linked Evidence

- Ring policy implementation: `backend/app/services/ring_policy.py`
- Trust Fabric enforcement: `backend/app/trust_fabric/enforcement.py`
- Trust Fabric routes: `backend/app/api/routes/trust_fabric.py`
- Inter-agent signing: `backend/app/fabric/security/agent_identity.py`
- Exec channel governance: `backend/app/api/routes/exec_channels.py`
- Remediation governance: `backend/app/api/routes/remediation.py`
- SRE policy engine: `backend/app/services/sre_policy.py`
- AGT bridge: `backend/app/trust_fabric/agt_bridge.py`
- Tests:
  - `backend/tests/test_owasp_asi_evidence.py` ← **primary ASI evidence suite (this release)**
  - `backend/tests/test_ring_policy.py`
  - `backend/tests/test_platform_regressions.py`
  - `backend/tests/test_swarm.py`
  - `backend/tests/test_trust_fabric.py`
