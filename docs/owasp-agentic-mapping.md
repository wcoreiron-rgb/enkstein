# OWASP Top 10 for LLM Applications (2025) — Enkstein Evidence Matrix

**Date:** 2026-05-31  
**Version:** 1.1  
**Scope:** Enkstein Zero Trust Security Platform (self-hosted)

> **Disclaimer:** This is a vendor self-assessment. Claims have been matched against source code in this repository but have not been independently audited. An independent third-party security assessment is recommended before relying on this document for compliance purposes.

---

## Table of Contents

1. [LLM01 – Prompt Injection](#llm01--prompt-injection)
2. [LLM02 – Insecure Output Handling](#llm02--insecure-output-handling)
3. [LLM03 – Training Data Poisoning](#llm03--training-data-poisoning)
4. [LLM04 – Model Denial of Service](#llm04--model-denial-of-service)
5. [LLM05 – Supply-Chain Vulnerabilities](#llm05--supply-chain-vulnerabilities)
6. [LLM06 – Sensitive Information Disclosure](#llm06--sensitive-information-disclosure)
7. [LLM07 – Insecure Plugin Design](#llm07--insecure-plugin-design)
8. [LLM08 – Excessive Agency](#llm08--excessive-agency)
9. [LLM09 – Overreliance](#llm09--overreliance)
10. [LLM10 – Model Theft](#llm10--model-theft)
11. [Summary Table](#summary-table)

---

## Summary Table

| # | Category | Status | Test Coverage |
|---|----------|--------|---------------|
| LLM01 | Prompt Injection | **Shipped** | `test_owasp_asi_evidence.py::test_asi01_prompt_injection_flagged_by_audit` (same prompt injection control as ASI-01) |
| LLM02 | Insecure Output Handling | **Shipped** | `test_model_router_hardening.py::test_model_router_output_rescan_redacts_sensitive_response`, `test_cortex_workspace.py::test_provider_download_with_secrets_is_blocked_not_written` |
| LLM03 | Training Data Poisoning | **N/A** | N/A |
| LLM04 | Model Denial of Service | **Shipped** | `test_model_router_hardening.py::test_model_route_rate_limit_blocks_after_threshold`, `test_cortex_workspace.py::test_ai_turn_endpoint_is_rate_limited` |
| LLM05 | Supply-Chain Vulnerabilities | **In Progress** | `test_owasp_asi_evidence.py::test_asi04_supply_chain_scan_returns_result`, `test_owasp_asi_evidence.py::test_asi04_tampered_hash_blocked_on_install` |
| LLM06 | Sensitive Information Disclosure | **Shipped** | No automated test (see gap note below) |
| LLM07 | Insecure Plugin Design | **Partially Shipped** | `test_ring_policy.py::test_ring0_always_blocked`, `test_owasp_asi_evidence.py::test_asi05_ring0_always_blocked_regardless_of_role_or_trust` |
| LLM08 | Excessive Agency | **Shipped** (strengthened) | `test_ring_policy.py::test_ring1_requires_two_approvals`, `test_owasp_asi_evidence.py::test_asi09_self_approval_is_blocked` |
| LLM09 | Overreliance | **Shipped** | `test_model_router_hardening.py::test_classification_downgrade_requires_justification`, `::test_justified_downgrade_is_recorded_in_the_audit_trail` |
| LLM10 | Model Theft | **N/A / Partial** | No automated test |

---

## LLM01 – Prompt Injection

**Description:** Prompt injection attacks manipulate LLM inputs to override instructions, exfiltrate data, or cause unintended behavior. In agentic systems this is especially dangerous because agents have tool access and can take real-world actions based on injected instructions.

**Enkstein Status:** Shipped

**Evidence:**

- `backend/app/claws/arcclaw/routes.py` (lines 63–91): Every AI event submission runs a dual-layer inspection:
  1. AGT `PromptDefenseEvaluator` — 12-vector injection audit covering direct injection, indirect injection, jailbreak attempts, role confusion, instruction override, and more.
  2. `scan_text()` from `backend/app/claws/arcclaw/scanner.py` — complementary pattern-based detection for sensitive data patterns that could indicate exfiltration.
- `backend/app/trust_fabric/agt_bridge.py`: `audit_prompt()` function called on every `POST /api/v1/arcclaw/events` and `POST /api/v1/arcclaw/chat`.
- Events with injection findings are blocked or flagged before tool execution proceeds.
- Results are written to the audit log with risk scores and vector detail.

**Test Coverage:**
- `backend/tests/test_owasp_asi_evidence.py::test_asi01_prompt_injection_flagged_by_audit` — directly calls `audit_prompt()` with a "ignore previous instructions" payload and asserts `is_injection_risk=True`, `risk_score >= 20`, and at least one finding. This is the same control as ASI-01 in `docs/owasp-asi-mapping.md`.
- `backend/tests/test_owasp_asi_evidence.py::test_asi01_benign_prompt_not_flagged` — verifies the control does not produce false positives for normal security operations queries.

**Known Limitations:**
- The AGT PromptDefenseEvaluator covers 12 vectors but may not catch all novel jailbreak techniques.
- Indirect injection (data poisoning from external sources read by an agent) is detected via pattern matching only — semantic detection would require additional LLM-as-judge tooling.
- No red-team test suite is included in the repository.

---

## LLM02 – Insecure Output Handling

**Description:** Failures to validate or sanitize LLM outputs before they are passed to downstream systems, rendered in browsers, or executed as code. Can lead to XSS, SQL injection, SSRF, or arbitrary command execution.

**Enkstein Status:** Shipped

**Evidence:**

- `backend/app/claws/arcclaw/scanner.py`: `scan_text()` redacts secrets, API keys, and PII patterns from content.
- DLP scanner (`backend/app/services/finding_pipeline.py`) flags sensitive patterns in event payloads.
- API responses do not reflect raw LLM output directly to clients — outputs pass through structured Pydantic schemas before serialization.
- `backend/app/services/model_router.py::route_and_call()`: model responses are re-scanned via `scan_text()` before return, with redaction applied when sensitive patterns are detected; scan metadata is attached as `output_scan`.
- `backend/app/core/modelclaw/brain_bridge.py`: every Brain vote (browser, CLI, and profile paths) re-scans the provider response before it leaves the bridge.
- `backend/app/core/marcellus/office.py::extract_scannable_text()` + `workspace.py::_attachment_changes()`: provider-generated *binary* downloads are unpacked (OOXML/ZIP members included) and DLP-scanned before they can become a governed file change. A file carrying a live credential is dropped and reported instead of written to the project folder.

**Test Coverage:**
- `backend/tests/test_model_router_hardening.py::test_model_router_output_rescan_redacts_sensitive_response` — injects a sensitive mock model completion and asserts redaction + output-scan findings.
- `backend/tests/test_cortex_workspace.py::test_provider_download_with_secrets_is_blocked_not_written` — a leaky harvested download never reaches the folder.
- `backend/tests/test_cortex_workspace.py::test_secrets_inside_generated_office_documents_are_detected` — a credential inside compressed OOXML XML is still recovered and flagged.

**Known Limitations:**
- Frontend rendering relies on `SafeMarkdown` rather than a separate server-side HTML sanitization layer.
- Binary scanning recovers text from OOXML/ZIP and UTF-8 payloads; genuinely opaque formats (images, compiled binaries) cannot be inspected and are bounded by the extension allowlist instead.

---

## LLM03 – Training Data Poisoning

**Description:** Manipulation of training data to introduce backdoors, biases, or vulnerabilities into a model's behavior.

**Enkstein Status:** N/A

**Evidence:**

- Enkstein does not train, fine-tune, or host model weights. All LLM capability is consumed via external provider APIs (Anthropic, OpenAI, Azure OpenAI, Ollama).
- `backend/app/claws/arcclaw/llm_proxy.py`: `call_llm()` delegates to configured providers via API calls. No training pipeline exists.
- Model selection is configured via `backend/app/core/config.py` settings — no weight files are bundled.

**Test Coverage:** N/A

**Known Limitations:**
- Supply-chain risk from model providers remains (covered under LLM05). If a hosted model is poisoned by a provider, Enkstein has no detection mechanism.
- No model output consistency checks or behavior baseline comparisons are implemented.

---

## LLM04 – Model Denial of Service

**Description:** Attacks that consume excessive compute, memory, or API quota by submitting crafted inputs (very long prompts, recursive queries, resource-intensive completions).

**Enkstein Status:** Shipped (baseline)

**Evidence:**

- `backend/main.py`: `slowapi` rate limiter applied to authentication endpoints.
- `backend/app/api/routes/model_router.py`: per-IP rate limiting is enforced on `POST /api/v1/model-router/route` (30 requests / 60s window, in-process limiter).
- `backend/app/core/marcellus/ai_rate_limit.py`: the governed Cowork/Chat AI surface is rate limited **per authenticated identity** (not per IP, since every desktop request shares the loopback address). Applied to `POST /conversations/{id}/turns`, its streaming variant, and project research. Tunable via `AI_RATE_LIMIT_WINDOW_SECONDS` / `AI_RATE_LIMIT_MAX_REQUESTS`.
- Prompt length is capped by request schema (`max_length=32_000`) on model-router route payloads.

**Test Coverage:**
- `backend/tests/test_model_router_hardening.py::test_model_route_rate_limit_blocks_after_threshold` — asserts 429 after threshold is exceeded.
- `backend/tests/test_cortex_workspace.py::test_ai_turn_endpoint_is_rate_limited` — asserts the governed turn endpoint returns 429 once the per-identity budget is spent.

**Known Limitations:**
- In-process limiter is single-instance scoped; multi-replica deployments should use Redis-backed distributed limits.
- Per-tenant quotas and token-budget controls are still planned; the current limit counts requests, not tokens or fan-out cost.

---

## LLM05 – Supply-Chain Vulnerabilities

**Description:** Vulnerabilities introduced through third-party model providers, plugins, datasets, fine-tuning services, or compromised Python packages in the dependency graph.

**Enkstein Status:** In Progress

**Evidence:**

- `backend/app/services/secrets_manager.py`: Connector credentials encrypted with Fernet (AES-128-CBC + HMAC). Keys never stored in plaintext.
- `requirements.txt`: PyJWT pinned to 2.9.0 (patched version). `python-multipart` pinned to 0.0.12 (patched for CVE-2024-53498).
- Connector field validation in `backend/app/api/routes/connectors.py` prevents SSRF via URL validation.
- `.github/workflows/ci.yml` (`supply-chain-security` job): generates CycloneDX SBOM artifacts for backend/frontend and publishes Python + npm dependency audit reports each run.
- `backend/app/api/routes/exchange.py::install_package()`: exchange package installation now enforces manifest checksum integrity and rejects forged `x-package-sha256` headers.

**Test Coverage:**
- `backend/tests/test_owasp_asi_evidence.py::test_asi04_tampered_hash_blocked_on_install` — verifies forged checksum headers are rejected during exchange install.

**Known Limitations:**
- Supply-chain reports are currently non-blocking CI artifacts; policy gating thresholds are not yet enforced as required checks.
- Model provider API keys are encrypted at rest but transmitted via HTTPS to third-party endpoints — provider compromise is out of scope for Enkstein's threat model.
- Plugin/connector installs require approval via policy (ZT — Block Connector Install Without Approval) but connector code is not sandboxed at the OS level.

---

## LLM06 – Sensitive Information Disclosure

**Description:** LLMs inadvertently revealing sensitive data — PII, credentials, financial data, or system internals — through model memorization, prompt echoing, or insufficient output filtering.

**Enkstein Status:** Shipped

**Evidence:**

- `backend/app/services/secrets_manager.py`: All connector credentials stored Fernet-encrypted at rest. The encryption key is auto-generated per deployment in `backend/.secrets/` (gitignored).
- `backend/app/claws/arcclaw/scanner.py`: `scan_text()` pattern-matches for API keys, tokens, AWS credentials, credit card numbers, SSNs, and email addresses. Applied to every submitted prompt.
- `backend/app/api/routes/exec_channels.py`: Credential injection endpoint never returns secret values via API — secrets are injected into agent runtime only (`"note": "Secret value is never returned via API"`).
- Credential broker returns `secret_path` and `secret_type` but not the secret value itself.
- Audit log records actor, action, and outcome but redacts sensitive parameter values.
- `backend/app/api/routes/connectors.py`: Credential hints are masked in responses (last 4 characters only).

**Test Coverage:** No automated test for the DLP output paths. `scan_text()` is exercised manually via `POST /api/v1/arcclaw/events` and the `arcclaw/chat` endpoint, but no isolated unit test covers the redaction pipeline.

**Coverage Gap:** `test_platform_regressions.py` does not include credential/secret exposure tests. The scanner is confirmed to redact AWS keys, API tokens, credit card numbers, and SSNs in code review, but no automated assertion exists for this behavior. This is the primary LLM06 test gap.

**Known Limitations:**
- Output scanning (LLM responses) is not systematically applied — model completions are not re-scanned before storage (see LLM02).
- Audit log entries include `detail_json` that could contain sensitive context if callers are not careful.
- No data classification framework (e.g., tagging fields as PII/PHI/PCI) is integrated into the data model.

---

## LLM07 – Insecure Plugin Design

**Description:** Plugin/tool interfaces that are overly permissive, lack input validation, do not enforce authentication, or allow SSRF, privilege escalation, or injection via tool parameters.

**Enkstein Status:** Shipped (baseline)

**Evidence:**

- `backend/app/services/ring_policy.py` (added in this release): Ring-based execution isolation classifies every action_type and exec channel into ring0..ring3, enforcing privilege tiers with deterministic approval gates. Prevents low-privilege agents from invoking privileged actions.
- `backend/app/api/routes/exec_channels.py`: Ring policy check applied before executing approved requests. ring0 actions are hard-blocked.
- `backend/app/services/connector_tester.py`: SSRF protection — connector test URLs are validated against a blocklist of private/reserved IP ranges before requests are made.
- Connector field validation (URL format, required fields) in connector creation routes.
- `backend/app/claws/arcclaw/security_agent.py`: `TOOLS` list explicitly bounds what tools the security agent can invoke.

**Test Coverage:**
- `backend/tests/test_ring_policy.py` — 32 tests covering ring classification, evaluation, role escalation blocking, and channel mapping.
- `backend/tests/test_owasp_asi_evidence.py::test_asi05_ring0_always_blocked_regardless_of_role_or_trust` — exercises the same ring0 unconditional block that prevents arbitrary code execution via insecure plugins.
- `backend/tests/test_owasp_asi_evidence.py::test_asi02_viewer_role_denied_ring1_action` — verifies low-privilege roles cannot invoke ring1 privileged plugin actions.

**Known Limitations:**
- Tool parameters passed to agents are not schema-validated against a strict allowlist — callers can supply arbitrary JSON.
- No runtime sandbox (seccomp, container isolation) prevents a plugin from making unexpected system calls.
- Plugin authentication is via the platform JWT — there is no per-plugin credential rotation or scoped token.
- The ring policy covers exec channels and remediation approvals, but not all tool invocation paths in AI Security's security agent.

---

## LLM08 – Excessive Agency

**Description:** LLM agents given more capabilities, permissions, or autonomy than needed to complete their task — leading to unauthorized actions, data destruction, or unintended side effects.

**Enkstein Status:** Shipped (strengthened by ring policy in this release)

**Evidence:**

- `backend/app/services/ring_policy.py`: Ring-based privilege isolation. Every action maps to ring0..ring3. ring0 is unconditionally blocked. ring1 (quarantine, suspend, revoke, delete_secret) requires 2 independent approvals. ring2 requires trust_score >= 80 or 1 approval. ring3 (read-only) is auto-allowed.
- `backend/app/api/routes/exec_channels.py` (`execute_request`): Ring policy evaluated before execution. Hard-blocked (ring0, low-role ring1) requests are refused with HTTP 403.
- `backend/app/api/routes/remediation.py` (`approve_action`): Ring policy check before calling `approve_remediation` — blocks role-escalation attempts.
- `backend/app/api/routes/exec_channels.py` (`approve_request`): Self-approval is blocked (`approver == r.requested_by` → 403). Dual approvals required for shell/browser/credential channels.
- Production gate system (`ProductionGate`) enforces dual approval for all production changes.
- Policy engine (`backend/app/services/policy_engine.py`): AGT/Swarm governance policies enforce swarm parallelism limits and approval gates on containment actions.
- `backend/app/services/exec_policy.py`: `evaluate_exec_request()` blocks commands matching destructive/credential-access patterns.

**Test Coverage:**
- `backend/tests/test_ring_policy.py::test_ring1_requires_two_approvals` — verifies that ring1 (privileged) actions always require 2 approvals regardless of trust score.
- `backend/tests/test_ring_policy.py::test_ring1_high_trust_still_requires_approval` — confirms trust score alone cannot bypass the dual-approval gate.
- `backend/tests/test_owasp_asi_evidence.py::test_asi09_self_approval_is_blocked` — HTTP-level integration test asserting that the same identity cannot approve its own exec channel request (HTTP 403), closing the self-approval path for excessive agency via approval fraud.

**Known Limitations:**
- The AI Security agent (`security_agent.py`) tool list is bounded but not dynamically validated against the ring policy at invocation time.
- Workflow runner (`workflow_runner.py`) can chain multiple actions — inter-step privilege accumulation is not yet tracked.
- No per-session capability token — an agent that obtains approval for one action could theoretically reuse context for adjacent actions.

---

## LLM09 – Overreliance

**Description:** Users or automated systems trusting LLM outputs without verification — leading to incorrect decisions, missed alerts, or automated actions based on hallucinated information.

**Enkstein Status:** Shipped (baseline)

**Evidence:**

- `backend/app/claws/arcclaw/routes.py`: Every AI event is stored with a `risk_score` and `outcome` computed by the AGT audit + scanner. Users can see these scores in the dashboard.
- AI events are never auto-executed — they are written to the event log and surface as findings requiring human review or policy-matched auto-response.
- Remediation playbooks have `requires_approval` flag — high-risk playbooks require human sign-off before execution.
- Findings include `severity` and `confidence` fields to help operators contextualize AI-generated detections.
- `backend/app/services/model_router.py::route_and_call()`: override paths record explicit audit fields (`override_used`, `override_reason`) to make human override behavior attributable.
- Lowering a detected data classification (the direction that can route restricted content to a cloud provider) is refused unless an `override_reason` is supplied, and the audit entry retains both the detected and the asserted level via `classification_downgraded` / `detected_sensitivity`.

**Test Coverage:**
- `backend/tests/test_model_router_hardening.py::test_classification_downgrade_requires_justification` — an unjustified downgrade is refused.
- `backend/tests/test_model_router_hardening.py::test_justified_downgrade_is_recorded_in_the_audit_trail` — detected level, asserted level, and reason all survive into the audit entry.
- `backend/tests/test_model_router_hardening.py::test_upgrade_override_needs_no_justification` — raising the classification stays frictionless.

**Known Limitations:**
- Risk scores are displayed to users but there is no enforcement mechanism preventing operators from always approving high-risk AI recommendations without review.
- No counter-factual or uncertainty quantification is presented alongside AI findings.
- The platform now logs model routing overrides; broader analyst dismiss/accept workflow telemetry across all UI surfaces remains in progress.
- No calibration data or false-positive rate reporting is implemented.

---

## LLM10 – Model Theft

**Description:** Attackers extracting model weights, system prompts, or training data through API abuse, timing attacks, or adversarial probing.

**Enkstein Status:** N/A / Partial

**Evidence:**

- Enkstein does not host model weights. All inference is via provider APIs (Anthropic, OpenAI, Azure OpenAI, Ollama). Model theft from the Enkstein platform itself is not applicable.
- `backend/app/services/secrets_manager.py`: Provider API keys encrypted at rest with Fernet. Keys are never logged or returned via API.
- System prompts used by AI Security's security agent (`backend/app/claws/arcclaw/security_agent.py`) are stored in source code — not separately protected.
- No system prompt confidentiality enforcement (prompt extraction via token probabilities or completion nudging is not mitigated).

**Test Coverage:** N/A

**Known Limitations:**
- System prompts are visible in source code — if source is leaked, prompt intellectual property is exposed.
- No mechanism to detect adversarial probing attempts (repeated queries designed to reconstruct system prompt).
- Provider-side model theft is entirely dependent on the provider's security posture.

---

*Last updated: 2026-05-31. Maintained by the Enkstein security team.*
