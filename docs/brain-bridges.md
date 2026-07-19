# Enkstein Brain Bridges

Enkstein can consult model runtimes authenticated on the desktop while the
governed FastAPI runtime remains in Docker. Vendor credentials stay in the
vendor-owned host credential store. They are not copied into containers,
connector records, prompts, logs, or API responses.

## Architecture

```text
Model Cortex / Security Arm
        |
        v
Trust Fabric policy decision
        |
        v
Docker backend -- shared-secret HTTP --> native host Brain Bridge
                                   |             |               |
                                   v             v               v
                              Vendor CLI    Desktop app UI   Local workspace
```

The native installer generates a random 256-bit bridge secret, stores it in
the user's Enkstein application-support directory with owner-only
permissions, and injects only that bridge secret and local endpoint into the
backend container. The bridge rejects non-local/private peers and compares the
secret in constant time.

macOS runs the signed universal helper as a per-user LaunchAgent so it remains
available while the console is closed. Windows starts the equivalent local
bridge as a hidden background process from the signed installer runtime.

## Codex Subscription Bridge

The bridge uses the official Codex executable and its existing ChatGPT-managed
login. Invocations are ephemeral, use a new empty temporary directory, run in a
read-only sandbox, inherit no project rules, and have a 24,000-character input
limit and 180-second deadline.

Desktop Cowork Agent tools use the official long-lived `codex app-server`
stdio protocol when a project has an approved native folder and the runtime
group is Hybrid or Cloud. Enkstein derives an opaque scope from tenant, owner,
Project, conversation, and the native folder grant; the browser cannot provide
a cwd, thread id, scope digest, or folder token. The bridge resumes one thread
per scope, supports read-only and workspace-write sandboxes, streams only
allowlisted agent/plan/diff events, and maps command/file approvals to governed
one-shot decisions. General permission expansion is deny-only and unknown
server requests are declined. Prompts travel in structured JSON-RPC over stdin,
never argv, and session persistence contains only owner-readable opaque
scope/thread metadata.

Every start, turn, status poll, approval, and cancellation receives a Trust
Fabric decision. Restricted and top-secret conversations are rejected before
the external CLI is invoked. Sensitive patterns in otherwise permitted input
are redacted. Transient App Server output is visible in Cowork but is not yet
written into encrypted conversation history. App Server patches, tests, and
artifacts are not yet normalized into durable structured records.

Check the host session with `codex login status`. Authenticate using the
official `codex login` flow when needed.

Brain Connections performs a governed live status check on page open, explicit
refresh, and when the console regains focus. A detected executable is never
sufficient: Codex must report an authenticated ChatGPT session and Claude Code
must pass its official `auth status` command. Short bridge failures are cached
for at most four seconds; a forced refresh bypasses that negative cache.

## Claude Agent SDK Bridge

The bridge detects the official `claude` host runtime and checks its
authentication status. Prompt mode runs with tools disabled and noninteractive
permissions. If the runtime is absent, unauthenticated, or no longer supported
for subscription usage, Enkstein reports the Brain as unavailable and does not
silently switch to an API key.

Anthropic's subscription and Agent SDK terms can change. Operators are
responsible for using an account and distribution model allowed by current
Anthropic terms. Enkstein does not extract browser cookies, desktop session
tokens, OAuth tokens, or undocumented credentials.

Claude Code CLI is the preferred Claude subscription path. When it is genuinely
ready, Brain Connections hides the Claude Browser Session entry. ChatGPT and
Gemini browser entries remain available for explicit migration/testing, and
Claude Browser reappears if the CLI becomes unhealthy. CLI prompts are written
to stdin; Codex runs read-only and Claude runs with an empty tool set. Prompt
text is never placed in process arguments.

## Desktop App Session Bridge (macOS preview)

ChatGPT Desktop and Claude Desktop can be selected as explicit Brains on macOS.
Enkstein uses the operating system Accessibility API to open the visible,
user-installed application, start a new conversation, enter the already
governed prompt, and read the visible completed response. The user must grant
Enkstein Accessibility permission. Enkstein does not read cookies, copy
session tokens, call private endpoints, or store the vendor account credential.

Desktop sessions are never chosen by automatic routing because they move focus
to another application. The user must select one directly or include it in a
Multi-Brain Swarm. The app remains visible while it works, vendor sign-in is
validated by the vendor UI, and normal provider plan limits, rate limits, and
terms still apply. A desktop UI change can temporarily make this preview bridge
unavailable; the CLI, API, and local model paths remain the stable unattended
options. Enkstein performs a live compatibility check and does not mark an app
ready unless its current version exposes a writable message field through the
macOS Accessibility tree.

Desktop requests are serialized because keyboard focus is a process-global
resource. The bridge verifies the exact frontmost vendor process immediately
before submission and fails closed if focus changes. The submitted prompt and
vendor response remain in the vendor-managed conversation history according to
that account's own retention settings.

## Browser Session Bridge

The Enkstein Browser Companion connects visible signed-in tabs for ChatGPT,
Claude, and Gemini. It uses public page controls rather than cookies, account
tokens, hidden endpoints, or copied browser profiles. Browser Brains are
explicit choices and are not added to silent automatic routing.

One-time setup on Chrome or Edge:

1. Open **Brain Connections** and select **Install companion**.
2. Open the browser's Extensions page, enable Developer mode, select **Load
   unpacked**, and choose the folder Enkstein opened.
3. Select **Pair browser**. Enkstein opens a five-minute loopback pairing page
   in the default browser; the extension exchanges that one-time code for an
   owner-only local bridge token. A new pairing rotates that token and
   invalidates older companion sessions.
4. Keep a signed-in `chatgpt.com`, `claude.ai`, or `gemini.google.com` tab open.
   Refresh Brain Connections and select the corresponding Browser Session.

The companion is limited by its manifest to those three provider origins and
the Enkstein loopback bridge. It reports only providers with an open tab,
submits the already governed/redacted prompt, waits for a stable visible
response, and returns that text for output scanning and audit. Vendor UI
changes can temporarily break a selector; Enkstein fails closed and leaves
CLI, API, and local Brains available. Provider plan limits and account terms
continue to apply.

Each Enkstein conversation receives an opaque tenant-scoped browser session
key. The companion opens one provider tab for the first turn and reuses that
same tab for later turns in the conversation. Starting or branching an
Enkstein conversation creates a separate provider thread. The companion stores
the provider conversation URL locally, not the provider authentication token,
so a closed tab or restarted browser can reopen the same provider thread.
ChatGPT and Gemini mappings refresh after delayed SPA navigation and retain
only sanitized origin plus pathname. Turn completion is correlated by provider
message identity (or an extension marker), submission time, and the last known
assistant identity; it does not depend on response counts or response text.
The durable task journal stores only lifecycle metadata and bounded error codes.
Detailed operator errors remain transient in memory, and prompts, responses,
paths, cookies, tokens, and provider page content are excluded from the journal.

Cowork sends explicitly selected text files in full up to a combined
100,000-character limit. It does not silently truncate selected code. A larger
selection is rejected with instructions to select fewer files; general project
context may be bounded and is visibly marked when truncated.

## Consensus routing

`POST /api/v1/modelclaw/consensus` accepts up to eight unique sources:

- `codex_subscription`
- `claude_subscription`
- `chatgpt_desktop` (explicit, visible macOS session)
- `claude_desktop` (explicit, visible macOS session)
- `chatgpt_browser` (paired visible browser tab)
- `claude_browser` (paired visible browser tab)
- `gemini_browser` (paired visible browser tab)
- `profile:<model-profile-name>` for approved API or local profiles

Trust Fabric evaluates each source. Model profile tenant, Capability, and data
classification constraints are enforced again before provider execution.
Only successful real responses count. Deterministic evidence-overlap scoring
reports agreement and confidence without exposing private chain-of-thought.
The primary response is selected with explicit provenance; all unavailable and
denied sources remain visible to the operator.

The request also accepts `runtime_group=local|hybrid|cloud`. Local retains only
approved local profiles, Hybrid stable-partitions local profiles before CLI/API
fallbacks, and Cloud excludes local, desktop, and browser sources. Browser and
desktop sessions remain explicit-only. Restricted and top-secret adaptive
requests are pinned to the local boundary regardless of group.

Sensitive input patterns are redacted before any subscription invocation.
`restricted` and `top_secret` requests are rejected for subscription Brains;
they require an approved local model profile.

### Provider maturity in 0.3.7

Shipped Model Cortex execution paths are Codex CLI subscription, Claude Code
CLI subscription, Ollama, OpenAI API, Anthropic API, Gemini API, and NVIDIA NIM.
Azure OpenAI remains available through the legacy sensitivity router but is
disabled in Model Cortex profiles until a native profile adapter is shipped.
Gemini CLI OAuth, DeepSeek API, Moonshot/Kimi API, Kimi CLI, and configurable
custom OpenAI-compatible endpoints are planned and are not reported ready by
this release. Kimi CLI remains fail closed because no verified unattended,
tool-disabled execution contract has been implemented.

Runtime groups are carried on each request and remembered by the local console.
They are not persisted per conversation/Project because the current schema has
no compatible field and 0.3.7 introduces no migration. Per-tenant specialist
role-route persistence is likewise planned. The bounded
`/modelclaw/task-graph` contract does support explicit per-node roles,
dependencies, ordered sources, timeouts, and provenance without adding a
second model router.

Context provenance is finalized after Gateway routing. It records the actual
ordered adapter attempts, Trust Fabric outcome, selected provider/model,
fallback reason, effective classification, and each artifact's compiled
disposition, redaction state, digest, id, and line citations. This is runtime
attempt provenance; it does not claim an upstream vendor accepted or retained a
prompt when an adapter reports unavailable.

### Multi-Brain Swarm execution

Cowork can run all policy-approved subscription, API, and local Brains in
parallel. Trust Fabric evaluates every source independently before execution;
a denied Brain remains visible in the vote record but is never invoked. The
result preserves each successful response, latency, model provenance, and
agreement score so the Cortex can synthesize evidence without hiding dissent.

The turn endpoint also exposes a server-sent event stream for lifecycle,
Brain-completion, governed response, and proposed-change updates. Provider
responses are completed and inspected before Enkstein streams the approved
response to the desktop; provider-token streaming is not yet enabled.

## Cowork file authority

Cowork has no blanket access to Desktop, Documents, or the rest of the host.
The user explicitly selects a project folder, and Enkstein issues a scoped
native token for that folder only. Direct user edits can create, update,
rename, move, or trash supported files inside that boundary.

Brain-generated changes are different: Brains return a structured change
proposal, Trust Fabric evaluates it, and Cowork shows the proposed path and
content for human review. Enkstein writes to the native folder only after the
user selects **Apply**. Path traversal, protected directories, stale file
versions, unsafe content, and denied policy decisions fail closed.

## Governed research and MCP tools

Cowork research accepts up to eight explicit public HTTPS sources. Enkstein
evaluates the research request and each source through Trust Fabric before
network access, rejects credentials and non-standard ports, resolves and blocks
private/link-local/metadata networks, disables redirects, limits responses to
512 KB, accepts text formats only, and scans retrieved text for sensitive data
and hostile prompt instructions.

The resulting source bundle and cited report are stored as encrypted, versioned
project artifacts. Citation metadata includes the source URL, retrieval time,
content type, and SHA-256 digest. Invalid bracketed citation numbers emitted by
a Brain are replaced with an unverified marker rather than presented as valid
evidence.

Enkstein exposes a deliberately small MCP capability registry:

- `browser.fetch` / `marcellus_browser_fetch`: retrieve one governed public
  source; it cannot access localhost, private networks, or arbitrary ports.
- `workspace.search` / `marcellus_workspace_search`: search active artifacts
  inside one owner-authorized Cowork project.

The stdio MCP server is only a stateless bridge to these authenticated backend
routes. It does not receive shell authority, desktop-wide file access, or a way
to register arbitrary executable tools.

## API Brains

Enkstein also supports approved API profiles for NVIDIA NIM, OpenAI,
Anthropic, Azure OpenAI, and Google Gemini. Gemini uses the documented Gemini
Developer API with a connector-managed API key and defaults to the stable
`gemini-2.5-flash` profile. Connector setup performs a real minimal generation;
fake keys are not marked connected. Enkstein does not extract or reuse Gemini
desktop/browser OAuth sessions.

## Local Ollama Brains

The desktop package reaches the host Ollama service through Docker Desktop's
private host gateway. Enkstein queries `/api/tags` and records the exact model
used. If a profile's default is not installed, automatic routing selects a real
installed model in this order: `MARCELLUS_OLLAMA_MODEL`, the profile default,
the security-tuned Regent model, Qwen 2.5 7B, Llama 3.2, Phi-3, then the first
installed model. An explicit model choice never falls through silently; it is
accepted only when that model (including its equivalent `:latest` alias) exists.

Ollama is local and requires no provider key. Install it, pull at least one
model, and leave its service running. The **Brains** page shows live reachability
and installed model names.

## Supported account boundaries

- A ChatGPT subscription can authenticate the official Codex runtime used by
  the Codex Subscription Bridge. On macOS, the separate opt-in Desktop Session
  Bridge can also operate the visible signed-in ChatGPT app through
  Accessibility. Neither path turns the subscription into an API credential.
- Direct GPT chat inside Enkstein uses an approved OpenAI API connector. OpenAI
  manages API usage and ChatGPT subscriptions separately.
- Claude Pro or Max can authenticate the official Claude Code host runtime.
  Direct Claude API profiles use an Anthropic API key or supported workload
  identity instead.
- Gemini uses a restricted Gemini API key today. Google desktop OAuth is a
  viable future connector, but Enkstein does not extract Google browser or
  Gemini application sessions.
- Consumer web chat pages are not treated as model APIs. Enkstein does not scrape
  consumer sessions, browser cookies, or undocumented private endpoints. The
  Desktop Session Bridge automates only a visible installed app after explicit
  operating-system permission.

Browser research and MCP tools remain separate from model authentication: they
retrieve explicitly approved public sources or authorized connector data and
return evidence through Trust Fabric.

## Security limitations

- The bridge is a local desktop capability, not a remote inference gateway.
- Subscription availability depends on installed official vendor runtimes and
  their current account policies.
- The reasoning bridge does not grant shell, filesystem, browser, connector,
  or remediation authority. Those actions must return through Enkstein policy
  and approval paths.
- Consensus confidence is operational agreement metadata, not a guarantee of
  factual correctness. Operators must inspect evidence before high-impact
  action.
