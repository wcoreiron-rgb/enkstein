# Marcellus Brain Bridges

Marcellus can consult model runtimes authenticated on the desktop while the
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
                                           |              |
                                           v              v
                                    Codex subscription  Claude runtime
```

The native installer generates a random 256-bit bridge secret, stores it in
the user's Marcellus application-support directory with owner-only
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

Check the host session with `codex login status`. Authenticate using the
official `codex login` flow when needed.

## Claude Agent SDK Bridge

The bridge detects the official `claude` host runtime and checks its
authentication status. Prompt mode runs with tools disabled and noninteractive
permissions. If the runtime is absent, unauthenticated, or no longer supported
for subscription usage, Marcellus reports the Brain as unavailable and does not
silently switch to an API key.

Anthropic's subscription and Agent SDK terms can change. Operators are
responsible for using an account and distribution model allowed by current
Anthropic terms. Marcellus does not extract browser cookies, desktop session
tokens, OAuth tokens, or undocumented credentials.

## Consensus routing

`POST /api/v1/modelclaw/consensus` accepts up to eight unique sources:

- `codex_subscription`
- `claude_subscription`
- `profile:<model-profile-name>` for approved API or local profiles

Trust Fabric evaluates each source. Model profile tenant, Capability, and data
classification constraints are enforced again before provider execution.
Only successful real responses count. Deterministic evidence-overlap scoring
reports agreement and confidence without exposing private chain-of-thought.
The primary response is selected with explicit provenance; all unavailable and
denied sources remain visible to the operator.

Sensitive input patterns are redacted before any subscription invocation.
`restricted` and `top_secret` requests are rejected for subscription Brains;
they require an approved local model profile.

## Security limitations

- The bridge is a local desktop capability, not a remote inference gateway.
- Subscription availability depends on installed official vendor runtimes and
  their current account policies.
- The reasoning bridge does not grant shell, filesystem, browser, connector,
  or remediation authority. Those actions must return through Marcellus policy
  and approval paths.
- Consensus confidence is operational agreement metadata, not a guarantee of
  factual correctness. Operators must inspect evidence before high-impact
  action.
