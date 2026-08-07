# Enkstein Guard

Blocks secrets and destructive commands **before** your AI coding agent runs them.

Works with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and
[Codex CLI](https://developers.openai.com/codex/cli). No account, no backend,
no Docker — install it and your next tool call is governed.

## Install

```bash
claude plugin marketplace add wcoreiron-rgb/enkstein
claude plugin install enkstein-guard@enkstein
```

## What it stops

Enkstein Guard runs on every `Write`, `Edit`, and `Bash` call your agent makes.
When it finds a problem the tool call never executes, and the agent is told why
so it can correct itself.

| Blocked outright | Held for approval |
|---|---|
| AWS access keys, private keys | Hardcoded passwords, bearer tokens |
| OpenAI / Anthropic / GitHub / Slack / Google keys | `git push --force`, `git reset --hard` |
| Database URLs with live credentials | Reading `~/.ssh/id_rsa`, `~/.aws/credentials` |
| `curl … \| sh` | `sudo …`, `npm publish` |
| `rm -rf /`, `rm -rf ~`, writes to `/dev/…` | |

## It also governs what you type

A secret pasted into chat leaves your control the moment you press enter — it
enters the provider's context, their logs, and usually their retention. Guard
runs on prompt submission too, so the message never leaves your machine:

```text
Enkstein stopped this message before it was sent.
AWS access key (line 1): AKIA3Z…OPAS
Rule: prompt.aws_access_key
```

Private keys and live connection strings are refused outright. Access keys,
provider tokens, payment cards, passwords, and SSNs are held for your decision.
Payment cards must pass a Luhn check, and an SSN needs nearby context, so order
numbers and version strings don't trip it.

It is deliberately quiet about things that only *look* dangerous:
`rm -rf ./build`, `git push --force-with-lease`, `postgresql://user:pass@localhost/db`
in an `.env.example`, and documented placeholders like `AKIAIOSFODNN7EXAMPLE`
all pass without comment. A security tool that cries wolf gets uninstalled.

## Two tiers

**Standalone (default).** Pure-Python pattern and structural analysis, no
network calls, no dependencies beyond Python 3. Every decision is local.

**Connected.** Set `ENKSTEIN_API_URL` (and `ENKSTEIN_TOKEN`) and the hook also
consults a running Enkstein backend. Every active CoreOS policy is evaluated
across Global, Module, Connector, and Identity scopes; enforcement retains the
console's priority order and first-match-wins behavior. The response includes
the catalog, evaluated, matched, and invalid-condition counts for audit proof.

Guard never sends the raw prompt, file content, command arguments, path, or
working directory to this endpoint. Trust Fabric receives policy IDs, fixed
classification labels, lengths, and SHA-256 digests, so connecting centralized
governance cannot create a second copy of the sensitive value in Events.

The two tiers **combine, strictest wins** — connecting a backend is purely
additive and can never reduce what the local pack already catches. If the
backend does not answer within two seconds the local decision stands, so a slow
or stopped runtime never blocks your editor.

```bash
export ENKSTEIN_API_URL=http://localhost:8000
export ENKSTEIN_TOKEN=…
```

CoreOS policy behavior is literal. If **Block Shell Execution** is active, a
connected Guard shell call is denied even when the standalone command pack
would allow it. Disable or change that policy in Enkstein when your tenant wants
approval or monitoring instead.

## Private policy packs

The rules that ship in this repository are open, because a client-side regex is
extractable from an installed plugin no matter how it is encoded. Shipping an
obfuscated bundle would buy the appearance of secrecy and none of the substance.

Detection content you license separately stays yours. A pack is generated on
your own machine from a source you already have, written outside the repository,
and loaded at runtime:

```bash
python3 tools/build_policy_pack.py --source /path/to/engine.py --name mypack
# -> ~/.enkstein/policy-packs/mypack.json  (mode 0600, never committed)
```

For a numbered 60-policy source, the builder preserves all 60 policy identities,
names, severities, risk scores, and scopes. Policies 1 and 2 delegate to
Enkstein's context-aware SSN and Luhn-validated payment-card rules rather than
importing their noisier fallback expressions. The current private source builds
60 policies backed by 228 local rules.

Point `ENKSTEIN_POLICY_PACK` at a different file or directory to override the
default location. Pack rules combine with the built-in pack, strictest wins, so
a pack can only add enforcement.

Before trusting a pack, measure it against real code:

```bash
python3 tools/build_policy_pack.py --source … --measure ~/src/your-repo
```

Any rule matching more than about 1% of ordinary source files belongs in
`PROSE_ONLY` — it will fire on normal work, and a guard that cries wolf gets
uninstalled. Rules the open pack already covers more carefully (SSN, payment
cards) are never imported, because the imported forms are context-free and
would undo tuning that took real false positives to get right.

### Actions

| Action | Effect |
| --- | --- |
| `deny` | The call is blocked. |
| `require_approval` | The call is held for a human decision. |
| `mask` | The value is replaced and the call proceeds. |
| `monitor` | Recorded, never interrupts. |

Masking rewrites the tool input through `updatedInput`, so a file write or shell
command continues with the sensitive value replaced and everything else intact.
That channel is `PreToolUse`-only: a submitted prompt cannot be rewritten, so a
mask rule that fires on a prompt escalates to `require_approval` rather than
reporting success while the raw text still reaches the provider.

## Design notes

The hook fails **open**: a crash, malformed input, or unreachable backend exits
0 and allows the call. For a local advisory tier that is the right trade — a
broken security hook must never become a broken editor. Non-bypassable
enforcement is a property of the connected tier, where policy lives server-side
and decisions are audited.

Block reasons never echo the secret they found. `AKIA3ZK7QWERTYUIOPAS` is
reported as `AKIA3Z…OPAS`: enough to locate it, not enough to leak it into a
transcript, a log, or a model's context.

Secret patterns are ported from Enkstein's ArcClaw scanner so a finding here
means the same thing it means in the console.
