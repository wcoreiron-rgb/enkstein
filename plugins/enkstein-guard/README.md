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
consults a running Enkstein backend, so tenant policy, approval queues,
isolation, and the console audit trail all apply.

The two tiers **combine, strictest wins** — connecting a backend is purely
additive and can never reduce what the local pack already catches. If the
backend does not answer within two seconds the local decision stands, so a slow
or stopped runtime never blocks your editor.

```bash
export ENKSTEIN_API_URL=http://localhost:8000
export ENKSTEIN_TOKEN=…
```

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
