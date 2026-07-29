# regentclaw-core

The embeddable heart of [RegentClaw](https://github.com/wcoreiron-rgb/enkstein) —
its Zero Trust governance and scanning primitives, runnable **in-process with no
server, no database, no Docker**. Just `pip install regentclaw-core`.

Use it to drop RegentClaw's enforcement logic directly into your own scripts,
agents, CI pipelines, or pre-commit hooks.

## Install

```bash
pip install ./regentclaw_core-0.5.7-py3-none-any.whl
```

Only dependency: `cryptography`.

## What's included

| Primitive | Import | Purpose |
|---|---|---|
| Execution Ring Policy | `classify_ring`, `evaluate_ring` | Classify any action into a privilege ring (ring0 blocked → ring3 auto-allow) and get a deterministic allow / approve / deny decision. |
| Provenance | `verify_package`, `compute_manifest_hash`, `verify_manifest_signature` | SHA-256 + Ed25519 verification for skill/plugin manifests. |
| Secret & PII Scanner | `scan_text`, `classify_prompt` | Detect exposed API keys, secrets, and PII in text/code; classify prompt intent. |

## Examples

**Gate an action locally:**
```python
from regentclaw_core import classify_ring, evaluate_ring

ring = classify_ring("quarantine_device")          # -> "ring1"
decision = evaluate_ring(ring, trust_score=72, caller_role="analyst")
if not decision["allowed"]:
    raise PermissionError(decision["deny_reason"])
```

**Scan for secrets before commit (e.g. in a pre-commit hook):**
```python
from regentclaw_core import scan_text

result = scan_text(open("config.env").read())
if result.is_sensitive:
    print("❌ secrets detected:", result.findings)
    raise SystemExit(1)
```

**Verify a manifest's integrity:**
```python
from regentclaw_core import verify_package

res = verify_package(manifest_json, expected_hash=h, signature_b64=sig, public_key_pem=key)
assert res.valid, res.error
```

## Scope

This package is the subset of RegentClaw that is genuinely standalone. The full
platform — 24+ security claws, multi-agent swarms, autonomous remediation, and
the Trust Fabric audit layer — runs as a server (FastAPI + Postgres). For that,
see the [main repo](https://github.com/wcoreiron-rgb/enkstein) or talk to it
with [`regentclaw-cli`](https://github.com/wcoreiron-rgb/enkstein/tree/main/cli)
and [`regentclaw-mcp`](https://github.com/wcoreiron-rgb/enkstein/tree/main/mcp-server).

> These modules are mirrored from the main repo's backend and kept in sync via
> `scripts/sync_core.sh`. The canonical source lives in `backend/app/`.

## License

MIT
