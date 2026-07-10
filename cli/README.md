# RegentClaw CLI

Command-line client for the [RegentClaw](https://github.com/wcoreiron-rgb/regentclaw)
Zero Trust Security Ecosystem. Drives a running RegentClaw server over its REST API —
the same way `kubectl` talks to a cluster.

## Install

```bash
pip install ./regentclaw_cli-0.7.0-py3-none-any.whl
# or from source:
pip install ./cli
```

Download the wheel from the matching GitHub Release. PyPI publication is not
part of the current release workflow.

## Configure

```bash
export REGENTCLAW_API_URL=http://localhost:8000   # your RegentClaw server
export REGENTCLAW_TOKEN=<jwt>                      # required when server runs DEBUG=false
# get a token: curl -X POST $REGENTCLAW_API_URL/api/v1/auth/token -d 'username=admin&password=...'
```

In local/DEBUG mode the server bypasses auth, so `REGENTCLAW_TOKEN` is optional.

## Usage

```bash
regentclaw status dashboard            # platform overview
regentclaw status connectors           # connector health
regentclaw connectors list             # list connectors
regentclaw connectors test okta        # test a connector's live credentials
regentclaw run workflow <name>         # trigger a workflow
regentclaw run status <run-id>         # check a run
regentclaw policies list               # list security policies
regentclaw approvals list              # pending agent-action approvals
regentclaw approvals approve <id>      # approve a queued action
regentclaw evidence collect --framework soc2   # compliance evidence export
regentclaw incidents list              # security incidents
regentclaw skill-packs list            # installed skill packs
```

Run `regentclaw --help` or `regentclaw <group> --help` for the full command tree.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REGENTCLAW_API_URL` | `http://localhost:8000` | Server base URL |
| `REGENTCLAW_TOKEN` | _(none)_ | Bearer JWT for authenticated servers |
| `REGENTCLAW_TIMEOUT` | `30` | Request timeout (seconds) |

## License

MIT
