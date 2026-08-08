# Enkstein CLI

Command-line client for the [Enkstein](https://github.com/wcoreiron-rgb/enkstein)
Zero Trust Security Ecosystem. Drives a running Enkstein server over its REST API —
the same way `kubectl` talks to a cluster.

## Install

```bash
pip install ./enkstein_cli-0.8.4-py3-none-any.whl
# or from source:
pip install ./cli
```

Download the wheel from the matching GitHub Release. PyPI publication is not
part of the current release workflow.

## Configure

```bash
export ENKSTEIN_API_URL=http://localhost:8000   # your Enkstein server
export ENKSTEIN_TOKEN=<jwt>                      # required when server runs DEBUG=false
# get a token: curl -X POST $ENKSTEIN_API_URL/api/v1/auth/token -d 'username=admin&password=...'
```

In local/DEBUG mode the server bypasses auth, so `ENKSTEIN_TOKEN` is optional.

## Usage

```bash
enkstein status dashboard            # platform overview
enkstein status connectors           # connector health
enkstein connectors list             # list connectors
enkstein connectors test okta        # test a connector's live credentials
enkstein run workflow <name>         # trigger a workflow
enkstein run status <run-id>         # check a run
enkstein policies list               # list security policies
enkstein approvals list              # pending agent-action approvals
enkstein approvals approve <id>      # approve a queued action
enkstein evidence collect --framework soc2   # compliance evidence export
enkstein incidents list              # security incidents
enkstein skill-packs list            # installed skill packs
```

Run `enkstein --help` or `enkstein <group> --help` for the full command tree.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ENKSTEIN_API_URL` | `http://localhost:8000` | Server base URL |
| `ENKSTEIN_TOKEN` | _(none)_ | Bearer JWT for authenticated servers |
| `ENKSTEIN_TIMEOUT` | `30` | Request timeout (seconds) |

## License

MIT
