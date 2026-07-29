# Enkstein MCP Server

Bring **governed security tools** into Cursor, VS Code, and Claude Desktop.

This [Model Context Protocol](https://modelcontextprotocol.io) server exposes
Enkstein's security capabilities as tools your AI coding agent can call —
scanning code for secrets, checking security posture, listing findings, and
launching multi-agent investigations. Every call is forwarded to your running
Enkstein backend, where the **Trust Fabric** applies policy, risk scoring, and
audit. The MCP server itself holds no credentials and executes nothing locally.

## Tools

| Tool | What it does |
|---|---|
| `scan_text_for_secrets` | Scan code/text for exposed secrets, API keys, PII, and prompt-injection patterns. Run it before you commit. |
| `get_security_posture` | Current platform posture — modules, identities, connectors, high-risk events, pending approvals. |
| `list_findings` | List security findings, filterable by claw and severity. |
| `list_connectors` | Show connected security tools and their status. |
| `run_swarm_investigation` | Launch a governed multi-agent investigation (high-risk actions still need human approval). |
| `marcellus_browser_fetch` | Retrieve a public HTTPS source through Trust Fabric, SSRF defense, and prompt-injection scanning. |
| `marcellus_workspace_search` | Search one authorized Cowork project's encrypted artifacts. |
| `terraclaw_generate_secure_terraform` | Generate Trust Fabric-governed Terraform from a deployment request. |
| `terraclaw_review_hcl` | Review Terraform HCL and return an APPROVE/WARN/BLOCK decision with remediations. |
| `terraclaw_analyze_plan` | Analyze normalized Terraform plan changes before apply. |

## Install

```bash
pip install ./enkstein_mcp-0.7.0-py3-none-any.whl
```

Download the wheel from the matching GitHub Release. PyPI publication is not
part of the current release workflow.

## Configure your editor

You need a running Enkstein backend (`docker compose up`) reachable at
`ENKSTEIN_API_URL`.

### Cursor — `~/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "enkstein": {
      "command": "enkstein-mcp",
      "env": {
        "ENKSTEIN_API_URL": "http://localhost:8000",
        "ENKSTEIN_TOKEN": ""
      }
    }
  }
}
```

### Claude Desktop — `claude_desktop_config.json`

```json
{
  "mcpServers": {
    "enkstein": {
      "command": "enkstein-mcp",
      "env": { "ENKSTEIN_API_URL": "http://localhost:8000" }
    }
  }
}
```

### VS Code (with an MCP-capable extension)

Point the extension at the `enkstein-mcp` command with the same env vars.

Set `ENKSTEIN_TOKEN` to a JWT when your server runs with `DEBUG=false`
(get one from `POST /api/v1/auth/token`). In local DEBUG mode it can be empty.

## Example prompts (once connected)

> "Scan the file I have open for hardcoded secrets."
> "What's my current security posture?"
> "List critical cloudclaw findings."
> "Investigate suspicious identity activity for user@corp.com."
> "Generate secure AWS RDS Terraform with encryption and private subnets."
> "Review this Terraform module before I open a pull request."

## License

MIT
