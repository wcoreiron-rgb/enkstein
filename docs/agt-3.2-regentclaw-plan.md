# RegentClaw AGT Upgrade Plan (v3.2 Track)

This plan applies AGT new-release capabilities without coupling Capability Nodes to AGT internals.

## Guardrails

1. Keep **Regent Fabric** as the stable interface.
2. Keep **AGT behind adapter boundary**: `backend/app/fabric/providers/agt/`.
3. Use **feature flags** for staged rollout:
   - `AGT_ENABLE_MCP_GATEWAY`
   - `AGT_ENABLE_E2E_MESSAGING`
   - `AGT_ENABLE_AGENT_MESH`
   - `AGT_ENABLE_SHADOW_DISCOVERY`
4. Keep **OS/runtime isolation** independent of AGT.

## Rollout Order

1. MCP Security Gateway (skills/connectors/tooling scan path).
2. Encrypted multi-agent messaging (SwarmClaw traffic).
3. Agent mesh + registry/relay.
4. Shadow AI discovery.
5. Marketplace trust scoring integration.

## Added API Surface

- `GET /api/v1/trust-fabric/multi-agent/status`
- `POST /api/v1/trust-fabric/mcp/scan`

## Operator Notes

- Do not expose raw AGT terms directly in product UX.
- Map governance to Regent language: Capability Nodes, Fabric decisions, policy packs, trust score, audit evidence.
- Validate each rollout with existing policy/approval/audit tests.

