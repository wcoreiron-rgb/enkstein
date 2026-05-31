const BASE = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/api/v1`
  : '/api/v1';

// ── Typed API error ────────────────────────────────────────────────────────────
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public data?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = typeof window !== 'undefined' ? localStorage.getItem('rc_token') : null;
  const authHeader: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...authHeader, ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    // Read body once as text, then try to parse as JSON.
    // Never call both .json() and .text() — the second call throws "body stream already read".
    let data: unknown;
    try {
      const text = await res.text();
      try { data = JSON.parse(text); } catch { data = text; }
    } catch { data = undefined; }
    throw new ApiError(res.status, `API error ${res.status}`, data);
  }
  return res.json();
}

// Dashboard
export const getDashboard = () => apiFetch<any>('/dashboard');

// ArcClaw
export const getArcStats = () => apiFetch<any>('/arcclaw/stats');
export const getArcEvents = (limit = 50) => apiFetch<any[]>(`/arcclaw/events?limit=${limit}`);
export const submitArcEvent = (body: object) =>
  apiFetch<any>('/arcclaw/events', { method: 'POST', body: JSON.stringify(body) });

// IdentityClaw
export const getIdentityStats = () => apiFetch<any>('/identityclaw/stats');
export const getIdentities = (type?: string) =>
  apiFetch<any[]>(`/identityclaw/identities${type ? `?identity_type=${type}` : ''}`);
export const getOrphaned = () => apiFetch<any[]>('/identityclaw/orphaned');
export const getApprovals = (status = 'pending') =>
  apiFetch<any[]>(`/identityclaw/approvals?status=${status}`);

// Policies
export const getPolicies = () => apiFetch<any[]>('/policies');
export const createPolicy = (body: object) =>
  apiFetch<any>('/policies', { method: 'POST', body: JSON.stringify(body) });
export const updatePolicy = (id: string, body: object) =>
  apiFetch<any>(`/policies/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const deletePolicy = (id: string) =>
  apiFetch<void>(`/policies/${id}`, { method: 'DELETE' });

// Events
export const getEvents = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/events${qs}`);
};
export const getAnomalies = () => apiFetch<any[]>('/events/anomalies');

// Audit
export const getAuditLogs = (complianceOnly = false) =>
  apiFetch<any[]>(`/audit?compliance_only=${complianceOnly}`);

// Connectors
export const getConnectors = () => apiFetch<any[]>('/connectors');

// Agents
export const getAgents = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/agents${qs}`);
};
export const getAgent = (id: string) => apiFetch<any>(`/agents/${id}`);
export const createAgent = (body: object) =>
  apiFetch<any>('/agents', { method: 'POST', body: JSON.stringify(body) });
export const updateAgent = (id: string, body: object) =>
  apiFetch<any>(`/agents/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const deleteAgent = (id: string) =>
  apiFetch<void>(`/agents/${id}`, { method: 'DELETE' });
export const triggerAgent = (id: string, body: object) =>
  apiFetch<any>(`/agents/${id}/run`, { method: 'POST', body: JSON.stringify(body) });
export const getAgentRuns = (id: string, limit = 20) =>
  apiFetch<any[]>(`/agents/${id}/runs?limit=${limit}`);
export const approveAction = (agentId: string, runId: string, body: object) =>
  apiFetch<any>(`/agents/${agentId}/runs/${runId}/approve`, { method: 'POST', body: JSON.stringify(body) });

// Schedules
export const getSchedules = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/schedules${qs}`);
};
export const createSchedule = (body: object) =>
  apiFetch<any>('/schedules', { method: 'POST', body: JSON.stringify(body) });
export const updateSchedule = (id: string, body: object) =>
  apiFetch<any>(`/schedules/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const deleteSchedule = (id: string) =>
  apiFetch<void>(`/schedules/${id}`, { method: 'DELETE' });
export const triggerSchedule = (id: string) =>
  apiFetch<any>(`/schedules/${id}/run`, { method: 'POST' });
export const triggerScheduleSwarm = (id: string) =>
  apiFetch<any>(`/schedules/${id}/run-swarm`, { method: 'POST' });
export const getScheduleRuns = (id: string, limit = 20) =>
  apiFetch<any[]>(`/schedules/${id}/runs?limit=${limit}`);

// Orchestrations
export const getWorkflows = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/orchestrations${qs}`);
};
export const getWorkflow = (id: string) => apiFetch<any>(`/orchestrations/${id}`);
export const createWorkflow = (body: object) =>
  apiFetch<any>('/orchestrations', { method: 'POST', body: JSON.stringify(body) });
export const updateWorkflow = (id: string, body: object) =>
  apiFetch<any>(`/orchestrations/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const deleteWorkflow = (id: string) =>
  apiFetch<void>(`/orchestrations/${id}`, { method: 'DELETE' });
export const triggerWorkflow = (id: string) =>
  apiFetch<any>(`/orchestrations/${id}/run`, { method: 'POST' });
export const getWorkflowRuns = (id: string, limit = 20) =>
  apiFetch<any[]>(`/orchestrations/${id}/runs?limit=${limit}`);
export const getRunReplay = (workflowId: string, runId: string) =>
  apiFetch<any>(`/orchestrations/${workflowId}/runs/${runId}/replay`);
export const getRunReplayById = (runId: string) =>
  apiFetch<any>(`/orchestrations/run-replay/${runId}`);
export const getRecentRuns = (limit = 20) =>
  apiFetch<any[]>(`/orchestrations/runs/recent?limit=${limit}`);

// Swarm
export interface SwarmTask {
  id: string;
  claw: string;
  task_type: string;
  status: string;
  severity?: string | null;
  confidence?: number | null;
  risk_score?: number | null;
  execution_time_ms?: number | null;
  output_json?: string | null;
}

export const createSwarmJob = (body: object) =>
  apiFetch<any>('/swarm/jobs', { method: 'POST', body: JSON.stringify(body) });
export const createSuspiciousIdentitySwarm = (body?: object) =>
  apiFetch<any>('/swarm/jobs/presets/suspicious-identity', { method: 'POST', body: JSON.stringify(body || {}) });
export const getSwarmJobs = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/swarm/jobs${qs}`);
};
export const getSwarmJob = (id: string) => apiFetch<any>(`/swarm/jobs/${id}`);
export const getSwarmTasks = (id: string) => apiFetch<SwarmTask[]>(`/swarm/jobs/${id}/tasks`);
export const cancelSwarmJob = (id: string) =>
  apiFetch<any>(`/swarm/jobs/${id}/cancel`, { method: 'POST' });
export const approveSwarmJob = (id: string) =>
  apiFetch<any>(`/swarm/jobs/${id}/approve`, { method: 'POST' });

// Policy Packs
export const getPolicyPacks = () => apiFetch<any[]>('/policy-packs');

// Remediation
export const triggerRemediationAction = (body: {
  action_spec: {
    provider: string;
    action_type: string;
    target_type: string;
    target_id: string;
    target_label?: string;
    parameters?: Record<string, unknown>;
  };
  triggered_by?: string;
}) =>
  apiFetch<any>('/remediation/trigger', { method: 'POST', body: JSON.stringify(body) });

// Event Triggers
export const getTriggers = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/triggers${qs}`);
};
export const getTrigger = (id: string) => apiFetch<any>(`/triggers/${id}`);
export const createTrigger = (body: object) =>
  apiFetch<any>('/triggers', { method: 'POST', body: JSON.stringify(body) });
export const updateTrigger = (id: string, body: object) =>
  apiFetch<any>(`/triggers/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const deleteTrigger = (id: string) =>
  apiFetch<void>(`/triggers/${id}`, { method: 'DELETE' });
export const testTrigger = (id: string, samplePayload: object) =>
  apiFetch<any>(`/triggers/${id}/test`, { method: 'POST', body: JSON.stringify(samplePayload) });
export const getTriggerStats = () => apiFetch<any[]>('/triggers/stats/summary');

// Autonomy Controls
export const getAutonomySettings = () => apiFetch<any>('/autonomy/settings');
export const updateAutonomySettings = (body: object) =>
  apiFetch<any>('/autonomy/settings', { method: 'PATCH', body: JSON.stringify(body) });
export const activateEmergencyMode = (reason: string, activatedBy = 'platform_admin') =>
  apiFetch<any>('/autonomy/emergency/activate', {
    method: 'POST', body: JSON.stringify({ reason, activated_by: activatedBy })
  });
export const deactivateEmergencyMode = (deactivatedBy = 'platform_admin') =>
  apiFetch<any>('/autonomy/emergency/deactivate', {
    method: 'POST', body: JSON.stringify({ deactivated_by: deactivatedBy })
  });
export const getAutonomyAgents = () => apiFetch<any[]>('/autonomy/agents');
export const updateAgentMode = (agentId: string, mode: string) =>
  apiFetch<any>(`/autonomy/agents/${agentId}/mode`, {
    method: 'PATCH', body: JSON.stringify({ mode })
  });
export const bulkUpdateAgentModes = (mode: string, clawFilter?: string) =>
  apiFetch<any>('/autonomy/agents/bulk-mode', {
    method: 'POST', body: JSON.stringify({ mode, claw_filter: clawFilter || null })
  });
export const applyPolicyPack = (id: string) =>
  apiFetch<any>(`/policy-packs/${id}/apply`, { method: 'POST' });
export const unapplyPolicyPack = (id: string) =>
  apiFetch<any>(`/policy-packs/${id}/unapply`, { method: 'POST' });

// Copilot — Natural Language Workflow Creation
export const nlToWorkflow = (prompt: string, requestedBy = 'copilot_ui') =>
  apiFetch<any>('/copilot/nl-to-workflow', {
    method: 'POST',
    body: JSON.stringify({ prompt, requested_by: requestedBy }),
  });
export const getCopilotDrafts = () => apiFetch<any>('/copilot/drafts');
export const getCopilotDraft = (draftId: string) => apiFetch<any>(`/copilot/drafts/${draftId}`);
export const patchCopilotDraft = (draftId: string, body: object) =>
  apiFetch<any>(`/copilot/drafts/${draftId}`, { method: 'PATCH', body: JSON.stringify(body) });
export const discardDraft = (draftId: string) =>
  apiFetch<any>(`/copilot/drafts/${draftId}`, { method: 'DELETE' });
export const approveDraft = (draftId: string, body: { run_immediately?: boolean; approved_by?: string }) =>
  apiFetch<any>(`/copilot/drafts/${draftId}/approve`, { method: 'POST', body: JSON.stringify(body) });
export const saveAsTemplate = (draftId: string) =>
  apiFetch<any>(`/copilot/drafts/${draftId}/save-template`, { method: 'POST' });

// Secure Model Router
export const classifyText = (text: string) =>
  apiFetch<any>('/model-router/classify', { method: 'POST', body: JSON.stringify({ text }) });
export const callModelRouter = (prompt: string, options?: {
  sensitivity_override?: string;
  provider_override?: string;
  caller?: string;
}) =>
  apiFetch<any>('/model-router/route', {
    method: 'POST',
    body: JSON.stringify({ prompt, ...options }),
  });
export const getModelRouterTable = () => apiFetch<any>('/model-router/routing-table');
export const updateModelRouterRule = (sensitivity: string, provider: string) =>
  apiFetch<any>('/model-router/routing-table', {
    method: 'PATCH',
    body: JSON.stringify({ sensitivity, provider }),
  });
export const resetModelRouterTable = () =>
  apiFetch<any>('/model-router/routing-table/reset', { method: 'POST' });
export const getModelRouterProviders = () => apiFetch<any>('/model-router/providers');
export const getModelRouterAudit = (limit = 50) =>
  apiFetch<any>(`/model-router/audit?limit=${limit}`);
export const getModelRouterSensitivityLevels = () =>
  apiFetch<any>('/model-router/sensitivity-levels');

// ModelClaw
export const getModelClawProviders = () => apiFetch<any[]>('/modelclaw/providers');
export const getModelClawProfiles = () => apiFetch<any[]>('/modelclaw/profiles');
export const createOrUpdateModelClawProfile = (body: object) =>
  apiFetch<any>('/modelclaw/profiles', { method: 'POST', body: JSON.stringify(body) });
export const routeModelClawCall = (body: object) =>
  apiFetch<any>('/modelclaw/route', { method: 'POST', body: JSON.stringify(body) });
export const getModelClawCalls = (limit = 50) =>
  apiFetch<any[]>(`/modelclaw/calls?limit=${limit}`);

// Memory / State Layer
export const getMemorySummary = () => apiFetch<any>('/memory/summary');
export const getIncidents = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/memory/incidents${qs}`);
};
export const getIncident = (id: string) => apiFetch<any>(`/memory/incidents/${id}`);
export const createIncident = (body: object) =>
  apiFetch<any>('/memory/incidents', { method: 'POST', body: JSON.stringify(body) });
export const updateIncident = (id: string, body: object) =>
  apiFetch<any>(`/memory/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const addIncidentTimeline = (id: string, body: object) =>
  apiFetch<any>(`/memory/incidents/${id}/timeline`, { method: 'POST', body: JSON.stringify(body) });
export const closeIncident = (id: string, body: object) =>
  apiFetch<any>(`/memory/incidents/${id}/close`, { method: 'POST', body: JSON.stringify(body) });
export const getTopAssets = (limit = 30) => apiFetch<any[]>(`/memory/assets?limit=${limit}`);
export const upsertAsset = (body: object) =>
  apiFetch<any>('/memory/assets', { method: 'POST', body: JSON.stringify(body) });
export const getTenantMemory = () => apiFetch<any>('/memory/tenant');
export const refreshTenantMemory = () => apiFetch<any>('/memory/tenant/refresh', { method: 'POST' });
export const getRiskTrends = (granularity = 'daily', days = 30) =>
  apiFetch<any>(`/memory/trends?granularity=${granularity}&days=${days}`);
export const captureRiskSnapshot = () =>
  apiFetch<any>('/memory/trends/snapshot', { method: 'POST' });

// Skill Packs
export const getSkillPacks = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any>(`/skill-packs${qs}`);
};
export const getSkillPackStats = () => apiFetch<any>('/skill-packs/stats');
export const getSkillPackDetail = (id: string) => apiFetch<any>(`/skill-packs/${id}`);
export const createSkillPack = (body: object) =>
  apiFetch<any>('/skill-packs', { method: 'POST', body: JSON.stringify(body) });
export const updateSkillPack = (id: string, body: object) =>
  apiFetch<any>(`/skill-packs/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const deleteSkillPack = (id: string) =>
  apiFetch<void>(`/skill-packs/${id}`, { method: 'DELETE' });
export const installSkillPack = (
  id: string,
  installedBy = 'platform_admin',
  scanPath?: string,
) =>
  apiFetch<any>(`/skill-packs/${id}/install`, {
    method: 'POST',
    body: JSON.stringify({
      installed_by: installedBy,
      ...(scanPath ? { scan_path: scanPath } : {}),
    }),
  });
export const uninstallSkillPack = (id: string) =>
  apiFetch<any>(`/skill-packs/${id}/uninstall`, { method: 'POST' });
export const activateSkillPack = (id: string) =>
  apiFetch<any>(`/skill-packs/${id}/activate`, { method: 'POST' });
export const deactivateSkillPack = (id: string) =>
  apiFetch<any>(`/skill-packs/${id}/deactivate`, { method: 'POST' });
export const getSkillPackSkills = (id: string) =>
  apiFetch<any>(`/skill-packs/${id}/skills`);

// Connector Health
export const getConnectorHealthSummary = () => apiFetch<any>('/connectors/health-summary');

// Security Exchange
export const getExchangePackages = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any>(`/exchange/packages${qs}`);
};
export const getExchangePackage = (id: string) => apiFetch<any>(`/exchange/packages/${id}`);
export const installExchangePackage = (
  id: string,
  installedBy = 'platform_admin',
  checksumHeader?: string,
) =>
  apiFetch<any>(`/exchange/packages/${id}/install?installed_by=${encodeURIComponent(installedBy)}`, {
    method: 'POST',
    headers: checksumHeader ? { 'x-package-sha256': checksumHeader } : undefined,
  });
export const getFeaturedPackages = () => apiFetch<any[]>('/exchange/featured');
export const searchExchangePackages = (q: string) =>
  apiFetch<any[]>(`/exchange/search?q=${encodeURIComponent(q)}`);
export const getExchangePublishers = () => apiFetch<any[]>('/exchange/publishers');
export const getExchangePublisher = (slug: string) => apiFetch<any>(`/exchange/publishers/${slug}`);
export const getExchangeStats = () => apiFetch<any>('/exchange/stats');

// Channel Gateway
export const getChannelMessages = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any>(`/channel-gateway/messages${qs}`);
};
export const simulateChannelMessage = (body: object) =>
  apiFetch<any>('/channel-gateway/simulate', { method: 'POST', body: JSON.stringify(body) });
export const ingestChannelMessage = (body: object) =>
  apiFetch<any>('/channel-gateway/message', { method: 'POST', body: JSON.stringify(body) });
export const ingestChannelWebhook = (body: object) =>
  apiFetch<any>('/channel-gateway/webhook', { method: 'POST', body: JSON.stringify(body) });
export const ingestChannelEmail = (body: object) =>
  apiFetch<any>('/channel-gateway/email/inbound', { method: 'POST', body: JSON.stringify(body) });
export const ingestChannelCli = (body: object) =>
  apiFetch<any>('/channel-gateway/cli/command', { method: 'POST', body: JSON.stringify(body) });
export const getChannelIdentities = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/channel-gateway/identities${qs}`);
};
export const upsertChannelIdentity = (body: object) =>
  apiFetch<any>('/channel-gateway/identities', { method: 'POST', body: JSON.stringify(body) });
export const getChannelConfigs = () => apiFetch<any[]>('/channel-gateway/configs');
export const createChannelConfig = (body: object) =>
  apiFetch<any>('/channel-gateway/configs', { method: 'POST', body: JSON.stringify(body) });
export const getChannelGatewayStats = () => apiFetch<any>('/channel-gateway/stats');
export const getPendingCommands = (
  limit = 50,
  filters?: { source?: string; requester?: string; min_risk?: number },
) => {
  const params = new URLSearchParams({ limit: String(limit) });
  if (filters?.source) params.set('source', filters.source);
  if (filters?.requester) params.set('requester', filters.requester);
  if (typeof filters?.min_risk === 'number') params.set('min_risk', String(filters.min_risk));
  return apiFetch<any>(`/commands/pending?${params.toString()}`);
};
export const approvePendingCommand = (commandId: string, body?: { approver?: string; reason?: string }) =>
  apiFetch<any>(`/commands/${encodeURIComponent(commandId)}/approve`, {
    method: 'POST',
    body: JSON.stringify(body || {}),
  });
export const rejectPendingCommand = (commandId: string, body?: { reviewer?: string; reason?: string }) =>
  apiFetch<any>(`/commands/${encodeURIComponent(commandId)}/reject`, {
    method: 'POST',
    body: JSON.stringify(body || {}),
  });
export const bulkReviewPendingCommands = (body: {
  command_ids: string[];
  decision: 'approve' | 'reject';
  reason?: string;
  actor?: string;
}) =>
  apiFetch<any>('/commands/bulk-review', {
    method: 'POST',
    body: JSON.stringify(body),
  });
export const getCommandTimeline = (
  commandId: string,
  limit = 100,
  filters?: { action_contains?: string; outcome?: string },
) => {
  const params = new URLSearchParams({ limit: String(limit) });
  if (filters?.action_contains) params.set('action_contains', filters.action_contains);
  if (filters?.outcome) params.set('outcome', filters.outcome);
  return apiFetch<any>(`/commands/${encodeURIComponent(commandId)}/timeline?${params.toString()}`);
};
export const getCommandStatus = (commandId: string) =>
  apiFetch<any>(`/commands/${encodeURIComponent(commandId)}/status`);
export const updateCommandApprovalPolicy = (
  commandId: string,
  body: { required_approvals: number; reason?: string },
) =>
  apiFetch<any>(`/commands/${encodeURIComponent(commandId)}/approval-policy`, {
    method: 'POST',
    body: JSON.stringify(body),
  });

// Governed Execution Channels
export const submitShellExec = (body: object) =>
  apiFetch<any>('/exec/shell', { method: 'POST', body: JSON.stringify(body) });
export const submitBrowserExec = (body: object) =>
  apiFetch<any>('/exec/browser', { method: 'POST', body: JSON.stringify(body) });
export const requestCredential = (body: object) =>
  apiFetch<any>('/exec/credential', { method: 'POST', body: JSON.stringify(body) });
export const submitProductionExec = (body: object) =>
  apiFetch<any>('/exec/production', { method: 'POST', body: JSON.stringify(body) });
export const getExecRequests = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any>(`/exec/requests${qs}`);
};
export const approveExecRequest = (id: string, body: object) =>
  apiFetch<any>(`/exec/requests/${id}/approve`, { method: 'POST', body: JSON.stringify(body) });
export const rejectExecRequest = (id: string, body: object) =>
  apiFetch<any>(`/exec/requests/${id}/reject`, { method: 'POST', body: JSON.stringify(body) });
export const executeExecRequest = (id: string) =>
  apiFetch<any>(`/exec/requests/${id}/execute`, { method: 'POST' });
export const getProductionGates = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/exec/production-gates${qs}`);
};
export const approveProductionGate = (id: string, body: object) =>
  apiFetch<any>(`/exec/production-gates/${id}/approve`, { method: 'POST', body: JSON.stringify(body) });
export const rejectProductionGate = (id: string, body: object) =>
  apiFetch<any>(`/exec/production-gates/${id}/reject`, { method: 'POST', body: JSON.stringify(body) });
export const executeProductionGate = (id: string) =>
  apiFetch<any>(`/exec/production-gates/${id}/execute`, { method: 'POST' });
export const rollbackProductionGate = (id: string) =>
  apiFetch<any>(`/exec/production-gates/${id}/rollback`, { method: 'POST' });
export const getCredentials = () => apiFetch<any[]>('/exec/credentials');
export const registerCredential = (body: object) =>
  apiFetch<any>('/exec/credentials', { method: 'POST', body: JSON.stringify(body) });
export const getExecStats = () => apiFetch<any>('/exec/stats');
export const testConnector = (id: string) =>
  apiFetch<any>(`/connectors/${id}/test`, { method: 'POST', body: JSON.stringify({}) });

// MemoryClaw — Behavioral Profiling
export const getEntityProfiles = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any>(`/memory/profiles${qs}`);
};
export const getAnomalousEntities = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/memory/profiles/anomalous${qs}`);
};
export const getProfileStats = () => apiFetch<any>('/memory/profiles/stats');
export const getEntityProfile = (entityId: string) =>
  apiFetch<any>(`/memory/profiles/${encodeURIComponent(entityId)}`);
export const deleteEntityProfile = (entityId: string) =>
  apiFetch<any>(`/memory/profiles/${encodeURIComponent(entityId)}`, { method: 'DELETE' });
export const getEntityContext = (entityId: string) =>
  apiFetch<any>(`/memory/profiles/${encodeURIComponent(entityId)}/context`);
export const recomputeBaseline = (entityId: string) =>
  apiFetch<any>(`/memory/profiles/${encodeURIComponent(entityId)}/recompute`, { method: 'POST' });
export const preflightScoreAnomaly = (body: object) =>
  apiFetch<any>('/memory/profiles/score', { method: 'POST', body: JSON.stringify(body) });
export const logBehaviorEvent = (body: object) =>
  apiFetch<any>('/memory/behavior-events', { method: 'POST', body: JSON.stringify(body) });
export const getBehaviorEvents = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any>(`/memory/behavior-events${qs}`);
};
export const getBehaviorEvent = (id: number) =>
  apiFetch<any>(`/memory/behavior-events/${id}`);

// ─── External Agents (Zero Trust OpenClaw integration) ───────────────────────
export const listExternalAgents = () =>
  apiFetch<any>('/external-agents');

export const getExternalAgent = (id: string) =>
  apiFetch<any>(`/external-agents/${id}`);

export const registerExternalAgent = (body: {
  name: string;
  description?: string;
  endpoint_url: string;
  allowed_scopes: string[];
  execution_mode?: string;
  risk_level?: string;
  owner_name?: string;
}) => apiFetch<any>('/external-agents/register', {
  method: 'POST',
  body: JSON.stringify(body),
});

export const rotateExternalAgentKey = (id: string) =>
  apiFetch<any>(`/external-agents/${id}/rotate-key`, { method: 'POST' });

export const verifyExternalAgentEndpoint = (id: string) =>
  apiFetch<any>(`/external-agents/${id}/verify`, { method: 'POST' });

export const updateExternalAgentScopes = (id: string, scopes: string[]) =>
  apiFetch<any>(`/external-agents/${id}/scopes`, {
    method: 'PATCH',
    body: JSON.stringify(scopes),
  });

export const deregisterExternalAgent = (id: string) =>
  apiFetch<any>(`/external-agents/${id}`, { method: 'DELETE' });

// Findings — Universal (all claws)
export const getFindings = (params?: Record<string, string>) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch<any[]>(`/findings${qs}`);
};
export const getFindingsStats = () => apiFetch<any>('/findings/stats');
export const updateFinding = (id: string, body: object) =>
  apiFetch<any>(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
