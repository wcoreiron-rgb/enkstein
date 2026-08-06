import { clearAuthToken, getAuthToken } from '@/lib/auth';

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

/** Retry budget for a request lost to a recycled proxy socket rather than a real
 *  server error. A reused keep-alive connection that the upstream closed shows up
 *  as ECONNRESET (surfaced as 500/502/504 by the Next proxy) or as a thrown
 *  TypeError, with the handler never having run. Retrying once is safe for the
 *  read-only endpoints that use it and avoids showing "API error 500" for a
 *  request that in fact succeeded server-side. */
const TRANSIENT_PROXY_STATUSES = new Set([500, 502, 503, 504]);

export type ApiFetchOptions = RequestInit & { retryTransient?: boolean };

export async function apiFetch<T>(path: string, options?: ApiFetchOptions): Promise<T> {
  const { retryTransient, ...init } = options ?? {};
  try {
    return await apiFetchOnce<T>(path, init);
  } catch (error) {
    const retryable =
      retryTransient === true &&
      (!(error instanceof ApiError) || TRANSIENT_PROXY_STATUSES.has(error.status));
    if (!retryable) throw error;
    return apiFetchOnce<T>(path, init);
  }
}

async function apiFetchOnce<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getAuthToken();
  const authHeader: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...authHeader, ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    if (res.status === 401 && typeof window !== 'undefined') {
      clearAuthToken();
      window.location.replace('/login');
    }
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
export const getControlCenterSummary = () => apiFetch<any>('/dashboard/control-center-summary');

// Enkstein architecture discovery
export type EnksteinImplementationState = 'existing' | 'partial' | 'contract_only';

export interface EnksteinCortexComponent {
  id: string;
  name: string;
  purpose: string;
  implementation_state: EnksteinImplementationState;
  legacy_components: string[];
}

export interface EnksteinHeart {
  id: string;
  name: string;
  purpose: string;
  implementation_state: EnksteinImplementationState;
  components: string[];
}

export interface EnksteinCapabilityNode {
  id: string;
  name: string;
  arm_id: string;
  purpose: string;
  legacy_module: string;
  legacy_route: string;
  task_route: string;
  capabilities: string[];
  authority_ceiling: 'observe' | 'recommend' | 'approval_gated_action';
  supports_focused_task: boolean;
  plexus_ready: boolean;
  implementation_state: EnksteinImplementationState;
}

export interface EnksteinSecurityArm {
  id: string;
  name: string;
  purpose: string;
  node_ids: string[];
  implementation_state: EnksteinImplementationState;
}

export interface EnksteinArchitecture {
  name: string;
  version: string;
  working_name: boolean;
  source_lineage: string;
  compatibility_mode: string;
  thesis: string;
  cortex: EnksteinCortexComponent[];
  hearts: EnksteinHeart[];
  arms: EnksteinSecurityArm[];
  capability_nodes: EnksteinCapabilityNode[];
  reflexes: {
    implementation_state: EnksteinImplementationState;
    purpose: string;
    existing_foundation: string[];
    invariants: string[];
  };
  plexus: {
    implementation_state: EnksteinImplementationState;
    purpose: string;
    current_transport: string;
    target_transport: string;
    invariants: string[];
  };
  regeneration: {
    implementation_state: EnksteinImplementationState;
    purpose: string;
    recovery_sequence: string[];
    invariants: string[];
  };
  invariants: string[];
}

export const getEnksteinArchitecture = () =>
  apiFetch<EnksteinArchitecture>('/marcellus/architecture');

export type CortexMissionCadence = 'manual' | 'hourly' | 'every_6h' | 'daily' | 'weekly';
export type CortexMissionMode = 'monitor' | 'assist' | 'approval';

export interface CortexMission {
  id: string;
  tenant_id: string;
  owner_id: string;
  name: string;
  objective: string;
  status: 'active' | 'paused' | 'archived';
  cadence: CortexMissionCadence;
  autonomy_mode: CortexMissionMode;
  profile: string;
  classification: string;
  participants: string[];
  parallelism: number;
  model_profile: string | null;
  run_count: number;
  latest_job_id: string | null;
  latest_status: string | null;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface CortexMissionObservation {
  id: string;
  mission_id: string;
  job_id: string;
  status: 'proposed' | 'approved' | 'rejected' | 'blocked';
  severity: string;
  summary: string;
  evidence: Record<string, unknown>;
  proposed_by: string;
  reviewed_by: string | null;
  review_reason: string | null;
  created_at: string;
  reviewed_at: string | null;
}

export interface CortexOvernightBrief {
  id: string;
  generated_at: string;
  window_start: string;
  window_end: string;
  headline: string;
  active_missions: Array<Record<string, unknown>>;
  material_changes: Array<Record<string, unknown>>;
  decisions_needed: Array<Record<string, unknown>>;
  running_arms: string[];
  recent_reflex_actions: Array<Record<string, unknown>>;
  blocked_actions: Array<Record<string, unknown>>;
  security_twin_health: Record<string, unknown>;
}

export const getCortexMissions = () =>
  apiFetch<CortexMission[]>('/marcellus/missions');
export const createCortexMission = (body: object) =>
  apiFetch<CortexMission>('/marcellus/missions', { method: 'POST', body: JSON.stringify(body) });
export const updateCortexMission = (missionId: string, body: object) =>
  apiFetch<CortexMission>(`/marcellus/missions/${encodeURIComponent(missionId)}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
export const runCortexMission = (missionId: string) =>
  apiFetch<{ mission_id: string; job_id: string; status: string; message: string }>(
    `/marcellus/missions/${encodeURIComponent(missionId)}/run`,
    { method: 'POST' },
  );
export const getCortexMissionObservations = (status?: string) => {
  const query = status ? `?status=${encodeURIComponent(status)}` : '';
  return apiFetch<CortexMissionObservation[]>(`/marcellus/missions/memory/observations${query}`);
};
export const reviewCortexMissionObservation = (
  observationId: string,
  decision: 'approve' | 'reject',
  reason = '',
) => apiFetch<CortexMissionObservation>(
  `/marcellus/missions/memory/observations/${encodeURIComponent(observationId)}/review`,
  { method: 'POST', body: JSON.stringify({ decision, reason }) },
);
export const generateCortexOvernightBrief = (hours = 12) =>
  apiFetch<CortexOvernightBrief>(`/marcellus/missions/overnight-brief?hours=${hours}`, { method: 'POST' });

export interface EnksteinPlexusMessage {
  id: string;
  tenant_id: string;
  sender_node_id: string;
  recipient_node_id: string;
  message_type: string;
  classification: string;
  correlation_id: string;
  trace_id: string;
  payload_digest: string;
  payload: Record<string, unknown> | null;
  signature_algorithm: string;
  key_id: string;
  status: string;
  policy_outcome: string;
  policy_reason: string;
  risk_score: number;
  created_by: string;
  approved_by: string | null;
  created_at: string;
  expires_at: string;
  processed_at: string | null;
}

export interface EnksteinReflexDefinition {
  id: string;
  tenant_id: string;
  name: string;
  node_id: string;
  event_type: string;
  conditions_json: string;
  action_kind: 'record_signal' | 'plexus_notify';
  action_config_json: string;
  authority: 'observe' | 'recommend' | 'approval_gated_action';
  classification: string;
  is_active: boolean;
  max_runs_per_hour: number;
  cooldown_seconds: number;
  run_count: number;
  last_run_at: string | null;
  expires_at: string | null;
}

export interface EnksteinReflexExecution {
  id: string;
  tenant_id: string;
  reflex_id: string;
  event_id: string;
  event_type: string;
  status: string;
  requested_by: string;
  approved_by: string | null;
  policy_outcome: string;
  policy_reason: string;
  risk_score: number;
  result_json: string | null;
  error_message: string | null;
  plexus_message_id: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface EnksteinCheckpoint {
  id: string;
  tenant_id: string;
  node_id: string;
  version: number;
  state_digest: string;
  manifest: Record<string, unknown>;
  manifest_digest: string;
  signature_algorithm: string;
  key_id: string;
  status: string;
  created_by: string;
  created_at: string;
  verified_at: string | null;
}

export interface EnksteinRegenerationRun {
  id: string;
  tenant_id: string;
  node_id: string;
  checkpoint_id: string;
  requested_by: string;
  approved_by: string | null;
  status: string;
  policy_outcome: string;
  policy_reason: string;
  risk_score: number;
  stages_json: string;
  verification_json: string | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface EnksteinNodeRuntime {
  id: string;
  tenant_id: string;
  node_id: string;
  instance_id: string;
  generation: number;
  status: string;
  state_digest: string;
  checkpoint_id: string;
  health_json: string;
  regenerated_at: string;
  last_health_at: string | null;
}

export const getEnksteinPlexusMessages = (tenantId: string) =>
  apiFetch<EnksteinPlexusMessage[]>(`/marcellus/plexus/messages?tenant_id=${encodeURIComponent(tenantId)}`);
export const sendEnksteinPlexusMessage = (body: Record<string, unknown>) =>
  apiFetch<EnksteinPlexusMessage>('/marcellus/plexus/messages', { method: 'POST', body: JSON.stringify(body) });
export const acknowledgeEnksteinPlexusMessage = (id: string, body: Record<string, unknown>) =>
  apiFetch<EnksteinPlexusMessage>(`/marcellus/plexus/messages/${encodeURIComponent(id)}/ack`, { method: 'POST', body: JSON.stringify(body) });
export const approveEnksteinPlexusMessage = (id: string, tenantId: string) =>
  apiFetch<EnksteinPlexusMessage>(`/marcellus/plexus/messages/${encodeURIComponent(id)}/approve`, { method: 'POST', body: JSON.stringify({ tenant_id: tenantId }) });

export const getEnksteinReflexes = (tenantId: string) =>
  apiFetch<EnksteinReflexDefinition[]>(`/marcellus/reflexes?tenant_id=${encodeURIComponent(tenantId)}`);
export const createEnksteinReflex = (body: Record<string, unknown>) =>
  apiFetch<EnksteinReflexDefinition>('/marcellus/reflexes', { method: 'POST', body: JSON.stringify(body) });
export const evaluateEnksteinReflexes = (body: Record<string, unknown>) =>
  apiFetch<EnksteinReflexExecution[]>('/marcellus/reflexes/evaluate', { method: 'POST', body: JSON.stringify(body) });
export const getEnksteinReflexExecutions = (tenantId: string) =>
  apiFetch<EnksteinReflexExecution[]>(`/marcellus/reflexes/executions?tenant_id=${encodeURIComponent(tenantId)}`);
export const approveEnksteinReflexExecution = (id: string, tenantId: string) =>
  apiFetch<EnksteinReflexExecution>(`/marcellus/reflexes/executions/${encodeURIComponent(id)}/approve`, { method: 'POST', body: JSON.stringify({ tenant_id: tenantId }) });

export const getEnksteinCheckpoints = (tenantId: string) =>
  apiFetch<EnksteinCheckpoint[]>(`/marcellus/regeneration/checkpoints?tenant_id=${encodeURIComponent(tenantId)}`);
export const createEnksteinCheckpoint = (body: Record<string, unknown>) =>
  apiFetch<EnksteinCheckpoint>('/marcellus/regeneration/checkpoints', { method: 'POST', body: JSON.stringify(body) });
export const verifyEnksteinCheckpoint = (id: string, tenantId: string) =>
  apiFetch<{ checkpoint_id: string; verified: boolean; checks: Record<string, boolean>; failures: string[] }>(`/marcellus/regeneration/checkpoints/${encodeURIComponent(id)}/verify`, { method: 'POST', body: JSON.stringify({ tenant_id: tenantId }) });
export const startEnksteinRegeneration = (tenantId: string, checkpointId: string) =>
  apiFetch<EnksteinRegenerationRun>('/marcellus/regeneration/runs', { method: 'POST', body: JSON.stringify({ tenant_id: tenantId, checkpoint_id: checkpointId }) });
export const getEnksteinRegenerationRuns = (tenantId: string) =>
  apiFetch<EnksteinRegenerationRun[]>(`/marcellus/regeneration/runs?tenant_id=${encodeURIComponent(tenantId)}`);
export const approveEnksteinRegeneration = (id: string, tenantId: string) =>
  apiFetch<EnksteinRegenerationRun>(`/marcellus/regeneration/runs/${encodeURIComponent(id)}/approve`, { method: 'POST', body: JSON.stringify({ tenant_id: tenantId }) });
export const getEnksteinNodeRuntimes = (tenantId: string) =>
  apiFetch<EnksteinNodeRuntime[]>(`/marcellus/regeneration/runtimes?tenant_id=${encodeURIComponent(tenantId)}`);

// ArcClaw
export const getArcStats = () => apiFetch<any>('/arcclaw/stats');
export const getArcEvents = (limit = 50) => apiFetch<any[]>(`/arcclaw/events?limit=${limit}`);
export const getArcProviders = () => apiFetch<any[]>('/arcclaw/providers');
export const getArcModels = () => apiFetch<Record<string, Array<{ id: string; name: string; tag?: string }>>>('/arcclaw/agent/models');
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

// ReleaseClaw
export const getReleaseStats = () => apiFetch<any>('/releaseclaw/stats');
export const getReleaseAdapters = () => apiFetch<any[]>('/releaseclaw/adapters');
export const getReleaseTemplates = () => apiFetch<any[]>('/releaseclaw/templates');
export const getReleaseDeployments = (limit = 50) =>
  apiFetch<any[]>(`/releaseclaw/deployments?limit=${limit}`);
export const preflightRelease = (body: object) =>
  apiFetch<any>('/releaseclaw/preflight', { method: 'POST', body: JSON.stringify(body) });
export const approveRelease = (id: string, body: object) =>
  apiFetch<any>(`/releaseclaw/deployments/${id}/approve`, { method: 'POST', body: JSON.stringify(body) });
export const executeRelease = (id: string) =>
  apiFetch<any>(`/releaseclaw/deployments/${id}/execute`, { method: 'POST' });

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
export const createMicrosoftIdentityIncidentSwarm = (body?: object) =>
  apiFetch<any>('/swarm/jobs/presets/microsoft-identity-incident', { method: 'POST', body: JSON.stringify(body || {}) });
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
export const getBrainStatuses = (force = false) =>
  apiFetch<any[]>(`/modelclaw/brains/status${force ? '?force=true' : ''}`);
export const requestDesktopBrainAccess = () =>
  apiFetch<{ granted: boolean; detail: string }>('/modelclaw/brains/desktop-access', { method: 'POST' });
export const launchCliLogin = (brain: 'codex_subscription' | 'claude_subscription') =>
  apiFetch<{ launched: boolean; detail?: string }>('/modelclaw/brains/cli-login', {
    method: 'POST',
    body: JSON.stringify({ brain }),
  });
export const startBrowserBrainPairing = () =>
  apiFetch<{ available: boolean; setup_url?: string; opened?: boolean; expires_in_seconds?: number; detail?: string }>(
    '/modelclaw/brains/browser-pair',
    { method: 'POST' },
  );
export const openBrowserCompanionFolder = () =>
  apiFetch<{ opened: boolean; detail?: string }>('/modelclaw/brains/browser-companion', { method: 'POST' });
/** Downloads the companion as a zip. Kept out of `apiFetch` because that
 * helper parses JSON, and revealing a folder on the host only helps someone
 * sitting at that machine. */
export async function downloadBrowserCompanion(): Promise<void> {
  const token = getAuthToken();
  const response = await fetch(`${BASE}/modelclaw/brains/browser-companion/download`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) {
    throw new Error(
      response.status === 404
        ? 'The browser companion is not bundled with this runtime.'
        : 'The browser companion could not be downloaded.',
    );
  }
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'enkstein-browser-companion.zip';
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}
export const invokeSubscriptionBrain = (body: object) =>
  apiFetch<any>('/modelclaw/brains/invoke', { method: 'POST', body: JSON.stringify(body) });
export const routeBrainConsensus = (body: object) =>
  apiFetch<any>('/modelclaw/consensus', { method: 'POST', body: JSON.stringify(body) });
export type CortexGatewayResponse = {
  status: string;
  response?: string;
  source?: string;
  provider?: string;
  model?: string;
  mode: string;
  governance: {
    outcome: string;
    policy_name: string;
    reason: string;
    risk_score: number;
    data_classification: string;
    input_redacted: boolean;
    output_redacted: boolean;
    injection_risk: boolean;
    injection_vectors: string[];
  };
  votes: any[];
  confidence?: number;
  agreement?: string;
  routing?: {
    strategy: string;
    reason: string;
    candidate_sources: string[];
    selected_source?: string;
    attempted_sources?: string[];
  };
  latency_ms?: number;
};
export const routeCortexGateway = (body: object) =>
  apiFetch<CortexGatewayResponse>('/modelclaw/gateway', { method: 'POST', body: JSON.stringify(body) });

export type CortexProject = {
  id: string;
  tenant_id: string;
  owner_id: string;
  name: string;
  description: string;
  kind: string;
  classification: string;
  default_source: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type CortexNativeWorkspace = {
  connected: boolean;
  name?: string;
  file_count: number;
  synced_files: number;
};

export type CortexConversation = {
  id: string;
  tenant_id: string;
  owner_id: string;
  project_id?: string;
  title: string;
  mode: 'chat' | 'cowork' | 'security';
  classification: string;
  selected_source: string;
  status: string;
  branch_of_id?: string;
  branch_message_id?: string;
  message_count: number;
  created_at: string;
  updated_at: string;
};

export type CortexBrainAnswer = {
  source?: string;
  provider?: string;
  model?: string;
  latency_ms?: number;
  primary: boolean;
  content: string;
  truncated?: boolean;
};

export type CortexMessageRecord = {
  id: string;
  tenant_id: string;
  conversation_id: string;
  role: 'user' | 'assistant';
  content: string;
  classification: string;
  source?: string;
  provider?: string;
  model?: string;
  governance: Record<string, any>;
  brain_answers?: CortexBrainAnswer[];
  parent_message_id?: string;
  created_at: string;
};

export type CortexConversationDetail = CortexConversation & { messages: CortexMessageRecord[] };

export type CortexArtifact = {
  id: string;
  tenant_id: string;
  project_id: string;
  conversation_id?: string;
  path: string;
  mime_type: string;
  size_bytes: number;
  content_digest: string;
  classification: string;
  version: number;
  status: string;
  created_by: string;
  created_at: string;
  content?: string;
};

export type ContextCitation = {
  path: string;
  line_start: number;
  line_end: number;
};

export type ContextManifestEntry = {
  artifact_id: string;
  path: string;
  size_bytes: number;
  content_digest: string;
  selection_reason: string;
  classification: string;
  destination_brain: string;
  disposition: 'sent_full' | 'summarized' | 'truncated' | 'omitted' | 'blocked_by_policy';
  characters_sent: number;
  estimated_tokens: number;
  redacted: boolean;
  citations: ContextCitation[];
};

export type ContextRouteAttempt = {
  source: string;
  provider?: string | null;
  model?: string | null;
  policy_outcome: string;
  status: string;
  reason?: string | null;
};

export type ContextManifest = {
  entries: ContextManifestEntry[];
  explicit: boolean;
  destination: 'local' | 'external' | 'adaptive';
  budget_characters: number;
  total_characters_sent: number;
  total_estimated_tokens: number;
  blocked: boolean;
  block_reason?: string | null;
  effective_classification?: string | null;
  attempts: ContextRouteAttempt[];
  selected_destination?: string | null;
  fallback_reason?: string | null;
};

export type CortexFileChange = {
  path: string;
  operation: 'create' | 'update' | 'delete' | string;
  outcome: 'applied' | 'proposed' | 'skipped' | 'blocked' | string;
};

export type CortexTurn = {
  conversation: CortexConversation;
  user_message: CortexMessageRecord;
  assistant_message?: CortexMessageRecord;
  gateway: CortexGatewayResponse;
};

export type CortexStreamEvent = { event: string; data: any };

export type CortexCodexApproval = {
  approval_id: string;
  method: string;
  detail: Record<string, string>;
  deny_only: boolean;
};

export type CortexCodexStatus = {
  status: string;
  transport: string;
  session: string;
  turn: 'idle' | 'running' | 'completed' | 'interrupted' | string;
  cursor: number;
  events: Array<{ cursor: number; channel: string; fields: Record<string, any> }>;
  pending_approvals: CortexCodexApproval[];
};

export type CortexChangeProposal = {
  id: string;
  project_id: string;
  conversation_id?: string;
  operation: 'create' | 'update' | 'delete';
  path: string;
  status: string;
  proposed_content?: string;
  current_content?: string;
  base_digest?: string;
  previous_path?: string;
  /** Unified diff of the pending write, when before/after text differ. */
  diff?: string;
  created_by: string;
  created_at: string;
};

export type CortexCitation = {
  id: number;
  url: string;
  title: string;
  retrieved_at: string;
  content_type: string;
  content_digest: string;
  excerpt: string;
};

export type CortexResearchResult = {
  status: string;
  turn: CortexTurn;
  source_artifact: CortexArtifact;
  report_artifact: CortexArtifact;
  citations: CortexCitation[];
  tool_trace: Array<Record<string, any>>;
};

export const getCortexProjects = (kind?: 'cowork' | 'chat') =>
  apiFetch<CortexProject[]>(`/marcellus/workspace/projects${kind ? `?kind=${kind}` : ''}`);
export const createCortexProject = (body: object) =>
  apiFetch<CortexProject>('/marcellus/workspace/projects', { method: 'POST', body: JSON.stringify(body) });
export const getCortexNativeWorkspace = (projectId: string) =>
  apiFetch<CortexNativeWorkspace>(`/marcellus/workspace/projects/${projectId}/native-workspace`);
export const connectCortexNativeWorkspace = (projectId: string, body: { token: string; name: string }) =>
  apiFetch<CortexNativeWorkspace>(`/marcellus/workspace/projects/${projectId}/native-workspace`, { method: 'POST', body: JSON.stringify(body) });
export const syncCortexNativeWorkspace = (projectId: string) =>
  apiFetch<CortexNativeWorkspace>(`/marcellus/workspace/projects/${projectId}/native-workspace/sync`, { method: 'POST' });
export const getCortexConversations = (mode?: string, projectId?: string, includeArchived = false) => {
  const params = new URLSearchParams();
  if (mode) params.set('mode', mode);
  if (projectId) params.set('project_id', projectId);
  if (includeArchived) params.set('include_archived', 'true');
  const query = params.toString();
  return apiFetch<CortexConversation[]>(`/marcellus/workspace/conversations${query ? `?${query}` : ''}`);
};
export const createCortexConversation = (body: object) =>
  apiFetch<CortexConversation>('/marcellus/workspace/conversations', { method: 'POST', body: JSON.stringify(body) });
export const getCortexConversation = (id: string) =>
  apiFetch<CortexConversationDetail>(`/marcellus/workspace/conversations/${id}`);
export const archiveCortexConversation = (id: string) =>
  apiFetch<CortexConversation>(`/marcellus/workspace/conversations/${id}`, { method: 'DELETE' });
export const reopenCortexConversation = (id: string) =>
  apiFetch<CortexConversation>(`/marcellus/workspace/conversations/${id}/reopen`, { method: 'POST' });
export const permanentlyDeleteCortexConversation = (id: string) =>
  apiFetch<{ id: string; status: 'deleted' }>(`/marcellus/workspace/conversations/${id}/permanent`, { method: 'DELETE' });
export const moveCortexConversation = (id: string, projectId: string) =>
  apiFetch<CortexConversation>(`/marcellus/workspace/conversations/${id}/move`, {
    method: 'POST',
    body: JSON.stringify({ project_id: projectId }),
  });
export const renameCortexConversation = (id: string, title: string) =>
  apiFetch<CortexConversation>(`/marcellus/workspace/conversations/${id}/rename`, {
    method: 'POST',
    body: JSON.stringify({ title }),
  });
export const sendCortexTurn = (id: string, body: object) =>
  apiFetch<CortexTurn>(`/marcellus/workspace/conversations/${id}/turns`, { method: 'POST', body: JSON.stringify(body) });
export const startCortexCodex = (id: string, body: object) =>
  apiFetch<{ status: string; sandbox: string; resumed: boolean }>(
    `/marcellus/workspace/conversations/${id}/codex/start`,
    { method: 'POST', body: JSON.stringify(body) },
  );
export const sendCortexCodexTurn = (id: string, body: object) =>
  apiFetch<{ status: string; cursor: number; turn_active: boolean; policy: Record<string, any> }>(
    `/marcellus/workspace/conversations/${id}/codex/turn`,
    { method: 'POST', body: JSON.stringify(body) },
  );
export const getCortexCodexStatus = (id: string, cursor = 0) =>
  apiFetch<CortexCodexStatus>(`/marcellus/workspace/conversations/${id}/codex/status?cursor=${Math.max(0, cursor)}`);
export const decideCortexCodexApproval = (id: string, approvalId: string, decision: 'accept' | 'decline') =>
  apiFetch<{ status: string; decision: string; governed: boolean }>(
    `/marcellus/workspace/conversations/${id}/codex/approvals/${encodeURIComponent(approvalId)}`,
    { method: 'POST', body: JSON.stringify({ decision }) },
  );
export const cancelCortexCodex = (id: string) =>
  apiFetch<{ status: string }>(`/marcellus/workspace/conversations/${id}/codex/cancel`, {
    method: 'POST',
    body: JSON.stringify({}),
  });
export async function streamCortexTurn(
  id: string,
  body: object,
  onEvent: (event: CortexStreamEvent) => void,
  signal?: AbortSignal,
): Promise<CortexTurn> {
  const token = getAuthToken();
  const response = await fetch(`${BASE}/marcellus/workspace/conversations/${id}/turns/stream`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
    signal,
  });
  if (!response.ok || !response.body) {
    if (response.status === 401 && typeof window !== 'undefined') {
      clearAuthToken();
      window.location.replace('/login');
    }
    throw new ApiError(response.status, `API error ${response.status}`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let completed: CortexTurn | null = null;
  // The server heartbeats the stream while a turn runs, so any live turn keeps
  // the socket producing frames. If no frame (not even a heartbeat) arrives for
  // this long, the stream is presumed dead and is abandoned rather than hanging
  // the UI indefinitely.
  // A healthy backend emits a heartbeat every 10 seconds. Leave enough room
  // for desktop WebKit scheduling and a transient Docker/Next handoff, while
  // still failing a genuinely dead stream well before the backend's governed
  // deadline. The dedicated workspace route preserves SSE frames for
  // multi-minute Browser Companion turns.
  // Browser Companion work can take several minutes and some desktop WebKit /
  // proxy combinations buffer intermediate SSE heartbeats. Treating a quiet
  // 75-second window as terminal meant the UI abandoned a healthy ChatGPT
  // turn while the native broker and provider page kept working. The backend
  // already enforces the real 15-minute browser deadline, so the client must
  // leave browser work alive for that same bounded window. Non-browser turns
  // retain the quick dead-stream guard.
  const requestPayload = body as { source?: unknown; consensus_sources?: unknown };
  const requestSources = [
    requestPayload.source,
    ...(Array.isArray(requestPayload.consensus_sources) ? requestPayload.consensus_sources : []),
  ].map((item) => String(item || ''));
  const isBrowserTurn = requestSources.some((source) => source.endsWith('_browser'));
  const IDLE_TIMEOUT_MS = isBrowserTurn ? 930_000 : 75_000;
  try {
    while (true) {
      let idleTimer: ReturnType<typeof setTimeout> | undefined;
      const idle = new Promise<never>((_, reject) => {
        idleTimer = setTimeout(
          () => reject(new Error('The governed turn stream stalled with no server activity and was stopped.')),
          IDLE_TIMEOUT_MS,
        );
      });
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await Promise.race([reader.read(), idle]);
      } finally {
        if (idleTimer) clearTimeout(idleTimer);
      }
      const { done, value } = chunk;
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
      const frames = buffer.split('\n\n');
      buffer = frames.pop() || '';
      for (const frame of frames) {
        const event = frame.split('\n').find((line) => line.startsWith('event: '))?.slice(7) || 'message';
        const encoded = frame.split('\n').filter((line) => line.startsWith('data: ')).map((line) => line.slice(6)).join('\n');
        if (!encoded) continue;
        const data = JSON.parse(encoded);
        onEvent({ event, data });
        if (event === 'turn_failed') throw new Error(data.detail || 'The governed turn failed.');
        if (event === 'turn_timeout') throw new Error(data.detail || 'The governed turn timed out and was stopped.');
        if (event === 'turn_completed') completed = data as CortexTurn;
      }
      if (done) break;
    }
  } finally {
    // Release the underlying connection on any exit path (error, abort, idle
    // timeout) so a stalled turn never leaks a held reader.
    try {
      await reader.cancel();
    } catch {
      /* reader already closed */
    }
  }
  if (!completed) throw new Error('The stream ended before the governed turn completed.');
  return completed;
}
export const branchCortexConversation = (id: string, body: object) =>
  apiFetch<CortexConversationDetail>(`/marcellus/workspace/conversations/${id}/branches`, { method: 'POST', body: JSON.stringify(body) });
export const createCortexSecurityInvestigation = (id: string, body: object = {}) =>
  apiFetch<{ job_id: string; status: string; name: string; requires_approval: boolean; conversation_id: string }>(
    `/marcellus/workspace/conversations/${id}/security-investigation`,
    { method: 'POST', body: JSON.stringify(body) },
  );
export const searchCortexConversations = (query: string) =>
  apiFetch<Array<{ conversation: CortexConversation; matching_message_id?: string; excerpt?: string }>>(
    `/marcellus/workspace/search?q=${encodeURIComponent(query)}`,
  );
export const getCortexArtifacts = (projectId: string) =>
  apiFetch<CortexArtifact[]>(`/marcellus/workspace/projects/${projectId}/artifacts`);
export const ingestCortexArtifacts = (body: object) =>
  apiFetch<CortexArtifact[]>('/marcellus/workspace/artifacts', { method: 'POST', body: JSON.stringify(body) });
export const getCortexArtifact = (id: string) =>
  apiFetch<CortexArtifact>(`/marcellus/workspace/artifacts/${id}`);
export const updateCortexArtifact = (id: string, body: { path: string; content: string; mime_type?: string }) =>
  apiFetch<CortexArtifact>(`/marcellus/workspace/artifacts/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const deleteCortexArtifact = (id: string) =>
  apiFetch<CortexArtifact>(`/marcellus/workspace/artifacts/${id}`, { method: 'DELETE' });
export const getCortexChangeProposals = (projectId: string) =>
  apiFetch<CortexChangeProposal[]>(`/marcellus/workspace/projects/${projectId}/change-proposals`);
export const reviewCortexChangeProposal = (id: string, decision: 'approve' | 'reject', reason = '') =>
  apiFetch<CortexChangeProposal>(`/marcellus/workspace/change-proposals/${id}/review`, {
    method: 'POST',
    body: JSON.stringify({ decision, reason }),
  });
export const runCortexResearch = (projectId: string, body: object) =>
  apiFetch<CortexResearchResult>(`/marcellus/workspace/projects/${projectId}/research`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
export const getCortexTools = () =>
  apiFetch<Array<{ name: string; description: string; capability: string; input_schema: Record<string, any> }>>(
    '/marcellus/workspace/tools',
  );
export const invokeCortexTool = (body: object) =>
  apiFetch<{ tool: string; status: string; policy: Record<string, any>; result: Record<string, any> }>(
    '/marcellus/workspace/tools/invoke',
    { method: 'POST', body: JSON.stringify(body) },
  );

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
export const getMemoryProposals = () => apiFetch<any[]>('/memory/proposals');
export const approveMemoryProposal = (id: string, body: object) =>
  apiFetch<any>(`/memory/proposals/${id}/approve`, { method: 'POST', body: JSON.stringify(body) });
export const rejectMemoryProposal = (id: string, body: object) =>
  apiFetch<any>(`/memory/proposals/${id}/reject`, { method: 'POST', body: JSON.stringify(body) });
export const rollbackMemoryIncident = (id: string, body: object) =>
  apiFetch<any>(`/memory/incidents/${id}/rollback`, { method: 'POST', body: JSON.stringify(body) });
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
export const previewSkillPackUpdate = (id: string, body: object) =>
  apiFetch<any>(`/skill-packs/${id}/preview-update`, { method: 'POST', body: JSON.stringify(body) });
export const upgradeSkillPack = (id: string, body: object) =>
  apiFetch<any>(`/skill-packs/${id}/upgrade`, { method: 'POST', body: JSON.stringify(body) });
export const rollbackSkillPack = (id: string, body: object) =>
  apiFetch<any>(`/skill-packs/${id}/rollback`, { method: 'POST', body: JSON.stringify(body) });

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

// ── Zero Trust control catalog ────────────────────────────────────────────────
export const getControlSummary = () => apiFetch<any>('/controls/summary');
export const getControlCoverage = () => apiFetch<any>('/controls/profiles/coverage');
export const getArmControlProfile = (claw: string) =>
  apiFetch<any>(`/controls/profiles/${claw}`);
export const getControlEvaluation = (claw?: string) =>
  apiFetch<any>(`/controls/evaluation${claw ? `?claw=${encodeURIComponent(claw)}` : ''}`);
export const getControlCollectors = () => apiFetch<any>('/controls/collectors');
export const getProwlerStatus = () => apiFetch<any>('/controls/prowler/status');
export const getControlRemediationProposals = (claw?: string) =>
  apiFetch<any>(`/controls/remediation/proposals${claw ? `?claw=${encodeURIComponent(claw)}` : ''}`);
export const getAssessmentSummary = (claw: string, classification = 'internal') =>
  apiFetch<any>('/controls/assessment-summary', {
    method: 'POST',
    body: JSON.stringify({ claw, classification }),
    // Brain narration can take tens of seconds, which is exactly when the proxy
    // is most likely to hand this request a recycled socket.
    retryTransient: true,
  });
export const syncProwlerCatalog = () =>
  apiFetch<any>('/controls/sync/prowler', { method: 'POST' });
export const syncNistCatalog = () =>
  apiFetch<any>('/controls/sync/nist', { method: 'POST' });
export const attachControlEvaluators = () =>
  apiFetch<any>('/controls/collectors/attach', { method: 'POST' });
export const getConnectorControlScope = (connectorType: string) =>
  apiFetch<any>(`/controls/connector-scope/${encodeURIComponent(connectorType)}`, {
    retryTransient: true,
  });
export const getConnectorScopeCatalog = () =>
  apiFetch<any>('/controls/connector-scope', { retryTransient: true });
export const remediateControl = (control_id: string, requested_by = 'operator') =>
  apiFetch<any>('/controls/remediation/execute', {
    method: 'POST',
    body: JSON.stringify({ control_id, requested_by }),
  });

// --- Cowork governed executors -------------------------------------------------
// A Brain plans and authors; an Executor runs commands and tests in the approved
// project root. They are independent, so the UI reports them as separate fields
// rather than inferring an executor from whichever Brain answered.

export type CoworkExecutor = {
  executor: string;
  label: string;
  available: boolean;
  reason: string;
};

export type CoworkExecutorStatus = {
  executors: CoworkExecutor[];
  selected: string;
  selected_label: string;
  any_available: boolean;
  project_selected: boolean;
  needs_folder: boolean;
};

export const getCoworkExecutors = (params: {
  tenantId?: string;
  projectId?: string;
  preference?: string;
} = {}) => {
  const query = new URLSearchParams();
  if (params.tenantId) query.set('tenant_id', params.tenantId);
  if (params.projectId) query.set('project_id', params.projectId);
  if (params.preference) query.set('preference', params.preference);
  const suffix = query.toString();
  return apiFetch<CoworkExecutorStatus>(`/marcellus/cowork/executors${suffix ? `?${suffix}` : ''}`);
};
