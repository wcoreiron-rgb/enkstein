'use client';
import { useState, useEffect, useCallback } from 'react';
import {
  Bot, Play, Pause, RefreshCw, Eye, Zap, UserCheck,
  CheckCircle2, XCircle, Clock, AlertTriangle, ChevronDown,
  Activity, Shield, Info, X, ChevronRight, Loader2,
} from 'lucide-react';

import Link from 'next/link';
import { getAgents, updateAgent, triggerAgent, getAgentRuns } from '@/lib/api';
import ClientDate from '@/components/ClientDate';
import { capabilityName } from '@/lib/capability-names';

// ─── Types ───────────────────────────────────────────────────────────────────

type ExecutionMode = 'monitor' | 'assist' | 'autonomous';
type AgentStatus   = 'active' | 'paused' | 'draft' | 'retired';
type RunStatus     = 'pending' | 'running' | 'completed' | 'failed' | 'blocked' | 'awaiting' | 'cancelled';
type RiskLevel     = 'low' | 'medium' | 'high' | 'critical';

interface Agent {
  id: string;
  name: string;
  description: string;
  claw: string;
  category: string;
  icon: string;
  execution_mode: ExecutionMode;
  risk_level: RiskLevel;
  max_runtime_sec: number;
  requires_approval: boolean;
  allowed_connectors: string | null;
  owner_name: string | null;
  status: AgentStatus;
  is_builtin: boolean;
  total_runs: number;
  last_run_at: string | null;
  last_run_status: string | null;
}

interface AgentRun {
  id: string;
  agent_id: string;
  status: RunStatus;
  execution_mode: ExecutionMode;
  triggered_by: string;
  policy_decision: string | null;
  policy_name: string | null;
  risk_score: number | null;
  tf_blocked: boolean;
  findings_count: number;
  actions_taken: string | null;
  actions_blocked: string | null;
  actions_pending: string | null;
  summary: string | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_sec: number | null;
  created_at: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const MODE_META: Record<ExecutionMode, { label: string; icon: React.ElementType; color: string; bg: string; desc: string }> = {
  monitor:    { label: 'Monitor',    icon: Eye,       color: '#60a5fa', bg: 'rgba(59,130,246,0.12)',   desc: 'Observe & log only — zero writes' },
  assist:     { label: 'Assist',     icon: UserCheck, color: '#a78bfa', bg: 'rgba(139,92,246,0.12)',   desc: 'Suggest actions — require approval' },
  autonomous: { label: 'Autonomous', icon: Zap,       color: '#4ade80', bg: 'rgba(34,197,94,0.12)',    desc: 'Auto-execute pre-approved actions' },
};

const RISK_META: Record<RiskLevel, { color: string; bg: string }> = {
  low:      { color: '#4ade80', bg: 'rgba(34,197,94,0.12)' },
  medium:   { color: '#facc15', bg: 'rgba(234,179,8,0.12)' },
  high:     { color: '#fb923c', bg: 'rgba(249,115,22,0.12)' },
  critical: { color: '#f87171', bg: 'rgba(239,68,68,0.12)' },
};

const RUN_STATUS_META: Record<RunStatus, { color: string; icon: React.ElementType; label: string }> = {
  pending:   { color: '#94a3b8', icon: Clock,         label: 'Pending' },
  running:   { color: '#60a5fa', icon: Loader2,       label: 'Running' },
  completed: { color: '#4ade80', icon: CheckCircle2,  label: 'Completed' },
  failed:    { color: '#f87171', icon: XCircle,       label: 'Failed' },
  blocked:   { color: '#fb923c', icon: Shield,        label: 'Blocked' },
  awaiting:  { color: '#a78bfa', icon: UserCheck,     label: 'Awaiting Approval' },
  cancelled: { color: '#94a3b8', icon: X,             label: 'Cancelled' },
};

// ─── Sub-components ──────────────────────────────────────────────────────────

function ModeToggle({ mode, onChange, disabled }: {
  mode: ExecutionMode;
  onChange: (m: ExecutionMode) => void;
  disabled?: boolean;
}) {
  const modes: ExecutionMode[] = ['monitor', 'assist', 'autonomous'];
  return (
    <div className="flex rounded-lg overflow-hidden border" style={{ borderColor: 'var(--rc-border)' }}>
      {modes.map(m => {
        const { label, icon: Icon, color, bg } = MODE_META[m];
        const active = m === mode;
        return (
          <button
            key={m}
            onClick={() => !disabled && onChange(m)}
            title={MODE_META[m].desc}
            disabled={disabled}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-all duration-150"
            style={{
              background: active ? bg : 'var(--rc-bg-elevated)',
              color:      active ? color : 'var(--rc-text-3)',
              borderRight: m !== 'autonomous' ? '1px solid var(--rc-border)' : undefined,
              cursor: disabled ? 'not-allowed' : 'pointer',
            }}
          >
            <Icon className="w-3 h-3" />
            {label}
          </button>
        );
      })}
    </div>
  );
}

function RunStatusBadge({ status }: { status: RunStatus }) {
  const { color, icon: Icon, label } = RUN_STATUS_META[status];
  const isSpinning = status === 'running';
  return (
    <span className="flex items-center gap-1.5 text-xs font-medium">
      <Icon className={`w-3.5 h-3.5 ${isSpinning ? 'animate-spin' : ''}`} style={{ color }} />
      <span style={{ color }}>{label}</span>
    </span>
  );
}

function RunDrawer({ agent, onClose }: { agent: Agent; onClose: () => void }) {
  const [runs, setRuns]     = useState<AgentRun[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAgentRuns(agent.id, 20)
      .then(data => { setRuns(Array.isArray(data) ? data : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [agent.id]);

  return (
    <div
      className="fixed inset-y-0 right-0 w-[480px] z-50 flex flex-col border-l shadow-2xl"
      style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}
    >
      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b" style={{ borderColor: 'var(--rc-border)' }}>
        <span className="text-2xl">{agent.icon}</span>
        <div className="flex-1 min-w-0">
          <h2 className="font-bold text-sm truncate" style={{ color: 'var(--rc-text-1)' }}>{agent.name}</h2>
          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Run History · last 20 runs</p>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:opacity-70">
          <X className="w-4 h-4" style={{ color: 'var(--rc-text-3)' }} />
        </button>
      </div>

      {/* Runs list */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {loading && (
          <div className="flex justify-center py-12">
            <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--rc-text-3)' }} />
          </div>
        )}
        {!loading && runs.length === 0 && (
          <p className="text-center text-sm py-12" style={{ color: 'var(--rc-text-3)' }}>No runs yet — trigger the agent to start.</p>
        )}
        {runs.map(run => {
          const acted   = run.actions_taken   ? JSON.parse(run.actions_taken).length   : 0;
          const pending = run.actions_pending ? JSON.parse(run.actions_pending).length : 0;
          const blocked = run.actions_blocked ? JSON.parse(run.actions_blocked).length : 0;
          return (
            <div
              key={run.id}
              className="rounded-lg border p-3 space-y-2 text-xs"
              style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' }}
            >
              <div className="flex items-center justify-between">
                <RunStatusBadge status={run.status} />
                <span style={{ color: 'var(--rc-text-3)' }}>
                  <ClientDate value={run.created_at} />
                </span>
              </div>
              {run.summary && (
                <p style={{ color: 'var(--rc-text-2)' }}>{run.summary}</p>
              )}
              <div className="flex gap-4 pt-1">
                <span style={{ color: 'var(--rc-text-3)' }}>
                  Findings: <strong style={{ color: '#facc15' }}>{run.findings_count}</strong>
                </span>
                {acted > 0 && (
                  <span style={{ color: 'var(--rc-text-3)' }}>
                    Executed: <strong style={{ color: '#4ade80' }}>{acted}</strong>
                  </span>
                )}
                {pending > 0 && (
                  <span style={{ color: 'var(--rc-text-3)' }}>
                    Pending: <strong style={{ color: '#a78bfa' }}>{pending}</strong>
                  </span>
                )}
                {blocked > 0 && (
                  <span style={{ color: 'var(--rc-text-3)' }}>
                    Suppressed: <strong style={{ color: '#60a5fa' }}>{blocked}</strong>
                  </span>
                )}
                {run.duration_sec != null && (
                  <span style={{ color: 'var(--rc-text-3)' }}>
                    {run.duration_sec.toFixed(1)}s
                  </span>
                )}
              </div>
              {run.tf_blocked && (
                <p className="text-xs font-medium" style={{ color: '#fb923c' }}>
                  ⛔ Blocked by Trust Fabric: {run.policy_name}
                </p>
              )}
              {run.error_message && (
                <p className="text-xs" style={{ color: '#f87171' }}>Error: {run.error_message}</p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Agent Card ──────────────────────────────────────────────────────────────

function AgentCard({ agent, onModeChange, onRun }: {
  agent: Agent;
  onModeChange: (id: string, mode: ExecutionMode) => void;
  onRun: (agent: Agent) => void;
}) {
  const [showHistory, setShowHistory] = useState(false);
  const [triggering, setTriggering]   = useState(false);
  const modeInfo = MODE_META[agent.execution_mode];
  const riskInfo = RISK_META[agent.risk_level];

  return (
    <>
      <div
        className="rounded-xl border p-4 space-y-3 transition-all duration-150 hover:border-opacity-70"
        style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}
      >
        {/* Header row */}
        <div className="flex items-start gap-3">
          <span className="text-2xl flex-shrink-0">{agent.icon}</span>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="font-semibold text-sm" style={{ color: 'var(--rc-text-1)' }}>
                {agent.name}
              </h3>
              {agent.is_builtin && (
                <span className="text-xs px-1.5 py-0.5 rounded border"
                  style={{ background: 'rgba(99,102,241,0.12)', borderColor: '#4f46e5', color: '#818cf8', fontSize: '10px' }}>
                  Built-in
                </span>
              )}
              <span className="text-xs px-1.5 py-0.5 rounded border"
                style={{ background: riskInfo.bg, borderColor: riskInfo.color, color: riskInfo.color, fontSize: '10px' }}>
                {agent.risk_level.toUpperCase()}
              </span>
              <span className="text-xs px-1.5 py-0.5 rounded"
                style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-3)', fontSize: '10px' }}>
                {capabilityName(agent.claw)}
              </span>
            </div>
            <p className="text-xs mt-1 line-clamp-2" style={{ color: 'var(--rc-text-2)' }}>
              {agent.description}
            </p>
          </div>
        </div>

        {/* Mode toggle */}
        <div className="space-y-1">
          <p className="text-xs font-medium" style={{ color: 'var(--rc-text-3)' }}>Execution Mode</p>
          <ModeToggle
            mode={agent.execution_mode}
            onChange={m => onModeChange(agent.id, m)}
            disabled={agent.status !== 'active'}
          />
          <p className="text-xs" style={{ color: modeInfo.color }}>
            {modeInfo.icon && <span className="inline-block mr-1">›</span>}
            {modeInfo.desc}
          </p>
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--rc-text-3)' }}>
          <span className="flex items-center gap-1">
            <Activity className="w-3 h-3" />
            {agent.total_runs} runs
          </span>
          {agent.last_run_at && (
            <span>Last: <ClientDate value={agent.last_run_at} format="date" /></span>
          )}
          {agent.last_run_status && (
            <RunStatusBadge status={agent.last_run_status as RunStatus} />
          )}
          {agent.owner_name && (
            <span className="ml-auto">{agent.owner_name}</span>
          )}
        </div>

        {/* Action row */}
        <div className="flex items-center gap-2 pt-1 border-t" style={{ borderColor: 'var(--rc-border)' }}>
          <button
            onClick={() => { setTriggering(true); onRun(agent); setTimeout(() => setTriggering(false), 2000); }}
            disabled={agent.status !== 'active' || triggering}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150"
            style={{
              background: agent.status === 'active' ? 'var(--regent-600)' : 'var(--rc-bg-elevated)',
              color: agent.status === 'active' ? '#fff' : 'var(--rc-text-3)',
              cursor: agent.status !== 'active' ? 'not-allowed' : 'pointer',
            }}
          >
            {triggering
              ? <Loader2 className="w-3 h-3 animate-spin" />
              : <Play className="w-3 h-3" />
            }
            Run Now
          </button>
          <button
            onClick={() => setShowHistory(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all hover:opacity-80"
            style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}
          >
            <Clock className="w-3 h-3" />
            History
          </button>
          {agent.requires_approval && (
            <span className="ml-auto flex items-center gap-1 text-xs" style={{ color: '#a78bfa' }}>
              <Shield className="w-3 h-3" />
              Approval required
            </span>
          )}
        </div>
      </div>

      {showHistory && <RunDrawer agent={agent} onClose={() => setShowHistory(false)} />}
    </>
  );
}


// ─── Main Page ───────────────────────────────────────────────────────────────

export default function AgentsPage() {
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [loading, setLoading]     = useState(true);
  const [filter, setFilter]       = useState<string>('ALL');
  const [runToast, setRunToast]   = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    getAgents()
      .then(data => { setAgents(Array.isArray(data) ? data : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleModeChange = async (agentId: string, mode: ExecutionMode) => {
    await updateAgent(agentId, { execution_mode: mode });
    setAgents(prev => prev.map(a => a.id === agentId ? { ...a, execution_mode: mode } : a));
  };

  const handleRun = async (agent: Agent) => {
    try {
      const data = await triggerAgent(agent.id, { triggered_by: 'manual' });
      setRunToast(`${agent.icon} ${agent.name} triggered — ${data.message}`);
      setTimeout(() => { setRunToast(null); load(); }, 3500);
    } catch (e) {
      setRunToast(`✕ Failed to trigger ${agent.name}`);
      setTimeout(() => setRunToast(null), 3500);
    }
  };

  // Categories from loaded agents
  const categories = ['ALL', ...Array.from(new Set(agents.map(a => a.category).filter(Boolean)))];
  const filtered = filter === 'ALL'
    ? agents
    : agents.filter(a => a.category === filter);

  // Stats
  const stats = {
    total:      agents.length,
    active:     agents.filter(a => a.status === 'active').length,
    monitor:    agents.filter(a => a.execution_mode === 'monitor').length,
    assist:     agents.filter(a => a.execution_mode === 'assist').length,
    autonomous: agents.filter(a => a.execution_mode === 'autonomous').length,
  };

  return (
    <div className="p-6 space-y-6">
      {/* Toast */}
      {runToast && (
        <div
          className="fixed top-4 right-4 z-50 px-4 py-3 rounded-xl border text-sm font-medium shadow-lg"
          style={{ background: 'var(--rc-bg-surface)', borderColor: '#4ade80', color: '#4ade80' }}
        >
          ✓ {runToast}
        </div>
      )}

      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--rc-text-1)' }}>Security Agents</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--rc-text-3)' }}>
            Governed automation — every agent runs through Trust Fabric
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={load}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-all hover:opacity-80"
            style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <Link href="/agents/new"
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all hover:opacity-90"
            style={{ background: 'var(--regent-600)', color: '#fff' }}
          >
            <Bot className="w-3.5 h-3.5" />
            Create Agent
          </Link>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Total Agents', value: stats.total,      color: 'var(--rc-text-1)' },
          { label: 'Active',       value: stats.active,     color: '#4ade80' },
          { label: 'Monitor',      value: stats.monitor,    color: '#60a5fa' },
          { label: 'Assist',       value: stats.assist,     color: '#a78bfa' },
          { label: 'Autonomous',   value: stats.autonomous, color: '#4ade80' },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-xl border p-3 text-center"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <p className="text-2xl font-bold" style={{ color }}>{value}</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>{label}</p>
          </div>
        ))}
      </div>

      {/* Mode legend */}
      <div className="rounded-xl border p-4 flex gap-6 flex-wrap"
        style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        <p className="text-xs font-semibold self-center" style={{ color: 'var(--rc-text-3)' }}>EXECUTION MODES</p>
        {Object.entries(MODE_META).map(([key, m]) => {
          const Icon = m.icon;
          return (
            <div key={key} className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: m.bg }}>
                <Icon className="w-3.5 h-3.5" style={{ color: m.color }} />
              </div>
              <div>
                <p className="text-xs font-semibold" style={{ color: m.color }}>{m.label}</p>
                <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{m.desc}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Category filter */}
      <div className="flex gap-2 flex-wrap">
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150"
            style={filter === cat
              ? { background: 'var(--regent-600)', color: '#fff' }
              : { background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Agent grid */}
      {loading ? (
        <div className="flex justify-center py-24">
          <Loader2 className="w-8 h-8 animate-spin" style={{ color: 'var(--rc-text-3)' }} />
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-24">
          <Bot className="w-12 h-12 mx-auto mb-3 opacity-30" style={{ color: 'var(--rc-text-3)' }} />
          <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>
            No agents yet. Run <code className="px-1 rounded" style={{ background: 'var(--rc-bg-elevated)' }}>python seed_agents.py</code> in the backend to load prebuilt agents.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map(agent => (
            <AgentCard
              key={agent.id}
              agent={agent}
              onModeChange={handleModeChange}
              onRun={handleRun}
            />
          ))}
        </div>
      )}
    </div>
  );
}
