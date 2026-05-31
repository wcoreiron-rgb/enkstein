'use client';
import { useState, useEffect, useCallback } from 'react';
import {
  CalendarClock, Play, Pause, RefreshCw, CheckCircle2,
  XCircle, Clock, AlertTriangle, Loader2, X, Bot,
  Eye, Zap, UserCheck, Activity, ChevronDown,
  Cloud, Users, Key, Monitor, Network, Database, Code, Package,
  Target, BookOpen, UserX, GitMerge, Radar, ClipboardCheck,
  Lock, Handshake, GitBranch, Settings, RefreshCcw, Shield,
} from 'lucide-react';

import { getSchedules, getAgents, updateSchedule, triggerSchedule, triggerScheduleSwarm } from '@/lib/api';

// ─── Types ───────────────────────────────────────────────────────────────────

type ScheduleFrequency = 'manual' | 'every_15min' | 'hourly' | 'every_6h' | 'daily' | 'weekly' | 'monthly';
type ScheduleStatus    = 'active' | 'paused' | 'disabled';
type ExecutionMode     = 'monitor' | 'assist' | 'autonomous';

interface Schedule {
  id: string;
  name: string;
  agent_id: string;
  connector_id: string | null;
  frequency: ScheduleFrequency;
  status: ScheduleStatus;
  approval_required: boolean;
  owner_name: string | null;
  notes: string | null;
  next_run_at: string | null;
  last_run_at: string | null;
  run_count: number;
  created_at: string;
}

interface Agent {
  id: string;
  name: string;
  icon: string;
  claw: string;
  execution_mode: ExecutionMode;
  category: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const FREQ_META: Record<ScheduleFrequency, { label: string; color: string }> = {
  manual:       { label: 'Manual',     color: '#94a3b8' },
  every_15min:  { label: 'Every 15m',  color: '#f87171' },
  hourly:       { label: 'Hourly',     color: '#fb923c' },
  every_6h:     { label: 'Every 6h',   color: '#facc15' },
  daily:        { label: 'Daily',      color: '#4ade80' },
  weekly:       { label: 'Weekly',     color: '#60a5fa' },
  monthly:      { label: 'Monthly',    color: '#a78bfa' },
};

const STATUS_META: Record<ScheduleStatus, { color: string; bg: string; label: string }> = {
  active:   { color: '#4ade80', bg: 'rgba(34,197,94,0.12)',   label: 'Active' },
  paused:   { color: '#facc15', bg: 'rgba(234,179,8,0.12)',   label: 'Paused' },
  disabled: { color: '#94a3b8', bg: 'rgba(148,163,184,0.12)', label: 'Disabled' },
};

const MODE_ICON: Record<ExecutionMode, React.ElementType> = {
  monitor:    Eye,
  assist:     UserCheck,
  autonomous: Zap,
};

const MODE_COLOR: Record<ExecutionMode, string> = {
  monitor:    '#60a5fa',
  assist:     '#a78bfa',
  autonomous: '#4ade80',
};

// Maps agent claw names → lucide icon (mirrors the sidebar exactly)
const CLAW_ICON: Record<string, React.ElementType> = {
  arcclaw:        Zap,
  cloudclaw:      Cloud,
  identityclaw:   Users,
  accessclaw:     Key,
  endpointclaw:   Monitor,
  netclaw:        Network,
  dataclaw:       Database,
  appclaw:        Code,
  saasclaw:       Package,
  threatclaw:     Target,
  logclaw:        BookOpen,
  intelclaw:      Eye,
  userclaw:       UserCheck,
  insiderclaw:    UserX,
  automationclaw: Bot,
  attackpathclaw: GitMerge,
  exposureclaw:   Radar,
  complianceclaw: ClipboardCheck,
  privacyclaw:    Lock,
  vendorclaw:     Handshake,
  devclaw:        GitBranch,
  configclaw:     Settings,
  recoveryclaw:   RefreshCcw,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function timeUntil(dateStr: string | null): string {
  if (!dateStr) return '—';
  const diff = new Date(dateStr).getTime() - Date.now();
  if (diff < 0) return 'Overdue';
  const m = Math.floor(diff / 60000);
  if (m < 60) return `in ${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `in ${h}h`;
  return `in ${Math.floor(h / 24)}d`;
}

function fmtDate(s: string | null): string {
  if (!s) return '—';
  return new Date(s).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function isSwarmSchedule(notes: string | null): boolean {
  if (!notes) return false;
  try {
    const parsed = JSON.parse(notes);
    const actionType = String(parsed?.type || '').toUpperCase();
    return actionType === 'SWARM_JOB' || actionType === 'START_SWARM' || actionType === 'FIRE_SWARM';
  } catch {
    return false;
  }
}

// ─── Schedule Row ─────────────────────────────────────────────────────────────

function ScheduleRow({ sched, agent, onToggle, onRun }: {
  sched: Schedule;
  agent?: Agent;
  onToggle: (id: string, current: ScheduleStatus) => void;
  onRun: (id: string, name: string) => void;
}) {
  const [running, setRunning] = useState(false);
  const swarmMode = isSwarmSchedule(sched.notes);
  const freq   = FREQ_META[sched.frequency];
  const status = STATUS_META[sched.status];
  const ModeIcon  = agent ? MODE_ICON[agent.execution_mode] : Bot;
  const modeColor = agent ? MODE_COLOR[agent.execution_mode] : '#94a3b8';
  const ClawIcon  = agent ? (CLAW_ICON[agent.claw] ?? Bot) : Bot;
  const clawColor = modeColor;

  const isOverdue = sched.next_run_at && new Date(sched.next_run_at) < new Date();

  return (
    <tr className="border-b transition-colors hover:bg-[var(--rc-bg-elevated)]"
      style={{ borderColor: 'var(--rc-border)' }}>
      {/* Name + agent */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center w-7 h-7 rounded-lg flex-shrink-0"
            style={{ background: `${clawColor}1a`, color: clawColor }}>
            <ClawIcon className="w-4 h-4" />
          </span>
          <div>
            <p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{sched.name}</p>
            {agent && (
              <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{agent.name}</p>
            )}
          </div>
        </div>
      </td>

      {/* Frequency */}
      <td className="px-4 py-3">
        <span className="text-xs font-semibold" style={{ color: freq.color }}>{freq.label}</span>
      </td>

      {/* Mode */}
      <td className="px-4 py-3">
        <span className="flex items-center gap-1.5 text-xs" style={{ color: modeColor }}>
          <ModeIcon className="w-3.5 h-3.5" />
          {agent ? agent.execution_mode.charAt(0).toUpperCase() + agent.execution_mode.slice(1) : '—'}
        </span>
      </td>

      {/* Status */}
      <td className="px-4 py-3">
        <span className="px-2 py-1 rounded-md text-xs font-medium"
          style={{ background: status.bg, color: status.color }}>
          {status.label}
        </span>
      </td>

      {/* Next run */}
      <td className="px-4 py-3">
        <div>
          <p className="text-xs font-medium" style={{ color: isOverdue ? '#f87171' : 'var(--rc-text-2)' }}>
            {timeUntil(sched.next_run_at)}
          </p>
          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            {fmtDate(sched.next_run_at)}
          </p>
        </div>
      </td>

      {/* Last run */}
      <td className="px-4 py-3">
        <div>
          <p className="text-xs" style={{ color: 'var(--rc-text-2)' }}>{fmtDate(sched.last_run_at)}</p>
          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{sched.run_count} total runs</p>
        </div>
      </td>

      {/* Approval */}
      <td className="px-4 py-3">
        {swarmMode ? (
          <span className="text-xs" style={{ color: '#22d3ee' }}>Swarm</span>
        ) : sched.approval_required
          ? <span className="text-xs" style={{ color: '#a78bfa' }}>Required</span>
          : <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>None</span>
        }
      </td>

      {/* Actions */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setRunning(true); onRun(sched.id, sched.name); setTimeout(() => setRunning(false), 2000); }}
            disabled={sched.status === 'disabled' || running}
            title={swarmMode ? "Run Swarm Job" : "Run now"}
            className="p-1.5 rounded-lg transition-all hover:opacity-80"
            style={{ background: 'rgba(34,197,94,0.12)', color: '#4ade80' }}
          >
            {running ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={() => onToggle(sched.id, sched.status)}
            title={sched.status === 'active' ? 'Pause' : 'Resume'}
            className="p-1.5 rounded-lg transition-all hover:opacity-80"
            style={{
              background: sched.status === 'active' ? 'rgba(234,179,8,0.12)' : 'rgba(34,197,94,0.12)',
              color:      sched.status === 'active' ? '#facc15' : '#4ade80',
            }}
          >
            {sched.status === 'active' ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>
        </div>
      </td>
    </tr>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SchedulesPage() {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [agentMap, setAgentMap]   = useState<Record<string, Agent>>({});
  const [loading, setLoading]     = useState(true);
  const [toast, setToast]         = useState<string | null>(null);
  const [filter, setFilter]       = useState<ScheduleStatus | 'ALL'>('ALL');

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [scheds, agents] = await Promise.all([
        getSchedules(),
        getAgents(),
      ]);
      setSchedules(Array.isArray(scheds) ? scheds : []);
      const map: Record<string, Agent> = {};
      if (Array.isArray(agents)) agents.forEach((a: Agent) => { map[a.id] = a; });
      setAgentMap(map);
    } catch (_) {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleToggle = async (id: string, current: ScheduleStatus) => {
    const newStatus = current === 'active' ? 'paused' : 'active';
    await updateSchedule(id, { status: newStatus });
    setSchedules(prev => prev.map(s => s.id === id ? { ...s, status: newStatus as ScheduleStatus } : s));
  };

  const handleRun = async (id: string, name: string) => {
    try {
      const schedule = schedules.find(s => s.id === id);
      const data = schedule && isSwarmSchedule(schedule.notes)
        ? await triggerScheduleSwarm(id)
        : await triggerSchedule(id);
      showToast(`▶ ${name} — ${data.message || 'Triggered'}`);
      setTimeout(load, 2000);
    } catch {
      showToast(`✕ Failed to trigger ${name}`);
    }
  };

  const filtered = filter === 'ALL' ? schedules : schedules.filter(s => s.status === filter);

  // Stats
  const stats = {
    total:    schedules.length,
    active:   schedules.filter(s => s.status === 'active').length,
    paused:   schedules.filter(s => s.status === 'paused').length,
    overdue:  schedules.filter(s => s.next_run_at && new Date(s.next_run_at) < new Date()).length,
    total_runs: schedules.reduce((acc, s) => acc + s.run_count, 0),
  };

  return (
    <div className="p-6 space-y-6">
      {/* Toast */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 px-4 py-3 rounded-xl border text-sm font-medium shadow-lg"
          style={{ background: 'var(--rc-bg-surface)', borderColor: '#4ade80', color: '#4ade80' }}>
          {toast}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--rc-text-1)' }}>Scheduled Jobs</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--rc-text-3)' }}>
            Automated security agent runs — governed by Trust Fabric
          </p>
        </div>
        <button onClick={load}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-all hover:opacity-80"
          style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}>
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Total Schedules', value: stats.total,      color: 'var(--rc-text-1)' },
          { label: 'Active',          value: stats.active,     color: '#4ade80' },
          { label: 'Paused',          value: stats.paused,     color: '#facc15' },
          { label: 'Overdue',         value: stats.overdue,    color: '#f87171' },
          { label: 'Total Runs',      value: stats.total_runs, color: '#60a5fa' },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-xl border p-3 text-center"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <p className="text-2xl font-bold" style={{ color }}>{value}</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>{label}</p>
          </div>
        ))}
      </div>

      {/* Filter pills */}
      <div className="flex gap-2">
        {(['ALL', 'active', 'paused', 'disabled'] as const).map(s => (
          <button key={s}
            onClick={() => setFilter(s)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
            style={filter === s
              ? { background: 'var(--regent-600)', color: '#fff' }
              : { background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}>
            {s === 'ALL' ? 'All Schedules' : s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="rounded-xl border overflow-hidden"
        style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        {loading ? (
          <div className="flex justify-center py-24">
            <Loader2 className="w-8 h-8 animate-spin" style={{ color: 'var(--rc-text-3)' }} />
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-24">
            <CalendarClock className="w-12 h-12 mx-auto mb-3 opacity-30" style={{ color: 'var(--rc-text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>
              No schedules. Run <code className="px-1 rounded" style={{ background: 'var(--rc-bg-elevated)' }}>python seed_agents.py</code> to load defaults.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
                  {['Schedule / Agent', 'Frequency', 'Mode', 'Status', 'Next Run', 'Last Run', 'Approval', 'Actions'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wider"
                      style={{ color: 'var(--rc-text-3)' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(sched => (
                  <ScheduleRow
                    key={sched.id}
                    sched={sched}
                    agent={agentMap[sched.agent_id]}
                    onToggle={handleToggle}
                    onRun={handleRun}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
