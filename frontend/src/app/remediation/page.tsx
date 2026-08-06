'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  ShieldAlert, CheckCircle, XCircle, RotateCcw, Clock, AlertTriangle,
  Zap, RefreshCcw, ChevronDown, ChevronUp, PlayCircle, ToggleLeft, ToggleRight,
  Shield, Activity, Ban
} from 'lucide-react';
import { capabilityName, marcellusText } from '@/lib/capability-names';
import { apiFetch, getControlRemediationProposals, remediateControl } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

interface RemAction {
  id: string;
  finding_id: string | null;
  playbook_id: string | null;
  provider: string;
  action_type: string;
  target_type: string;
  target_id: string;
  target_label: string | null;
  status: string;
  risk_level: string;
  requires_approval: boolean;
  triggered_by: string;
  approved_by: string | null;
  rejected_reason: string | null;
  approval_expires_at: string | null;
  executed_at: string | null;
  completed_at: string | null;
  output: Record<string, unknown> | null;
  error: string | null;
  rollback_data: Record<string, unknown> | null;
  created_at: string | null;
}

interface Playbook {
  id: string;
  slug: string | null;
  name: string;
  description: string | null;
  trigger_claw: string | null;
  trigger_severity: string | null;
  trigger_keywords: string[];
  actions: Array<{ provider: string; action_type: string; risk_level: string }>;
  is_active: boolean;
  requires_approval: boolean;
  run_count: number;
}

interface Stats {
  pending_approval: number;
  executing: number;
  completed_today: number;
  failed: number;
  rolled_back: number;
  timed_out: number;
  total: number;
  active_playbooks: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
};

const STATUS_COLORS: Record<string, string> = {
  pending_approval: '#f97316',
  approved:         '#3b82f6',
  rejected:         '#ef4444',
  executing:        '#a855f7',
  completed:        '#22c55e',
  failed:           '#ef4444',
  rolled_back:      '#6b7280',
  timed_out:        '#6b7280',
};

function RiskBadge({ level }: { level: string }) {
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold uppercase"
      style={{ background: RISK_COLORS[level] + '22', color: RISK_COLORS[level], border: `1px solid ${RISK_COLORS[level]}44` }}
    >
      {level}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLORS[status] || '#6b7280';
  const label = status.replace(/_/g, ' ');
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium capitalize"
      style={{ background: color + '22', color, border: `1px solid ${color}44` }}
    >
      {status === 'executing' && <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse" />}
      {label}
    </span>
  );
}

function fmt(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

function fmtRelative(iso: string | null): string {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ─── API functions ────────────────────────────────────────────────────────────

// These went through a bare fetch against an absolute localhost URL, which
// sent no bearer token and could not resolve from the packaged desktop app.
// apiFetch uses the same-origin proxy and carries the operator's session.

async function fetchStats(): Promise<Stats> {
  return apiFetch<Stats>('/remediation/stats');
}

async function fetchActions(status?: string): Promise<RemAction[]> {
  const query = status ? `?status=${encodeURIComponent(status)}&limit=100` : '?limit=100';
  const data = await apiFetch<{ actions?: RemAction[] }>(`/remediation/actions${query}`);
  return data.actions || [];
}

async function fetchPlaybooks(): Promise<Playbook[]> {
  const data = await apiFetch<{ playbooks?: Playbook[] }>('/remediation/playbooks');
  return data.playbooks || [];
}

/** Approver identity comes from the bearer token server-side, not the body. */
async function approveAction(id: string): Promise<RemAction> {
  return apiFetch<RemAction>(`/remediation/actions/${id}/approve`, {
    method: 'POST',
    body: JSON.stringify({}),
  });
}

async function rejectAction(id: string, reason: string): Promise<RemAction> {
  return apiFetch<RemAction>(`/remediation/actions/${id}/reject`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

async function rollbackAction(id: string): Promise<RemAction> {
  return apiFetch<RemAction>(`/remediation/actions/${id}/rollback`, { method: 'POST' });
}

async function togglePlaybook(id: string): Promise<Playbook> {
  return apiFetch<Playbook>(`/remediation/playbooks/${id}/toggle`, { method: 'POST' });
}

// ─── Approval Queue Card ──────────────────────────────────────────────────────

function ApprovalCard({ action, onApprove, onReject }: {
  action: RemAction;
  onApprove: (id: string) => Promise<void>;
  onReject: (id: string, reason: string) => Promise<void>;
}) {
  const [rejectMode, setRejectMode]   = useState(false);
  const [reason, setReason]           = useState('');
  const [loading, setLoading]         = useState(false);
  const [expanded, setExpanded]       = useState(false);

  const expiresAt = action.approval_expires_at ? new Date(action.approval_expires_at) : null;
  const now       = new Date();
  const expired   = expiresAt ? expiresAt < now : false;
  const minutesLeft = expiresAt ? Math.max(0, Math.floor((expiresAt.getTime() - now.getTime()) / 60000)) : 0;

  return (
    <div
      className="rounded-xl border p-4 space-y-3"
      style={{ background: 'var(--rc-surface)', borderColor: expired ? '#ef444488' : '#f9731644' }}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <RiskBadge level={action.risk_level} />
            <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}>
              {action.provider}
            </span>
            <span className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
              {action.action_type.replace(/_/g, ' ')}
            </span>
          </div>
          <p className="text-sm mt-1" style={{ color: 'var(--rc-text-2)' }}>
            Target: <span className="font-mono text-xs">{action.target_label || action.target_id}</span>
            <span className="ml-2 text-xs" style={{ color: 'var(--rc-text-3)' }}>({action.target_type})</span>
          </p>
          {action.triggered_by && (
            <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
              Triggered by: {action.triggered_by} · {fmtRelative(action.created_at)}
            </p>
          )}
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {expired ? (
            <span className="text-xs text-red-400 flex items-center gap-1">
              <Clock className="w-3 h-3" /> Expired
            </span>
          ) : expiresAt ? (
            <span className="text-xs flex items-center gap-1" style={{ color: 'var(--rc-text-3)' }}>
              <Clock className="w-3 h-3" /> {minutesLeft}m left
            </span>
          ) : null}
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1 rounded hover:opacity-70"
            style={{ color: 'var(--rc-text-3)' }}
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="rounded-lg p-3 text-xs font-mono space-y-1" style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}>
          <div>action_id: {action.id}</div>
          {action.finding_id && <div>finding_id: {action.finding_id}</div>}
          {action.playbook_id && <div>playbook_id: {action.playbook_id}</div>}
          <div>created_at: {fmt(action.created_at)}</div>
          {expiresAt && <div>approval_expires: {fmt(action.approval_expires_at)}</div>}
        </div>
      )}

      {/* Action buttons */}
      {!expired && !rejectMode && (
        <div className="flex items-center gap-2">
          <button
            disabled={loading}
            onClick={async () => {
              setLoading(true);
              await onApprove(action.id);
              setLoading(false);
            }}
            className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-opacity disabled:opacity-50"
            style={{ background: '#22c55e22', color: '#22c55e', border: '1px solid #22c55e44' }}
          >
            <CheckCircle className="w-4 h-4" />
            {loading ? 'Approving…' : 'Approve & Execute'}
          </button>
          <button
            disabled={loading}
            onClick={() => setRejectMode(true)}
            className="flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-opacity disabled:opacity-50"
            style={{ background: '#ef444422', color: '#ef4444', border: '1px solid #ef444444' }}
          >
            <XCircle className="w-4 h-4" />
            Reject
          </button>
        </div>
      )}

      {rejectMode && (
        <div className="space-y-2">
          <textarea
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="Rejection reason…"
            rows={2}
            className="w-full rounded-lg px-3 py-2 text-sm resize-none outline-none"
            style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-1)', border: '1px solid var(--rc-border)' }}
          />
          <div className="flex gap-2">
            <button
              disabled={loading}
              onClick={async () => {
                setLoading(true);
                await onReject(action.id, reason || 'Rejected by admin');
                setLoading(false);
                setRejectMode(false);
              }}
              className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium"
              style={{ background: '#ef444422', color: '#ef4444', border: '1px solid #ef444444' }}
            >
              <XCircle className="w-3.5 h-3.5" />
              {loading ? 'Rejecting…' : 'Confirm Reject'}
            </button>
            <button
              onClick={() => { setRejectMode(false); setReason(''); }}
              className="px-3 py-1.5 rounded-lg text-sm"
              style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {expired && (
        <p className="text-xs text-red-400">This approval window has expired. The action was not executed.</p>
      )}
    </div>
  );
}

// ─── History Row ──────────────────────────────────────────────────────────────

function ActionRow({ action, onRollback }: { action: RemAction; onRollback: (id: string) => Promise<void> }) {
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr
        className="border-b transition-colors hover:opacity-80 cursor-pointer"
        style={{ borderColor: 'var(--rc-border)' }}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-1.5 py-0.5 rounded" style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}>
              {action.provider}
            </span>
            <span className="text-sm" style={{ color: 'var(--rc-text-1)' }}>
              {action.action_type.replace(/_/g, ' ')}
            </span>
          </div>
        </td>
        <td className="px-4 py-3 text-sm font-mono" style={{ color: 'var(--rc-text-2)' }}>
          {action.target_label || action.target_id}
        </td>
        <td className="px-4 py-3">
          <StatusBadge status={action.status} />
        </td>
        <td className="px-4 py-3">
          <RiskBadge level={action.risk_level} />
        </td>
        <td className="px-4 py-3 text-xs" style={{ color: 'var(--rc-text-3)' }}>
          {fmtRelative(action.completed_at || action.created_at)}
        </td>
        <td className="px-4 py-3 text-right">
          <div className="flex items-center justify-end gap-2">
            {action.status === 'completed' && action.rollback_data && (
              <button
                disabled={loading}
                onClick={async (e) => {
                  e.stopPropagation();
                  setLoading(true);
                  await onRollback(action.id);
                  setLoading(false);
                }}
                className="flex items-center gap-1 px-2 py-1 rounded text-xs transition-opacity disabled:opacity-50"
                style={{ background: '#6b728022', color: '#9ca3af', border: '1px solid #6b728044' }}
              >
                <RotateCcw className="w-3 h-3" />
                {loading ? '…' : 'Rollback'}
              </button>
            )}
            {expanded
              ? <ChevronUp className="w-4 h-4" style={{ color: 'var(--rc-text-3)' }} />
              : <ChevronDown className="w-4 h-4" style={{ color: 'var(--rc-text-3)' }} />}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr style={{ background: 'var(--rc-bg-elevated)' }}>
          <td colSpan={6} className="px-4 py-3">
            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
              <div className="space-y-1">
                <div><span style={{ color: 'var(--rc-text-3)' }}>action_id:</span> <span style={{ color: 'var(--rc-text-2)' }}>{action.id}</span></div>
                {action.finding_id && <div><span style={{ color: 'var(--rc-text-3)' }}>finding_id:</span> <span style={{ color: 'var(--rc-text-2)' }}>{action.finding_id}</span></div>}
                <div><span style={{ color: 'var(--rc-text-3)' }}>triggered_by:</span> <span style={{ color: 'var(--rc-text-2)' }}>{action.triggered_by}</span></div>
                {action.approved_by && <div><span style={{ color: 'var(--rc-text-3)' }}>approved_by:</span> <span style={{ color: 'var(--rc-text-2)' }}>{action.approved_by}</span></div>}
                {action.rejected_reason && <div><span style={{ color: 'var(--rc-text-3)' }}>rejected_reason:</span> <span style={{ color: '#ef4444' }}>{action.rejected_reason}</span></div>}
              </div>
              <div className="space-y-1">
                {action.executed_at && <div><span style={{ color: 'var(--rc-text-3)' }}>executed_at:</span> <span style={{ color: 'var(--rc-text-2)' }}>{fmt(action.executed_at)}</span></div>}
                {action.completed_at && <div><span style={{ color: 'var(--rc-text-3)' }}>completed_at:</span> <span style={{ color: 'var(--rc-text-2)' }}>{fmt(action.completed_at)}</span></div>}
                {action.output && (
                  <div>
                    <span style={{ color: 'var(--rc-text-3)' }}>output:</span>
                    <pre className="mt-1 p-2 rounded text-xs overflow-auto" style={{ background: 'var(--rc-bg)', color: 'var(--rc-text-2)', maxHeight: 120 }}>
                      {JSON.stringify(action.output, null, 2)}
                    </pre>
                  </div>
                )}
                {action.error && (
                  <div><span style={{ color: 'var(--rc-text-3)' }}>error:</span> <span style={{ color: '#ef4444' }}>{action.error}</span></div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Playbook Card ────────────────────────────────────────────────────────────

function PlaybookCard({ pb, onToggle }: { pb: Playbook; onToggle: (id: string) => Promise<void> }) {
  const [loading, setLoading] = useState(false);

  return (
    <div
      className="rounded-xl border p-4 space-y-3 transition-opacity"
      style={{
        background:   'var(--rc-surface)',
        borderColor:  pb.is_active ? 'var(--rc-brand)44' : 'var(--rc-border)',
        opacity:      pb.is_active ? 1 : 0.6,
      }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <Zap className="w-3.5 h-3.5" style={{ color: pb.is_active ? 'var(--rc-brand)' : 'var(--rc-text-3)' }} />
            <span className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{pb.name}</span>
            {pb.trigger_severity && (
              <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-3)' }}>
                {pb.trigger_severity}+
              </span>
            )}
            {pb.trigger_claw && (
              <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-3)' }}>
                {capabilityName(pb.trigger_claw)}
              </span>
            )}
          </div>
          {pb.description && (
            <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>{marcellusText(pb.description)}</p>
          )}
          {pb.trigger_keywords.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {pb.trigger_keywords.slice(0, 5).map(kw => (
                <span key={kw} className="text-xs px-1.5 py-0.5 rounded-full" style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-3)' }}>
                  {kw}
                </span>
              ))}
            </div>
          )}
        </div>
        <button
          disabled={loading}
          onClick={async () => {
            setLoading(true);
            await onToggle(pb.id);
            setLoading(false);
          }}
          className="flex-shrink-0 flex items-center gap-1 text-xs px-2 py-1 rounded-lg transition-opacity disabled:opacity-50"
          style={{
            background: pb.is_active ? '#22c55e22' : 'var(--rc-bg-elevated)',
            color:      pb.is_active ? '#22c55e'   : 'var(--rc-text-3)',
            border:     `1px solid ${pb.is_active ? '#22c55e44' : 'var(--rc-border)'}`,
          }}
        >
          {pb.is_active
            ? <><ToggleRight className="w-3.5 h-3.5" /> Enabled</>
            : <><ToggleLeft  className="w-3.5 h-3.5" /> Disabled</>}
        </button>
      </div>

      {/* Actions summary */}
      <div className="space-y-1">
        {pb.actions.map((a, i) => (
          <div key={i} className="flex items-center gap-2 text-xs" style={{ color: 'var(--rc-text-3)' }}>
            <span className="w-4 h-4 flex items-center justify-center rounded-full text-xs font-bold flex-shrink-0"
              style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)', fontSize: '9px' }}>
              {i + 1}
            </span>
            <span className="font-mono" style={{ color: 'var(--rc-text-2)' }}>{a.provider}</span>
            <span>·</span>
            <span>{a.action_type.replace(/_/g, ' ')}</span>
            <RiskBadge level={a.risk_level} />
          </div>
        ))}
      </div>

      <div className="flex items-center justify-between text-xs" style={{ color: 'var(--rc-text-3)' }}>
        <span>{pb.run_count} runs</span>
        <span>{pb.requires_approval ? 'Requires approval' : 'Auto-executes'}</span>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function RemediationPage() {
  const [stats,     setStats]     = useState<Stats | null>(null);
  const [pending,   setPending]   = useState<RemAction[]>([]);
  const [history,   setHistory]   = useState<RemAction[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loading,   setLoading]   = useState(true);
  const [tab,       setTab]       = useState<'all' | 'completed' | 'failed'>('all');
  const [proposals, setProposals] = useState<any | null>(null);
  const [proposing, setProposing] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, pend, hist, pbs, props] = await Promise.all([
        fetchStats(),
        fetchActions('pending_approval'),
        fetchActions(),
        fetchPlaybooks(),
        // Failing controls from the assessment. Without this the page shows an
        // empty queue while the node pages report open violations, which reads
        // as "nothing to do" when the opposite is true.
        getControlRemediationProposals().catch(() => null),
      ]);
      setStats(s);
      setPending(pend);
      setHistory(hist.filter(a => a.status !== 'pending_approval'));
      setPlaybooks(pbs);
      setProposals(props);
    } catch (e) {
      console.error('Remediation fetch error:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  const handlePropose = useCallback(async (controlId: string) => {
    setProposing(controlId);
    try {
      await remediateControl(controlId);
      await refresh();
    } finally {
      setProposing(null);
    }
  }, [refresh]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 15000);
    return () => clearInterval(interval);
  }, [refresh]);

  const handleApprove = useCallback(async (id: string) => {
    await approveAction(id);
    await refresh();
  }, [refresh]);

  const handleReject = useCallback(async (id: string, reason: string) => {
    await rejectAction(id, reason);
    await refresh();
  }, [refresh]);

  const handleRollback = useCallback(async (id: string) => {
    await rollbackAction(id);
    await refresh();
  }, [refresh]);

  const handleTogglePlaybook = useCallback(async (id: string) => {
    await togglePlaybook(id);
    await refresh();
  }, [refresh]);

  const filteredHistory = history.filter(a => {
    if (tab === 'completed') return a.status === 'completed' || a.status === 'rolled_back';
    if (tab === 'failed')    return a.status === 'failed' || a.status === 'timed_out';
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCcw className="w-6 h-6 animate-spin" style={{ color: 'var(--rc-brand)' }} />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-8 max-w-7xl mx-auto">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-7 h-7" style={{ color: 'var(--rc-accent)' }} />
          <div>
            <h1 className="text-xl font-bold" style={{ color: 'var(--rc-text-1)' }}>
              Autonomous Remediation
            </h1>
            <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>
              Governed auto-remediation — approval queue, action history, rollback
            </p>
          </div>
        </div>
        <button
          onClick={refresh}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm"
          style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}
        >
          <RefreshCcw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
          {[
            { label: 'Pending Approval', value: stats.pending_approval,  icon: Clock,        color: '#f97316' },
            { label: 'Executing',        value: stats.executing,         icon: Activity,     color: '#a855f7' },
            { label: 'Done Today',       value: stats.completed_today,   icon: CheckCircle,  color: '#22c55e' },
            { label: 'Failed',           value: stats.failed,            icon: XCircle,      color: '#ef4444' },
            { label: 'Rolled Back',      value: stats.rolled_back,       icon: RotateCcw,    color: '#6b7280' },
            { label: 'Timed Out',        value: stats.timed_out,         icon: Ban,          color: '#6b7280' },
            { label: 'Total Actions',    value: stats.total,             icon: Shield,       color: 'var(--rc-brand)' },
            { label: 'Active Playbooks', value: stats.active_playbooks,  icon: Zap,          color: '#22c55e' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div
              key={label}
              className="rounded-xl border p-3 flex flex-col items-center gap-1 text-center"
              style={{ background: 'var(--rc-surface)', borderColor: 'var(--rc-border)' }}
            >
              <Icon className="w-4 h-4" style={{ color }} />
              <div className="text-xl font-bold" style={{ color: 'var(--rc-text-1)' }}>{value}</div>
              <div className="text-xs leading-tight" style={{ color: 'var(--rc-text-3)' }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Failing controls from the assessment */}
      {proposals && (proposals.actionable?.length || proposals.advisory_only?.length) ? (
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5" style={{ color: 'var(--rc-brand)' }} />
            <h2 className="text-base font-semibold" style={{ color: 'var(--rc-text-1)' }}>
              Failing Controls
            </h2>
            <span className="px-2 py-0.5 rounded-full text-xs font-bold text-white" style={{ background: '#ef4444' }}>
              {proposals.failing}
            </span>
            <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
              from the latest assessment
            </span>
          </div>

          {proposals.actionable?.length > 0 && (
            <div className="space-y-2">
              {proposals.actionable.map((item: any) => (
                <div
                  key={item.control_id}
                  className="rounded-xl border p-3 flex items-start gap-3"
                  style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}
                >
                  <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-orange-400" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{item.title}</p>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
                      {item.control_id} · {capabilityName(item.claw)} · {item.severity} · {item.evidence_count} finding(s)
                    </p>
                    <p className="text-xs mt-1" style={{ color: 'var(--rc-text-2)' }}>
                      Proposes <code>{item.action_type}</code> via {item.provider}. Governed by Trust Fabric and the approval gate.
                    </p>
                  </div>
                  <button
                    onClick={() => handlePropose(item.control_id)}
                    disabled={proposing === item.control_id}
                    className="shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium border disabled:opacity-50"
                    style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-2)' }}
                  >
                    {proposing === item.control_id ? 'Proposing…' : 'Propose remediation'}
                  </button>
                </div>
              ))}
            </div>
          )}

          {proposals.advisory_only?.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--rc-text-3)' }}>
                Recommendation only ({proposals.advisory_only.length})
              </p>
              {proposals.advisory_only.map((item: any) => (
                <div
                  key={item.control_id}
                  className="rounded-xl border p-3 flex items-start gap-3"
                  style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}
                >
                  <Ban className="w-4 h-4 mt-0.5 shrink-0" style={{ color: 'var(--rc-text-3)' }} />
                  <div className="min-w-0">
                    <p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{item.title}</p>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
                      {item.control_id} · {capabilityName(item.claw)} · {item.evidence_count} finding(s)
                    </p>
                    <p className="text-xs mt-1" style={{ color: 'var(--rc-text-2)' }}>{item.reason}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      ) : null}

      {/* Approval Queue */}
      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-orange-400" />
          <h2 className="text-base font-semibold" style={{ color: 'var(--rc-text-1)' }}>
            Approval Queue
          </h2>
          {pending.length > 0 && (
            <span className="px-2 py-0.5 rounded-full text-xs font-bold text-white" style={{ background: '#f97316' }}>
              {pending.length}
            </span>
          )}
        </div>

        {pending.length === 0 ? (
          <div
            className="rounded-xl border p-8 text-center"
            style={{ background: 'var(--rc-surface)', borderColor: 'var(--rc-border)' }}
          >
            <CheckCircle className="w-8 h-8 mx-auto mb-2" style={{ color: '#22c55e88' }} />
            <p style={{ color: 'var(--rc-text-3)' }}>No actions pending approval</p>
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {pending.map(a => (
              <ApprovalCard
                key={a.id}
                action={a}
                onApprove={handleApprove}
                onReject={handleReject}
              />
            ))}
          </div>
        )}
      </section>

      {/* Action History */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5" style={{ color: 'var(--rc-brand)' }} />
            <h2 className="text-base font-semibold" style={{ color: 'var(--rc-text-1)' }}>
              Action History
            </h2>
          </div>
          <div className="flex gap-1">
            {(['all', 'completed', 'failed'] as const).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className="px-3 py-1 rounded-lg text-xs capitalize transition-colors"
                style={{
                  background: tab === t ? 'var(--rc-brand)' : 'var(--rc-bg-elevated)',
                  color:      tab === t ? '#fff'              : 'var(--rc-text-2)',
                }}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        <div
          className="rounded-xl border overflow-hidden"
          style={{ background: 'var(--rc-surface)', borderColor: 'var(--rc-border)' }}
        >
          {filteredHistory.length === 0 ? (
            <div className="p-8 text-center" style={{ color: 'var(--rc-text-3)' }}>
              No actions found
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--rc-border)' }}>
                    {['Action', 'Target', 'Status', 'Risk', 'Time', ''].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider"
                        style={{ color: 'var(--rc-text-3)' }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredHistory.map(a => (
                    <ActionRow key={a.id} action={a} onRollback={handleRollback} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {/* Playbooks */}
      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <Zap className="w-5 h-5" style={{ color: 'var(--rc-brand)' }} />
          <h2 className="text-base font-semibold" style={{ color: 'var(--rc-text-1)' }}>
            Remediation Playbooks
          </h2>
          <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            — Auto-triggered on matching findings
          </span>
        </div>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {playbooks.map(pb => (
            <PlaybookCard key={pb.id} pb={pb} onToggle={handleTogglePlaybook} />
          ))}
          {playbooks.length === 0 && (
            <div
              className="col-span-full rounded-xl border p-8 text-center"
              style={{ background: 'var(--rc-surface)', borderColor: 'var(--rc-border)' }}
            >
              <PlayCircle className="w-8 h-8 mx-auto mb-2" style={{ color: 'var(--rc-text-3)' }} />
              <p style={{ color: 'var(--rc-text-3)' }}>
                No playbooks found. Visit the API once to seed built-in playbooks.
              </p>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
