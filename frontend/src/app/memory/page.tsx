'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  Brain, AlertTriangle, CheckCircle, Clock, Activity,
  TrendingUp, TrendingDown, Server, User, Cloud,
  ChevronRight, ChevronDown, RefreshCw, Plus, X,
  Shield, Target, Database, BarChart3, Layers,
  Fingerprint, Zap, Eye, Search,
} from 'lucide-react';
import ClientDate from '@/components/ClientDate';
import {
  getMemorySummary, getIncidents, getTopAssets, getTenantMemory,
  getRiskTrends, createIncident, addIncidentTimeline, closeIncident,
  getEntityProfiles, getAnomalousEntities, getProfileStats, getEntityProfile,
  getEntityContext, recomputeBaseline, preflightScoreAnomaly,
  logBehaviorEvent, getBehaviorEvents, getMemoryProposals,
  approveMemoryProposal, rejectMemoryProposal, rollbackMemoryIncident,
} from '@/lib/api';
import { capabilityName } from '@/lib/capability-names';

// ─── Types ────────────────────────────────────────────────────────────────────
type IncidentStatus = 'open' | 'investigating' | 'contained' | 'remediated' | 'closed' | 'false_positive';

type Incident = {
  id: string; title: string; severity: string; status: IncidentStatus;
  source_claw: string | null; affected_assets_count: number;
  timeline_count: number; assigned_to: string | null;
  opened_at: string; closed_at: string | null; mttr_minutes: number | null;
  mitre_tactics: string | null;
};

type Asset = {
  id: string; asset_id: string; asset_type: string; display_name: string | null;
  claw: string | null; risk_score: number; risk_level: string;
  open_findings: number; critical_findings: number; incidents_involved: number;
  last_seen_at: string;
};

type Summary = {
  tenant_risk_level: string; tenant_risk_score: number; active_incidents: number;
  open_findings: number; total_incidents_tracked: number; total_assets_tracked: number;
  total_snapshots: number; last_refreshed: string | null;
};

type TrendPoint = {
  date: string; risk_score: number; open_findings: number; critical: number; incidents: number;
};

type EntityProfile = {
  entity_id: string; entity_type: string; display_name: string; source_claw: string;
  event_count: number; anomalous_event_count: number;
  first_seen_at: string | null; last_event_at: string | null; last_anomaly_at: string | null;
  baseline_established: boolean; baseline_event_count: number;
  risk_score: number; anomaly_score: number; anomaly_level: string; anomaly_flags: string[];
  events_last_1h: number; events_last_24h: number;
  avg_events_1h: number; avg_events_24h: number;
  typical_claws: string[]; action_freq: Record<string, number>;
  typical_resources: string[]; outcome_dist: Record<string, number>;
  hourly_dist: number[]; dow_dist: number[];
  tags: string[]; context_notes: string; updated_at: string | null;
};

type ProfileStats = {
  total_profiles: number; with_baseline: number; anomalous_entities: number;
  high_risk_entities: number; total_events: number; anomalous_events: number;
  anomaly_event_rate: number;
  type_breakdown: Record<string, number>; level_breakdown: Record<string, number>;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400    bg-red-900/30    border-red-800',
  high:     'text-orange-400 bg-orange-900/30 border-orange-800',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-800',
  low:      'text-green-400  bg-green-900/30  border-green-800',
};

const STATUS_META: Record<IncidentStatus, { color: string; label: string }> = {
  open:          { color: 'text-red-400',    label: 'Open' },
  investigating: { color: 'text-orange-400', label: 'Investigating' },
  contained:     { color: 'text-yellow-400', label: 'Contained' },
  remediated:    { color: 'text-blue-400',   label: 'Remediated' },
  closed:        { color: 'text-green-400',  label: 'Closed' },
  false_positive:{ color: 'text-gray-500',   label: 'False Positive' },
};

const RISK_LEVEL_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-green-400',
  none:     'text-gray-400',
};

const ANOMALY_LEVEL_COLOR: Record<string, string> = {
  critical: 'text-red-400    bg-red-900/30    border-red-700',
  high:     'text-orange-400 bg-orange-900/30 border-orange-700',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-700',
  low:      'text-blue-400   bg-blue-900/30   border-blue-700',
  none:     'text-gray-500   bg-gray-800/30   border-gray-700',
};

const ASSET_TYPE_ICON: Record<string, React.ElementType> = {
  endpoint:       Server,
  identity:       User,
  cloud_resource: Cloud,
  application:    Activity,
  data_store:     Database,
  unknown:        Shield,
};

const ENTITY_TYPE_ICON: Record<string, React.ElementType> = {
  user:            User,
  agent:           Zap,
  asset:           Server,
  connector:       Layers,
  ip:              Target,
  service_account: Shield,
};

const DOW_LABELS = ['M', 'T', 'W', 'T', 'F', 'S', 'S'];

// ─── Sparkline ────────────────────────────────────────────────────────────────
function Sparkline({ data, color = 'cyan' }: { data: number[]; color?: string }) {
  if (data.length < 2) return null;
  const max = Math.max(...data, 1);
  const w = 80; const h = 28;
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - (v / max) * h}`).join(' ');
  const colorMap: Record<string, string> = {
    cyan: '#22d3ee', green: '#4ade80', red: '#f87171', yellow: '#facc15',
  };
  return (
    <svg width={w} height={h} className="overflow-visible">
      <polyline points={pts} fill="none" stroke={colorMap[color] ?? colorMap.cyan} strokeWidth="1.5" />
    </svg>
  );
}

// ─── Hourly heatmap ───────────────────────────────────────────────────────────
function HourlyHeatmap({ dist }: { dist: number[] }) {
  const filled = [...(dist || []), ...Array(24).fill(0)].slice(0, 24);
  const max = Math.max(...filled, 1);
  return (
    <div className="flex gap-0.5 items-end h-8">
      {filled.map((v, i) => {
        const pct = v / max;
        return (
          <div
            key={i}
            title={`${i.toString().padStart(2, '0')}:00 — ${v} events`}
            className="flex-1 rounded-sm cursor-default transition-all"
            style={{
              height: `${Math.max(8, pct * 100)}%`,
              backgroundColor: `rgba(34,211,238,${0.1 + pct * 0.9})`,
            }}
          />
        );
      })}
    </div>
  );
}

// ─── New incident modal ───────────────────────────────────────────────────────
function NewIncidentModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    title: '', description: '', severity: 'medium',
    source_claw: '', assigned_to: '', created_by: 'analyst',
  });
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    if (!form.title.trim()) return;
    setSaving(true);
    try {
      await createIncident({ ...form, affected_assets: [], affected_users: [] });
      onCreated();
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold text-white">Open New Incident</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white"><X className="w-4 h-4" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Title *</label>
            <input
              value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none focus:border-cyan-700"
              placeholder="Suspicious login activity on prod account"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Description</label>
            <textarea
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              rows={3}
              className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none focus:border-cyan-700 resize-none"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Severity</label>
              <select
                value={form.severity}
                onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none"
              >
                {['critical','high','medium','low'].map(s => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Source Capability</label>
              <input
                value={form.source_claw}
                onChange={e => setForm(f => ({ ...f, source_claw: e.target.value }))}
                className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none"
                placeholder="Identity Security"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Assigned To</label>
            <input
              value={form.assigned_to}
              onChange={e => setForm(f => ({ ...f, assigned_to: e.target.value }))}
              className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none"
              placeholder="redacted_user"
            />
          </div>
        </div>
        <div className="flex gap-2 px-6 pb-6">
          <button
            onClick={submit}
            disabled={saving || !form.title.trim()}
            className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-sm font-semibold px-5 py-2 rounded-xl transition-colors"
          >
            {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Open Incident'}
          </button>
          <button onClick={onClose} className="bg-gray-800 hover:bg-gray-700 text-white text-sm px-4 py-2 rounded-xl transition-colors">
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Profile detail drawer ────────────────────────────────────────────────────
function ProfileDrawer({ entityId, onClose }: { entityId: string; onClose: () => void }) {
  const [profile, setProfile]   = useState<EntityProfile | null>(null);
  const [context, setContext]   = useState<any>(null);
  const [events, setEvents]     = useState<any[]>([]);
  const [loading, setLoading]   = useState(true);
  const [recomputing, setRecomputing] = useState(false);

  const [pfForm, setPfForm]     = useState({ action: '', claw: '', resource: '' });
  const [pfResult, setPfResult] = useState<any>(null);
  const [pfLoading, setPfLoading] = useState(false);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const [p, ctx, ev] = await Promise.all([
          getEntityProfile(entityId).catch(() => null),
          getEntityContext(entityId).catch(() => null),
          getBehaviorEvents({ entity_id: entityId, limit: '20', anomalous_only: 'true' }).catch(() => ({ events: [] })),
        ]);
        setProfile(p);
        setContext(ctx);
        setEvents((ev as any).events ?? []);
      } finally {
        setLoading(false);
      }
    })();
  }, [entityId]);

  const handleRecompute = async () => {
    setRecomputing(true);
    try { await recomputeBaseline(entityId); const p = await getEntityProfile(entityId); setProfile(p); }
    finally { setRecomputing(false); }
  };

  const handlePreflight = async () => {
    if (!pfForm.action || !pfForm.claw) return;
    setPfLoading(true);
    try {
      const r = await preflightScoreAnomaly({ entity_id: entityId, ...pfForm });
      setPfResult(r);
    } finally { setPfLoading(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex justify-end z-50" onClick={onClose}>
      <div
        className="w-full max-w-2xl bg-gray-950 border-l border-gray-800 overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 bg-gray-950 border-b border-gray-800 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Fingerprint className="w-5 h-5 text-cyan-400" />
            <div>
              <p className="font-semibold text-white text-sm">{profile?.display_name || entityId}</p>
              <p className="text-xs text-gray-500 font-mono">{entityId}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleRecompute}
              disabled={recomputing}
              className="text-xs text-gray-400 hover:text-white bg-gray-800 border border-gray-700 px-3 py-1.5 rounded-lg flex items-center gap-1 transition-colors"
            >
              <RefreshCw className={`w-3 h-3 ${recomputing ? 'animate-spin' : ''}`} />
              Recompute Baseline
            </button>
            <button onClick={onClose} className="text-gray-500 hover:text-white"><X className="w-5 h-5" /></button>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-40">
            <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
          </div>
        ) : profile ? (
          <div className="p-6 space-y-6">

            {/* Score summary */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'Anomaly Score', value: profile.anomaly_score.toFixed(0), color: RISK_LEVEL_COLOR[profile.anomaly_level] ?? 'text-gray-400', sub: profile.anomaly_level.toUpperCase() },
                { label: 'Risk Score',    value: profile.risk_score.toFixed(0),    color: 'text-white',       sub: 'current' },
                { label: 'Events',        value: profile.event_count,              color: 'text-gray-300',    sub: `${profile.anomalous_event_count} anomalous` },
              ].map(c => (
                <div key={c.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3 text-center">
                  <p className="text-xs text-gray-500">{c.label}</p>
                  <p className={`text-2xl font-bold mt-1 ${c.color}`}>{c.value}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{c.sub}</p>
                </div>
              ))}
            </div>

            {/* Anomaly flags */}
            {profile.anomaly_flags.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Active Anomaly Flags</p>
                <div className="flex flex-wrap gap-2">
                  {profile.anomaly_flags.map((flag, i) => (
                    <span key={i} className="text-xs bg-red-900/30 text-red-300 border border-red-800 px-2 py-1 rounded-lg">
                      {flag}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Baseline status */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="flex items-center justify-between mb-3">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Behavioral Baseline</p>
                {profile.baseline_established
                  ? <span className="text-xs text-green-400 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Established ({profile.baseline_event_count} events)</span>
                  : <span className="text-xs text-yellow-400 flex items-center gap-1"><Clock className="w-3 h-3" /> Building… ({profile.event_count}/20 events)</span>
                }
              </div>
              {!profile.baseline_established && (
                <div className="w-full bg-gray-800 rounded-full h-1.5">
                  <div
                    className="h-1.5 bg-yellow-500 rounded-full"
                    style={{ width: `${Math.min(100, (profile.event_count / 20) * 100)}%` }}
                  />
                </div>
              )}
            </div>

            {/* Hourly activity heatmap */}
            {profile.hourly_dist.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">
                  Hourly Activity Distribution
                </p>
                <HourlyHeatmap dist={profile.hourly_dist} />
                <div className="flex justify-between mt-1 text-xs text-gray-600">
                  <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
                </div>
              </div>
            )}

            {/* Day-of-week distribution */}
            {profile.dow_dist.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Day-of-Week Activity</p>
                <div className="flex gap-1 items-end h-12">
                  {profile.dow_dist.map((v, i) => {
                    const max = Math.max(...profile.dow_dist, 1);
                    return (
                      <div key={i} className="flex-1 flex flex-col items-center gap-1">
                        <div
                          className="w-full rounded-t-sm bg-cyan-700/60"
                          style={{ height: `${Math.max(4, (v / max) * 100)}%` }}
                          title={`${DOW_LABELS[i]}: ${v} events`}
                        />
                        <span className="text-xs text-gray-600">{DOW_LABELS[i]}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Top actions */}
            {Object.keys(profile.action_freq).length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Top Actions</p>
                <div className="space-y-1.5">
                  {Object.entries(profile.action_freq)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 8)
                    .map(([action, count]) => {
                      const total = Object.values(profile.action_freq).reduce((s, n) => s + n, 0);
                      const pct = total > 0 ? (count / total) * 100 : 0;
                      return (
                        <div key={action} className="flex items-center gap-3">
                          <span className="text-xs text-gray-300 w-32 truncate font-mono">{action}</span>
                          <div className="flex-1 bg-gray-800 rounded-full h-1.5">
                            <div className="h-1.5 bg-cyan-600 rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs text-gray-500 w-8 text-right">{count}</span>
                        </div>
                      );
                  })}
                </div>
              </div>
            )}

            {/* Velocity */}
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
                <p className="text-xs text-gray-500">Last Hour</p>
                <p className="text-lg font-bold text-white mt-1">{profile.events_last_1h}</p>
                <p className="text-xs text-gray-600">baseline avg: {profile.avg_events_1h.toFixed(1)}/hr</p>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
                <p className="text-xs text-gray-500">Last 24 Hours</p>
                <p className="text-lg font-bold text-white mt-1">{profile.events_last_24h}</p>
                <p className="text-xs text-gray-600">baseline avg: {profile.avg_events_24h.toFixed(1)}/day</p>
              </div>
            </div>

            {/* Recent anomalous events */}
            {events.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-800">
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                    Recent Anomalous Events ({events.length})
                  </p>
                </div>
                <div className="divide-y divide-gray-800">
                  {events.map(ev => (
                    <div key={ev.id} className="px-4 py-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-orange-400">{ev.action}</span>
                          <span className="text-xs text-gray-600">via {capabilityName(ev.claw)}</span>
                        </div>
                        <span className="text-xs text-gray-500">
                          {ev.occurred_at ? new Date(ev.occurred_at).toLocaleString() : '—'}
                        </span>
                      </div>
                      {ev.anomaly_reasons?.length > 0 && (
                        <p className="text-xs text-red-400 mt-1">{ev.anomaly_reasons.join(' · ')}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Pre-flight scorer */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">
                Pre-flight Anomaly Scorer
              </p>
              <div className="grid grid-cols-3 gap-2 mb-3">
                {[
                  { label: 'Action', key: 'action', placeholder: 'e.g. login' },
                  { label: 'Capability', key: 'claw', placeholder: 'e.g. Identity Security' },
                  { label: 'Resource', key: 'resource', placeholder: 'optional' },
                ].map(f => (
                  <div key={f.key}>
                    <label className="text-xs text-gray-500 mb-1 block">{f.label}</label>
                    <input
                      value={(pfForm as any)[f.key]}
                      onChange={e => setPfForm(p => ({ ...p, [f.key]: e.target.value }))}
                      placeholder={f.placeholder}
                      className="w-full bg-gray-800 border border-gray-700 text-white text-xs rounded-lg px-2.5 py-1.5 outline-none focus:border-cyan-700"
                    />
                  </div>
                ))}
              </div>
              <button
                onClick={handlePreflight}
                disabled={pfLoading || !pfForm.action || !pfForm.claw}
                className="flex items-center gap-2 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-xs px-3 py-1.5 rounded-lg transition-colors"
              >
                {pfLoading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Eye className="w-3 h-3" />}
                Score without logging
              </button>
              {pfResult && (
                <div className={`mt-3 p-3 rounded-lg border text-xs ${
                  pfResult.is_anomalous ? 'bg-red-900/20 border-red-800 text-red-300' : 'bg-green-900/20 border-green-800 text-green-300'
                }`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold">{pfResult.is_anomalous ? '⚠ Anomalous' : '✓ Normal'}</span>
                    <span>Score: {pfResult.anomaly_score?.toFixed(0) ?? '—'}</span>
                  </div>
                  <p>{pfResult.recommendation}</p>
                  {pfResult.reasons?.length > 0 && (
                    <ul className="mt-1 space-y-0.5">
                      {pfResult.reasons.map((r: string, i: number) => <li key={i}>• {r}</li>)}
                    </ul>
                  )}
                </div>
              )}
            </div>

          </div>
        ) : (
          <p className="p-6 text-sm text-gray-500">Profile not found.</p>
        )}
      </div>
    </div>
  );
}

// ─── Profiles tab ─────────────────────────────────────────────────────────────
function ProfilesTab() {
  const [stats, setStats]       = useState<ProfileStats | null>(null);
  const [profiles, setProfiles] = useState<EntityProfile[]>([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [sort, setSort]         = useState('anomaly');
  const [typeFilter, setTypeFilter] = useState('');
  const [levelFilter, setLevelFilter] = useState('');
  const [search, setSearch]     = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = { sort, limit: '50' };
      if (typeFilter)  params.entity_type   = typeFilter;
      if (levelFilter) params.anomaly_level = levelFilter;
      const [s, p] = await Promise.all([
        getProfileStats().catch(() => null),
        getEntityProfiles(params).catch(() => ({ profiles: [], total: 0 })),
      ]);
      setStats(s);
      setProfiles((p as any).profiles ?? []);
      setTotal((p as any).total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [sort, typeFilter, levelFilter]);

  useEffect(() => { load(); }, [load]);

  const displayed = profiles.filter(p =>
    !search || p.entity_id.includes(search) || (p.display_name || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-5">
      {selected && <ProfileDrawer entityId={selected} onClose={() => setSelected(null)} />}

      {/* Stats row */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            { label: 'Profiles',        value: stats.total_profiles,     color: 'text-white' },
            { label: 'With Baseline',   value: stats.with_baseline,      color: 'text-cyan-400' },
            { label: 'Anomalous',       value: stats.anomalous_entities, color: 'text-orange-400' },
            { label: 'High Risk',       value: stats.high_risk_entities, color: 'text-red-400' },
            { label: 'Total Events',    value: stats.total_events,       color: 'text-gray-300' },
            { label: 'Anomaly Rate',    value: `${stats.anomaly_event_rate}%`, color: stats.anomaly_event_rate > 10 ? 'text-orange-400' : 'text-green-400' },
          ].map(c => (
            <div key={c.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
              <p className="text-xs text-gray-500">{c.label}</p>
              <p className={`text-xl font-bold mt-1 ${c.color}`}>{c.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Level breakdown mini-bar */}
      {stats && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Anomaly Level Distribution</p>
          <div className="flex gap-2 items-end h-10">
            {['none','low','medium','high','critical'].map(lvl => {
              const count = stats.level_breakdown[lvl] ?? 0;
              const maxCount = Math.max(...Object.values(stats.level_breakdown), 1);
              const colors: Record<string, string> = {
                none: 'bg-gray-700', low: 'bg-blue-600', medium: 'bg-yellow-600', high: 'bg-orange-600', critical: 'bg-red-600',
              };
              return (
                <div key={lvl} className="flex-1 flex flex-col items-center gap-1">
                  <div
                    className={`w-full rounded-t-sm ${colors[lvl]}`}
                    style={{ height: `${Math.max(4, (count / maxCount) * 100)}%` }}
                    title={`${lvl}: ${count}`}
                  />
                  <span className="text-xs text-gray-600 capitalize">{lvl}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search entity…"
            className="bg-gray-800 border border-gray-700 text-white text-xs pl-8 pr-3 py-1.5 rounded-lg outline-none focus:border-cyan-700 w-48"
          />
        </div>
        <select
          value={sort}
          onChange={e => setSort(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-white text-xs px-3 py-1.5 rounded-lg outline-none"
        >
          {[['anomaly','Highest Anomaly'],['risk','Highest Risk'],['events','Most Events'],['recent','Most Recent']].map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-white text-xs px-3 py-1.5 rounded-lg outline-none"
        >
          <option value="">All Types</option>
          {['user','agent','asset','connector','ip','service_account'].map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <select
          value={levelFilter}
          onChange={e => setLevelFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-white text-xs px-3 py-1.5 rounded-lg outline-none"
        >
          <option value="">All Levels</option>
          {['critical','high','medium','low','none'].map(l => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>
        <button onClick={load} className="p-1.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
        <span className="text-xs text-gray-500 ml-auto">{total} profiles</span>
      </div>

      {/* Profile table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        {displayed.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <Fingerprint className="w-10 h-10 text-gray-700 mx-auto mb-3" />
            <p className="text-sm text-gray-500">
              {loading ? 'Loading profiles…' : 'No entity profiles yet. Behavior events will auto-create profiles.'}
            </p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-5 py-3 text-left">Entity</th>
                <th className="px-5 py-3 text-left">Type</th>
                <th className="px-5 py-3 text-left">Anomaly</th>
                <th className="px-5 py-3 text-left">Risk</th>
                <th className="px-5 py-3 text-left">Events</th>
                <th className="px-5 py-3 text-left">Baseline</th>
                <th className="px-5 py-3 text-left">Last Seen</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {displayed.map(p => {
                const Icon = ENTITY_TYPE_ICON[p.entity_type] ?? Shield;
                const lvlClass = ANOMALY_LEVEL_COLOR[p.anomaly_level] ?? ANOMALY_LEVEL_COLOR.none;
                return (
                  <tr key={p.entity_id} className="hover:bg-gray-800/30 cursor-pointer" onClick={() => setSelected(p.entity_id)}>
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <Icon className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" />
                        <div className="min-w-0">
                          <p className="text-white text-xs font-medium truncate">
                            {p.display_name || p.entity_id}
                          </p>
                          <p className="text-gray-600 text-xs font-mono truncate">{p.entity_id}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-3 text-gray-400 text-xs capitalize">{p.entity_type.replace('_', ' ')}</td>
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${lvlClass}`}>
                          {p.anomaly_level}
                        </span>
                        <span className="text-xs text-gray-400">{p.anomaly_score.toFixed(0)}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-14 bg-gray-800 rounded-full h-1.5">
                          <div
                            className={`h-1.5 rounded-full ${
                              p.risk_score >= 70 ? 'bg-red-500' :
                              p.risk_score >= 40 ? 'bg-orange-500' :
                              p.risk_score >= 20 ? 'bg-yellow-500' : 'bg-green-500'
                            }`}
                            style={{ width: `${Math.min(100, p.risk_score)}%` }}
                          />
                        </div>
                        <span className="text-xs text-gray-400">{p.risk_score.toFixed(0)}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3 text-xs text-gray-300">
                      {p.event_count}
                      {p.anomalous_event_count > 0 && (
                        <span className="text-red-400 ml-1">({p.anomalous_event_count}✗)</span>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      {p.baseline_established
                        ? <span className="text-xs text-green-400 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> {p.baseline_event_count}</span>
                        : <span className="text-xs text-yellow-500 flex items-center gap-1"><Clock className="w-3 h-3" /> {p.event_count}/20</span>
                      }
                    </td>
                    <td className="px-5 py-3 text-xs text-gray-500">
                      {p.last_event_at ? new Date(p.last_event_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-5 py-3">
                      <ChevronRight className="w-4 h-4 text-gray-600" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function MemoryPage() {
  const [summary, setSummary]     = useState<Summary | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [proposals, setProposals] = useState<any[]>([]);
  const [assets, setAssets]       = useState<Asset[]>([]);
  const [trends, setTrends]       = useState<TrendPoint[]>([]);
  const [loading, setLoading]     = useState(true);
  const [activeTab, setActiveTab] = useState<'incidents' | 'assets' | 'trends' | 'profiles'>('incidents');
  const [showNew, setShowNew]     = useState(false);
  const [expandedIncident, setExpandedIncident] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [sumData, incData, proposalData, assetData, trendData] = await Promise.all([
        getMemorySummary().catch(() => null),
        getIncidents().catch(() => []),
        getMemoryProposals().catch(() => []),
        getTopAssets().catch(() => []),
        getRiskTrends('daily', 14).catch(() => ({ data: [] })),
      ]);
      setSummary(sumData as Summary);
      setIncidents(incData as Incident[]);
      setProposals(Array.isArray(proposalData) ? proposalData : []);
      setAssets(assetData as Asset[]);
      setTrends((trendData as any).data ?? []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const riskScores = trends.map(t => t.risk_score);
  const openFindingsTrend = trends.map(t => t.open_findings);
  const reviewMemory = async (id: string, decision: 'approve' | 'reject' | 'rollback') => {
    const body = { reviewer: 'memory_ui', reason: `${decision} from Memory Cortex UI` };
    if (decision === 'approve') await approveMemoryProposal(id, body);
    if (decision === 'reject') await rejectMemoryProposal(id, body);
    if (decision === 'rollback') await rollbackMemoryIncident(id, body);
    await load();
  };

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">

      {showNew && (
        <NewIncidentModal onClose={() => setShowNew(false)} onCreated={load} />
      )}

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Brain className="text-cyan-400" /> Memory & State
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            Incident timelines, asset risk history, behavioral profiles, and platform-wide threat context.
          </p>
        </div>
        <div className="flex gap-2">
          {activeTab !== 'profiles' && (
            <button
              onClick={() => setShowNew(true)}
              className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold px-4 py-2 rounded-xl transition-colors"
            >
              <Plus className="w-4 h-4" /> New Incident
            </button>
          )}
          {activeTab !== 'profiles' && (
            <button onClick={load} className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            {
              label: 'Platform Risk',
              value: summary.tenant_risk_level.toUpperCase(),
              sub: `score ${summary.tenant_risk_score.toFixed(0)}`,
              color: RISK_LEVEL_COLOR[summary.tenant_risk_level] ?? 'text-white',
              trend: riskScores, trendColor: summary.tenant_risk_level === 'low' ? 'green' : 'red' as const,
            },
            {
              label: 'Active Incidents',
              value: summary.active_incidents,
              sub: `${summary.total_incidents_tracked} total tracked`,
              color: summary.active_incidents > 0 ? 'text-red-400' : 'text-green-400',
              trend: [], trendColor: 'cyan' as const,
            },
            {
              label: 'Open Findings',
              value: summary.open_findings,
              sub: 'across all capabilities',
              color: summary.open_findings > 10 ? 'text-orange-400' : 'text-white',
              trend: openFindingsTrend, trendColor: 'yellow' as const,
            },
            {
              label: 'Assets Tracked',
              value: summary.total_assets_tracked,
              sub: `${summary.total_snapshots} snapshots`,
              color: 'text-white',
              trend: [], trendColor: 'cyan' as const,
            },
          ].map(card => (
            <div key={card.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
              <p className="text-xs text-gray-500">{card.label}</p>
              <div className="flex items-end justify-between mt-1">
                <div>
                  <p className={`text-2xl font-bold ${card.color}`}>{card.value}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{card.sub}</p>
                </div>
                {card.trend.length > 1 && (
                  <Sparkline data={card.trend} color={card.trendColor} />
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {(['incidents', 'assets', 'trends', 'profiles'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium capitalize transition-colors -mb-px border-b-2 ${
              activeTab === tab
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            {tab === 'incidents' && `Incidents (${incidents.length})`}
            {tab === 'assets'    && `Asset Memory (${assets.length})`}
            {tab === 'trends'    && 'Risk Trends'}
            {tab === 'profiles'  && 'Entity Profiles'}
          </button>
        ))}
      </div>

      {/* ── Incidents ──────────────────────────────────────────────────────── */}
      {activeTab === 'incidents' && (
        <div className="space-y-2">
          {proposals.length > 0 && (
            <section className="bg-yellow-950/20 border border-yellow-800 rounded-xl overflow-hidden mb-4">
              <div className="px-5 py-4 border-b border-yellow-900/60 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-yellow-200 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    Memory Review Queue
                  </h2>
                  <p className="text-xs text-yellow-300/70 mt-1">
                    Swarm-proposed incident memory requires analyst approval before it should influence future investigations.
                  </p>
                </div>
                <span className="text-xs text-yellow-200">{proposals.length} pending</span>
              </div>
              <div className="divide-y divide-yellow-900/40">
                {proposals.slice(0, 5).map((proposal) => (
                  <div key={proposal.id} className="px-5 py-3 flex flex-col md:flex-row md:items-center gap-3">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-white truncate">{proposal.title}</p>
                      <p className="text-xs text-yellow-200/70 mt-0.5">
                        {proposal.severity} · {capabilityName(proposal.source_claw || 'memoryclaw')} · {proposal.affected_users?.join(', ') || 'no user scope'}
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => reviewMemory(proposal.id, 'approve')}
                        className="px-3 py-1.5 rounded-lg bg-green-700 hover:bg-green-600 text-white text-xs font-semibold"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => reviewMemory(proposal.id, 'reject')}
                        className="px-3 py-1.5 rounded-lg bg-red-800 hover:bg-red-700 text-white text-xs font-semibold"
                      >
                        Reject
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}
          {incidents.length === 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl px-6 py-10 text-center">
              <Brain className="w-10 h-10 text-gray-600 mx-auto mb-3" />
              <p className="text-gray-400 text-sm">No incidents tracked yet.</p>
              <button onClick={() => setShowNew(true)} className="mt-3 text-sm text-cyan-400 hover:text-cyan-300">
                Open the first one →
              </button>
            </div>
          )}
          {incidents.map(inc => {
            const statusMeta = STATUS_META[inc.status] ?? STATUS_META.open;
            const sevClass = SEVERITY_COLORS[inc.severity] ?? SEVERITY_COLORS.medium;
            const isOpen = expandedIncident === inc.id;

            return (
              <div key={inc.id} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                <button
                  onClick={() => setExpandedIncident(isOpen ? null : inc.id)}
                  className="w-full flex items-center gap-4 px-5 py-4 hover:bg-gray-800/30 text-left transition-colors"
                >
                  <div className={`flex-shrink-0 text-xs font-bold px-2 py-1 rounded-lg border uppercase tracking-wide ${sevClass}`}>
                    {inc.severity}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-white text-sm font-medium truncate">{inc.title}</p>
                    <div className="flex gap-3 mt-0.5 text-xs text-gray-500">
                      {inc.source_claw && <span>{capabilityName(inc.source_claw)}</span>}
                      <span>{inc.affected_assets_count} asset(s)</span>
                      <span>{inc.timeline_count} events</span>
                      {inc.mitre_tactics && <span>MITRE: {inc.mitre_tactics}</span>}
                    </div>
                  </div>
                  <div className="flex-shrink-0 text-right">
                    <p className={`text-xs font-semibold ${statusMeta.color}`}>{statusMeta.label}</p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      <ClientDate value={inc.opened_at} format="date" />
                    </p>
                  </div>
                  {isOpen ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                </button>

                {isOpen && (
                  <div className="px-5 pb-5 border-t border-gray-800 pt-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                    <div>
                      <p className="text-gray-500">Opened</p>
                      <p className="text-white"><ClientDate value={inc.opened_at} /></p>
                    </div>
                    {inc.closed_at && (
                      <div>
                        <p className="text-gray-500">Closed</p>
                        <p className="text-white"><ClientDate value={inc.closed_at} /></p>
                      </div>
                    )}
                    {inc.mttr_minutes != null && (
                      <div>
                        <p className="text-gray-500">MTTR</p>
                        <p className="text-white">{inc.mttr_minutes < 60
                          ? `${Math.round(inc.mttr_minutes)}m`
                          : `${(inc.mttr_minutes / 60).toFixed(1)}h`
                        }</p>
                      </div>
                    )}
                    {inc.assigned_to && (
                      <div>
                        <p className="text-gray-500">Assigned to</p>
                        <p className="text-white">{inc.assigned_to}</p>
                      </div>
                    )}
                    {inc.status !== 'false_positive' && (
                      <div>
                        <p className="text-gray-500">Memory control</p>
                        <button
                          onClick={() => reviewMemory(inc.id, 'rollback')}
                          className="mt-1 px-2.5 py-1 rounded-lg border border-red-800 text-red-300 hover:bg-red-950/30"
                        >
                          Roll back memory
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ── Asset Memory ───────────────────────────────────────────────────── */}
      {activeTab === 'assets' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-800 flex justify-between items-center">
            <h2 className="font-semibold text-white text-sm">Top Assets by Risk Score</h2>
            <span className="text-xs text-gray-500">{assets.length} tracked</span>
          </div>
          {assets.length === 0 ? (
            <p className="px-5 py-8 text-sm text-gray-500">No assets in memory yet. Run a scan to populate.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 text-xs">
                  <th className="px-5 py-3 text-left">Asset</th>
                  <th className="px-5 py-3 text-left">Type</th>
                  <th className="px-5 py-3 text-left">Risk</th>
                  <th className="px-5 py-3 text-left">Findings</th>
                  <th className="px-5 py-3 text-left">Incidents</th>
                  <th className="px-5 py-3 text-left">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {assets.map(a => {
                  const Icon = ASSET_TYPE_ICON[a.asset_type] ?? Shield;
                  const riskColor = RISK_LEVEL_COLOR[a.risk_level] ?? 'text-gray-400';
                  return (
                    <tr key={a.id} className="hover:bg-gray-800/30">
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-2">
                          <Icon className={`w-3.5 h-3.5 flex-shrink-0 ${riskColor}`} />
                          <div className="min-w-0">
                            <p className="text-white text-xs font-medium truncate">
                              {a.display_name || a.asset_id}
                            </p>
                            <p className="text-gray-500 text-xs font-mono truncate">{a.asset_id}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-3 text-gray-400 text-xs capitalize">{a.asset_type.replace('_', ' ')}</td>
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 bg-gray-800 rounded-full h-1.5">
                            <div
                              className={`h-1.5 rounded-full ${
                                a.risk_level === 'critical' ? 'bg-red-500' :
                                a.risk_level === 'high' ? 'bg-orange-500' :
                                a.risk_level === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                              }`}
                              style={{ width: `${Math.min(100, a.risk_score)}%` }}
                            />
                          </div>
                          <span className={`text-xs font-semibold ${riskColor}`}>
                            {a.risk_score.toFixed(0)}
                          </span>
                        </div>
                      </td>
                      <td className="px-5 py-3 text-xs">
                        <span className="text-gray-300">{a.open_findings}</span>
                        {a.critical_findings > 0 && (
                          <span className="text-red-400 ml-2">{a.critical_findings} crit</span>
                        )}
                      </td>
                      <td className="px-5 py-3 text-xs text-gray-400">{a.incidents_involved}</td>
                      <td className="px-5 py-3 text-xs text-gray-400">
                        <ClientDate value={a.last_seen_at} format="date" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Risk Trends ─────────────────────────────────────────────────────── */}
      {activeTab === 'trends' && (
        <div className="space-y-4">
          {trends.length === 0 ? (
            <div className="bg-gray-900 border border-gray-800 rounded-xl px-6 py-10 text-center">
              <BarChart3 className="w-10 h-10 text-gray-600 mx-auto mb-3" />
              <p className="text-gray-400 text-sm">No trend data yet.</p>
              <p className="text-xs text-gray-500 mt-1">Snapshots are captured automatically or via POST /memory/trends/snapshot</p>
            </div>
          ) : (
            <>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-4">
                  Risk Score — last {trends.length} data points
                </p>
                <div className="h-32 flex items-end gap-1">
                  {trends.map((t, i) => {
                    const maxScore = Math.max(...trends.map(x => x.risk_score), 1);
                    const h = Math.max(4, (t.risk_score / maxScore) * 100);
                    return (
                      <div key={i} className="flex-1 flex flex-col items-center gap-1 group">
                        <div
                          className="w-full rounded-t-sm transition-all bg-cyan-600/60 hover:bg-cyan-500 cursor-default"
                          style={{ height: `${h}%` }}
                          title={`${new Date(t.date).toLocaleDateString()}: ${t.risk_score.toFixed(1)}`}
                        />
                      </div>
                    );
                  })}
                </div>
                <div className="flex justify-between mt-2 text-xs text-gray-600">
                  <span>{new Date(trends[0].date).toLocaleDateString()}</span>
                  <span>{new Date(trends[trends.length - 1].date).toLocaleDateString()}</span>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                  { label: 'Peak Risk', value: Math.max(...riskScores).toFixed(0), color: 'text-red-400' },
                  { label: 'Current Risk', value: riskScores[riskScores.length - 1]?.toFixed(0) ?? '—', color: 'text-white' },
                  { label: 'Trend', value: riskScores.length >= 2
                      ? (riskScores[riskScores.length - 1] > riskScores[0] ? '↑ Rising' : '↓ Falling')
                      : '—',
                    color: riskScores.length >= 2
                      ? (riskScores[riskScores.length - 1] > riskScores[0] ? 'text-red-400' : 'text-green-400')
                      : 'text-gray-400' },
                  { label: 'Data Points', value: trends.length, color: 'text-gray-300' },
                ].map(item => (
                  <div key={item.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
                    <p className="text-xs text-gray-500">{item.label}</p>
                    <p className={`text-xl font-bold mt-1 ${item.color}`}>{item.value}</p>
                  </div>
                ))}
              </div>

              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                <div className="px-5 py-3 border-b border-gray-800">
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Raw Snapshots</p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-gray-800 text-gray-500">
                        <th className="px-5 py-2 text-left">Date</th>
                        <th className="px-5 py-2 text-left">Risk Score</th>
                        <th className="px-5 py-2 text-left">Open</th>
                        <th className="px-5 py-2 text-left">Critical</th>
                        <th className="px-5 py-2 text-left">Incidents</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {trends.slice(-14).reverse().map((t, i) => (
                        <tr key={i} className="hover:bg-gray-800/30">
                          <td className="px-5 py-2 text-gray-400">{new Date(t.date).toLocaleDateString()}</td>
                          <td className="px-5 py-2 text-white font-medium">{t.risk_score.toFixed(1)}</td>
                          <td className="px-5 py-2 text-gray-300">{t.open_findings}</td>
                          <td className="px-5 py-2 text-red-400">{t.critical}</td>
                          <td className="px-5 py-2 text-gray-300">{t.incidents}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* ── Entity Profiles ─────────────────────────────────────────────────── */}
      {activeTab === 'profiles' && <ProfilesTab />}

    </div>
  );
}
