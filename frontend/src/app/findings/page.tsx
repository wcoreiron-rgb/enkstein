'use client';
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Search, Filter, RefreshCw, ChevronRight, X, ExternalLink,
  AlertTriangle, ShieldAlert, Info, Bug, Clock, CheckCircle2,
  Flame, AlertCircle, SlidersHorizontal, Users2,
} from 'lucide-react';
import { createSwarmJob, getFindings, getFindingsStats, updateFinding } from '@/lib/api';
import { useWebSocket } from '@/hooks/useWebSocket';

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES   = ['open', 'in_remediation', 'resolved', 'accepted_risk', 'false_positive'];

const SEV_STYLE: Record<string, { badge: string; dot: string; icon: React.ReactNode }> = {
  critical: { badge: 'text-red-500 bg-red-500/10 border-red-500/30',    dot: 'bg-red-500',    icon: <Flame         className="w-3 h-3" /> },
  high:     { badge: 'text-orange-500 bg-orange-500/10 border-orange-500/30', dot: 'bg-orange-500', icon: <ShieldAlert   className="w-3 h-3" /> },
  medium:   { badge: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30', dot: 'bg-yellow-500', icon: <AlertTriangle className="w-3 h-3" /> },
  low:      { badge: 'text-blue-500 bg-blue-500/10 border-blue-500/30',  dot: 'bg-blue-500',   icon: <AlertCircle   className="w-3 h-3" /> },
  info:     { badge: 'text-gray-500 bg-gray-500/10 border-gray-500/30',  dot: 'bg-gray-400',   icon: <Info          className="w-3 h-3" /> },
};

const STATUS_STYLE: Record<string, string> = {
  open:            'text-red-500 bg-red-500/10 border-red-500/30',
  in_remediation:  'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
  resolved:        'text-green-500 bg-green-500/10 border-green-500/30',
  accepted_risk:   'text-purple-500 bg-purple-500/10 border-purple-500/30',
  false_positive:  'text-gray-400 bg-gray-400/10 border-gray-400/30',
};

const CLAW_COLORS: Record<string, string> = {
  cloudclaw:      '#0ea5e9', exposureclaw:   '#f97316', identityclaw:   '#a855f7',
  threatclaw:     '#ef4444', netclaw:        '#22c55e', endpointclaw:   '#eab308',
  logclaw:        '#64748b', accessclaw:     '#ec4899', dataclaw:       '#14b8a6',
  appclaw:        '#8b5cf6', saasclaw:       '#06b6d4', configclaw:     '#f59e0b',
  complianceclaw: '#10b981', privacyclaw:    '#6366f1', vendorclaw:     '#84cc16',
  userclaw:       '#f43f5e', insiderclaw:    '#dc2626', automationclaw: '#7c3aed',
  attackpathclaw: '#b91c1c', devclaw:        '#0891b2', intelclaw:      '#9333ea',
  recoveryclaw:   '#16a34a', arcclaw:        '#2563eb',
};

function clawColor(claw: string) { return CLAW_COLORS[claw] ?? '#6b7280'; }

function fmt(date: string | null) {
  if (!date) return '—';
  return new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: '2-digit' });
}

function riskColor(score: number) {
  if (score >= 80) return '#ef4444';
  if (score >= 60) return '#f97316';
  if (score >= 40) return '#eab308';
  return '#22c55e';
}

// ─── Stats bar ────────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: any }) {
  if (!stats) return null;
  const t = stats.totals ?? {};
  return (
    <div className="flex items-center gap-6 flex-wrap">
      {SEVERITIES.map(s => {
        const n = t[s] ?? 0;
        const style = SEV_STYLE[s];
        if (!n) return null;
        return (
          <div key={s} className="flex items-center gap-1.5">
            <span className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${style.badge}`}>
              {style.icon} {s}
            </span>
            <span className="text-sm font-bold" style={{ color: 'var(--rc-text-1)' }}>{n}</span>
          </div>
        );
      })}
      <span className="text-xs ml-auto" style={{ color: 'var(--rc-text-3)' }}>
        {stats.open_count ?? 0} open · {stats.critical_count ?? 0} critical
      </span>
    </div>
  );
}

// ─── Detail drawer ────────────────────────────────────────────────────────────

function DetailDrawer({ finding, onClose, onUpdate }: {
  finding: any; onClose: () => void; onUpdate: () => void;
}) {
  const [saving, setSaving] = useState(false);
  const [launchingSwarm, setLaunchingSwarm] = useState(false);
  const [swarmError, setSwarmError] = useState<string | null>(null);
  const [status, setStatus] = useState(finding.status);
  const sev   = SEV_STYLE[finding.severity] ?? SEV_STYLE.info;
  const score = Number(finding.risk_score ?? 50);

  const save = async () => {
    setSaving(true);
    try { await updateFinding(finding.id, { status }); onUpdate(); }
    catch (e) { console.error(e); }
    finally { setSaving(false); }
  };

  const launchSwarm = async () => {
    setLaunchingSwarm(true);
    setSwarmError(null);
    const selectedFinding = {
      finding_id: finding.id,
      claw: finding.claw,
      provider: finding.provider,
      title: finding.title,
      repo: finding.resource_name || finding.resource_id || finding.account_id || '',
      package: finding.package || finding.component || finding.category || '',
      severity: finding.severity,
      risk_score: finding.risk_score,
    };
    try {
      const job = await createSwarmJob({
        name: `${finding.provider || finding.claw} Finding Investigation Swarm`,
        profile: 'DEEP_INVESTIGATION',
        requested_by: 'portal-user',
        trigger_type: 'finding_context',
        classification: 'confidential',
        participants: ['devclaw', 'appclaw', 'threatclaw', 'complianceclaw', 'automationclaw'],
        task_type: 'investigate_selected_finding',
        input: {
          source: 'findings_page',
          selected_finding: selectedFinding,
        },
        parallelism: 5,
        model_profile: 'swarm_judge_profile',
      });
      if (job?.id) window.location.href = `/swarm/${job.id}`;
    } catch (e: any) {
      setSwarmError(e?.message || 'Failed to launch focused swarm.');
    } finally {
      setLaunchingSwarm(false);
    }
  };

  return (
    <>
      <div className="fixed inset-0 bg-black/40 z-40 backdrop-blur-sm" onClick={onClose} />
      <div
        className="fixed top-0 right-0 h-full z-50 flex flex-col overflow-hidden"
        style={{
          width: 'min(480px, 100vw)',
          background: 'var(--rc-bg-surface)',
          borderLeft: '1px solid var(--rc-border)',
        }}
      >
        {/* Header */}
        <div className="flex items-start gap-3 px-5 py-4 border-b" style={{ borderColor: 'var(--rc-border)' }}>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${sev.badge}`}>
                {sev.icon} {finding.severity}
              </span>
              <span className="text-xs px-2 py-0.5 rounded-full border" style={{
                color: clawColor(finding.claw),
                borderColor: clawColor(finding.claw) + '40',
                background: clawColor(finding.claw) + '10',
              }}>
                {finding.claw}
              </span>
            </div>
            <h2 className="text-sm font-semibold leading-snug" style={{ color: 'var(--rc-text-1)' }}>{finding.title}</h2>
          </div>
          <button onClick={onClose} className="transition-colors mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Risk score */}
          <div className="flex items-center gap-3">
            <div className="flex-1">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Risk Score</span>
                <span className="text-sm font-bold" style={{ color: riskColor(score) }}>{score.toFixed(0)}</span>
              </div>
              <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--rc-bg-elevated)' }}>
                <div className="h-full rounded-full transition-all"
                  style={{ width: `${Math.min(score, 100)}%`, background: riskColor(score) }} />
              </div>
            </div>
            {finding.actively_exploited && (
              <span className="flex items-center gap-1 text-xs text-red-500 bg-red-500/10 border border-red-500/30 px-2 py-1 rounded-full flex-shrink-0">
                <Flame className="w-3 h-3" /> KEV
              </span>
            )}
          </div>

          {/* Meta grid */}
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: 'Provider',      value: finding.provider },
              { label: 'Category',      value: finding.category || '—' },
              { label: 'Resource',      value: finding.resource_name || finding.resource_id || '—' },
              { label: 'Resource Type', value: finding.resource_type || '—' },
              { label: 'Region',        value: finding.region || '—' },
              { label: 'Account',       value: finding.account_id || '—' },
              { label: 'CVSS',          value: finding.cvss_score != null ? String(finding.cvss_score) : '—' },
              { label: 'EPSS',          value: finding.epss_score != null ? `${(finding.epss_score * 100).toFixed(1)}%` : '—' },
              { label: 'First Seen',    value: fmt(finding.first_seen) },
              { label: 'Last Seen',     value: fmt(finding.last_seen) },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-lg px-3 py-2" style={{ background: 'var(--rc-bg-elevated)' }}>
                <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{label}</p>
                <p className="text-xs font-medium mt-0.5 truncate" style={{ color: 'var(--rc-text-1)' }} title={value}>{value}</p>
              </div>
            ))}
          </div>

          {/* Description */}
          {finding.description && (
            <div>
              <p className="text-xs mb-1.5" style={{ color: 'var(--rc-text-3)' }}>Description</p>
              <p className="text-xs leading-relaxed" style={{ color: 'var(--rc-text-2)' }}>{finding.description}</p>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div className="rounded-xl px-4 py-3" style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.25)' }}>
              <p className="text-xs font-semibold text-green-500 mb-1.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" /> Remediation
              </p>
              <p className="text-xs leading-relaxed" style={{ color: 'var(--rc-text-2)' }}>{finding.remediation}</p>
              {finding.remediation_effort && (
                <p className="text-green-500 text-xs mt-1.5">Effort: {finding.remediation_effort.replace('_', ' ')}</p>
              )}
            </div>
          )}

          {/* External ID */}
          {(finding.external_id || finding.reference_url) && (
            <div className="flex items-center gap-2 flex-wrap">
              {finding.external_id && (
                <span className="text-xs font-mono px-2 py-1 rounded-lg" style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}>
                  {finding.external_id}
                </span>
              )}
              {finding.reference_url && (
                <a href={finding.reference_url} target="_blank" rel="noreferrer"
                  className="flex items-center gap-1 text-xs text-cyan-500 hover:text-cyan-400 transition-colors">
                  <ExternalLink className="w-3 h-3" /> Reference
                </a>
              )}
            </div>
          )}

          {/* Status update */}
          <div>
            <p className="text-xs mb-1.5" style={{ color: 'var(--rc-text-3)' }}>Update Status</p>
            <div className="flex gap-2 flex-wrap">
              {STATUSES.map(s => (
                <button key={s} onClick={() => setStatus(s)}
                  className={`text-xs px-2.5 py-1.5 rounded-lg border transition-colors ${status === s ? STATUS_STYLE[s] : ''}`}
                  style={status !== s ? { color: 'var(--rc-text-3)', borderColor: 'var(--rc-border-2)' } : {}}>
                  {s.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>

          {swarmError && (
            <div className="rounded-xl px-4 py-3 text-xs text-red-300 border border-red-900 bg-red-950/30">
              {swarmError}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-4 border-t flex gap-2" style={{ borderColor: 'var(--rc-border)' }}>
          <button onClick={launchSwarm} disabled={launchingSwarm}
            className="flex items-center gap-2 text-white text-sm font-semibold px-4 py-2 rounded-xl transition-colors disabled:opacity-40"
            style={{ background: 'rgb(8 145 178)' }}>
            {launchingSwarm ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Users2 className="w-4 h-4" />}
            Investigate
          </button>
          <button onClick={save} disabled={saving || status === finding.status}
            className="flex items-center gap-2 text-white text-sm font-semibold px-4 py-2 rounded-xl transition-colors disabled:opacity-40"
            style={{ background: 'var(--regent-600)' }}>
            {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
            Save
          </button>
          <button onClick={onClose} className="text-sm px-4 py-2 rounded-xl transition-colors" style={{ color: 'var(--rc-text-2)' }}>
            Close
          </button>
        </div>
      </div>
    </>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([]);
  const [stats, setStats]       = useState<any>(null);
  const [loading, setLoading]   = useState(true);
  const [selected, setSelected] = useState<any | null>(null);
  const [search,   setSearch]   = useState('');
  const [severity, setSeverity] = useState('');
  const [claw,     setClaw]     = useState('');
  const [status,   setStatus]   = useState('');
  const [sort,     setSort]     = useState<'recent' | 'risk' | 'last_seen'>('recent');
  const [showFilters, setShowFilters] = useState(false);

  const { subscribe } = useWebSocket();
  const debounceRef   = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchAll = useCallback(async (params: Record<string, string> = {}) => {
    setLoading(true);
    try {
      const [f, s] = await Promise.all([getFindings(params), getFindingsStats()]);
      setFindings(f); setStats(s);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  const buildParams = useCallback(() => {
    const p: Record<string, string> = { limit: '200', sort };
    if (severity) p.severity = severity;
    if (claw)     p.claw     = claw;
    if (status)   p.status   = status;
    if (search)   p.search   = search;
    return p;
  }, [severity, claw, status, search, sort]);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => fetchAll(buildParams()), 300);
  }, [fetchAll, buildParams]);

  useEffect(() => {
    return subscribe('finding.created', () => fetchAll(buildParams()));
  }, [subscribe, fetchAll, buildParams]);

  const knownClaws = Array.from(new Set(findings.map(f => f.claw))).sort();

  return (
    <div className="space-y-5 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
            <Bug className="text-orange-500" /> Findings
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
            All security findings across every Claw — unified, filterable, and actionable.
          </p>
        </div>
        <button onClick={() => fetchAll(buildParams())}
          className="flex items-center gap-2 text-sm px-3 py-2 rounded-xl transition-colors"
          style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)', border: '1px solid var(--rc-border)' }}>
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {/* Stats bar */}
      <StatsBar stats={stats} />

      {/* Filter toolbar */}
      <div className="flex items-center gap-2 flex-wrap">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-2.5 w-4 h-4" style={{ color: 'var(--rc-text-3)' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search findings…"
            className="w-full pl-9 pr-3 py-2 rounded-xl text-sm outline-none"
            style={{
              background: 'var(--rc-bg-input)',
              border: '1px solid var(--rc-border-2)',
              color: 'var(--rc-text-1)',
            }}
          />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-3 top-2.5" style={{ color: 'var(--rc-text-3)' }}>
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        <button onClick={() => setShowFilters(!showFilters)}
          className="flex items-center gap-2 text-sm px-3 py-2 rounded-xl transition-colors"
          style={{
            background: showFilters ? 'var(--regent-600)' : 'var(--rc-bg-elevated)',
            color: showFilters ? '#fff' : 'var(--rc-text-2)',
            border: '1px solid ' + (showFilters ? 'var(--regent-600)' : 'var(--rc-border)'),
          }}>
          <SlidersHorizontal className="w-4 h-4" />
          Filters
          {(severity || claw || status) && <span className="w-2 h-2 rounded-full bg-cyan-500" />}
        </button>

        <div className="flex items-center rounded-xl overflow-hidden border" style={{ borderColor: 'var(--rc-border)' }}>
          {[
            { value: 'recent', label: 'Latest' },
            { value: 'risk', label: 'Risk' },
            { value: 'last_seen', label: 'Last seen' },
          ].map(opt => (
            <button
              key={opt.value}
              onClick={() => setSort(opt.value as 'recent' | 'risk' | 'last_seen')}
              className="text-xs px-3 py-2 transition-colors"
              style={{
                background: sort === opt.value ? 'var(--regent-600)' : 'var(--rc-bg-elevated)',
                color: sort === opt.value ? '#fff' : 'var(--rc-text-2)',
                borderRight: opt.value !== 'last_seen' ? '1px solid var(--rc-border)' : undefined,
              }}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Active filter pills */}
        {severity && (
          <span className={`flex items-center gap-1 text-xs px-2 py-1 rounded-full border ${SEV_STYLE[severity]?.badge}`}>
            {severity} <button onClick={() => setSeverity('')}><X className="w-3 h-3" /></button>
          </span>
        )}
        {claw && (
          <span className="flex items-center gap-1 text-xs px-2 py-1 rounded-full border" style={{
            color: clawColor(claw), borderColor: clawColor(claw) + '50', background: clawColor(claw) + '15',
          }}>
            {claw} <button onClick={() => setClaw('')}><X className="w-3 h-3" /></button>
          </span>
        )}
        {status && (
          <span className={`flex items-center gap-1 text-xs px-2 py-1 rounded-full border ${STATUS_STYLE[status]}`}>
            {status.replace(/_/g, ' ')} <button onClick={() => setStatus('')}><X className="w-3 h-3" /></button>
          </span>
        )}

        <span className="ml-auto text-xs" style={{ color: 'var(--rc-text-3)' }}>
          {findings.length} findings · sorted by {sort === 'recent' ? 'latest run' : sort === 'last_seen' ? 'last seen' : 'risk'}
        </span>
      </div>

      {/* Expanded filters */}
      {showFilters && (
        <div className="rounded-xl p-4 flex gap-4 flex-wrap" style={{ background: 'var(--rc-bg-surface)', border: '1px solid var(--rc-border)' }}>
          <div>
            <label className="text-xs block mb-1.5" style={{ color: 'var(--rc-text-3)' }}>Severity</label>
            <div className="flex gap-1.5 flex-wrap">
              <button onClick={() => setSeverity('')}
                className="text-xs px-2.5 py-1 rounded-lg border transition-colors"
                style={{ background: !severity ? 'var(--regent-600)' : 'transparent', borderColor: !severity ? 'var(--regent-600)' : 'var(--rc-border-2)', color: !severity ? '#fff' : 'var(--rc-text-3)' }}>
                All
              </button>
              {SEVERITIES.map(s => (
                <button key={s} onClick={() => setSeverity(s === severity ? '' : s)}
                  className={`text-xs px-2.5 py-1 rounded-lg border transition-colors ${severity === s ? SEV_STYLE[s].badge : ''}`}
                  style={severity !== s ? { color: 'var(--rc-text-3)', borderColor: 'var(--rc-border-2)' } : {}}>
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="text-xs block mb-1.5" style={{ color: 'var(--rc-text-3)' }}>Status</label>
            <div className="flex gap-1.5 flex-wrap">
              <button onClick={() => setStatus('')}
                className="text-xs px-2.5 py-1 rounded-lg border transition-colors"
                style={{ background: !status ? 'var(--regent-600)' : 'transparent', borderColor: !status ? 'var(--regent-600)' : 'var(--rc-border-2)', color: !status ? '#fff' : 'var(--rc-text-3)' }}>
                All
              </button>
              {STATUSES.map(s => (
                <button key={s} onClick={() => setStatus(s === status ? '' : s)}
                  className={`text-xs px-2.5 py-1 rounded-lg border transition-colors ${status === s ? STATUS_STYLE[s] : ''}`}
                  style={status !== s ? { color: 'var(--rc-text-3)', borderColor: 'var(--rc-border-2)' } : {}}>
                  {s.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>

          {knownClaws.length > 0 && (
            <div>
              <label className="text-xs block mb-1.5" style={{ color: 'var(--rc-text-3)' }}>Claw</label>
              <div className="flex gap-1.5 flex-wrap">
                <button onClick={() => setClaw('')}
                  className="text-xs px-2.5 py-1 rounded-lg border transition-colors"
                  style={{ background: !claw ? 'var(--regent-600)' : 'transparent', borderColor: !claw ? 'var(--regent-600)' : 'var(--rc-border-2)', color: !claw ? '#fff' : 'var(--rc-text-3)' }}>
                  All
                </button>
                {knownClaws.map(c => (
                  <button key={c} onClick={() => setClaw(c === claw ? '' : c)}
                    className="text-xs px-2.5 py-1 rounded-lg border transition-colors"
                    style={{
                      color: claw === c ? '#fff' : clawColor(c),
                      borderColor: claw === c ? clawColor(c) : clawColor(c) + '40',
                      background: claw === c ? clawColor(c) + '30' : 'transparent',
                    }}>
                    {c}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Table */}
      <div className="flex-1 rounded-xl overflow-hidden" style={{ background: 'var(--rc-bg-surface)', border: '1px solid var(--rc-border)' }}>
        {/* Table header */}
        <div className="grid text-xs font-semibold uppercase tracking-wide px-4 py-2.5 border-b"
          style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)', gridTemplateColumns: '28px 1fr 100px 80px 60px 90px 80px 20px' }}>
          <span /><span>Finding</span><span>Claw</span><span>Status</span>
          <span>Risk</span><span>{sort === 'recent' ? 'Created' : sort === 'last_seen' ? 'Last Seen' : 'First Seen'}</span><span>KEV</span><span />
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 py-20 text-sm" style={{ color: 'var(--rc-text-3)' }}>
            <RefreshCw className="w-4 h-4 animate-spin" /> Loading findings…
          </div>
        ) : findings.length === 0 ? (
          <div className="text-center py-20" style={{ color: 'var(--rc-text-3)' }}>
            <Bug className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No findings match your filters.</p>
            <p className="text-xs mt-1">Run a scan on any Claw to populate findings.</p>
          </div>
        ) : (
          <div className="divide-y overflow-y-auto" style={{ borderColor: 'var(--rc-border)', maxHeight: 'calc(100vh - 340px)' }}>
            {findings.map(f => {
              const sev   = SEV_STYLE[f.severity] ?? SEV_STYLE.info;
              const score = Number(f.risk_score ?? 50);
              return (
                <button key={f.id} onClick={() => setSelected(f)}
                  className="w-full grid items-center gap-3 px-4 py-3 text-left transition-colors hover:opacity-80"
                  style={{ gridTemplateColumns: '28px 1fr 100px 80px 60px 90px 80px 20px' }}>
                  {/* Severity dot */}
                  <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${sev.dot}`} />

                  {/* Title + provider */}
                  <div className="min-w-0">
                    <p className="text-sm truncate font-medium" style={{ color: 'var(--rc-text-1)' }}>{f.title}</p>
                    <p className="text-xs truncate" style={{ color: 'var(--rc-text-3)' }}>
                      {f.provider}{f.resource_name ? ` · ${f.resource_name}` : ''}
                    </p>
                  </div>

                  {/* Claw */}
                  <span className="text-xs font-medium truncate" style={{ color: clawColor(f.claw) }}>{f.claw}</span>

                  {/* Status */}
                  <span className={`text-xs px-2 py-0.5 rounded-full border inline-block w-fit ${STATUS_STYLE[f.status] ?? ''}`}>
                    {f.status?.replace(/_/g, ' ')}
                  </span>

                  {/* Risk score */}
                  <span className="text-sm font-bold tabular-nums" style={{ color: riskColor(score) }}>
                    {score.toFixed(0)}
                  </span>

                  {/* First seen */}
                  <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
                    {fmt(sort === 'recent' ? f.created_at : sort === 'last_seen' ? f.last_seen : f.first_seen)}
                  </span>

                  {/* KEV */}
                  {f.actively_exploited
                    ? <span className="text-xs text-red-500 flex items-center gap-0.5"><Flame className="w-3 h-3" />KEV</span>
                    : <span />}

                  {/* Arrow */}
                  <ChevronRight className="w-4 h-4" style={{ color: 'var(--rc-text-3)' }} />
                </button>
              );
            })}
          </div>
        )}
      </div>

      {selected && (
        <DetailDrawer finding={selected} onClose={() => setSelected(null)}
          onUpdate={() => { fetchAll(buildParams()); setSelected(null); }} />
      )}
    </div>
  );
}
