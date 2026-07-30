'use client';
import { useEffect, useState } from 'react';
import { Target, RefreshCw, Plug, ChevronDown, ChevronRight } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { ProviderPill } from '@/components/ProviderPill';
import NodeAiAdvisory from '@/components/NodeAiAdvisory';

const SEVERITY_STYLE = {
  critical: { color: 'text-red-400',    bg: 'bg-red-900/20',    border: 'border-red-800',    dot: 'bg-red-500'    },
  high:     { color: 'text-orange-400', bg: 'bg-orange-900/20', border: 'border-orange-800', dot: 'bg-orange-500' },
  medium:   { color: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-800', dot: 'bg-yellow-500' },
  low:      { color: 'text-blue-400',   bg: 'bg-blue-900/20',   border: 'border-blue-800',   dot: 'bg-blue-500'   },
  info:     { color: 'text-gray-400',   bg: 'bg-gray-900/20',   border: 'border-gray-800',   dot: 'bg-gray-500'   },
};

const STATUS_STYLE: Record<string, string> = {
  open:           'text-red-400',
  in_remediation: 'text-yellow-400',
  resolved:       'text-green-400',
  accepted_risk:  'text-gray-400',
  false_positive: 'text-gray-500',
};

export default function ThreatClawPage() {
  const [stats, setStats]         = useState<any>(null);
  const [findings, setFindings]   = useState<any[]>([]);
  const [providers, setProviders] = useState<any[]>([]);
  const [loading, setLoading]     = useState(true);
  const [scanning, setScanning]   = useState(false);
  const [expanded, setExpanded]   = useState<string | null>(null);
  const [scanMsg, setScanMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [filterSev, setFilterSev] = useState('all');

  const load = async () => {
    setLoading(true);
    try {
      const [s, f, p] = await Promise.all([
        apiFetch<any>('/threatclaw/stats'),
        apiFetch<any[]>('/threatclaw/findings'),
        apiFetch<any[]>('/threatclaw/providers'),
      ]);
      setStats(s); setFindings(f); setProviders(p);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleScan = async () => {
    setScanning(true);
    setScanMsg(null);
    try {
      const res = await apiFetch<any>('/threatclaw/scan', { method: 'POST' });
      await load();
      setScanMsg({ type: 'success', text: `Scan complete — ${res.findings_created ?? 0} new, ${res.findings_updated ?? 0} updated. Critical: ${res.critical ?? 0}, High: ${res.high ?? 0}.` });
    } catch (e: any) {
      setScanMsg({ type: 'error', text: `Scan failed: ${e?.message ?? 'Unknown error'}` });
    } finally {
      setScanning(false);
      setTimeout(() => setScanMsg(null), 8000);
    }
  };

  const shown = filterSev === 'all' ? findings : findings.filter(f => f.severity === filterSev);
  const configured = providers.filter(p => p.configured).length;

  return (
    <div className="space-y-6">
      <NodeAiAdvisory claw="threatclaw" />
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
            <Target className="text-red-400" /> Threat Analysis
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
            Threat detection and active incident response - correlated alerts, MITRE ATT&CK mapping, and active threat campaigns.
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {[
            { label: 'Total', val: stats?.total_findings ?? stats?.total ?? '\u2014', c: 'text-red-400 bg-red-900/20 border-red-800' },
            { label: 'Critical', val: stats?.by_severity?.critical ?? stats?.critical ?? '\u2014', c: 'text-red-400 bg-red-900/20 border-red-800' },
            { label: 'Active', val: stats?.active_threats ?? '\u2014', c: 'text-orange-400 bg-orange-900/20 border-orange-800' },
            { label: 'Providers', val: `${configured}/${providers.length}`, c: configured > 0 ? 'text-green-400 bg-green-900/20 border-green-800' : 'text-gray-400 bg-gray-900/20 border-gray-800' },
          ].map(({ label, val, c }) => (
            <div key={label} className={`px-4 py-2 rounded-xl border text-center ${c}`}>
              <p className="text-xl font-bold">{val}</p>
              <p className="text-xs">{label}</p>
            </div>
          ))}
          <button onClick={handleScan} disabled={scanning}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium text-white disabled:opacity-50"
            style={{ background: 'var(--regent-600)' }}>
            <RefreshCw className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
            {scanning ? 'Scanning…' : 'Run Scan'}
          </button>
        </div>
      </div>

      <div className="rounded-xl border p-4" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
            <Plug className="w-4 h-4 text-red-400" /> Connected Providers
          </h2>
          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Configure in Connector Marketplace → credentials stored encrypted</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {loading ? <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Loading…</p> :
            providers.map((p: any) => (
              <ProviderPill key={p.provider} provider={p} />
            ))
          }
        </div>
      </div>

      {scanMsg && (
        <div className={`flex items-center gap-3 rounded-xl border px-4 py-3 text-sm transition-all ${
          scanMsg.type === 'success'
            ? 'text-green-300 border-green-800 bg-green-900/20'
            : 'text-red-300 border-red-800 bg-red-900/20'
        }`}>
          <span>{scanMsg.type === 'success' ? '✓' : '✗'}</span>
          {scanMsg.text}
        </div>
      )}

      {configured === 0 && providers.length > 0 && (
        <div className="flex items-start gap-3 rounded-xl border px-4 py-3"
          style={{ background: 'rgba(234,179,8,0.06)', borderColor: 'rgba(234,179,8,0.3)' }}>
          <span className="text-yellow-400 text-lg leading-none flex-shrink-0">⚠</span>
          <div>
            <p className="text-sm font-semibold text-yellow-300">Demo Data — No Connector Configured</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
              These findings are sample data for demonstration only. Connect a real data source
              in <strong style={{ color: 'var(--rc-text-2)' }}>Connector Marketplace</strong> to
              see your organization's actual security findings.
            </p>
          </div>
        </div>
      )}

      <div className="flex gap-2 flex-wrap">
        {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
          <button key={sev} onClick={() => setFilterSev(sev)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition-colors ${filterSev === sev ? 'bg-red-600 text-white' : 'hover:opacity-80'}`}
            style={filterSev !== sev ? { color: 'var(--rc-text-2)', background: 'var(--rc-bg-elevated)' } : {}}>
            {sev} {sev !== 'all' && findings.filter(f => f.severity === sev).length > 0 && `(${findings.filter(f => f.severity === sev).length})`}
          </button>
        ))}
      </div>

      {loading ? (
        <p className="p-6 text-sm" style={{ color: 'var(--rc-text-3)' }}>Loading…</p>
      ) : shown.length === 0 ? (
        <div className="rounded-xl border border-dashed p-8 text-center" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <p className="font-semibold mb-2" style={{ color: 'var(--rc-text-1)' }}>No findings yet</p>
          <p className="text-sm mb-3" style={{ color: 'var(--rc-text-2)' }}>
            Connect a provider above or click Run Scan to load demo findings.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {shown.map((f: any) => {
            const sev = SEVERITY_STYLE[f.severity as keyof typeof SEVERITY_STYLE] ?? SEVERITY_STYLE.medium;
            const isOpen = expanded === f.id;
            return (
              <div key={f.id} className="rounded-xl border transition-all" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
                <button className="w-full flex items-start gap-3 p-4 text-left" onClick={() => setExpanded(isOpen ? null : f.id)}>
                  <div className={`flex-shrink-0 w-2 h-2 rounded-full mt-2 ${sev.dot}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-0.5">
                      <p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{f.title}</p>
                      <span className={`text-xs px-2 py-0.5 rounded border ${sev.color} ${sev.bg} ${sev.border}`}>{f.severity}</span>
                      {f.actively_exploited && <span className="text-xs text-red-400 font-bold">⚠ KEV</span>}
                    </div>
                    <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
                      {f.resource_name || f.resource_id || 'Unknown resource'} · {f.provider} · {f.category || 'finding'}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className={`text-xs font-medium ${STATUS_STYLE[String(f.status).toLowerCase()] ?? 'text-gray-400'}`}>{String(f.status).toLowerCase()}</span>
                    {isOpen ? <ChevronDown className="w-4 h-4" style={{ color: 'var(--rc-text-3)' }} /> : <ChevronRight className="w-4 h-4" style={{ color: 'var(--rc-text-3)' }} />}
                  </div>
                </button>
                {isOpen && (
                  <div className="px-4 pb-4 border-t pt-3 space-y-3" style={{ borderColor: 'var(--rc-border)' }}>
                    {f.description && <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>{f.description}</p>}
                    {f.remediation && (
                      <div className="rounded-lg p-3" style={{ background: 'var(--rc-bg-elevated)' }}>
                        <p className="text-xs font-semibold mb-1 text-green-400">Remediation</p>
                        <p className="text-xs" style={{ color: 'var(--rc-text-2)' }}>{f.remediation}</p>
                        {f.remediation_effort && (
                          <span className="text-xs mt-1 inline-block text-yellow-400">Effort: {f.remediation_effort.replace('_', ' ')}</span>
                        )}
                      </div>
                    )}
                    <div className="flex gap-4 text-xs" style={{ color: 'var(--rc-text-3)' }}>
                      {f.cvss_score && <span>CVSS: <strong className="text-orange-400">{f.cvss_score}</strong></span>}
                      {f.epss_score && <span>EPSS: <strong className="text-yellow-400">{(f.epss_score * 100).toFixed(1)}%</strong></span>}
                      {f.risk_score && <span>Risk: <strong style={{ color: 'var(--rc-text-1)' }}>{f.risk_score.toFixed(0)}/100</strong></span>}
                      {f.region && <span>Region: {f.region}</span>}
                      {f.external_id && <span>ID: {f.external_id}</span>}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
