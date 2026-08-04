'use client';
import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Plug, CheckCircle, XCircle, Clock, AlertTriangle,
  RefreshCw, Settings, Ban, ChevronLeft,
  Activity, Shield,
} from 'lucide-react';
import ClientDate from '@/components/ClientDate';
import { getConnectorHealthSummary, testConnector } from '@/lib/api';

type ConnectorHealth = {
  id: string;
  name: string;
  connector_type: string;
  category: string | null;
  status: string;
  health: 'verified' | 'unverified' | 'unconfigured' | 'pending' | 'blocked' | 'restricted' | 'unknown';
  is_configured: boolean;
  trust_score: number;
  risk_level: string;
  last_used: string | null;
  last_verified_at: string | null;
  verification_level: string | null;
};

type Summary = {
  total: number;
  verified: number;
  unverified: number;
  unconfigured: number;
  pending: number;
  blocked: number;
  configured: number;
  connectors: ConnectorHealth[];
};

const HEALTH_META: Record<string, { icon: React.ElementType; color: string; bg: string; label: string }> = {
  verified:     { icon: CheckCircle,   color: 'text-green-400',  bg: 'bg-green-900/30 border-green-800',   label: 'Verified' },
  unverified:   { icon: AlertTriangle, color: 'text-amber-400',  bg: 'bg-amber-900/30 border-amber-800',   label: 'Needs Verification' },
  unconfigured: { icon: Settings,      color: 'text-yellow-400', bg: 'bg-yellow-900/30 border-yellow-800', label: 'Not Configured' },
  pending:      { icon: Clock,         color: 'text-blue-400',   bg: 'bg-blue-900/30 border-blue-800',     label: 'Pending Approval' },
  blocked:      { icon: Ban,           color: 'text-red-400',    bg: 'bg-red-900/30 border-red-800',       label: 'Blocked' },
  restricted:   { icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-900/30 border-orange-800', label: 'Restricted' },
  unknown:      { icon: Clock,         color: 'text-gray-400',   bg: 'bg-gray-800 border-gray-700',        label: 'Unknown' },
};

const TRUST_COLOR = (score: number) =>
  score >= 80 ? 'text-green-400' : score >= 50 ? 'text-yellow-400' : 'text-red-400';

export default function ConnectorHealthPage() {
  const router = useRouter();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message: string }>>({});
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [healthFilter, setHealthFilter]     = useState('all');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getConnectorHealthSummary() as Summary;
      setSummary(data);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleTest = async (id: string) => {
    setTesting(id);
    try {
      const res = await testConnector(id) as any;
      setTestResults(prev => ({ ...prev, [id]: { success: res.success, message: res.message } }));
      await load();
    } finally {
      setTesting(null);
    }
  };

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const all = summary?.connectors ?? [];
  const categories = ['All', ...Array.from(new Set(all.map(c => c.category ?? 'Other').filter(Boolean)))];

  const filtered = all.filter(c => {
    if (categoryFilter !== 'All' && (c.category ?? 'Other') !== categoryFilter) return false;
    if (healthFilter !== 'all' && c.health !== healthFilter) return false;
    return true;
  });

  const verified = all.filter(c => c.health === 'verified').length;
  const issues   = all.filter(c => c.health !== 'verified').length;
  const overallHealth = all.length === 0 ? 'unknown' :
    verified === all.length ? 'all_verified' :
    verified === 0 ? 'none_verified' : 'partial';

  return (
    <div className="space-y-6">

      {/* Header */}
      <div>
        <button
          onClick={() => router.push('/connectors')}
          className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-white mb-4 transition-colors"
        >
          <ChevronLeft className="w-4 h-4" /> Back to Connectors
        </button>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3">
              <Activity className="text-cyan-400" /> Connector Health
            </h1>
            <p className="text-gray-400 mt-1 text-sm">
              Recorded read-only verification status. A connector is verified only after Enkstein completes a provider-specific check.
            </p>
          </div>
          <button onClick={load} className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Overall health banner */}
      {summary && (
        <div className={`rounded-xl border px-6 py-4 flex items-center gap-4 ${
          overallHealth === 'all_verified' ? 'bg-green-900/20 border-green-800' :
          overallHealth === 'none_verified' ? 'bg-red-900/20 border-red-800' :
          'bg-yellow-900/20 border-yellow-800'
        }`}>
          {overallHealth === 'all_verified' && <CheckCircle className="w-6 h-6 text-green-400 flex-shrink-0" />}
          {overallHealth === 'none_verified' && <XCircle className="w-6 h-6 text-red-400 flex-shrink-0" />}
          {overallHealth === 'partial' && <AlertTriangle className="w-6 h-6 text-yellow-400 flex-shrink-0" />}
          <div>
            <p className="text-white font-semibold text-sm">
              {overallHealth === 'all_verified' && 'All connectors verified'}
              {overallHealth === 'none_verified' && 'No verified connectors — configure and test a connector to get started'}
              {overallHealth === 'partial' && `${verified} of ${all.length} connectors verified — ${issues} need attention`}
            </p>
            <p className="text-gray-400 text-xs mt-0.5">
              {summary.configured} configured · {summary.verified} verified · {summary.unverified} awaiting test · {summary.unconfigured} unconfigured
            </p>
          </div>
        </div>
      )}

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: 'Total', value: summary.total, color: 'text-white' },
            { label: 'Verified', value: summary.verified, color: 'text-green-400' },
            { label: 'Needs Test', value: summary.unverified, color: summary.unverified > 0 ? 'text-amber-400' : 'text-gray-500' },
            { label: 'Configured', value: summary.configured, color: 'text-blue-400' },
            { label: 'Unconfigured', value: summary.unconfigured, color: summary.unconfigured > 0 ? 'text-yellow-400' : 'text-gray-500' },
            { label: 'Blocked', value: summary.blocked, color: summary.blocked > 0 ? 'text-red-400' : 'text-gray-500' },
          ].map(s => (
            <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
              <p className="text-xs text-gray-500">{s.label}</p>
              <p className={`text-2xl font-bold mt-0.5 ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          value={categoryFilter}
          onChange={e => setCategoryFilter(e.target.value)}
          className="bg-gray-900 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none"
        >
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <div className="flex gap-1 bg-gray-900 border border-gray-700 rounded-xl p-1">
          {['all', 'verified', 'unverified', 'unconfigured', 'pending', 'blocked'].map(h => (
            <button
              key={h}
              onClick={() => setHealthFilter(h)}
              className={`text-xs px-3 py-1.5 rounded-lg capitalize transition-colors ${
                healthFilter === h ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              {h}
            </button>
          ))}
        </div>
        <span className="text-xs text-gray-500 self-center">{filtered.length} connectors</span>
      </div>

      {/* Connector health table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-500 text-xs">
              <th className="px-5 py-3 text-left">Connector</th>
              <th className="px-5 py-3 text-left">Category</th>
              <th className="px-5 py-3 text-left">Health</th>
              <th className="px-5 py-3 text-left">Trust Score</th>
              <th className="px-5 py-3 text-left">Risk</th>
              <th className="px-5 py-3 text-left">Last Verified</th>
              <th className="px-5 py-3 text-left">Test</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {filtered.map(c => {
              const meta = HEALTH_META[c.health] ?? HEALTH_META.unknown;
              const Icon = meta.icon;
              const testResult = testResults[c.id];

              return (
                <tr key={c.id} className="hover:bg-gray-800/30">
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-2.5">
                      <Plug className={`w-3.5 h-3.5 flex-shrink-0 ${meta.color}`} />
                      <div>
                        <p className="text-white text-xs font-medium">{c.name}</p>
                        <p className="text-gray-500 text-xs">{c.connector_type}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3 text-gray-400 text-xs">{c.category ?? '—'}</td>
                  <td className="px-5 py-3">
                    <span className={`flex items-center gap-1.5 text-xs font-medium w-fit px-2 py-1 rounded-lg border ${meta.bg}`}>
                      <Icon className={`w-3 h-3 ${meta.color}`} /> {meta.label}
                    </span>
                    {testResult && (
                      <p className={`text-xs mt-0.5 ${testResult.success ? 'text-green-400' : 'text-red-400'}`}>
                        {testResult.message}
                      </p>
                    )}
                  </td>
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-gray-800 rounded-full h-1.5">
                        <div
                          className="h-1.5 rounded-full bg-cyan-500"
                          style={{ width: `${c.trust_score}%` }}
                        />
                      </div>
                      <span className={`text-xs font-semibold ${TRUST_COLOR(c.trust_score)}`}>
                        {c.trust_score.toFixed(0)}
                      </span>
                    </div>
                  </td>
                  <td className="px-5 py-3">
                    <span className={`text-xs capitalize px-1.5 py-0.5 rounded ${
                      c.risk_level === 'critical' ? 'text-red-400 bg-red-900/20' :
                      c.risk_level === 'high'     ? 'text-orange-400 bg-orange-900/20' :
                      c.risk_level === 'medium'   ? 'text-yellow-400 bg-yellow-900/20' :
                      'text-green-400 bg-green-900/20'
                    }`}>{c.risk_level}</span>
                  </td>
                  <td className="px-5 py-3 text-gray-400 text-xs">
                    {c.last_verified_at ? <ClientDate value={c.last_verified_at} format="date" /> : 'Never'}
                  </td>
                  <td className="px-5 py-3">
                    {c.is_configured ? (
                      <button
                        onClick={() => handleTest(c.id)}
                        disabled={testing === c.id}
                        className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 disabled:opacity-50 transition-colors"
                      >
                        {testing === c.id
                          ? <RefreshCw className="w-3 h-3 animate-spin" />
                          : <Activity className="w-3 h-3" />
                        }
                        Test
                      </button>
                    ) : (
                      <button
                        onClick={() => router.push('/connectors')}
                        className="flex items-center gap-1.5 text-xs text-yellow-400 hover:text-yellow-300 transition-colors"
                      >
                        <Settings className="w-3 h-3" /> Configure
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <p className="px-5 py-8 text-gray-500 text-sm text-center">
            No connectors match the current filters.
          </p>
        )}
      </div>
    </div>
  );
}
