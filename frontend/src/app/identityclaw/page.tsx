'use client';
import { useEffect, useState } from 'react';
import { Users, AlertTriangle, Clock, UserX, RefreshCw } from 'lucide-react';
import StatCard from '@/components/StatCard';
import RiskBadge from '@/components/RiskBadge';
import { apiFetch, getIdentityStats, getIdentities, getOrphaned, getApprovals } from '@/lib/api';
import ClientDate from '@/components/ClientDate';
import NodeAiAdvisory from '@/components/NodeAiAdvisory';

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-sky-400',
};

export default function IdentityClawPage() {
  const [stats, setStats] = useState<any>(null);
  const [identities, setIdentities] = useState<any[]>([]);
  const [orphaned, setOrphaned] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [providers, setProviders] = useState<any[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [tab, setTab] = useState<'findings' | 'all' | 'orphaned' | 'approvals'>('findings');

  const load = async () => {
    try {
      const [s, ids, orph, appr, f, p] = await Promise.all([
        getIdentityStats(),
        getIdentities(),
        getOrphaned(),
        getApprovals(),
        apiFetch<any[]>('/identityclaw/findings'),
        apiFetch<any[]>('/identityclaw/providers'),
      ]);
      setStats(s);
      setIdentities(ids);
      setOrphaned(orph);
      setApprovals(appr);
      setFindings(f);
      setProviders(p);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => { load(); }, []);

  const handleScan = async () => {
    setScanning(true);
    setScanMsg(null);
    try {
      const res = await apiFetch<any>('/identityclaw/scan', { method: 'POST' });
      await load();
      setScanMsg({
        type: 'success',
        text: `Scan complete — ${res.findings_created ?? 0} new, ${res.findings_updated ?? 0} updated (${res.mode ?? 'unknown'} data).`,
      });
    } catch (e: any) {
      setScanMsg({ type: 'error', text: `Scan failed: ${e?.message ?? 'Unknown error'}` });
    } finally {
      setScanning(false);
      setTimeout(() => setScanMsg(null), 8000);
    }
  };

  const connected = providers.filter((p: any) => p.status === 'approved').length;

  const typeColor = (t: string) => {
    if (t === 'human') return 'text-green-400';
    if (t === 'agent') return 'text-yellow-400';
    if (t === 'connector') return 'text-blue-400';
    return 'text-gray-400';
  };

  return (
    <div className="space-y-8">
      <NodeAiAdvisory claw="identityclaw" />
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Users className="text-blue-400" /> Identity Security
          </h1>
          <p className="text-gray-400 mt-1">
            Identity Security — Govern every human and non-human identity
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500">
            {connected} of {providers.length} directory connectors approved
          </span>
          <button
            onClick={handleScan}
            disabled={scanning}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-regent-600 text-white hover:bg-regent-500 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
            {scanning ? 'Scanning…' : 'Run Scan'}
          </button>
        </div>
      </div>

      {scanMsg && (
        <div
          className={`px-4 py-3 rounded-lg text-sm border ${
            scanMsg.type === 'success'
              ? 'bg-green-900/20 border-green-800/40 text-green-300'
              : 'bg-red-900/20 border-red-800/40 text-red-300'
          }`}
        >
          {scanMsg.text}
        </div>
      )}

      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
          <StatCard label="Total Identities" value={stats.total_identities} icon={Users} color="indigo" />
          <StatCard label="Non-Human Identities" value={stats.non_human_identities} icon={AlertTriangle} color="orange" sub="Agents, connectors, services" />
          <StatCard label="Orphaned Identities" value={stats.orphaned_identities} icon={UserX} color="red" sub="No owner assigned" />
          <StatCard label="High Risk" value={stats.high_risk_identities} icon={AlertTriangle} color="red" />
          <StatCard label="Pending Approvals" value={stats.pending_approvals} icon={Clock} color="yellow" />
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b border-gray-800 pb-2">
        {(['findings', 'all', 'orphaned', 'approvals'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${tab === t ? 'bg-regent-600 text-white' : 'text-gray-400 hover:text-white'}`}
          >
            {t === 'findings'
              ? `Findings (${findings.length})`
              : t === 'all'
              ? 'All Identities'
              : t === 'orphaned'
              ? `Orphaned (${orphaned.length})`
              : `Pending Approvals (${approvals.length})`}
          </button>
        ))}
      </div>

      {tab === 'findings' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-6 py-3 text-left">Finding</th>
                <th className="px-6 py-3 text-left">Severity</th>
                <th className="px-6 py-3 text-left">Source</th>
                <th className="px-6 py-3 text-right">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {findings.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-6 py-6 text-gray-500 text-center">
                    No findings yet. Connect a directory and run a scan.
                  </td>
                </tr>
              )}
              {findings.map((f: any) => (
                <tr key={f.id} className="hover:bg-gray-800/50 align-top">
                  <td className="px-6 py-3">
                    <div className="text-white font-medium">{f.title}</div>
                    {f.remediation && (
                      <div className="text-xs text-gray-500 mt-1">{f.remediation}</div>
                    )}
                  </td>
                  <td className={`px-6 py-3 font-medium ${SEV_COLOR[f.severity] ?? 'text-gray-400'}`}>
                    {f.severity}
                  </td>
                  <td className="px-6 py-3">
                    <span
                      className={`text-xs px-2 py-0.5 rounded ${
                        f.data_origin === 'live'
                          ? 'bg-green-900/30 text-green-400'
                          : 'bg-gray-800 text-gray-500'
                      }`}
                    >
                      {f.data_origin === 'live' ? 'live' : f.data_origin ?? 'unknown'}
                    </span>
                    <span className="text-gray-500 text-xs ml-2">{f.provider ?? '—'}</span>
                  </td>
                  <td className="px-6 py-3 text-right font-mono text-gray-300">
                    {Number(f.risk_score ?? 0).toFixed(0)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'all' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-6 py-3 text-left">Name</th>
                <th className="px-6 py-3 text-left">Type</th>
                <th className="px-6 py-3 text-left">Status</th>
                <th className="px-6 py-3 text-left">Owner</th>
                <th className="px-6 py-3 text-right">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {identities.length === 0 && (
                <tr><td colSpan={5} className="px-6 py-6 text-gray-500 text-center">No identities registered yet.</td></tr>
              )}
              {identities.map((id: any) => (
                <tr key={id.id} className="hover:bg-gray-800/50">
                  <td className="px-6 py-3 text-white font-medium">{id.name}</td>
                  <td className={`px-6 py-3 font-medium ${typeColor(id.type)}`}>{id.type}</td>
                  <td className="px-6 py-3"><RiskBadge value={id.status} /></td>
                  <td className="px-6 py-3 text-gray-400">{id.owner_id ? 'Assigned' : <span className="text-red-400">Unowned</span>}</td>
                  <td className="px-6 py-3 text-right font-mono text-gray-300">{id.risk_score.toFixed(0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'orphaned' && (
        <div className="bg-gray-900 border border-red-800/40 rounded-xl overflow-hidden">
          <div className="px-6 py-3 bg-red-900/20 border-b border-red-800/40 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <p className="text-sm text-red-300 font-medium">Orphaned identities have no owner — critical risk. Assign ownership or revoke immediately.</p>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-6 py-3 text-left">Name</th>
                <th className="px-6 py-3 text-left">Type</th>
                <th className="px-6 py-3 text-left">Source</th>
                <th className="px-6 py-3 text-right">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {orphaned.length === 0 && <tr><td colSpan={4} className="px-6 py-6 text-green-400 text-center">No orphaned identities. ✓</td></tr>}
              {orphaned.map((id: any) => (
                <tr key={id.id} className="hover:bg-gray-800/50">
                  <td className="px-6 py-3 text-white">{id.name}</td>
                  <td className={`px-6 py-3 font-medium ${typeColor(id.type)}`}>{id.type}</td>
                  <td className="px-6 py-3 text-gray-400">{id.source ?? '—'}</td>
                  <td className="px-6 py-3 text-right font-mono text-gray-300">{id.risk_score.toFixed(0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'approvals' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-6 py-3 text-left">Requestor</th>
                <th className="px-6 py-3 text-left">Action</th>
                <th className="px-6 py-3 text-left">Justification</th>
                <th className="px-6 py-3 text-left">Status</th>
                <th className="px-6 py-3 text-left">Requested</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {approvals.length === 0 && <tr><td colSpan={5} className="px-6 py-6 text-gray-500 text-center">No pending approvals.</td></tr>}
              {approvals.map((a: any) => (
                <tr key={a.id} className="hover:bg-gray-800/50">
                  <td className="px-6 py-3 text-white">{a.requestor_name ?? a.requestor_id}</td>
                  <td className="px-6 py-3 text-gray-300">{a.action}</td>
                  <td className="px-6 py-3 text-gray-400 max-w-xs truncate">{a.justification ?? '—'}</td>
                  <td className="px-6 py-3"><RiskBadge value={a.status} /></td>
                  <td className="px-6 py-3 text-gray-500"><ClientDate value={a.timestamp} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
