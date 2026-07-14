'use client';
import { useEffect, useState } from 'react';
import { Users, AlertTriangle, Clock, UserX } from 'lucide-react';
import StatCard from '@/components/StatCard';
import RiskBadge from '@/components/RiskBadge';
import { getIdentityStats, getIdentities, getOrphaned, getApprovals } from '@/lib/api';
import ClientDate from '@/components/ClientDate';

export default function IdentityClawPage() {
  const [stats, setStats] = useState<any>(null);
  const [identities, setIdentities] = useState<any[]>([]);
  const [orphaned, setOrphaned] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [tab, setTab] = useState<'all' | 'orphaned' | 'approvals'>('all');

  useEffect(() => {
    Promise.all([getIdentityStats(), getIdentities(), getOrphaned(), getApprovals()])
      .then(([s, ids, orph, appr]) => {
        setStats(s);
        setIdentities(ids);
        setOrphaned(orph);
        setApprovals(appr);
      })
      .catch(console.error);
  }, []);

  const typeColor = (t: string) => {
    if (t === 'human') return 'text-green-400';
    if (t === 'agent') return 'text-yellow-400';
    if (t === 'connector') return 'text-blue-400';
    return 'text-gray-400';
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Users className="text-blue-400" /> Identity Security
        </h1>
        <p className="text-gray-400 mt-1">Identity Security — Govern every human and non-human identity</p>
      </div>

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
        {(['all', 'orphaned', 'approvals'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${tab === t ? 'bg-regent-600 text-white' : 'text-gray-400 hover:text-white'}`}
          >
            {t === 'all' ? 'All Identities' : t === 'orphaned' ? `Orphaned (${orphaned.length})` : `Pending Approvals (${approvals.length})`}
          </button>
        ))}
      </div>

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
