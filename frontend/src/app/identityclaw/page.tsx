'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Users, AlertTriangle, Clock, UserX, RefreshCw, ShieldCheck, Play, Database, Radio } from 'lucide-react';
import StatCard from '@/components/StatCard';
import RiskBadge from '@/components/RiskBadge';
import { apiFetch, createMicrosoftIdentityIncidentSwarm, getIdentityStats, getIdentities, getOrphaned, getApprovals } from '@/lib/api';
import ClientDate from '@/components/ClientDate';
import NodeAiAdvisory from '@/components/NodeAiAdvisory';

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-sky-400',
};

export default function IdentityClawPage() {
  const router = useRouter();
  const [stats, setStats] = useState<any>(null);
  const [identities, setIdentities] = useState<any[]>([]);
  const [orphaned, setOrphaned] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [providers, setProviders] = useState<any[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [tab, setTab] = useState<'findings' | 'all' | 'orphaned' | 'approvals'>('findings');
  const [missionIdentity, setMissionIdentity] = useState('');
  const [missionWindow, setMissionWindow] = useState('24h');
  const [allowDemoEvidence, setAllowDemoEvidence] = useState(false);
  const [launchingMission, setLaunchingMission] = useState(false);
  const [missionError, setMissionError] = useState<string | null>(null);

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

  const launchIdentityMission = async () => {
    const identity = missionIdentity.trim();
    if (!identity) {
      setMissionError('Enter the affected identity before starting an investigation.');
      return;
    }
    setLaunchingMission(true);
    setMissionError(null);
    try {
      const job = await createMicrosoftIdentityIncidentSwarm({
        identity,
        time_range: missionWindow,
        requested_by: 'identity-security',
        // Investigation is read/analyze/recommend only. Any later containment
        // or ticket action still gets its own Trust Fabric approval.
        requires_approval_for_actions: false,
        allow_demo_evidence: allowDemoEvidence,
      });
      router.push(`/swarm/${job.id}`);
    } catch (e: any) {
      setMissionError(e?.message || 'Could not start the identity investigation.');
    } finally {
      setLaunchingMission(false);
    }
  };

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

      <section className="rounded-xl border border-cyan-900/60 bg-cyan-950/20 p-5">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
          <div className="max-w-2xl">
            <div className="flex items-center gap-2 text-cyan-200">
              <ShieldCheck className="h-5 w-5" />
              <h2 className="font-semibold">Investigate Identity Incident</h2>
            </div>
            <p className="mt-1 text-sm text-gray-300">
              Correlate identity, endpoint, cloud, log, threat, and compliance evidence. The mission only reads and recommends;
              containment, session revocation, and ticket actions remain approval-gated.
            </p>
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              <span className="inline-flex items-center gap-1 rounded border border-green-800 bg-green-900/20 px-2 py-1 text-green-300"><Radio className="h-3 w-3" /> {connected} approved identity source{connected === 1 ? '' : 's'}</span>
              <span className="inline-flex items-center gap-1 rounded border border-cyan-800 bg-cyan-900/20 px-2 py-1 text-cyan-300"><Database className="h-3 w-3" /> live or recorded evidence required</span>
            </div>
          </div>
          <div className="grid w-full gap-2 sm:grid-cols-[minmax(220px,1fr)_100px_auto] xl:w-auto">
            <input
              value={missionIdentity}
              onChange={(event) => setMissionIdentity(event.target.value)}
              placeholder="affected user or principal"
              aria-label="Affected identity"
              className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder:text-gray-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <select
              value={missionWindow}
              onChange={(event) => setMissionWindow(event.target.value)}
              aria-label="Evidence time range"
              className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200"
            >
              <option value="4h">4 hours</option>
              <option value="24h">24 hours</option>
              <option value="7d">7 days</option>
            </select>
            <button
              onClick={launchIdentityMission}
              disabled={launchingMission || !missionIdentity.trim()}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-600 px-3 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-60"
            >
              <Play className="h-4 w-4" /> {launchingMission ? 'Starting…' : 'Investigate'}
            </button>
          </div>
        </div>
        <label className="mt-4 flex w-fit cursor-pointer items-center gap-2 text-xs text-gray-400">
          <input
            type="checkbox"
            checked={allowDemoEvidence}
            onChange={(event) => setAllowDemoEvidence(event.target.checked)}
            className="h-4 w-4 rounded border-gray-700 bg-gray-950 text-cyan-500"
          />
          Allow labeled demo evidence for a local walkthrough
        </label>
        {missionError && <p className="mt-3 text-sm text-red-300">{missionError}</p>}
      </section>

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
