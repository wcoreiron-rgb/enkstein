'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  MessageSquare,
  Shield,
  Users2,
  Workflow,
} from 'lucide-react';
import {
  getChannelGatewayStats,
  getExecStats,
  getPendingCommands,
  getRecentRuns,
  getSchedules,
  getSwarmJobs,
  listExternalAgents,
} from '@/lib/api';

type KpiCardProps = {
  label: string;
  value: string;
  hint?: string;
  tone?: 'cyan' | 'green' | 'yellow' | 'red' | 'gray';
  icon: React.ElementType;
};

function KpiCard({ label, value, hint, tone = 'gray', icon: Icon }: KpiCardProps) {
  const toneClass =
    tone === 'cyan'
      ? 'border-cyan-800 bg-cyan-950/20 text-cyan-200'
      : tone === 'green'
        ? 'border-green-800 bg-green-950/20 text-green-200'
        : tone === 'yellow'
          ? 'border-yellow-800 bg-yellow-950/20 text-yellow-200'
          : tone === 'red'
            ? 'border-red-800 bg-red-950/20 text-red-200'
            : 'border-gray-800 bg-gray-950/40 text-gray-200';
  return (
    <div className={`rounded-lg border p-4 ${toneClass}`}>
      <div className="flex items-center justify-between">
        <p className="text-xs uppercase tracking-wider opacity-80">{label}</p>
        <Icon className="w-4 h-4 opacity-80" />
      </div>
      <p className="mt-2 text-2xl font-semibold">{value}</p>
      {hint ? <p className="mt-1 text-xs opacity-80">{hint}</p> : null}
    </div>
  );
}

export default function ControlCenterPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingCount, setPendingCount] = useState(0);
  const [swarmJobs, setSwarmJobs] = useState<any[]>([]);
  const [agents, setAgents] = useState<any[]>([]);
  const [runs, setRuns] = useState<any[]>([]);
  const [scheduleCount, setScheduleCount] = useState(0);
  const [execStats, setExecStats] = useState<any>(null);
  const [channelStats, setChannelStats] = useState<any>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const [
          pending,
          swarms,
          remoteAgents,
          recentRuns,
          schedules,
          exec,
          gateway,
        ] = await Promise.all([
          getPendingCommands(100),
          getSwarmJobs(),
          listExternalAgents(),
          getRecentRuns(20),
          getSchedules(),
          getExecStats(),
          getChannelGatewayStats(),
        ]);
        if (!active) return;
        setPendingCount((pending as any)?.count ?? 0);
        setSwarmJobs(Array.isArray(swarms) ? swarms : []);
        setAgents(Array.isArray(remoteAgents) ? remoteAgents : []);
        setRuns(Array.isArray(recentRuns) ? recentRuns : []);
        setScheduleCount(Array.isArray(schedules) ? schedules.length : 0);
        setExecStats(exec || null);
        setChannelStats(gateway || null);
      } catch (e: any) {
        if (!active) return;
        setError(e?.message || 'Failed to load control center');
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const runningSwarms = useMemo(
    () => swarmJobs.filter((j) => ['pending', 'running'].includes((j?.status || '').toLowerCase())),
    [swarmJobs],
  );
  const blockedSwarms = useMemo(
    () => swarmJobs.filter((j) => ['blocked', 'failed', 'cancelled'].includes((j?.status || '').toLowerCase())),
    [swarmJobs],
  );
  const remoteOnline = useMemo(
    () => agents.filter((a) => ['active', 'online'].includes((a?.status || '').toLowerCase())).length,
    [agents],
  );
  const pendingExec = Number(execStats?.pending_approval || 0);
  const recentFailures = useMemo(
    () => runs.filter((r) => ['failed', 'error', 'blocked'].includes((r?.status || '').toLowerCase())).slice(0, 6),
    [runs],
  );

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            Regent Control Center
          </h1>
          <p className="mt-1 text-sm text-gray-400">
            Unified command and orchestration view across channels, swarms, remote agents, approvals, and execution.
          </p>
        </div>
        <button
          onClick={() => window.location.reload()}
          className="px-3 py-2 rounded-lg border border-gray-800 text-sm text-gray-300 hover:bg-gray-900"
        >
          Refresh
        </button>
      </div>

      {error ? (
        <div className="rounded-lg border border-red-800 bg-red-950/20 p-4 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <KpiCard label="Pending Commands" value={String(pendingCount)} hint="Awaiting human decision" tone={pendingCount > 0 ? 'yellow' : 'green'} icon={Clock} />
        <KpiCard label="Running Swarms" value={String(runningSwarms.length)} hint={`${blockedSwarms.length} blocked/failed`} tone={runningSwarms.length > 0 ? 'cyan' : 'gray'} icon={Users2} />
        <KpiCard label="Remote Agents Online" value={`${remoteOnline}/${agents.length}`} hint="External and remote workers" tone={remoteOnline > 0 ? 'green' : 'red'} icon={Activity} />
        <KpiCard label="Pending Exec Gates" value={String(pendingExec)} hint="Ring policy approvals" tone={pendingExec > 0 ? 'yellow' : 'green'} icon={Workflow} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <section className="xl:col-span-2 rounded-lg border border-gray-800 bg-gray-950/40 p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              Immediate Operator Queue
            </h2>
            <Link href="/channel-gateway" className="text-xs text-cyan-300 hover:text-cyan-200">Open Commands</Link>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
            <div className="rounded border border-gray-800 p-3">
              <p className="text-gray-400 text-xs">Command approvals</p>
              <p className="text-xl font-semibold text-white mt-1">{pendingCount}</p>
            </div>
            <div className="rounded border border-gray-800 p-3">
              <p className="text-gray-400 text-xs">Channel pending</p>
              <p className="text-xl font-semibold text-white mt-1">{channelStats?.pending_approval ?? 0}</p>
            </div>
            <div className="rounded border border-gray-800 p-3">
              <p className="text-gray-400 text-xs">Schedules configured</p>
              <p className="text-xl font-semibold text-white mt-1">{scheduleCount}</p>
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
            <MessageSquare className="w-4 h-4 text-cyan-400" />
            Channel Ingress
          </h2>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-gray-400">Messages</span><span className="text-white">{channelStats?.total_messages ?? 0}</span></div>
            <div className="flex justify-between"><span className="text-gray-400">Allowed</span><span className="text-green-300">{channelStats?.allowed ?? 0}</span></div>
            <div className="flex justify-between"><span className="text-gray-400">Blocked</span><span className="text-red-300">{channelStats?.blocked ?? 0}</span></div>
            <div className="flex justify-between"><span className="text-gray-400">Pending</span><span className="text-yellow-300">{channelStats?.pending_approval ?? 0}</span></div>
          </div>
        </section>
      </div>

      <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-white">Recent Failed / Blocked Runs</h2>
          <Link href="/runs" className="text-xs text-cyan-300 hover:text-cyan-200">Open Run History</Link>
        </div>
        {loading ? (
          <p className="text-sm text-gray-400">Loading…</p>
        ) : recentFailures.length === 0 ? (
          <div className="text-sm text-gray-400 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-green-400" />
            No recent failed/blocked runs.
          </div>
        ) : (
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead className="text-xs text-gray-500 border-b border-gray-800">
                <tr>
                  <th className="py-2 text-left">Run</th>
                  <th className="py-2 text-left">Status</th>
                  <th className="py-2 text-left">Triggered By</th>
                  <th className="py-2 text-left">Started</th>
                </tr>
              </thead>
              <tbody>
                {recentFailures.map((r: any) => (
                  <tr key={r.id} className="border-b border-gray-900">
                    <td className="py-2 text-gray-200">{r.run_id || r.id}</td>
                    <td className="py-2">
                      <span className="px-2 py-0.5 rounded border border-red-800 bg-red-950/20 text-red-300 text-xs">
                        {r.status}
                      </span>
                    </td>
                    <td className="py-2 text-gray-300">{r.triggered_by || '—'}</td>
                    <td className="py-2 text-gray-400">{r.started_at ? new Date(r.started_at).toLocaleString() : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
