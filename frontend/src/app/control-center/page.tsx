'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Link2,
  MessageSquare,
  PlayCircle,
  ShieldAlert,
  Shield,
  Siren,
  Timer,
  Users2,
  Workflow,
} from 'lucide-react';
import {
  getControlCenterSummary,
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
  const [summary, setSummary] = useState<any>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const [
          summaryData,
          pending,
          swarms,
          remoteAgents,
          recentRuns,
          schedules,
          exec,
          gateway,
        ] = await Promise.all([
          getControlCenterSummary(),
          getPendingCommands(100),
          getSwarmJobs(),
          listExternalAgents(),
          getRecentRuns(20),
          getSchedules(),
          getExecStats(),
          getChannelGatewayStats(),
        ]);
        if (!active) return;
        setSummary(summaryData || null);
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
  const pendingCommandsEff = summary?.pending_commands ?? pendingCount;
  const runningSwarmsEff = summary?.running_swarms ?? runningSwarms.length;
  const blockedSwarmsEff = summary?.blocked_swarms ?? blockedSwarms.length;
  const remoteOnlineEff = summary?.remote_agents_online ?? remoteOnline;
  const remoteTotalEff = summary?.remote_agents_total ?? agents.length;
  const pendingExecEff = summary?.execution_pending_approval ?? pendingExec;
  const channelBlockedEff = summary?.channel_blocked_24h ?? channelStats?.blocked ?? 0;
  const channelMsgs24hEff = summary?.channel_messages_24h ?? channelStats?.total_messages ?? 0;
  const blockedActions24hEff = summary?.blocked_actions_24h ?? 0;

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
        <KpiCard label="Pending Commands" value={String(pendingCommandsEff)} hint="Awaiting human decision" tone={pendingCommandsEff > 0 ? 'yellow' : 'green'} icon={Clock} />
        <KpiCard label="Running Swarms" value={String(runningSwarmsEff)} hint={`${blockedSwarmsEff} blocked/failed`} tone={runningSwarmsEff > 0 ? 'cyan' : 'gray'} icon={Users2} />
        <KpiCard label="Remote Agents Online" value={`${remoteOnlineEff}/${remoteTotalEff}`} hint="External and remote workers" tone={remoteOnlineEff > 0 ? 'green' : 'red'} icon={Activity} />
        <KpiCard label="Pending Exec Gates" value={String(pendingExecEff)} hint="Ring policy approvals" tone={pendingExecEff > 0 ? 'yellow' : 'green'} icon={Workflow} />
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
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-sm">
            <div className="rounded border border-gray-800 p-3">
              <p className="text-gray-400 text-xs">Command approvals</p>
              <p className="text-xl font-semibold text-white mt-1">{pendingCommandsEff}</p>
            </div>
            <div className="rounded border border-gray-800 p-3">
              <p className="text-gray-400 text-xs">Channel blocked (24h)</p>
              <p className="text-xl font-semibold text-white mt-1">{channelBlockedEff}</p>
            </div>
            <div className="rounded border border-gray-800 p-3">
              <p className="text-gray-400 text-xs">Schedules configured</p>
              <p className="text-xl font-semibold text-white mt-1">{summary?.schedules_total ?? scheduleCount}</p>
            </div>
            <div className="rounded border border-gray-800 p-3">
              <p className="text-gray-400 text-xs">Platform blocked (24h)</p>
              <p className="text-xl font-semibold text-white mt-1">{blockedActions24hEff}</p>
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
            <MessageSquare className="w-4 h-4 text-cyan-400" />
            Channel Ingress
          </h2>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-gray-400">Messages (24h)</span><span className="text-white">{channelMsgs24hEff}</span></div>
            <div className="flex justify-between"><span className="text-gray-400">Allowed</span><span className="text-green-300">{channelStats?.allowed ?? 0}</span></div>
            <div className="flex justify-between"><span className="text-gray-400">Blocked</span><span className="text-red-300">{channelStats?.blocked ?? 0}</span></div>
            <div className="flex justify-between"><span className="text-gray-400">Pending</span><span className="text-yellow-300">{channelStats?.pending_approval ?? 0}</span></div>
          </div>
        </section>
      </div>

      <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Link2 className="w-4 h-4 text-cyan-400" />
            Control Plane Shortcuts
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          <Link href="/channel-gateway" className="rounded border border-gray-800 p-3 hover:border-cyan-700 transition-colors">
            <div className="flex items-center gap-2 text-cyan-300 text-sm font-medium"><MessageSquare className="w-4 h-4" /> Commands</div>
            <p className="text-xs text-gray-400 mt-1">Review, approve, reject, and export command timelines.</p>
          </Link>
          <Link href="/swarm" className="rounded border border-gray-800 p-3 hover:border-cyan-700 transition-colors">
            <div className="flex items-center gap-2 text-cyan-300 text-sm font-medium"><Users2 className="w-4 h-4" /> Swarms</div>
            <p className="text-xs text-gray-400 mt-1">Launch investigations and monitor live task execution.</p>
          </Link>
          <Link href="/external-agents" className="rounded border border-gray-800 p-3 hover:border-cyan-700 transition-colors">
            <div className="flex items-center gap-2 text-cyan-300 text-sm font-medium"><Activity className="w-4 h-4" /> Remote Agents</div>
            <p className="text-xs text-gray-400 mt-1">Trust, heartbeat, dispatch, and kill-switch visibility.</p>
          </Link>
          <Link href="/exec-channels" className="rounded border border-gray-800 p-3 hover:border-cyan-700 transition-colors">
            <div className="flex items-center gap-2 text-cyan-300 text-sm font-medium"><ShieldAlert className="w-4 h-4" /> Execution Gates</div>
            <p className="text-xs text-gray-400 mt-1">Ring-policy execution requests and production approvals.</p>
          </Link>
        </div>
      </section>

      <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Siren className="w-4 h-4 text-yellow-400" />
            Orchestration Pressure
          </h2>
          <Link href="/schedules" className="text-xs text-cyan-300 hover:text-cyan-200">Open Schedules</Link>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
          <div className="rounded border border-gray-800 p-3">
            <p className="text-gray-400 text-xs">Swarms running</p>
            <p className="text-xl font-semibold text-white mt-1">{runningSwarmsEff}</p>
          </div>
          <div className="rounded border border-gray-800 p-3">
            <p className="text-gray-400 text-xs">Swarms blocked/failed</p>
            <p className="text-xl font-semibold text-white mt-1">{blockedSwarmsEff}</p>
          </div>
          <div className="rounded border border-gray-800 p-3">
            <p className="text-gray-400 text-xs">Active schedules</p>
            <p className="text-xl font-semibold text-white mt-1">{summary?.schedules_active ?? 0}</p>
          </div>
        </div>
      </section>

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
                    <td className="py-2 text-gray-400 flex items-center gap-1">
                      <Timer className="w-3 h-3" />
                      {r.started_at ? new Date(r.started_at).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <PlayCircle className="w-4 h-4 text-cyan-400" />
            Next Actions
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
          <Link href="/channel-gateway" className="rounded border border-gray-800 p-3 hover:border-cyan-700 transition-colors">
            <p className="text-gray-200 font-medium">Clear pending approvals</p>
            <p className="text-gray-400 text-xs mt-1">Prioritize command approvals before queue saturation.</p>
          </Link>
          <Link href="/swarm" className="rounded border border-gray-800 p-3 hover:border-cyan-700 transition-colors">
            <p className="text-gray-200 font-medium">Review blocked swarms</p>
            <p className="text-gray-400 text-xs mt-1">Inspect failed/blocked runs and retry with corrected scope.</p>
          </Link>
          <Link href="/external-agents" className="rounded border border-gray-800 p-3 hover:border-cyan-700 transition-colors">
            <p className="text-gray-200 font-medium">Validate remote trust posture</p>
            <p className="text-gray-400 text-xs mt-1">Check heartbeat freshness and trust score drift.</p>
          </Link>
        </div>
      </section>
    </div>
  );
}
