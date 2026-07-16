'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock,
  MessageSquare,
  PlayCircle,
  RefreshCw,
  Rocket,
  Shield,
  ShieldAlert,
  Siren,
  Timer,
  Users2,
  Wifi,
  WifiOff,
  Workflow,
  Zap,
} from 'lucide-react';
import StatCard from '@/components/StatCard';
import RiskBadge from '@/components/RiskBadge';
import ClientDate from '@/components/ClientDate';
import { useWebSocket } from '@/hooks/useWebSocket';
import {
  getChannelGatewayStats,
  getControlCenterSummary,
  getExecStats,
  getPendingCommands,
  getRecentRuns,
  getSchedules,
  getSwarmJobs,
  listExternalAgents,
} from '@/lib/api';

type Shortcut = {
  href: string;
  label: string;
  sub: string;
  icon: React.ElementType;
};

const shortcuts: Shortcut[] = [
  { href: '/channel-gateway', label: 'Commands', sub: 'Review approvals and channel timelines.', icon: MessageSquare },
  { href: '/swarm', label: 'Swarms', sub: 'Launch investigations and watch live tasks.', icon: Users2 },
  { href: '/external-agents', label: 'Remote Agents', sub: 'Heartbeat, trust, dispatch, kill switch.', icon: Activity },
  { href: '/exec-channels', label: 'Execution Gates', sub: 'Ring-policy and production approvals.', icon: ShieldAlert },
  { href: '/releaseclaw', label: 'Release Gates', sub: 'Preflight deployments and generate evidence.', icon: Rocket },
];

function toneForQueue(value: number) {
  if (value >= 5) return 'red';
  if (value > 0) return 'yellow';
  return 'green';
}

function MiniMetric({ label, value, tone = 'gray' }: { label: string; value: string | number; tone?: 'green' | 'yellow' | 'red' | 'cyan' | 'gray' }) {
  const color =
    tone === 'green' ? '#4ade80'
      : tone === 'yellow' ? '#facc15'
        : tone === 'red' ? '#f87171'
          : tone === 'cyan' ? '#22d3ee'
            : 'var(--rc-text-1)';
  return (
    <div className="rounded-xl border px-4 py-3" style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' }}>
      <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{label}</p>
      <p className="text-2xl font-bold mt-1" style={{ color }}>{value}</p>
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
  const refreshing = useRef(false);
  const { connected, status: wsStatus, reconnect } = useWebSocket();

  const load = useCallback(async () => {
    if (refreshing.current) return;
    refreshing.current = true;
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
      setSummary(summaryData || null);
      setPendingCount((pending as any)?.count ?? 0);
      setSwarmJobs(Array.isArray(swarms) ? swarms : []);
      setAgents(Array.isArray(remoteAgents) ? remoteAgents : []);
      setRuns(Array.isArray(recentRuns) ? recentRuns : []);
      setScheduleCount(Array.isArray(schedules) ? schedules.length : 0);
      setExecStats(exec || null);
      setChannelStats(gateway || null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load control center');
    } finally {
      refreshing.current = false;
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

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
  const recentFailures = useMemo(
    () => runs.filter((r) => ['failed', 'error', 'blocked'].includes((r?.status || '').toLowerCase())).slice(0, 6),
    [runs],
  );

  const pendingCommands = summary?.pending_commands ?? pendingCount;
  const runningSwarmsEff = summary?.running_swarms ?? runningSwarms.length;
  const blockedSwarmsEff = summary?.blocked_swarms ?? blockedSwarms.length;
  const remoteOnlineEff = summary?.remote_agents_online ?? remoteOnline;
  const remoteTotalEff = summary?.remote_agents_total ?? agents.length;
  const pendingExec = summary?.execution_pending_approval ?? Number(execStats?.pending_approval || 0);
  const blockedExec = summary?.execution_blocked_24h ?? 0;
  const channelMessages = summary?.channel_messages_24h ?? channelStats?.total_messages ?? 0;
  const channelBlocked = summary?.channel_blocked_24h ?? channelStats?.blocked ?? 0;
  const channelReplies = summary?.channel_replies_sent_24h ?? 0;
  const channelRepliesPending = summary?.channel_replies_pending_24h ?? 0;
  const schedulesActive = summary?.schedules_active ?? 0;
  const schedulesTotal = summary?.schedules_total ?? scheduleCount;
  const blockedActions = summary?.blocked_actions_24h ?? 0;
  const pressureScore = pendingCommands + pendingExec + blockedSwarmsEff + channelBlocked + blockedExec;
  const pressureColor = pressureScore >= 8 ? '#b91c1c' : pressureScore > 0 ? '#a16207' : '#15803d';

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64" style={{ color: 'var(--rc-text-2)' }}>
        Loading Enkstein Control Center…
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
            <Shield className="w-7 h-7 text-cyan-400" />
            Enkstein Control Center
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
            Command, channel, swarm, remote-agent, and execution control plane.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div
            className="flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium border"
            style={{
              background: connected ? 'rgba(34,197,94,0.1)' : wsStatus === 'failed' ? 'rgba(113,113,122,0.1)' : 'rgba(239,68,68,0.1)',
              borderColor: connected ? 'rgba(34,197,94,0.3)' : wsStatus === 'failed' ? 'rgba(113,113,122,0.3)' : 'rgba(239,68,68,0.3)',
              color: connected ? '#4ade80' : wsStatus === 'failed' ? '#a1a1aa' : '#f87171',
            }}
          >
            {connected
              ? <><Wifi className="w-3 h-3" /> Live</>
              : wsStatus === 'failed'
                ? <><WifiOff className="w-3 h-3" /> Disconnected</>
                : <><WifiOff className="w-3 h-3" /> Reconnecting…</>}
          </div>
          {wsStatus === 'failed' && (
            <button onClick={reconnect} className="text-xs px-2 py-1 rounded-lg border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500">
              Retry
            </button>
          )}
          <button
            onClick={load}
            className="flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors"
            style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}
          >
            <RefreshCw className={`w-4 h-4 ${refreshing.current ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-xl border border-red-800 bg-red-950/20 p-4 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      <div className="rounded-xl border p-6 flex items-center justify-between bg-gradient-to-r from-regent-900/80 to-gray-900 border-regent-700/50">
        <div>
          <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>Operator Pressure</p>
          <p className="text-5xl font-bold mt-1" style={{ color: pressureColor }}>{pressureScore}</p>
          <p className="text-xs mt-2" style={{ color: 'var(--rc-text-3)' }}>
            Pending approvals, blocked swarms, blocked channel messages, and execution gates.
          </p>
          <div className="mt-3 flex items-center gap-4 text-xs" style={{ color: 'var(--rc-text-2)' }}>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-green-500" /> Clear</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-yellow-500" /> Needs review</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500" /> Saturated</span>
          </div>
        </div>
        <Siren className="w-20 h-20 opacity-20" style={{ color: 'var(--regent-500)' }} />
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Pending Commands" value={pendingCommands} icon={Clock} color={toneForQueue(pendingCommands)} sub="Awaiting human decision" />
        <StatCard label="Running Swarms" value={runningSwarmsEff} icon={Users2} color={runningSwarmsEff > 0 ? 'indigo' : 'green'} sub={`${blockedSwarmsEff} blocked or failed`} />
        <StatCard label="Remote Agents" value={`${remoteOnlineEff}/${remoteTotalEff}`} icon={Activity} color={remoteOnlineEff > 0 ? 'green' : 'red'} sub="Online / enrolled" />
        <StatCard label="Execution Gates" value={pendingExec} icon={Workflow} color={toneForQueue(pendingExec)} sub={`${blockedExec} blocked in 24h`} />
        <StatCard label="Channel Messages" value={channelMessages} icon={MessageSquare} color="indigo" sub={`${channelReplies} replies sent`} />
        <StatCard label="Blocked (24h)" value={blockedActions} icon={Ban} color={blockedActions > 0 ? 'red' : 'green'} sub={`${channelBlocked} channel blocks`} />
        <StatCard label="Schedules" value={schedulesActive} icon={Timer} color="green" sub={`${schedulesTotal} configured`} />
        <StatCard label="Reply Gaps" value={channelRepliesPending} icon={AlertTriangle} color={channelRepliesPending > 0 ? 'yellow' : 'green'} sub="Needs channel config" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <section className="xl:col-span-2 rounded-xl border overflow-hidden" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--rc-border)' }}>
            <h2 className="font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
              <Zap className="w-4 h-4 text-yellow-400" />
              Immediate Operator Queue
            </h2>
            <Link href="/channel-gateway" className="text-xs text-cyan-400 hover:text-cyan-300">Open Commands</Link>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 p-5">
            <MiniMetric label="Command approvals" value={pendingCommands} tone={pendingCommands > 0 ? 'yellow' : 'green'} />
            <MiniMetric label="Channel blocked" value={channelBlocked} tone={channelBlocked > 0 ? 'red' : 'green'} />
            <MiniMetric label="Exec approvals" value={pendingExec} tone={pendingExec > 0 ? 'yellow' : 'green'} />
            <MiniMetric label="Platform blocked" value={blockedActions} tone={blockedActions > 0 ? 'red' : 'green'} />
          </div>
        </section>

        <section className="rounded-xl border overflow-hidden" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--rc-border)' }}>
            <h2 className="font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
              <MessageSquare className="w-4 h-4 text-cyan-400" />
              Channel Ingress
            </h2>
          </div>
          <div className="p-5 space-y-3 text-sm">
            {[
              ['Messages (24h)', channelMessages, 'var(--rc-text-1)'],
              ['Allowed', channelStats?.allowed ?? 0, '#4ade80'],
              ['Blocked', channelStats?.blocked ?? 0, '#f87171'],
              ['Pending', channelStats?.pending_approval ?? 0, '#facc15'],
              ['Replies sent', channelReplies, '#22d3ee'],
              ['Replies pending config', channelRepliesPending, '#facc15'],
            ].map(([label, value, color]) => (
              <div key={String(label)} className="flex justify-between gap-3">
                <span style={{ color: 'var(--rc-text-2)' }}>{label}</span>
                <span className="font-semibold" style={{ color: String(color) }}>{String(value)}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="rounded-xl border overflow-hidden" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--rc-border)' }}>
          <h2 className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Control Plane Shortcuts</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-0 divide-y md:divide-y-0 md:divide-x" style={{ borderColor: 'var(--rc-border)' }}>
          {shortcuts.map((item) => {
            const Icon = item.icon;
            return (
              <Link key={item.href} href={item.href} className="p-5 transition-colors hover:opacity-80">
                <div className="flex items-center gap-2 text-sm font-semibold text-cyan-400">
                  <Icon className="w-4 h-4" />
                  {item.label}
                </div>
                <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>{item.sub}</p>
              </Link>
            );
          })}
        </div>
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <section className="xl:col-span-2 rounded-xl border overflow-hidden" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--rc-border)' }}>
            <h2 className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Recent Failed / Blocked Runs</h2>
            <Link href="/runs" className="text-xs text-cyan-400 hover:text-cyan-300">Open Run History</Link>
          </div>
          {recentFailures.length === 0 ? (
            <div className="p-6 text-sm flex items-center gap-2" style={{ color: 'var(--rc-text-2)' }}>
              <CheckCircle2 className="w-4 h-4 text-green-400" />
              No recent failed or blocked runs.
            </div>
          ) : (
            <div>
              {recentFailures.map((r: any, i: number) => (
                <div key={r.id} className="px-6 py-3 flex items-center gap-4" style={{ borderTop: i === 0 ? 'none' : '1px solid var(--rc-border)' }}>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm truncate" style={{ color: 'var(--rc-text-1)' }}>{r.run_id || r.id}</p>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
                      {r.started_at ? <ClientDate value={r.started_at} /> : 'No start time'}
                    </p>
                  </div>
                  <RiskBadge value={r.status || 'failed'} />
                  <span className="text-xs" style={{ color: 'var(--rc-text-2)' }}>{r.triggered_by || 'system'}</span>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="rounded-xl border overflow-hidden" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--rc-border)' }}>
            <h2 className="font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
              <PlayCircle className="w-4 h-4 text-cyan-400" />
              Next Actions
            </h2>
          </div>
          <div className="p-5 space-y-4">
            <Link href="/channel-gateway" className="block">
              <p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>Clear pending approvals</p>
              <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>Prioritize command approvals before queue saturation.</p>
            </Link>
            <Link href="/swarm" className="block">
              <p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>Review blocked swarms</p>
              <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>Inspect failed runs and retry with corrected scope.</p>
            </Link>
            <Link href="/external-agents" className="block">
              <p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>Validate remote trust posture</p>
              <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>Check heartbeat freshness and trust score drift.</p>
            </Link>
          </div>
        </section>
      </div>
    </div>
  );
}
