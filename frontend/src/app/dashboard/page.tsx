'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { Shield, Users, AlertTriangle, Ban, Clock, Cpu, Plug, Wifi, WifiOff, Zap } from 'lucide-react';
import StatCard from '@/components/StatCard';
import RiskBadge from '@/components/RiskBadge';
import { getDashboard } from '@/lib/api';
import ClientDate from '@/components/ClientDate';
import { useWebSocket } from '@/hooks/useWebSocket';

// ── Live toast for real-time events ──────────────────────────────────────────
interface LiveToast {
  id: number;
  type: string;
  label: string;
  sub: string;
}

let _toastId = 0;

export default function DashboardPage() {
  const [data, setData]       = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [toasts, setToasts]   = useState<LiveToast[]>([]);
  const refreshing             = useRef(false);

  const { connected, status: wsStatus, reconnect, subscribe } = useWebSocket();

  // ── Data fetching ──────────────────────────────────────────────────────────
  const fetchData = useCallback(async () => {
    if (refreshing.current) return;
    refreshing.current = true;
    try {
      const d = await getDashboard();
      setData(d);
    } catch (e) {
      console.error(e);
    } finally {
      refreshing.current = false;
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // ── Live-update toasts helper ──────────────────────────────────────────────
  const pushToast = useCallback((type: string, label: string, sub: string) => {
    const id = ++_toastId;
    setToasts((prev) => [...prev.slice(-4), { id, type, label, sub }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5000);
  }, []);

  // ── WebSocket subscriptions ────────────────────────────────────────────────
  useEffect(() => {
    const unsubs = [
      subscribe('dashboard.refresh', () => {
        fetchData();
      }),
      subscribe('finding.created', (d: any) => {
        fetchData();
        pushToast('finding', `New ${d.severity ?? ''} finding`.trim(), d.title ?? '');
      }),
      subscribe('finding.updated', (d: any) => {
        fetchData();
        pushToast('finding', `Finding escalated (${d.severity ?? ''})`, d.title ?? '');
      }),
      subscribe('agent.run_completed', (d: any) => {
        fetchData();
        pushToast('agent', `Agent run: ${d.status ?? 'done'}`, d.agent_name ?? '');
      }),
      subscribe('workflow.completed', (d: any) => {
        fetchData();
        pushToast('workflow', `Workflow: ${d.status ?? 'done'}`, d.workflow_name ?? '');
      }),
    ];
    return () => unsubs.forEach((u) => u());
  }, [subscribe, fetchData, pushToast]);

  // ── Render ─────────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64" style={{ color: 'var(--rc-text-2)' }}>
        Loading Marcellus platform data…
      </div>
    );
  }

  if (!data) {
    return (
      <div className="text-red-400">
        Unable to connect to backend. Make sure{' '}
        <code className="px-1 rounded text-sm" style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-1)' }}>
          docker compose up
        </code>{' '}
        is running.
      </div>
    );
  }

  const score = data.platform_risk_score ?? 0;
  const scoreColor = score >= 70 ? '#b91c1c' : score >= 40 ? '#a16207' : '#15803d';

  return (
    <div className="space-y-8">
      {/* Live toasts — top-right corner */}
      <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="flex items-start gap-2 rounded-lg border px-3 py-2 shadow-lg text-sm pointer-events-auto"
            style={{
              background: 'var(--rc-bg-elevated)',
              borderColor: 'var(--rc-border)',
              color: 'var(--rc-text-1)',
              minWidth: '240px',
              maxWidth: '320px',
              animation: 'fadeIn 0.2s ease',
            }}
          >
            <Zap className="w-4 h-4 mt-0.5 shrink-0 text-indigo-400" />
            <div className="min-w-0">
              <p className="font-medium truncate">{t.label}</p>
              <p className="text-xs truncate" style={{ color: 'var(--rc-text-3)' }}>{t.sub}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div>
            <h1 className="text-3xl font-bold" style={{ color: 'var(--rc-text-1)' }}>Platform Overview</h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
              Distributed Zero Trust Security — Marcellus Cortex
            </p>
          </div>
        </div>
        {/* Live / disconnected badge */}
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
            <button
              onClick={reconnect}
              className="text-xs px-2 py-1 rounded-lg border border-zinc-700 text-zinc-400 hover:text-white hover:border-zinc-500 transition-colors"
            >
              Retry
            </button>
          )}
        </div>
      </div>

      {/* Risk Score Banner */}
      <div
        className="rounded-xl border p-6 flex items-center justify-between bg-gradient-to-r from-regent-900/80 to-gray-900 border-regent-700/50"
      >
        <div>
          <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>Platform Risk Score</p>
          <p className="text-5xl font-bold mt-1" style={{ color: scoreColor }}>
            {score.toFixed(1)}
          </p>
          <p className="text-xs mt-2" style={{ color: 'var(--rc-text-3)' }}>
            Avg across all events · Scale 0–100
          </p>
          <div className="mt-3 flex items-center gap-4 text-xs" style={{ color: 'var(--rc-text-2)' }}>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-green-500 inline-block" /> 0–39 Low
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-yellow-500 inline-block" /> 40–69 Medium
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" /> 70+ High
            </span>
          </div>
        </div>
        <Shield className="w-20 h-20 opacity-20" style={{ color: 'var(--regent-500)' }} />
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Active Modules"    value={data.active_modules}      icon={Cpu}           color="indigo" sub={`${data.total_modules} total`} />
        <StatCard label="Identities"        value={data.total_identities}    icon={Users}         color="indigo" />
        <StatCard label="High Risk Events"  value={data.high_risk_events}    icon={AlertTriangle} color="orange" />
        <StatCard label="Blocked (24h)"     value={data.blocked_actions_24h} icon={Ban}           color="red" />
        <StatCard label="Connectors"        value={data.total_connectors}    icon={Plug}          color="green"  sub={`${data.pending_connectors} pending review`} />
        <StatCard label="Pending Approvals" value={data.pending_approvals}   icon={Clock}         color="yellow" />
      </div>

      {/* Recent Events */}
      <div className="rounded-xl border overflow-hidden" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--rc-border)' }}>
          <h2 className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Recent Events</h2>
          <div className="flex items-center gap-2">
            {connected && (
              <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block animate-pulse" />
                Live feed
              </span>
            )}
          </div>
        </div>
        <div>
          {data.recent_events.length === 0 && (
            <p className="text-sm p-6" style={{ color: 'var(--rc-text-3)' }}>
              No events yet. Submit an AI Security event to get started.
            </p>
          )}
          {data.recent_events.map((e: any, i: number) => (
            <div
              key={e.id}
              className="px-6 py-3 flex items-center gap-4"
              style={{
                borderTop: i === 0 ? 'none' : `1px solid var(--rc-border)`,
              }}
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm truncate" style={{ color: 'var(--rc-text-1)' }}>
                  <span className="font-medium text-indigo-400">{e.module}</span>
                  {' · '}
                  <span style={{ color: 'var(--rc-text-2)' }}>{e.actor} → {e.action}</span>
                </p>
                <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
                  <ClientDate value={e.timestamp} />
                </p>
              </div>
              <RiskBadge value={e.outcome} />
              <RiskBadge value={e.severity} />
              <span className="text-sm font-mono w-12 text-right" style={{ color: 'var(--rc-text-2)' }}>
                {e.risk_score.toFixed(0)}
              </span>
            </div>
          ))}
        </div>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
