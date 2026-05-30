'use client';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, ChevronLeft, Clock, RefreshCw, ShieldAlert, StopCircle, XCircle, Sparkles, Ban, RotateCcw } from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import { approveSwarmJob, cancelSwarmJob, getSwarmJob, getSwarmTasks } from '@/lib/api';

function statusMeta(status: string) {
  const s = (status || '').toLowerCase();
  if (s === 'completed') return { icon: CheckCircle2, color: 'text-green-400' };
  if (s === 'running') return { icon: RefreshCw, color: 'text-blue-400' };
  if (s === 'failed' || s === 'blocked') return { icon: XCircle, color: 'text-red-400' };
  if (s === 'requires_approval') return { icon: ShieldAlert, color: 'text-yellow-400' };
  return { icon: Clock, color: 'text-gray-400' };
}

function secureChannelMeta(outputJson?: string | null): string {
  if (!outputJson) return '—';
  try {
    const parsed = JSON.parse(outputJson);
    const channel = parsed?.secure_channel;
    if (!channel || channel.enabled !== true) return 'disabled';
    return channel.status || 'enabled';
  } catch {
    return '—';
  }
}

function judgeModelMeta(summary: any): { label: string; detail?: string; blocked?: boolean } {
  const jm = summary?.judge_model;
  if (!jm) return { label: 'deterministic fallback' };
  if (jm.blocked) return { label: 'blocked by policy', detail: jm.reason || jm.policy_name || 'ModelClaw denied', blocked: true };
  if (jm.provider || jm.profile) {
    return {
      label: `${jm.provider || 'model'} / ${jm.profile || 'profile'}`,
      detail: jm.model || '',
    };
  }
  if (jm.error) return { label: 'error fallback', detail: jm.error, blocked: true };
  return { label: 'deterministic fallback' };
}

function judgeBadgeMeta(judgeMeta: { blocked?: boolean; label: string }) {
  if (judgeMeta.blocked) {
    return { icon: Ban, cls: 'bg-yellow-900/30 text-yellow-300 border-yellow-800' };
  }
  if (judgeMeta.label.includes('fallback') || judgeMeta.label.includes('deterministic')) {
    return { icon: RotateCcw, cls: 'bg-gray-800 text-gray-300 border-gray-700' };
  }
  return { icon: Sparkles, cls: 'bg-cyan-900/30 text-cyan-300 border-cyan-800' };
}

function eventText(type: string, data: any): string {
  const claw = data?.claw ? ` ${data.claw}` : '';
  if (type === 'job_started') return `Swarm job started.`;
  if (type === 'job_completed') return `Swarm job completed with status ${data?.status || 'unknown'}.`;
  if (type === 'task_started') return `Task started for${claw}.`;
  if (type === 'task_completed') {
    const sev = data?.severity ? ` (${data.severity})` : '';
    const risk = data?.risk_score != null ? ` risk ${data.risk_score}` : '';
    return `Task completed for${claw}${sev}${risk ? ` ·${risk}` : ''}.`;
  }
  if (type === 'task_status_changed') return `Task status changed for${claw}: ${data?.status || 'unknown'}.`;
  if (type === 'job_snapshot') return `Snapshot: ${data?.status || 'unknown'} · ${data?.task_count ?? 0} tasks.`;
  if (type === 'stream_timeout') return `Stream timed out after ${data?.timeout_seconds || '?'}s.`;
  if (type === 'error') return data?.message || 'Stream error.';
  return `${type}`;
}

function eventTone(type: string): string {
  if (type === 'job_completed' || type === 'task_completed') return 'text-green-300';
  if (type === 'error') return 'text-red-300';
  if (type === 'task_status_changed') return 'text-yellow-300';
  return 'text-cyan-300';
}

function isDuplicateEvent(
  prev: { type: string; data: any } | undefined,
  next: { type: string; data: any }
): boolean {
  if (!prev) return false;
  if (prev.type !== next.type) return false;
  if (next.type === 'job_snapshot') {
    return prev.data?.status === next.data?.status && prev.data?.task_count === next.data?.task_count;
  }
  if (next.type === 'task_status_changed') {
    return prev.data?.claw === next.data?.claw && prev.data?.status === next.data?.status;
  }
  return false;
}

export default function SwarmJobDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [job, setJob] = useState<any>(null);
  const [tasks, setTasks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<Array<{ type: string; data: any; ts: string }>>([]);
  const [streaming, setStreaming] = useState(false);
  const [eventFilter, setEventFilter] = useState<'all' | 'job' | 'task' | 'errors'>('all');
  const [taskFilter, setTaskFilter] = useState<'all' | 'running' | 'completed' | 'failed'>('all');
  const [copiedEventIdx, setCopiedEventIdx] = useState<number | null>(null);
  const [eventsPaused, setEventsPaused] = useState(false);
  const [unreadWhilePaused, setUnreadWhilePaused] = useState(0);
  const lastIngestedEventRef = useRef<{ type: string; data: any } | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const [j, t] = await Promise.all([getSwarmJob(id), getSwarmTasks(id)]);
      setJob(j);
      setTasks(t);
    } catch (e: any) {
      setError(e?.message || 'Failed to load swarm job');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!id) return;
    const terminal = ['completed', 'failed', 'cancelled', 'blocked', 'requires_approval'].includes((job?.status || '').toLowerCase());
    if (terminal) return;

    const controller = new AbortController();
    const token = typeof window !== 'undefined' ? localStorage.getItem('rc_token') : null;

    (async () => {
      try {
        setStreaming(true);
        const res = await fetch(`/api/v1/swarm/jobs/${id}/stream?timeout_seconds=20&poll_interval_ms=400`, {
          signal: controller.signal,
          headers: {
            Accept: 'text/event-stream',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
        });
        if (!res.body) return;

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let currentEvent = 'message';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const chunks = buffer.split('\n');
          buffer = chunks.pop() || '';

          for (const raw of chunks) {
            const line = raw.trim();
            if (!line) continue;
            if (line.startsWith('event:')) {
              currentEvent = line.replace('event:', '').trim();
              continue;
            }
            if (line.startsWith('data:')) {
              const payloadText = line.replace('data:', '').trim();
              let payload: any = payloadText;
              try { payload = JSON.parse(payloadText); } catch {}
              const nextEvt = { type: currentEvent, data: payload, ts: new Date().toISOString() };
              if (isDuplicateEvent(lastIngestedEventRef.current || undefined, nextEvt)) continue;
              lastIngestedEventRef.current = { type: nextEvt.type, data: nextEvt.data };
              if (eventsPaused) {
                setUnreadWhilePaused(v => v + 1);
              } else {
                setEvents(prev => [nextEvt, ...prev].slice(0, 50));
              }
              if (['task_started', 'task_completed', 'job_completed', 'job_snapshot'].includes(currentEvent)) {
                load();
              }
            }
          }
        }
      } catch {
        // stream interruptions are non-fatal; UI still supports manual refresh.
      } finally {
        setStreaming(false);
      }
    })();

    return () => controller.abort();
  }, [id, job?.status, load, eventsPaused]);

  const cancelJob = async () => {
    if (!id) return;
    setBusy(true);
    try { await cancelSwarmJob(id); await load(); } finally { setBusy(false); }
  };

  const approveJob = async () => {
    if (!id) return;
    setBusy(true);
    try { await approveSwarmJob(id); await load(); } finally { setBusy(false); }
  };

  if (loading) {
    return <div className="h-64 flex items-center justify-center"><RefreshCw className="w-7 h-7 text-cyan-400 animate-spin" /></div>;
  }

  if (error || !job) {
    return (
      <div className="space-y-4">
        <Link href="/swarm" className="text-sm text-gray-400 hover:text-white inline-flex items-center gap-1"><ChevronLeft className="w-4 h-4" /> Back to Swarm</Link>
        <div className="rounded-xl border border-red-900 bg-red-950/30 p-4 text-red-300 text-sm">{error || 'Swarm job not found'}</div>
      </div>
    );
  }

  const meta = statusMeta(job.status);
  const Icon = meta.icon;
  let summary: any = null;
  try { summary = job.result_json ? JSON.parse(job.result_json) : null; } catch { summary = null; }
  const judgeMeta = judgeModelMeta(summary);
  const judgeBadge = judgeBadgeMeta(judgeMeta);
  const JudgeIcon = judgeBadge.icon;
  const totalTasks = tasks.length;
  const completedTasks = tasks.filter(t => t.status === 'completed').length;
  const failedTasks = tasks.filter(t => t.status === 'failed' || t.status === 'blocked').length;
  const runningTasks = tasks.filter(t => t.status === 'running').length;
  const progressPct = totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0;
  const visibleEvents = events.filter((evt) => {
    if (eventFilter === 'all') return true;
    if (eventFilter === 'job') return evt.type.startsWith('job_');
    if (eventFilter === 'task') return evt.type.startsWith('task_');
    if (eventFilter === 'errors') return evt.type === 'error' || evt.type === 'task_status_changed';
    return true;
  });
  const eventCounts = {
    all: events.length,
    job: events.filter((evt) => evt.type.startsWith('job_')).length,
    task: events.filter((evt) => evt.type.startsWith('task_')).length,
    errors: events.filter((evt) => evt.type === 'error' || evt.type === 'task_status_changed').length,
  };
  const latestJobEvent = events.find((evt) => evt.type.startsWith('job_'));
  const visibleTasks = tasks.filter((task) => {
    if (taskFilter === 'all') return true;
    if (taskFilter === 'running') return task.status === 'running';
    if (taskFilter === 'completed') return task.status === 'completed';
    if (taskFilter === 'failed') return task.status === 'failed' || task.status === 'blocked' || task.status === 'cancelled';
    return true;
  });

  const copyEvent = async (evt: { type: string; data: any; ts: string }, idx: number) => {
    const payload = `[${new Date(evt.ts).toISOString()}] ${evt.type}: ${eventText(evt.type, evt.data)} | ${JSON.stringify(evt.data)}`;
    try {
      await navigator.clipboard.writeText(payload);
      setCopiedEventIdx(idx);
      setTimeout(() => setCopiedEventIdx((prev) => (prev === idx ? null : prev)), 1200);
    } catch {
      // best effort; no-op if clipboard is unavailable
    }
  };

  const exportEvents = () => {
    try {
      const payload = {
        job_id: id,
        exported_at: new Date().toISOString(),
        filter: eventFilter,
        count: visibleEvents.length,
        events: visibleEvents,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = `swarm-${id}-stream-events.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(href);
    } catch {
      // no-op
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-3">
        <div>
          <Link href="/swarm" className="text-sm text-gray-400 hover:text-white inline-flex items-center gap-1"><ChevronLeft className="w-4 h-4" /> Back to Swarm</Link>
          <h1 className="text-3xl font-bold text-white mt-2">{job.name}</h1>
          <p className="text-gray-400 mt-1">{job.profile} · {job.classification}</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="px-3 py-2 rounded-lg border border-gray-700 bg-gray-900 text-gray-200 text-sm hover:bg-gray-800">
            <RefreshCw className="w-4 h-4 inline mr-1" /> Refresh
          </button>
          <button onClick={cancelJob} disabled={busy || ['completed', 'failed', 'cancelled'].includes(job.status)} className="px-3 py-2 rounded-lg border border-gray-700 text-gray-200 text-sm disabled:opacity-50">
            <StopCircle className="w-4 h-4 inline mr-1" /> Cancel
          </button>
          <button onClick={approveJob} disabled={busy || job.status !== 'requires_approval'} className="px-3 py-2 rounded-lg border border-green-700 text-green-300 text-sm disabled:opacity-50">
            <CheckCircle2 className="w-4 h-4 inline mr-1" /> Approve
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card label="Status"><span className={`inline-flex items-center gap-1 ${meta.color}`}><Icon className={`w-4 h-4 ${job.status === 'running' ? 'animate-spin' : ''}`} /> {job.status}</span></Card>
        <Card label="Severity"><RiskBadge value={job.overall_severity || 'info'} /></Card>
        <Card label="Confidence">{job.confidence ?? '—'}</Card>
        <Card label="Parallelism">{job.parallelism}</Card>
        <Card label="Tasks">{String(tasks.length)}</Card>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-white font-semibold text-sm">Task Progress</h2>
          <span className="text-xs text-gray-400">{completedTasks}/{totalTasks} completed</span>
        </div>
        <div className="h-2 w-full rounded-full bg-gray-800 overflow-hidden">
          <div
            className="h-full bg-cyan-500 transition-all duration-300"
            style={{ width: `${progressPct}%` }}
          />
        </div>
        <div className="mt-3 flex items-center gap-4 text-xs">
          <span className="text-green-300">completed: {completedTasks}</span>
          <span className="text-blue-300">running: {runningTasks}</span>
          <span className="text-red-300">failed/blocked: {failedTasks}</span>
        </div>
      </div>

      {summary?.executive_summary && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-start justify-between gap-3">
            <h2 className="text-white font-semibold">Judge Summary</h2>
            <span className={`text-xs px-2 py-0.5 rounded border inline-flex items-center gap-1 ${judgeBadge.cls}`}>
              <JudgeIcon className="w-3 h-3" /> {judgeMeta.label}
            </span>
          </div>
          {judgeMeta.detail && <p className="text-xs text-gray-500 mt-1">{judgeMeta.detail}</p>}
          <p className="text-sm text-gray-300 mt-2 leading-relaxed">{summary.executive_summary}</p>
        </div>
      )}

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <div className="sticky top-0 z-10 -mx-5 px-5 py-2 bg-gray-900/95 backdrop-blur supports-[backdrop-filter]:bg-gray-900/80 border-b border-gray-800">
          <div className="flex items-center justify-between">
            <h2 className="text-white font-semibold">Live Stream</h2>
            <div className="flex items-center gap-2">
              <span className={`text-xs px-2 py-0.5 rounded ${streaming ? 'bg-green-900/30 text-green-400' : 'bg-gray-800 text-gray-400'}`}>
                {streaming ? 'connected' : 'idle'}
              </span>
              <button
                onClick={() => {
                  setEventsPaused(v => {
                    const next = !v;
                    if (!next) setUnreadWhilePaused(0);
                    return next;
                  });
                }}
                className={`text-xs px-2 py-0.5 rounded border ${
                  eventsPaused
                    ? 'border-yellow-800 bg-yellow-900/30 text-yellow-300'
                    : 'border-gray-700 text-gray-400 hover:text-white'
                }`}
              >
                {eventsPaused ? `resume${unreadWhilePaused > 0 ? ` (${unreadWhilePaused})` : ''}` : 'pause'}
              </button>
              <button
                onClick={exportEvents}
                className="text-xs px-2 py-0.5 rounded border border-gray-700 text-gray-400 hover:text-white"
              >
                export
              </button>
              <button
                onClick={() => {
                  setEvents([]);
                  setUnreadWhilePaused(0);
                }}
                className="text-xs px-2 py-0.5 rounded border border-gray-700 text-gray-400 hover:text-white"
              >
                clear
              </button>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-1.5">
            {[
              { id: 'all', label: `All (${eventCounts.all})` },
              { id: 'job', label: `Job (${eventCounts.job})` },
              { id: 'task', label: `Task (${eventCounts.task})` },
              { id: 'errors', label: `Errors (${eventCounts.errors})` },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setEventFilter(f.id as 'all' | 'job' | 'task' | 'errors')}
                className={`text-xs px-2 py-0.5 rounded border ${
                  eventFilter === f.id
                    ? 'bg-cyan-900/30 text-cyan-300 border-cyan-800'
                    : 'bg-gray-950 text-gray-400 border-gray-800 hover:text-white'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
          {latestJobEvent && (
            <p className="mt-2 text-xs text-gray-400">
              latest: <span className="text-gray-300">{eventText(latestJobEvent.type, latestJobEvent.data)}</span>{' '}
              <span className="text-gray-500">({new Date(latestJobEvent.ts).toLocaleTimeString()})</span>
            </p>
          )}
        </div>
        {events.length === 0 ? (
          <p className="text-sm text-gray-500 mt-3">Waiting for stream events…</p>
        ) : (
          <div className="mt-3 space-y-2 max-h-44 overflow-auto pr-1">
            {visibleEvents.map((evt, idx) => (
              <div key={`${evt.type}-${idx}`} className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2">
                <div className="flex items-start justify-between gap-2">
                  <p className={`text-xs font-medium ${eventTone(evt.type)}`}>{eventText(evt.type, evt.data)}</p>
                  <button
                    onClick={() => copyEvent(evt, idx)}
                    className="text-[11px] px-1.5 py-0.5 rounded border border-gray-700 text-gray-400 hover:text-white"
                  >
                    {copiedEventIdx === idx ? 'copied' : 'copy'}
                  </button>
                </div>
                <p className="text-[11px] text-gray-500 mt-0.5">
                  {evt.type} · {new Date(evt.ts).toLocaleTimeString()}
                </p>
              </div>
            ))}
            {visibleEvents.length === 0 && (
              <p className="text-xs text-gray-500 px-1 py-2">No events for this filter yet.</p>
            )}
          </div>
        )}
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-white font-semibold">Tasks</h2>
            <div className="flex items-center gap-1.5">
              {[
                { id: 'all', label: `All (${tasks.length})` },
                { id: 'running', label: `Running (${runningTasks})` },
                { id: 'completed', label: `Completed (${completedTasks})` },
                { id: 'failed', label: `Failed (${failedTasks})` },
              ].map((f) => (
                <button
                  key={f.id}
                  onClick={() => setTaskFilter(f.id as 'all' | 'running' | 'completed' | 'failed')}
                  className={`text-xs px-2 py-0.5 rounded border ${
                    taskFilter === f.id
                      ? 'bg-cyan-900/30 text-cyan-300 border-cyan-800'
                      : 'bg-gray-950 text-gray-400 border-gray-800 hover:text-white'
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>
        </div>
        {tasks.length === 0 ? (
          <p className="px-5 py-6 text-sm text-gray-500">No tasks attached to this job.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] text-sm">
              <thead className="text-xs text-gray-500 border-b border-gray-800">
                <tr>
                  <th className="px-5 py-3 text-left">Claw</th>
                  <th className="px-5 py-3 text-left">Task Type</th>
                  <th className="px-5 py-3 text-left">Status</th>
                  <th className="px-5 py-3 text-left">Severity</th>
                  <th className="px-5 py-3 text-left">Confidence</th>
                  <th className="px-5 py-3 text-left">Risk</th>
                  <th className="px-5 py-3 text-left">Secure Channel</th>
                  <th className="px-5 py-3 text-left">Exec Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {visibleTasks.map((task) => {
                  const tMeta = statusMeta(task.status);
                  const TIcon = tMeta.icon;
                  const secureState = secureChannelMeta(task.output_json);
                  return (
                    <tr key={task.id} className="hover:bg-gray-800/40">
                      <td className="px-5 py-3 text-white">{task.claw}</td>
                      <td className="px-5 py-3 text-gray-400">{task.task_type}</td>
                      <td className="px-5 py-3"><span className={`inline-flex items-center gap-1 ${tMeta.color}`}><TIcon className="w-4 h-4" /> {task.status}</span></td>
                      <td className="px-5 py-3"><RiskBadge value={task.severity || 'info'} /></td>
                      <td className="px-5 py-3 text-gray-300">{task.confidence ?? '—'}</td>
                      <td className="px-5 py-3 text-gray-300">{task.risk_score ?? '—'}</td>
                      <td className="px-5 py-3 text-gray-300">{secureState}</td>
                      <td className="px-5 py-3 text-gray-400">{task.execution_time_ms != null ? `${task.execution_time_ms}ms` : '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {tasks.length > 0 && visibleTasks.length === 0 && (
          <p className="px-5 py-4 text-xs text-gray-500">No tasks in this filter.</p>
        )}
      </div>
    </div>
  );
}

function Card({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
      <p className="text-xs text-gray-500">{label}</p>
      <div className="text-white font-semibold mt-1">{children}</div>
    </div>
  );
}
