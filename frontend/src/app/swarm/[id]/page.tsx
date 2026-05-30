'use client';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, ChevronLeft, Clock, RefreshCw, ShieldAlert, StopCircle, XCircle } from 'lucide-react';
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

export default function SwarmJobDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [job, setJob] = useState<any>(null);
  const [tasks, setTasks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<Array<{ type: string; data: any }>>([]);
  const [streaming, setStreaming] = useState(false);

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
              setEvents(prev => [{ type: currentEvent, data: payload }, ...prev].slice(0, 40));
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
  }, [id, job?.status, load]);

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

      {summary?.executive_summary && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-start justify-between gap-3">
            <h2 className="text-white font-semibold">Judge Summary</h2>
            <span className={`text-xs px-2 py-0.5 rounded ${judgeMeta.blocked ? 'bg-yellow-900/30 text-yellow-300' : 'bg-cyan-900/30 text-cyan-300'}`}>
              {judgeMeta.label}
            </span>
          </div>
          {judgeMeta.detail && <p className="text-xs text-gray-500 mt-1">{judgeMeta.detail}</p>}
          <p className="text-sm text-gray-300 mt-2 leading-relaxed">{summary.executive_summary}</p>
        </div>
      )}

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-white font-semibold">Live Stream</h2>
          <span className={`text-xs px-2 py-0.5 rounded ${streaming ? 'bg-green-900/30 text-green-400' : 'bg-gray-800 text-gray-400'}`}>
            {streaming ? 'connected' : 'idle'}
          </span>
        </div>
        {events.length === 0 ? (
          <p className="text-sm text-gray-500 mt-3">Waiting for stream events…</p>
        ) : (
          <div className="mt-3 space-y-2 max-h-44 overflow-auto pr-1">
            {events.map((evt, idx) => (
              <div key={`${evt.type}-${idx}`} className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2">
                <p className="text-xs text-cyan-300">{evt.type}</p>
                <p className="text-xs text-gray-400 mt-0.5 break-words">{JSON.stringify(evt.data)}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800">
          <h2 className="text-white font-semibold">Tasks</h2>
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
                {tasks.map((task) => {
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
