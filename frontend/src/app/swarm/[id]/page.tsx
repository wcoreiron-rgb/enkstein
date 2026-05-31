'use client';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, ChevronLeft, Clock, RefreshCw, ShieldAlert, StopCircle, XCircle, Sparkles, Ban, RotateCcw, AlertTriangle, Activity, Copy } from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import { approveSwarmJob, cancelSwarmJob, getSwarmJob, getSwarmTasks, triggerRemediationAction, type SwarmTask } from '@/lib/api';

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

function executionMeta(outputJson?: string | null): { mode: string; fallbackReason?: string } {
  if (!outputJson) return { mode: 'unknown' };
  try {
    const parsed = JSON.parse(outputJson);
    return {
      mode: parsed?.execution_mode || 'unknown',
      fallbackReason: parsed?.fallback_reason,
    };
  } catch {
    return { mode: 'unknown' };
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

function eventIconMeta(type: string): { icon: any; cls: string } {
  if (type === 'job_completed' || type === 'task_completed') return { icon: CheckCircle2, cls: 'text-green-300' };
  if (type === 'error') return { icon: AlertTriangle, cls: 'text-red-300' };
  if (type === 'task_status_changed') return { icon: ShieldAlert, cls: 'text-yellow-300' };
  if (type === 'task_started') return { icon: Activity, cls: 'text-blue-300' };
  return { icon: Clock, cls: 'text-cyan-300' };
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

function parseParticipants(value?: string): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function collectComplianceRollup(summary: any, tasks: any[]): Array<{ key: string; count: number }> {
  const counts = new Map<string, number>();
  const add = (v?: string) => {
    if (!v) return;
    const key = String(v).trim();
    if (!key) return;
    counts.set(key, (counts.get(key) || 0) + 1);
  };

  const summaryImpact = Array.isArray(summary?.compliance_impact) ? summary.compliance_impact : [];
  for (const item of summaryImpact) {
    if (typeof item === 'string') add(item);
    if (item && typeof item === 'object') {
      add(item.control);
      add(item.framework);
      add(item.mapping);
      add(item.reference);
    }
  }

  for (const task of tasks) {
    try {
      const parsed = task?.output_json ? JSON.parse(task.output_json) : null;
      const mappings = Array.isArray(parsed?.compliance_mappings) ? parsed.compliance_mappings : [];
      for (const m of mappings) {
        if (typeof m === 'string') add(m);
        if (m && typeof m === 'object') {
          add(m.control);
          add(m.framework);
          add(m.mapping);
          add(m.reference);
        }
      }
    } catch {
      // ignore malformed task output payloads
    }
  }

  return Array.from(counts.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);
}

function buildTicketDraft(job: any, summary: any, tasks: any[]): string {
  const participants = parseParticipants(job?.participants_json);
  const topFindings = Array.isArray(summary?.top_findings) ? summary.top_findings : [];
  const recs = Array.isArray(summary?.recommended_actions) ? summary.recommended_actions : [];
  const compliance = collectComplianceRollup(summary, tasks);
  const now = new Date().toISOString();
  const findingLines = topFindings.slice(0, 5).map((f: any, i: number) => {
    if (typeof f === 'string') return `${i + 1}. ${f}`;
    return `${i + 1}. ${f?.title || f?.detail || 'finding'}`;
  });
  const actionLines = recs.slice(0, 6).map((r: any, i: number) => {
    if (typeof r === 'string') return `${i + 1}. ${r}`;
    return `${i + 1}. ${r?.action || r?.title || JSON.stringify(r)}`;
  });
  const complianceLines = compliance.slice(0, 8).map((c, i) => `${i + 1}. ${c.key} (${c.count})`);

  return [
    `Title: [RegentClaw] Suspicious Identity Investigation - ${job?.name || 'Swarm Job'}`,
    `Generated: ${now}`,
    `Job ID: ${job?.id || ''}`,
    `Profile: ${job?.profile || ''}`,
    `Status: ${job?.status || ''}`,
    `Severity: ${job?.overall_severity || 'info'}`,
    `Confidence: ${job?.confidence ?? 'n/a'}`,
    `Participants: ${participants.length ? participants.join(', ') : 'n/a'}`,
    '',
    'Executive Summary:',
    `${summary?.executive_summary || 'No summary available.'}`,
    '',
    `Root Cause: ${summary?.root_cause || 'n/a'}`,
    `Blast Radius: ${summary?.blast_radius || 'n/a'}`,
    '',
    'Top Findings:',
    ...(findingLines.length ? findingLines : ['1. n/a']),
    '',
    'Recommended Actions:',
    ...(actionLines.length ? actionLines : ['1. n/a']),
    '',
    'Compliance Impact Rollup:',
    ...(complianceLines.length ? complianceLines : ['1. none reported']),
    '',
    'Next Steps:',
    ...(Array.isArray(summary?.next_steps) && summary.next_steps.length
      ? summary.next_steps.map((s: string, i: number) => `${i + 1}. ${s}`)
      : ['1. Validate findings and action plan with incident owner.']),
  ].join('\n');
}

export default function SwarmJobDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [job, setJob] = useState<any>(null);
  const [tasks, setTasks] = useState<SwarmTask[]>([]);
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
  const [streamErrorCount, setStreamErrorCount] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<string | null>(null);
  const [eventSearch, setEventSearch] = useState('');
  const [eventSort, setEventSort] = useState<'newest' | 'oldest'>('newest');
  const [ticketCopied, setTicketCopied] = useState(false);
  const [complianceCopied, setComplianceCopied] = useState(false);
  const [ticketProjectKey, setTicketProjectKey] = useState('SEC');
  const [creatingTicket, setCreatingTicket] = useState(false);
  const [ticketHandoffMsg, setTicketHandoffMsg] = useState<string | null>(null);
  const lastIngestedEventRef = useRef<{ type: string; data: any } | null>(null);
  const [newEventCutoffMs, setNewEventCutoffMs] = useState<number>(Date.now());

  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      const saved = localStorage.getItem('rc_swarm_stream_prefs');
      if (!saved) return;
      const parsed = JSON.parse(saved);
      if (parsed?.eventFilter) setEventFilter(parsed.eventFilter);
      if (parsed?.taskFilter) setTaskFilter(parsed.taskFilter);
      if (parsed?.eventSort) setEventSort(parsed.eventSort);
      if (typeof parsed?.eventsPaused === 'boolean') setEventsPaused(parsed.eventsPaused);
    } catch {
      // ignore persisted state parse errors
    }
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    localStorage.setItem(
      'rc_swarm_stream_prefs',
      JSON.stringify({ eventFilter, taskFilter, eventSort, eventsPaused })
    );
  }, [eventFilter, taskFilter, eventSort, eventsPaused]);

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
              setLastEventAt(nextEvt.ts);
              if (eventsPaused) {
                setUnreadWhilePaused(v => v + 1);
              } else {
                setNewEventCutoffMs(Date.now());
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
        setStreamErrorCount(v => v + 1);
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
  const filteredEvents = events.filter((evt) => {
    if (eventFilter === 'all') return true;
    if (eventFilter === 'job') return evt.type.startsWith('job_');
    if (eventFilter === 'task') return evt.type.startsWith('task_');
    if (eventFilter === 'errors') return evt.type === 'error' || evt.type === 'task_status_changed';
    return true;
  });
  const visibleEvents = filteredEvents
    .filter((evt) => {
      if (!eventSearch.trim()) return true;
      const q = eventSearch.toLowerCase();
      const txt = eventText(evt.type, evt.data).toLowerCase();
      return txt.includes(q) || evt.type.toLowerCase().includes(q);
    })
    .sort((a, b) => (eventSort === 'newest'
      ? new Date(b.ts).getTime() - new Date(a.ts).getTime()
      : new Date(a.ts).getTime() - new Date(b.ts).getTime()));
  const eventCounts = {
    all: events.length,
    job: events.filter((evt) => evt.type.startsWith('job_')).length,
    task: events.filter((evt) => evt.type.startsWith('task_')).length,
    errors: events.filter((evt) => evt.type === 'error' || evt.type === 'task_status_changed').length,
  };
  const newEventThresholdMs = newEventCutoffMs - 6000;
  const latestJobEvent = events.find((evt) => evt.type.startsWith('job_'));
  const visibleTasks = tasks.filter((task) => {
    if (taskFilter === 'all') return true;
    if (taskFilter === 'running') return task.status === 'running';
    if (taskFilter === 'completed') return task.status === 'completed';
    if (taskFilter === 'failed') return task.status === 'failed' || task.status === 'blocked' || task.status === 'cancelled';
    return true;
  });
  const complianceRollup = collectComplianceRollup(summary, tasks);
  const ticketDraft = buildTicketDraft(job, summary, tasks);

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
  const copyVisibleEvents = async () => {
    if (visibleEvents.length === 0) return;
    const text = visibleEvents
      .map((evt) => `[${new Date(evt.ts).toISOString()}] ${evt.type}: ${eventText(evt.type, evt.data)}`)
      .join('\n');
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // no-op
    }
  };
  const copyTicketDraft = async () => {
    try {
      await navigator.clipboard.writeText(ticketDraft);
      setTicketCopied(true);
      setTimeout(() => setTicketCopied(false), 1200);
    } catch {
      // no-op
    }
  };
  const copyComplianceRollup = async () => {
    try {
      const body = complianceRollup.map((c) => `${c.key}: ${c.count}`).join('\n');
      await navigator.clipboard.writeText(body || 'No compliance impact reported.');
      setComplianceCopied(true);
      setTimeout(() => setComplianceCopied(false), 1200);
    } catch {
      // no-op
    }
  };
  const handoffTicket = async () => {
    setCreatingTicket(true);
    setTicketHandoffMsg(null);
    try {
      const complianceSummary = complianceRollup.map((c) => ({ control: c.key, count: c.count }));
      const title = `[RegentClaw] ${job?.name || 'Swarm Incident'} (${(job?.overall_severity || 'info').toUpperCase()})`;
      const response = await triggerRemediationAction({
        triggered_by: `swarm:${id}`,
        action_spec: {
          provider: 'generic',
          action_type: 'create_jira_ticket',
          target_type: 'ticket',
          target_id: String(job?.id || id),
          target_label: job?.name || 'Swarm Investigation',
          parameters: {
            project_key: ticketProjectKey || 'SEC',
            summary: title,
            description: ticketDraft,
            priority: String(job?.overall_severity || 'medium').toUpperCase(),
            labels: ['regentclaw', 'swarm', 'incident-response'],
            compliance_impact: complianceSummary,
            metadata: {
              swarm_job_id: job?.id,
              profile: job?.profile,
              confidence: job?.confidence,
              classification: job?.classification,
            },
          },
        },
      });
      const actionId = response?.actions?.[0]?.id;
      setTicketHandoffMsg(actionId ? `Ticket action queued: ${actionId}` : 'Ticket handoff submitted.');
    } catch (e: any) {
      setTicketHandoffMsg(e?.message || 'Ticket handoff failed.');
    } finally {
      setCreatingTicket(false);
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
          {summary?.root_cause && (
            <p className="text-xs text-gray-400 mt-3"><span className="text-gray-500">root cause:</span> {summary.root_cause}</p>
          )}
          {summary?.blast_radius && (
            <p className="text-xs text-gray-400 mt-1"><span className="text-gray-500">blast radius:</span> {summary.blast_radius}</p>
          )}
          {!!summary?.next_steps?.length && (
            <div className="mt-3">
              <p className="text-xs text-gray-500 mb-1">next steps</p>
              <ul className="list-disc list-inside text-xs text-gray-300 space-y-0.5">
                {summary.next_steps.map((s: string, i: number) => (
                  <li key={`${s}-${i}`}>{s}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-start justify-between gap-2">
            <div>
              <h2 className="text-white font-semibold">Ticket Draft</h2>
              <p className="text-xs text-gray-500 mt-1">Live draft from current swarm judgment and task evidence.</p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={copyTicketDraft}
                className="text-xs px-2 py-1 rounded border border-gray-700 text-gray-300 hover:text-white inline-flex items-center gap-1"
              >
                <Copy className="w-3 h-3" /> {ticketCopied ? 'copied' : 'copy'}
              </button>
              <button
                onClick={handoffTicket}
                disabled={creatingTicket}
                className="text-xs px-2 py-1 rounded border border-cyan-700 text-cyan-300 hover:bg-cyan-900/30 disabled:opacity-60"
              >
                {creatingTicket ? 'Creating...' : 'Create Ticket'}
              </button>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <label className="text-xs text-gray-500">Project</label>
            <input
              value={ticketProjectKey}
              onChange={(e) => setTicketProjectKey(e.target.value)}
              className="w-20 px-2 py-1 rounded border border-gray-700 bg-gray-950 text-xs text-gray-200"
            />
            {ticketHandoffMsg && <span className="text-xs text-cyan-300">{ticketHandoffMsg}</span>}
          </div>
          <pre className="mt-3 text-xs text-gray-300 bg-gray-950 border border-gray-800 rounded-lg p-3 whitespace-pre-wrap max-h-72 overflow-auto">{ticketDraft}</pre>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-start justify-between gap-2">
            <div>
              <h2 className="text-white font-semibold">Compliance Impact Rollup</h2>
              <p className="text-xs text-gray-500 mt-1">Aggregated from judge summary and task-level compliance mappings.</p>
            </div>
            <button
              onClick={copyComplianceRollup}
              className="text-xs px-2 py-1 rounded border border-gray-700 text-gray-300 hover:text-white inline-flex items-center gap-1"
            >
              <Copy className="w-3 h-3" /> {complianceCopied ? 'copied' : 'copy'}
            </button>
          </div>
          {complianceRollup.length === 0 ? (
            <p className="text-sm text-gray-500 mt-4">No compliance impact reported yet.</p>
          ) : (
            <div className="mt-3 space-y-2 max-h-72 overflow-auto pr-1">
              {complianceRollup.map((item) => (
                <div key={item.key} className="flex items-center justify-between text-xs border border-gray-800 bg-gray-950 rounded px-2 py-1.5">
                  <span className="text-gray-300 truncate mr-2">{item.key}</span>
                  <span className="text-cyan-300">{item.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <div className="sticky top-0 z-10 -mx-5 px-5 py-2 bg-gray-900/95 backdrop-blur supports-[backdrop-filter]:bg-gray-900/80 border-b border-gray-800">
          <div className="flex items-center justify-between">
            <h2 className="text-white font-semibold">Live Stream</h2>
            <div className="flex items-center gap-2">
              <span className={`text-xs px-2 py-0.5 rounded ${streaming ? 'bg-green-900/30 text-green-400' : 'bg-gray-800 text-gray-400'}`}>
                {streaming ? 'connected' : 'idle'}
              </span>
              {lastEventAt && (
                <span className="text-xs px-2 py-0.5 rounded border border-gray-700 text-gray-400">
                  last {new Date(lastEventAt).toLocaleTimeString()}
                </span>
              )}
              {streamErrorCount > 0 && (
                <span className="text-xs px-2 py-0.5 rounded border border-yellow-800 bg-yellow-900/20 text-yellow-300">
                  reconnects {streamErrorCount}
                </span>
              )}
              {eventCounts.errors > 0 && (
                <span className="text-xs px-2 py-0.5 rounded bg-red-900/30 text-red-300 border border-red-800">
                  errors {eventCounts.errors}
                </span>
              )}
              <button
                onClick={() => setEventFilter('errors')}
                className="text-xs px-2 py-0.5 rounded border border-red-800 text-red-300 hover:bg-red-900/20"
              >
                errors only
              </button>
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
                onClick={copyVisibleEvents}
                className="text-xs px-2 py-0.5 rounded border border-gray-700 text-gray-400 hover:text-white"
              >
                copy visible
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
          <div className="mt-2 flex items-center gap-2">
            <input
              value={eventSearch}
              onChange={(e) => setEventSearch(e.target.value)}
              placeholder="Search stream events"
              className="w-full max-w-xs px-2 py-1 rounded border border-gray-700 bg-gray-950 text-xs text-gray-200 placeholder:text-gray-500 focus:outline-none focus:ring-1 focus:ring-cyan-700"
            />
            <button
              onClick={() => setEventSort((s) => (s === 'newest' ? 'oldest' : 'newest'))}
              className="text-xs px-2 py-1 rounded border border-gray-700 text-gray-300 hover:text-white"
            >
              {eventSort === 'newest' ? 'newest first' : 'oldest first'}
            </button>
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
              <div
                key={`${evt.type}-${idx}`}
                className={`rounded-lg border px-3 py-2 ${
                  new Date(evt.ts).getTime() >= newEventThresholdMs
                    ? 'border-cyan-800/70 bg-cyan-950/20'
                    : 'border-gray-800 bg-gray-950'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-start gap-2 min-w-0">
                    {(() => {
                      const meta = eventIconMeta(evt.type);
                      const EIcon = meta.icon;
                      return <EIcon className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${meta.cls}`} />;
                    })()}
                    <p className={`text-xs font-medium ${eventTone(evt.type)}`}>{eventText(evt.type, evt.data)}</p>
                  </div>
                  <button
                    onClick={() => copyEvent(evt, idx)}
                    className="text-[11px] px-1.5 py-0.5 rounded border border-gray-700 text-gray-400 hover:text-white"
                  >
                    {copiedEventIdx === idx ? 'copied' : 'copy'}
                  </button>
                </div>
                <p className="text-[11px] text-gray-500 mt-0.5">
                  <span className="inline-block px-1 py-0 rounded border border-gray-700 text-gray-400 mr-1">{evt.type}</span>
                  {new Date(evt.ts).toLocaleTimeString()}
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
                  <th className="px-5 py-3 text-left">Execution</th>
                  <th className="px-5 py-3 text-left">Exec Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {visibleTasks.map((task) => {
                  const tMeta = statusMeta(task.status);
                  const TIcon = tMeta.icon;
                  const secureState = secureChannelMeta(task.output_json);
                  const exec = executionMeta(task.output_json);
                  const simulated = exec.mode === 'simulated_fallback';
                  return (
                    <tr key={task.id} className="hover:bg-gray-800/40">
                      <td className="px-5 py-3 text-white">{task.claw}</td>
                      <td className="px-5 py-3 text-gray-400">{task.task_type}</td>
                      <td className="px-5 py-3"><span className={`inline-flex items-center gap-1 ${tMeta.color}`}><TIcon className="w-4 h-4" /> {task.status}</span></td>
                      <td className="px-5 py-3"><RiskBadge value={task.severity || 'info'} /></td>
                      <td className="px-5 py-3 text-gray-300">{task.confidence ?? '—'}</td>
                      <td className="px-5 py-3 text-gray-300">{task.risk_score ?? '—'}</td>
                      <td className="px-5 py-3 text-gray-300">{secureState}</td>
                      <td className="px-5 py-3">
                        <div className="flex flex-col gap-0.5">
                          <span className={`text-xs inline-flex w-fit px-1.5 py-0.5 rounded border ${
                            simulated
                              ? 'bg-yellow-900/30 text-yellow-300 border-yellow-800'
                              : 'bg-cyan-900/30 text-cyan-300 border-cyan-800'
                          }`}>
                            {simulated ? 'simulated fallback' : 'real handler'}
                          </span>
                          {simulated && exec.fallbackReason && (
                            <span className="text-[11px] text-gray-500 max-w-[260px] truncate" title={exec.fallbackReason}>
                              {exec.fallbackReason}
                            </span>
                          )}
                        </div>
                      </td>
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
