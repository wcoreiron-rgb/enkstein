'use client';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { Bot, CheckCircle2, Clock, Plus, RefreshCw, ShieldAlert, StopCircle, Users2, XCircle, Sparkles, Ban, RotateCcw } from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import { approveSwarmJob, cancelSwarmJob, createSuspiciousIdentitySwarm, createSwarmJob, getSwarmJobs } from '@/lib/api';

function statusMeta(status: string) {
  const s = (status || '').toLowerCase();
  if (s === 'completed') return { icon: CheckCircle2, color: 'text-green-400' };
  if (s === 'running') return { icon: RefreshCw, color: 'text-blue-400' };
  if (s === 'failed' || s === 'blocked') return { icon: XCircle, color: 'text-red-400' };
  if (s === 'requires_approval') return { icon: ShieldAlert, color: 'text-yellow-400' };
  return { icon: Clock, color: 'text-gray-400' };
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

function runtimeLabel(startedAt?: string | null, completedAt?: string | null): string {
  if (!startedAt) return '—';
  const start = new Date(startedAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return '—';
  const seconds = Math.round((end - start) / 1000);
  return `${seconds}s`;
}

function parseJudgeModel(resultJson?: string | null): { label: string; detail?: string; state: 'allowed' | 'blocked' | 'fallback' } {
  if (!resultJson) return { label: '—', state: 'fallback' };
  try {
    const parsed = JSON.parse(resultJson);
    const jm = parsed?.judge_model;
    if (!jm) return { label: 'deterministic', state: 'fallback' };
    if (jm.blocked) return { label: 'blocked', detail: jm.reason || jm.policy_name || 'policy blocked', state: 'blocked' };
    if (jm.provider || jm.profile) {
      return { label: `${jm.provider || 'model'} / ${jm.profile || 'profile'}`, detail: jm.model || '', state: 'allowed' };
    }
    if (jm.error) return { label: 'fallback', detail: jm.error, state: 'fallback' };
    return { label: 'deterministic', state: 'fallback' };
  } catch {
    return { label: '—', state: 'fallback' };
  }
}

function judgeStateMeta(state: 'allowed' | 'blocked' | 'fallback') {
  if (state === 'allowed') return { icon: Sparkles, cls: 'bg-cyan-900/30 text-cyan-300 border-cyan-800' };
  if (state === 'blocked') return { icon: Ban, cls: 'bg-yellow-900/30 text-yellow-300 border-yellow-800' };
  return { icon: RotateCcw, cls: 'bg-gray-800 text-gray-300 border-gray-700' };
}

export default function SwarmPage() {
  const [jobs, setJobs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [launchingPreset, setLaunchingPreset] = useState(false);
  const [form, setForm] = useState({
    name: 'Incident Response Swarm',
    profile: 'INCIDENT_RESPONSE',
    participants: 'identityclaw,cloudclaw,threatclaw',
    task_type: 'investigate',
    classification: 'confidential',
    parallelism: 3,
    requested_by: 'portal-user',
  });
  const [presetIdentity, setPresetIdentity] = useState('user@company.com');
  const [presetTimeRange, setPresetTimeRange] = useState('24h');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      setJobs(await getSwarmJobs());
    } catch (e: any) {
      setJobs([]);
      setError(e?.status === 404
        ? 'Swarm API is not available on the backend yet (404).'
        : (e?.message || 'Failed to load swarm jobs.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const createJob = async () => {
    setCreating(true);
    setError(null);
    try {
      const payload = {
        ...form,
        participants: form.participants.split(',').map(s => s.trim()).filter(Boolean),
        input: { source: 'ui', reason: 'manual start' },
      };
      await createSwarmJob(payload);
      setShowCreate(false);
      await load();
    } catch (e: any) {
      setError(e?.status === 404
        ? 'Swarm create endpoint is not available on this backend (404).'
        : (e?.message || 'Failed to create swarm job.'));
    } finally {
      setCreating(false);
    }
  };

  const cancelJob = async (id: string) => {
    setBusyId(id);
    setError(null);
    try { await cancelSwarmJob(id); await load(); } catch (e: any) {
      setError(e?.message || 'Failed to cancel swarm job.');
    } finally { setBusyId(null); }
  };

  const approveJob = async (id: string) => {
    setBusyId(id);
    setError(null);
    try { await approveSwarmJob(id); await load(); } catch (e: any) {
      setError(e?.message || 'Failed to approve swarm job.');
    } finally { setBusyId(null); }
  };

  const launchIdentityPreset = async () => {
    setLaunchingPreset(true);
    setError(null);
    try {
      await createSuspiciousIdentitySwarm({
        identity: presetIdentity,
        time_range: presetTimeRange,
        requested_by: form.requested_by || 'portal-user',
        requires_approval_for_actions: true,
      });
      await load();
    } catch (e: any) {
      setError(e?.message || 'Failed to launch suspicious identity preset.');
    } finally {
      setLaunchingPreset(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Users2 className="text-cyan-400" /> Swarm
          </h1>
          <p className="text-gray-400 mt-1">Parallel Claw orchestration jobs and live task execution status.</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="px-3 py-2 rounded-lg border border-gray-700 bg-gray-900 text-gray-200 text-sm hover:bg-gray-800">
            <RefreshCw className={`w-4 h-4 inline mr-1 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
          <button onClick={() => setShowCreate(true)} className="px-3 py-2 rounded-lg bg-regent-600 text-white text-sm hover:bg-regent-500">
            <Plus className="w-4 h-4 inline mr-1" /> New Job
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-900 bg-red-950/30 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Stat label="Total Jobs" value={String(jobs.length)} />
        <Stat label="Running" value={String(jobs.filter(j => j.status === 'running').length)} />
        <Stat label="Needs Approval" value={String(jobs.filter(j => j.status === 'requires_approval').length)} />
        <Stat label="Completed" value={String(jobs.filter(j => j.status === 'completed').length)} />
      </div>

      <div className="bg-gray-900 border border-cyan-900/60 rounded-xl p-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h3 className="text-cyan-300 font-semibold">Sprint 6 Preset · Suspicious Identity Investigation</h3>
            <p className="text-xs text-gray-400 mt-1">Launches Identity + Threat + Cloud + Data + Compliance + Automation with approval gate.</p>
          </div>
          <div className="flex items-center gap-2">
            <input
              value={presetIdentity}
              onChange={(e) => setPresetIdentity(e.target.value)}
              placeholder="identity"
              className="px-2 py-1.5 rounded bg-gray-950 border border-gray-800 text-sm text-gray-200"
            />
            <input
              value={presetTimeRange}
              onChange={(e) => setPresetTimeRange(e.target.value)}
              placeholder="time range"
              className="w-24 px-2 py-1.5 rounded bg-gray-950 border border-gray-800 text-sm text-gray-200"
            />
            <button
              onClick={launchIdentityPreset}
              disabled={launchingPreset || !presetIdentity.trim()}
              className="px-3 py-1.5 rounded bg-cyan-700 hover:bg-cyan-600 text-white text-sm disabled:opacity-60"
            >
              {launchingPreset ? 'Launching...' : 'Launch Preset'}
            </button>
          </div>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800">
          <h2 className="text-white font-semibold">Swarm Jobs</h2>
        </div>
        {jobs.length === 0 ? (
          <p className="px-5 py-8 text-sm text-gray-500">No swarm jobs yet. Start one with New Job.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px] text-sm">
              <thead className="text-xs text-gray-500 border-b border-gray-800">
                <tr>
                  <th className="px-5 py-3 text-left">Name</th>
                  <th className="px-5 py-3 text-left">Profile</th>
                  <th className="px-5 py-3 text-left">Participants</th>
                  <th className="px-5 py-3 text-left">Status</th>
                  <th className="px-5 py-3 text-left">Severity</th>
                  <th className="px-5 py-3 text-left">Confidence</th>
                  <th className="px-5 py-3 text-left">Runtime</th>
                  <th className="px-5 py-3 text-left">Judge Model</th>
                  <th className="px-5 py-3 text-left">Requested By</th>
                  <th className="px-5 py-3 text-left">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {jobs.map((job) => {
                  const meta = statusMeta(job.status);
                  const Icon = meta.icon;
                  const busy = busyId === job.id;
                  const participants = parseParticipants(job.participants_json);
                  const judge = parseJudgeModel(job.result_json);
                  const judgeMeta = judgeStateMeta(judge.state);
                  const JudgeIcon = judgeMeta.icon;
                  return (
                    <tr key={job.id} className="hover:bg-gray-800/40">
                      <td className="px-5 py-3">
                        <Link href={`/swarm/${job.id}`} className="text-white hover:text-cyan-300">{job.name}</Link>
                      </td>
                      <td className="px-5 py-3 text-gray-400">{job.profile}</td>
                      <td className="px-5 py-3 text-gray-400">{participants.length ? participants.join(', ') : '—'}</td>
                      <td className="px-5 py-3">
                        <span className={`inline-flex items-center gap-1 ${meta.color}`}>
                          <Icon className={`w-4 h-4 ${job.status === 'running' ? 'animate-spin' : ''}`} />
                          {job.status}
                        </span>
                      </td>
                      <td className="px-5 py-3"><RiskBadge value={job.overall_severity || 'info'} /></td>
                      <td className="px-5 py-3 text-gray-300">{job.confidence ?? '—'}</td>
                      <td className="px-5 py-3 text-gray-300">{runtimeLabel(job.started_at, job.completed_at)}</td>
                      <td className="px-5 py-3 text-gray-300">
                        <div className="text-xs space-y-1">
                          <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border ${judgeMeta.cls}`}>
                            <JudgeIcon className="w-3 h-3" /> {judge.label}
                          </span>
                          {judge.detail && <p className="text-gray-500 truncate max-w-[180px]" title={judge.detail}>{judge.detail}</p>}
                        </div>
                      </td>
                      <td className="px-5 py-3 text-gray-400">{job.requested_by}</td>
                      <td className="px-5 py-3">
                        <div className="flex gap-2">
                          <button
                            onClick={() => cancelJob(job.id)}
                            disabled={busy || ['completed', 'failed', 'cancelled'].includes(job.status)}
                            className="px-2 py-1 rounded border border-gray-700 text-gray-300 hover:bg-gray-800 disabled:opacity-50"
                          >
                            <StopCircle className="w-3.5 h-3.5 inline mr-1" /> Cancel
                          </button>
                          <button
                            onClick={() => approveJob(job.id)}
                            disabled={busy || job.status !== 'requires_approval'}
                            className="px-2 py-1 rounded border border-green-700 text-green-300 hover:bg-green-900/30 disabled:opacity-50"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5 inline mr-1" /> Approve
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70" onClick={(e) => e.target === e.currentTarget && setShowCreate(false)}>
          <div className="w-full max-w-xl rounded-xl border border-gray-800 bg-gray-900 p-5 space-y-4">
            <h3 className="text-white font-semibold flex items-center gap-2"><Bot className="w-4 h-4 text-cyan-400" /> Create Swarm Job</h3>
            <Field label="Name"><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-gray-200" /></Field>
            <Field label="Profile"><input value={form.profile} onChange={(e) => setForm({ ...form, profile: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-gray-200" /></Field>
            <Field label="Participants (comma-separated)"><input value={form.participants} onChange={(e) => setForm({ ...form, participants: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-gray-200" /></Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Task Type"><input value={form.task_type} onChange={(e) => setForm({ ...form, task_type: e.target.value })} className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-gray-200" /></Field>
              <Field label="Parallelism"><input type="number" min={1} max={24} value={form.parallelism} onChange={(e) => setForm({ ...form, parallelism: Number(e.target.value || 1) })} className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-gray-200" /></Field>
            </div>
            <div className="flex justify-end gap-2">
              <button onClick={() => setShowCreate(false)} className="px-3 py-2 rounded-lg border border-gray-700 text-gray-300">Close</button>
              <button onClick={createJob} disabled={creating} className="px-3 py-2 rounded-lg bg-regent-600 text-white disabled:opacity-60">
                {creating ? 'Creating...' : 'Create Job'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
      <p className="text-xs text-gray-500">{label}</p>
      <p className="text-xl font-semibold text-white mt-1">{value}</p>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs text-gray-500">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}
