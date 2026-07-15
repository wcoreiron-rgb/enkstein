'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  BrainCircuit,
  Check,
  Clock3,
  Eye,
  HeartPulse,
  Loader2,
  Pause,
  Play,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
  CortexMission,
  CortexMissionCadence,
  CortexMissionMode,
  CortexMissionObservation,
  CortexOvernightBrief,
  createCortexMission,
  generateCortexOvernightBrief,
  getCortexMissionObservations,
  getCortexMissions,
  reviewCortexMissionObservation,
  runCortexMission,
  updateCortexMission,
} from '@/lib/api';

const PARTICIPANTS = [
  ['identityclaw', 'Identity'],
  ['cloudclaw', 'Cloud'],
  ['threatclaw', 'Threat'],
  ['dataclaw', 'Data'],
  ['complianceclaw', 'Compliance'],
  ['automationclaw', 'Automation'],
  ['appclaw', 'Application'],
  ['endpointclaw', 'Endpoint'],
] as const;

const DEFAULT_PARTICIPANTS = ['identityclaw', 'cloudclaw', 'threatclaw', 'dataclaw', 'complianceclaw'];

function armLabel(value: string) {
  const known = PARTICIPANTS.find(([id]) => id === value)?.[1];
  if (known) return known;
  return value.replace(/claw$/i, '').replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function relativeTime(value: string | null) {
  if (!value) return 'Not run';
  const delta = new Date(value).getTime() - Date.now();
  const minutes = Math.round(Math.abs(delta) / 60_000);
  if (minutes < 1) return 'Now';
  if (minutes < 60) return delta > 0 ? `In ${minutes}m` : `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return delta > 0 ? `In ${hours}h` : `${hours}h ago`;
  const days = Math.round(hours / 24);
  return delta > 0 ? `In ${days}d` : `${days}d ago`;
}

function statusColor(status: string | null) {
  if (status === 'critical' || status === 'high') return '#dc2626';
  if (status === 'medium') return '#d97706';
  if (status === 'low' || status === 'info') return '#16a34a';
  if (status === 'completed' || status === 'active' || status === 'healthy' || status === 'approved') return '#16a34a';
  if (status === 'failed' || status === 'blocked' || status === 'rejected') return '#dc2626';
  if (status === 'pending' || status === 'running' || status === 'proposed') return '#d97706';
  return '#64748b';
}

function CountMetric({ label, value, icon: Icon }: { label: string; value: number | string; icon: React.ElementType }) {
  return (
    <div className="min-w-0 border-l-2 pl-3" style={{ borderColor: 'var(--rc-border-2)' }}>
      <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--rc-text-3)' }}>
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <p className="mt-1 truncate text-xl font-semibold" style={{ color: 'var(--rc-text-1)' }}>{value}</p>
    </div>
  );
}

export default function MissionControl() {
  const [missions, setMissions] = useState<CortexMission[]>([]);
  const [observations, setObservations] = useState<CortexMissionObservation[]>([]);
  const [brief, setBrief] = useState<CortexOvernightBrief | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('Continuous Identity Risk Watch');
  const [objective, setObjective] = useState('Continuously detect material identity risk changes and recommend governed response actions.');
  const [cadence, setCadence] = useState<CortexMissionCadence>('daily');
  const [mode, setMode] = useState<CortexMissionMode>('assist');
  const [participants, setParticipants] = useState<string[]>(DEFAULT_PARTICIPANTS);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [missionRows, observationRows, currentBrief] = await Promise.all([
        getCortexMissions(),
        getCortexMissionObservations(),
        generateCortexOvernightBrief(12),
      ]);
      setMissions(missionRows);
      setObservations(observationRows);
      setBrief(currentBrief);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Mission intelligence is unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const pending = useMemo(() => observations.filter((item) => item.status === 'proposed'), [observations]);
  const activeMissions = missions.filter((item) => item.status === 'active');
  const runningArms = brief?.running_arms || [];
  const health = String(brief?.security_twin_health.status || (missions.length ? 'warming' : 'unconfigured'));

  const createMission = async () => {
    if (participants.length < 2) {
      setError('Select at least two Security Arms.');
      return;
    }
    setBusy('create');
    setError(null);
    try {
      const created = await createCortexMission({ name, objective, cadence, autonomy_mode: mode, participants });
      setMissions((current) => [created, ...current]);
      setShowCreate(false);
      setBrief(await generateCortexOvernightBrief(12));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Mission could not be created');
    } finally {
      setBusy(null);
    }
  };

  const runMission = async (mission: CortexMission) => {
    setBusy(`run:${mission.id}`);
    setError(null);
    try {
      await runCortexMission(mission.id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Mission could not be started');
    } finally {
      setBusy(null);
    }
  };

  const toggleMission = async (mission: CortexMission) => {
    setBusy(`status:${mission.id}`);
    setError(null);
    try {
      const updated = await updateCortexMission(mission.id, {
        status: mission.status === 'active' ? 'paused' : 'active',
      });
      setMissions((current) => current.map((item) => item.id === updated.id ? updated : item));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Mission status could not be changed');
    } finally {
      setBusy(null);
    }
  };

  const reviewObservation = async (observation: CortexMissionObservation, decision: 'approve' | 'reject') => {
    setBusy(`review:${observation.id}`);
    setError(null);
    try {
      const reviewed = await reviewCortexMissionObservation(
        observation.id,
        decision,
        decision === 'approve' ? 'Approved for future Mission context' : 'Rejected by operator',
      );
      setObservations((current) => current.map((item) => item.id === reviewed.id ? reviewed : item));
      setBrief(await generateCortexOvernightBrief(12));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Memory decision could not be recorded');
    } finally {
      setBusy(null);
    }
  };

  if (loading) {
    return (
      <section className="flex h-52 items-center justify-center border-y" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Preparing Mission intelligence
      </section>
    );
  }

  return (
    <section className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <BrainCircuit className="h-6 w-6 text-cyan-500" />
            <h1 className="text-2xl font-semibold" style={{ color: 'var(--rc-text-1)' }}>Mission Control</h1>
            <span className="inline-flex items-center gap-1 text-xs font-medium" style={{ color: statusColor(health) }}>
              <HeartPulse className="h-3.5 w-3.5" /> Cortex {health}
            </span>
          </div>
          <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
            {brief?.headline || 'Create a persistent Mission to begin continuous security intelligence.'}
          </p>
          {brief && <p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>12-hour brief generated {relativeTime(brief.generated_at)}</p>}
        </div>
        <div className="flex items-center gap-2">
          <button type="button" onClick={() => void load()} title="Refresh intelligence" aria-label="Refresh intelligence"
            className="flex h-9 w-9 items-center justify-center rounded-md border" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
            <RefreshCw className="h-4 w-4" />
          </button>
          <button type="button" onClick={() => setShowCreate(true)}
            className="inline-flex h-9 items-center gap-2 rounded-md bg-cyan-600 px-3 text-sm font-medium text-white hover:bg-cyan-500">
            <Plus className="h-4 w-4" /> New Mission
          </button>
        </div>
      </header>

      {error && <div className="border-l-2 border-red-500 py-2 pl-3 text-sm text-red-500">{error}</div>}

      <div className="grid grid-cols-2 gap-5 border-y py-4 md:grid-cols-4" style={{ borderColor: 'var(--rc-border)' }}>
        <CountMetric label="Active Missions" value={activeMissions.length} icon={Activity} />
        <CountMetric label="Decisions Needed" value={pending.length} icon={ShieldAlert} />
        <CountMetric label="Material Changes" value={brief?.material_changes.length || 0} icon={Eye} />
        <CountMetric label="Running Arms" value={runningArms.length} icon={HeartPulse} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(300px,.6fr)]">
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Persistent Missions</h2>
            <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Read, analyze, and recommend authority</span>
          </div>
          <div className="divide-y border-y" style={{ borderColor: 'var(--rc-border)' }}>
            {missions.length === 0 && <p className="py-8 text-center text-sm" style={{ color: 'var(--rc-text-3)' }}>No Missions configured.</p>}
            {missions.map((mission) => (
              <article key={mission.id} className="py-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{mission.name}</h3>
                      <span className="text-xs font-medium" style={{ color: statusColor(mission.status) }}>{mission.status}</span>
                      {mission.latest_status && <span className="text-xs" style={{ color: statusColor(mission.latest_status) }}>{mission.latest_status}</span>}
                    </div>
                    <p className="mt-1 line-clamp-2 text-xs leading-5" style={{ color: 'var(--rc-text-2)' }}>{mission.objective}</p>
                    <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>
                      <span>{mission.cadence.replaceAll('_', ' ')}</span>
                      <span>{mission.autonomy_mode} mode</span>
                      <span>{mission.run_count} runs</span>
                      <span>Next {relativeTime(mission.next_run_at)}</span>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {mission.participants.map((arm) => <span key={arm} className="text-[11px]" style={{ color: 'var(--rc-text-3)' }}>{armLabel(arm)}</span>)}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <button type="button" onClick={() => void toggleMission(mission)} disabled={busy === `status:${mission.id}`}
                      title={mission.status === 'active' ? 'Pause Mission' : 'Resume Mission'} aria-label={mission.status === 'active' ? 'Pause Mission' : 'Resume Mission'}
                      className="flex h-8 w-8 items-center justify-center rounded-md border disabled:opacity-50" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
                      {mission.status === 'active' ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
                    </button>
                    <button type="button" onClick={() => void runMission(mission)} disabled={busy === `run:${mission.id}` || mission.status === 'archived'}
                      title="Run Mission now" aria-label="Run Mission now"
                      className="inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium disabled:opacity-50" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
                      {busy === `run:${mission.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />} Run
                    </button>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </div>

        <aside>
          <h2 className="mb-3 text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Decisions Needed</h2>
          <div className="space-y-3">
            {pending.length === 0 && <div className="border-l-2 border-green-500 py-2 pl-3 text-sm" style={{ color: 'var(--rc-text-2)' }}>No Mission memory awaiting review.</div>}
            {pending.slice(0, 5).map((observation) => (
              <article key={observation.id} className="border-l-2 py-1 pl-3" style={{ borderColor: statusColor(observation.severity) }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium uppercase" style={{ color: statusColor(observation.severity) }}>{observation.severity}</span>
                  <span className="text-[11px]" style={{ color: 'var(--rc-text-3)' }}>{relativeTime(observation.created_at)}</span>
                </div>
                <p className="mt-1 line-clamp-4 text-xs leading-5" style={{ color: 'var(--rc-text-2)' }}>{observation.summary}</p>
                <div className="mt-2 flex gap-2">
                  <button type="button" onClick={() => void reviewObservation(observation, 'approve')} disabled={busy === `review:${observation.id}`}
                    className="inline-flex h-7 items-center gap-1 rounded-md bg-green-600 px-2 text-xs font-medium text-white disabled:opacity-50">
                    <Check className="h-3 w-3" /> Approve
                  </button>
                  <button type="button" onClick={() => void reviewObservation(observation, 'reject')} disabled={busy === `review:${observation.id}`}
                    className="inline-flex h-7 items-center gap-1 rounded-md border px-2 text-xs font-medium disabled:opacity-50" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
                    <X className="h-3 w-3" /> Reject
                  </button>
                </div>
              </article>
            ))}
          </div>
        </aside>
      </div>

      <div className="grid gap-5 border-y py-4 md:grid-cols-3" style={{ borderColor: 'var(--rc-border)' }}>
        <div>
          <div className="flex items-center gap-2 text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}><ShieldCheck className="h-4 w-4 text-green-500" /> Security Twin Health</div>
          <p className="mt-2 text-sm font-semibold capitalize" style={{ color: statusColor(health) }}>{health}</p>
          <p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>{Number(brief?.security_twin_health.approved_observations || 0)} approved observations</p>
        </div>
        <div>
          <div className="flex items-center gap-2 text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}><Clock3 className="h-4 w-4 text-cyan-500" /> Recent Reflex Actions</div>
          <p className="mt-2 text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{brief?.recent_reflex_actions.length || 0}</p>
          <p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>Policy-bounded actions in the brief window</p>
        </div>
        <div>
          <div className="flex items-center gap-2 text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}><ShieldAlert className="h-4 w-4 text-red-500" /> Blocked Actions</div>
          <p className="mt-2 text-sm font-semibold" style={{ color: brief?.blocked_actions.length ? '#dc2626' : 'var(--rc-text-1)' }}>{brief?.blocked_actions.length || 0}</p>
          <p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>Denied or failed Mission activity</p>
        </div>
      </div>

      {showCreate && (
        <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/55 p-4" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) setShowCreate(false); }}>
          <div className="w-full max-w-xl rounded-lg border p-5 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="mission-dialog-title"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <div className="flex items-center justify-between">
              <div><h2 id="mission-dialog-title" className="text-lg font-semibold" style={{ color: 'var(--rc-text-1)' }}>New persistent Mission</h2><p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>Mission output becomes reviewable memory, never automatic truth.</p></div>
              <button type="button" onClick={() => setShowCreate(false)} aria-label="Close"><X className="h-4 w-4" /></button>
            </div>
            <div className="mt-5 space-y-4">
              <label className="block text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}>Name<input value={name} onChange={(event) => setName(event.target.value)} className="mt-1 h-10 w-full rounded-md border px-3 text-sm outline-none focus:border-cyan-500" style={{ background: 'var(--rc-bg-input)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }} /></label>
              <label className="block text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}>Objective<textarea value={objective} onChange={(event) => setObjective(event.target.value)} rows={3} className="mt-1 w-full resize-none rounded-md border px-3 py-2 text-sm outline-none focus:border-cyan-500" style={{ background: 'var(--rc-bg-input)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }} /></label>
              <div className="grid grid-cols-2 gap-3">
                <label className="text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}>Cadence<select value={cadence} onChange={(event) => setCadence(event.target.value as CortexMissionCadence)} className="mt-1 h-10 w-full rounded-md border px-2 text-sm" style={{ background: 'var(--rc-bg-input)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}><option value="manual">Manual</option><option value="hourly">Hourly</option><option value="every_6h">Every 6 hours</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></label>
                <label className="text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}>Autonomy<select value={mode} onChange={(event) => setMode(event.target.value as CortexMissionMode)} className="mt-1 h-10 w-full rounded-md border px-2 text-sm" style={{ background: 'var(--rc-bg-input)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}><option value="monitor">Monitor</option><option value="assist">Assist</option><option value="approval">Approval gated</option></select></label>
              </div>
              <fieldset><legend className="text-xs font-medium" style={{ color: 'var(--rc-text-2)' }}>Security Arms</legend><div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">{PARTICIPANTS.map(([id, label]) => { const selected = participants.includes(id); return <button key={id} type="button" aria-pressed={selected} onClick={() => setParticipants((current) => selected ? current.filter((item) => item !== id) : [...current, id])} className="h-9 rounded-md border px-2 text-xs font-medium" style={{ borderColor: selected ? '#0891b2' : 'var(--rc-border)', background: selected ? 'rgba(8,145,178,.12)' : 'transparent', color: selected ? '#06b6d4' : 'var(--rc-text-2)' }}>{label}</button>; })}</div></fieldset>
            </div>
            <div className="mt-6 flex justify-end gap-2"><button type="button" onClick={() => setShowCreate(false)} className="h-9 rounded-md border px-3 text-sm" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>Cancel</button><button type="button" onClick={() => void createMission()} disabled={busy === 'create' || name.trim().length < 3 || objective.trim().length < 10 || participants.length < 2} className="inline-flex h-9 items-center gap-2 rounded-md bg-cyan-600 px-3 text-sm font-medium text-white disabled:opacity-50">{busy === 'create' && <Loader2 className="h-4 w-4 animate-spin" />} Create Mission</button></div>
          </div>
        </div>
      )}
    </section>
  );
}
