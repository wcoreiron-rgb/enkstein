'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  GitMerge, Play, Plus, Trash2, ChevronDown, ChevronRight,
  CheckCircle2, XCircle, Clock, AlertTriangle, RefreshCw,
  Bot, Shield, GitBranch, Bell, Timer, Pencil, X, Save,
  Zap, Activity, Calendar, MousePointer2, Layers,
} from 'lucide-react';
import {
  getWorkflows, createWorkflow, updateWorkflow, deleteWorkflow,
  triggerWorkflow, getWorkflowRuns,
} from '@/lib/api';
import ClientDate from '@/components/ClientDate';

// ── Step type config ──────────────────────────────────────────────────────────

const STEP_TYPES: Record<string, { label: string; icon: React.ElementType; color: string; bg: string; border: string; desc: string }> = {
  agent_run:    { label: 'Agent Run',     icon: Bot,         color: 'text-indigo-400', bg: 'bg-indigo-900/30', border: 'border-indigo-700', desc: 'Trigger a registered agent' },
  policy_check: { label: 'Policy Check',  icon: Shield,      color: 'text-cyan-400',   bg: 'bg-cyan-900/30',   border: 'border-cyan-700',   desc: 'Evaluate a policy condition' },
  condition:    { label: 'Condition',     icon: GitBranch,   color: 'text-yellow-400', bg: 'bg-yellow-900/30', border: 'border-yellow-700', desc: 'Branch on an expression' },
  wait:         { label: 'Wait',          icon: Timer,       color: 'text-gray-400',   bg: 'bg-gray-900/30',   border: 'border-gray-700',   desc: 'Pause N seconds' },
  notify:       { label: 'Notify',        icon: Bell,        color: 'text-green-400',  bg: 'bg-green-900/30',  border: 'border-green-700',  desc: 'Emit a notification event' },
};

const TRIGGER_META: Record<string, { label: string; icon: React.ElementType; color: string }> = {
  manual:   { label: 'Manual',   icon: MousePointer2, color: 'text-gray-400' },
  schedule: { label: 'Schedule', icon: Calendar,      color: 'text-blue-400' },
  event:    { label: 'Event',    icon: Zap,           color: 'text-yellow-400' },
};

const RUN_STATUS_STYLE: Record<string, { color: string; icon: React.ElementType; label: string }> = {
  completed: { color: 'text-green-400',  icon: CheckCircle2, label: 'Completed' },
  failed:    { color: 'text-red-400',    icon: XCircle,      label: 'Failed' },
  running:   { color: 'text-blue-400',   icon: RefreshCw,    label: 'Running' },
  pending:   { color: 'text-gray-400',   icon: Clock,        label: 'Pending' },
  cancelled: { color: 'text-gray-500',   icon: X,            label: 'Cancelled' },
  blocked:   { color: 'text-orange-400', icon: AlertTriangle,label: 'Blocked' },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function newStep(idx: number) {
  return { id: `step-${Date.now()}-${idx}`, name: '', type: 'notify', config: {}, on_failure: 'stop' };
}

function StepTypeBadge({ type }: { type: string }) {
  const meta = STEP_TYPES[type] ?? STEP_TYPES.notify;
  const Icon = meta.icon;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${meta.color} ${meta.bg} ${meta.border}`}>
      <Icon className="w-3 h-3" /> {meta.label}
    </span>
  );
}

// ── Step editor row ───────────────────────────────────────────────────────────

function StepRow({ step, idx, onChange, onRemove, onMoveUp, onMoveDown, isFirst, isLast }: {
  step: any; idx: number;
  onChange: (s: any) => void;
  onRemove: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
  isFirst: boolean; isLast: boolean;
}) {
  const meta = STEP_TYPES[step.type] ?? STEP_TYPES.notify;
  const Icon = meta.icon;

  return (
    <div className="rounded-xl border p-3 space-y-2" style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' }}>
      <div className="flex items-center gap-2">
        {/* Order number */}
        <span className="flex-shrink-0 w-6 h-6 rounded-md flex items-center justify-center text-xs font-bold"
          style={{ background: 'var(--rc-bg-base)', color: 'var(--rc-text-3)' }}>
          {idx + 1}
        </span>

        {/* Step name */}
        <input
          value={step.name}
          onChange={e => onChange({ ...step, name: e.target.value })}
          placeholder="Step name…"
          className="flex-1 min-w-0 px-2 py-1 text-sm rounded border focus:outline-none focus:ring-1 focus:ring-indigo-500"
          style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-1)' }}
        />

        {/* Type selector */}
        <select
          value={step.type}
          onChange={e => onChange({ ...step, type: e.target.value, config: {} })}
          className="px-2 py-1 text-xs rounded border focus:outline-none"
          style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-1)' }}
        >
          {Object.entries(STEP_TYPES).map(([val, { label }]) => (
            <option key={val} value={val}>{label}</option>
          ))}
        </select>

        {/* On failure */}
        <select
          value={step.on_failure}
          onChange={e => onChange({ ...step, on_failure: e.target.value })}
          className="px-2 py-1 text-xs rounded border focus:outline-none"
          style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-1)' }}
          title="On failure"
        >
          <option value="stop">Stop on fail</option>
          <option value="continue">Continue on fail</option>
        </select>

        {/* Move / remove */}
        <div className="flex gap-1">
          <button onClick={onMoveUp} disabled={isFirst} className="p-1 rounded hover:opacity-70 disabled:opacity-20"
            style={{ color: 'var(--rc-text-3)' }} title="Move up">▲</button>
          <button onClick={onMoveDown} disabled={isLast} className="p-1 rounded hover:opacity-70 disabled:opacity-20"
            style={{ color: 'var(--rc-text-3)' }} title="Move down">▼</button>
          <button onClick={onRemove} className="p-1 rounded hover:text-red-400"
            style={{ color: 'var(--rc-text-3)' }}>
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Type-specific config fields */}
      {step.type === 'agent_run' && (
        <input
          value={step.config?.label ?? ''}
          onChange={e => onChange({ ...step, config: { ...step.config, label: e.target.value } })}
          placeholder="Agent label (e.g. Identity Security Auditor)"
          className="w-full px-2 py-1 text-xs rounded border focus:outline-none"
          style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
        />
      )}
      {step.type === 'policy_check' && (
        <div className="flex gap-2">
          <input
            value={step.config?.field ?? ''}
            onChange={e => onChange({ ...step, config: { ...step.config, field: e.target.value } })}
            placeholder="Field"
            className="flex-1 px-2 py-1 text-xs rounded border focus:outline-none"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
          />
          <select
            value={step.config?.op ?? 'eq'}
            onChange={e => onChange({ ...step, config: { ...step.config, op: e.target.value } })}
            className="px-2 py-1 text-xs rounded border focus:outline-none w-24"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
          >
            {['eq','neq','gte','lte','in','contains'].map(o => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            value={step.config?.value ?? ''}
            onChange={e => onChange({ ...step, config: { ...step.config, value: e.target.value } })}
            placeholder="Value"
            className="flex-1 px-2 py-1 text-xs rounded border focus:outline-none"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
          />
        </div>
      )}
      {step.type === 'condition' && (
        <input
          value={step.config?.expression ?? ''}
          onChange={e => onChange({ ...step, config: { ...step.config, expression: e.target.value } })}
          placeholder="Expression (e.g. risk_score > 70)"
          className="w-full px-2 py-1 text-xs rounded border focus:outline-none"
          style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
        />
      )}
      {step.type === 'wait' && (
        <input
          type="number" min={1} max={300}
          value={step.config?.seconds ?? 1}
          onChange={e => onChange({ ...step, config: { ...step.config, seconds: Number(e.target.value) } })}
          className="w-24 px-2 py-1 text-xs rounded border focus:outline-none"
          style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
          placeholder="Seconds"
        />
      )}
      {step.type === 'notify' && (
        <div className="flex gap-2">
          <input
            value={step.config?.message ?? ''}
            onChange={e => onChange({ ...step, config: { ...step.config, message: e.target.value } })}
            placeholder="Notification message…"
            className="flex-1 px-2 py-1 text-xs rounded border focus:outline-none"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
          />
          <select
            value={step.config?.severity ?? 'info'}
            onChange={e => onChange({ ...step, config: { ...step.config, severity: e.target.value } })}
            className="px-2 py-1 text-xs rounded border focus:outline-none w-24"
            style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
          >
            {['info','low','medium','high','critical'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      )}
    </div>
  );
}

// ── Workflow builder modal ────────────────────────────────────────────────────

function BuilderModal({ workflow, onSave, onClose }: {
  workflow?: any; onSave: (w: any) => void; onClose: () => void;
}) {
  const isEdit = !!workflow;
  const [name, setName]         = useState(workflow?.name ?? '');
  const [desc, setDesc]         = useState(workflow?.description ?? '');
  const [trigger, setTrigger]   = useState(workflow?.trigger_type ?? 'manual');
  const [category, setCategory] = useState(workflow?.category ?? '');
  const [steps, setSteps]       = useState<any[]>(() => {
    try { return JSON.parse(workflow?.steps_json ?? '[]'); } catch { return []; }
  });
  const [saving, setSaving] = useState(false);
  const [error, setError]   = useState('');

  const addStep = () => setSteps(s => [...s, newStep(s.length)]);
  const removeStep = (i: number) => setSteps(s => s.filter((_, idx) => idx !== i));
  const changeStep = (i: number, s: any) => setSteps(prev => prev.map((x, idx) => idx === i ? s : x));
  const moveStep = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= steps.length) return;
    const arr = [...steps];
    [arr[i], arr[j]] = [arr[j], arr[i]];
    setSteps(arr);
  };

  const handleSave = async () => {
    if (!name.trim()) { setError('Name is required'); return; }
    setSaving(true); setError('');
    try {
      const payload = {
        name: name.trim(), description: desc, trigger_type: trigger,
        category, steps_json: JSON.stringify(steps), step_count: steps.length,
      };
      const result = isEdit
        ? await updateWorkflow(workflow.id, payload)
        : await createWorkflow(payload);
      onSave(result);
    } catch (e: any) { setError(e.message || 'Save failed'); }
    finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 overflow-y-auto"
      style={{ background: 'rgba(0,0,0,0.7)' }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="w-full max-w-2xl my-8 rounded-2xl border shadow-2xl overflow-hidden"
        style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b"
          style={{ borderColor: 'var(--rc-border)' }}>
          <h2 className="font-semibold text-base flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
            <GitMerge className="w-5 h-5 text-indigo-400" />
            {isEdit ? 'Edit Workflow' : 'New Workflow'}
          </h2>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:opacity-70" style={{ color: 'var(--rc-text-3)' }}>
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          {/* Metadata */}
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="block text-xs font-semibold uppercase tracking-wide mb-1.5" style={{ color: 'var(--rc-text-3)' }}>
                Workflow name *
              </label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Daily Identity Audit"
                className="w-full px-3 py-2 text-sm rounded-lg border focus:outline-none focus:ring-2 focus:ring-indigo-500"
                style={{ background: 'var(--rc-bg-input)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-1)' }} />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-semibold uppercase tracking-wide mb-1.5" style={{ color: 'var(--rc-text-3)' }}>
                Description
              </label>
              <textarea value={desc} onChange={e => setDesc(e.target.value)} rows={2} placeholder="What does this workflow do?"
                className="w-full px-3 py-2 text-sm rounded-lg border focus:outline-none resize-none"
                style={{ background: 'var(--rc-bg-input)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-1)' }} />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide mb-1.5" style={{ color: 'var(--rc-text-3)' }}>
                Trigger
              </label>
              <select value={trigger} onChange={e => setTrigger(e.target.value)}
                className="w-full px-3 py-2 text-sm rounded-lg border focus:outline-none"
                style={{ background: 'var(--rc-bg-input)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-1)' }}>
                <option value="manual">Manual</option>
                <option value="schedule">Schedule</option>
                <option value="event">Event-driven</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide mb-1.5" style={{ color: 'var(--rc-text-3)' }}>
                Category
              </label>
              <input value={category} onChange={e => setCategory(e.target.value)} placeholder="e.g. Compliance"
                className="w-full px-3 py-2 text-sm rounded-lg border focus:outline-none"
                style={{ background: 'var(--rc-bg-input)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-1)' }} />
            </div>
          </div>

          {/* Steps builder */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--rc-text-3)' }}>
                Steps ({steps.length})
              </label>
              <button onClick={addStep}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-white"
                style={{ background: 'var(--regent-600)' }}>
                <Plus className="w-3.5 h-3.5" /> Add Step
              </button>
            </div>

            {steps.length === 0 ? (
              <div className="rounded-xl border border-dashed p-6 text-center"
                style={{ borderColor: 'var(--rc-border-2)' }}>
                <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>
                  No steps yet — click "Add Step" to start building.
                </p>
              </div>
            ) : (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {steps.map((step, i) => (
                  <StepRow
                    key={step.id}
                    step={step} idx={i}
                    onChange={s => changeStep(i, s)}
                    onRemove={() => removeStep(i)}
                    onMoveUp={() => moveStep(i, -1)}
                    onMoveDown={() => moveStep(i, 1)}
                    isFirst={i === 0} isLast={i === steps.length - 1}
                  />
                ))}
              </div>
            )}
          </div>

          {error && (
            <p className="text-sm text-red-400 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4" /> {error}
            </p>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t"
          style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm border"
            style={{ borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}>
            Cancel
          </button>
          <button onClick={handleSave} disabled={saving}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50"
            style={{ background: 'var(--regent-600)' }}>
            {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            {saving ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Workflow'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Run history panel ─────────────────────────────────────────────────────────

function RunHistoryPanel({ workflowId, onClose }: { workflowId: string; onClose: () => void }) {
  const [runs, setRuns]       = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    getWorkflowRuns(workflowId).then(setRuns).catch(console.error).finally(() => setLoading(false));
  }, [workflowId]);

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-full max-w-md shadow-2xl flex flex-col border-l"
      style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
      <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: 'var(--rc-border)' }}>
        <h2 className="font-semibold text-sm flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
          <Activity className="w-4 h-4 text-indigo-400" /> Run History
        </h2>
        <button onClick={onClose} className="p-1.5 rounded hover:opacity-70" style={{ color: 'var(--rc-text-3)' }}>
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {loading ? (
          <p className="text-sm text-center py-8" style={{ color: 'var(--rc-text-3)' }}>Loading runs…</p>
        ) : runs.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>No runs yet.</p>
            <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>Click "Run" to execute the workflow.</p>
          </div>
        ) : runs.map(run => {
          const statusMeta = RUN_STATUS_STYLE[run.status] ?? RUN_STATUS_STYLE.pending;
          const StatusIcon = statusMeta.icon;
          const isOpen = expanded === run.id;
          let stepLogs: any[] = [];
          try { stepLogs = JSON.parse(run.steps_log ?? '[]'); } catch { /* empty */ }

          return (
            <div key={run.id} className="rounded-xl border overflow-hidden"
              style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' }}>
              <button className="w-full flex items-start gap-3 p-3 text-left"
                onClick={() => setExpanded(isOpen ? null : run.id)}>
                <StatusIcon className={`w-4 h-4 flex-shrink-0 mt-0.5 ${statusMeta.color} ${run.status === 'running' ? 'animate-spin' : ''}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <p className={`text-xs font-semibold ${statusMeta.color}`}>{statusMeta.label}</p>
                    <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
                      {run.duration_sec != null ? `${run.duration_sec.toFixed(1)}s` : '—'}
                    </p>
                  </div>
                  <p className="text-xs mt-0.5 line-clamp-2" style={{ color: 'var(--rc-text-2)' }}>
                    {run.summary || 'No summary'}
                  </p>
                  <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>
                    <ClientDate value={run.created_at} /> · {run.steps_completed} steps OK
                    {run.steps_failed > 0 && `, ${run.steps_failed} failed`}
                  </p>
                </div>
                {isOpen ? <ChevronDown className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />
                         : <ChevronRight className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />}
              </button>

              {isOpen && stepLogs.length > 0 && (
                <div className="border-t px-3 pb-3 space-y-1.5 pt-2" style={{ borderColor: 'var(--rc-border)' }}>
                  {stepLogs.map((sl: any, i: number) => {
                    const slStatus = RUN_STATUS_STYLE[sl.status] ?? RUN_STATUS_STYLE.pending;
                    const SlIcon = slStatus.icon;
                    return (
                      <div key={i} className="flex items-start gap-2">
                        <SlIcon className={`w-3 h-3 flex-shrink-0 mt-0.5 ${slStatus.color}`} />
                        <div className="min-w-0">
                          <p className="text-xs font-medium" style={{ color: 'var(--rc-text-1)' }}>
                            {sl.name || sl.step_id}
                            <span className="ml-1.5 font-normal" style={{ color: 'var(--rc-text-3)' }}>
                              [{sl.type}]
                            </span>
                          </p>
                          <p className="text-xs" style={{ color: 'var(--rc-text-2)' }}>{sl.output}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Workflow card ─────────────────────────────────────────────────────────────

function WorkflowCard({ workflow, onEdit, onDelete, onRun, onViewRuns }: {
  workflow: any;
  onEdit: () => void;
  onDelete: () => void;
  onRun: () => Promise<void>;
  onViewRuns: () => void;
}) {
  const [running, setRunning]   = useState(false);
  const [runResult, setRunResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [expanded, setExpanded] = useState(false);

  const triggerMeta = TRIGGER_META[workflow.trigger_type] ?? TRIGGER_META.manual;
  const TrigIcon = triggerMeta.icon;
  const lastStatus = RUN_STATUS_STYLE[workflow.last_run_status ?? ''];
  const LastIcon = lastStatus?.icon;

  let steps: any[] = [];
  try { steps = JSON.parse(workflow.steps_json); } catch { /* empty */ }

  const handleRun = async () => {
    setRunning(true); setRunResult(null);
    try {
      await onRun();
      setRunResult({ ok: true, msg: 'Workflow executed successfully' });
    } catch (e: any) {
      setRunResult({ ok: false, msg: e.message || 'Execution failed' });
    } finally { setRunning(false); }
  };

  return (
    <div className="rounded-2xl border transition-all duration-150"
      style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
      {/* Status bar */}
      {workflow.last_run_status && (
        <div className={`h-0.5 w-full ${workflow.last_run_status === 'completed' ? 'bg-green-500' : workflow.last_run_status === 'failed' ? 'bg-red-500' : 'bg-gray-600'}`} />
      )}

      <div className="p-5">
        {/* Header row */}
        <div className="flex items-start gap-3 mb-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <span className={`flex items-center gap-1 text-xs font-medium ${triggerMeta.color}`}>
                <TrigIcon className="w-3 h-3" /> {triggerMeta.label}
              </span>
              {workflow.category && (
                <span className="text-xs px-2 py-0.5 rounded border"
                  style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)', fontSize: '10px' }}>
                  {workflow.category}
                </span>
              )}
              {!workflow.is_active && (
                <span className="text-xs text-orange-400 font-medium">Paused</span>
              )}
            </div>
            <h3 className="font-semibold text-base" style={{ color: 'var(--rc-text-1)' }}>{workflow.name}</h3>
            {workflow.description && (
              <p className="text-sm mt-0.5 leading-relaxed line-clamp-2" style={{ color: 'var(--rc-text-2)' }}>
                {workflow.description}
              </p>
            )}
          </div>

          {/* Step count badge */}
          <div className="flex-shrink-0 text-center px-3 py-2 rounded-xl border"
            style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' }}>
            <p className="text-lg font-bold" style={{ color: 'var(--rc-text-1)' }}>{workflow.step_count}</p>
            <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>steps</p>
          </div>
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-4 mb-4 text-xs" style={{ color: 'var(--rc-text-3)' }}>
          <span>{workflow.run_count ?? 0} runs</span>
          {workflow.last_run_at && (
            <span>Last: <ClientDate value={workflow.last_run_at} format="date" /></span>
          )}
          {lastStatus && LastIcon && (
            <span className={`flex items-center gap-1 ${lastStatus.color}`}>
              <LastIcon className="w-3 h-3" /> {lastStatus.label}
            </span>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 flex-wrap">
          <button onClick={handleRun} disabled={running || !workflow.is_active}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-white disabled:opacity-50 transition-colors"
            style={{ background: 'var(--regent-600)' }}>
            {running ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            {running ? 'Running…' : 'Run'}
          </button>
          <button onClick={onViewRuns}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border transition-colors hover:opacity-80"
            style={{ borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-elevated)' }}>
            <Activity className="w-3.5 h-3.5" /> History
          </button>
          <button onClick={onEdit}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border transition-colors hover:opacity-80"
            style={{ borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-elevated)' }}>
            <Pencil className="w-3.5 h-3.5" /> Edit
          </button>
          <button onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs border transition-colors"
            style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)' }}>
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            Steps
          </button>
          <button onClick={onDelete}
            className="ml-auto p-1.5 rounded-lg hover:text-red-400 hover:bg-red-900/20"
            style={{ color: 'var(--rc-text-3)' }}>
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Run result toast */}
        {runResult && (
          <div className={`mt-3 flex items-start gap-2 text-xs p-2.5 rounded-lg ${runResult.ok ? 'text-green-400 bg-green-900/20' : 'text-red-400 bg-red-900/20'}`}>
            {runResult.ok ? <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                          : <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />}
            {runResult.msg}
          </div>
        )}
      </div>

      {/* Expanded steps list */}
      {expanded && steps.length > 0 && (
        <div className="border-t px-5 pb-4" style={{ borderColor: 'var(--rc-border)' }}>
          <p className="text-xs font-semibold uppercase tracking-wide mt-3 mb-2" style={{ color: 'var(--rc-text-3)' }}>
            Workflow steps
          </p>
          <div className="space-y-1.5">
            {steps.map((step, i) => (
              <div key={step.id ?? i} className="flex items-center gap-2.5">
                <span className="flex-shrink-0 w-5 h-5 rounded flex items-center justify-center text-xs font-bold"
                  style={{ background: 'var(--rc-bg-base)', color: 'var(--rc-text-3)' }}>
                  {i + 1}
                </span>
                <StepTypeBadge type={step.type} />
                <p className="text-xs flex-1 truncate" style={{ color: 'var(--rc-text-1)' }}>
                  {step.name || step.type}
                </p>
                {step.on_failure === 'stop' && (
                  <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>stop on fail</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function OrchestrationsPage() {
  const [workflows, setWorkflows]   = useState<any[]>([]);
  const [loading, setLoading]       = useState(true);
  const [showBuilder, setShowBuilder] = useState(false);
  const [editing, setEditing]       = useState<any | null>(null);
  const [viewingRuns, setViewingRuns] = useState<string | null>(null);
  const [filterCat, setFilterCat]   = useState('ALL');

  const load = useCallback(() => {
    setLoading(true);
    getWorkflows().then(setWorkflows).catch(console.error).finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSave = (wf: any) => {
    setWorkflows(prev => {
      const idx = prev.findIndex(w => w.id === wf.id);
      return idx >= 0 ? prev.map(w => w.id === wf.id ? wf : w) : [wf, ...prev];
    });
    setShowBuilder(false);
    setEditing(null);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this workflow? All run history will be lost.')) return;
    try {
      await deleteWorkflow(id);
      setWorkflows(prev => prev.filter(w => w.id !== id));
    } catch (e) { console.error(e); }
  };

  const handleRun = async (id: string) => {
    const result = await triggerWorkflow(id);
    // Refresh to get updated run_count / last_run_status
    const updated = await getWorkflows();
    setWorkflows(updated);
    return result;
  };

  // Category list
  const categories = ['ALL', ...Array.from(new Set(workflows.map(w => w.category).filter(Boolean)))];
  const shown = filterCat === 'ALL' ? workflows : workflows.filter(w => w.category === filterCat);

  // Stats
  const totalRuns   = workflows.reduce((s, w) => s + (w.run_count || 0), 0);
  const activeCount = workflows.filter(w => w.is_active).length;
  const totalSteps  = workflows.reduce((s, w) => s + (w.step_count || 0), 0);

  return (
    <div className="space-y-6">
      {/* Modals */}
      {(showBuilder || editing) && (
        <BuilderModal
          workflow={editing ?? undefined}
          onSave={handleSave}
          onClose={() => { setShowBuilder(false); setEditing(null); }}
        />
      )}
      {viewingRuns && (
        <RunHistoryPanel workflowId={viewingRuns} onClose={() => setViewingRuns(null)} />
      )}

      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
            <GitMerge className="text-indigo-400" /> Orchestrations
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
            Chain agents into governed multi-step workflows — all execution flows through Trust Fabric
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {/* Stats */}
          {[
            { label: 'Workflows', val: workflows.length, c: 'text-indigo-400 bg-indigo-900/20 border-indigo-800' },
            { label: 'Active',    val: activeCount,      c: 'text-green-400 bg-green-900/20 border-green-800' },
            { label: 'Steps',     val: totalSteps,       c: 'text-cyan-400 bg-cyan-900/20 border-cyan-800' },
            { label: 'Runs',      val: totalRuns,        c: 'text-yellow-400 bg-yellow-900/20 border-yellow-800' },
          ].map(({ label, val, c }) => (
            <div key={label} className={`px-4 py-2 rounded-xl border text-center ${c}`}>
              <p className="text-xl font-bold">{val}</p>
              <p className="text-xs">{label}</p>
            </div>
          ))}
          <button
            onClick={() => { setEditing(null); setShowBuilder(true); }}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium text-white"
            style={{ background: 'var(--regent-600)' }}>
            <Plus className="w-4 h-4" /> New Workflow
          </button>
        </div>
      </div>

      {/* Step type legend */}
      <div className="rounded-xl border p-4" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        <p className="text-xs font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--rc-text-3)' }}>
          Step types
        </p>
        <div className="flex flex-wrap gap-2">
          {Object.entries(STEP_TYPES).map(([type, meta]) => {
            const Icon = meta.icon;
            return (
              <div key={type} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs ${meta.color} ${meta.bg} ${meta.border}`}>
                <Icon className="w-3.5 h-3.5" />
                <span className="font-medium">{meta.label}</span>
                <span className="opacity-60 hidden sm:inline">— {meta.desc}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Category filter */}
      {categories.length > 1 && (
        <div className="flex flex-wrap gap-2">
          {categories.map(cat => {
            const count = cat === 'ALL' ? workflows.length : workflows.filter(w => w.category === cat).length;
            const isActive = filterCat === cat;
            return (
              <button key={cat} onClick={() => setFilterCat(cat)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${isActive ? 'bg-indigo-600 text-white' : 'hover:opacity-80'}`}
                style={isActive ? {} : { color: 'var(--rc-text-2)', background: 'var(--rc-bg-elevated)' }}>
                {cat} <span className="opacity-70">({count})</span>
              </button>
            );
          })}
        </div>
      )}

      {/* Workflow grid */}
      {loading ? (
        <p className="p-6 text-sm" style={{ color: 'var(--rc-text-3)' }}>Loading workflows…</p>
      ) : workflows.length === 0 ? (
        <div className="rounded-xl border border-yellow-700/40 p-8 text-center" style={{ background: 'var(--rc-bg-surface)' }}>
          <GitMerge className="w-10 h-10 mx-auto mb-3 text-yellow-500 opacity-50" />
          <p className="text-yellow-400 font-semibold mb-2">No workflows yet</p>
          <p className="text-sm mb-4" style={{ color: 'var(--rc-text-2)' }}>
            Create one above, or load the example workflows:
          </p>
          <div className="space-y-2">
            <div>
              <code className="px-4 py-2 rounded text-green-400 text-sm" style={{ background: 'var(--rc-bg-elevated)' }}>
                docker compose exec backend python migrate_workflows.py
              </code>
            </div>
            <div>
              <code className="px-4 py-2 rounded text-green-400 text-sm" style={{ background: 'var(--rc-bg-elevated)' }}>
                docker compose exec backend python seed_workflows.py --reset
              </code>
            </div>
          </div>
        </div>
      ) : shown.length === 0 ? (
        <div className="rounded-xl border p-6 text-center" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>No workflows match this filter.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
          {shown.map(wf => (
            <WorkflowCard
              key={wf.id}
              workflow={wf}
              onEdit={() => setEditing(wf)}
              onDelete={() => handleDelete(wf.id)}
              onRun={() => handleRun(wf.id)}
              onViewRuns={() => setViewingRuns(wf.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
