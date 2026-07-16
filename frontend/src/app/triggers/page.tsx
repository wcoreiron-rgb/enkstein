'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  Zap, Plus, Trash2, ToggleLeft, ToggleRight,
  Webhook, AlertTriangle, Activity, Search,
  ChevronDown, ChevronRight, CheckCircle, XCircle,
  RefreshCw, Play, Clock,
} from 'lucide-react';
import { getTriggers, getTriggerStats, createTrigger, updateTrigger, deleteTrigger, getWorkflows, testTrigger } from '@/lib/api';
import ClientDate from '@/components/ClientDate';
import { capabilityName } from '@/lib/capability-names';

// ─── Trigger type metadata ────────────────────────────────────────────────────

const TRIGGER_TYPE_META: Record<string, { label: string; icon: React.ElementType; color: string; desc: string }> = {
  finding_created:   { label: 'Finding Created',   icon: AlertTriangle, color: 'text-orange-400', desc: 'Fires when a new finding is ingested by any claw' },
  finding_escalated: { label: 'Finding Escalated', icon: Activity,      color: 'text-red-400',    desc: 'Fires when an existing finding severity increases' },
  event_created:     { label: 'Event Created',     icon: Activity,      color: 'text-blue-400',   desc: 'Fires when a platform event is written to the audit bus' },
  webhook_inbound:   { label: 'Webhook Inbound',   icon: Webhook,       color: 'text-cyan-400',   desc: 'Fires when an external HTTP POST arrives at the webhook URL' },
};

const ACTION_TYPE_META: Record<string, { label: string; color: string }> = {
  fire_workflow: { label: 'Launch Workflow', color: 'text-purple-400' },
  fire_scan:     { label: 'Trigger Scan',   color: 'text-green-400'  },
  fire_alert:    { label: 'Send Alert',     color: 'text-yellow-400' },
  start_swarm:   { label: 'Start Swarm',    color: 'text-cyan-400'   },
  fire_swarm:    { label: 'Fire Swarm',     color: 'text-cyan-400'   },
};

const OPERATOR_LABELS: Record<string, string> = {
  eq: '=', neq: '≠', gt: '>', gte: '≥', lt: '<', lte: '≤',
  contains: 'contains', not_contains: 'not contains', in: 'in', not_in: 'not in',
};

// ─── New trigger form defaults ────────────────────────────────────────────────

const BLANK_FORM = {
  name: '',
  description: '',
  trigger_type: 'finding_created',
  source_filter: '',
  severity_min: '',
  action_type: 'fire_workflow',
  workflow_id: '',
  target_claw: '',
  cooldown_seconds: 300,
  category: 'detection',
  conditions: [{ field: 'severity', op: 'gte', value: 'high' }],
  swarm_profile: 'INCIDENT_RESPONSE',
  swarm_task_type: 'investigate',
  swarm_parallelism: 3,
  swarm_classification: 'internal',
  swarm_model_profile: '',
  swarm_requires_approval: true,
  alert_title: '',
  alert_description: '',
  alert_severity: 'medium',
};

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function TriggersPage() {
  const [triggers, setTriggers]     = useState<any[]>([]);
  const [stats, setStats]           = useState<any[]>([]);
  const [workflows, setWorkflows]   = useState<any[]>([]);
  const [loading, setLoading]       = useState(true);
  const [showForm, setShowForm]     = useState(false);
  const [form, setForm]             = useState({ ...BLANK_FORM, conditions: [...BLANK_FORM.conditions] });
  const [saving, setSaving]         = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [search, setSearch]         = useState('');
  const [testingId, setTestingId]   = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, any>>({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [t, s, w] = await Promise.all([
        getTriggers().catch(() => []),
        getTriggerStats().catch(() => []),
        getWorkflows().catch(() => []),
      ]);
      setTriggers(t ?? []);
      setStats(s ?? []);
      setWorkflows(w ?? []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // ── Derived stats ──────────────────────────────────────────────────────────
  const totalActive  = triggers.filter(t => t.is_active).length;
  const totalFires   = triggers.reduce((s: number, t: any) => s + (t.trigger_count || 0), 0);
  const webhookCount = triggers.filter(t => t.trigger_type === 'webhook_inbound').length;

  const filtered = triggers.filter(t =>
    !search || t.name.toLowerCase().includes(search.toLowerCase()) ||
    (t.description || '').toLowerCase().includes(search.toLowerCase())
  );

  // ── Toggle active state ────────────────────────────────────────────────────
  const toggleActive = async (trigger: any) => {
    await updateTrigger(trigger.id, { is_active: !trigger.is_active });
    await load();
  };

  // ── Delete ─────────────────────────────────────────────────────────────────
  const handleDelete = async (id: string) => {
    if (!confirm('Delete this trigger?')) return;
    await deleteTrigger(id);
    await load();
  };

  const runTest = async (trigger: any) => {
    setTestingId(trigger.id);
    const samplePayload = {
      source_module: trigger.source_filter || 'identityclaw',
      severity: trigger.severity_min || 'high',
      risk_score: 80,
      category: trigger.category || 'detection',
      outcome: 'allowed',
      action: 'simulated_test',
      provider: 'test-provider',
      claw: trigger.target_claw || 'identityclaw',
    };
    try {
      const result = await testTrigger(trigger.id, samplePayload);
      setTestResults(prev => ({ ...prev, [trigger.id]: result }));
      await load();
    } catch (error: any) {
      setTestResults(prev => ({
        ...prev,
        [trigger.id]: { matched: false, error: error?.message || 'Test failed' },
      }));
    } finally {
      setTestingId(null);
    }
  };

  // ── Form submission ────────────────────────────────────────────────────────
  const handleSave = async () => {
    if (!form.name.trim()) return;
    setSaving(true);
    try {
      const payload: any = {
        name:             form.name,
        description:      form.description || undefined,
        trigger_type:     form.trigger_type,
        source_filter:    form.source_filter || undefined,
        severity_min:     form.severity_min || undefined,
        action_type:      form.action_type,
        workflow_id:      form.workflow_id || undefined,
        target_claw:      form.target_claw || undefined,
        cooldown_seconds: form.cooldown_seconds,
        category:         form.category || undefined,
        conditions_json:  JSON.stringify(form.conditions),
      };
      if (form.action_type === 'fire_alert') {
        payload.alert_config_json = JSON.stringify({
          title: form.alert_title || undefined,
          description: form.alert_description || undefined,
          severity: form.alert_severity || 'medium',
        });
      }
      if (form.action_type === 'start_swarm' || form.action_type === 'fire_swarm') {
        const participants = form.target_claw
          .split(',')
          .map((v: string) => v.trim())
          .filter(Boolean);
        payload.alert_config_json = JSON.stringify({
          profile: form.swarm_profile,
          task_type: form.swarm_task_type,
          parallelism: form.swarm_parallelism,
          classification: form.swarm_classification,
          model_profile: form.swarm_model_profile || undefined,
          requires_approval_for_actions: form.swarm_requires_approval,
          ...(participants.length ? { participants } : {}),
        });
      }
      await createTrigger(payload);
      setShowForm(false);
      setForm({ ...BLANK_FORM, conditions: [{ field: 'severity', op: 'gte', value: 'high' }] });
      await load();
    } finally {
      setSaving(false);
    }
  };

  // ── Condition helpers ──────────────────────────────────────────────────────
  const addCondition = () => setForm(f => ({
    ...f, conditions: [...f.conditions, { field: '', op: 'eq', value: '' }]
  }));
  const removeCondition = (i: number) => setForm(f => ({
    ...f, conditions: f.conditions.filter((_, idx) => idx !== i)
  }));
  const updateCondition = (i: number, key: string, val: string) => setForm(f => ({
    ...f,
    conditions: f.conditions.map((c, idx) => idx === i ? { ...c, [key]: val } : c),
  }));

  // ── Parse conditions for display ──────────────────────────────────────────
  const parseConditions = (json: string) => {
    try { return JSON.parse(json); } catch { return []; }
  };

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Zap className="text-yellow-400" /> Event Trigger System
          </h1>
          <p className="text-gray-400 mt-1">
            Reactive rules that auto-launch workflows when findings, events, or webhooks match conditions
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={load}
            className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setShowForm(true)}
            className="flex items-center gap-2 px-4 py-2 bg-yellow-500 hover:bg-yellow-400 text-black font-semibold rounded-lg text-sm transition-colors"
          >
            <Plus className="w-4 h-4" /> New Trigger
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Active Triggers', value: totalActive,             color: 'text-green-400',  icon: <CheckCircle className="w-5 h-5 text-green-400" /> },
          { label: 'Total Triggers',  value: triggers.length,         color: 'text-white',      icon: <Zap className="w-5 h-5 text-yellow-400" /> },
          { label: 'Total Fires',     value: totalFires,              color: 'text-purple-400', icon: <Play className="w-5 h-5 text-purple-400" /> },
          { label: 'Webhook Endpoints', value: webhookCount,          color: 'text-cyan-400',   icon: <Webhook className="w-5 h-5 text-cyan-400" /> },
        ].map(s => (
          <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
            <div className="flex items-start justify-between mb-2">
              <p className="text-xs text-gray-500">{s.label}</p>
              {s.icon}
            </div>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Trigger type breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {Object.entries(TRIGGER_TYPE_META).map(([type, meta]) => {
          const Icon = meta.icon;
          const count = triggers.filter(t => t.trigger_type === type).length;
          const fires = triggers.filter(t => t.trigger_type === type)
            .reduce((s: number, t: any) => s + (t.trigger_count || 0), 0);
          return (
            <div key={type} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
              <div className="flex items-center gap-2 mb-1">
                <Icon className={`w-4 h-4 ${meta.color}`} />
                <p className={`text-xs font-medium ${meta.color}`}>{meta.label}</p>
              </div>
              <p className="text-xl font-bold text-white">{count}</p>
              <p className="text-xs text-gray-500 mt-0.5">{fires} fires</p>
            </div>
          );
        })}
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search triggers…"
          className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
        />
      </div>

      {/* Trigger list */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-semibold text-white">Trigger Definitions</h2>
          <span className="text-xs text-gray-500">{filtered.length} triggers</span>
        </div>

        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <Zap className="w-10 h-10 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-500 text-sm">
              {search ? 'No triggers match your search.' : 'No triggers defined yet.'}
            </p>
            <p className="text-gray-600 text-xs mt-1">
              Create a trigger to auto-launch workflows when findings or events match conditions.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {filtered.map((trigger: any) => {
              const meta = TRIGGER_TYPE_META[trigger.trigger_type] ?? TRIGGER_TYPE_META.event_created;
              const Icon = meta.icon;
              const actionMeta = ACTION_TYPE_META[trigger.action_type] ?? ACTION_TYPE_META.fire_workflow;
              const conditions = parseConditions(trigger.conditions_json);
              const isExpanded = expandedId === trigger.id;

              return (
                <div key={trigger.id} className="hover:bg-gray-800/30 transition-colors">
                  {/* Main row */}
                  <div className="px-6 py-4 flex items-center gap-4">
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : trigger.id)}
                      className="flex-shrink-0 text-gray-600 hover:text-gray-400"
                    >
                      {isExpanded
                        ? <ChevronDown className="w-4 h-4" />
                        : <ChevronRight className="w-4 h-4" />
                      }
                    </button>

                    {/* Type icon */}
                    <div className={`flex-shrink-0 ${meta.color}`}>
                      <Icon className="w-4 h-4" />
                    </div>

                    {/* Name + description */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-white text-sm font-medium truncate">{trigger.name}</p>
                        {trigger.category && (
                          <span className="text-xs text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">
                            {trigger.category}
                          </span>
                        )}
                      </div>
                      {trigger.description && (
                        <p className="text-xs text-gray-400 mt-0.5 truncate">{trigger.description}</p>
                      )}
                    </div>

                    {/* Type badge */}
                    <span className={`text-xs ${meta.color} flex-shrink-0 hidden md:block`}>
                      {meta.label}
                    </span>

                    {/* Action */}
                    <span className={`text-xs ${actionMeta.color} flex-shrink-0 hidden md:block`}>
                      {actionMeta.label}
                    </span>

                    {/* Fire count */}
                    <div className="flex items-center gap-1 text-xs text-gray-500 flex-shrink-0">
                      <Play className="w-3 h-3" />
                      {trigger.trigger_count || 0}
                    </div>

                    {/* Cooldown */}
                    <div className="flex items-center gap-1 text-xs text-gray-500 flex-shrink-0">
                      <Clock className="w-3 h-3" />
                      {trigger.cooldown_seconds}s
                    </div>

                    {/* Active toggle */}
                    <button
                      onClick={() => toggleActive(trigger)}
                      className={trigger.is_active ? 'text-green-400' : 'text-gray-600'}
                      title={trigger.is_active ? 'Disable trigger' : 'Enable trigger'}
                    >
                      {trigger.is_active
                        ? <ToggleRight className="w-5 h-5" />
                        : <ToggleLeft className="w-5 h-5" />
                      }
                    </button>

                    {/* Delete */}
                    <button
                      onClick={() => handleDelete(trigger.id)}
                      className="text-gray-700 hover:text-red-400 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>

                  {/* Expanded detail */}
                  {isExpanded && (
                    <div className="px-16 pb-5 space-y-3">
                      {/* Conditions */}
                      <div>
                        <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Conditions (ALL must match)</p>
                        {conditions.length === 0 ? (
                          <p className="text-xs text-gray-600">No conditions — fires on every matching event</p>
                        ) : (
                          <div className="flex flex-wrap gap-2">
                            {conditions.map((c: any, i: number) => (
                              <span key={i} className="inline-flex items-center gap-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300">
                                <span className="text-gray-500">{c.field}</span>
                                <span className="text-yellow-400">{OPERATOR_LABELS[c.op] || c.op}</span>
                                <span className="text-white">{String(c.value)}</span>
                              </span>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Metadata */}
                      <div className="flex flex-wrap gap-6 text-xs text-gray-400">
                        {trigger.source_filter && (
                          <span><span className="text-gray-500">Source filter: </span>{trigger.source_filter}</span>
                        )}
                        {trigger.severity_min && (
                          <span><span className="text-gray-500">Min severity: </span>{trigger.severity_min}</span>
                        )}
                        {trigger.workflow_id && (
                          <span><span className="text-gray-500">Workflow ID: </span>{trigger.workflow_id}</span>
                        )}
                        {trigger.target_claw && (
                          <span><span className="text-gray-500">Target capability: </span>{capabilityName(trigger.target_claw)}</span>
                        )}
                        {trigger.last_triggered_at && (
                          <span><span className="text-gray-500">Last fired: </span><ClientDate value={trigger.last_triggered_at} /></span>
                        )}
                        {trigger.trigger_type === 'webhook_inbound' && (
                          <span className="text-cyan-400">
                            Webhook URL: /api/v1/triggers/webhook/{trigger.id}
                          </span>
                        )}
                      </div>

                      <div className="pt-1 flex items-center gap-3">
                        <button
                          onClick={() => runTest(trigger)}
                          disabled={testingId === trigger.id}
                          className="inline-flex items-center gap-1.5 rounded border border-yellow-800 bg-yellow-950/40 px-2.5 py-1 text-xs text-yellow-300 hover:bg-yellow-900/40 disabled:opacity-60"
                        >
                          {testingId === trigger.id ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                          Test Trigger
                        </button>
                        {testResults[trigger.id] && (
                          <span className={`text-xs ${testResults[trigger.id].matched ? 'text-green-300' : 'text-red-300'}`}>
                            {testResults[trigger.id].matched ? 'Matched sample payload' : (testResults[trigger.id].error || 'Did not match sample payload')}
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Create Trigger Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
              <h2 className="font-semibold text-white text-lg">New Event Trigger</h2>
              <button onClick={() => setShowForm(false)} className="text-gray-500 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="px-6 py-5 space-y-5">

              {/* Name */}
              <div>
                <label className="block text-xs text-gray-400 mb-1.5">Trigger Name *</label>
                <input
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. Auto-contain critical endpoint findings"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs text-gray-400 mb-1.5">Description</label>
                <input
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="What does this trigger do?"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                />
              </div>

              {/* Trigger type + action type row */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Trigger Type</label>
                  <select
                    value={form.trigger_type}
                    onChange={e => setForm(f => ({ ...f, trigger_type: e.target.value }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-yellow-500"
                  >
                    {Object.entries(TRIGGER_TYPE_META).map(([val, { label }]) => (
                      <option key={val} value={val}>{label}</option>
                    ))}
                  </select>
                  <p className="text-xs text-gray-600 mt-1">{TRIGGER_TYPE_META[form.trigger_type]?.desc}</p>
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Action Type</label>
                  <select
                    value={form.action_type}
                    onChange={e => setForm(f => ({ ...f, action_type: e.target.value }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-yellow-500"
                  >
                    {Object.entries(ACTION_TYPE_META).map(([val, { label }]) => (
                      <option key={val} value={val}>{label}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Workflow picker (if fire_workflow) */}
              {form.action_type === 'fire_workflow' && (
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Workflow to Launch</label>
                  <select
                    value={form.workflow_id}
                    onChange={e => setForm(f => ({ ...f, workflow_id: e.target.value }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-yellow-500"
                  >
                    <option value="">— select a workflow —</option>
                    {workflows.map((w: any) => (
                      <option key={w.id} value={w.id}>{w.name}</option>
                    ))}
                  </select>
                </div>
              )}

              {/* Target claw (if fire_scan) */}
              {form.action_type === 'fire_scan' && (
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Target Capability</label>
                  <input
                    value={form.target_claw}
                    onChange={e => setForm(f => ({ ...f, target_claw: e.target.value }))}
                    placeholder="e.g. cloudclaw, exposureclaw"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                  />
                </div>
              )}

              {(form.action_type === 'start_swarm' || form.action_type === 'fire_swarm') && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">Swarm Profile</label>
                    <select
                      value={form.swarm_profile}
                      onChange={e => setForm(f => ({ ...f, swarm_profile: e.target.value }))}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-yellow-500"
                    >
                      <option value="FAST_TRIAGE">FAST_TRIAGE</option>
                      <option value="DEEP_INVESTIGATION">DEEP_INVESTIGATION</option>
                      <option value="INCIDENT_RESPONSE">INCIDENT_RESPONSE</option>
                      <option value="AUTONOMOUS_LOW_RISK">AUTONOMOUS_LOW_RISK</option>
                      <option value="EMERGENCY_CONTAINMENT">EMERGENCY_CONTAINMENT</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">Task Type</label>
                    <input
                      value={form.swarm_task_type}
                      onChange={e => setForm(f => ({ ...f, swarm_task_type: e.target.value }))}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">Participants (comma-separated capabilities)</label>
                    <input
                      value={form.target_claw}
                      onChange={e => setForm(f => ({ ...f, target_claw: e.target.value }))}
                      placeholder="identityclaw,threatclaw,cloudclaw"
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">Parallelism</label>
                    <input
                      type="number"
                      min={1}
                      max={24}
                      value={form.swarm_parallelism}
                      onChange={e => setForm(f => ({ ...f, swarm_parallelism: parseInt(e.target.value, 10) || 3 }))}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-yellow-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">Classification</label>
                    <input
                      value={form.swarm_classification}
                      onChange={e => setForm(f => ({ ...f, swarm_classification: e.target.value }))}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">Model Profile (optional)</label>
                    <input
                      value={form.swarm_model_profile}
                      onChange={e => setForm(f => ({ ...f, swarm_model_profile: e.target.value }))}
                      placeholder="swarm_judge_incident"
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                    />
                  </div>
                  <label className="col-span-2 flex items-center gap-2 text-xs text-gray-300">
                    <input
                      type="checkbox"
                      checked={form.swarm_requires_approval}
                      onChange={e => setForm(f => ({ ...f, swarm_requires_approval: e.target.checked }))}
                      className="rounded border-gray-600 bg-gray-800 text-yellow-500 focus:ring-yellow-500"
                    />
                    Require approval before swarm execution
                  </label>
                </div>
              )}

              {form.action_type === 'fire_alert' && (
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">Alert Title</label>
                    <input
                      value={form.alert_title}
                      onChange={e => setForm(f => ({ ...f, alert_title: e.target.value }))}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">Severity</label>
                    <select
                      value={form.alert_severity}
                      onChange={e => setForm(f => ({ ...f, alert_severity: e.target.value }))}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-yellow-500"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                  <div className="col-span-3">
                    <label className="block text-xs text-gray-400 mb-1.5">Alert Description</label>
                    <input
                      value={form.alert_description}
                      onChange={e => setForm(f => ({ ...f, alert_description: e.target.value }))}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                    />
                  </div>
                </div>
              )}

              {/* Filters row */}
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Source Filter</label>
                  <input
                    value={form.source_filter}
                    onChange={e => setForm(f => ({ ...f, source_filter: e.target.value }))}
                    placeholder="e.g. endpointclaw"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Min Severity</label>
                  <select
                    value={form.severity_min}
                    onChange={e => setForm(f => ({ ...f, severity_min: e.target.value }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-yellow-500"
                  >
                    <option value="">Any</option>
                    <option value="info">Info</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Cooldown (seconds)</label>
                  <input
                    type="number"
                    value={form.cooldown_seconds}
                    onChange={e => setForm(f => ({ ...f, cooldown_seconds: parseInt(e.target.value) || 300 }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-yellow-500"
                  />
                </div>
              </div>

              {/* Conditions */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-xs text-gray-400 uppercase tracking-wide">Conditions (AND logic)</label>
                  <button
                    onClick={addCondition}
                    className="text-xs text-yellow-400 hover:text-yellow-300 flex items-center gap-1"
                  >
                    <Plus className="w-3 h-3" /> Add condition
                  </button>
                </div>
                <div className="space-y-2">
                  {form.conditions.map((cond, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <input
                        value={cond.field}
                        onChange={e => updateCondition(i, 'field', e.target.value)}
                        placeholder="field (e.g. severity)"
                        className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                      />
                      <select
                        value={cond.op}
                        onChange={e => updateCondition(i, 'op', e.target.value)}
                        className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-yellow-400 focus:outline-none"
                      >
                        {Object.entries(OPERATOR_LABELS).map(([val, label]) => (
                          <option key={val} value={val}>{label}</option>
                        ))}
                      </select>
                      <input
                        value={cond.value}
                        onChange={e => updateCondition(i, 'value', e.target.value)}
                        placeholder="value (e.g. high)"
                        className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500"
                      />
                      <button
                        onClick={() => removeCondition(i)}
                        className="text-gray-600 hover:text-red-400"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
                <p className="text-xs text-gray-600 mt-2">
                  Supported fields: severity, risk_score, claw, provider, category, resource_type, actively_exploited, source_module, action, outcome
                </p>
              </div>

            </div>

            <div className="px-6 py-4 border-t border-gray-800 flex items-center justify-end gap-3">
              <button
                onClick={() => setShowForm(false)}
                className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !form.name.trim()}
                className="px-5 py-2 bg-yellow-500 hover:bg-yellow-400 disabled:opacity-50 text-black font-semibold rounded-lg text-sm transition-colors"
              >
                {saving ? 'Creating…' : 'Create Trigger'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reference panel */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold text-white text-sm">Condition Field Reference</h2>
        </div>
        <div className="px-6 py-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          {[
            { group: 'Finding fields',  fields: ['severity', 'claw', 'provider', 'risk_score', 'category', 'resource_type', 'actively_exploited', 'status'] },
            { group: 'Event fields',    fields: ['source_module', 'action', 'outcome', 'severity', 'risk_score', 'is_anomaly', 'actor_type', 'target_type'] },
            { group: 'Operators',       fields: ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'contains', 'not_contains', 'in', 'not_in'] },
            { group: 'Severity values', fields: ['info', 'low', 'medium', 'high', 'critical'] },
          ].map(g => (
            <div key={g.group}>
              <p className="text-gray-500 uppercase tracking-wide text-xs mb-2">{g.group}</p>
              <div className="flex flex-wrap gap-1">
                {g.fields.map(f => (
                  <span key={f} className="bg-gray-800 text-gray-300 px-1.5 py-0.5 rounded text-xs font-mono">{f}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
