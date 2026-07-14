'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import {
  Shield, AlertTriangle, CheckCircle, Eye, Clock,
  Zap, Lock, RefreshCw, ChevronDown, ChevronRight, Users, X,
} from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import {
  getAutonomySettings, updateAutonomySettings,
  activateEmergencyMode, deactivateEmergencyMode,
  getAutonomyAgents, updateAgentMode, bulkUpdateAgentModes,
} from '@/lib/api';
import { capabilityName } from '@/lib/capability-names';

// ─── Mode metadata ────────────────────────────────────────────────────────────
const MODES = [
  { value: 'monitor',    label: 'Monitor',    icon: Eye,           color: 'text-blue-400',   borderColor: 'border-blue-800',   bgColor: 'bg-blue-900/20',   desc: 'Observe and log only. Zero writes.', risk: 'None' },
  { value: 'assist',     label: 'Assist',     icon: Users,         color: 'text-cyan-400',   borderColor: 'border-cyan-800',   bgColor: 'bg-cyan-900/20',   desc: 'Surface findings for human review.', risk: 'Low' },
  { value: 'approval',   label: 'Approval',   icon: CheckCircle,   color: 'text-purple-400', borderColor: 'border-purple-800', bgColor: 'bg-purple-900/20', desc: 'Every write requires human approval.', risk: 'Low' },
  { value: 'autonomous', label: 'Autonomous', icon: Zap,           color: 'text-green-400',  borderColor: 'border-green-800',  bgColor: 'bg-green-900/20',  desc: 'Auto-execute pre-approved low/medium risk.', risk: 'Medium' },
  { value: 'emergency',  label: 'Emergency',  icon: AlertTriangle, color: 'text-red-400',    borderColor: 'border-red-800',    bgColor: 'bg-red-900/20',    desc: 'Containment-only. All other actions blocked.', risk: 'Controlled' },
];
const MODE_MAP = Object.fromEntries(MODES.map(m => [m.value, m]));

// ─── Toast ────────────────────────────────────────────────────────────────────
type Toast = { id: number; message: string; type: 'success' | 'error' };

function ToastContainer({ toasts, remove }: { toasts: Toast[]; remove: (id: number) => void }) {
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`flex items-start gap-3 px-4 py-3 rounded-xl shadow-2xl border text-sm font-medium ${
            t.type === 'success'
              ? 'bg-green-900/90 border-green-700 text-green-200'
              : 'bg-red-900/90 border-red-700 text-red-200'
          }`}
        >
          {t.type === 'success'
            ? <CheckCircle className="w-4 h-4 mt-0.5 flex-shrink-0 text-green-400" />
            : <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0 text-red-400" />
          }
          <span className="flex-1">{t.message}</span>
          <button onClick={() => remove(t.id)} className="opacity-60 hover:opacity-100">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────
export default function AutonomyPage() {
  const [settings, setSettings]         = useState<any>(null);
  const [agents, setAgents]             = useState<any[]>([]);
  const [loading, setLoading]           = useState(true);
  const [saving, setSaving]             = useState(false);
  const [savingAgentId, setSavingAgentId] = useState<string | null>(null);
  const [emergencyReason, setEmergencyReason] = useState('');
  const [showEmergencyModal, setShowEmergencyModal] = useState(false);
  const [bulkMode, setBulkMode]         = useState('');
  const [expandedClaws, setExpandedClaws] = useState<Set<string>>(new Set());
  const [toasts, setToasts]             = useState<Toast[]>([]);
  const toastId = useRef(0);

  const toast = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    const id = ++toastId.current;
    setToasts(t => [...t, { id, message, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4000);
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts(t => t.filter(x => x.id !== id));
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, a] = await Promise.all([
        getAutonomySettings().catch(() => null),
        getAutonomyAgents().catch(() => []),
      ]);
      setSettings(s);
      const agentList = (a ?? []) as any[];
      setAgents(agentList);
      // Auto-expand all claw groups so changes are visible
      const claws = new Set(agentList.map((ag: any) => ag.claw as string));
      setExpandedClaws(claws);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const agentsByClaw: Record<string, any[]> = {};
  for (const a of agents) {
    if (!agentsByClaw[a.claw]) agentsByClaw[a.claw] = [];
    agentsByClaw[a.claw].push(a);
  }

  const handleCeilingChange = async (mode: string) => {
    setSaving(true);
    try {
      await updateAutonomySettings({ autonomy_ceiling: mode });
      await load();
      toast(`Platform ceiling set to ${MODE_MAP[mode]?.label ?? mode}`);
    } catch (e: any) {
      toast(`Failed to update ceiling: ${e.message}`, 'error');
    } finally { setSaving(false); }
  };

  const handleFlagToggle = async (key: string, current: boolean) => {
    try {
      await updateAutonomySettings({ [key]: !current });
      await load();
      toast(`${key.replace(/_/g,' ')} ${!current ? 'enabled' : 'disabled'}`);
    } catch (e: any) {
      toast(`Failed: ${e.message}`, 'error');
    }
  };

  const handleEmergencyActivate = async () => {
    if (!emergencyReason.trim()) return;
    setSaving(true);
    try {
      await activateEmergencyMode(emergencyReason);
      setShowEmergencyModal(false);
      setEmergencyReason('');
      await load();
      toast('Emergency mode activated — all agents locked to containment-only', 'error');
    } catch (e: any) {
      toast(`Failed: ${e.message}`, 'error');
    } finally { setSaving(false); }
  };

  const handleEmergencyDeactivate = async () => {
    setSaving(true);
    try {
      await deactivateEmergencyMode();
      await load();
      toast('Emergency mode deactivated — agents restored to configured modes');
    } catch (e: any) {
      toast(`Failed: ${e.message}`, 'error');
    } finally { setSaving(false); }
  };

  const handleAgentMode = async (agentId: string, agentName: string, mode: string) => {
    setSavingAgentId(agentId);
    try {
      await updateAgentMode(agentId, mode);
      await load();
      toast(`${agentName} → ${MODE_MAP[mode]?.label ?? mode}`);
    } catch (e: any) {
      toast(`Failed to update ${agentName}: ${e.message}`, 'error');
    } finally { setSavingAgentId(null); }
  };

  const handleBulkMode = async () => {
    if (!bulkMode) return;
    setSaving(true);
    try {
      const result: any = await bulkUpdateAgentModes(bulkMode);
      setBulkMode('');
      await load();
      toast(`${result.count ?? 'All'} agents set to ${MODE_MAP[bulkMode]?.label ?? bulkMode} mode`);
    } catch (e: any) {
      toast(`Bulk update failed: ${e.message}`, 'error');
    } finally { setSaving(false); }
  };

  const toggleClaw = (claw: string) => {
    setExpandedClaws(prev => {
      const next = new Set(prev);
      if (next.has(claw)) next.delete(claw);
      else next.add(claw);
      return next;
    });
  };

  const isEmergency = settings?.emergency_mode_active;
  const ceiling = settings?.autonomy_ceiling ?? 'autonomous';

  return (
    <div className="space-y-6">
      <ToastContainer toasts={toasts} remove={removeToast} />

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Shield className="text-purple-400" /> Autonomy Mode Controls
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            Control how much the platform self-executes — per agent, per capability, or platform-wide.
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Emergency Banner */}
      {isEmergency && (
        <div className="bg-red-900/30 border border-red-700 rounded-xl px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
            <div>
              <p className="text-red-300 font-semibold">Emergency Mode Active</p>
              <p className="text-red-400 text-sm mt-0.5">
                {settings.emergency_mode_reason || 'No reason provided'} — activated by {settings.emergency_mode_activated_by || 'unknown'}
              </p>
            </div>
          </div>
          <button
            onClick={handleEmergencyDeactivate}
            disabled={saving}
            className="px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            Deactivate Emergency Mode
          </button>
        </div>
      )}

      {/* Mode reference cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {MODES.map(m => {
          const Icon = m.icon;
          const isCeiling = ceiling === m.value && !isEmergency;
          return (
            <div key={m.value} className={`relative rounded-xl border px-4 py-3 ${m.borderColor} ${m.bgColor} ${isCeiling ? 'ring-2 ring-purple-500 ring-offset-1 ring-offset-gray-950' : ''}`}>
              {isCeiling && (
                <span className="absolute -top-2 left-3 bg-gray-950 px-1.5 text-xs text-purple-400 border border-purple-700 rounded">ceiling</span>
              )}
              <div className="flex items-center gap-2 mb-1.5">
                <Icon className={`w-4 h-4 ${m.color}`} />
                <p className={`text-sm font-semibold ${m.color}`}>{m.label}</p>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed">{m.desc}</p>
              <p className="text-xs text-gray-500 mt-1.5">Blast radius: <span className={m.color}>{m.risk}</span></p>
            </div>
          );
        })}
      </div>

      {/* Platform Settings */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-purple-400" /> Platform Autonomy Settings
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">Individual agent modes cannot exceed the platform ceiling.</p>
        </div>
        <div className="px-6 py-5 grid grid-cols-1 md:grid-cols-2 gap-8">

          {/* Ceiling selector */}
          <div>
            <p className="text-sm text-white font-medium mb-1">Autonomy Ceiling</p>
            <p className="text-xs text-gray-500 mb-4">The maximum mode any agent can operate in.</p>
            <div className="space-y-2">
              {MODES.map(m => {
                const isActive = ceiling === m.value && !isEmergency;
                return (
                  <button
                    key={m.value}
                    onClick={() => handleCeilingChange(m.value)}
                    disabled={saving || isEmergency}
                    className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg border transition-all text-left disabled:opacity-50 disabled:cursor-not-allowed ${
                      isActive ? `${m.borderColor} ${m.bgColor}` : 'border-gray-800 hover:border-gray-600 hover:bg-gray-800/40'
                    }`}
                  >
                    <div className={`w-3 h-3 rounded-full border-2 flex-shrink-0 ${isActive ? `${m.color.replace('text-','border-')} bg-current` : 'border-gray-600'}`} />
                    <span className={`text-sm font-medium flex-1 ${isActive ? m.color : 'text-gray-300'}`}>{m.label}</span>
                    {isActive && <CheckCircle className={`w-4 h-4 ${m.color}`} />}
                    <span className="text-xs text-gray-500">{m.risk}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Flags + Emergency */}
          <div className="space-y-5">
            <div>
              <p className="text-sm text-white font-medium mb-3">Global Flags</p>
              <div className="space-y-3">
                {[
                  { key: 'change_window_active',     label: 'Change Window Active',     desc: 'All high/critical actions require approval' },
                  { key: 'require_mfa_for_approval', label: 'Require MFA for Approvals', desc: 'Approvers must re-authenticate first' },
                  { key: 'auto_approve_low_risk',    label: 'Auto-approve Low Risk',    desc: 'Low risk actions bypass the approval queue' },
                ].map(flag => (
                  <div key={flag.key} className="flex items-start gap-3">
                    <button
                      onClick={() => handleFlagToggle(flag.key, settings?.[flag.key])}
                      className={`flex-shrink-0 w-10 h-5 rounded-full mt-0.5 transition-colors ${settings?.[flag.key] ? 'bg-purple-600' : 'bg-gray-700'}`}
                    >
                      <div className={`w-4 h-4 bg-white rounded-full shadow transition-transform mx-0.5 ${settings?.[flag.key] ? 'translate-x-5' : 'translate-x-0'}`} />
                    </button>
                    <div>
                      <p className="text-sm text-white">{flag.label}</p>
                      <p className="text-xs text-gray-500">{flag.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className={`rounded-xl border px-5 py-4 ${isEmergency ? 'border-red-700 bg-red-900/20' : 'border-gray-800'}`}>
              <p className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
                <AlertTriangle className={`w-4 h-4 ${isEmergency ? 'text-red-400' : 'text-gray-500'}`} />
                Emergency Mode
              </p>
              <p className="text-xs text-gray-500 mb-3">Forces ALL agents to containment-only. Use during active incidents.</p>
              {isEmergency ? (
                <div className="space-y-2">
                  <p className="text-xs text-red-400">Active — {settings?.emergency_mode_reason}</p>
                  <button onClick={handleEmergencyDeactivate} className="w-full py-2 bg-red-800 hover:bg-red-700 text-white rounded-lg text-sm font-medium">
                    Deactivate Emergency Mode
                  </button>
                </div>
              ) : (
                <button onClick={() => setShowEmergencyModal(true)} className="w-full py-2 bg-red-900/40 border border-red-800 hover:bg-red-900/60 text-red-400 rounded-lg text-sm font-medium">
                  Activate Emergency Mode
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Bulk Mode Update */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl px-6 py-4">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex-1 min-w-0">
            <p className="text-sm text-white font-medium">Bulk Mode Update</p>
            <p className="text-xs text-gray-500 mt-0.5">Set all agents to a specific mode at once</p>
          </div>
          <select
            value={bulkMode}
            onChange={e => setBulkMode(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500"
          >
            <option value="">Select mode…</option>
            {MODES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
          </select>
          <button
            onClick={handleBulkMode}
            disabled={!bulkMode || saving}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
          >
            {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : null}
            Apply to All
          </button>
        </div>
        {/* Live preview of what will change */}
        {bulkMode && (
          <div className={`mt-3 px-3 py-2 rounded-lg border text-xs flex items-center gap-2 ${MODE_MAP[bulkMode]?.bgColor ?? ''} ${MODE_MAP[bulkMode]?.borderColor ?? 'border-gray-700'}`}>
            <span className={MODE_MAP[bulkMode]?.color ?? 'text-white'}>
              {MODE_MAP[bulkMode]?.label}
            </span>
            <span className="text-gray-400">— {MODE_MAP[bulkMode]?.desc}</span>
            <span className="ml-auto text-gray-500">{agents.length} agents will be updated</span>
          </div>
        )}
      </div>

      {/* Per-agent table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-semibold text-white">Per-Agent Mode Configuration</h2>
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-500">{agents.length} agents</span>
            <button
              onClick={() => setExpandedClaws(expandedClaws.size > 0 ? new Set() : new Set(Object.keys(agentsByClaw)))}
              className="text-xs text-gray-400 hover:text-white"
            >
              {expandedClaws.size > 0 ? 'Collapse all' : 'Expand all'}
            </button>
          </div>
        </div>

        {agents.length === 0 ? (
          <p className="px-6 py-6 text-gray-500 text-sm">No agents found. Run the seed script first.</p>
        ) : (
          Object.entries(agentsByClaw).map(([claw, clawAgents]) => {
            const isOpen = expandedClaws.has(claw);
            const hasDowngraded = clawAgents.some((a: any) => a.effective_mode !== a.configured_mode);

            return (
              <div key={claw} className="border-b border-gray-800 last:border-0">
                <button
                  onClick={() => toggleClaw(claw)}
                  className="w-full px-6 py-3.5 flex items-center gap-3 hover:bg-gray-800/30 transition-colors text-left"
                >
                  {isOpen ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                  <p className="text-white text-sm font-medium flex-1">{capabilityName(claw)}</p>
                  <span className="text-xs text-gray-500">{clawAgents.length} agents</span>
                  {hasDowngraded && (
                    <span className="text-xs text-yellow-400 flex items-center gap-1 ml-2">
                      <AlertTriangle className="w-3 h-3" /> ceiling applied
                    </span>
                  )}
                </button>

                {isOpen && (
                  <div className="px-6 pb-3">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-gray-800 text-gray-500 text-xs">
                          <th className="py-2 text-left">Agent</th>
                          <th className="py-2 text-left">Configured</th>
                          <th className="py-2 text-left">Effective</th>
                          <th className="py-2 text-left">Risk</th>
                          <th className="py-2 text-left w-40">Change Mode</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800/50">
                        {clawAgents.map((agent: any) => {
                          const configMeta  = MODE_MAP[agent.configured_mode];
                          const effMeta     = MODE_MAP[agent.effective_mode];
                          const downgraded  = agent.effective_mode !== agent.configured_mode;
                          const isSaving    = savingAgentId === agent.id;
                          return (
                            <tr key={agent.id} className={`hover:bg-gray-800/20 ${isSaving ? 'opacity-60' : ''}`}>
                              <td className="py-2.5 text-white text-xs">{agent.name}</td>
                              <td className="py-2.5">
                                <span className={`text-xs font-medium ${configMeta?.color ?? 'text-gray-400'}`}>
                                  {configMeta?.label ?? agent.configured_mode}
                                </span>
                              </td>
                              <td className="py-2.5">
                                <span className={`text-xs font-medium flex items-center gap-1 ${effMeta?.color ?? 'text-gray-400'}`}>
                                  {isSaving
                                    ? <RefreshCw className="w-3 h-3 animate-spin" />
                                    : effMeta?.label ?? agent.effective_mode
                                  }
                                  {downgraded && !isSaving && <span title="Capped by platform ceiling"><AlertTriangle className="w-3 h-3 text-yellow-400" /></span>}
                                </span>
                              </td>
                              <td className="py-2.5"><RiskBadge value={agent.risk_level} /></td>
                              <td className="py-2.5">
                                <select
                                  value={agent.configured_mode}
                                  onChange={e => handleAgentMode(agent.id, agent.name, e.target.value)}
                                  disabled={isEmergency || isSaving}
                                  className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-purple-500 disabled:opacity-50 w-full"
                                >
                                  {MODES.map(m => (
                                    <option key={m.value} value={m.value}>{m.label}</option>
                                  ))}
                                </select>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Emergency Modal */}
      {showEmergencyModal && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-red-700 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-red-800 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h2 className="font-semibold text-white">Activate Emergency Mode</h2>
            </div>
            <div className="px-6 py-5 space-y-4">
              <p className="text-sm text-gray-300">
                This immediately forces ALL agents platform-wide to containment-only mode.
                Only isolate/block/quarantine actions will be permitted until deactivated.
              </p>
              <div>
                <label className="block text-xs text-gray-400 mb-1.5">Reason (required)</label>
                <input
                  value={emergencyReason}
                  onChange={e => setEmergencyReason(e.target.value)}
                  placeholder="e.g. Active ransomware incident — contain blast radius"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-red-500"
                />
              </div>
            </div>
            <div className="px-6 py-4 border-t border-red-800 flex items-center justify-end gap-3">
              <button onClick={() => setShowEmergencyModal(false)} className="px-4 py-2 text-sm text-gray-400 hover:text-white">
                Cancel
              </button>
              <button
                onClick={handleEmergencyActivate}
                disabled={saving || !emergencyReason.trim()}
                className="flex items-center gap-2 px-5 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-semibold rounded-lg text-sm"
              >
                {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : null}
                Activate Emergency Mode
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
