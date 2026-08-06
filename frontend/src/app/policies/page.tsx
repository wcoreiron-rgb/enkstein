'use client';
import { useEffect, useState } from 'react';
import {
  FileText, Shield, Cpu, Zap, Users, CheckCircle, XCircle,
  Clock, Eye, X, Save, Pencil, Trash2,
  Cloud, Key, Monitor, Globe, Database, Code, Package,
  Target, BookOpen, Search, UserCheck, UserX,
  Bot, GitMerge, Radar, ClipboardCheck, Lock, Handshake,
  GitBranch, Settings, RefreshCcw, Network,
} from 'lucide-react';
import { getPolicies, updatePolicy, deletePolicy } from '@/lib/api';
import { capabilityName, marcellusText } from '@/lib/capability-names';
import OverlayPortal from '@/components/OverlayPortal';

// ── Layer metadata ─────────────────────────────────────────────────────────────

const LAYER_META: Record<string, {
  color: string;
  bg: string;
  border: string;
  icon: React.ElementType;
  category: string;
  label?: string; // display name for non-capability layers; capability layers resolve via capabilityName()
}> = {
  'TRUST FABRIC':    { color: 'text-indigo-400',  bg: 'bg-indigo-900/30',  border: 'border-indigo-800',  icon: Shield,        category: 'Platform',      label: 'Trust Fabric'    },
  'COREOS':          { color: 'text-cyan-400',     bg: 'bg-cyan-900/30',    border: 'border-cyan-800',    icon: Cpu,           category: 'Platform',      label: 'CoreOS'          },
  'ARCCLAW':         { color: 'text-yellow-400',   bg: 'bg-yellow-900/30',  border: 'border-yellow-800',  icon: Zap,           category: 'Core Security' },
  'CLOUDCLAW':       { color: 'text-sky-400',      bg: 'bg-sky-900/30',     border: 'border-sky-800',     icon: Cloud,         category: 'Core Security' },
  'IDENTITYCLAW':    { color: 'text-blue-400',     bg: 'bg-blue-900/30',    border: 'border-blue-800',    icon: Users,         category: 'Core Security' },
  'ACCESSCLAW':      { color: 'text-amber-400',    bg: 'bg-amber-900/30',   border: 'border-amber-800',   icon: Key,           category: 'Core Security' },
  'ENDPOINTCLAW':    { color: 'text-orange-400',   bg: 'bg-orange-900/30',  border: 'border-orange-800',  icon: Monitor,       category: 'Core Security' },
  'NETCLAW':         { color: 'text-teal-400',     bg: 'bg-teal-900/30',    border: 'border-teal-800',    icon: Network,       category: 'Core Security' },
  'DATACLAW':        { color: 'text-emerald-400',  bg: 'bg-emerald-900/30', border: 'border-emerald-800', icon: Database,      category: 'Core Security' },
  'APPCLAW':         { color: 'text-blue-300',     bg: 'bg-blue-900/20',    border: 'border-blue-700',    icon: Code,          category: 'Core Security' },
  'SAASCLAW':        { color: 'text-violet-400',   bg: 'bg-violet-900/30',  border: 'border-violet-800',  icon: Package,       category: 'Core Security' },
  'THREATCLAW':      { color: 'text-red-400',      bg: 'bg-red-900/30',     border: 'border-red-800',     icon: Target,        category: 'Detection' },
  'LOGCLAW':         { color: 'text-cyan-300',     bg: 'bg-cyan-900/20',    border: 'border-cyan-700',    icon: BookOpen,      category: 'Detection' },
  'INTELCLAW':       { color: 'text-purple-400',   bg: 'bg-purple-900/30',  border: 'border-purple-800',  icon: Search,        category: 'Detection' },
  'USERCLAW':        { color: 'text-pink-400',     bg: 'bg-pink-900/30',    border: 'border-pink-800',    icon: UserCheck,     category: 'Detection' },
  'INSIDERCLAW':     { color: 'text-rose-400',     bg: 'bg-rose-900/30',    border: 'border-rose-800',    icon: UserX,         category: 'Detection' },
  'AUTOMATIONCLAW':  { color: 'text-blue-400',     bg: 'bg-blue-900/25',    border: 'border-blue-700',    icon: Bot,           category: 'SecOps' },
  'ATTACKPATHCLAW':  { color: 'text-red-300',      bg: 'bg-red-900/20',     border: 'border-red-700',     icon: GitMerge,      category: 'SecOps' },
  'EXPOSURECLAW':    { color: 'text-yellow-300',   bg: 'bg-yellow-900/20',  border: 'border-yellow-700',  icon: Radar,         category: 'SecOps' },
  'COMPLIANCECLAW':  { color: 'text-green-400',    bg: 'bg-green-900/30',   border: 'border-green-800',   icon: ClipboardCheck,category: 'Governance' },
  'PRIVACYCLAW':     { color: 'text-violet-300',   bg: 'bg-violet-900/20',  border: 'border-violet-700',  icon: Lock,          category: 'Governance' },
  'VENDORCLAW':      { color: 'text-teal-300',     bg: 'bg-teal-900/20',    border: 'border-teal-700',    icon: Handshake,     category: 'Governance' },
  'DEVCLAW':         { color: 'text-indigo-300',   bg: 'bg-indigo-900/20',  border: 'border-indigo-700',  icon: GitBranch,     category: 'Infrastructure' },
  'CONFIGCLAW':      { color: 'text-sky-300',      bg: 'bg-sky-900/20',     border: 'border-sky-700',     icon: Settings,      category: 'Infrastructure' },
  'RECOVERYCLAW':    { color: 'text-emerald-300',  bg: 'bg-emerald-900/20', border: 'border-emerald-700', icon: RefreshCcw,    category: 'Infrastructure' },
};

const CATEGORIES = ['ALL', 'Platform', 'Core Security', 'Detection', 'SecOps', 'Governance', 'Infrastructure'];

const CATEGORY_COLORS: Record<string, string> = {
  'Platform':       'bg-indigo-600',
  'Core Security':  'bg-yellow-600',
  'Detection':      'bg-red-600',
  'SecOps':         'bg-blue-700',
  'Governance':     'bg-green-700',
  'Infrastructure': 'bg-violet-700',
};

// ── Action styles ─────────────────────────────────────────────────────────────

const ACTION_STYLE: Record<string, { color: string; label: string; icon: typeof CheckCircle }> = {
  deny:             { color: 'text-red-400 bg-red-900/30 border-red-800',          label: 'BLOCK',   icon: XCircle },
  require_approval: { color: 'text-yellow-400 bg-yellow-900/30 border-yellow-800', label: 'APPROVE', icon: Clock },
  monitor:          { color: 'text-blue-400 bg-blue-900/30 border-blue-800',       label: 'MONITOR', icon: Eye },
  allow:            { color: 'text-green-400 bg-green-900/30 border-green-800',    label: 'ALLOW',   icon: CheckCircle },
  isolate:          { color: 'text-purple-400 bg-purple-900/30 border-purple-800', label: 'ISOLATE', icon: Shield },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function getLayer(desc: string): string {
  if (!desc) return 'GLOBAL';
  const prefix = desc.split('|')[0].trim().toUpperCase();
  // Match longest known key first to avoid partial matches
  const sorted = Object.keys(LAYER_META).sort((a, b) => b.length - a.length);
  for (const key of sorted) {
    if (prefix === key) return key;
  }
  return 'GLOBAL';
}

function getDescription(desc: string): string {
  if (!desc) return '';
  return marcellusText(desc.replace(/^[^|]+\|/, '').trim());
}

function layerDisplayName(layer: string): string {
  const meta = LAYER_META[layer];
  return layer.endsWith('CLAW') ? capabilityName(layer) : (meta?.label ?? layer);
}

function conditionLabel(json: string): string {
  try {
    const c = JSON.parse(json);
    return `if ${c.field} ${c.op} "${c.value}"`;
  } catch { return json; }
}

// ── Toggle switch ─────────────────────────────────────────────────────────────

function ToggleSwitch({ checked, onChange, disabled }: {
  checked: boolean; onChange: (v: boolean) => void; disabled?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="relative flex-shrink-0 w-10 h-6 rounded-full transition-colors duration-200 focus:outline-none disabled:opacity-40"
      style={{ background: checked ? '#4f46e5' : 'var(--rc-bg-elevated)' }}
    >
      <div
        className="absolute top-1 w-4 h-4 rounded-full bg-white shadow transition-all duration-200"
        style={{ left: checked ? '22px' : '4px' }}
      />
    </button>
  );
}

// ── Edit Modal ────────────────────────────────────────────────────────────────

function EditModal({ policy, onSave, onClose }: {
  policy: any; onSave: (updated: any) => void; onClose: () => void;
}) {
  const [action, setAction]     = useState(policy.action);
  const [priority, setPriority] = useState(String(policy.priority));
  const [isActive, setIsActive] = useState(policy.is_active);
  const [saving, setSaving]     = useState(false);
  const [error, setError]       = useState('');

  const layer = getLayer(policy.description || '');
  const meta  = LAYER_META[layer];
  const Icon  = meta?.icon ?? Shield;

  const handleSave = async () => {
    setSaving(true); setError('');
    try {
      const updated = await updatePolicy(policy.id, {
        action, priority: parseInt(priority, 10), is_active: isActive,
      });
      onSave(updated);
    } catch (e: any) { setError(e.message || 'Save failed'); }
    finally { setSaving(false); }
  };

  return (
    <OverlayPortal>
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.65)' }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="w-full max-w-lg rounded-2xl border shadow-2xl overflow-hidden"
        style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>

        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b" style={{ borderColor: 'var(--rc-border)' }}>
          <div className="flex-1 min-w-0 pr-4">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              {meta && (
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${meta.color} ${meta.bg} ${meta.border}`}>
                  <Icon className="w-3 h-3" /> {layerDisplayName(layer)}
                </span>
              )}
              <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Priority {policy.priority}</span>
            </div>
            <h2 className="font-semibold text-base" style={{ color: 'var(--rc-text-1)' }}>{marcellusText(policy.name)}</h2>
            <p className="text-sm mt-1 leading-relaxed" style={{ color: 'var(--rc-text-2)' }}>
              {getDescription(policy.description)}
            </p>
          </div>
          <button onClick={onClose} className="flex-shrink-0 p-1.5 rounded-lg hover:opacity-70" style={{ color: 'var(--rc-text-3)' }}>
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-6">
          {/* Action selector */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--rc-text-3)' }}>
              Enforcement Action
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {Object.entries(ACTION_STYLE).map(([val, { label, icon: AIcon, color }]) => (
                <button key={val} type="button" onClick={() => setAction(val)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium transition-all ${action === val ? color + ' ring-2 ring-offset-1 ring-current ring-offset-transparent' : ''}`}
                  style={action !== val ? { borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-elevated)', opacity: 0.6 } : {}}>
                  <AIcon className="w-3.5 h-3.5 flex-shrink-0" />{label}
                </button>
              ))}
            </div>
          </div>

          {/* Priority */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--rc-text-3)' }}>
              Priority <span className="normal-case font-normal">(lower = evaluated first)</span>
            </label>
            <input type="number" min={1} max={999} value={priority} onChange={e => setPriority(e.target.value)}
              className="w-28 px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              style={{ background: 'var(--rc-bg-input)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-1)' }} />
          </div>

          {/* Condition */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--rc-text-3)' }}>
              Condition <span className="normal-case font-normal">(edit via seed script)</span>
            </label>
            <div className="px-3 py-2 rounded-lg border text-xs font-mono"
              style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
              {conditionLabel(policy.condition_json)}
            </div>
          </div>

          {/* Active toggle */}
          <div className="flex items-center justify-between py-2">
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>Policy active</p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>Inactive policies are stored but never evaluated</p>
            </div>
            <ToggleSwitch checked={isActive} onChange={setIsActive} />
          </div>

          {error && <p className="text-sm text-red-400">{error}</p>}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t"
          style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm border transition-colors"
            style={{ borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}>
            Cancel
          </button>
          <button onClick={handleSave} disabled={saving}
            className="px-4 py-2 rounded-lg text-sm font-medium bg-indigo-600 hover:bg-indigo-700 text-white flex items-center gap-2 disabled:opacity-50 transition-colors">
            <Save className="w-4 h-4" />
            {saving ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </div>
    </div>
    </OverlayPortal>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function PoliciesPage() {
  const [policies, setPolicies]   = useState<any[]>([]);
  const [loading, setLoading]     = useState(true);
  const [category, setCategory]   = useState('ALL');
  const [layer, setLayer]         = useState('ALL');
  const [editing, setEditing]     = useState<any | null>(null);
  const [toggling, setToggling]   = useState<Set<string>>(new Set());

  useEffect(() => {
    getPolicies().then(setPolicies).catch(console.error).finally(() => setLoading(false));
  }, []);

  // Reset layer filter when category changes
  const handleCategory = (cat: string) => { setCategory(cat); setLayer('ALL'); };

  // Layers present in the DB for the selected category
  const layersInCategory = (cat: string) =>
    Array.from(new Set(
      policies
        .filter(p => cat === 'ALL' || LAYER_META[getLayer(p.description)]?.category === cat)
        .map(p => getLayer(p.description))
        .filter(l => l !== 'GLOBAL')
    )).sort((a, b) => {
      const pa = (LAYER_META[a]?.category ?? '') + a;
      const pb = (LAYER_META[b]?.category ?? '') + b;
      return pa.localeCompare(pb);
    });

  const availableLayers = layersInCategory(category);

  // Final filtered list
  const shown = policies.filter(p => {
    const l = getLayer(p.description);
    if (category !== 'ALL' && LAYER_META[l]?.category !== category) return false;
    if (layer !== 'ALL' && l !== layer) return false;
    return true;
  });

  const handleToggleActive = async (p: any) => {
    setToggling(prev => new Set(prev).add(p.id));
    try {
      const updated = await updatePolicy(p.id, { is_active: !p.is_active });
      setPolicies(prev => prev.map(x => x.id === p.id ? { ...x, ...updated } : x));
    } catch (e) { console.error(e); }
    finally { setToggling(prev => { const s = new Set(prev); s.delete(p.id); return s; }); }
  };

  const handleSave = (updated: any) => {
    setPolicies(prev => prev.map(p => p.id === updated.id ? { ...p, ...updated } : p));
    setEditing(null);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this policy? This cannot be undone.')) return;
    try { await deletePolicy(id); setPolicies(prev => prev.filter(p => p.id !== id)); }
    catch (e) { console.error(e); }
  };

  // Stats
  const total   = policies.length;
  const active  = policies.filter(p => p.is_active).length;
  const blocks  = policies.filter(p => p.action === 'deny').length;
  const approvals = policies.filter(p => p.action === 'require_approval').length;

  return (
    <div className="space-y-6">
      {editing && (
        <EditModal policy={editing} onSave={handleSave} onClose={() => setEditing(null)} />
      )}

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
            <FileText className="text-purple-400" /> Policies
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
            CoreOS Policy Engine — {total} policies across {Object.keys(LAYER_META).length} modules
          </p>
        </div>
        {/* Summary stats */}
        <div className="hidden md:flex gap-3">
          {[
            { label: 'Total', val: total,    c: 'text-indigo-400 bg-indigo-900/20 border-indigo-800' },
            { label: 'Active', val: active,   c: 'text-green-400 bg-green-900/20 border-green-800' },
            { label: 'Block', val: blocks,    c: 'text-red-400 bg-red-900/20 border-red-800' },
            { label: 'Approve', val: approvals, c: 'text-yellow-400 bg-yellow-900/20 border-yellow-800' },
          ].map(({ label, val, c }) => (
            <div key={label} className={`px-4 py-2 rounded-xl border text-center ${c}`}>
              <p className="text-xl font-bold">{val}</p>
              <p className="text-xs">{label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* How policies work */}
      <div className="rounded-xl border p-4" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-semibold text-sm" style={{ color: 'var(--rc-text-1)' }}>Enforcement actions</h2>
          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Evaluated in priority order · first match wins · default: ALLOW
          </p>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
          {Object.entries(ACTION_STYLE).map(([action, { color, label, icon: Icon }]) => (
            <div key={action} className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs ${color}`}>
              <Icon className="w-3.5 h-3.5 flex-shrink-0" />
              <div>
                <p className="font-semibold">{label}</p>
                <p className="opacity-70">
                  {action === 'deny' ? 'Stops action' : action === 'require_approval' ? 'Pauses for admin'
                    : action === 'monitor' ? 'Logs + scores' : action === 'isolate' ? 'Quarantines' : 'Permits'}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Category filter ────────────────────────────────────────────────── */}
      <div className="space-y-3">
        {/* Category pills */}
        <div className="flex flex-wrap gap-2">
          {CATEGORIES.map(cat => {
            const count = cat === 'ALL'
              ? policies.length
              : policies.filter(p => LAYER_META[getLayer(p.description)]?.category === cat).length;
            const active = category === cat;
            return (
              <button key={cat} onClick={() => handleCategory(cat)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  active
                    ? (CATEGORY_COLORS[cat] ?? 'bg-indigo-600') + ' text-white'
                    : 'hover:opacity-80'
                }`}
                style={active ? {} : { color: 'var(--rc-text-2)', background: 'var(--rc-bg-elevated)' }}>
                {cat} <span className="opacity-70">({count})</span>
              </button>
            );
          })}
        </div>

        {/* Layer sub-filter — only when a category is picked and it has multiple layers */}
        {availableLayers.length > 1 && (
          <div className="flex flex-wrap gap-1.5 border-t pt-3" style={{ borderColor: 'var(--rc-border)' }}>
            <button onClick={() => setLayer('ALL')}
              className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                layer === 'ALL' ? 'bg-indigo-600 text-white' : 'hover:opacity-80'
              }`}
              style={layer === 'ALL' ? {} : { color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)' }}>
              All <span className="opacity-60">({shown.length})</span>
            </button>
            {availableLayers.map(l => {
              const meta = LAYER_META[l];
              const Icon = meta?.icon ?? Shield;
              const cnt  = policies.filter(p => getLayer(p.description) === l).length;
              const isActive = layer === l;
              return (
                <button key={l} onClick={() => setLayer(l)}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-medium transition-all ${
                    isActive ? `${meta?.color ?? ''} ${meta?.bg ?? ''} ${meta?.border ?? ''}` : ''
                  }`}
                  style={isActive ? {} : { color: 'var(--rc-text-3)', borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
                  <Icon className="w-3 h-3" />
                  {layerDisplayName(l)} <span className="opacity-60">({cnt})</span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Policy list ──────────────────────────────────────────────────────── */}
      {loading ? (
        <p className="p-6 text-sm" style={{ color: 'var(--rc-text-3)' }}>Loading policies…</p>
      ) : policies.length === 0 ? (
        <div className="rounded-xl border border-yellow-700/40 p-8 text-center" style={{ background: 'var(--rc-bg-surface)' }}>
          <p className="text-yellow-400 font-semibold mb-2">No policies loaded yet</p>
          <p className="text-sm mb-4" style={{ color: 'var(--rc-text-2)' }}>
            Load all {Object.keys(LAYER_META).length} module policies:
          </p>
          <code className="px-4 py-2 rounded text-green-400 text-sm" style={{ background: 'var(--rc-bg-elevated)' }}>
            docker compose exec backend python seed_policies.py --reset
          </code>
        </div>
      ) : shown.length === 0 ? (
        <div className="rounded-xl border p-6 text-center" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>No policies match this filter.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {shown
            .slice()
            .sort((a, b) => a.priority - b.priority)
            .map((p: any) => {
              const l = getLayer(p.description);
              const meta = LAYER_META[l];
              const Icon = meta?.icon ?? Shield;
              const actionStyle = ACTION_STYLE[p.action] || ACTION_STYLE.monitor;
              const ActionIcon = actionStyle.icon;
              const isTogglingThis = toggling.has(p.id);

              return (
                <div key={p.id}
                  className="rounded-xl border p-4 transition-all duration-150"
                  style={{
                    background: 'var(--rc-bg-surface)',
                    borderColor: 'var(--rc-border)',
                    opacity: p.is_active ? 1 : 0.45,
                  }}>
                  <div className="flex items-center gap-3">
                    {/* Priority */}
                    <div className="flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center text-xs font-bold"
                      style={{ background: 'var(--rc-bg-elevated)', color: 'var(--regent-500)' }}>
                      {p.priority}
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-0.5">
                        <h3 className="font-semibold text-sm" style={{ color: 'var(--rc-text-1)' }}>{marcellusText(p.name)}</h3>
                        {meta && (
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${meta.color} ${meta.bg} ${meta.border}`}>
                            <Icon className="w-3 h-3" /> {layerDisplayName(l)}
                          </span>
                        )}
                        {p.scope_target && (
                          <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>→ {p.scope_target}</span>
                        )}
                      </div>
                      <p className="text-xs truncate" style={{ color: 'var(--rc-text-2)' }}>
                        {getDescription(p.description)}
                      </p>
                      <div className="mt-1 text-xs font-mono inline-block px-2 py-0.5 rounded"
                        style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-3)' }}>
                        {conditionLabel(p.condition_json)}
                      </div>
                    </div>

                    {/* Controls */}
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <div className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-semibold ${actionStyle.color}`}>
                        <ActionIcon className="w-3.5 h-3.5" /> {actionStyle.label}
                      </div>
                      <ToggleSwitch checked={p.is_active} onChange={() => handleToggleActive(p)} disabled={isTogglingThis} />
                      <button onClick={() => setEditing(p)}
                        className="p-1.5 rounded-lg hover:opacity-70"
                        style={{ color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)' }}>
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => handleDelete(p.id)}
                        className="p-1.5 rounded-lg hover:text-red-400 hover:bg-red-900/20"
                        style={{ color: 'var(--rc-text-3)' }}>
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
        </div>
      )}
    </div>
  );
}
