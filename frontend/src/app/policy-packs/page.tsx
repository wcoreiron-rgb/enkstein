'use client';
import { useCallback, useEffect, useState } from 'react';
import {
  Package, Shield, CheckCircle2, XCircle, Clock,
  ChevronDown, ChevronRight, Zap, Eye,
  RefreshCw, AlertTriangle, Layers,
} from 'lucide-react';
import { getPolicyPacks, applyPolicyPack, unapplyPolicyPack } from '@/lib/api';
import ClientDate from '@/components/ClientDate';

// ── Framework metadata ────────────────────────────────────────────────────────

const FRAMEWORK_META: Record<string, {
  label: string;
  color: string;
  bg: string;
  border: string;
  badge: string;
  description: string;
}> = {
  'zero-trust': {
    label: 'Zero Trust',
    color: 'text-indigo-400',
    bg: 'bg-indigo-900/30',
    border: 'border-indigo-700',
    badge: 'bg-indigo-600',
    description: 'Never trust, always verify',
  },
  'soc2': {
    label: 'SOC 2',
    color: 'text-cyan-400',
    bg: 'bg-cyan-900/30',
    border: 'border-cyan-700',
    badge: 'bg-cyan-700',
    description: 'AICPA Trust Services Criteria',
  },
  'iso27001': {
    label: 'ISO 27001',
    color: 'text-blue-400',
    bg: 'bg-blue-900/30',
    border: 'border-blue-700',
    badge: 'bg-blue-700',
    description: 'Information security management',
  },
  'hipaa': {
    label: 'HIPAA',
    color: 'text-green-400',
    bg: 'bg-green-900/30',
    border: 'border-green-700',
    badge: 'bg-green-700',
    description: 'Healthcare data protection',
  },
  'pci-dss': {
    label: 'PCI-DSS',
    color: 'text-yellow-400',
    bg: 'bg-yellow-900/30',
    border: 'border-yellow-700',
    badge: 'bg-yellow-600',
    description: 'Payment card security standard',
  },
};

const ACTION_STYLE: Record<string, { color: string; label: string; dot: string }> = {
  deny:             { color: 'text-red-400',    label: 'BLOCK',   dot: 'bg-red-500' },
  require_approval: { color: 'text-yellow-400', label: 'APPROVE', dot: 'bg-yellow-500' },
  monitor:          { color: 'text-blue-400',   label: 'MONITOR', dot: 'bg-blue-500' },
  allow:            { color: 'text-green-400',  label: 'ALLOW',   dot: 'bg-green-500' },
  isolate:          { color: 'text-purple-400', label: 'ISOLATE', dot: 'bg-purple-500' },
};

// ── Policy row inside expansion panel ────────────────────────────────────────

function PolicyRow({ policy, idx }: { policy: any; idx: number }) {
  const actionStyle = ACTION_STYLE[policy.action] || ACTION_STYLE.monitor;
  let condLabel = policy.condition_json;
  try {
    const c = JSON.parse(policy.condition_json);
    const val = Array.isArray(c.value) ? c.value.join(', ') : String(c.value);
    condLabel = `if ${c.field} ${c.op} "${val}"`;
  } catch { /* leave raw */ }

  const module = (() => {
    if (!policy.description) return null;
    const part = policy.description.split('|')[0]?.trim();
    return part || null;
  })();

  return (
    <div className="flex items-start gap-3 py-2.5 border-t" style={{ borderColor: 'var(--rc-border)' }}>
      <span className="flex-shrink-0 w-5 h-5 rounded flex items-center justify-center text-xs font-bold mt-0.5"
        style={{ background: 'var(--rc-bg-base)', color: 'var(--rc-text-3)' }}>
        {idx + 1}
      </span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="text-xs font-medium" style={{ color: 'var(--rc-text-1)' }}>{policy.name}</p>
          {module && (
            <span className="text-xs px-1.5 py-0.5 rounded border"
              style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)', background: 'var(--rc-bg-base)', fontSize: '10px' }}>
              {module}
            </span>
          )}
        </div>
        <p className="text-xs mt-0.5 font-mono" style={{ color: 'var(--rc-text-3)' }}>{condLabel}</p>
      </div>
      <div className={`flex-shrink-0 flex items-center gap-1.5 text-xs font-semibold ${actionStyle.color}`}>
        <div className={`w-1.5 h-1.5 rounded-full ${actionStyle.dot}`} />
        {actionStyle.label}
      </div>
    </div>
  );
}

// ── Pack card ─────────────────────────────────────────────────────────────────

function PackCard({ pack, onApply, onUnapply }: {
  pack: any;
  onApply: (id: string) => Promise<void>;
  onUnapply: (id: string) => Promise<void>;
}) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const meta = FRAMEWORK_META[pack.framework] ?? {
    label: pack.framework,
    color: 'text-gray-400',
    bg: 'bg-gray-900/30',
    border: 'border-gray-700',
    badge: 'bg-gray-700',
    description: '',
  };

  let policies: any[] = [];
  try { policies = JSON.parse(pack.policies_json); } catch { /* empty */ }

  const blockCount   = policies.filter(p => p.action === 'deny').length;
  const approveCount = policies.filter(p => p.action === 'require_approval').length;
  const monitorCount = policies.filter(p => p.action === 'monitor').length;

  const handleApply = async () => {
    setLoading(true); setError('');
    try { await onApply(pack.id); }
    catch (e: any) { setError(e.message || 'Failed to apply'); }
    finally { setLoading(false); }
  };

  const handleUnapply = async () => {
    if (!confirm(`Remove all ${pack.policy_count} policies from "${pack.name}"?`)) return;
    setLoading(true); setError('');
    try { await onUnapply(pack.id); }
    catch (e: any) { setError(e.message || 'Failed to remove'); }
    finally { setLoading(false); }
  };

  return (
    <div
      className={`rounded-2xl border transition-all duration-200 overflow-hidden ${pack.is_applied ? meta.border : ''}`}
      style={{
        background: 'var(--rc-bg-surface)',
        borderColor: pack.is_applied ? undefined : 'var(--rc-border)',
      }}
    >
      {/* Applied indicator bar */}
      {pack.is_applied && (
        <div className={`h-1 w-full ${meta.badge}`} />
      )}

      {/* Card header */}
      <div className="p-5">
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex-1 min-w-0">
            {/* Framework badge + version */}
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold text-white ${meta.badge}`}>
                <Shield className="w-3 h-3" /> {meta.label}
              </span>
              <span className="text-xs px-2 py-0.5 rounded border"
                style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)' }}>
                v{pack.version}
              </span>
              {pack.is_applied && (
                <span className="inline-flex items-center gap-1 text-xs font-medium text-green-400">
                  <CheckCircle2 className="w-3 h-3" /> Applied
                </span>
              )}
            </div>
            <h3 className="font-semibold text-base" style={{ color: 'var(--rc-text-1)' }}>{pack.name}</h3>
            <p className="text-sm mt-1 leading-relaxed" style={{ color: 'var(--rc-text-2)' }}>{pack.description}</p>
          </div>

          {/* Policy count circle */}
          <div className={`flex-shrink-0 w-14 h-14 rounded-xl flex flex-col items-center justify-center border ${meta.bg} ${meta.border}`}>
            <p className={`text-xl font-bold ${meta.color}`}>{pack.policy_count}</p>
            <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>policies</p>
          </div>
        </div>

        {/* Policy action breakdown */}
        <div className="flex gap-3 mb-4">
          {blockCount > 0 && (
            <span className="flex items-center gap-1.5 text-xs text-red-400">
              <XCircle className="w-3.5 h-3.5" /> {blockCount} block
            </span>
          )}
          {approveCount > 0 && (
            <span className="flex items-center gap-1.5 text-xs text-yellow-400">
              <Clock className="w-3.5 h-3.5" /> {approveCount} approve
            </span>
          )}
          {monitorCount > 0 && (
            <span className="flex items-center gap-1.5 text-xs text-blue-400">
              <Eye className="w-3.5 h-3.5" /> {monitorCount} monitor
            </span>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          {!pack.is_applied ? (
            <button
              onClick={handleApply}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors disabled:opacity-50"
              style={{ background: 'var(--regent-600)' }}
            >
              {loading
                ? <RefreshCw className="w-4 h-4 animate-spin" />
                : <Zap className="w-4 h-4" />
              }
              {loading ? 'Applying…' : 'Apply Pack'}
            </button>
          ) : (
            <button
              onClick={handleUnapply}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border transition-colors disabled:opacity-50 hover:text-red-400 hover:border-red-700"
              style={{ borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-elevated)' }}
            >
              {loading
                ? <RefreshCw className="w-4 h-4 animate-spin" />
                : <XCircle className="w-4 h-4" />
              }
              {loading ? 'Removing…' : 'Remove Pack'}
            </button>
          )}

          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs border transition-colors"
            style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)' }}
          >
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            {expanded ? 'Hide' : 'Preview'} policies
          </button>
        </div>

        {error && (
          <p className="mt-2 text-xs text-red-400 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" /> {error}
          </p>
        )}

        {pack.applied_at && (
          <p className="mt-2 text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Applied <ClientDate value={pack.applied_at} />
          </p>
        )}
      </div>

      {/* Expanded policies list */}
      {expanded && policies.length > 0 && (
        <div className="px-5 pb-5 border-t" style={{ borderColor: 'var(--rc-border)' }}>
          <p className="text-xs font-semibold uppercase tracking-wide mt-4 mb-1" style={{ color: 'var(--rc-text-3)' }}>
            Policies in this pack
          </p>
          {policies.map((p, i) => (
            <PolicyRow key={i} policy={p} idx={i} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function PolicyPacksPage() {
  const [packs, setPacks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const loadPolicyPacks = useCallback(() => {
    setLoading(true);
    getPolicyPacks()
      .then(rows => { setPacks(rows); setLoadError(null); })
      .catch(error => setLoadError(error?.message || 'Could not reach the Enkstein API.'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadPolicyPacks();
  }, [loadPolicyPacks]);

  const handleApply = async (id: string) => {
    const updated = await applyPolicyPack(id);
    setPacks(prev => prev.map(p => p.id === id ? { ...p, ...updated } : p));
  };

  const handleUnapply = async (id: string) => {
    const updated = await unapplyPolicyPack(id);
    setPacks(prev => prev.map(p => p.id === id ? { ...p, ...updated } : p));
  };

  // Stats
  const totalPacks    = packs.length;
  const appliedPacks  = packs.filter(p => p.is_applied).length;
  const totalPolicies = packs.reduce((s, p) => s + (p.policy_count || 0), 0);
  const deployed      = packs.filter(p => p.is_applied).reduce((s, p) => s + (p.policy_count || 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
            <Layers className="text-indigo-400" /> Policy Packs
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
            Compliance framework bundles — deploy curated policy sets with one click
          </p>
        </div>

        {/* Stats */}
        <div className="flex gap-3 flex-wrap">
          {[
            { label: 'Packs',     val: totalPacks,   c: 'text-indigo-400 bg-indigo-900/20 border-indigo-800' },
            { label: 'Applied',   val: appliedPacks,  c: 'text-green-400 bg-green-900/20 border-green-800' },
            { label: 'Available', val: totalPolicies, c: 'text-cyan-400 bg-cyan-900/20 border-cyan-800' },
            { label: 'Deployed',  val: deployed,      c: 'text-yellow-400 bg-yellow-900/20 border-yellow-800' },
          ].map(({ label, val, c }) => (
            <div key={label} className={`px-4 py-2 rounded-xl border text-center ${c}`}>
              <p className="text-xl font-bold">{val}</p>
              <p className="text-xs">{label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* How it works */}
      <div className="rounded-xl border p-4" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        <div className="flex items-center gap-2 mb-3">
          <Package className="w-4 h-4 text-indigo-400" />
          <h2 className="font-semibold text-sm" style={{ color: 'var(--rc-text-1)' }}>How Policy Packs work</h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs" style={{ color: 'var(--rc-text-2)' }}>
          <div className="flex items-start gap-2">
            <span className="flex-shrink-0 w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center font-bold text-xs">1</span>
            <p>Each pack contains curated policies mapped to a specific compliance framework.</p>
          </div>
          <div className="flex items-start gap-2">
            <span className="flex-shrink-0 w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center font-bold text-xs">2</span>
            <p>Clicking <strong style={{ color: 'var(--rc-text-1)' }}>Apply Pack</strong> deploys all policies into the CoreOS Policy Engine and activates them immediately.</p>
          </div>
          <div className="flex items-start gap-2">
            <span className="flex-shrink-0 w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center font-bold text-xs">3</span>
            <p>Packs can be removed cleanly — all deployed policies are deleted, leaving custom policies untouched.</p>
          </div>
        </div>
      </div>

      {/* Pack grid */}
      {loading ? (
        <p className="p-6 text-sm" style={{ color: 'var(--rc-text-3)' }}>Loading policy packs…</p>
      ) : loadError ? (
        <div className="rounded-xl border border-red-700/40 p-8 text-center" style={{ background: 'var(--rc-bg-surface)' }}>
          <p className="text-red-400 font-semibold mb-2">Could not load policy packs</p>
          <p className="text-sm mb-4" style={{ color: 'var(--rc-text-2)' }}>{loadError}</p>
          <button
            onClick={loadPolicyPacks}
            className="px-4 py-2 rounded text-sm font-medium"
            style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-1)', border: '1px solid var(--rc-border)' }}>
            Retry
          </button>
        </div>
      ) : packs.length === 0 ? (
        <div className="rounded-xl border border-yellow-700/40 p-8 text-center" style={{ background: 'var(--rc-bg-surface)' }}>
          <p className="text-yellow-400 font-semibold mb-2">No policy packs loaded yet</p>
          <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>
            Enkstein installs its policy packs at startup. If this stays empty, restart Enkstein so
            the runtime can finish preparing the database.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {packs.map(pack => (
            <PackCard
              key={pack.id}
              pack={pack}
              onApply={handleApply}
              onUnapply={handleUnapply}
            />
          ))}
        </div>
      )}
    </div>
  );
}
