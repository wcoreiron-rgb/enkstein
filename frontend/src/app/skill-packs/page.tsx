'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  Package, CheckCircle, Download, Trash2, Play, Pause,
  RefreshCw, Search, Shield, AlertTriangle, ChevronDown, ChevronRight,
  Plug, Cpu, Lock, FileText, Star, Tag, RotateCcw, GitCompare,
} from 'lucide-react';
import {
  getSkillPacks, installSkillPack, uninstallSkillPack,
  activateSkillPack, deactivateSkillPack, getSkillPackStats,
  previewSkillPackUpdate, upgradeSkillPack, rollbackSkillPack,
  ApiError,
} from '@/lib/api';
import { capabilityName } from '@/lib/capability-names';

// ─── Types ────────────────────────────────────────────────────────────────────
type Skill = {
  id: string; name: string; description?: string; claw: string; action: string;
};

type SkillPack = {
  id: string;
  name: string;
  slug: string;
  version: string;
  description: string | null;
  icon: string | null;
  category: string | null;
  publisher: string | null;
  tags: string | null;
  is_installed: boolean;
  is_active: boolean;
  is_builtin: boolean;
  risk_level: string;
  requires_approval: boolean;
  skill_count: number;
  run_count: number;
  installed_at: string | null;
  installed_by: string | null;
  license: string | null;
  changelog: string | null;
  manifest: {
    skills?: Skill[];
    required_connectors?: string[];
    required_claws?: string[];
    scope_permissions?: string[];
    policy_mappings?: { skill_id: string; policy_name: string }[];
  };
  rollback_available?: boolean;
};

type Stats = {
  total_packs: number;
  installed: number;
  active: number;
  total_skills: number;
  high_risk: number;
  requires_approval: number;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-400    bg-red-900/30    border-red-800',
  high:     'text-orange-400 bg-orange-900/30 border-orange-800',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-800',
  low:      'text-green-400  bg-green-900/30  border-green-800',
};

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  'Incident Response':       Shield,
  'Threat Hunting':          Search,
  'Hardening':               Lock,
  'Compliance':              FileText,
  'Vulnerability Management': AlertTriangle,
  'DevSecOps':               Cpu,
  'default':                 Package,
};

// ─── Pack card ────────────────────────────────────────────────────────────────
function PackCard({ pack, onAction }: { pack: SkillPack; onAction: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [scanPath, setScanPath] = useState('');
  const [installResult, setInstallResult] = useState<any | null>(null);
  const [lifecycleResult, setLifecycleResult] = useState<any | null>(null);
  const [targetVersion, setTargetVersion] = useState(() => `${pack.version}.1`);
  const [targetManifest, setTargetManifest] = useState(() => JSON.stringify(pack.manifest || {}, null, 2));
  const [actionError, setActionError] = useState<string | null>(null);

  const Icon = CATEGORY_ICONS[pack.category ?? 'default'] ?? Package;
  const riskClass = RISK_COLORS[pack.risk_level] ?? RISK_COLORS.low;

  const doAction = async (action: () => Promise<any>) => {
    setBusy(action.name || 'working');
    setActionError(null);
    try {
      const result = await action();
      if (result?.install_policy || result?.gateway_scan) setInstallResult(result);
      if (result?.diff || result?.upgrade_diff || result?.rollback) setLifecycleResult(result);
      onAction();
    } catch (err: any) {
      if (err instanceof ApiError && err.data && typeof err.data === 'object') {
        const detail = (err.data as any).detail;
        if (typeof detail === 'string') setActionError(detail);
        else if (detail?.message) setActionError(detail.message);
        else setActionError(`Request failed (${err.status})`);
      } else {
        setActionError(err?.message || 'Request failed');
      }
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className={`bg-gray-900 border rounded-xl overflow-hidden transition-all ${
      pack.is_active ? 'border-cyan-800/60' :
      pack.is_installed ? 'border-gray-700' : 'border-gray-800'
    }`}>

      {/* Header */}
      <div className="px-5 py-4">
        <div className="flex items-start gap-3">
          {/* Icon */}
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 text-xl
            ${pack.is_active ? 'bg-cyan-900/40' : 'bg-gray-800'}`}>
            {pack.icon || <Icon className={`w-5 h-5 ${pack.is_active ? 'text-cyan-400' : 'text-gray-400'}`} />}
          </div>

          {/* Info */}
          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between gap-2 flex-wrap">
              <div>
                <p className="text-white font-semibold text-sm">{pack.name}</p>
                <p className="text-gray-500 text-xs">{pack.publisher} · v{pack.version}</p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                {pack.is_active && (
                  <span className="text-xs text-cyan-400 bg-cyan-900/30 border border-cyan-800 rounded px-2 py-0.5">Active</span>
                )}
                {pack.is_installed && !pack.is_active && (
                  <span className="text-xs text-gray-400 bg-gray-800 border border-gray-700 rounded px-2 py-0.5">Installed</span>
                )}
                {pack.is_builtin && (
                  <span className="text-xs text-purple-400 bg-purple-900/30 border border-purple-800 rounded px-2 py-0.5">Built-in</span>
                )}
                <span className={`text-xs px-2 py-0.5 rounded border capitalize ${riskClass}`}>
                  {pack.risk_level}
                </span>
              </div>
            </div>

            <p className="text-gray-400 text-xs mt-1.5 line-clamp-2">{pack.description}</p>

            {/* Meta pills */}
            <div className="flex flex-wrap gap-1.5 mt-2">
              <span className="text-xs text-gray-500 flex items-center gap-1">
                <Cpu className="w-3 h-3" /> {pack.skill_count} skills
              </span>
              {pack.category && (
                <span className="text-xs text-gray-500">{pack.category}</span>
              )}
              {pack.requires_approval && (
                <span className="text-xs text-orange-400 flex items-center gap-1">
                  <Shield className="w-3 h-3" /> Approval required
                </span>
              )}
              {pack.license && (
                <span className="text-xs text-gray-600">{pack.license}</span>
              )}
            </div>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2 mt-3 pt-3 border-t border-gray-800">
          {!pack.is_installed && (
            <button
              onClick={() => doAction(() => installSkillPack(pack.id, 'platform_admin', scanPath || undefined))}
              disabled={!!busy}
              className="flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors"
            >
              {busy ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
              Install
            </button>
          )}
          {pack.is_installed && !pack.is_active && (
            <button
              onClick={() => doAction(() => activateSkillPack(pack.id))}
              disabled={!!busy}
              className="flex items-center gap-1.5 bg-green-700 hover:bg-green-600 disabled:opacity-50 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors"
            >
              {busy ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
              Activate
            </button>
          )}
          {pack.is_active && (
            <button
              onClick={() => doAction(() => deactivateSkillPack(pack.id))}
              disabled={!!busy}
              className="flex items-center gap-1.5 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors"
            >
              {busy ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Pause className="w-3 h-3" />}
              Deactivate
            </button>
          )}
          {pack.is_installed && !pack.is_builtin && (
            <button
              onClick={() => doAction(() => uninstallSkillPack(pack.id))}
              disabled={!!busy}
              className="flex items-center gap-1.5 text-gray-500 hover:text-red-400 text-xs px-2 py-1.5 rounded-lg transition-colors ml-auto"
            >
              <Trash2 className="w-3 h-3" /> Uninstall
            </button>
          )}
          {pack.is_installed && (
            <button
              onClick={() => setExpanded(true)}
              className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 px-2 py-1.5 rounded-lg transition-colors"
            >
              <GitCompare className="w-3 h-3" /> Lifecycle
            </button>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1 text-xs text-gray-500 hover:text-white ml-auto transition-colors"
          >
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            Details
          </button>
        </div>
      </div>

      {/* Expanded manifest */}
      {expanded && (
        <div className="border-t border-gray-800 px-5 py-4 space-y-4">
          {!pack.is_installed && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Gateway Scan Path (Optional)</p>
              <input
                value={scanPath}
                onChange={(e) => setScanPath(e.target.value)}
                placeholder="backend/app/claws/identityclaw"
                className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-gray-200 text-xs outline-none focus:border-cyan-700"
              />
              <p className="text-[11px] text-gray-500 mt-1">
                Used only when MCP gateway is enabled. High-risk scan results can block install.
              </p>
            </div>
          )}

          {installResult?.install_policy && (
            <div className="rounded-lg border border-green-900 bg-green-950/20 px-3 py-2">
              <p className="text-xs text-green-300">
                Install Policy: {installResult.install_policy.outcome} · risk {installResult.install_policy.risk_score}
              </p>
              <p className="text-[11px] text-green-400/80">{installResult.install_policy.policy_name}</p>
            </div>
          )}

          {installResult?.gateway_scan && (
            <div className="rounded-lg border border-blue-900 bg-blue-950/20 px-3 py-2">
              <p className="text-xs text-blue-300">
                Gateway Scan: risk {installResult.gateway_scan.risk_score} · critical {installResult.gateway_scan.critical_count} · high {installResult.gateway_scan.high_count}
              </p>
            </div>
          )}

          {actionError && (
            <div className="rounded-lg border border-red-900 bg-red-950/30 px-3 py-2 text-xs text-red-300">
              {actionError}
            </div>
          )}

          {pack.is_installed && (
            <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-3 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <p className="text-xs text-gray-400 uppercase tracking-wide">Lifecycle Preview / Upgrade / Rollback</p>
                  <p className="text-[11px] text-gray-500 mt-0.5">
                    Preview manifest diff before applying an upgrade. Rollback restores the last saved previous version.
                  </p>
                </div>
                {pack.rollback_available && (
                  <span className="text-[11px] text-green-300 border border-green-800 rounded px-2 py-0.5">Rollback ready</span>
                )}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                <input
                  value={targetVersion}
                  onChange={(e) => setTargetVersion(e.target.value)}
                  className="px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-gray-200 text-xs outline-none focus:border-cyan-700"
                  placeholder="1.1.0"
                />
                <button
                  onClick={() => doAction(() => previewSkillPackUpdate(pack.id, {
                    version: targetVersion,
                    manifest_json: targetManifest,
                    upgraded_by: 'platform_admin',
                  }))}
                  disabled={!!busy}
                  className="flex items-center justify-center gap-1.5 rounded-lg border border-cyan-800 text-cyan-300 hover:bg-cyan-950/30 text-xs px-3 py-2"
                >
                  <GitCompare className="w-3 h-3" /> Preview
                </button>
                <button
                  onClick={() => doAction(() => upgradeSkillPack(pack.id, {
                    version: targetVersion,
                    manifest_json: targetManifest,
                    changelog: 'Upgraded from Skill Packs UI',
                    upgraded_by: 'platform_admin',
                  }))}
                  disabled={!!busy}
                  className="flex items-center justify-center gap-1.5 rounded-lg bg-blue-700 hover:bg-blue-600 disabled:opacity-50 text-white text-xs px-3 py-2"
                >
                  <Download className="w-3 h-3" /> Upgrade
                </button>
              </div>
              <textarea
                value={targetManifest}
                onChange={(e) => setTargetManifest(e.target.value)}
                rows={5}
                className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-gray-200 text-xs font-mono outline-none focus:border-cyan-700"
              />
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => doAction(() => rollbackSkillPack(pack.id, {
                    rolled_back_by: 'platform_admin',
                    reason: 'Rollback from Skill Packs UI',
                  }))}
                  disabled={!!busy || !pack.rollback_available}
                  className="flex items-center gap-1.5 rounded-lg border border-yellow-800 disabled:opacity-40 text-yellow-300 hover:bg-yellow-950/30 text-xs px-3 py-2"
                >
                  <RotateCcw className="w-3 h-3" /> Rollback
                </button>
                {lifecycleResult?.diff && (
                  <span className="text-xs text-cyan-300">
                    Preview: +{lifecycleResult.diff.skills_added?.length ?? 0} skills, -{lifecycleResult.diff.skills_removed?.length ?? 0} removed
                  </span>
                )}
                {lifecycleResult?.upgrade_diff && (
                  <span className="text-xs text-blue-300">
                    Upgraded to v{lifecycleResult.version}; rollback {lifecycleResult.rollback_available ? 'available' : 'not available'}
                  </span>
                )}
                {lifecycleResult?.rollback && (
                  <span className="text-xs text-yellow-300">
                    Rolled back from v{lifecycleResult.rollback.rolled_back_from}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Skills list */}
          {(pack.manifest.skills?.length ?? 0) > 0 && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Skills</p>
              <div className="space-y-1.5">
                {pack.manifest.skills!.map(s => (
                  <div key={s.id} className="flex items-start gap-3 bg-gray-800/60 rounded-lg px-3 py-2">
                    <Cpu className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <p className="text-white text-xs font-medium">{s.name}</p>
                      {s.description && <p className="text-gray-400 text-xs">{s.description}</p>}
                      <p className="text-gray-500 text-xs">{capabilityName(s.claw)} · {s.action}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Required connectors */}
          {(pack.manifest.required_connectors?.length ?? 0) > 0 && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Required Connectors</p>
              <div className="flex flex-wrap gap-1.5">
                {pack.manifest.required_connectors!.map(c => (
                  <span key={c} className="flex items-center gap-1 text-xs bg-gray-800 border border-gray-700 text-gray-300 rounded px-2 py-0.5">
                    <Plug className="w-3 h-3" /> {c}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Scope permissions */}
          {(pack.manifest.scope_permissions?.length ?? 0) > 0 && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Scope Permissions</p>
              <div className="flex flex-wrap gap-1.5">
                {pack.manifest.scope_permissions!.map(s => (
                  <span key={s} className="text-xs bg-blue-900/30 border border-blue-800 text-blue-300 rounded px-2 py-0.5">{s}</span>
                ))}
              </div>
            </div>
          )}

          {/* Policy mappings */}
          {(pack.manifest.policy_mappings?.length ?? 0) > 0 && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Policy Gates</p>
              <div className="space-y-1">
                {pack.manifest.policy_mappings!.map((m, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <Shield className="w-3 h-3 text-purple-400" />
                    <span className="text-gray-400">{m.skill_id}</span>
                    <span className="text-gray-600">→</span>
                    <span className="text-purple-300">{m.policy_name}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function SkillPacksPage() {
  const [packs, setPacks]       = useState<SkillPack[]>([]);
  const [stats, setStats]       = useState<Stats | null>(null);
  const [loading, setLoading]   = useState(true);
  const [search, setSearch]     = useState('');
  const [category, setCategory] = useState('');
  const [filter, setFilter]     = useState<'all' | 'installed' | 'active'>('all');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [packsData, statsData] = await Promise.all([
        getSkillPacks().catch(() => ({ skill_packs: [] })),
        getSkillPackStats().catch(() => null),
      ]);
      setPacks((packsData as any).skill_packs ?? []);
      setStats(statsData as Stats | null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const categories = Array.from(new Set(packs.map(p => p.category).filter(Boolean))) as string[];

  const filtered = packs.filter(p => {
    if (filter === 'installed' && !p.is_installed) return false;
    if (filter === 'active' && !p.is_active) return false;
    if (category && p.category !== category) return false;
    if (search) {
      const q = search.toLowerCase();
      return p.name.toLowerCase().includes(q) ||
        (p.description ?? '').toLowerCase().includes(q) ||
        (p.tags ?? '').toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Package className="text-cyan-400" /> Skill Packs
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            Versioned security automation bundles. Install, activate, and govern skill packs across your Capability Nodes.
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          {[
            { label: 'Total Packs',     value: stats.total_packs,     color: 'text-white' },
            { label: 'Installed',       value: stats.installed,       color: 'text-blue-400' },
            { label: 'Active',          value: stats.active,          color: 'text-green-400' },
            { label: 'Total Skills',    value: stats.total_skills,    color: 'text-cyan-400' },
            { label: 'High Risk',       value: stats.high_risk,       color: stats.high_risk > 0 ? 'text-orange-400' : 'text-gray-500' },
            { label: 'Need Approval',   value: stats.requires_approval, color: stats.requires_approval > 0 ? 'text-yellow-400' : 'text-gray-500' },
          ].map(s => (
            <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
              <p className="text-xs text-gray-500">{s.label}</p>
              <p className={`text-xl font-bold mt-0.5 ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-0 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search skill packs…"
            className="w-full pl-9 pr-3 py-2 bg-gray-900 border border-gray-700 text-white text-sm rounded-xl outline-none focus:border-cyan-700 transition-colors"
          />
        </div>
        <select
          value={category}
          onChange={e => setCategory(e.target.value)}
          className="bg-gray-900 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none"
        >
          <option value="">All categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <div className="flex gap-1 bg-gray-900 border border-gray-700 rounded-xl p-1">
          {(['all', 'installed', 'active'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`text-xs px-3 py-1.5 rounded-lg capitalize transition-colors ${
                filter === f ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
        <span className="text-xs text-gray-500">{filtered.length} packs</span>
      </div>

      {/* Pack grid */}
      {loading && packs.length === 0 ? (
        <div className="flex items-center justify-center h-48">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-6 py-12 text-center">
          <Package className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400 text-sm">No skill packs found matching your filters.</p>
          <button onClick={() => { setSearch(''); setCategory(''); setFilter('all'); }}
            className="mt-2 text-xs text-cyan-400 hover:text-cyan-300">Clear filters</button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filtered.map(pack => (
            <PackCard key={pack.id} pack={pack} onAction={load} />
          ))}
        </div>
      )}
    </div>
  );
}
