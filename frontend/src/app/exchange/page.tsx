'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  ShoppingBag, Search, Shield, Star, Download, CheckCircle,
  Award, Package, FileText, Zap, Globe, RefreshCw,
  ChevronDown, ChevronRight, ExternalLink, Lock, Sparkles,
} from 'lucide-react';
import {
  getExchangePackages, getFeaturedPackages, searchExchangePackages,
  getExchangePublishers, getExchangeStats, installExchangePackage,
} from '@/lib/api';
import { capabilityName } from '@/lib/capability-names';

// ─── types ───────────────────────────────────────────────────────────────────

type Package = {
  id: string;
  publisher_name: string;
  name: string;
  slug: string;
  package_type: 'skill_pack' | 'policy_pack' | 'playbook' | 'connector';
  category: string;
  tags: string[];
  description: string;
  long_description?: string;
  version: string;
  license_type: string;
  trust_score: number;
  download_count: number;
  rating: number;
  rating_count: number;
  is_featured: boolean;
  is_official: boolean;
  is_signed: boolean;
  signature_verified: boolean;
  manifest_json: any;
};

type Publisher = {
  id: string;
  name: string;
  slug: string;
  description: string;
  tier: 'official' | 'verified' | 'community';
  is_verified: boolean;
  pgp_fingerprint: string;
  total_packages: number;
  avg_trust_score: number;
};

type Stats = {
  total_packages: number;
  signed_packages: number;
  official_packages: number;
  total_publishers: number;
  verified_publishers: number;
  total_installs: number;
  type_breakdown: Record<string, number>;
  categories: { category: string; count: number }[];
};

// ─── helpers ─────────────────────────────────────────────────────────────────

const TYPE_META: Record<string, { icon: React.ElementType; color: string; bg: string; label: string }> = {
  skill_pack:  { icon: Zap,       color: 'text-cyan-400',   bg: 'bg-cyan-900/30 border-cyan-800',   label: 'Skill Pack' },
  policy_pack: { icon: FileText,  color: 'text-blue-400',   bg: 'bg-blue-900/30 border-blue-800',   label: 'Policy Pack' },
  playbook:    { icon: Globe,     color: 'text-purple-400', bg: 'bg-purple-900/30 border-purple-800', label: 'Playbook' },
  connector:   { icon: Package,   color: 'text-orange-400', bg: 'bg-orange-900/30 border-orange-800', label: 'Connector' },
};

const TIER_META: Record<string, { label: string; color: string; icon: React.ElementType }> = {
  official:  { label: 'Official',  color: 'text-cyan-400',  icon: Award },
  verified:  { label: 'Verified',  color: 'text-green-400', icon: CheckCircle },
  community: { label: 'Community', color: 'text-gray-400',  icon: Globe },
};

function TrustBar({ score }: { score: number }) {
  const color = score >= 90 ? 'bg-green-500' : score >= 75 ? 'bg-yellow-500' : 'bg-red-500';
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 bg-gray-800 rounded-full h-1.5">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-400">{score.toFixed(0)}</span>
    </div>
  );
}

function StarRating({ rating, count }: { rating: number; count: number }) {
  return (
    <div className="flex items-center gap-1">
      <Star className="w-3 h-3 text-yellow-400 fill-yellow-400" />
      <span className="text-xs text-gray-300">{rating.toFixed(1)}</span>
      <span className="text-xs text-gray-500">({count})</span>
    </div>
  );
}

// ─── package card ────────────────────────────────────────────────────────────

function PackageCard({
  pkg,
  onInstall,
  installing,
}: {
  pkg: Package;
  onInstall: (id: string) => void;
  installing: string | null;
}) {
  const [expanded, setExpanded] = useState(false);
  const meta   = TYPE_META[pkg.package_type] ?? TYPE_META.skill_pack;
  const Icon   = meta.icon;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className={`mt-0.5 p-2 rounded-lg border ${meta.bg} flex-shrink-0`}>
            <Icon className={`w-4 h-4 ${meta.color}`} />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-white font-semibold text-sm truncate">{pkg.name}</h3>
              {pkg.is_official && (
                <span className="flex items-center gap-1 text-xs px-1.5 py-0.5 rounded-full bg-cyan-900/30 border border-cyan-800 text-cyan-400">
                  <Award className="w-2.5 h-2.5" /> Official
                </span>
              )}
              {pkg.is_signed && pkg.signature_verified && (
                <span className="flex items-center gap-1 text-xs px-1.5 py-0.5 rounded-full bg-green-900/30 border border-green-800 text-green-400">
                  <Lock className="w-2.5 h-2.5" /> Signed
                </span>
              )}
              {pkg.is_featured && (
                <span className="flex items-center gap-1 text-xs px-1.5 py-0.5 rounded-full bg-yellow-900/30 border border-yellow-800 text-yellow-400">
                  <Sparkles className="w-2.5 h-2.5" /> Featured
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500 mt-0.5">{pkg.publisher_name} · v{pkg.version}</p>
          </div>
        </div>
        <span className={`text-xs px-2 py-1 rounded-lg border flex-shrink-0 ${meta.bg} ${meta.color}`}>
          {meta.label}
        </span>
      </div>

      {/* Description */}
      <p className="text-sm text-gray-400 mb-3 line-clamp-2">{pkg.description}</p>

      {/* Tags */}
      {pkg.tags?.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-3">
          {pkg.tags.slice(0, 5).map(t => (
            <span key={t} className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-400">
              {t}
            </span>
          ))}
        </div>
      )}

      {/* Metrics row */}
      <div className="flex items-center gap-4 mb-4 flex-wrap">
        <TrustBar score={pkg.trust_score} />
        <StarRating rating={pkg.rating} count={pkg.rating_count} />
        <div className="flex items-center gap-1 text-xs text-gray-500">
          <Download className="w-3 h-3" /> {pkg.download_count.toLocaleString()}
        </div>
        <span className="text-xs text-gray-500">{pkg.license_type}</span>
      </div>

      {/* Manifest preview (expandable) */}
      {pkg.manifest_json && Object.keys(pkg.manifest_json).length > 0 && (
        <div className="mb-4">
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors"
          >
            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            View manifest
          </button>
          {expanded && (
            <div className="mt-2 bg-gray-950 border border-gray-800 rounded-lg p-3">
              {(pkg.manifest_json.skills || pkg.manifest_json.playbooks || []).map((s: any, i: number) => (
                <div key={i} className="flex items-center gap-2 py-1 border-b border-gray-800 last:border-0">
                  <Zap className="w-3 h-3 text-cyan-500 flex-shrink-0" />
                  <span className="text-xs text-gray-300 flex-1">{s.name}</span>
                  {s.claw && (
                    <span className="text-xs text-gray-600 flex-shrink-0">{capabilityName(s.claw)}</span>
                  )}
                </div>
              ))}
              {pkg.manifest_json.capabilities && (
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {pkg.manifest_json.capabilities.map((c: string) => (
                    <span key={c} className="text-xs px-2 py-0.5 bg-gray-800 rounded text-gray-400">{c}</span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Install button */}
      <button
        onClick={() => onInstall(pkg.id)}
        disabled={installing === pkg.id}
        className="w-full py-2 px-4 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
        style={{ background: installing === pkg.id ? undefined : 'var(--regent-600)' }}
      >
        {installing === pkg.id
          ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Installing…</>
          : <><Download className="w-3.5 h-3.5" /> Install</>
        }
      </button>
    </div>
  );
}

// ─── publisher card ───────────────────────────────────────────────────────────

function PublisherCard({ pub }: { pub: Publisher }) {
  const tierMeta = TIER_META[pub.tier] ?? TIER_META.community;
  const TierIcon = tierMeta.icon;
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-start gap-3">
      <div className="w-10 h-10 rounded-full bg-gray-800 flex items-center justify-center flex-shrink-0">
        <TierIcon className={`w-5 h-5 ${tierMeta.color}`} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-white text-sm font-medium truncate">{pub.name}</span>
          {pub.is_verified && (
            <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
          )}
        </div>
        <p className="text-xs text-gray-500 mt-0.5 truncate">{pub.description}</p>
        <div className="flex items-center gap-3 mt-1.5">
          <span className={`text-xs ${tierMeta.color}`}>{tierMeta.label}</span>
          <span className="text-xs text-gray-600">{pub.total_packages} packages</span>
          <span className="text-xs text-gray-600">Trust {pub.avg_trust_score.toFixed(0)}</span>
        </div>
        {pub.pgp_fingerprint && (
          <p className="text-xs text-gray-700 mt-1 font-mono truncate">{pub.pgp_fingerprint}</p>
        )}
      </div>
    </div>
  );
}

// ─── main page ────────────────────────────────────────────────────────────────

const TABS = ['Browse', 'Featured', 'Publishers', 'Stats'] as const;
type Tab = typeof TABS[number];

const TYPES = ['All', 'skill_pack', 'policy_pack', 'playbook', 'connector'];
const TYPE_LABELS: Record<string, string> = {
  'All': 'All Types', skill_pack: 'Skill Packs', policy_pack: 'Policy Packs',
  playbook: 'Playbooks', connector: 'Connectors',
};
const SORT_OPTIONS = [
  { value: 'downloads', label: 'Most Downloaded' },
  { value: 'rating',    label: 'Top Rated' },
  { value: 'trust',     label: 'Highest Trust' },
  { value: 'newest',    label: 'Newest' },
];

export default function ExchangePage() {
  const [tab,        setTab]        = useState<Tab>('Browse');
  const [packages,   setPackages]   = useState<Package[]>([]);
  const [featured,   setFeatured]   = useState<Package[]>([]);
  const [publishers, setPublishers] = useState<Publisher[]>([]);
  const [stats,      setStats]      = useState<Stats | null>(null);
  const [total,      setTotal]      = useState(0);
  const [loading,    setLoading]    = useState(true);
  const [installing, setInstalling] = useState<string | null>(null);
  const [installMsg, setInstallMsg] = useState<{ id: string; msg: string; ok: boolean } | null>(null);

  // Filters
  const [search,      setSearch]      = useState('');
  const [typeFilter,  setTypeFilter]  = useState('All');
  const [sortBy,      setSortBy]      = useState('downloads');

  const loadBrowse = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = { sort: sortBy, limit: '24' };
      if (typeFilter !== 'All') params.package_type = typeFilter;
      const data = await getExchangePackages(params) as any;
      setPackages(data.packages || []);
      setTotal(data.total || 0);
    } finally { setLoading(false); }
  }, [sortBy, typeFilter]);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [featData, pubData, statsData] = await Promise.all([
        getFeaturedPackages(),
        getExchangePublishers(),
        getExchangeStats(),
      ]);
      setFeatured(featData as Package[]);
      setPublishers(pubData as Publisher[]);
      setStats(statsData as Stats);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { loadBrowse(); }, [loadBrowse]);
  useEffect(() => { loadAll(); }, [loadAll]);

  const handleSearch = async () => {
    if (!search.trim()) { loadBrowse(); return; }
    setLoading(true);
    try {
      const res = await searchExchangePackages(search.trim());
      setPackages(res as Package[]);
      setTotal(res.length);
    } finally { setLoading(false); }
  };

  const handleInstall = async (id: string) => {
    setInstalling(id);
    setInstallMsg(null);
    try {
      const res = await installExchangePackage(id) as any;
      setInstallMsg({ id, msg: res.message || 'Installed', ok: true });
    } catch (e: any) {
      setInstallMsg({ id, msg: e.message || 'Install failed', ok: false });
    } finally {
      setInstalling(null);
    }
  };

  const displayPkgs = tab === 'Featured' ? featured : packages;

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <ShoppingBag className="text-cyan-400" /> Security Exchange
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            Curated, signed skills, policies, playbooks, and connectors from verified publishers.
          </p>
        </div>
        <div className="flex gap-2">
          {stats && (
            <div className="flex items-center gap-4 bg-gray-900 border border-gray-800 rounded-xl px-4 py-2">
              <div className="text-center">
                <p className="text-xl font-bold text-white">{stats.total_packages}</p>
                <p className="text-xs text-gray-500">Packages</p>
              </div>
              <div className="w-px h-8 bg-gray-800" />
              <div className="text-center">
                <p className="text-xl font-bold text-green-400">{stats.signed_packages}</p>
                <p className="text-xs text-gray-500">Signed</p>
              </div>
              <div className="w-px h-8 bg-gray-800" />
              <div className="text-center">
                <p className="text-xl font-bold text-cyan-400">{stats.total_publishers}</p>
                <p className="text-xs text-gray-500">Publishers</p>
              </div>
              <div className="w-px h-8 bg-gray-800" />
              <div className="text-center">
                <p className="text-xl font-bold text-yellow-400">{stats.total_installs}</p>
                <p className="text-xs text-gray-500">Installs</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Trust banner */}
      <div className="rounded-xl border border-green-800 bg-green-900/20 px-5 py-3 flex items-center gap-3">
        <Shield className="w-5 h-5 text-green-400 flex-shrink-0" />
        <div>
          <p className="text-green-300 text-sm font-medium">
            All Official and Verified packages are PGP-signed and checksum-verified before install
          </p>
          <p className="text-green-600 text-xs mt-0.5">
            Community packages are community-maintained. Review the manifest before installing in production.
          </p>
        </div>
      </div>

      {/* Install notification */}
      {installMsg && (
        <div className={`rounded-xl border px-5 py-3 text-sm flex items-center gap-3 ${
          installMsg.ok
            ? 'bg-green-900/20 border-green-800 text-green-300'
            : 'bg-red-900/20 border-red-800 text-red-300'
        }`}>
          {installMsg.ok ? <CheckCircle className="w-4 h-4 flex-shrink-0" /> : <Shield className="w-4 h-4 flex-shrink-0" />}
          {installMsg.msg}
          <button onClick={() => setInstallMsg(null)} className="ml-auto text-gray-500 hover:text-white">✕</button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900 border border-gray-800 rounded-xl p-1 w-fit">
        {TABS.map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-lg text-sm transition-colors ${
              tab === t ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* ── Browse / Featured ── */}
      {(tab === 'Browse' || tab === 'Featured') && (
        <>
          {tab === 'Browse' && (
            <div className="flex flex-wrap gap-3">
              {/* Search */}
              <div className="flex gap-2 flex-1 min-w-64">
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleSearch()}
                  placeholder="Search packages…"
                  className="flex-1 bg-gray-900 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none"
                />
                <button
                  onClick={handleSearch}
                  className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-xl text-gray-400 hover:text-white"
                >
                  <Search className="w-4 h-4" />
                </button>
              </div>
              {/* Type filter */}
              <select
                value={typeFilter}
                onChange={e => setTypeFilter(e.target.value)}
                className="bg-gray-900 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none"
              >
                {TYPES.map(t => <option key={t} value={t}>{TYPE_LABELS[t] ?? t}</option>)}
              </select>
              {/* Sort */}
              <select
                value={sortBy}
                onChange={e => setSortBy(e.target.value)}
                className="bg-gray-900 border border-gray-700 text-white text-sm rounded-xl px-3 py-2 outline-none"
              >
                {SORT_OPTIONS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
              <span className="text-xs text-gray-500 self-center">{total} packages</span>
            </div>
          )}

          {loading ? (
            <div className="flex justify-center py-16">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {displayPkgs.map(pkg => (
                <PackageCard
                  key={pkg.id}
                  pkg={pkg}
                  onInstall={handleInstall}
                  installing={installing}
                />
              ))}
              {displayPkgs.length === 0 && (
                <div className="col-span-3 py-16 text-center text-gray-500 text-sm">
                  No packages found.
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ── Publishers ── */}
      {tab === 'Publishers' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {publishers.map(pub => <PublisherCard key={pub.id} pub={pub} />)}
          {publishers.length === 0 && (
            <p className="col-span-2 text-gray-500 text-sm text-center py-16">No publishers found.</p>
          )}
        </div>
      )}

      {/* ── Stats ── */}
      {tab === 'Stats' && stats && (
        <div className="space-y-6">
          {/* Type breakdown */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <h2 className="text-white font-semibold mb-4">Package Types</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(stats.type_breakdown).map(([type, count]) => {
                const meta = TYPE_META[type] ?? { icon: Package, color: 'text-gray-400', bg: '', label: type };
                const Icon = meta.icon;
                return (
                  <div key={type} className="bg-gray-950 border border-gray-800 rounded-xl p-4">
                    <Icon className={`w-6 h-6 ${meta.color} mb-2`} />
                    <p className="text-2xl font-bold text-white">{count}</p>
                    <p className="text-xs text-gray-500 mt-0.5">{TYPE_LABELS[type] ?? type}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Categories */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <h2 className="text-white font-semibold mb-4">Categories</h2>
            <div className="space-y-2">
              {stats.categories.map(({ category, count }) => (
                <div key={category} className="flex items-center gap-3">
                  <span className="text-sm text-gray-300 w-40 truncate">{category}</span>
                  <div className="flex-1 bg-gray-800 rounded-full h-2">
                    <div
                      className="h-2 rounded-full bg-cyan-500"
                      style={{ width: `${Math.round((count / (stats.total_packages || 1)) * 100)}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-500 w-6 text-right">{count}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Trust & verification summary */}
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: 'Signed Packages', value: stats.signed_packages, total: stats.total_packages, color: 'text-green-400', bg: 'bg-green-500' },
              { label: 'Official Packages', value: stats.official_packages, total: stats.total_packages, color: 'text-cyan-400', bg: 'bg-cyan-500' },
              { label: 'Verified Publishers', value: stats.verified_publishers, total: stats.total_publishers, color: 'text-yellow-400', bg: 'bg-yellow-500' },
            ].map(s => (
              <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <p className={`text-3xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-xs text-gray-500 mt-1">{s.label}</p>
                <div className="mt-3 bg-gray-800 rounded-full h-1.5">
                  <div
                    className={`h-1.5 rounded-full ${s.bg}`}
                    style={{ width: `${Math.round((s.value / (s.total || 1)) * 100)}%` }}
                  />
                </div>
                <p className="text-xs text-gray-600 mt-1">
                  {Math.round((s.value / (s.total || 1)) * 100)}% of {s.total}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
