'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  Cpu, Shield, CheckCircle, AlertTriangle, Lock, Globe,
  Building2, RefreshCw, Send, ChevronDown, ChevronRight,
  Activity, Clock, Hash, FileText, BarChart3, Settings,
} from 'lucide-react';
import {
  getModelRouterTable, getModelRouterProviders, getModelRouterAudit,
  classifyText, updateModelRouterRule, resetModelRouterTable,
  callModelRouter, getModelRouterSensitivityLevels,
} from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────
type RoutingRule = {
  sensitivity: string;
  sensitivity_rank: number;
  provider: string;
  tier: string;
  rationale: string;
};

type ProviderInfo = {
  provider: string;
  status: string;
  tier: string;
  detail?: string;
};

type AuditEntry = {
  id: string;
  timestamp: string;
  caller: string;
  sensitivity: string;
  provider: string;
  model: string;
  latency_ms: number;
  usage: any;
  error: string | null;
  fallback: boolean;
  redacted: boolean;
  prompt_chars: number;
};

type SensitivityLevel = {
  level: string;
  rank: number;
  provider: string;
  tier: string;
  description: string;
  examples: string[];
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
const TIER_COLORS: Record<string, string> = {
  local:      'text-green-400  bg-green-900/30  border-green-800',
  enterprise: 'text-blue-400   bg-blue-900/30   border-blue-800',
  cloud:      'text-purple-400 bg-purple-900/30 border-purple-800',
  unknown:    'text-gray-400   bg-gray-800      border-gray-700',
};

const TIER_ICONS: Record<string, React.ElementType> = {
  local:      Lock,
  enterprise: Building2,
  cloud:      Globe,
  unknown:    Cpu,
};

const SENSITIVITY_COLORS: Record<string, string> = {
  public:       'text-green-400',
  internal:     'text-blue-400',
  confidential: 'text-yellow-400',
  restricted:   'text-orange-400',
  top_secret:   'text-red-400',
};

const PROVIDER_LABELS: Record<string, string> = {
  ollama:       'Ollama (Local)',
  azure_openai: 'Azure OpenAI',
  anthropic:    'Anthropic',
  openai:       'OpenAI',
  mock:         'Mock (Dev)',
};

const ALL_PROVIDERS = ['ollama', 'azure_openai', 'anthropic', 'mock'];

// ─── Component ────────────────────────────────────────────────────────────────
export default function ModelRouterPage() {
  const [rules, setRules]         = useState<RoutingRule[]>([]);
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [audit, setAudit]         = useState<AuditEntry[]>([]);
  const [levels, setLevels]       = useState<SensitivityLevel[]>([]);
  const [loading, setLoading]     = useState(true);
  const [activeTab, setActiveTab] = useState<'routing' | 'test' | 'audit'>('routing');

  // Test panel state
  const [testText, setTestText]       = useState('');
  const [classResult, setClassResult] = useState<any>(null);
  const [classifying, setClassifying] = useState(false);
  const [callResult, setCallResult]   = useState<any>(null);
  const [calling, setCalling]         = useState(false);

  // Rule editor
  const [editingRule, setEditingRule] = useState<string | null>(null);
  const [pendingProvider, setPendingProvider] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [tableData, providersData, auditData, levelsData] = await Promise.all([
        getModelRouterTable().catch(() => ({ routing_table: [] })),
        getModelRouterProviders().catch(() => ({ providers: [] })),
        getModelRouterAudit(30).catch(() => ({ entries: [] })),
        getModelRouterSensitivityLevels().catch(() => ({ levels: [] })),
      ]);
      setRules((tableData as any).routing_table ?? []);
      setProviders((providersData as any).providers ?? []);
      setAudit((auditData as any).entries ?? []);
      setLevels((levelsData as any).levels ?? []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleClassify = async () => {
    if (!testText.trim()) return;
    setClassifying(true);
    setClassResult(null);
    try {
      const res = await classifyText(testText) as any;
      setClassResult(res);
    } finally {
      setClassifying(false);
    }
  };

  const handleCall = async () => {
    if (!testText.trim()) return;
    setCalling(true);
    setCallResult(null);
    try {
      const res = await callModelRouter(testText) as any;
      setCallResult(res);
    } finally {
      setCalling(false);
    }
  };

  const handleSaveRule = async (sensitivity: string) => {
    if (!pendingProvider) return;
    setSaving(true);
    try {
      await updateModelRouterRule(sensitivity, pendingProvider);
      setEditingRule(null);
      await load();
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (!confirm('Reset all routing rules to defaults?')) return;
    await resetModelRouterTable();
    await load();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Cpu className="text-cyan-400" /> Secure Model Router
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            Routes LLM calls to local, enterprise, or cloud providers based on data sensitivity classification.
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Provider status strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {providers.map(p => {
          const TierIcon = TIER_ICONS[p.tier] ?? Cpu;
          const tierClass = TIER_COLORS[p.tier] ?? TIER_COLORS.unknown;
          return (
            <div key={p.provider} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3 flex items-center gap-3">
              <TierIcon className={`w-5 h-5 flex-shrink-0 ${tierClass.split(' ')[0]}`} />
              <div className="min-w-0">
                <p className="text-white text-xs font-medium truncate">{PROVIDER_LABELS[p.provider] ?? p.provider}</p>
                <p className="text-gray-500 text-xs capitalize">{p.tier} tier</p>
              </div>
              <span
                title={p.detail || undefined}
                className={`ml-auto text-xs px-1.5 py-0.5 rounded border flex-shrink-0 ${
                  p.status === 'healthy' ? 'text-green-400 bg-green-900/30 border-green-800' :
                  p.status === 'degraded' ? 'text-yellow-400 bg-yellow-900/30 border-yellow-800' :
                  p.status === 'offline' ? 'text-red-400 bg-red-900/30 border-red-800' :
                  p.status === 'unconfigured' ? 'text-yellow-400 bg-yellow-900/30 border-yellow-800' :
                  'text-gray-400 bg-gray-800 border-gray-700'
                }`}
              >
                {p.status === 'healthy' ? 'Ready'
                  : p.status === 'unconfigured' ? 'No key'
                  : p.status === 'offline' ? 'Offline'
                  : p.status}
              </span>
            </div>
          );
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {(['routing', 'test', 'audit'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium capitalize transition-colors -mb-px border-b-2 ${
              activeTab === tab
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            {tab === 'routing' && 'Routing Rules'}
            {tab === 'test' && 'Test & Classify'}
            {tab === 'audit' && `Audit Log (${audit.length})`}
          </button>
        ))}
      </div>

      {/* ── Tab: Routing Rules ──────────────────────────────────────────────── */}
      {activeTab === 'routing' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button
              onClick={handleReset}
              className="text-xs text-gray-400 hover:text-white bg-gray-800 border border-gray-700 px-3 py-1.5 rounded-lg transition-colors"
            >
              Reset to defaults
            </button>
          </div>

          {/* Flow diagram */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-4">Data Flow</p>
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="flex flex-col items-center gap-1">
                <div className="bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 text-xs text-white font-medium">
                  Prompt
                </div>
                <p className="text-xs text-gray-600">Input</p>
              </div>
              <ChevronRight className="w-4 h-4 text-gray-600 flex-shrink-0" />
              <div className="flex flex-col items-center gap-1">
                <div className="bg-cyan-900/40 border border-cyan-800 rounded-xl px-3 py-2 text-xs text-cyan-400 font-medium">
                  Classifier
                </div>
                <p className="text-xs text-gray-600">Sensitivity</p>
              </div>
              <ChevronRight className="w-4 h-4 text-gray-600 flex-shrink-0" />
              <div className="flex flex-col items-center gap-1">
                <div className="bg-purple-900/40 border border-purple-800 rounded-xl px-3 py-2 text-xs text-purple-400 font-medium">
                  Router
                </div>
                <p className="text-xs text-gray-600">Policy rules</p>
              </div>
              <ChevronRight className="w-4 h-4 text-gray-600 flex-shrink-0" />
              <div className="flex flex-col gap-2">
                {[
                  { label: 'Ollama', sub: 'Restricted/Top Secret', cls: TIER_COLORS.local },
                  { label: 'Azure OpenAI', sub: 'Confidential', cls: TIER_COLORS.enterprise },
                  { label: 'Anthropic', sub: 'Public/Internal', cls: TIER_COLORS.cloud },
                ].map(p => (
                  <div key={p.label} className={`flex items-center gap-2 text-xs px-2.5 py-1.5 rounded-lg border ${p.cls}`}>
                    <span className="font-medium">{p.label}</span>
                    <span className="opacity-60">— {p.sub}</span>
                  </div>
                ))}
              </div>
              <ChevronRight className="w-4 h-4 text-gray-600 flex-shrink-0" />
              <div className="flex flex-col items-center gap-1">
                <div className="bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 text-xs text-white font-medium">
                  Audit
                </div>
                <p className="text-xs text-gray-600">Log entry</p>
              </div>
            </div>
          </div>

          {/* Rules table */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-800">
              <h2 className="font-semibold text-white text-sm">Routing Rules</h2>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 text-xs">
                  <th className="px-5 py-3 text-left">Sensitivity</th>
                  <th className="px-5 py-3 text-left">Provider</th>
                  <th className="px-5 py-3 text-left">Tier</th>
                  <th className="px-5 py-3 text-left">Rationale</th>
                  <th className="px-5 py-3 text-left">Edit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {rules.map(rule => {
                  const sensColor = SENSITIVITY_COLORS[rule.sensitivity] ?? 'text-gray-400';
                  const TierIcon = TIER_ICONS[rule.tier] ?? Cpu;
                  const tierCls = TIER_COLORS[rule.tier] ?? TIER_COLORS.unknown;
                  const isEditing = editingRule === rule.sensitivity;

                  return (
                    <tr key={rule.sensitivity} className="hover:bg-gray-800/30">
                      <td className="px-5 py-3">
                        <span className={`text-xs font-semibold uppercase tracking-wide ${sensColor}`}>
                          {rule.sensitivity.replace('_', ' ')}
                        </span>
                        <p className="text-xs text-gray-500">rank {rule.sensitivity_rank}</p>
                      </td>
                      <td className="px-5 py-3 text-white text-xs font-medium">
                        {PROVIDER_LABELS[rule.provider] ?? rule.provider}
                      </td>
                      <td className="px-5 py-3">
                        <span className={`flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-lg border w-fit ${tierCls}`}>
                          <TierIcon className="w-3 h-3" /> {rule.tier}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-gray-400 text-xs max-w-xs">
                        {rule.rationale}
                      </td>
                      <td className="px-5 py-3">
                        {isEditing ? (
                          <div className="flex items-center gap-2">
                            <select
                              value={pendingProvider}
                              onChange={e => setPendingProvider(e.target.value)}
                              className="bg-gray-800 text-white text-xs rounded border border-gray-600 px-2 py-1"
                            >
                              {ALL_PROVIDERS.map(p => (
                                <option key={p} value={p}>{PROVIDER_LABELS[p] ?? p}</option>
                              ))}
                            </select>
                            <button
                              onClick={() => handleSaveRule(rule.sensitivity)}
                              disabled={saving}
                              className="text-xs text-cyan-400 hover:text-cyan-300"
                            >
                              {saving ? <RefreshCw className="w-3 h-3 animate-spin" /> : 'Save'}
                            </button>
                            <button
                              onClick={() => setEditingRule(null)}
                              className="text-xs text-gray-500 hover:text-white"
                            >Cancel</button>
                          </div>
                        ) : (
                          <button
                            onClick={() => { setEditingRule(rule.sensitivity); setPendingProvider(rule.provider); }}
                            className="text-xs text-gray-400 hover:text-cyan-400 transition-colors"
                          >
                            <Settings className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Sensitivity reference */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {levels.map(l => {
              const sensColor = SENSITIVITY_COLORS[l.level] ?? 'text-gray-400';
              const TierIcon = TIER_ICONS[l.tier] ?? Cpu;
              const tierCls = TIER_COLORS[l.tier] ?? TIER_COLORS.unknown;
              return (
                <div key={l.level} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="flex items-start justify-between mb-2">
                    <span className={`text-xs font-bold uppercase tracking-wider ${sensColor}`}>
                      {l.level.replace('_', ' ')}
                    </span>
                    <span className={`flex items-center gap-1 text-xs px-1.5 py-0.5 rounded border ${tierCls}`}>
                      <TierIcon className="w-3 h-3" /> {PROVIDER_LABELS[l.provider] ?? l.provider}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 mb-2">{l.description}</p>
                  <div className="flex flex-wrap gap-1">
                    {l.examples.map(ex => (
                      <span key={ex} className="text-xs bg-gray-800 text-gray-400 rounded px-1.5 py-0.5">{ex}</span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Tab: Test & Classify ────────────────────────────────────────────── */}
      {activeTab === 'test' && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
            <p className="text-xs text-gray-500 uppercase tracking-wide font-semibold">Test Prompt</p>
            <textarea
              value={testText}
              onChange={e => setTestText(e.target.value)}
              rows={5}
              placeholder="Paste any text to classify its sensitivity and see where it would be routed…"
              className="w-full bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 text-white text-sm placeholder-gray-500 resize-none outline-none focus:border-cyan-700 transition-colors"
            />
            <div className="flex gap-2">
              <button
                onClick={handleClassify}
                disabled={!testText.trim() || classifying}
                className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-xl transition-colors"
              >
                {classifying ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
                Classify Only
              </button>
              <button
                onClick={handleCall}
                disabled={!testText.trim() || calling}
                className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-xl transition-colors"
              >
                {calling ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                Classify &amp; Route
              </button>
            </div>
          </div>

          {/* Classification result */}
          {classResult && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
              <p className="text-xs text-gray-500 uppercase tracking-wide font-semibold">Classification Result</p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                  { label: 'Sensitivity', value: classResult.level?.replace('_', ' '), color: SENSITIVITY_COLORS[classResult.level] ?? 'text-white' },
                  { label: 'Routed to', value: PROVIDER_LABELS[classResult.routed_to] ?? classResult.routed_to, color: 'text-white' },
                  { label: 'Confidence', value: `${Math.round((classResult.confidence ?? 0) * 100)}%`, color: 'text-white' },
                  { label: 'Matched', value: classResult.matched_text ?? 'pattern', color: 'text-yellow-400' },
                ].map(item => (
                  <div key={item.label} className="bg-gray-800 rounded-lg px-3 py-2">
                    <p className="text-xs text-gray-500">{item.label}</p>
                    <p className={`text-sm font-semibold mt-0.5 capitalize truncate ${item.color}`}>{item.value}</p>
                  </div>
                ))}
              </div>
              {classResult.rationale && (
                <p className="text-xs text-gray-400 italic">{classResult.rationale}</p>
              )}
            </div>
          )}

          {/* Model call result */}
          {callResult && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
              <p className="text-xs text-gray-500 uppercase tracking-wide font-semibold">Model Response</p>
              <div className="grid grid-cols-3 gap-3 text-xs">
                <div className="bg-gray-800 rounded-lg px-3 py-2">
                  <p className="text-gray-500">Provider</p>
                  <p className="text-white font-medium mt-0.5">{PROVIDER_LABELS[callResult.provider] ?? callResult.provider}</p>
                </div>
                <div className="bg-gray-800 rounded-lg px-3 py-2">
                  <p className="text-gray-500">Model</p>
                  <p className="text-white font-medium mt-0.5 truncate">{callResult.model || '—'}</p>
                </div>
                <div className="bg-gray-800 rounded-lg px-3 py-2">
                  <p className="text-gray-500">Latency</p>
                  <p className="text-white font-medium mt-0.5">{callResult.latency_ms}ms</p>
                </div>
              </div>
              {callResult.routing && (
                <div className="flex gap-3 flex-wrap text-xs">
                  <span className={`px-2 py-0.5 rounded border ${TIER_COLORS[callResult.routing.provider === 'ollama' ? 'local' : callResult.routing.provider === 'azure_openai' ? 'enterprise' : 'cloud'] ?? TIER_COLORS.unknown}`}>
                    Sensitivity: {callResult.routing.sensitivity}
                  </span>
                  {callResult.routing.redacted && (
                    <span className="text-orange-400 bg-orange-900/20 border border-orange-800 rounded px-2 py-0.5">
                      ⚠ Prompt was redacted before sending
                    </span>
                  )}
                  {callResult.fallback && (
                    <span className="text-yellow-400 bg-yellow-900/20 border border-yellow-800 rounded px-2 py-0.5">
                      Fallback to Mock (primary provider unavailable)
                    </span>
                  )}
                </div>
              )}
              <div className="bg-gray-800/60 rounded-lg px-4 py-3">
                <p className="text-xs text-gray-500 mb-1.5">Response</p>
                <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">{callResult.response}</p>
              </div>
              <p className="text-xs text-gray-600">Audit ID: {callResult.audit_id}</p>
            </div>
          )}
        </div>
      )}

      {/* ── Tab: Audit Log ──────────────────────────────────────────────────── */}
      {activeTab === 'audit' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
            <h2 className="font-semibold text-white text-sm">Routing Audit Log</h2>
            <span className="text-xs text-gray-500">{audit.length} entries</span>
          </div>
          {audit.length === 0 ? (
            <p className="px-5 py-8 text-gray-500 text-sm">No routing decisions yet. Use the Test panel to generate audit entries.</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500">
                  <th className="px-5 py-3 text-left">Timestamp</th>
                  <th className="px-5 py-3 text-left">Sensitivity</th>
                  <th className="px-5 py-3 text-left">Provider</th>
                  <th className="px-5 py-3 text-left">Model</th>
                  <th className="px-5 py-3 text-left">Latency</th>
                  <th className="px-5 py-3 text-left">Caller</th>
                  <th className="px-5 py-3 text-left">Flags</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {audit.map(entry => (
                  <tr key={entry.id} className="hover:bg-gray-800/30">
                    <td className="px-5 py-2 text-gray-400 font-mono">
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-5 py-2">
                      <span className={`font-semibold uppercase tracking-wide ${SENSITIVITY_COLORS[entry.sensitivity] ?? 'text-gray-400'}`}>
                        {entry.sensitivity.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-5 py-2 text-white">{PROVIDER_LABELS[entry.provider] ?? entry.provider}</td>
                    <td className="px-5 py-2 text-gray-400 max-w-[120px] truncate">{entry.model || '—'}</td>
                    <td className="px-5 py-2 text-gray-400">{entry.latency_ms}ms</td>
                    <td className="px-5 py-2 text-gray-400">{entry.caller}</td>
                    <td className="px-5 py-2">
                      <div className="flex gap-1.5">
                        {entry.error && <span className="text-red-400 bg-red-900/20 border border-red-800 rounded px-1.5 py-0.5">error</span>}
                        {entry.fallback && <span className="text-yellow-400 bg-yellow-900/20 border border-yellow-800 rounded px-1.5 py-0.5">fallback</span>}
                        {entry.redacted && <span className="text-orange-400 bg-orange-900/20 border border-orange-800 rounded px-1.5 py-0.5">redacted</span>}
                        {!entry.error && !entry.fallback && !entry.redacted && (
                          <span className="text-green-400">✓</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
