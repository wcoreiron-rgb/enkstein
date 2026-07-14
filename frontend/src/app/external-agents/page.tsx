'use client';
import { useState, useEffect, useCallback } from 'react';
import {
  Globe, Shield, Key, RefreshCw, CheckCircle, XCircle,
  AlertTriangle, Copy, Trash2, Plus, Zap,
  Lock, Activity, ChevronDown, ChevronRight, Terminal,
  ClipboardCheck,
} from 'lucide-react';
import {
  listExternalAgents, registerExternalAgent,
  rotateExternalAgentKey, verifyExternalAgentEndpoint,
  deregisterExternalAgent,
} from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

type ExternalAgent = {
  id: string;
  name: string;
  description: string;
  endpoint_url: string;
  api_key_preview: string;
  allowed_scopes: string[];
  execution_mode: string;
  risk_level: string;
  status: string;
  owner_name: string;
  endpoint_verified_at: string | null;
  endpoint_last_error: string | null;
  total_runs: number;
  last_run_at: string | null;
  last_run_status: string | null;
};

type VerifyResult = {
  ok: boolean;
  status_code?: number;
  findings?: number;
  actions?: number;
  latency_ms?: number;
  raw?: any;
  error?: string;
};

const ALL_SCOPES = [
  { value: '*.read',           label: '*.read',           desc: 'All read-only operations',            risk: 'low'     },
  { value: 'identity:read',    label: 'identity:read',    desc: 'List accounts, read profiles',        risk: 'low'     },
  { value: 'identity:write',   label: 'identity:write',   desc: 'Disable/enable accounts, MFA',       risk: 'medium'  },
  { value: 'secrets:read',     label: 'secrets:read',     desc: 'Read secret metadata',                risk: 'medium'  },
  { value: 'secrets:write',    label: 'secrets:write',    desc: 'Rotate credentials, revoke tokens',   risk: 'high'    },
  { value: 'network:write',    label: 'network:write',    desc: 'Block IPs, firewall rules',           risk: 'high'    },
  { value: 'endpoint:write',   label: 'endpoint:write',   desc: 'Isolate, quarantine hosts',           risk: 'high'    },
  { value: 'cloud:write',      label: 'cloud:write',      desc: 'Modify cloud resources/IAM',         risk: 'high'    },
  { value: 'cloud:read',       label: 'cloud:read',       desc: 'List cloud resources',               risk: 'low'     },
  { value: 'data:read',        label: 'data:read',        desc: 'Flag data for review',               risk: 'low'     },
  { value: 'ai:write',         label: 'ai:write',         desc: 'Block LLM sessions',                 risk: 'medium'  },
  { value: 'compliance:write', label: 'compliance:write', desc: 'Enable logging, schedule reviews',   risk: 'low'     },
  { value: 'compliance:read',  label: 'compliance:read',  desc: 'Generate compliance reports',        risk: 'low'     },
  { value: 'notify:write',     label: 'notify:write',     desc: 'Send alerts, create incidents',      risk: 'low'     },
  { value: '*',                label: '* (all)',           desc: 'Unrestricted — use with care',       risk: 'critical'},
];

const RISK_COLOR: Record<string, string> = {
  low:      'text-green-400 bg-green-900/20 border-green-800',
  medium:   'text-yellow-400 bg-yellow-900/20 border-yellow-800',
  high:     'text-orange-400 bg-orange-900/20 border-orange-800',
  critical: 'text-red-400 bg-red-900/20 border-red-800',
};

// ─── Toast ────────────────────────────────────────────────────────────────────

type Toast = { id: string; msg: string; type: 'success' | 'error' | 'warning' };

function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toast = useCallback((msg: string, type: Toast['type'] = 'success') => {
    const id = crypto.randomUUID();
    setToasts(p => [...p, { id, msg, type }]);
    setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 5000);
  }, []);
  return { toasts, toast };
}

// ─── Secret modal — improved ──────────────────────────────────────────────────

function SecretModal({ secret, onClose }: { secret: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [countdown, setCountdown] = useState(10);

  // Countdown before allowing close without confirming
  useEffect(() => {
    if (countdown <= 0) return;
    const t = setTimeout(() => setCountdown(c => c - 1), 1000);
    return () => clearTimeout(t);
  }, [countdown]);

  const copy = () => {
    navigator.clipboard.writeText(secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
      <div
        className="rounded-2xl max-w-lg w-full p-6 shadow-2xl"
        style={{ background: '#111', border: '1px solid #92400e' }}
      >
        {/* Header */}
        <div className="flex items-center gap-3 mb-1">
          <div className="w-8 h-8 rounded-full bg-yellow-900/40 border border-yellow-700 flex items-center justify-center flex-shrink-0">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
          </div>
          <div>
            <h2 className="text-white font-bold text-base">Save Your Signing Secret</h2>
            <p className="text-yellow-500 text-xs">This is the only time this secret will be shown</p>
          </div>
        </div>

        <div className="h-px bg-yellow-900/40 my-4" />

        {/* Warning box */}
        <div className="bg-yellow-950/50 border border-yellow-800/60 rounded-xl px-4 py-3 mb-4 text-sm text-yellow-300 leading-relaxed">
          Copy this secret and set it as <code className="font-mono bg-yellow-900/40 px-1 rounded text-yellow-200">REGENTCLAW_SIGNING_SECRET</code> in your
          external agent environment. Marcellus stores only a hashed preview — the full secret cannot be retrieved after you close this dialog.
        </div>

        {/* Secret box */}
        <div className="relative mb-4">
          <div
            className="rounded-xl px-4 py-3 font-mono text-sm break-all pr-12 select-all"
            style={{ background: '#0a0a0a', border: '1px solid #1f2937', color: '#34d399' }}
          >
            {secret}
          </div>
          <button
            onClick={copy}
            className="absolute top-2 right-2 p-1.5 rounded-lg transition-colors"
            style={{ background: copied ? '#064e3b' : '#1f2937', color: copied ? '#34d399' : '#9ca3af' }}
            title="Copy to clipboard"
          >
            {copied ? <ClipboardCheck className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>

        {/* Copy button */}
        <button
          onClick={copy}
          className="w-full flex items-center justify-center gap-2 font-semibold py-2.5 rounded-xl mb-3 transition-colors text-sm"
          style={{
            background: copied ? '#064e3b' : '#0e7490',
            color: '#fff',
          }}
        >
          {copied ? <><CheckCircle className="w-4 h-4" /> Copied to clipboard!</> : <><Copy className="w-4 h-4" /> Copy Secret</>}
        </button>

        {/* Confirm checkbox */}
        <label className="flex items-center gap-2.5 cursor-pointer mb-4">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={e => setConfirmed(e.target.checked)}
            className="w-4 h-4 rounded accent-cyan-500"
          />
          <span className="text-sm text-gray-300">I have saved the secret in a secure location</span>
        </label>

        {/* Close */}
        <button
          onClick={onClose}
          disabled={!confirmed && countdown > 0}
          className="w-full py-2.5 rounded-xl text-sm font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          style={{ background: confirmed ? '#1d4ed8' : '#374151', color: '#fff' }}
        >
          {confirmed
            ? "Close — I've saved my secret"
            : countdown > 0
              ? `Please save your secret (${countdown}s)…`
              : "Close anyway"}
        </button>
      </div>
    </div>
  );
}

// ─── Test Connection panel ────────────────────────────────────────────────────

function TestConnectionPanel({ result }: { result: VerifyResult }) {
  const [showRaw, setShowRaw] = useState(false);

  return (
    <div
      className="rounded-xl border overflow-hidden"
      style={{ background: '#0a0a0a', borderColor: result.ok ? '#166534' : '#7f1d1d' }}
    >
      {/* Status bar */}
      <div
        className="flex items-center gap-2 px-4 py-2.5"
        style={{ background: result.ok ? '#052e16' : '#450a0a' }}
      >
        {result.ok
          ? <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
          : <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />}
        <span className="text-sm font-semibold" style={{ color: result.ok ? '#4ade80' : '#f87171' }}>
          {result.ok ? 'Connection verified' : 'Connection failed'}
        </span>
        {result.status_code && (
          <span className="ml-auto text-xs font-mono" style={{ color: result.ok ? '#86efac' : '#fca5a5' }}>
            HTTP {result.status_code}
          </span>
        )}
        {result.latency_ms !== undefined && (
          <span className="text-xs font-mono text-gray-500">{result.latency_ms}ms</span>
        )}
      </div>

      {/* Metrics */}
      {result.ok && (
        <div className="grid grid-cols-2 gap-px border-t" style={{ borderColor: '#166534' }}>
          {[
            { label: 'Findings returned', value: result.findings ?? 0 },
            { label: 'Actions proposed',  value: result.actions  ?? 0 },
          ].map(m => (
            <div key={m.label} className="px-4 py-2.5">
              <p className="text-xs text-gray-500">{m.label}</p>
              <p className="text-white text-lg font-bold">{m.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Error message */}
      {!result.ok && result.error && (
        <div className="px-4 py-3 border-t" style={{ borderColor: '#7f1d1d' }}>
          <p className="text-xs font-mono text-red-300 leading-relaxed">{result.error}</p>
        </div>
      )}

      {/* Raw response toggle */}
      {result.raw !== undefined && (
        <div className="border-t" style={{ borderColor: result.ok ? '#166534' : '#7f1d1d' }}>
          <button
            onClick={() => setShowRaw(!showRaw)}
            className="w-full flex items-center gap-2 px-4 py-2 text-xs text-gray-400 hover:text-gray-200 transition-colors"
          >
            <Terminal className="w-3.5 h-3.5" />
            {showRaw ? 'Hide' : 'Show'} raw response
            {showRaw ? <ChevronDown className="w-3 h-3 ml-auto" /> : <ChevronRight className="w-3 h-3 ml-auto" />}
          </button>
          {showRaw && (
            <pre
              className="px-4 pb-4 text-xs font-mono leading-relaxed overflow-x-auto"
              style={{ color: '#6ee7b7', maxHeight: '200px', overflowY: 'auto' }}
            >
              {JSON.stringify(result.raw, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Register form ────────────────────────────────────────────────────────────

function RegisterForm({ onRegistered }: { onRegistered: (secret: string) => void }) {
  const [open, setOpen]     = useState(false);
  const [saving, setSaving] = useState(false);
  const [name, setName]     = useState('');
  const [desc, setDesc]     = useState('');
  const [url, setUrl]       = useState('');
  const [scopes, setScopes] = useState<string[]>(['*.read']);
  const [mode, setMode]     = useState('monitor');
  const [risk, setRisk]     = useState('low');
  const [error, setError]   = useState('');

  const toggleScope = (s: string) =>
    setScopes(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]);

  const submit = async () => {
    if (!name.trim() || !url.trim()) { setError('Name and endpoint URL are required.'); return; }
    setSaving(true); setError('');
    try {
      const res = await registerExternalAgent({
        name: name.trim(),
        description: desc.trim() || undefined,
        endpoint_url: url.trim(),
        allowed_scopes: scopes,
        execution_mode: mode,
        risk_level: risk,
      }) as any;
      onRegistered(res.signing_secret);
      setOpen(false);
      setName(''); setDesc(''); setUrl(''); setScopes(['*.read']); setMode('monitor'); setRisk('low');
    } catch (e: any) {
      setError(e?.message ?? 'Registration failed');
    } finally {
      setSaving(false);
    }
  };

  if (!open) return (
    <button
      onClick={() => setOpen(true)}
      className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold px-4 py-2 rounded-xl transition-colors"
    >
      <Plus className="w-4 h-4" /> Register External Agent
    </button>
  );

  return (
    <div className="rounded-2xl p-6 mb-6" style={{ background: '#0f172a', border: '1px solid #164e63' }}>
      <h2 className="text-white font-bold text-base mb-4 flex items-center gap-2">
        <Globe className="w-4 h-4 text-cyan-400" /> Register External Agent
      </h2>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="text-xs text-gray-400 block mb-1">Agent Name *</label>
          <input value={name} onChange={e => setName(e.target.value)}
            placeholder="My Vulnerability Scanner"
            className="w-full rounded-xl px-3 py-2 text-sm text-white placeholder-gray-500 outline-none"
            style={{ background: '#1e293b', border: '1px solid #334155' }}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1">Endpoint URL * (HTTPS required)</label>
          <input value={url} onChange={e => setUrl(e.target.value)}
            placeholder="https://my-agent.example.com/run"
            className="w-full rounded-xl px-3 py-2 text-sm text-white placeholder-gray-500 outline-none"
            style={{ background: '#1e293b', border: '1px solid #334155' }}
          />
        </div>
      </div>

      <div className="mb-4">
        <label className="text-xs text-gray-400 block mb-1">Description</label>
        <input value={desc} onChange={e => setDesc(e.target.value)}
          placeholder="What does this agent do?"
          className="w-full rounded-xl px-3 py-2 text-sm text-white placeholder-gray-500 outline-none"
          style={{ background: '#1e293b', border: '1px solid #334155' }}
        />
      </div>

      <div className="mb-4">
        <label className="text-xs text-gray-400 block mb-2">
          Allowed Scopes — <span className="text-yellow-400">least-privilege: only grant what this agent needs</span>
        </label>
        <div className="grid grid-cols-2 gap-1.5">
          {ALL_SCOPES.map(s => (
            <label key={s.value}
              className="flex items-start gap-2 px-3 py-2 rounded-lg cursor-pointer border transition-colors"
              style={{
                background: scopes.includes(s.value) ? 'rgba(14,116,144,0.15)' : 'rgba(30,41,59,0.5)',
                borderColor: scopes.includes(s.value) ? '#0e7490' : '#334155',
              }}
            >
              <input type="checkbox" checked={scopes.includes(s.value)}
                onChange={() => toggleScope(s.value)}
                className="mt-0.5 accent-cyan-500 flex-shrink-0"
              />
              <div className="min-w-0">
                <p className="text-xs font-mono text-white">{s.label}</p>
                <p className="text-xs text-gray-500 truncate">{s.desc}</p>
              </div>
              <span className={`text-xs px-1.5 py-0.5 rounded border ml-auto flex-shrink-0 ${RISK_COLOR[s.risk]}`}>
                {s.risk}
              </span>
            </label>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="text-xs text-gray-400 block mb-1">Execution Mode</label>
          <select value={mode} onChange={e => setMode(e.target.value)}
            className="w-full rounded-xl px-3 py-2 text-sm text-white outline-none"
            style={{ background: '#1e293b', border: '1px solid #334155' }}
          >
            {['monitor','assist','approval','autonomous'].map(m => (
              <option key={m} value={m}>{m.charAt(0).toUpperCase() + m.slice(1)}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1">Risk Level</label>
          <select value={risk} onChange={e => setRisk(e.target.value)}
            className="w-full rounded-xl px-3 py-2 text-sm text-white outline-none"
            style={{ background: '#1e293b', border: '1px solid #334155' }}
          >
            {['low','medium','high','critical'].map(r => (
              <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <p className="text-red-400 text-xs mb-3 rounded-xl px-3 py-2" style={{ background: 'rgba(127,29,29,0.3)', border: '1px solid #991b1b' }}>
          {error}
        </p>
      )}

      <div className="flex gap-3">
        <button onClick={submit} disabled={saving}
          className="flex items-center gap-2 text-white text-sm font-semibold px-4 py-2 rounded-xl transition-colors disabled:opacity-60"
          style={{ background: '#0e7490' }}
        >
          {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
          Register Agent
        </button>
        <button onClick={() => setOpen(false)}
          className="text-gray-400 hover:text-white text-sm px-4 py-2 rounded-xl transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ─── Agent card ───────────────────────────────────────────────────────────────

function AgentCard({ agent, onRefresh, toast }: {
  agent: ExternalAgent;
  onRefresh: () => void;
  toast: (msg: string, type?: 'success' | 'error' | 'warning') => void;
}) {
  const [expanded, setExpanded]       = useState(false);
  const [verifying, setVerifying]     = useState(false);
  const [rotating, setRotating]       = useState(false);
  const [newSecret, setNewSecret]     = useState('');
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);

  const verify = async () => {
    setVerifying(true);
    setVerifyResult(null);
    const start = Date.now();
    try {
      const res = await verifyExternalAgentEndpoint(agent.id) as any;
      setVerifyResult({
        ok:         true,
        status_code: res.status_code ?? 200,
        findings:   res.findings   ?? 0,
        actions:    res.actions    ?? 0,
        latency_ms: Date.now() - start,
        raw:        res,
      });
      toast(`Endpoint verified — ${res.findings ?? 0} findings, ${res.actions ?? 0} actions`);
      onRefresh();
    } catch (e: any) {
      setVerifyResult({
        ok:    false,
        error: e?.message ?? 'Verification failed',
        latency_ms: Date.now() - start,
        raw:   null,
      });
      toast(e?.message ?? 'Verification failed', 'error');
    } finally {
      setVerifying(false);
    }
  };

  const rotate = async () => {
    setRotating(true);
    try {
      const res = await rotateExternalAgentKey(agent.id) as any;
      setNewSecret(res.signing_secret);
      onRefresh();
    } catch (e: any) {
      toast(e?.message ?? 'Key rotation failed', 'error');
    } finally {
      setRotating(false);
    }
  };

  const deregister = async () => {
    if (!confirm(`Deregister "${agent.name}"? This cannot be undone.`)) return;
    try {
      await deregisterExternalAgent(agent.id);
      toast(`${agent.name} deregistered`);
      onRefresh();
    } catch (e: any) {
      toast(e?.message ?? 'Deregister failed', 'error');
    }
  };

  const verified = !!agent.endpoint_verified_at;

  return (
    <>
      {newSecret && <SecretModal secret={newSecret} onClose={() => setNewSecret('')} />}

      <div className="rounded-2xl overflow-hidden" style={{ background: '#0f172a', border: '1px solid #1e293b' }}>
        {/* Header row */}
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center gap-3 px-5 py-4 hover:bg-white/5 transition-colors text-left"
        >
          <Globe className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-white font-semibold text-sm truncate">{agent.name}</p>
            <p className="text-gray-500 text-xs truncate">{agent.endpoint_url}</p>
          </div>

          {verified ? (
            <span className="flex items-center gap-1 text-xs text-green-400 px-2 py-1 rounded-lg flex-shrink-0" style={{ background: 'rgba(22,101,52,0.3)', border: '1px solid #166534' }}>
              <CheckCircle className="w-3 h-3" /> Verified
            </span>
          ) : (
            <span className="flex items-center gap-1 text-xs text-yellow-400 px-2 py-1 rounded-lg flex-shrink-0" style={{ background: 'rgba(120,53,15,0.3)', border: '1px solid #92400e' }}>
              <AlertTriangle className="w-3 h-3" /> Unverified
            </span>
          )}

          <span className={`text-xs px-2 py-1 rounded-lg border flex-shrink-0 ${RISK_COLOR[agent.risk_level] ?? RISK_COLOR.low}`}>
            {agent.risk_level}
          </span>
          {expanded ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
        </button>

        {expanded && (
          <div className="px-5 pb-5 space-y-4 border-t" style={{ borderColor: '#1e293b' }}>
            {/* Error banner */}
            {agent.endpoint_last_error && (
              <div className="flex items-start gap-2 rounded-xl px-4 py-3 mt-4" style={{ background: 'rgba(127,29,29,0.2)', border: '1px solid #991b1b' }}>
                <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-xs font-semibold text-red-400">Last Error</p>
                  <p className="text-xs text-red-300 mt-0.5 font-mono">{agent.endpoint_last_error}</p>
                </div>
              </div>
            )}

            {/* Metadata grid */}
            <div className="grid grid-cols-3 gap-3 pt-4">
              {[
                { label: 'Execution Mode', value: agent.execution_mode },
                { label: 'Runs',           value: String(agent.total_runs) },
                { label: 'Last Run',       value: agent.last_run_at ? new Date(agent.last_run_at).toLocaleDateString() : 'Never' },
              ].map(item => (
                <div key={item.label} className="rounded-xl px-3 py-2" style={{ background: 'rgba(30,41,59,0.6)' }}>
                  <p className="text-xs text-gray-500">{item.label}</p>
                  <p className="text-white text-sm font-medium mt-0.5 capitalize">{item.value}</p>
                </div>
              ))}
            </div>

            {/* API key preview */}
            <div className="rounded-xl px-4 py-3" style={{ background: 'rgba(30,41,59,0.6)' }}>
              <p className="text-xs text-gray-500 mb-1">Signing Secret (preview only)</p>
              <p className="font-mono text-sm text-cyan-400">{agent.api_key_preview}•••••••••••••••••••••••••••••••••••</p>
            </div>

            {/* Scopes */}
            <div>
              <p className="text-xs text-gray-500 mb-2">Granted Scopes</p>
              <div className="flex flex-wrap gap-1.5">
                {agent.allowed_scopes.map(s => (
                  <span key={s} className="text-xs font-mono px-2 py-1 rounded-lg" style={{ background: '#1e293b', border: '1px solid #334155', color: '#67e8f9' }}>
                    {s}
                  </span>
                ))}
              </div>
            </div>

            {/* Test Connection result */}
            {verifyResult && <TestConnectionPanel result={verifyResult} />}

            {/* Zero Trust controls */}
            <div className="rounded-xl px-4 py-3" style={{ background: 'rgba(23,37,84,0.3)', border: '1px solid rgba(37,99,235,0.2)' }}>
              <p className="text-xs font-semibold text-blue-400 mb-2 flex items-center gap-1.5">
                <Lock className="w-3 h-3" /> Zero Trust Controls Active
              </p>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-gray-400">
                <p>✓ SSRF guard — private IPs blocked</p>
                <p>✓ HTTPS enforced — no plain HTTP</p>
                <p>✓ HMAC-SHA256 request signing</p>
                <p>✓ Response signature verified</p>
                <p>✓ Schema validation enforced</p>
                <p>✓ Scope enforcement active</p>
                <p>✓ 30s hard timeout</p>
                <p>✓ Trust Fabric + autonomy mode applied</p>
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 pt-1 flex-wrap">
              <button onClick={verify} disabled={verifying}
                className="flex items-center gap-2 text-white text-xs font-semibold px-3 py-2 rounded-xl transition-colors disabled:opacity-60"
                style={{ background: verifying ? '#14532d' : '#166534' }}
              >
                {verifying ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                {verifying ? 'Testing…' : 'Test Connection'}
              </button>
              <button onClick={rotate} disabled={rotating}
                className="flex items-center gap-2 text-white text-xs font-semibold px-3 py-2 rounded-xl transition-colors disabled:opacity-60"
                style={{ background: '#78350f' }}
              >
                {rotating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Key className="w-3.5 h-3.5" />}
                Rotate Key
              </button>
              <button onClick={deregister}
                className="flex items-center gap-2 text-gray-400 hover:text-red-400 text-xs px-3 py-2 rounded-xl transition-colors ml-auto"
                style={{ background: 'rgba(30,41,59,0.6)' }}
              >
                <Trash2 className="w-3.5 h-3.5" /> Deregister
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ExternalAgentsPage() {
  const [agents, setAgents]       = useState<ExternalAgent[]>([]);
  const [loading, setLoading]     = useState(true);
  const [newSecret, setNewSecret] = useState('');
  const { toasts, toast }         = useToast();

  const load = useCallback(async () => {
    try {
      const res = await listExternalAgents() as any;
      setAgents(res.agents ?? []);
    } catch { /* noop */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-6">
      {/* Toast layer */}
      <div className="fixed top-4 right-4 z-50 space-y-2 pointer-events-none">
        {toasts.map(t => (
          <div key={t.id} className={`px-4 py-3 rounded-xl text-sm font-medium shadow-xl border pointer-events-auto ${
            t.type === 'success' ? 'bg-green-950 border-green-800 text-green-200' :
            t.type === 'error'   ? 'bg-red-950 border-red-800 text-red-200' :
                                   'bg-yellow-950 border-yellow-800 text-yellow-200'
          }`}>
            {t.msg}
          </div>
        ))}
      </div>

      {newSecret && <SecretModal secret={newSecret} onClose={() => { setNewSecret(''); load(); }} />}

      {/* Page header */}
      <div className="pb-4 border-b" style={{ borderColor: '#1e293b' }}>
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Globe className="text-cyan-400" /> External Agents
        </h1>
        <p className="text-gray-400 mt-1 text-sm">
          Register and govern external agents under Marcellus Zero Trust architecture.
          Every call is HMAC-signed, SSRF-protected, scope-enforced, and runs through Trust Fabric.
        </p>
      </div>

      {/* How it works */}
      <div className="rounded-2xl p-5" style={{ background: '#0f172a', border: '1px solid #1e293b' }}>
        <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">How external agents work</p>
        <div className="flex items-start gap-3 overflow-x-auto pb-1">
          {[
            { icon: Globe,    color: 'text-cyan-400',   title: '1. Register',  body: 'Provide your HTTPS endpoint and declare scopes. Marcellus generates a signing secret.' },
            { icon: Key,      color: 'text-yellow-400', title: '2. Configure', body: 'Set REGENTCLAW_SIGNING_SECRET on your agent so it can verify inbound calls and sign responses.' },
            { icon: Shield,   color: 'text-purple-400', title: '3. Dispatch',  body: 'When run, Marcellus signs the payload with HMAC-SHA256 and calls your endpoint.' },
            { icon: Lock,     color: 'text-green-400',  title: '4. Verify',    body: 'Marcellus verifies X-Agent-Signature. Invalid signatures abort the run immediately.' },
            { icon: Activity, color: 'text-blue-400',   title: '5. Govern',    body: 'Findings and actions flow through Trust Fabric, autonomy modes, approval gates, and audit trail.' },
          ].map(({ icon: Icon, color, title, body }) => (
            <div key={title} className="flex-shrink-0 w-44 rounded-xl p-3" style={{ background: 'rgba(30,41,59,0.6)' }}>
              <Icon className={`w-4 h-4 ${color} mb-2`} />
              <p className="text-white text-xs font-semibold">{title}</p>
              <p className="text-gray-400 text-xs mt-1 leading-relaxed">{body}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Register form */}
      <RegisterForm onRegistered={secret => { setNewSecret(secret); load(); }} />

      {/* Agent list */}
      {loading ? (
        <div className="flex items-center gap-2 text-gray-500 text-sm py-8 justify-center">
          <RefreshCw className="w-4 h-4 animate-spin" /> Loading external agents…
        </div>
      ) : agents.length === 0 ? (
        <div className="text-center py-16" style={{ color: '#374151' }}>
          <Globe className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">No external agents registered yet.</p>
          <p className="text-xs mt-1">Register your first external agent above.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {agents.map(a => (
            <AgentCard key={a.id} agent={a} onRefresh={load} toast={toast} />
          ))}
        </div>
      )}
    </div>
  );
}
