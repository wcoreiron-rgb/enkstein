'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  Container, RefreshCw, Plug, ChevronDown, ChevronRight,
  ShieldCheck, ShieldAlert, ShieldX, AlertTriangle,
  Code2, Wand2, FileSearch, ClipboardList, BarChart3,
  Copy, CheckCheck, ExternalLink, Bot, User, Send, TerminalSquare,
  Network, Layers3, Route, Sparkles,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

type Decision = 'APPROVE' | 'WARN' | 'BLOCK';

interface ReviewFinding {
  id: string;
  name: string;
  category: string;
  severity: string;
  risk_delta: number;
  secure_score_delta: number;
  frameworks: string[];
  remediation: string;
  line_hint?: number;
}

interface ReviewResult {
  review_id: string;
  decision: Decision;
  risk_score: number;
  secure_score: number;
  finding_count: number;
  findings: ReviewFinding[];
  frameworks_impacted: Record<string, number>;
  recommended_actions: string[];
  execution_time_ms: number;
}

interface GenerateResult {
  generate_id: string;
  decision: Decision;
  risk_score: number;
  secure_score: number;
  terraform: string;
  template_used: string;
  template_name?: string;
  cloud: string;
  selected_cloud?: string;
  workspace: string;
  environment: string;
  output_mode: string;
  mcp?: { server: string; tool: string; mode: string; terraform_cloud_ready: boolean };
  agent_trace?: Array<{ step: string; status: string; detail: string }>;
  artifacts?: Array<{ path: string; type: string; bytes?: number; variables?: string[]; template?: string }>;
  controls_applied?: string[];
  frameworks_impacted?: Record<string, number>;
  security_review: { finding_count: number; findings: ReviewFinding[] };
  notes: string[];
  next_actions?: Array<{ label: string; target: string; type: string }>;
  execution_time_ms: number;
}

interface PlanChange {
  action: string;
  resource_type: string;
  resource_name: string;
  attribute_changes: Record<string, unknown>;
}

interface PlanResult {
  plan_id: string;
  decision: Decision;
  risk_score: number;
  summary: { creates: number; updates: number; deletes: number; replacements: number; total_changes: number };
  risky_changes: Array<{ resource: string; action: string; severity: string; reason: string; risk_delta: number; new_value?: string }>;
  recommended_actions: string[];
  execution_time_ms: number;
}

// ─── Style helpers ────────────────────────────────────────────────────────────

const SEV: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  CRITICAL: { color: 'text-red-400',    bg: 'bg-red-900/20',    border: 'border-red-800',    dot: 'bg-red-500'    },
  HIGH:     { color: 'text-orange-400', bg: 'bg-orange-900/20', border: 'border-orange-800', dot: 'bg-orange-500' },
  MEDIUM:   { color: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-800', dot: 'bg-yellow-500' },
  LOW:      { color: 'text-blue-400',   bg: 'bg-blue-900/20',   border: 'border-blue-800',   dot: 'bg-blue-500'   },
};
const sev = (s: string) => SEV[s?.toUpperCase()] ?? SEV.LOW;

const DECISION_STYLE: Record<Decision, { color: string; bg: string; border: string; icon: React.ElementType; label: string }> = {
  APPROVE: { color: 'text-green-300',  bg: 'bg-green-900/30',  border: 'border-green-700', icon: ShieldCheck, label: 'APPROVE — Safe to apply' },
  WARN:    { color: 'text-yellow-300', bg: 'bg-yellow-900/30', border: 'border-yellow-700',icon: ShieldAlert, label: 'WARN — Review findings before applying' },
  BLOCK:   { color: 'text-red-300',    bg: 'bg-red-900/30',    border: 'border-red-700',   icon: ShieldX,     label: 'BLOCK — Do not apply until risks are resolved' },
};

function DecisionBanner({ decision, risk_score, secure_score }: { decision: Decision; risk_score: number; secure_score: number }) {
  const ds = DECISION_STYLE[decision];
  const Icon = ds.icon;
  return (
    <div className={`flex items-center gap-4 p-4 rounded-lg border ${ds.bg} ${ds.border}`}>
      <Icon className={`w-8 h-8 flex-shrink-0 ${ds.color}`} />
      <div className="flex-1">
        <p className={`font-bold text-lg ${ds.color}`}>{ds.label}</p>
        <p className="text-sm mt-0.5" style={{ color: 'var(--rc-text-2)' }}>
          Risk Score: <span className={ds.color}>{risk_score}/100</span>
          {' · '}
          Secure Score: <span className={`${secure_score >= 80 ? 'text-green-400' : secure_score >= 60 ? 'text-yellow-400' : 'text-red-400'}`}>{secure_score}/100</span>
        </p>
      </div>
      <div className="text-right hidden sm:block">
        <div className={`text-3xl font-bold ${ds.color}`}>{risk_score}</div>
        <div className="text-xs" style={{ color: 'var(--rc-text-3)' }}>risk score</div>
      </div>
    </div>
  );
}

function FindingCard({ f, expanded, onToggle }: { f: ReviewFinding; expanded: boolean; onToggle: () => void }) {
  const s = sev(f.severity);
  return (
    <div className={`rounded-lg border ${s.border} ${s.bg} overflow-hidden`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 p-3 text-left hover:bg-white/5 transition-colors"
      >
        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.dot}`} />
        <span className="flex-1 text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{f.name}</span>
        <span className={`text-xs font-mono px-2 py-0.5 rounded ${s.bg} ${s.color} border ${s.border}`}>{f.id}</span>
        <span className={`text-xs font-bold ${s.color}`}>{f.severity}</span>
        {f.line_hint && (
          <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>L{f.line_hint}</span>
        )}
        {expanded ? <ChevronDown className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />
                  : <ChevronRight className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />}
      </button>
      {expanded && (
        <div className="px-4 pb-4 space-y-2 border-t border-white/10">
          <p className="text-sm pt-3" style={{ color: 'var(--rc-text-2)' }}>
            <span className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Remediation: </span>
            {f.remediation}
          </p>
          <div className="flex flex-wrap gap-1.5 pt-1">
            {f.frameworks.map(fw => (
              <span key={fw} className="text-xs px-2 py-0.5 rounded bg-regent-900/40 border border-regent-800 text-regent-300">{fw}</span>
            ))}
          </div>
          <div className="flex gap-4 text-xs pt-1" style={{ color: 'var(--rc-text-3)' }}>
            <span>Risk delta: +{f.risk_delta}</span>
            <span>Secure score: {f.secure_score_delta}</span>
            <span>Category: {f.category}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={handleCopy} className="flex items-center gap-1.5 text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10 transition-colors" style={{ color: 'var(--rc-text-2)' }}>
      {copied ? <CheckCheck className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

// ─── Tab: Review ─────────────────────────────────────────────────────────────

function ReviewTab() {
  const [hcl, setHcl] = useState('');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ReviewResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ hcl?: string; context?: string }>).detail;
      if (detail?.hcl) setHcl(detail.hcl);
      if (detail?.context) setContext(detail.context);
    };
    window.addEventListener('terraclaw:set-review-hcl', handler);
    return () => window.removeEventListener('terraclaw:set-review-hcl', handler);
  }, []);

  const handleReview = async () => {
    if (hcl.trim().length < 10) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await apiFetch<ReviewResult>('/terraclaw/review', {
        method: 'POST',
        body: JSON.stringify({ hcl, context }),
      });
      setResult(res);
    } catch (e: any) {
      setError(e?.message ?? 'Review failed');
    } finally {
      setLoading(false);
    }
  };

  const EXAMPLE_HCL = `resource "azurerm_mssql_server" "prod" {
  name                          = "prod-sql"
  resource_group_name           = "prod-rg"
  location                      = "eastus"
  version                       = "12.0"
  administrator_login           = "sqladmin"
  administrator_login_password  = "Passw0rd123!"
  public_network_access_enabled = true
}`;

  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>Terraform HCL</label>
          <button
            onClick={() => setHcl(EXAMPLE_HCL)}
            className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10 transition-colors"
            style={{ color: 'var(--rc-text-3)' }}
          >
            Load example
          </button>
        </div>
        <textarea
          value={hcl}
          onChange={e => setHcl(e.target.value)}
          placeholder="Paste Terraform HCL here (.tf file content)..."
          rows={12}
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm font-mono px-3 py-2 focus:outline-none focus:border-regent-500 resize-y"
          style={{ color: 'var(--rc-text-1)' }}
        />
      </div>
      <div>
        <label className="text-sm font-medium mb-1 block" style={{ color: 'var(--rc-text-2)' }}>Context (optional)</label>
        <input
          value={context}
          onChange={e => setContext(e.target.value)}
          placeholder="e.g. Production Azure SQL deployment, PR #142"
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm px-3 py-2 focus:outline-none focus:border-regent-500"
          style={{ color: 'var(--rc-text-1)' }}
        />
      </div>
      <button
        onClick={handleReview}
        disabled={loading || hcl.trim().length < 10}
        className="px-4 py-2 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
      >
        {loading && <RefreshCw className="w-4 h-4 animate-spin" />}
        {loading ? 'Reviewing…' : 'Run Security Review'}
      </button>

      {error && (
        <div className="p-3 rounded-lg bg-red-900/20 border border-red-800 text-sm text-red-300">{error}</div>
      )}

      {result && (
        <div className="space-y-4 mt-2">
          <DecisionBanner decision={result.decision} risk_score={result.risk_score} secure_score={result.secure_score} />

          {result.findings.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                Findings ({result.finding_count})
              </h3>
              {result.findings.map(f => (
                <FindingCard
                  key={f.id}
                  f={f}
                  expanded={expanded === f.id}
                  onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
                />
              ))}
            </div>
          )}

          {Object.keys(result.frameworks_impacted).length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--rc-text-1)' }}>Frameworks Impacted</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(result.frameworks_impacted).map(([fw, count]) => (
                  <span key={fw} className="text-xs px-2 py-1 rounded bg-regent-900/40 border border-regent-800 text-regent-300">
                    {fw} <span className="opacity-60">({count})</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {result.findings.length === 0 && (
            <div className="p-4 rounded-lg bg-green-900/20 border border-green-800 text-sm text-green-300">
              No security issues detected. Review result: {result.decision}.
            </div>
          )}

          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Reviewed in {result.execution_time_ms}ms · ID: {result.review_id}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Tab: Generate ────────────────────────────────────────────────────────────

function GenerateTab() {
  const [description, setDescription] = useState('');
  const [cloud, setCloud] = useState<'azure' | 'aws' | 'gcp'>('azure');
  const [environment, setEnvironment] = useState('prod');
  const [workspace, setWorkspace] = useState('platform-secure-iac');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GenerateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [chat, setChat] = useState<Array<{ role: 'user' | 'agent'; text: string; id: string }>>([
    {
      id: 'welcome',
      role: 'agent',
      text: 'Describe the infrastructure you want. Terraform Governance will choose a secure module, run Trust Fabric, review the HCL, and return artifacts you can send to plan analysis.',
    },
  ]);

  const inferCloudFromText = (text: string): 'azure' | 'aws' | 'gcp' | null => {
    const lower = text.toLowerCase();
    if (/\b(aws|rds|ec2|aurora|eks|s3|dynamodb)\b/.test(lower)) return 'aws';
    if (/\b(gcp|google cloud|cloud sql|gke|bigquery)\b/.test(lower)) return 'gcp';
    if (/\b(azure|azurerm|aks|mssql|entra|defender)\b/.test(lower)) return 'azure';
    return null;
  };

  const setPrompt = (text: string) => {
    setDescription(text);
    const inferred = inferCloudFromText(text);
    if (inferred) setCloud(inferred);
  };

  const handleGenerate = async () => {
    if (description.trim().length < 5) return;
    setLoading(true);
    setError(null);
    setResult(null);
    const userMessage = {
      id: `user-${Date.now()}`,
      role: 'user' as const,
      text: description.trim(),
    };
    setChat(prev => [...prev, userMessage]);
    try {
      const res = await apiFetch<GenerateResult>('/terraclaw/generate', {
        method: 'POST',
          body: JSON.stringify({ description, cloud: inferCloudFromText(description) ?? cloud, environment, workspace, output_mode: 'module' }),
      });
      setResult(res);
      setChat(prev => [
        ...prev,
        {
          id: res.generate_id,
          role: 'agent',
          text: `${res.decision}: generated ${res.template_name ?? res.template_used} with risk ${res.risk_score}/100 and secure score ${res.secure_score}/100.`,
        },
      ]);
    } catch (e: any) {
      setError(e?.message ?? 'Generation failed');
      setChat(prev => [...prev, { id: `err-${Date.now()}`, role: 'agent', text: `Generation failed: ${e?.message ?? 'Unknown error'}` }]);
    } finally {
      setLoading(false);
    }
  };

  const sendToReview = () => {
    if (!result) return;
    window.dispatchEvent(new CustomEvent('terraclaw:switch-tab', { detail: { tab: 'review' } }));
    window.setTimeout(() => {
      window.dispatchEvent(new CustomEvent('terraclaw:set-review-hcl', {
        detail: {
          hcl: result.terraform,
          context: `${result.template_name ?? result.template_used} · ${result.cloud}/${result.environment} · ${result.generate_id}`,
        },
      }));
    }, 0);
  };

  const sendToPlan = () => {
    if (!result) return;
    const resources = result.artifacts?.find(a => a.path === 'main.tf');
    const sample = JSON.stringify([
      {
        action: 'create',
        resource_type: result.template_used,
        resource_name: result.template_name ?? result.template_used,
        attribute_changes: { source: resources?.path ?? 'main.tf', generated_by: result.generate_id },
      },
    ], null, 2);
    window.dispatchEvent(new CustomEvent('terraclaw:switch-tab', { detail: { tab: 'plan' } }));
    window.setTimeout(() => {
      window.dispatchEvent(new CustomEvent('terraclaw:set-plan-json', {
        detail: {
          planJson: sample,
          context: `Plan pre-check for ${result.generate_id}`,
        },
      }));
    }, 0);
  };

  const EXAMPLES = [
    'Secure Azure SQL Server with Private Endpoint and Defender',
    'Azure Storage Account with encryption and no public access',
    'AWS RDS PostgreSQL with encryption and private subnets',
    'AWS EC2 instance with SSM access (no SSH keys)',
    'Private AKS cluster with Defender for Containers',
  ];

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.35fr)] gap-4">
      <div className="space-y-4">
        <div className="rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)]">
          <div className="border-b border-white/10 px-4 py-3 flex items-center gap-2">
            <Bot className="w-4 h-4 text-orange-300" />
            <div>
              <p className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Terraform Governance Agent</p>
              <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Terraform MCP · Trust Fabric · secure module generation</p>
            </div>
          </div>
          <div className="p-4 space-y-3 max-h-[360px] overflow-auto">
            {chat.map(msg => (
              <div key={msg.id} className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                {msg.role === 'agent' && <Bot className="w-5 h-5 mt-1 text-orange-300 flex-shrink-0" />}
                <div className={`max-w-[86%] rounded-lg px-3 py-2 text-sm border ${
                  msg.role === 'user'
                    ? 'bg-regent-900/40 border-regent-700 text-regent-100'
                    : 'bg-white/5 border-white/10'
                }`} style={msg.role === 'agent' ? { color: 'var(--rc-text-2)' } : {}}>
                  {msg.text}
                </div>
                {msg.role === 'user' && <User className="w-5 h-5 mt-1 text-regent-300 flex-shrink-0" />}
              </div>
            ))}
            {loading && (
              <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--rc-text-3)' }}>
                <RefreshCw className="w-4 h-4 animate-spin" /> Terraform Governance is selecting a module, applying policy, and reviewing HCL…
              </div>
            )}
          </div>
        </div>

        <div>
          <label className="text-sm font-medium mb-2 block" style={{ color: 'var(--rc-text-1)' }}>Describe what you want to deploy</label>
          <textarea
            value={description}
            onChange={e => {
              setDescription(e.target.value);
              const inferred = inferCloudFromText(e.target.value);
              if (inferred) setCloud(inferred);
            }}
            placeholder="e.g. Create Azure SQL with private endpoint, Defender, diagnostics, Key Vault-ready variables, and no public network access"
            rows={4}
            className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm px-3 py-2 focus:outline-none focus:border-regent-500 resize-none"
            style={{ color: 'var(--rc-text-1)' }}
          />
        </div>

        <div className="flex flex-wrap gap-2">
          {EXAMPLES.map(ex => (
            <button
              key={ex}
            onClick={() => setPrompt(ex)}
              className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10 transition-colors text-left"
              style={{ color: 'var(--rc-text-3)' }}
            >
              {ex}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--rc-text-2)' }}>Workspace</label>
            <input
              value={workspace}
              onChange={e => setWorkspace(e.target.value)}
              className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm px-3 py-2 focus:outline-none focus:border-regent-500"
              style={{ color: 'var(--rc-text-1)' }}
            />
          </div>
          <div>
            <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--rc-text-2)' }}>Environment</label>
            <input
              value={environment}
              onChange={e => setEnvironment(e.target.value)}
              className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm px-3 py-2 focus:outline-none focus:border-regent-500"
              style={{ color: 'var(--rc-text-1)' }}
            />
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-sm font-medium" style={{ color: 'var(--rc-text-2)' }}>Cloud:</label>
          {(['azure', 'aws', 'gcp'] as const).map(c => (
            <button
              key={c}
              onClick={() => setCloud(c)}
              className={`text-sm px-3 py-1 rounded border transition-colors ${
                cloud === c
                  ? 'border-regent-500 bg-regent-900/40 text-regent-300'
                  : 'border-white/10 hover:bg-white/10'
              }`}
              style={cloud !== c ? { color: 'var(--rc-text-2)' } : {}}
            >
              {c.toUpperCase()}
            </button>
          ))}
        </div>

        <button
          onClick={handleGenerate}
          disabled={loading || description.trim().length < 5}
          className="px-4 py-2 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          {loading ? 'Generating…' : 'Generate Secure Terraform'}
        </button>
      </div>

      <div className="space-y-4">

      {error && (
        <div className="p-3 rounded-lg bg-red-900/20 border border-red-800 text-sm text-red-300">{error}</div>
      )}

      {result && (
        <div className="space-y-4 mt-2">
          <DecisionBanner decision={result.decision} risk_score={result.risk_score} secure_score={result.secure_score} />

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="rounded-lg border border-white/10 bg-white/5 p-3">
              <div className="flex items-center gap-2 text-xs uppercase tracking-wide" style={{ color: 'var(--rc-text-3)' }}>
                <Network className="w-4 h-4" /> MCP Mode
              </div>
              <p className="mt-1 text-sm font-semibold text-orange-300">{result.mcp?.mode ?? 'local_guarded_fallback'}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>{result.mcp?.server ?? 'marcellus-mcp'} · {result.mcp?.tool ?? 'generate'}</p>
            </div>
            <div className="rounded-lg border border-white/10 bg-white/5 p-3">
              <div className="flex items-center gap-2 text-xs uppercase tracking-wide" style={{ color: 'var(--rc-text-3)' }}>
                <Layers3 className="w-4 h-4" /> Module
              </div>
              <p className="mt-1 text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{result.template_name ?? result.template_used}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>{result.cloud.toUpperCase()} · {result.environment} · {result.workspace}</p>
            </div>
            <div className="rounded-lg border border-white/10 bg-white/5 p-3">
              <div className="flex items-center gap-2 text-xs uppercase tracking-wide" style={{ color: 'var(--rc-text-3)' }}>
                <Route className="w-4 h-4" /> Next Gates
              </div>
              <div className="flex gap-2 mt-2 flex-wrap">
                <button onClick={sendToReview} className="text-xs px-2 py-1 rounded border border-green-800 bg-green-900/20 text-green-300 hover:bg-green-900/30">Review</button>
                <button onClick={sendToPlan} className="text-xs px-2 py-1 rounded border border-blue-800 bg-blue-900/20 text-blue-300 hover:bg-blue-900/30">Plan</button>
              </div>
            </div>
          </div>

          {result.agent_trace && result.agent_trace.length > 0 && (
            <div className="rounded-lg border border-white/10 bg-white/5 p-3">
              <h3 className="text-sm font-semibold mb-2 flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
                <Sparkles className="w-4 h-4 text-orange-300" /> Agent Trace
              </h3>
              <div className="space-y-2">
                {result.agent_trace.map(step => (
                  <div key={step.step} className="flex gap-2 text-xs">
                    <span className="mt-1 w-2 h-2 rounded-full bg-green-400 flex-shrink-0" />
                    <div>
                      <span className="font-mono text-regent-300">{step.step}</span>
                      <span className="ml-2" style={{ color: 'var(--rc-text-3)' }}>{step.detail}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                Generated Terraform
                <span className="ml-2 text-xs font-normal" style={{ color: 'var(--rc-text-3)' }}>template: {result.template_used}</span>
              </h3>
              <CopyButton text={result.terraform} />
            </div>
            <pre className="rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] p-4 text-xs font-mono overflow-auto max-h-96 leading-relaxed" style={{ color: 'var(--rc-text-1)' }}>
              {result.terraform}
            </pre>
          </div>

          {result.security_review.finding_count === 0 ? (
            <div className="p-3 rounded-lg bg-green-900/20 border border-green-800 text-sm text-green-300">
              Security review passed — generated code uses secure-by-default settings.
            </div>
          ) : (
            <div className="space-y-2">
              <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                Security Review ({result.security_review.finding_count} findings)
              </h3>
              {result.security_review.findings.map(f => (
                <FindingCard
                  key={f.id}
                  f={f}
                  expanded={expanded === f.id}
                  onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
                />
              ))}
            </div>
          )}

          {result.artifacts && result.artifacts.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2 flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
                <TerminalSquare className="w-4 h-4 text-regent-300" /> Output Artifacts
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {result.artifacts.map(a => (
                  <div key={a.path} className="rounded-lg border border-white/10 bg-white/5 p-3">
                    <p className="text-sm font-mono" style={{ color: 'var(--rc-text-1)' }}>{a.path}</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>{a.type}{a.bytes ? ` · ${a.bytes} bytes` : ''}</p>
                    {a.variables && a.variables.length > 0 && (
                      <p className="text-xs mt-1 text-regent-300">{a.variables.length} variables</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.controls_applied && result.controls_applied.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--rc-text-1)' }}>Controls Applied</h3>
              <div className="flex flex-wrap gap-1.5">
                {result.controls_applied.map(ctrl => (
                  <span key={ctrl} className="text-xs px-2 py-0.5 rounded bg-regent-900/40 border border-regent-800 text-regent-300">{ctrl}</span>
                ))}
              </div>
            </div>
          )}

          {result.notes.length > 0 && (
            <div className="p-3 rounded-lg bg-blue-900/20 border border-blue-800 space-y-1">
              {result.notes.map((n, i) => (
                <p key={i} className="text-sm text-blue-300">• {n}</p>
              ))}
            </div>
          )}

          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Generated in {result.execution_time_ms}ms · ID: {result.generate_id}
          </p>
        </div>
      )}
      {!result && !error && (
        <div className="rounded-lg border border-dashed border-white/15 bg-white/5 p-8 text-center">
          <Wand2 className="w-8 h-8 mx-auto text-orange-300" />
          <p className="mt-3 text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Generated Terraform will appear here</p>
          <p className="mt-1 text-xs max-w-md mx-auto" style={{ color: 'var(--rc-text-3)' }}>
            Terraform Governance returns the module, Trust Fabric decision, controls, MCP trace, review findings, and plan-ready artifacts.
          </p>
        </div>
      )}
      </div>
    </div>
  );
}

// ─── Tab: Plan Analysis ───────────────────────────────────────────────────────

const PLAN_EXAMPLE_JSON = JSON.stringify([
  {
    action: 'update',
    resource_type: 'azurerm_mssql_server',
    resource_name: 'prod-sql',
    attribute_changes: { public_network_access_enabled: true },
  },
  {
    action: 'create',
    resource_type: 'azurerm_private_endpoint',
    resource_name: 'sql-pe',
    attribute_changes: {},
  },
  {
    action: 'delete',
    resource_type: 'azurerm_network_security_rule',
    resource_name: 'allow-internal-only',
    attribute_changes: {},
  },
], null, 2);

function PlanTab() {
  const [planJson, setPlanJson] = useState('');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setPlanResult] = useState<PlanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ planJson?: string; context?: string }>).detail;
      if (detail?.planJson) setPlanJson(detail.planJson);
      if (detail?.context) setContext(detail.context);
    };
    window.addEventListener('terraclaw:set-plan-json', handler);
    return () => window.removeEventListener('terraclaw:set-plan-json', handler);
  }, []);

  const handleAnalyze = async () => {
    setParseError(null);
    setError(null);
    let changes: PlanChange[];
    try {
      changes = JSON.parse(planJson);
      if (!Array.isArray(changes)) throw new Error('Expected a JSON array of changes');
    } catch (e: any) {
      setParseError(`JSON parse error: ${e.message}`);
      return;
    }
    setLoading(true);
    setPlanResult(null);
    try {
      const res = await apiFetch<PlanResult>('/terraclaw/plan', {
        method: 'POST',
        body: JSON.stringify({ changes, context }),
      });
      setPlanResult(res);
    } catch (e: any) {
      setError(e?.message ?? 'Plan analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const SMAP: Record<string, string> = {
    CRITICAL: 'text-red-400', HIGH: 'text-orange-400', MEDIUM: 'text-yellow-400', LOW: 'text-blue-400',
  };

  return (
    <div className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>
        Paste a JSON array of planned changes — each with <code className="text-xs bg-white/10 px-1 rounded">action</code>, <code className="text-xs bg-white/10 px-1 rounded">resource_type</code>, <code className="text-xs bg-white/10 px-1 rounded">resource_name</code>, and <code className="text-xs bg-white/10 px-1 rounded">attribute_changes</code>.
      </p>

      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>Plan Changes (JSON)</label>
          <button
            onClick={() => setPlanJson(PLAN_EXAMPLE_JSON)}
            className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10 transition-colors"
            style={{ color: 'var(--rc-text-3)' }}
          >
            Load example
          </button>
        </div>
        <textarea
          value={planJson}
          onChange={e => { setPlanJson(e.target.value); setParseError(null); }}
          placeholder='[{"action":"update","resource_type":"azurerm_mssql_server","resource_name":"prod-sql","attribute_changes":{"public_network_access_enabled":true}}]'
          rows={10}
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm font-mono px-3 py-2 focus:outline-none focus:border-regent-500 resize-y"
          style={{ color: 'var(--rc-text-1)' }}
        />
        {parseError && <p className="text-xs text-red-400 mt-1">{parseError}</p>}
      </div>

      <div>
        <label className="text-sm font-medium mb-1 block" style={{ color: 'var(--rc-text-2)' }}>Context (optional)</label>
        <input
          value={context}
          onChange={e => setContext(e.target.value)}
          placeholder="e.g. Pre-prod Terraform apply — sprint 7 deployment"
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm px-3 py-2 focus:outline-none focus:border-regent-500"
          style={{ color: 'var(--rc-text-1)' }}
        />
      </div>

      <button
        onClick={handleAnalyze}
        disabled={loading || planJson.trim().length < 5}
        className="px-4 py-2 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
      >
        {loading && <RefreshCw className="w-4 h-4 animate-spin" />}
        {loading ? 'Analyzing…' : 'Analyze Plan'}
      </button>

      {error && (
        <div className="p-3 rounded-lg bg-red-900/20 border border-red-800 text-sm text-red-300">{error}</div>
      )}

      {result && (
        <div className="space-y-4 mt-2">
          <DecisionBanner decision={result.decision} risk_score={result.risk_score} secure_score={100 - result.risk_score} />

          {/* Summary chips */}
          <div className="flex flex-wrap gap-2">
            {[
              { label: 'Creates', val: result.summary.creates, color: 'text-green-400' },
              { label: 'Updates', val: result.summary.updates, color: 'text-blue-400' },
              { label: 'Deletes', val: result.summary.deletes, color: 'text-red-400' },
              { label: 'Replacements', val: result.summary.replacements, color: 'text-orange-400' },
            ].map(({ label, val, color }) => (
              <div key={label} className="px-3 py-1.5 rounded border border-white/10 bg-white/5">
                <span className={`text-base font-bold ${color}`}>{val}</span>
                <span className="text-xs ml-1" style={{ color: 'var(--rc-text-3)' }}>{label}</span>
              </div>
            ))}
          </div>

          {result.risky_changes.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--rc-text-1)' }}>
                Risky Changes ({result.risky_changes.length})
              </h3>
              <div className="space-y-2">
                {result.risky_changes.map((c, i) => {
                  const color = SMAP[c.severity] ?? 'text-gray-400';
                  return (
                    <div key={i} className="p-3 rounded-lg border border-white/10 bg-white/5 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <code className="text-xs font-mono" style={{ color: 'var(--rc-text-1)' }}>{c.resource}</code>
                        <span className={`text-xs font-bold flex-shrink-0 ${color}`}>{c.severity}</span>
                      </div>
                      <p className="text-xs" style={{ color: 'var(--rc-text-2)' }}>
                        <span className="font-mono bg-white/10 px-1 rounded">{c.action}</span>
                        {c.new_value && <span className="ml-2 text-orange-300">→ {c.new_value}</span>}
                      </p>
                      <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{c.reason}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {result.risky_changes.length === 0 && (
            <div className="p-3 rounded-lg bg-green-900/20 border border-green-800 text-sm text-green-300">
              No risky attribute changes detected. Plan looks safe to apply.
            </div>
          )}

          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Analyzed in {result.execution_time_ms}ms · ID: {result.plan_id}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Tab: Findings ────────────────────────────────────────────────────────────

function FindingsTab() {
  const [findings, setFindings] = useState<any[]>([]);
  const [stats, setStats]       = useState<any>(null);
  const [providers, setProviders] = useState<any[]>([]);
  const [loading, setLoading]   = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg]   = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filterSev, setFilterSev] = useState('all');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, f, p] = await Promise.all([
        apiFetch<any>('/terraclaw/stats'),
        apiFetch<any[]>('/terraclaw/findings'),
        apiFetch<any[]>('/terraclaw/providers'),
      ]);
      setStats(s); setFindings(f); setProviders(p);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleScan = async () => {
    setScanning(true); setScanMsg(null);
    try {
      const res = await apiFetch<any>('/terraclaw/scan', { method: 'POST' });
      await load();
      setScanMsg({ type: 'success', text: `Scan complete — ${res.findings_created ?? 0} new, ${res.findings_updated ?? 0} updated.` });
    } catch (e: any) {
      setScanMsg({ type: 'error', text: `Scan failed: ${e?.message ?? 'Unknown error'}` });
    } finally {
      setScanning(false);
      setTimeout(() => setScanMsg(null), 8000);
    }
  };

  const shown = filterSev === 'all' ? findings : findings.filter(f => f.severity?.toUpperCase() === filterSev);
  const configured = providers.filter(p => p.configured).length;

  if (loading) {
    return <div className="text-sm py-8 text-center" style={{ color: 'var(--rc-text-3)' }}>Loading findings…</div>;
  }

  return (
    <div className="space-y-4">
      {/* KPI row */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            { label: 'Total', val: stats.total, c: 'text-green-400 bg-green-900/20 border-green-800' },
            { label: 'Critical', val: stats.critical, c: 'text-red-400 bg-red-900/20 border-red-800' },
            { label: 'High', val: stats.high, c: 'text-orange-400 bg-orange-900/20 border-orange-800' },
            { label: 'Medium', val: stats.medium, c: 'text-yellow-400 bg-yellow-900/20 border-yellow-800' },
            { label: 'Secure Score', val: stats.secure_score ?? '—', c: (stats.secure_score ?? 0) >= 80 ? 'text-green-400 bg-green-900/20 border-green-800' : 'text-yellow-400 bg-yellow-900/20 border-yellow-800' },
            { label: 'Connectors', val: `${configured}/${providers.length}`, c: configured > 0 ? 'text-green-400 bg-green-900/20 border-green-800' : 'text-gray-400 bg-gray-900/20 border-gray-700' },
          ].map(({ label, val, c }) => (
            <div key={label} className={`rounded-lg border px-3 py-2.5 text-center ${c}`}>
              <div className="text-xl font-bold">{val}</div>
              <div className="text-xs opacity-70">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-3 flex-wrap">
        <button
          onClick={handleScan}
          disabled={scanning}
          className="px-3 py-1.5 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
          {scanning ? 'Scanning…' : 'Run Scan'}
        </button>
        {(['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s => (
          <button
            key={s}
            onClick={() => setFilterSev(s)}
            className={`text-xs px-2.5 py-1 rounded border transition-colors ${filterSev === s ? 'border-regent-500 bg-regent-900/40 text-regent-300' : 'border-white/10 hover:bg-white/10'}`}
            style={filterSev !== s ? { color: 'var(--rc-text-2)' } : {}}
          >
            {s === 'all' ? 'All' : s}
          </button>
        ))}
      </div>

      {scanMsg && (
        <div className={`p-3 rounded-lg border text-sm ${scanMsg.type === 'success' ? 'bg-green-900/20 border-green-800 text-green-300' : 'bg-red-900/20 border-red-800 text-red-300'}`}>
          {scanMsg.text}
        </div>
      )}

      {/* Findings list */}
      <div className="space-y-2">
        {shown.map((f: any) => {
          const s = sev(f.severity);
          const id = f.id;
          return (
            <div key={id} className={`rounded-lg border ${s.border} ${s.bg} overflow-hidden`}>
              <button
                onClick={() => setExpanded(expanded === id ? null : id)}
                className="w-full flex items-center gap-3 p-3 text-left hover:bg-white/5 transition-colors"
              >
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.dot}`} />
                <span className="flex-1 text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{f.title}</span>
                <span className={`text-xs font-bold ${s.color} flex-shrink-0`}>{f.severity}</span>
                <span className="text-xs flex-shrink-0" style={{ color: 'var(--rc-text-3)' }}>{f.resource_type}</span>
                {expanded === id ? <ChevronDown className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />
                                : <ChevronRight className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />}
              </button>
              {expanded === id && (
                <div className="px-4 pb-4 space-y-2 border-t border-white/10">
                  <p className="text-sm pt-3" style={{ color: 'var(--rc-text-2)' }}>{f.description}</p>
                  <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>
                    <span className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Remediation: </span>
                    {f.remediation}
                  </p>
                  <div className="flex flex-wrap gap-2 text-xs" style={{ color: 'var(--rc-text-3)' }}>
                    {f.resource_name && <span>Resource: <span style={{ color: 'var(--rc-text-2)' }}>{f.resource_name}</span></span>}
                    {f.region && <span>Region: <span style={{ color: 'var(--rc-text-2)' }}>{f.region}</span></span>}
                    {f.provider && <span>Provider: <span style={{ color: 'var(--rc-text-2)' }}>{f.provider}</span></span>}
                  </div>
                  {f.frameworks && f.frameworks.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {f.frameworks.map((fw: string) => (
                        <span key={fw} className="text-xs px-2 py-0.5 rounded bg-regent-900/40 border border-regent-800 text-regent-300">{fw}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {shown.length === 0 && (
          <p className="text-sm text-center py-8" style={{ color: 'var(--rc-text-3)' }}>
            No findings for the selected filter.
          </p>
        )}
      </div>
    </div>
  );
}

// ─── Tab: Compliance ──────────────────────────────────────────────────────────

const FRAMEWORK_RULES: Record<string, { id: string; name: string; ruleIds: string[] }[]> = {
  'CIS Azure': [
    { id: 'CIS-AZ-3.1',  name: 'Ensure HTTPS-only traffic on Storage Accounts', ruleIds: ['TC-DATA-002'] },
    { id: 'CIS-AZ-3.7',  name: 'Ensure public blob access is disabled', ruleIds: ['TC-DATA-001'] },
    { id: 'CIS-AZ-4.1',  name: 'Ensure SQL Server disables public network access', ruleIds: ['TC-NET-004'] },
    { id: 'CIS-AZ-6.1',  name: 'Ensure RDP access is restricted from internet', ruleIds: ['TC-NET-002'] },
    { id: 'CIS-AZ-6.2',  name: 'Ensure SSH access is restricted from internet', ruleIds: ['TC-NET-001'] },
    { id: 'CIS-AZ-8.2',  name: 'Ensure AKS cluster API server is private', ruleIds: ['TC-NET-005'] },
  ],
  'CIS AWS': [
    { id: 'CIS-AWS-4.1', name: 'Ensure no security groups allow SSH from 0.0.0.0/0', ruleIds: ['TC-NET-001', 'TC-NET-003'] },
    { id: 'CIS-AWS-4.2', name: 'Ensure no security groups allow RDP from 0.0.0.0/0', ruleIds: ['TC-NET-002'] },
    { id: 'CIS-AWS-2.3', name: 'Ensure RDS instances have encryption enabled', ruleIds: ['TC-DATA-003'] },
  ],
  'NIST 800-53': [
    { id: 'NIST-AC-6',   name: 'Least Privilege', ruleIds: ['TC-IAM-001', 'TC-IAM-002'] },
    { id: 'NIST-SC-7',   name: 'Boundary Protection', ruleIds: ['TC-NET-001', 'TC-NET-002', 'TC-NET-003', 'TC-NET-004', 'TC-NET-005'] },
    { id: 'NIST-SC-8',   name: 'Transmission Confidentiality', ruleIds: ['TC-DATA-002', 'TC-DATA-004'] },
    { id: 'NIST-SC-28',  name: 'Protection of Information at Rest', ruleIds: ['TC-DATA-003', 'TC-DATA-001'] },
    { id: 'NIST-AU-2',   name: 'Event Logging', ruleIds: ['TC-MON-001', 'TC-MON-002'] },
    { id: 'NIST-IA-5',   name: 'Authenticator Management', ruleIds: ['TC-SEC-001'] },
  ],
  'SOC 2': [
    { id: 'CC6.1',  name: 'Logical and Physical Access Controls', ruleIds: ['TC-DATA-001', 'TC-DATA-003'] },
    { id: 'CC6.2',  name: 'Authenticator Management', ruleIds: ['TC-SEC-001'] },
    { id: 'CC6.3',  name: 'Least Privilege Access', ruleIds: ['TC-IAM-001', 'TC-IAM-002'] },
    { id: 'CC6.6',  name: 'Network Restriction', ruleIds: ['TC-NET-001', 'TC-NET-002', 'TC-NET-004', 'TC-NET-005'] },
    { id: 'CC6.7',  name: 'Transmission Encryption', ruleIds: ['TC-DATA-002', 'TC-DATA-004'] },
    { id: 'CC7.2',  name: 'Monitoring of System Components', ruleIds: ['TC-MON-001', 'TC-MON-002'] },
  ],
};

function ComplianceTab() {
  const [selectedFW, setSelectedFW] = useState('CIS Azure');
  const controls = FRAMEWORK_RULES[selectedFW] ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {Object.keys(FRAMEWORK_RULES).map(fw => (
          <button
            key={fw}
            onClick={() => setSelectedFW(fw)}
            className={`text-sm px-3 py-1.5 rounded border transition-colors ${
              selectedFW === fw
                ? 'border-regent-500 bg-regent-900/40 text-regent-300'
                : 'border-white/10 hover:bg-white/10'
            }`}
            style={selectedFW !== fw ? { color: 'var(--rc-text-2)' } : {}}
          >
            {fw}
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-white/10 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10" style={{ background: 'var(--rc-bg-elevated)' }}>
              <th className="text-left px-4 py-2.5 font-medium" style={{ color: 'var(--rc-text-2)' }}>Control ID</th>
              <th className="text-left px-4 py-2.5 font-medium" style={{ color: 'var(--rc-text-2)' }}>Control Name</th>
              <th className="text-left px-4 py-2.5 font-medium" style={{ color: 'var(--rc-text-2)' }}>Governance Rules</th>
            </tr>
          </thead>
          <tbody>
            {controls.map((ctrl, i) => (
              <tr key={ctrl.id} className={`border-b border-white/5 ${i % 2 === 0 ? '' : 'bg-white/2'} hover:bg-white/5 transition-colors`}>
                <td className="px-4 py-3 font-mono text-xs text-regent-300">{ctrl.id}</td>
                <td className="px-4 py-3" style={{ color: 'var(--rc-text-1)' }}>{ctrl.name}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {ctrl.ruleIds.map(rid => (
                      <span key={rid} className="text-xs px-1.5 py-0.5 rounded bg-white/10 font-mono" style={{ color: 'var(--rc-text-2)' }}>{rid}</span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="p-4 rounded-lg bg-blue-900/10 border border-blue-900/40">
        <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>
          Compliance coverage is based on infrastructure-governance rules mapped to framework controls.
          Run a <span className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Review</span> or <span className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Scan</span> to generate evidence against these controls.
          For a full evidence export, use <span className="font-semibold text-green-400">Compliance Assurance → Evidence Export</span>.
        </p>
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'review',     label: 'Review',       icon: FileSearch    },
  { id: 'generate',   label: 'Generate',     icon: Wand2         },
  { id: 'plan',       label: 'Plan Analysis',icon: BarChart3     },
  { id: 'findings',   label: 'Findings',     icon: ClipboardList },
  { id: 'compliance', label: 'Compliance',   icon: Code2         },
] as const;

type TabId = typeof TABS[number]['id'];

export default function TerraClawPage() {
  const [activeTab, setActiveTab] = useState<TabId>('review');

  useEffect(() => {
    const handler = (event: Event) => {
      const tab = (event as CustomEvent<{ tab?: TabId }>).detail?.tab;
      if (tab && TABS.some(t => t.id === tab)) setActiveTab(tab);
    };
    window.addEventListener('terraclaw:switch-tab', handler);
    return () => window.removeEventListener('terraclaw:switch-tab', handler);
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
            <Container className="text-orange-400" /> Terraform Governance
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
            Terraform security governance — review, generate, and gate IaC with APPROVE / WARN / BLOCK decisions.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-white/10">
        <nav className="flex gap-1 -mb-px overflow-x-auto">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === id
                  ? 'border-regent-500 text-regent-300'
                  : 'border-transparent hover:border-white/20'
              }`}
              style={activeTab !== id ? { color: 'var(--rc-text-2)' } : {}}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'review'     && <ReviewTab />}
        {activeTab === 'generate'   && <GenerateTab />}
        {activeTab === 'plan'       && <PlanTab />}
        {activeTab === 'findings'   && <FindingsTab />}
        {activeTab === 'compliance' && <ComplianceTab />}
      </div>
    </div>
  );
}
