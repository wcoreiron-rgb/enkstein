'use client';
import { useEffect, useState, useRef, useCallback } from 'react';
import {
  Zap, Ban, AlertTriangle, Eye, Send, Shield, Search, Globe, Play,
  Bell, Clock, ChevronDown, ChevronRight, Cpu, Activity, Terminal,
  CheckCircle, RefreshCw, Key,
} from 'lucide-react';
import StatCard from '@/components/StatCard';
import RiskBadge from '@/components/RiskBadge';
import { getArcStats, getArcEvents, apiFetch } from '@/lib/api';
import { capabilityName } from '@/lib/capability-names';

// ── Types ─────────────────────────────────────────────────────────────────────

interface ToolCall {
  tool: string;
  input: Record<string, unknown>;
  result: Record<string, unknown>;
  duration_ms: number;
}

interface AgentMessage {
  role: 'user' | 'assistant';
  content: string;
  tool_calls?: ToolCall[];
  steps?: number;
  error?: string | null;
  timestamp: Date;
}

// ── Quick action prompts ───────────────────────────────────────────────────────

const QUICK_ACTIONS = [
  { label: "Security Posture",        prompt: "What's my current security posture?",              icon: Shield },
  { label: "Critical Cloud Findings", prompt: "Show me critical cloud findings",                   icon: AlertTriangle },
  { label: "CVEs This Week",          prompt: "Scan for CVEs published this week",                 icon: Search },
  { label: "Actively Exploited",      prompt: "What CVEs are actively exploited right now?",       icon: Zap },
  { label: "Compliance Sweep",        prompt: "Run the compliance sweep workflow",                  icon: Play },
  { label: "Identity Risks",          prompt: "Show me my top identity risks",                      icon: Eye },
  { label: "Lateral Movement",        prompt: "Search MITRE ATT&CK for lateral movement",          icon: Globe },
  { label: "Critical Vulns",          prompt: "What are my most critical vulnerabilities?",         icon: Activity },
];

// ── Tool metadata (name → display label + icon + color) ──────────────────────

const TOOL_META: Record<string, { label: string; icon: typeof Search; color: string }> = {
  lookup_cve:                  { label: "CVE Lookup",          icon: Search,        color: "#6366f1" },
  scan_recent_vulnerabilities: { label: "Vulnerability Scan",  icon: RefreshCw,     color: "#f97316" },
  check_actively_exploited:    { label: "CISA KEV",            icon: Zap,           color: "#ef4444" },
  search_mitre_attack:         { label: "MITRE ATT&CK",        icon: Globe,         color: "#8b5cf6" },
  get_security_posture:        { label: "Security Posture",    icon: Shield,        color: "#22c55e" },
  get_findings:                { label: "Findings Query",      icon: Eye,           color: "#3b82f6" },
  run_claw_scan:               { label: "Trigger Scan",        icon: Zap,           color: "#f59e0b" },
  run_identity_detection:      { label: "Identity Detection",  icon: Shield,        color: "#06b6d4" },
  trigger_workflow:            { label: "Run Workflow",        icon: Play,          color: "#10b981" },
  send_security_alert:         { label: "Send Alert",          icon: Bell,          color: "#ef4444" },
  get_recent_events:           { label: "Recent Events",       icon: Clock,         color: "#6b7280" },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function toolInputSummary(tool: string, input: Record<string, unknown>): string {
  if (tool === "lookup_cve") return String(input.cve_id ?? "");
  if (tool === "scan_recent_vulnerabilities")
    return `last ${input.days_back ?? 30}d · CVSS ≥ ${input.cvss_min ?? 7.0}`;
  if (tool === "check_actively_exploited") return `limit ${input.limit ?? 15}`;
  if (tool === "search_mitre_attack") return `"${input.query}"`;
  if (tool === "get_security_posture") return "all domains";
  if (tool === "get_findings")
    return `${capabilityName(String(input.claw ?? ''))}${input.severity ? ` · ${input.severity}` : ""}`;
  if (tool === "run_claw_scan") return capabilityName(String(input.claw ?? ""));
  if (tool === "run_identity_detection") return "governed read-only detection";
  if (tool === "trigger_workflow") return String(input.workflow_name ?? "");
  if (tool === "send_security_alert")
    return `${input.severity?.toString().toUpperCase()} · "${input.title}"`;
  if (tool === "get_recent_events") return `limit ${input.limit ?? 10}`;
  return JSON.stringify(input).slice(0, 60);
}

function toolResultSummary(tool: string, result: Record<string, unknown>): string {
  if (result.error) return `Error: ${result.error}`;
  if (tool === "lookup_cve") {
    const r = result as any;
    if (r.cvss_score) return `CVSS ${r.cvss_score} · ${r.severity}${r.actively_exploited ? " · Actively exploited" : ""}`;
    return "No data";
  }
  if (tool === "scan_recent_vulnerabilities") {
    const r = result as any;
    const count = r.top_cves?.length ?? 0;
    const kev = r.actively_exploited_count ?? 0;
    return `${count} CVEs returned · ${kev} actively exploited`;
  }
  if (tool === "check_actively_exploited") {
    const r = result as any;
    return `${r.total_in_kev ?? 0} total in KEV`;
  }
  if (tool === "search_mitre_attack") {
    const r = result as any;
    return `${r.matched ?? 0} techniques matched`;
  }
  if (tool === "get_security_posture") {
    const r = result as any;
    return `${r.risk_level} · ${r.total_critical_findings ?? 0} critical · ${r.total_high_findings ?? 0} high`;
  }
  if (tool === "get_findings") {
    const r = result as any;
    return `${r.count ?? 0} findings returned`;
  }
  if (tool === "run_claw_scan") {
    const r = result as any;
    return r.status ?? "scan triggered";
  }
  if (tool === "run_identity_detection") {
    const r = result as any;
    if (r.data_source === "live_connector") {
      return `Live · ${r.findings?.length ?? 0} findings · risk ${r.risk_score ?? 0}`;
    }
    if (r.data_source === "persisted_db") {
      return `Stored evidence · ${r.findings?.length ?? 0} findings`;
    }
    return "Connector required · no environment scanned";
  }
  if (tool === "trigger_workflow") {
    const r = result as any;
    return `${r.workflow} · ${r.status}`;
  }
  if (tool === "send_security_alert") {
    return "Alert created";
  }
  if (tool === "get_recent_events") {
    const r = result as any;
    return `${r.count ?? 0} events`;
  }
  return "Done";
}

// ── Markdown renderer (minimal) ───────────────────────────────────────────────

function renderMarkdown(text: string): React.ReactNode[] {
  const lines = text.split("\n");
  const nodes: React.ReactNode[] = [];
  let key = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("### ")) {
      nodes.push(
        <h3 key={key++} className="text-base font-bold mt-3 mb-1" style={{ color: "var(--rc-text-1)" }}>
          {inlineMarkdown(trimmed.slice(4))}
        </h3>
      );
    } else if (trimmed.startsWith("## ")) {
      nodes.push(
        <h2 key={key++} className="text-lg font-bold mt-4 mb-1" style={{ color: "var(--rc-text-1)" }}>
          {inlineMarkdown(trimmed.slice(3))}
        </h2>
      );
    } else if (trimmed.startsWith("# ")) {
      nodes.push(
        <h1 key={key++} className="text-xl font-bold mt-4 mb-2" style={{ color: "var(--rc-text-1)" }}>
          {inlineMarkdown(trimmed.slice(2))}
        </h1>
      );
    } else if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
      nodes.push(
        <li key={key++} className="ml-4 list-disc text-sm" style={{ color: "var(--rc-text-1)" }}>
          {inlineMarkdown(trimmed.slice(2))}
        </li>
      );
    } else if (trimmed === "") {
      nodes.push(<div key={key++} className="h-2" />);
    } else {
      nodes.push(
        <p key={key++} className="text-sm leading-relaxed" style={{ color: "var(--rc-text-1)" }}>
          {inlineMarkdown(trimmed)}
        </p>
      );
    }
  }
  return nodes;
}

function inlineMarkdown(text: string): React.ReactNode {
  // Handle **bold**, `code`, and plain text
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i} className="font-semibold">{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={i} className="px-1 py-0.5 rounded text-xs font-mono"
          style={{ background: "var(--rc-bg-elevated)", color: "#a5f3fc" }}>
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

// ── Tool call card ────────────────────────────────────────────────────────────

function ToolCallCard({ tc }: { tc: ToolCall }) {
  const [expanded, setExpanded] = useState(false);
  const meta = TOOL_META[tc.tool] ?? { label: tc.tool, icon: Terminal, color: "#6b7280" };
  const Icon = meta.icon;

  return (
    <div className="rounded-lg border text-xs font-mono overflow-hidden"
      style={{ borderColor: "var(--rc-border)", background: "#0d1117" }}>
      {/* Header row */}
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/5 transition-colors text-left"
      >
        <span className="flex-shrink-0 w-5 h-5 rounded flex items-center justify-center"
          style={{ background: `${meta.color}22` }}>
          <Icon className="w-3 h-3" style={{ color: meta.color }} />
        </span>
        <span className="font-semibold" style={{ color: meta.color }}>{meta.label}</span>
        <span className="text-gray-500 mx-1">·</span>
        <span className="text-gray-400 truncate flex-1">{toolInputSummary(tc.tool, tc.input)}</span>
        <span className="ml-auto text-gray-500 flex-shrink-0">{toolResultSummary(tc.tool, tc.result)}</span>
        <span className="ml-2 px-1.5 py-0.5 rounded text-gray-500 flex-shrink-0"
          style={{ background: "var(--rc-bg-elevated)" }}>
          {tc.duration_ms}ms
        </span>
        {expanded
          ? <ChevronDown className="w-3 h-3 text-gray-500 flex-shrink-0" />
          : <ChevronRight className="w-3 h-3 text-gray-500 flex-shrink-0" />
        }
      </button>

      {/* Expanded: full JSON */}
      {expanded && (
        <div className="border-t px-3 py-3 space-y-2" style={{ borderColor: "var(--rc-border)" }}>
          <div>
            <p className="text-gray-500 mb-1">Input:</p>
            <pre className="text-gray-300 text-xs overflow-x-auto whitespace-pre-wrap break-words">
              {JSON.stringify(tc.input, null, 2)}
            </pre>
          </div>
          <div>
            <p className="text-gray-500 mb-1">Result:</p>
            <pre className="text-gray-300 text-xs overflow-x-auto whitespace-pre-wrap break-words">
              {JSON.stringify(tc.result, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Typing indicator ──────────────────────────────────────────────────────────

function TypingIndicator() {
  return (
    <div className="flex items-start gap-3">
      <div className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0"
        style={{ background: "var(--rc-bg-elevated)" }}>
        <Cpu className="w-3.5 h-3.5 text-regent-400" />
      </div>
      <div className="px-4 py-3 rounded-2xl rounded-bl-sm flex items-center gap-1.5"
        style={{ background: "var(--rc-bg-elevated)" }}>
        {[0, 1, 2].map(i => (
          <span key={i}
            className="w-1.5 h-1.5 rounded-full bg-regent-400 animate-bounce"
            style={{ animationDelay: `${i * 0.15}s` }}
          />
        ))}
      </div>
    </div>
  );
}

// ── Expandable event row ──────────────────────────────────────────────────────

function EventRow({ event: e, findings, cats, detectedTypes }: {
  event: any;
  findings: any[];
  cats: any;
  detectedTypes: string;
}) {
  const [open, setOpen] = useState(false);

  const outcomeColor: Record<string, string> = {
    redacted: '#f97316', blocked: '#ef4444', flagged: '#eab308',
    allowed: '#22c55e',
  };
  const riskColor = (s: number) =>
    s >= 70 ? '#ef4444' : s >= 40 ? '#f97316' : s >= 20 ? '#eab308' : '#22c55e';

  return (
    <>
      <tr
        onClick={() => setOpen(v => !v)}
        className="border-b transition-colors hover:bg-white/5 cursor-pointer"
        style={{ borderColor: "var(--rc-border)" }}
      >
        <td className="pl-5 py-3">
          {open
            ? <ChevronDown className="w-3.5 h-3.5" style={{ color: "var(--rc-text-3)" }} />
            : <ChevronRight className="w-3.5 h-3.5" style={{ color: "var(--rc-text-3)" }} />
          }
        </td>
        <td className="px-3 py-3 text-xs whitespace-nowrap" style={{ color: "var(--rc-text-3)" }}>
          {new Date(e.timestamp).toLocaleString()}
        </td>
        <td className="px-3 py-3 text-xs font-medium" style={{ color: "var(--rc-text-1)" }}>
          {e.tool_name ?? '—'}
        </td>
        <td className="px-3 py-3 text-xs" style={{ color: "var(--rc-text-2)" }}>
          {detectedTypes !== '—' ? (
            <span className="px-2 py-0.5 rounded font-mono text-xs"
              style={{ background: 'rgba(249,115,22,0.1)', color: '#fb923c', border: '1px solid rgba(249,115,22,0.3)' }}>
              {detectedTypes}
            </span>
          ) : '—'}
        </td>
        <td className="px-3 py-3">
          <span className="px-2 py-0.5 rounded text-xs font-semibold capitalize"
            style={{
              background: `${outcomeColor[e.outcome] ?? '#6b7280'}18`,
              color: outcomeColor[e.outcome] ?? '#6b7280',
              border: `1px solid ${outcomeColor[e.outcome] ?? '#6b7280'}40`,
            }}>
            {e.outcome}
          </span>
        </td>
        <td className="px-5 py-3 text-right font-mono text-sm font-semibold"
          style={{ color: riskColor(e.risk_score ?? 0) }}>
          {e.risk_score?.toFixed(0) ?? 0}
        </td>
      </tr>

      {/* Expanded detail row */}
      {open && (
        <tr style={{ background: "rgba(0,0,0,0.2)" }}>
          <td colSpan={6} className="px-8 py-4">
            <div className="space-y-3 text-xs">

              {/* Scanner detections — real PII/secrets caught */}
              {(() => {
                const scannerHits = findings.filter((f: any) => f.source !== 'agt' && f.pattern);
                if (scannerHits.length === 0) return null;
                return (
                  <div>
                    <p className="font-semibold mb-1.5" style={{ color: "var(--rc-text-2)" }}>
                      🔍 Detected &amp; Redacted
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {scannerHits.map((f: any, i: number) => (
                        <div key={i} className="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs"
                          style={{ background: "rgba(249,115,22,0.08)", borderColor: "rgba(249,115,22,0.35)" }}>
                          <span className="font-semibold" style={{ color: "#fb923c" }}>{f.pattern}</span>
                          <span style={{ color: "var(--rc-text-3)" }}>
                            {f.count} match{f.count > 1 ? 'es' : ''}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-xs"
                            style={{ background: 'rgba(239,68,68,0.1)', color: '#fca5a5', fontSize: '10px' }}>
                            {f.signal ?? 'pii'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}

              {/* AGT audit vectors — always runs 12 checks per prompt, collapsible */}
              {(() => {
                const agtHits = findings.filter((f: any) => f.source === 'agt');
                if (agtHits.length === 0) return null;
                return (
                  <details className="group">
                    <summary className="cursor-pointer select-none font-semibold text-xs list-none flex items-center gap-1.5"
                      style={{ color: "var(--rc-text-3)" }}>
                      <ChevronRight className="w-3 h-3 group-open:rotate-90 transition-transform" />
                      AGT Audit Trail — {agtHits.length} defense vectors checked
                      <span className="px-1.5 py-0.5 rounded ml-1"
                        style={{ background: 'rgba(99,102,241,0.15)', color: '#818cf8', fontSize: '10px' }}>
                        Microsoft AGT
                      </span>
                    </summary>
                    <div className="mt-2 flex flex-wrap gap-1.5 pl-4">
                      {agtHits.map((f: any, i: number) => (
                        <div key={i} className="px-2.5 py-1 rounded border text-xs"
                          style={{ background: "var(--rc-bg-elevated)", borderColor: "var(--rc-border)" }}>
                          <span className="font-medium" style={{ color: '#a5b4fc' }}>
                            {f.vector ?? f.name ?? f.type ?? 'vector'}
                          </span>
                          {f.severity && f.severity !== 'unknown' && (
                            <span className="ml-2" style={{ color: "var(--rc-text-3)" }}>
                              {f.severity}
                            </span>
                          )}
                          {f.description && (
                            <span className="ml-2 italic" style={{ color: "var(--rc-text-3)", fontSize: '10px' }}>
                              {String(f.description).slice(0, 60)}{String(f.description).length > 60 ? '…' : ''}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </details>
                );
              })()}

              {/* Block / redaction reason */}
              {e.block_reason && (
                <div>
                  <p className="font-semibold mb-1" style={{ color: "var(--rc-text-2)" }}>
                    {e.outcome === 'blocked' ? '🚫 Block Reason' : '✂️ Redaction Note'}
                  </p>
                  <p className="font-mono" style={{ color: "var(--rc-text-3)" }}>{e.block_reason}</p>
                </div>
              )}

              {/* Redacted text preview */}
              {e.redacted_text && e.redacted_text !== e.prompt_text && (
                <div>
                  <p className="font-semibold mb-1" style={{ color: "var(--rc-text-2)" }}>✂️ Sanitised Content</p>
                  <p className="font-mono px-3 py-2 rounded"
                    style={{ background: "var(--rc-bg-elevated)", color: "#a5f3fc" }}>
                    {e.redacted_text.slice(0, 300)}{e.redacted_text.length > 300 ? '…' : ''}
                  </p>
                </div>
              )}

              {/* Policy + categories */}
              <div className="flex flex-wrap gap-4">
                {e.policy_applied && (
                  <div>
                    <p className="font-semibold mb-1" style={{ color: "var(--rc-text-2)" }}>Policy</p>
                    <span className="px-2 py-0.5 rounded font-mono"
                      style={{ background: "var(--rc-bg-elevated)", color: "var(--rc-text-3)" }}>
                      {e.policy_applied}
                    </span>
                  </div>
                )}
                {cats.risk_level && (
                  <div>
                    <p className="font-semibold mb-1" style={{ color: "var(--rc-text-2)" }}>Intent Risk</p>
                    <span className="px-2 py-0.5 rounded capitalize font-semibold"
                      style={{
                        background: cats.risk_level === 'high' ? '#ef444420' : cats.risk_level === 'medium' ? '#f9731620' : '#22c55e20',
                        color: cats.risk_level === 'high' ? '#f87171' : cats.risk_level === 'medium' ? '#fb923c' : '#4ade80',
                      }}>
                      {cats.risk_level}
                    </span>
                  </div>
                )}
                {cats.categories?.length > 0 && (
                  <div>
                    <p className="font-semibold mb-1" style={{ color: "var(--rc-text-2)" }}>Categories</p>
                    <div className="flex gap-1 flex-wrap">
                      {cats.categories.map((c: string) => (
                        <span key={c} className="px-2 py-0.5 rounded text-xs"
                          style={{ background: "var(--rc-bg-elevated)", color: "var(--rc-text-3)" }}>
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

// Provider display config
const PROVIDER_META: Record<string, { label: string; color: string; toolSupport: boolean; badge?: string }> = {
  anthropic: { label: 'Claude',       color: '#d4a27f', toolSupport: true  },
  openai:    { label: 'OpenAI',       color: '#74aa9c', toolSupport: true  },
  nvidia:    { label: 'NVIDIA NIM',   color: '#76b900', toolSupport: true,  badge: 'Free' },
  ollama:    { label: 'Ollama',       color: '#a78bfa', toolSupport: false },
};

export default function ArcClawPage() {
  const [stats, setStats]         = useState<any>(null);
  const [events, setEvents]       = useState<any[]>([]);
  const [providers, setProviders] = useState<any[]>([]);
  const [provider, setProvider]   = useState('anthropic');
  const [tab, setTab]             = useState<'copilot' | 'governance'>('copilot');

  // Model selection
  const [availableModels, setAvailableModels] = useState<Record<string, any[]>>({ anthropic: [], openai: [], nvidia: [], ollama: [] });
  const [selectedModel, setSelectedModel]     = useState<string>('');
  const [loadingModels, setLoadingModels]     = useState(false);

  // Copilot state
  const [agentMessages, setAgentMessages] = useState<AgentMessage[]>([]);
  const [input, setInput]                 = useState('');
  const [sending, setSending]             = useState(false);
  const [conversationHistory, setConversationHistory] = useState<{ role: string; content: string }[]>([]);

  const bottomRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    const [s, e, p] = await Promise.all([
      getArcStats(),
      getArcEvents(20),
      apiFetch<any[]>('/arcclaw/providers'),
    ]);
    setStats(s);
    setEvents(e);
    setProviders(p);
    // Auto-select the first ready provider so the user doesn't start
    // on an unconfigured one and get an api_key_missing error.
    const firstReady = (p as any[]).find((pd: any) => pd.ready);
    if (firstReady) setProvider(firstReady.provider);
  }, []);

  // Fetch models whenever provider changes
  const fetchModels = useCallback(async () => {
    setLoadingModels(true);
    try {
      const data = await apiFetch<Record<string, any[]>>('/arcclaw/agent/models');
      setAvailableModels(data);
      // Auto-select first model for the current provider
      const providerModels = data[provider] || [];
      if (providerModels.length > 0) {
        setSelectedModel(providerModels[0].id);
      } else {
        setSelectedModel('');
      }
    } catch {
      // silently fail
    } finally {
      setLoadingModels(false);
    }
  }, [provider]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { fetchModels(); }, [fetchModels]);
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [agentMessages, sending]);

  // When provider changes, reset model to first available
  const handleProviderChange = (p: string) => {
    setProvider(p);
    const models = availableModels[p] || [];
    setSelectedModel(models.length > 0 ? models[0].id : '');
  };

  const sendToAgent = async (text: string) => {
    if (!text.trim() || sending) return;
    setInput('');
    setSending(true);

    const userMsg: AgentMessage = { role: 'user', content: text, timestamp: new Date() };
    setAgentMessages(prev => [...prev, userMsg]);

    const newHistory = [
      ...conversationHistory,
      { role: 'user', content: text },
    ];

    try {
      const result = await apiFetch<any>('/arcclaw/agent/chat', {
        method: 'POST',
        body: JSON.stringify({
          messages: newHistory,
          provider,
          model: selectedModel || undefined,
        }),
      });

      const assistantMsg: AgentMessage = {
        role: 'assistant',
        content: result.response || '',
        tool_calls: result.tool_calls || [],
        steps: result.steps,
        error: result.error,
        timestamp: new Date(),
      };
      setAgentMessages(prev => [...prev, assistantMsg]);

      // Append assistant turn to history
      setConversationHistory([
        ...newHistory,
        { role: 'assistant', content: result.response || '' },
      ]);
    } catch (err: any) {
      setAgentMessages(prev => [...prev, {
        role: 'assistant',
        content: `Error: ${err.message}`,
        tool_calls: [],
        timestamp: new Date(),
      }]);
    } finally {
      setSending(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendToAgent(input);
  };

  const clearConversation = () => {
    setAgentMessages([]);
    setConversationHistory([]);
  };

  const selectedProvider   = providers.find(p => p.provider === provider);
  const currentModels      = availableModels[provider] || [];
  const selectedModelMeta  = currentModels.find(m => m.id === selectedModel);
  // A provider is "ready" if it's ollama (no key needed) or has a configured API key
  const providerReady      = provider === 'ollama' || (selectedProvider?.ready ?? false);

  return (
    <div className="space-y-6">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3"
            style={{ color: "var(--rc-text-1)" }}>
            <Shield className="text-regent-400" /> AI Security
          </h1>
          <p className="mt-1 text-sm" style={{ color: "var(--rc-text-2)" }}>
            AI Security &amp; Governance — Security Copilot with live tool calling + AI Governance
          </p>
        </div>
      </div>

      {/* ── Stats ────────────────────────────────────────────────────────────── */}
      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Total AI Events"  value={stats.total_events}   icon={Eye}           color="indigo" />
          <StatCard label="Blocked"          value={stats.blocked_events} icon={Ban}           color="red" />
          <StatCard label="Flagged"          value={stats.flagged_events} icon={AlertTriangle} color="orange" />
          <StatCard label="Avg Risk Score"   value={stats.avg_risk_score} icon={Zap}           color="yellow" />
        </div>
      )}

      {/* ── Tabs ─────────────────────────────────────────────────────────────── */}
      <div className="flex gap-1 border-b" style={{ borderColor: "var(--rc-border)" }}>
        {([
          { id: 'copilot',    label: 'Security Copilot', icon: Cpu },
          { id: 'governance', label: 'AI Governance',    icon: Eye },
        ] as const).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors ${
              tab === t.id
                ? 'border-regent-500 text-regent-400'
                : 'border-transparent hover:text-white'
            }`}
            style={{ color: tab === t.id ? undefined : "var(--rc-text-2)" }}>
            <t.icon className="w-4 h-4" />
            {t.label}
          </button>
        ))}
      </div>

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* SECURITY COPILOT TAB                                                  */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {tab === 'copilot' && (
        <div className="space-y-4">
          {/* Provider + Model selector */}
          <div className="rounded-xl border p-4 space-y-3"
            style={{ background: "var(--rc-bg-surface)", borderColor: "var(--rc-border)" }}>

            {/* Top row: title + clear */}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold" style={{ color: "var(--rc-text-1)" }}>Security Copilot</p>
                <p className="text-xs mt-0.5" style={{ color: "var(--rc-text-3)" }}>
                  AI agent with live tool calling — CVEs, MITRE ATT&amp;CK, findings, scans, workflows, alerts
                </p>
              </div>
              {agentMessages.length > 0 && (
                <button onClick={clearConversation}
                  className="px-3 py-1 rounded-lg text-xs border hover:opacity-70 transition-opacity"
                  style={{ color: "var(--rc-text-3)", borderColor: "var(--rc-border)" }}>
                  Clear chat
                </button>
              )}
            </div>

            {/* Provider row */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-medium w-16 flex-shrink-0" style={{ color: "var(--rc-text-3)" }}>Provider</span>
              {(['anthropic', 'openai', 'nvidia', 'ollama'] as const).map(p => {
                const meta  = PROVIDER_META[p];
                const pData = providers.find(pd => pd.provider === p);
                const ready = pData?.ready ?? false;
                const active = provider === p;
                return (
                  <button key={p} onClick={() => handleProviderChange(p)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all"
                    style={{
                      borderColor: active ? meta.color : 'var(--rc-border)',
                      background:  active ? `${meta.color}18` : 'var(--rc-bg-elevated)',
                      color:       active ? meta.color : 'var(--rc-text-2)',
                    }}>
                    {/* Color dot */}
                    <span className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{ background: active ? meta.color : 'var(--rc-text-3)' }} />
                    {meta.label}
                    {/* Free badge for NVIDIA */}
                    {meta.badge && (
                      <span className="px-1 py-0.5 rounded text-xs font-bold leading-none"
                        style={{
                          background: active ? `${meta.color}30` : 'rgba(118,185,0,0.15)',
                          color: '#76b900',
                          fontSize: '9px',
                        }}>
                        {meta.badge}
                      </span>
                    )}
                    {!meta.toolSupport && (
                      <span className="text-purple-400 text-xs ml-0.5" title="No tool calling">⚡</span>
                    )}
                    {meta.toolSupport && !ready && (
                      <span className="text-yellow-400 text-xs ml-0.5" title="API key not configured">!</span>
                    )}
                    {meta.toolSupport && ready && (
                      <span className="text-green-400 text-xs ml-0.5">✓</span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Model row */}
            <div className="flex items-start gap-2 flex-wrap">
              <span className="text-xs font-medium w-16 flex-shrink-0 pt-1.5" style={{ color: "var(--rc-text-3)" }}>Model</span>
              {loadingModels ? (
                <span className="text-xs pt-1.5 flex items-center gap-1" style={{ color: "var(--rc-text-3)" }}>
                  <RefreshCw className="w-3 h-3 animate-spin" /> Loading models…
                </span>
              ) : currentModels.length === 0 ? (
                <span className="text-xs pt-1.5" style={{ color: "var(--rc-text-3)" }}>
                  {provider === 'ollama'
                    ? 'No Ollama models found — run: ollama pull llama3.2'
                    : provider === 'nvidia'
                    ? <>Get a free key at{' '}
                        <a href="https://build.nvidia.com/models" target="_blank" rel="noreferrer"
                           className="underline" style={{ color: '#76b900' }}>
                          build.nvidia.com/models
                        </a>
                        {' '}→ add via Connector Marketplace → NVIDIA NIM</>
                    : 'Configure API key in Connector Marketplace to see models'}
                </span>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {currentModels.map(m => {
                    const active = selectedModel === m.id;
                    const meta = PROVIDER_META[provider];
                    return (
                      <button key={m.id} onClick={() => setSelectedModel(m.id)}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs border transition-all"
                        style={{
                          borderColor: active ? meta.color : 'var(--rc-border)',
                          background:  active ? `${meta.color}18` : 'var(--rc-bg-elevated)',
                          color:       active ? meta.color : 'var(--rc-text-2)',
                        }}>
                        <span className="font-medium">{m.name}</span>
                        {m.tag && (
                          <span className="px-1 py-0.5 rounded text-xs opacity-60"
                            style={{ background: 'var(--rc-bg-surface)', fontSize: '10px' }}>
                            {m.tag}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Active selection summary */}
            {selectedModelMeta && (
              <div className="flex items-center gap-2 pt-1 border-t" style={{ borderColor: "var(--rc-border)" }}>
                <span className="text-xs" style={{ color: "var(--rc-text-3)" }}>Active:</span>
                <span className="text-xs font-medium" style={{ color: PROVIDER_META[provider].color }}>
                  {PROVIDER_META[provider].label} / {selectedModelMeta.name}
                </span>
                {!PROVIDER_META[provider].toolSupport && (
                  <span className="text-xs text-purple-400">⚡ No tool calling — answers from training only</span>
                )}
                {PROVIDER_META[provider].toolSupport && !(providers.find(p => p.provider === provider)?.ready) && (
                  <span className="text-xs text-yellow-400">⚠ Add API key in Connector Marketplace for tool calling</span>
                )}
              </div>
            )}
          </div>

          {/* Chat area */}
          <div className="rounded-xl border flex flex-col"
            style={{
              background: "var(--rc-bg-surface)",
              borderColor: "var(--rc-border)",
              height: "580px",
            }}>
            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-5 space-y-5">
              {/* Empty state */}
              {agentMessages.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full gap-6 pb-4">
                  {/* Setup banner — shown when no provider is configured */}
                  {!providerReady && (
                    <div className="w-full max-w-lg rounded-xl border p-5 space-y-3"
                      style={{
                        background: "rgba(99,102,241,0.06)",
                        borderColor: "rgba(99,102,241,0.35)",
                      }}>
                      <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0"
                          style={{ background: "rgba(99,102,241,0.15)" }}>
                          <Key className="w-4 h-4 text-indigo-400" />
                        </div>
                        <div>
                          <p className="font-semibold text-sm" style={{ color: "var(--rc-text-1)" }}>
                            Add an LLM API key to activate Security Copilot
                          </p>
                          <p className="text-xs mt-0.5" style={{ color: "var(--rc-text-3)" }}>
                            Select a provider above, then configure its API key.
                          </p>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div className="p-2 rounded-lg border space-y-0.5"
                          style={{ borderColor: "rgba(118,185,0,0.3)", background: "rgba(118,185,0,0.05)" }}>
                          <p className="font-semibold" style={{ color: '#76b900' }}>🆓 NVIDIA NIM — Free</p>
                          <p style={{ color: "var(--rc-text-3)" }}>80+ frontier models, no cost</p>
                          <a href="https://build.nvidia.com/models" target="_blank" rel="noreferrer"
                            className="underline" style={{ color: '#76b900' }}>
                            build.nvidia.com/models →
                          </a>
                        </div>
                        <div className="p-2 rounded-lg border space-y-0.5"
                          style={{ borderColor: "rgba(212,162,127,0.3)", background: "rgba(212,162,127,0.05)" }}>
                          <p className="font-semibold" style={{ color: '#d4a27f' }}>🤖 Anthropic Claude</p>
                          <p style={{ color: "var(--rc-text-3)" }}>Best tool-calling accuracy</p>
                          <a href="https://console.anthropic.com" target="_blank" rel="noreferrer"
                            className="underline" style={{ color: '#d4a27f' }}>
                            console.anthropic.com →
                          </a>
                        </div>
                      </div>
                      <a href="/connectors"
                        className="flex items-center justify-center gap-2 w-full py-2 rounded-lg text-sm font-medium transition-colors"
                        style={{
                          background: "rgba(99,102,241,0.15)",
                          color: "var(--rc-accent)",
                          border: "1px solid rgba(99,102,241,0.35)",
                        }}>
                        Go to Connector Marketplace →
                      </a>
                    </div>
                  )}

                  {/* Header */}
                  <div className="text-center space-y-2">
                    <div className="w-12 h-12 rounded-2xl flex items-center justify-center mx-auto"
                      style={{ background: "var(--rc-bg-elevated)" }}>
                      <Shield className="w-6 h-6 text-regent-400" />
                    </div>
                    <p className="font-semibold" style={{ color: "var(--rc-text-1)" }}>Security Copilot</p>
                    <p className="text-sm max-w-sm" style={{ color: "var(--rc-text-3)" }}>
                      Ask anything security-related. I'll use live tools to query CVEs,
                      MITRE ATT&amp;CK, findings, and more.
                    </p>
                  </div>

                  {/* Quick action chips — always visible */}
                  <div className="flex flex-wrap justify-center gap-2 max-w-2xl">
                    {QUICK_ACTIONS.map(({ label, prompt, icon: Icon }) => (
                      <button key={label}
                        onClick={() => sendToAgent(prompt)}
                        disabled={sending}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border transition-all hover:border-regent-500 hover:text-regent-300 disabled:opacity-50"
                        style={{
                          background: "var(--rc-bg-elevated)",
                          borderColor: "var(--rc-border-2)",
                          color: "var(--rc-text-2)",
                        }}>
                        <Icon className="w-3 h-3" />
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Message list */}
              {agentMessages.map((msg, i) => (
                <div key={i}
                  className={`flex flex-col gap-2 ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                  {msg.role === 'user' ? (
                    /* User bubble */
                    <div className="max-w-2xl px-4 py-3 rounded-2xl rounded-br-sm text-sm"
                      style={{ background: "#4f46e5", color: "#fff" }}>
                      {msg.content}
                    </div>
                  ) : (
                    /* Agent response */
                    <div className="max-w-3xl w-full space-y-2">
                      {/* Agent header */}
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0"
                          style={{ background: "var(--rc-bg-elevated)" }}>
                          <Cpu className="w-3 h-3 text-regent-400" />
                        </div>
                        <span className="text-xs font-medium text-regent-400">Security Copilot</span>
                        {msg.steps && msg.steps > 1 && (
                          <span className="text-xs px-1.5 py-0.5 rounded"
                            style={{ background: "var(--rc-bg-elevated)", color: "var(--rc-text-3)" }}>
                            {msg.steps} steps
                          </span>
                        )}
                        <span className="text-xs ml-auto" style={{ color: "var(--rc-text-3)" }}>
                          {msg.timestamp.toLocaleTimeString()}
                        </span>
                      </div>

                      {/* Tool call cards */}
                      {msg.tool_calls && msg.tool_calls.length > 0 && (
                        <div className="space-y-1.5 pl-8">
                          {msg.tool_calls.map((tc, j) => (
                            <ToolCallCard key={j} tc={tc} />
                          ))}
                        </div>
                      )}

                      {/* Response text */}
                      {msg.content && (
                        <div className="pl-8 rounded-2xl rounded-tl-sm px-4 py-3 text-sm space-y-1"
                          style={{ background: "var(--rc-bg-elevated)" }}>
                          {msg.error && msg.error !== "max_steps" && msg.error !== "api_key_missing" ? (
                            <p className="text-red-400 text-xs mb-2">Error: {msg.error}</p>
                          ) : null}
                          {renderMarkdown(msg.content)}
                          {/* Inline configure CTA when API key is missing */}
                          {msg.error === 'api_key_missing' && (
                            <a href="/connectors"
                              className="mt-3 flex items-center gap-2 w-fit px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors hover:opacity-80"
                              style={{
                                background: "rgba(99,102,241,0.12)",
                                borderColor: "rgba(99,102,241,0.4)",
                                color: "var(--rc-accent)",
                              }}>
                              <Key className="w-3 h-3" />
                              Open Connector Marketplace →
                            </a>
                          )}
                        </div>
                      )}

                      {/* Quick actions after first response */}
                      {i === agentMessages.length - 1 && agentMessages.length > 0 && (
                        <div className="pl-8 flex flex-wrap gap-2 pt-1">
                          {QUICK_ACTIONS.slice(0, 4).map(({ label, prompt, icon: Icon }) => (
                            <button key={label}
                              onClick={() => sendToAgent(prompt)}
                              disabled={sending}
                              className="flex items-center gap-1 px-2.5 py-1 rounded-full text-xs border transition-all hover:border-regent-500 disabled:opacity-50"
                              style={{
                                background: "var(--rc-bg-elevated)",
                                borderColor: "var(--rc-border)",
                                color: "var(--rc-text-3)",
                              }}>
                              <Icon className="w-3 h-3" />
                              {label}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}

              {/* Typing indicator */}
              {sending && <TypingIndicator />}

              <div ref={bottomRef} />
            </div>

            {/* Input bar */}
            <div className="border-t p-4" style={{ borderColor: "var(--rc-border)" }}>
              <form onSubmit={handleSubmit} className="flex gap-3">
                <input
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  placeholder="Ask Security Copilot anything — CVEs, findings, threats, posture…"
                  disabled={sending}
                  className="flex-1 rounded-xl px-4 py-2.5 text-sm border focus:outline-none disabled:opacity-50"
                  style={{
                    background: "var(--rc-bg-input)",
                    borderColor: "var(--rc-border-2)",
                    color: "var(--rc-text-1)",
                  }}
                />
                <button type="submit" disabled={sending || !input.trim()}
                  className="px-4 py-2.5 rounded-xl flex items-center gap-2 text-sm font-medium transition-colors disabled:opacity-50 bg-regent-600 hover:bg-regent-700 text-white">
                  <Send className="w-4 h-4" />
                  {sending ? 'Thinking…' : 'Send'}
                </button>
              </form>
            </div>
          </div>

          {/* Provider status note */}
          {selectedProvider && !selectedProvider.ready && provider !== 'ollama' && (
            <div className="rounded-lg border px-4 py-3 text-sm flex items-center gap-2"
              style={{
                background: provider === 'nvidia' ? "rgba(118,185,0,0.05)" : "rgba(234,179,8,0.05)",
                borderColor: provider === 'nvidia' ? "rgba(118,185,0,0.3)" : "rgba(234,179,8,0.3)",
                color: provider === 'nvidia' ? "#76b900" : "#fbbf24",
              }}>
              {provider === 'nvidia'
                ? <span className="text-base flex-shrink-0">🆓</span>
                : <AlertTriangle className="w-4 h-4 flex-shrink-0" />}
              <span>
                {provider === 'nvidia'
                  ? <>
                      <strong>NVIDIA NIM is free</strong> — get your API key at{' '}
                      <a href="https://build.nvidia.com/models" target="_blank" rel="noreferrer"
                         className="underline font-medium">build.nvidia.com/models</a>
                      {' '}and add it via <strong>Connector Marketplace → NVIDIA NIM</strong>.
                      Access 80+ frontier models at no cost.
                    </>
                  : <>{selectedProvider.label} API key not configured. Tool calling will fail.
                      {" "}Add via <strong>Connector Marketplace</strong>.</>
                }
              </span>
            </div>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* AI GOVERNANCE TAB                                                     */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {tab === 'governance' && (
        <div className="space-y-4">
          {/* How AI Security works */}
          <div className="rounded-xl border p-5"
            style={{ background: "var(--rc-bg-surface)", borderColor: "var(--rc-border)" }}>
            <p className="text-sm font-semibold mb-2" style={{ color: "var(--rc-text-1)" }}>
              How AI Governance works
            </p>
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              {[
                { label: 'Prompt submitted',              color: 'border-gray-700 text-gray-300'   },
                { label: 'AI Security inspects it',       color: 'border-yellow-700 text-yellow-300' },
                { label: 'AGT injection scan',            color: 'border-blue-700 text-blue-300'   },
                { label: 'Pattern detection',             color: 'border-yellow-700 text-yellow-300' },
                { label: 'Policy check',                  color: 'border-regent-700 text-regent-300' },
                { label: '✅ ALLOWED → LLM responds',    color: 'border-green-700 text-green-300'  },
                { label: '✂️ REDACTED → secrets stripped', color: 'border-orange-700 text-orange-300' },
                { label: '🚫 BLOCKED → never hits LLM', color: 'border-red-700 text-red-300'     },
              ].map((s, i, arr) => (
                <span key={s.label} className="flex items-center gap-1.5">
                  <span className={`px-2 py-1 rounded border bg-black/20 ${s.color}`}>{s.label}</span>
                  {i < arr.length - 1 && <ChevronRight className="w-3 h-3 text-gray-600 flex-shrink-0" />}
                </span>
              ))}
            </div>
          </div>

          {/* Events table */}
          <div className="rounded-xl border overflow-hidden"
            style={{ background: "var(--rc-bg-surface)", borderColor: "var(--rc-border)" }}>
            <div className="px-5 py-3 border-b flex items-center justify-between"
              style={{ borderColor: "var(--rc-border)" }}>
              <p className="text-sm font-semibold" style={{ color: "var(--rc-text-1)" }}>
                AI Event Log
              </p>
              <div className="flex items-center gap-2">
                <span className="text-xs" style={{ color: "var(--rc-text-3)" }}>Click a row for details</span>
                <span className="text-xs px-2 py-0.5 rounded"
                  style={{ background: "var(--rc-bg-elevated)", color: "var(--rc-text-3)" }}>
                  {events.length} events
                </span>
              </div>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs border-b" style={{ borderColor: "var(--rc-border)", color: "var(--rc-text-3)" }}>
                  <th className="px-5 py-3 text-left font-medium w-6"></th>
                  <th className="px-5 py-3 text-left font-medium">Timestamp</th>
                  <th className="px-5 py-3 text-left font-medium">Provider / Model</th>
                  <th className="px-5 py-3 text-left font-medium">Detected</th>
                  <th className="px-5 py-3 text-left font-medium">Outcome</th>
                  <th className="px-5 py-3 text-right font-medium">Risk</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-5 py-10 text-center text-sm"
                      style={{ color: "var(--rc-text-3)" }}>
                      No events yet. Submit a prompt via the Security Copilot or AI Chat.
                    </td>
                  </tr>
                )}
                {events.map((e: any) => {
                  const findings = (() => { try { return JSON.parse(e.findings_json || '[]'); } catch { return []; } })();
                  const cats = (() => { try { return JSON.parse(e.categories_json || '{}'); } catch { return {}; } })();
                  // Only show scanner findings (not AGT audit vectors) in the table column
                  const detectedTypes = findings
                    .filter((f: any) => f.source !== 'agt' && f.pattern)
                    .map((f: any) => f.pattern)
                    .join(', ') || (e.block_reason ? 'injection attempt' : '—');
                  return (
                    <EventRow
                      key={e.id}
                      event={e}
                      findings={findings}
                      cats={cats}
                      detectedTypes={detectedTypes}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
