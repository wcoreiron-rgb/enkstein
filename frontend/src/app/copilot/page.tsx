'use client';
import { useState, useRef, useEffect } from 'react';
import {
  Sparkles, Send, CheckCircle, XCircle, AlertTriangle, Clock,
  ChevronDown, ChevronRight, Play, Save, Trash2, Shield,
  Bot, Bell, GitMerge, Activity, RefreshCw, Info, Zap,
  ArrowRight,
} from 'lucide-react';
import { nlToWorkflow, approveDraft, saveAsTemplate, discardDraft } from '@/lib/api';
import { capabilityName } from '@/lib/capability-names';

// ─── Types ────────────────────────────────────────────────────────────────────
type PolicyFlag = { rule: string; severity: string; message: string };
type DetectedClaw = { claw_id: string; label: string };
type DetectedIntent = { type: string; label: string };

type Draft = {
  draft_id: string;
  created_at: string;
  prompt: string;
  status: 'ready' | 'pending_approval';
  workflow: {
    name: string;
    description: string;
    trigger_type: string;
    step_count: number;
    steps_json: string;
    category: string;
    tags: string;
  };
  policy_evaluation: {
    decision: 'allow' | 'warn' | 'require_approval';
    flags: PolicyFlag[];
    requires_approval: boolean;
    risk_level: 'low' | 'medium' | 'high';
  };
  explanation: {
    detected_claws: DetectedClaw[];
    detected_intents: DetectedIntent[];
    step_count: number;
    high_risk: boolean;
    trigger_type: string;
  };
};

type ChatMsg = {
  id: string;
  role: 'user' | 'assistant';
  text?: string;
  draft?: Draft;
  error?: string;
  loading?: boolean;
};

// ─── Step type display ────────────────────────────────────────────────────────
const STEP_TYPE_META: Record<string, { icon: React.ElementType; color: string; label: string }> = {
  agent_run:    { icon: Bot,      color: 'text-blue-400',   label: 'Agent Run'    },
  policy_check: { icon: Shield,   color: 'text-purple-400', label: 'Policy Check' },
  condition:    { icon: GitMerge, color: 'text-orange-400', label: 'Condition'    },
  notify:       { icon: Bell,     color: 'text-yellow-400', label: 'Notify'       },
  unknown:      { icon: Activity, color: 'text-gray-500',   label: 'Step'         },
};

const RISK_COLORS: Record<string, string> = {
  low:    'text-green-400  bg-green-900/30  border-green-800',
  medium: 'text-yellow-400 bg-yellow-900/30 border-yellow-800',
  high:   'text-red-400    bg-red-900/30    border-red-800',
};

const DECISION_META: Record<string, { icon: React.ElementType; color: string; label: string }> = {
  allow:           { icon: CheckCircle,   color: 'text-green-400',  label: 'Policy: Allow'            },
  warn:            { icon: AlertTriangle, color: 'text-yellow-400', label: 'Policy: Warning'           },
  require_approval:{ icon: Shield,        color: 'text-red-400',    label: 'Policy: Approval Required' },
};

// ─── Example prompts ──────────────────────────────────────────────────────────
const EXAMPLE_PROMPTS = [
  "Scan all endpoints for malware and isolate any infected devices",
  "When a critical vulnerability is found, enrich the IOC and notify the security team",
  "Daily audit of cloud IAM permissions across AWS and Azure",
  "Block the compromised user account and rotate their credentials immediately",
  "Investigate anomalous login activity across identity providers and escalate if suspicious",
  "Collect compliance evidence for PCI-DSS controls and generate a report",
];

// ─── Draft card component ─────────────────────────────────────────────────────
function DraftCard({ draft, onApprove, onSave, onDiscard }: {
  draft: Draft;
  onApprove: (runNow: boolean) => void;
  onSave: () => void;
  onDiscard: () => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const [stepsOpen, setStepsOpen] = useState(false);
  const [approving, setApproving] = useState(false);
  const [saving, setSaving] = useState(false);

  const steps = (() => {
    try { return JSON.parse(draft.workflow.steps_json); } catch { return []; }
  })();

  const { policy_evaluation: pe, explanation: ex } = draft;
  const decisionMeta = DECISION_META[pe.decision] ?? DECISION_META.warn;
  const DecisionIcon = decisionMeta.icon;
  const riskClass = RISK_COLORS[pe.risk_level] ?? RISK_COLORS.medium;

  return (
    <div className="border border-cyan-800/60 bg-gray-900/80 rounded-2xl overflow-hidden shadow-lg shadow-cyan-900/10 mt-3">

      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-5 py-4 hover:bg-gray-800/30 transition-colors text-left"
      >
        <Sparkles className="w-5 h-5 text-cyan-400 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-white font-semibold text-sm truncate">{draft.workflow.name}</p>
          <p className="text-gray-400 text-xs mt-0.5 truncate">{draft.workflow.description}</p>
        </div>
        <div className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-lg border ${riskClass}`}>
          <span className="capitalize">{pe.risk_level} risk</span>
        </div>
        {expanded ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
      </button>

      {expanded && (
        <div className="px-5 pb-5 space-y-4">

          {/* Policy evaluation */}
          <div className={`flex items-start gap-3 px-4 py-3 rounded-xl border ${
            pe.decision === 'allow' ? 'bg-green-900/20 border-green-800' :
            pe.decision === 'warn'  ? 'bg-yellow-900/20 border-yellow-800' :
            'bg-red-900/20 border-red-800'
          }`}>
            <DecisionIcon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${decisionMeta.color}`} />
            <div className="min-w-0">
              <p className={`text-xs font-semibold ${decisionMeta.color}`}>{decisionMeta.label}</p>
              {pe.flags.length === 0 && (
                <p className="text-xs text-gray-400 mt-0.5">No policy violations detected.</p>
              )}
              {pe.flags.map((f, i) => (
                <div key={i} className="mt-1.5">
                  <p className="text-xs text-gray-300">{f.message}</p>
                  <span className="text-xs text-gray-500">{f.rule}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Explanation pills */}
          <div className="space-y-2">
            <p className="text-xs text-gray-500 uppercase tracking-wide">Detected context</p>
            <div className="flex flex-wrap gap-1.5">
              {ex.detected_claws.map(c => (
                <span key={c.claw_id} className="text-xs bg-blue-900/40 border border-blue-800 text-blue-300 rounded-lg px-2 py-0.5">
                  {capabilityName(c.claw_id || c.label)}
                </span>
              ))}
              {ex.detected_intents.map(i => (
                <span key={i.label} className="text-xs bg-purple-900/40 border border-purple-800 text-purple-300 rounded-lg px-2 py-0.5">
                  {i.label}
                </span>
              ))}
              <span className="text-xs bg-gray-800 border border-gray-700 text-gray-400 rounded-lg px-2 py-0.5">
                {ex.trigger_type} trigger
              </span>
            </div>
          </div>

          {/* Step list toggle */}
          <button
            onClick={() => setStepsOpen(!stepsOpen)}
            className="flex items-center gap-2 text-xs text-gray-400 hover:text-white transition-colors"
          >
            {stepsOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            {steps.length} steps
          </button>

          {stepsOpen && (
            <div className="space-y-1.5">
              {steps.map((step: any, idx: number) => {
                const meta = STEP_TYPE_META[step.type] ?? STEP_TYPE_META.unknown;
                const Icon = meta.icon;
                return (
                  <div key={idx} className="flex items-center gap-3 bg-gray-800/60 rounded-lg px-3 py-2">
                    <span className="text-xs text-gray-600 font-mono w-4 flex-shrink-0">{step.index}</span>
                    <Icon className={`w-3.5 h-3.5 flex-shrink-0 ${meta.color}`} />
                    <span className="text-xs text-gray-300 flex-1 truncate">{step.name}</span>
                    <span className={`text-xs ${meta.color}`}>{meta.label}</span>
                  </div>
                );
              })}
            </div>
          )}

          {/* Workflow metadata */}
          <div className="grid grid-cols-3 gap-3 text-xs">
            {[
              { label: 'Trigger', value: draft.workflow.trigger_type },
              { label: 'Category', value: draft.workflow.category },
              { label: 'Capabilities', value: ex.detected_claws.length.toString() },
            ].map(item => (
              <div key={item.label} className="bg-gray-800/50 rounded-lg px-3 py-2">
                <p className="text-gray-500">{item.label}</p>
                <p className="text-white font-medium mt-0.5 capitalize">{item.value}</p>
              </div>
            ))}
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2 pt-1">
            {/* Approve + Run */}
            <button
              disabled={approving}
              onClick={async () => {
                setApproving(true);
                await onApprove(true);
              }}
              className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-60 text-white text-xs font-semibold px-4 py-2 rounded-xl transition-colors"
            >
              {approving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              Approve &amp; Run
            </button>

            {/* Save as draft */}
            <button
              disabled={saving}
              onClick={async () => {
                setSaving(true);
                await onSave();
              }}
              className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 disabled:opacity-60 text-white text-xs font-semibold px-4 py-2 rounded-xl transition-colors"
            >
              {saving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
              Save Draft
            </button>

            {/* Discard */}
            <button
              onClick={onDiscard}
              className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white text-xs px-3 py-2 rounded-xl transition-colors ml-auto"
            >
              <Trash2 className="w-3.5 h-3.5" /> Discard
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function CopilotPage() {
  const [messages, setMessages] = useState<ChatMsg[]>([
    {
      id: 'welcome',
      role: 'assistant',
      text: "Hello! I'm the Marcellus Copilot. Describe a security workflow in plain English and I'll generate a governed, policy-evaluated workflow draft for you to review before running.",
    },
  ]);
  const [input, setInput]       = useState('');
  const [sending, setSending]   = useState(false);
  const bottomRef               = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const addMsg = (msg: Omit<ChatMsg, 'id'>) => {
    const id = crypto.randomUUID();
    setMessages(prev => [...prev, { ...msg, id }]);
    return id;
  };

  const updateMsg = (id: string, updates: Partial<ChatMsg>) => {
    setMessages(prev => prev.map(m => m.id === id ? { ...m, ...updates } : m));
  };

  const removeMsg = (id: string) => {
    setMessages(prev => prev.filter(m => m.id !== id));
  };

  const send = async (promptText?: string) => {
    const text = (promptText ?? input).trim();
    if (!text || sending) return;
    setInput('');
    setSending(true);

    addMsg({ role: 'user', text });

    const thinkingId = addMsg({ role: 'assistant', loading: true });

    try {
      const draft = await nlToWorkflow(text) as Draft;
      updateMsg(thinkingId, {
        loading: false,
        text: `I've analysed your intent and generated a ${draft.explanation.step_count}-step workflow covering ${draft.explanation.detected_claws.length} capabilities. Policy evaluation: **${draft.policy_evaluation.decision}**.`,
        draft,
      });
    } catch (e: any) {
      updateMsg(thinkingId, {
        loading: false,
        error: e?.message ?? 'Failed to generate workflow draft.',
      });
    } finally {
      setSending(false);
    }
  };

  const handleApprove = async (msgId: string, draft: Draft, runNow: boolean) => {
    try {
      const res = await approveDraft(draft.draft_id, { run_immediately: runNow }) as any;
      updateMsg(msgId, {
        text: runNow
          ? `✅ Workflow created and run started! Run ID: ${res.run_id}`
          : `✅ Workflow saved as draft. Open Orchestrations to activate it.`,
        draft: undefined,
      });
    } catch (e: any) {
      updateMsg(msgId, {
        text: `❌ Approval failed: ${e?.message}`,
        draft: undefined,
      });
    }
  };

  const handleSave = async (msgId: string, draft: Draft) => {
    try {
      const res = await saveAsTemplate(draft.draft_id) as any;
      updateMsg(msgId, {
        text: `✅ Saved as draft template: "${res.workflow_name}". Open Orchestrations to launch it.`,
        draft: undefined,
      });
    } catch (e: any) {
      updateMsg(msgId, {
        text: `❌ Save failed: ${e?.message}`,
        draft: undefined,
      });
    }
  };

  const handleDiscard = async (msgId: string, draft: Draft) => {
    try {
      await discardDraft(draft.draft_id);
    } catch { /* draft may already be gone */ }
    updateMsg(msgId, {
      text: 'Draft discarded.',
      draft: undefined,
    });
  };

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">

      {/* Page header */}
      <div className="flex-shrink-0 pb-4 border-b border-gray-800">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Sparkles className="text-cyan-400" /> Security Copilot
        </h1>
        <p className="text-gray-400 mt-1 text-sm">
          Describe a security workflow in natural language — Copilot generates a governed, policy-checked draft.
        </p>
      </div>

      <div className="flex flex-1 min-h-0 gap-5 pt-4">

        {/* ── Left: Chat ─────────────────────────────────────────────────── */}
        <div className="flex-1 flex flex-col min-w-0">

          {/* Messages */}
          <div className="flex-1 overflow-y-auto space-y-4 pr-2" style={{ scrollbarWidth: 'thin' }}>
            {messages.map(msg => (
              <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] ${msg.role === 'user' ? '' : 'w-full'}`}>

                  {/* User bubble */}
                  {msg.role === 'user' && (
                    <div className="bg-cyan-600/20 border border-cyan-700/40 text-white text-sm px-4 py-3 rounded-2xl rounded-tr-sm">
                      {msg.text}
                    </div>
                  )}

                  {/* Assistant bubble */}
                  {msg.role === 'assistant' && (
                    <div>
                      <div className="flex items-start gap-2.5">
                        <div className="w-7 h-7 rounded-full bg-cyan-900/60 border border-cyan-700 flex items-center justify-center flex-shrink-0 mt-0.5">
                          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                        </div>
                        <div className="flex-1 min-w-0">
                          {msg.loading && (
                            <div className="flex items-center gap-2 text-gray-400 text-sm">
                              <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                              Analysing intent and building workflow draft…
                            </div>
                          )}
                          {msg.error && (
                            <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-800 rounded-xl px-4 py-3">
                              <XCircle className="w-4 h-4 flex-shrink-0" /> {msg.error}
                            </div>
                          )}
                          {!msg.loading && !msg.error && msg.text && (
                            <p className="text-gray-300 text-sm leading-relaxed">{msg.text}</p>
                          )}
                          {msg.draft && (
                            <DraftCard
                              draft={msg.draft}
                              onApprove={(runNow) => handleApprove(msg.id, msg.draft!, runNow)}
                              onSave={() => handleSave(msg.id, msg.draft!)}
                              onDiscard={() => handleDiscard(msg.id, msg.draft!)}
                            />
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                </div>
              </div>
            ))}
            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div className="flex-shrink-0 pt-3">
            <div className="flex gap-2 items-end bg-gray-900 border border-gray-700 rounded-2xl px-4 py-3 focus-within:border-cyan-700 transition-colors">
              <textarea
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    send();
                  }
                }}
                disabled={sending}
                rows={2}
                placeholder="Describe your security workflow… (Shift+Enter for new line)"
                className="flex-1 bg-transparent text-white text-sm placeholder-gray-500 resize-none outline-none leading-relaxed disabled:opacity-60"
              />
              <button
                onClick={() => send()}
                disabled={!input.trim() || sending}
                className="flex-shrink-0 p-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed text-white transition-colors"
              >
                {sending
                  ? <RefreshCw className="w-4 h-4 animate-spin" />
                  : <Send className="w-4 h-4" />
                }
              </button>
            </div>
            <p className="text-xs text-gray-600 mt-1.5 px-1">
              Enter to send · Shift+Enter for new line · All workflows require policy evaluation before running
            </p>
          </div>
        </div>

        {/* ── Right: Examples panel ───────────────────────────────────────── */}
        <div className="w-72 flex-shrink-0 space-y-4 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>

          {/* Examples */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                Example prompts
              </p>
            </div>
            <div className="p-3 space-y-2">
              {EXAMPLE_PROMPTS.map((p, i) => (
                <button
                  key={i}
                  onClick={() => send(p)}
                  disabled={sending}
                  className="w-full text-left text-xs text-gray-300 bg-gray-800/60 hover:bg-gray-700 disabled:opacity-50 rounded-lg px-3 py-2.5 transition-colors flex items-start gap-2 group"
                >
                  <ArrowRight className="w-3 h-3 text-cyan-500 flex-shrink-0 mt-0.5 group-hover:translate-x-0.5 transition-transform" />
                  <span className="leading-relaxed">{p}</span>
                </button>
              ))}
            </div>
          </div>

          {/* How it works */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                How it works
              </p>
            </div>
            <div className="p-4 space-y-3">
              {[
                { icon: Sparkles,   color: 'text-cyan-400',   title: 'Parse intent', body: 'Copilot extracts security intent, affected domains, and claws from your description.' },
                { icon: Shield,     color: 'text-purple-400', title: 'Policy eval',  body: 'The draft is evaluated against active policies. High-risk actions flag for approval.' },
                { icon: Zap,        color: 'text-yellow-400', title: 'Review steps', body: 'Inspect the generated steps before approving. Edit name or tags if needed.' },
                { icon: Play,       color: 'text-green-400',  title: 'Run or save',  body: 'Approve & Run fires it immediately. Save Draft stores it in Orchestrations.' },
              ].map(({ icon: Icon, color, title, body }) => (
                <div key={title} className="flex gap-3">
                  <div className="w-6 h-6 rounded-lg bg-gray-800 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Icon className={`w-3.5 h-3.5 ${color}`} />
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-white">{title}</p>
                    <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Policy legend */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                Policy decisions
              </p>
            </div>
            <div className="p-4 space-y-2.5">
              {[
                { icon: CheckCircle,   color: 'text-green-400',  label: 'Allow',            body: 'Safe to run immediately.' },
                { icon: AlertTriangle, color: 'text-yellow-400', label: 'Warning',           body: 'Review flags before running.' },
                { icon: Shield,        color: 'text-red-400',    label: 'Approval Required', body: 'Destructive action — explicit sign-off needed.' },
              ].map(({ icon: Icon, color, label, body }) => (
                <div key={label} className="flex gap-2.5">
                  <Icon className={`w-3.5 h-3.5 ${color} flex-shrink-0 mt-0.5`} />
                  <div>
                    <p className="text-xs font-semibold text-white">{label}</p>
                    <p className="text-xs text-gray-400">{body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
