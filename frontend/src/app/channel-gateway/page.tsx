'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  MessageSquare, Shield, CheckCircle, XCircle, Clock,
  RefreshCw, Send, User, Zap, Filter,
  Slack, Building2, Terminal, Activity, Check, Mail, Webhook, Command,
} from 'lucide-react';
import {
  getChannelMessages, getChannelGatewayStats, simulateChannelMessage,
  getChannelIdentities, upsertChannelIdentity,
  getPendingCommands, approvePendingCommand, rejectPendingCommand, bulkReviewPendingCommands, getCommandTimeline, getCommandStatus, updateCommandApprovalPolicy,
  ingestChannelCli, ingestChannelEmail, ingestChannelWebhook,
} from '@/lib/api';

// ─── types ───────────────────────────────────────────────────────────────────

type Message = {
  id:               string;
  channel_type:     string;
  channel_name:     string;
  sender_name:      string;
  sender_email:     string;
  message_text:     string;
  identity_verified: boolean;
  identity_risk:    string;
  policy_decision:  'allowed' | 'blocked' | 'requires_approval';
  policy_flags:     string[];
  detected_intent:  string;
  detected_claws:   string[];
  execution_status: string;
  workflow_run_id:  string;
  response_text:    string;
  created_at:       string;
  command_result?: {
    command_id: string;
    source: string;
    intent: string;
    target: string;
    outcome: string;
    reason?: string;
    tenant_id?: string;
  } | null;
};

type Stats = {
  total_messages:       number;
  allowed:              number;
  blocked:              number;
  pending_approval:     number;
  identity_verified:    number;
  slack_messages:       number;
  teams_messages:       number;
  dispatched_runs:      number;
  registered_identities: number;
  trusted_identities:   number;
  connected_channels:   number;
};

type Identity = {
  id:               number;
  channel_type:     string;
  platform_user_id: string;
  platform_email:   string;
  platform_name:    string;
  regentclaw_role:  string;
  is_trusted:       boolean;
  trust_score:      number;
  max_autonomy:     string;
};

type PendingCommand = {
  command_id: string;
  timestamp: string | null;
  actor: string;
  action: string;
  target: string;
  outcome: string;
  risk_score: number;
  policy_name: string;
  reason: string;
  required_approvals?: number;
  approvals_received?: number;
  approval_status?: string;
};

type TimelineEvent = {
  timestamp: string | null;
  actor: string;
  action: string;
  outcome: string;
  policy_name: string;
  reason: string;
};

type TimelineFilter = 'all' | 'approvals' | 'rejections';

// ─── helpers ─────────────────────────────────────────────────────────────────

const DECISION_META: Record<string, { color: string; bg: string; icon: React.ElementType; label: string }> = {
  allowed:           { color: 'text-green-400',  bg: 'bg-green-900/20 border-green-800',  icon: CheckCircle, label: 'Allowed' },
  blocked:           { color: 'text-red-400',    bg: 'bg-red-900/20 border-red-800',      icon: XCircle,     label: 'Blocked' },
  requires_approval: { color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-800', icon: Clock,      label: 'Pending Approval' },
};

const RISK_COLOR: Record<string, string> = {
  low:      'text-green-400',
  medium:   'text-yellow-400',
  high:     'text-orange-400',
  critical: 'text-red-400',
  unknown:  'text-gray-500',
};

const CHANNEL_ICON: Record<string, React.ElementType> = {
  slack: Slack,
  teams: Building2,
};

const ROLES = ['analyst', 'engineer', 'admin', 'readonly'];
const AUTONOMY_LEVELS = ['monitor', 'assist', 'approval', 'autonomous'];

// ─── message row ─────────────────────────────────────────────────────────────

function MessageRow({ msg }: { msg: Message }) {
  const [expanded, setExpanded] = useState(false);
  const meta = DECISION_META[msg.policy_decision] ?? DECISION_META.blocked;
  const Icon = meta.icon;
  const ChanIcon = CHANNEL_ICON[msg.channel_type] ?? MessageSquare;

  return (
    <>
      <tr
        className="border-b border-gray-800 hover:bg-gray-800/30 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <ChanIcon className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
            <span className="text-xs text-gray-400">{msg.channel_name || msg.channel_type}</span>
          </div>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <User className="w-3.5 h-3.5 text-gray-600 flex-shrink-0" />
            <div>
              <p className="text-xs text-white">{msg.sender_name}</p>
              <p className="text-xs text-gray-600">{msg.sender_email || '—'}</p>
            </div>
          </div>
        </td>
        <td className="px-4 py-3 max-w-xs">
          <p className="text-xs text-gray-300 truncate">{msg.message_text}</p>
          {msg.detected_claws?.length > 0 && (
            <div className="flex gap-1 mt-1">
              {msg.detected_claws.slice(0, 3).map(c => (
                <span key={c} className="text-xs px-1.5 py-0.5 bg-gray-800 rounded text-gray-500">{c}</span>
              ))}
            </div>
          )}
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-1.5">
            {msg.identity_verified
              ? <CheckCircle className="w-3 h-3 text-green-400" />
              : <XCircle    className="w-3 h-3 text-red-400" />
            }
            <span className={`text-xs ${RISK_COLOR[msg.identity_risk] ?? 'text-gray-500'}`}>
              {msg.identity_risk}
            </span>
          </div>
        </td>
        <td className="px-4 py-3">
          <span className={`flex items-center gap-1.5 text-xs font-medium px-2 py-1 rounded-lg border w-fit ${meta.bg}`}>
            <Icon className={`w-3 h-3 ${meta.color}`} /> {meta.label}
          </span>
        </td>
        <td className="px-4 py-3">
          <span className={`text-xs capitalize ${
            msg.execution_status === 'dispatched'     ? 'text-green-400'  :
            msg.execution_status === 'blocked'        ? 'text-red-400'    :
            msg.execution_status === 'pending_approval' ? 'text-yellow-400' :
            'text-gray-500'
          }`}>
            {msg.execution_status?.replace('_', ' ')}
          </span>
          {msg.workflow_run_id && (
            <p className="text-xs text-gray-600 mt-0.5 font-mono truncate max-w-24">{msg.workflow_run_id.slice(0, 8)}…</p>
          )}
        </td>
        <td className="px-4 py-3 text-xs text-gray-600">
          {msg.created_at ? new Date(msg.created_at).toLocaleTimeString() : '—'}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-gray-800 bg-gray-950">
          <td colSpan={7} className="px-6 py-4">
            <div className="grid grid-cols-2 gap-6">
              <div>
                <p className="text-xs font-semibold text-gray-400 mb-2">Original Message</p>
                <p className="text-sm text-gray-300 bg-gray-900 rounded-lg p-3">{msg.message_text}</p>
                {msg.policy_flags?.length > 0 && (
                  <div className="mt-2">
                    <p className="text-xs text-gray-500 mb-1">Policy Flags</p>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.policy_flags.map(f => (
                        <span key={f} className="text-xs px-2 py-0.5 bg-red-900/20 border border-red-800 rounded text-red-400">
                          {f.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <div>
                <p className="text-xs font-semibold text-gray-400 mb-2">RegentClaw Response</p>
                <pre className="text-xs text-gray-300 bg-gray-900 rounded-lg p-3 whitespace-pre-wrap">
                  {msg.response_text}
                </pre>
                {msg.command_result && (
                  <div className="mt-2">
                    <p className="text-xs text-gray-500 mb-1">Command Result</p>
                    <div className="grid grid-cols-2 gap-2 text-xs bg-gray-900 rounded-lg p-3">
                      <p className="text-gray-500">ID <span className="text-gray-300 font-mono ml-1">{msg.command_result.command_id}</span></p>
                      <p className="text-gray-500">Outcome <span className="text-gray-300 ml-1">{msg.command_result.outcome}</span></p>
                      <p className="text-gray-500">Intent <span className="text-gray-300 ml-1">{msg.command_result.intent}</span></p>
                      <p className="text-gray-500">Target <span className="text-gray-300 ml-1">{msg.command_result.target}</span></p>
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

// ─── simulate panel ───────────────────────────────────────────────────────────

function SimulatePanel({ onResult }: { onResult: (r: any) => void }) {
  const [form, setForm] = useState({
    channel_type: 'slack',
    channel_id:   'C-general',
    sender_id:    'U-demo-analyst',
    sender_email: 'redacted_user',
    sender_name:  'Demo Analyst',
    message_text: 'Scan all cloud connectors for misconfigurations',
  });
  const [loading, setLoading] = useState(false);

  const EXAMPLES = [
    'Scan all cloud connectors for misconfigurations',
    'Block the IP 192.168.1.100 in NetClaw',
    'Rotate all expired credentials in AccessClaw',
    'Run the ransomware containment workflow',
    'Give me a security status report',
    'Disable the account for redacted_user',
  ];

  const submit = async () => {
    setLoading(true);
    try {
      const result = await simulateChannelMessage(form);
      onResult(result);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
      <h3 className="text-white font-semibold text-sm flex items-center gap-2">
        <Terminal className="w-4 h-4 text-cyan-400" /> Simulate Message
      </h3>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Channel Type</label>
          <select
            value={form.channel_type}
            onChange={e => setForm(f => ({ ...f, channel_type: e.target.value }))}
            className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
          >
            <option value="slack">Slack</option>
            <option value="teams">Teams</option>
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Channel ID</label>
          <input
            value={form.channel_id}
            onChange={e => setForm(f => ({ ...f, channel_id: e.target.value }))}
            className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
          />
        </div>
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Sender Email</label>
          <input
            value={form.sender_email}
            onChange={e => setForm(f => ({ ...f, sender_email: e.target.value }))}
            className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
          />
        </div>
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Sender Name</label>
          <input
            value={form.sender_name}
            onChange={e => setForm(f => ({ ...f, sender_name: e.target.value }))}
            className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
          />
        </div>
      </div>

      <div>
        <label className="text-xs text-gray-500 mb-1 block">Message</label>
        <textarea
          value={form.message_text}
          onChange={e => setForm(f => ({ ...f, message_text: e.target.value }))}
          rows={3}
          className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none resize-none"
        />
      </div>

      <div>
        <p className="text-xs text-gray-500 mb-2">Example messages:</p>
        <div className="flex flex-wrap gap-2">
          {EXAMPLES.map(ex => (
            <button
              key={ex}
              onClick={() => setForm(f => ({ ...f, message_text: ex }))}
              className="text-xs px-2.5 py-1 bg-gray-800 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
            >
              {ex.length > 40 ? ex.slice(0, 40) + '…' : ex}
            </button>
          ))}
        </div>
      </div>

      <button
        onClick={submit}
        disabled={loading}
        className="w-full py-2 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
      >
        {loading
          ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Processing…</>
          : <><Send className="w-3.5 h-3.5" /> Simulate</>
        }
      </button>
    </div>
  );
}

// ─── ingress quick tests ─────────────────────────────────────────────────────

function IngressQuickTests({ onResult }: { onResult: (r: any) => void }) {
  const [loading, setLoading] = useState<string | null>(null);

  const sendCli = async () => {
    setLoading('cli');
    try {
      const result = await ingestChannelCli({
        terminal_id: 'soc-terminal',
        terminal_name: 'SOC CLI',
        user: 'analyst@company.com',
        tenant_id: 'tenant_cli_demo',
        message_text: 'run cloud scan now',
      });
      onResult(result);
    } finally { setLoading(null); }
  };

  const sendWebhook = async () => {
    setLoading('webhook');
    try {
      const result = await ingestChannelWebhook({
        channel_id: 'webhook-alerts',
        channel_name: 'Webhook Alerts',
        sender_email: 'webhook@company.com',
        sender_name: 'Webhook Bot',
        message_text: 'investigate threat indicator in prod',
      });
      onResult(result);
    } finally { setLoading(null); }
  };

  const sendEmail = async () => {
    setLoading('email');
    try {
      const result = await ingestChannelEmail({
        inbox: 'soc-inbox',
        inbox_name: 'SOC Inbox',
        from_email: 'analyst@company.com',
        from_name: 'SOC Analyst',
        subject: 'Cloud alert',
        body_text: 'run cloud scan for tenant prod',
      });
      onResult(result);
    } finally { setLoading(null); }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
      <h3 className="text-white font-semibold text-sm flex items-center gap-2">
        <Command className="w-4 h-4 text-cyan-400" /> Channel Ingress Quick Tests
      </h3>
      <p className="text-xs text-gray-500">Send a real ingest request through each adapter to verify normalized command flow.</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <button
          onClick={sendCli}
          disabled={loading !== null}
          className="px-3 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-xs text-gray-200 flex items-center justify-center gap-1.5 disabled:opacity-60"
        >
          {loading === 'cli' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Terminal className="w-3.5 h-3.5 text-cyan-400" />}
          CLI Ingest
        </button>
        <button
          onClick={sendWebhook}
          disabled={loading !== null}
          className="px-3 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-xs text-gray-200 flex items-center justify-center gap-1.5 disabled:opacity-60"
        >
          {loading === 'webhook' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Webhook className="w-3.5 h-3.5 text-purple-400" />}
          Webhook Ingest
        </button>
        <button
          onClick={sendEmail}
          disabled={loading !== null}
          className="px-3 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-xs text-gray-200 flex items-center justify-center gap-1.5 disabled:opacity-60"
        >
          {loading === 'email' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Mail className="w-3.5 h-3.5 text-yellow-400" />}
          Email Ingest
        </button>
      </div>
    </div>
  );
}

// ─── simulation result ────────────────────────────────────────────────────────

function SimResult({ result }: { result: any }) {
  if (!result) return null;
  const meta = DECISION_META[result.policy_decision] ?? DECISION_META.blocked;
  const Icon = meta.icon;

  return (
    <div className={`rounded-xl border p-5 space-y-3 ${meta.bg}`}>
      <div className="flex items-center gap-2">
        <Icon className={`w-5 h-5 ${meta.color}`} />
        <span className={`font-semibold text-sm ${meta.color}`}>
          {meta.label} — {result.execution_status?.replace('_', ' ')}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div>
          <p className="text-gray-500 mb-0.5">Identity</p>
          <p className={`${result.identity_verified ? 'text-green-400' : 'text-red-400'}`}>
            {result.identity_verified ? 'Verified' : 'Unverified'} · Risk: {result.identity_risk}
          </p>
        </div>
        <div>
          <p className="text-gray-500 mb-0.5">Detected Intent</p>
          <p className="text-gray-300">{result.detected_intent || 'none'}</p>
        </div>
        <div>
          <p className="text-gray-500 mb-0.5">Detected Claws</p>
          <p className="text-gray-300">{result.detected_claws?.join(', ') || 'none'}</p>
        </div>
        <div>
          <p className="text-gray-500 mb-0.5">Policy Flags</p>
          <p className="text-gray-300">{result.policy_flags?.join(', ') || 'none'}</p>
        </div>
      </div>
      <div>
        <p className="text-xs text-gray-500 mb-1">Response</p>
        <pre className="text-sm text-gray-200 bg-black/20 rounded-lg p-3 whitespace-pre-wrap">
          {result.response_text}
        </pre>
      </div>
    </div>
  );
}

// ─── identity editor ──────────────────────────────────────────────────────────

function IdentityEditor({ identities, onSaved }: { identities: Identity[]; onSaved: () => void }) {
  const [form, setForm] = useState({
    channel_type:     'slack',
    platform_user_id: '',
    platform_email:   '',
    platform_name:    '',
    regentclaw_role:  'analyst',
    is_trusted:       true,
    trust_score:      80,
    max_autonomy:     'approval',
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.platform_user_id) return;
    setSaving(true);
    try {
      await upsertChannelIdentity(form);
      onSaved();
    } finally { setSaving(false); }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        {[
          { label: 'Channel Type', key: 'channel_type', type: 'select', options: ['slack', 'teams'] },
          { label: 'Platform User ID', key: 'platform_user_id', type: 'text' },
          { label: 'Email', key: 'platform_email', type: 'text' },
          { label: 'Name', key: 'platform_name', type: 'text' },
          { label: 'Role', key: 'regentclaw_role', type: 'select', options: ROLES },
          { label: 'Max Autonomy', key: 'max_autonomy', type: 'select', options: AUTONOMY_LEVELS },
        ].map(({ label, key, type, options }) => (
          <div key={key}>
            <label className="text-xs text-gray-500 mb-1 block">{label}</label>
            {type === 'select' ? (
              <select
                value={(form as any)[key]}
                onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
              >
                {options!.map(o => <option key={o} value={o}>{o}</option>)}
              </select>
            ) : (
              <input
                value={(form as any)[key]}
                onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
              />
            )}
          </div>
        ))}
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Trust Score (0-100)</label>
          <input
            type="number" min={0} max={100}
            value={form.trust_score}
            onChange={e => setForm(f => ({ ...f, trust_score: parseInt(e.target.value) || 0 }))}
            className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
          />
        </div>
        <div className="flex items-center gap-3 mt-6">
          <label className="text-xs text-gray-400">Trusted</label>
          <button
            onClick={() => setForm(f => ({ ...f, is_trusted: !f.is_trusted }))}
            className={`relative w-10 h-5 rounded-full transition-colors ${form.is_trusted ? 'bg-cyan-600' : 'bg-gray-700'}`}
          >
            <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${form.is_trusted ? 'left-5' : 'left-0.5'}`} />
          </button>
        </div>
      </div>
      <button
        onClick={save} disabled={saving || !form.platform_user_id}
        className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm rounded-lg transition-colors disabled:opacity-50"
      >
        {saving ? 'Saving…' : 'Save Identity'}
      </button>

      {identities.length > 0 && (
        <div className="mt-4">
          <p className="text-xs text-gray-500 mb-2">Registered Identities</p>
          <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500">
                  <th className="px-4 py-2 text-left">Platform</th>
                  <th className="px-4 py-2 text-left">User ID</th>
                  <th className="px-4 py-2 text-left">Email</th>
                  <th className="px-4 py-2 text-left">Role</th>
                  <th className="px-4 py-2 text-left">Trust</th>
                  <th className="px-4 py-2 text-left">Trusted</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {identities.map(ci => (
                  <tr key={ci.id} className="hover:bg-gray-900/50">
                    <td className="px-4 py-2 text-gray-400 capitalize">{ci.channel_type}</td>
                    <td className="px-4 py-2 text-gray-300 font-mono">{ci.platform_user_id}</td>
                    <td className="px-4 py-2 text-gray-400">{ci.platform_email || '—'}</td>
                    <td className="px-4 py-2 text-cyan-400 capitalize">{ci.regentclaw_role}</td>
                    <td className="px-4 py-2 text-gray-300">{ci.trust_score}</td>
                    <td className="px-4 py-2">
                      {ci.is_trusted
                        ? <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                        : <XCircle    className="w-3.5 h-3.5 text-red-400" />
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── main page ────────────────────────────────────────────────────────────────

const TABS = ['Messages', 'Simulate', 'Commands', 'Identities'] as const;
type Tab = typeof TABS[number];

export default function ChannelGatewayPage() {
  const [tab,        setTab]        = useState<Tab>('Messages');
  const [messages,   setMessages]   = useState<Message[]>([]);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [pendingCommands, setPendingCommands] = useState<PendingCommand[]>([]);
  const [stats,      setStats]      = useState<Stats | null>(null);
  const [total,      setTotal]      = useState(0);
  const [loading,    setLoading]    = useState(true);
  const [simResult,  setSimResult]  = useState<any>(null);
  const [approving, setApproving] = useState<string | null>(null);
  const [rejecting, setRejecting] = useState<string | null>(null);
  const [timelineOpenFor, setTimelineOpenFor] = useState<string | null>(null);
  const [timelineLoadingFor, setTimelineLoadingFor] = useState<string | null>(null);
  const [timelines, setTimelines] = useState<Record<string, TimelineEvent[]>>({});
  const [timelineFilter, setTimelineFilter] = useState<TimelineFilter>('all');
  const [commandSearch, setCommandSearch] = useState('');
  const [commandSourceFilter, setCommandSourceFilter] = useState('all');
  const [commandMinRisk, setCommandMinRisk] = useState(0);
  const [commandStatus, setCommandStatus] = useState<Record<string, any>>({});
  const [updatingPolicyFor, setUpdatingPolicyFor] = useState<string | null>(null);
  const [selectedCommandIds, setSelectedCommandIds] = useState<string[]>([]);
  const [bulkReviewing, setBulkReviewing] = useState<'approve' | 'reject' | null>(null);
  const [bulkReviewResult, setBulkReviewResult] = useState<any | null>(null);

  // Filters
  const [typeFilter,     setTypeFilter]     = useState('all');
  const [decisionFilter, setDecisionFilter] = useState('all');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = { limit: '50' };
      if (typeFilter !== 'all')     params.channel_type    = typeFilter;
      if (decisionFilter !== 'all') params.policy_decision = decisionFilter;
      const [msgData, statsData, idData, pendingData] = await Promise.all([
        getChannelMessages(params),
        getChannelGatewayStats(),
        getChannelIdentities(),
        getPendingCommands(50, {
          source: commandSourceFilter === 'all' ? undefined : commandSourceFilter,
          min_risk: commandMinRisk > 0 ? commandMinRisk : undefined,
        }),
      ]);
      setMessages((msgData as any).messages || []);
      setTotal((msgData as any).total || 0);
      setStats(statsData as Stats);
      setIdentities(idData as Identity[]);
      setPendingCommands((pendingData as any).commands || []);
    } finally { setLoading(false); }
  }, [typeFilter, decisionFilter, commandSourceFilter, commandMinRisk]);

  useEffect(() => { load(); }, [load]);

  const approveCommand = async (commandId: string) => {
    setApproving(commandId);
    try {
      await approvePendingCommand(commandId, {
        approver: 'channel_gateway_ui',
        reason: 'Approved from Channel Gateway command panel',
      });
      await load();
    } finally {
      setApproving(null);
    }
  };

  const rejectCommand = async (commandId: string) => {
    setRejecting(commandId);
    try {
      await rejectPendingCommand(commandId, {
        reviewer: 'channel_gateway_ui',
        reason: 'Rejected from Channel Gateway command panel',
      });
      await load();
    } finally {
      setRejecting(null);
    }
  };

  const toggleTimeline = async (commandId: string) => {
    if (timelineOpenFor === commandId) {
      setTimelineOpenFor(null);
      return;
    }
    setTimelineOpenFor(commandId);
    if (timelines[commandId]) return;
    setTimelineLoadingFor(commandId);
    try {
      const timelineFilters =
        timelineFilter === 'approvals'
          ? { action_contains: 'approve' }
          : timelineFilter === 'rejections'
          ? { action_contains: 'reject' }
          : undefined;
      const res = await getCommandTimeline(commandId, 100, timelineFilters);
      setTimelines(prev => ({ ...prev, [commandId]: (res?.timeline || []) as TimelineEvent[] }));
      const status = await getCommandStatus(commandId);
      setCommandStatus(prev => ({ ...prev, [commandId]: status }));
    } catch {
      setTimelines(prev => ({ ...prev, [commandId]: [] }));
    } finally {
      setTimelineLoadingFor(null);
    }
  };

  useEffect(() => {
    if (!timelineOpenFor) return;
    const loadTimelineFiltered = async () => {
      setTimelineLoadingFor(timelineOpenFor);
      try {
        const timelineFilters =
          timelineFilter === 'approvals'
            ? { action_contains: 'approve' }
            : timelineFilter === 'rejections'
            ? { action_contains: 'reject' }
            : undefined;
        const res = await getCommandTimeline(timelineOpenFor, 100, timelineFilters);
        setTimelines(prev => ({ ...prev, [timelineOpenFor]: (res?.timeline || []) as TimelineEvent[] }));
      } finally {
        setTimelineLoadingFor(null);
      }
    };
    loadTimelineFiltered();
  }, [timelineFilter, timelineOpenFor]);

  const setRequiredApprovals = async (commandId: string, required: number) => {
    setUpdatingPolicyFor(commandId);
    try {
      await updateCommandApprovalPolicy(commandId, {
        required_approvals: required,
        reason: 'Updated from Channel Gateway command panel',
      });
      await load();
      if (timelineOpenFor === commandId) {
        const status = await getCommandStatus(commandId);
        setCommandStatus(prev => ({ ...prev, [commandId]: status }));
      }
    } finally {
      setUpdatingPolicyFor(null);
    }
  };

  const visiblePendingCommands = pendingCommands.filter((cmd) => {
    if (!commandSearch.trim()) return true;
    const q = commandSearch.toLowerCase();
    return (
      (cmd.command_id || '').toLowerCase().includes(q) ||
      (cmd.actor || '').toLowerCase().includes(q) ||
      (cmd.action || '').toLowerCase().includes(q) ||
      (cmd.target || '').toLowerCase().includes(q)
    );
  });

  const visiblePendingIds = visiblePendingCommands.map((cmd) => cmd.command_id);
  const selectedVisibleCount = selectedCommandIds.filter((id) => visiblePendingIds.includes(id)).length;
  const allVisibleSelected = visiblePendingIds.length > 0 && selectedVisibleCount === visiblePendingIds.length;

  const toggleCommandSelection = (commandId: string) => {
    setSelectedCommandIds((prev) =>
      prev.includes(commandId) ? prev.filter((id) => id !== commandId) : [...prev, commandId],
    );
  };

  const toggleSelectAllVisible = () => {
    setSelectedCommandIds((prev) => {
      if (allVisibleSelected) {
        return prev.filter((id) => !visiblePendingIds.includes(id));
      }
      const next = new Set(prev);
      visiblePendingIds.forEach((id) => next.add(id));
      return Array.from(next);
    });
  };

  const runBulkReview = async (decision: 'approve' | 'reject') => {
    const commandIds = selectedCommandIds.filter((id) => visiblePendingIds.includes(id));
    if (!commandIds.length) return;
    setBulkReviewing(decision);
    try {
      const result = await bulkReviewPendingCommands({
        command_ids: commandIds,
        decision,
        actor: 'channel_gateway_ui',
        reason:
          decision === 'approve'
            ? 'Bulk approved from Channel Gateway command panel'
            : 'Bulk rejected from Channel Gateway command panel',
      });
      setBulkReviewResult(result);
      setSelectedCommandIds([]);
      await load();
    } finally {
      setBulkReviewing(null);
    }
  };

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <MessageSquare className="text-cyan-400" /> Channel Gateway
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            Teams and Slack bot — identity check, policy gate, and claw execution from chat.
          </p>
        </div>
        <button
          onClick={load}
          className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            { label: 'Total',      value: stats.total_messages,       color: 'text-white' },
            { label: 'Allowed',    value: stats.allowed,              color: 'text-green-400' },
            { label: 'Blocked',    value: stats.blocked,              color: stats.blocked > 0 ? 'text-red-400' : 'text-gray-600' },
            { label: 'Pending',    value: stats.pending_approval,     color: stats.pending_approval > 0 ? 'text-yellow-400' : 'text-gray-600' },
            { label: 'Dispatched', value: stats.dispatched_runs,      color: 'text-cyan-400' },
            { label: 'Identities', value: stats.registered_identities, color: 'text-purple-400' },
          ].map(s => (
            <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
              <p className="text-xs text-gray-500">{s.label}</p>
              <p className={`text-2xl font-bold mt-0.5 ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Architecture info */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h3 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" /> Processing Pipeline
        </h3>
        <div className="flex items-center gap-2 text-xs flex-wrap">
          {[
            { label: 'Inbound Message', color: 'bg-gray-700 text-gray-300' },
            { label: '→', color: '' },
            { label: 'Identity Check', color: 'bg-blue-900/30 border border-blue-800 text-blue-300' },
            { label: '→', color: '' },
            { label: 'Policy Gate', color: 'bg-purple-900/30 border border-purple-800 text-purple-300' },
            { label: '→', color: '' },
            { label: 'Intent Parsing', color: 'bg-cyan-900/30 border border-cyan-800 text-cyan-300' },
            { label: '→', color: '' },
            { label: 'Claw Dispatch', color: 'bg-green-900/30 border border-green-800 text-green-300' },
            { label: '→', color: '' },
            { label: 'Respond to Channel', color: 'bg-yellow-900/30 border border-yellow-800 text-yellow-300' },
          ].map((step, i) =>
            step.color
              ? <span key={i} className={`px-2.5 py-1 rounded-lg ${step.color}`}>{step.label}</span>
              : <span key={i} className="text-gray-600">{step.label}</span>
          )}
        </div>
        <p className="text-xs text-gray-600 mt-3">
          Webhook endpoints: <code className="text-gray-400">POST /api/v1/channel-gateway/slack/events</code>  ·  <code className="text-gray-400">POST /api/v1/channel-gateway/teams/webhook</code>  ·  <code className="text-gray-400">POST /api/v1/channel-gateway/webhook</code>  ·  <code className="text-gray-400">POST /api/v1/channel-gateway/email/inbound</code>  ·  <code className="text-gray-400">POST /api/v1/channel-gateway/cli/command</code>
        </p>
      </div>

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

      {/* ── Messages ── */}
      {tab === 'Messages' && (
        <>
          <div className="flex flex-wrap gap-3">
            <div className="flex gap-1 bg-gray-900 border border-gray-700 rounded-xl p-1">
              {['all', 'slack', 'teams'].map(t => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t)}
                  className={`text-xs px-3 py-1.5 rounded-lg capitalize transition-colors ${
                    typeFilter === t ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'
                  }`}
                >{t}</button>
              ))}
            </div>
            <div className="flex gap-1 bg-gray-900 border border-gray-700 rounded-xl p-1">
              {['all', 'allowed', 'blocked', 'requires_approval'].map(d => (
                <button
                  key={d}
                  onClick={() => setDecisionFilter(d)}
                  className={`text-xs px-3 py-1.5 rounded-lg capitalize transition-colors ${
                    decisionFilter === d ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'
                  }`}
                >{d === 'requires_approval' ? 'Pending' : d}</button>
              ))}
            </div>
            <span className="text-xs text-gray-500 self-center">{total} messages</span>
          </div>

          {loading ? (
            <div className="flex justify-center py-12">
              <RefreshCw className="w-7 h-7 text-cyan-400 animate-spin" />
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500 text-xs">
                    <th className="px-4 py-3 text-left">Channel</th>
                    <th className="px-4 py-3 text-left">Sender</th>
                    <th className="px-4 py-3 text-left">Message</th>
                    <th className="px-4 py-3 text-left">Identity</th>
                    <th className="px-4 py-3 text-left">Decision</th>
                    <th className="px-4 py-3 text-left">Execution</th>
                    <th className="px-4 py-3 text-left">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {messages.map(m => <MessageRow key={m.id} msg={m} />)}
                </tbody>
              </table>
              {messages.length === 0 && (
                <p className="text-center py-12 text-gray-500 text-sm">
                  No messages yet. Use the Simulate tab to send a test message.
                </p>
              )}
            </div>
          )}
        </>
      )}

      {/* ── Simulate ── */}
      {tab === 'Simulate' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <SimulatePanel onResult={setSimResult} />
            <IngressQuickTests onResult={setSimResult} />
          </div>
          <div className="space-y-4">
            <h3 className="text-white font-semibold text-sm">Processing Result</h3>
            {simResult
              ? <SimResult result={simResult} />
              : <p className="text-gray-500 text-sm">Simulate a message to see the full processing pipeline output here.</p>
            }
          </div>
        </div>
      )}

      {/* ── Commands ── */}
      {tab === 'Commands' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
            <div>
              <h3 className="text-white font-semibold text-sm flex items-center gap-2">
                <Clock className="w-4 h-4 text-yellow-400" /> Pending Command Approvals
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">Commands requiring approval from CommandClaw policy outcomes.</p>
            </div>
            <span className="text-xs px-2 py-1 rounded bg-gray-800 text-gray-300 border border-gray-700">
              {pendingCommands.length} pending
            </span>
          </div>
          <div className="px-5 py-3 border-b border-gray-800 bg-gray-950/60 flex flex-wrap gap-2">
            <input
              value={commandSearch}
              onChange={(e) => setCommandSearch(e.target.value)}
              placeholder="Search command id/actor/action/target"
              className="px-3 py-1.5 bg-gray-900 border border-gray-700 rounded-lg text-xs text-gray-200 min-w-[240px]"
            />
            <select
              value={commandSourceFilter}
              onChange={(e) => setCommandSourceFilter(e.target.value)}
              className="px-2.5 py-1.5 bg-gray-900 border border-gray-700 rounded-lg text-xs text-gray-200"
            >
              <option value="all">All Sources</option>
              <option value="cli">CLI</option>
              <option value="teams">Teams</option>
              <option value="slack">Slack</option>
              <option value="webhook">Webhook</option>
              <option value="email">Email</option>
            </select>
            <input
              type="number"
              min={0}
              max={100}
              value={commandMinRisk}
              onChange={(e) => setCommandMinRisk(Math.max(0, Math.min(100, parseInt(e.target.value || '0', 10))))}
              className="px-2.5 py-1.5 bg-gray-900 border border-gray-700 rounded-lg text-xs text-gray-200 w-28"
              placeholder="Min risk"
            />
            <button
              onClick={toggleSelectAllVisible}
              className="px-2.5 py-1.5 rounded-lg bg-gray-900 border border-gray-700 text-xs text-gray-200"
            >
              {allVisibleSelected ? 'Unselect visible' : 'Select visible'}
            </button>
            <button
              onClick={() => runBulkReview('approve')}
              disabled={selectedVisibleCount === 0 || bulkReviewing !== null}
              className="px-2.5 py-1.5 rounded-lg bg-green-700 hover:bg-green-600 text-white text-xs disabled:opacity-60"
            >
              {bulkReviewing === 'approve' ? 'Approving…' : `Bulk Approve (${selectedVisibleCount})`}
            </button>
            <button
              onClick={() => runBulkReview('reject')}
              disabled={selectedVisibleCount === 0 || bulkReviewing !== null}
              className="px-2.5 py-1.5 rounded-lg bg-red-800 hover:bg-red-700 text-white text-xs disabled:opacity-60"
            >
              {bulkReviewing === 'reject' ? 'Rejecting…' : `Bulk Reject (${selectedVisibleCount})`}
            </button>
          </div>
          {bulkReviewResult && (
            <div className="px-5 py-3 border-b border-gray-800 bg-gray-950/60">
              <p className="text-xs text-gray-300">
                Bulk result: processed {bulkReviewResult.processed ?? 0} of {bulkReviewResult.requested ?? 0}
                {' · '}approved {bulkReviewResult.approved ?? 0}
                {' · '}rejected {bulkReviewResult.rejected ?? 0}
                {' · '}errors {(bulkReviewResult.errors || []).length}
              </p>
              {(bulkReviewResult.errors || []).length > 0 && (
                <div className="mt-2 space-y-1">
                  {(bulkReviewResult.errors as Array<{ command_id: string; detail: string }>).slice(0, 3).map((e) => (
                    <p key={`${e.command_id}-${e.detail}`} className="text-xs text-red-300">
                      {e.command_id}: {e.detail}
                    </p>
                  ))}
                </div>
              )}
            </div>
          )}
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-4 py-3 text-left">Sel</th>
                <th className="px-4 py-3 text-left">Command ID</th>
                <th className="px-4 py-3 text-left">Actor</th>
                <th className="px-4 py-3 text-left">Actions</th>
                <th className="px-4 py-3 text-left">Target</th>
                <th className="px-4 py-3 text-left">Risk</th>
                <th className="px-4 py-3 text-left">Approvals</th>
                <th className="px-4 py-3 text-left">Time</th>
                <th className="px-4 py-3 text-left">Action</th>
              </tr>
            </thead>
            <tbody>
              {visiblePendingCommands.map(cmd => (
                <div key={cmd.command_id} className="contents">
                  <tr key={cmd.command_id} className="border-b border-gray-800 hover:bg-gray-800/30">
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedCommandIds.includes(cmd.command_id)}
                        onChange={() => toggleCommandSelection(cmd.command_id)}
                        className="h-3.5 w-3.5 accent-cyan-500"
                      />
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-cyan-300">{cmd.command_id}</td>
                    <td className="px-4 py-3 text-xs text-gray-300">{cmd.actor || '—'}</td>
                    <td className="px-4 py-3 text-xs text-gray-300">{cmd.action}</td>
                    <td className="px-4 py-3 text-xs text-gray-400">{cmd.target || '—'}</td>
                    <td className="px-4 py-3 text-xs text-yellow-300">{Math.round(cmd.risk_score || 0)}</td>
                    <td className="px-4 py-3 text-xs text-gray-300">
                      {(cmd.approvals_received ?? 0)}/{(cmd.required_approvals ?? 1)}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {cmd.timestamp ? new Date(cmd.timestamp).toLocaleTimeString() : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1.5 flex-wrap">
                        <button
                          onClick={() => approveCommand(cmd.command_id)}
                          disabled={approving === cmd.command_id || rejecting === cmd.command_id}
                          className="px-2.5 py-1.5 rounded-lg bg-green-700 hover:bg-green-600 text-white text-xs flex items-center gap-1.5 disabled:opacity-60"
                        >
                          {approving === cmd.command_id
                            ? <RefreshCw className="w-3 h-3 animate-spin" />
                            : <Check className="w-3 h-3" />}
                          Approve
                        </button>
                        <button
                          onClick={() => rejectCommand(cmd.command_id)}
                          disabled={rejecting === cmd.command_id || approving === cmd.command_id}
                          className="px-2.5 py-1.5 rounded-lg bg-red-800 hover:bg-red-700 text-white text-xs flex items-center gap-1.5 disabled:opacity-60"
                        >
                          {rejecting === cmd.command_id
                            ? <RefreshCw className="w-3 h-3 animate-spin" />
                            : <XCircle className="w-3 h-3" />}
                          Reject
                        </button>
                        <button
                          onClick={() => toggleTimeline(cmd.command_id)}
                          disabled={timelineLoadingFor === cmd.command_id}
                          className="px-2.5 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 text-xs flex items-center gap-1.5 disabled:opacity-60"
                        >
                          {timelineLoadingFor === cmd.command_id
                            ? <RefreshCw className="w-3 h-3 animate-spin" />
                            : <Clock className="w-3 h-3" />}
                          Timeline
                        </button>
                        <select
                          value={cmd.required_approvals ?? 1}
                          onChange={(e) => setRequiredApprovals(cmd.command_id, parseInt(e.target.value, 10))}
                          disabled={updatingPolicyFor === cmd.command_id}
                          className="px-2 py-1.5 rounded-lg bg-gray-900 border border-gray-700 text-gray-200 text-xs disabled:opacity-60"
                        >
                          <option value={1}>1 approval</option>
                          <option value={2}>2 approvals</option>
                          <option value={3}>3 approvals</option>
                          <option value={4}>4 approvals</option>
                        </select>
                      </div>
                    </td>
                  </tr>
                  {timelineOpenFor === cmd.command_id && (
                    <tr className="border-b border-gray-800 bg-gray-950">
                      <td colSpan={9} className="px-4 py-3">
                        <div className="flex items-center justify-between mb-2">
                          <p className="text-xs text-gray-400">Command Timeline</p>
                          <div className="flex gap-1">
                            {(['all', 'approvals', 'rejections'] as TimelineFilter[]).map((f) => (
                              <button
                                key={f}
                                onClick={() => setTimelineFilter(f)}
                                className={`text-xs px-2 py-1 rounded border ${
                                  timelineFilter === f
                                    ? 'bg-gray-700 border-gray-600 text-white'
                                    : 'bg-gray-900 border-gray-700 text-gray-400'
                                }`}
                              >
                                {f === 'all' ? 'All' : f === 'approvals' ? 'Approvals' : 'Rejections'}
                              </button>
                            ))}
                          </div>
                        </div>
                        <div className="space-y-1.5">
                          {(timelines[cmd.command_id] || []).map((ev, idx) => (
                            <div key={`${cmd.command_id}-${idx}`} className="text-xs bg-gray-900 border border-gray-800 rounded px-2.5 py-1.5 text-gray-300 flex flex-wrap gap-3">
                              <span className="text-gray-500">{ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '—'}</span>
                              <span>{ev.action}</span>
                              <span className="text-cyan-300">{ev.outcome}</span>
                              <span>{ev.actor || '—'}</span>
                              <span className="text-gray-500">{ev.policy_name || '—'}</span>
                            </div>
                          ))}
                          {(timelines[cmd.command_id] || []).length === 0 && (
                            <p className="text-xs text-gray-500">No timeline events available.</p>
                          )}
                          {commandStatus[cmd.command_id] && (
                            <div className="mt-2 text-xs text-gray-400 bg-gray-900 border border-gray-800 rounded px-2.5 py-1.5">
                              Latest outcome: <span className="text-cyan-300">{commandStatus[cmd.command_id].latest_outcome}</span>
                              {' · '}
                              Source: <span className="text-gray-200">{commandStatus[cmd.command_id].source || '—'}</span>
                              {' · '}
                              Requester: <span className="text-gray-200">{commandStatus[cmd.command_id].requester || '—'}</span>
                              {' · '}
                              Last approver: <span className="text-gray-200">{commandStatus[cmd.command_id]?.approval_audit?.last_approver_display || commandStatus[cmd.command_id]?.approval_audit?.last_approved_by || '—'}</span>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </div>
              ))}
            </tbody>
          </table>
          {visiblePendingCommands.length === 0 && (
            <p className="text-center py-10 text-gray-500 text-sm">No pending commands right now.</p>
          )}
        </div>
      )}

      {/* ── Identities ── */}
      {tab === 'Identities' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
            <User className="w-4 h-4 text-cyan-400" /> Channel Identity Registry
          </h3>
          <p className="text-xs text-gray-500 mb-4">
            Register Slack/Teams users with their RegentClaw roles and trust levels. Unregistered users will be blocked.
          </p>
          <IdentityEditor identities={identities} onSaved={load} />
        </div>
      )}
    </div>
  );
}
