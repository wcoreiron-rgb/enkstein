'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Bot, Eye, Zap, UserCheck, Shield, ChevronRight,
  ChevronLeft, Check, AlertTriangle, Plus, X, Loader2,
  Plug, Settings, CalendarClock, Info,
} from 'lucide-react';
import { createAgent, createSchedule } from '@/lib/api';
import { capabilityName } from '@/lib/capability-names';

// ─── Constants ───────────────────────────────────────────────────────────────

const CLAWS = [
  { value: 'arcclaw',         label: 'ArcClaw',         category: 'Core Security', icon: '🤖', color: '#a78bfa' },
  { value: 'identityclaw',    label: 'IdentityClaw',    category: 'Core Security', icon: '👤', color: '#60a5fa' },
  { value: 'cloudclaw',       label: 'CloudClaw',       category: 'Core Security', icon: '☁️', color: '#38bdf8' },
  { value: 'accessclaw',      label: 'AccessClaw',      category: 'Core Security', icon: '🗝️', color: '#facc15' },
  { value: 'endpointclaw',    label: 'EndpointClaw',    category: 'Core Security', icon: '💻', color: '#4ade80' },
  { value: 'netclaw',         label: 'NetClaw',         category: 'Core Security', icon: '🌐', color: '#34d399' },
  { value: 'dataclaw',        label: 'DataClaw',        category: 'Core Security', icon: '🛡️', color: '#fb923c' },
  { value: 'appclaw',         label: 'AppClaw',         category: 'Core Security', icon: '🔌', color: '#f472b6' },
  { value: 'saasclaw',        label: 'SaaSClaw',        category: 'Core Security', icon: '📦', color: '#c084fc' },
  { value: 'threatclaw',      label: 'ThreatClaw',      category: 'Detection',     icon: '🎯', color: '#f87171' },
  { value: 'logclaw',         label: 'LogClaw',         category: 'Detection',     icon: '📜', color: '#94a3b8' },
  { value: 'intelclaw',       label: 'IntelClaw',       category: 'Detection',     icon: '🔍', color: '#818cf8' },
  { value: 'userclaw',        label: 'UserClaw',        category: 'Detection',     icon: '👁️', color: '#22d3ee' },
  { value: 'insiderclaw',     label: 'InsiderClaw',     category: 'Detection',     icon: '🚨', color: '#fb923c' },
  { value: 'automationclaw',  label: 'AutomationClaw',  category: 'SecOps',        icon: '⚡', color: '#fbbf24' },
  { value: 'attackpathclaw',  label: 'AttackPathClaw',  category: 'SecOps',        icon: '🗺️', color: '#f87171' },
  { value: 'exposureclaw',    label: 'ExposureClaw',    category: 'SecOps',        icon: '📡', color: '#fb923c' },
  { value: 'complianceclaw',  label: 'ComplianceClaw',  category: 'Governance',    icon: '📋', color: '#4ade80' },
  { value: 'privacyclaw',     label: 'PrivacyClaw',     category: 'Governance',    icon: '🔒', color: '#a78bfa' },
  { value: 'vendorclaw',      label: 'VendorClaw',      category: 'Governance',    icon: '🤝', color: '#60a5fa' },
  { value: 'devclaw',         label: 'DevClaw',         category: 'Infrastructure',icon: '🔧', color: '#34d399' },
  { value: 'configclaw',      label: 'ConfigClaw',      category: 'Infrastructure',icon: '⚙️', color: '#94a3b8' },
  { value: 'recoveryclaw',    label: 'RecoveryClaw',    category: 'Infrastructure',icon: '🔄', color: '#22d3ee' },
];

const CONNECTOR_OPTIONS = [
  { value: 'entra_id',              label: 'Microsoft Entra ID',     category: 'Identity' },
  { value: 'active_directory',      label: 'Active Directory',        category: 'Identity' },
  { value: 'okta',                  label: 'Okta',                    category: 'Identity' },
  { value: 'microsoft_sentinel',    label: 'Microsoft Sentinel',      category: 'SIEM' },
  { value: 'microsoft_defender',    label: 'Microsoft Defender',      category: 'Endpoint' },
  { value: 'crowdstrike',           label: 'CrowdStrike',             category: 'Endpoint' },
  { value: 'intune',                label: 'Microsoft Intune',        category: 'Endpoint' },
  { value: 'azure_security_center', label: 'Azure Security Center',   category: 'Cloud' },
  { value: 'aws_security_hub',      label: 'AWS Security Hub',        category: 'Cloud' },
  { value: 'google_workspace',      label: 'Google Workspace',        category: 'SaaS' },
  { value: 'microsoft_purview',     label: 'Microsoft Purview',       category: 'Data' },
  { value: 'openai',                label: 'OpenAI',                  category: 'AI' },
  { value: 'azure_openai',          label: 'Azure OpenAI',            category: 'AI' },
  { value: 'anthropic',             label: 'Anthropic Claude',        category: 'AI' },
  { value: 'virustotal',            label: 'VirusTotal',              category: 'Threat Intel' },
  { value: 'abuseipdb',             label: 'AbuseIPDB',               category: 'Threat Intel' },
  { value: 'servicenow',            label: 'ServiceNow',              category: 'Ticketing' },
  { value: 'jira',                  label: 'Jira',                    category: 'Ticketing' },
  { value: 'github',                label: 'GitHub',                  category: 'DevSecOps' },
  { value: 'vanta',                 label: 'Vanta',                   category: 'Compliance' },
  { value: 'drata',                 label: 'Drata',                   category: 'Compliance' },
];

const ACTION_OPTIONS: Record<string, string[]> = {
  arcclaw:        ['read_llm_traffic', 'block_session', 'flag_output', 'log_violation'],
  identityclaw:   ['read_users', 'read_groups', 'read_mfa_status', 'disable_account', 'enforce_mfa_policy', 'send_notification'],
  cloudclaw:      ['read_storage_config', 'read_iam_roles', 'enable_encryption', 'remove_public_acl', 'disable_iam_role'],
  accessclaw:     ['read_privileged_accounts', 'rotate_credential', 'revoke_stale_tokens', 'read_session_logs'],
  endpointclaw:   ['read_endpoint_inventory', 'read_patch_status', 'deploy_edr', 'quarantine_hosts', 'isolate_host'],
  netclaw:        ['read_flow_logs', 'read_firewall_logs', 'block_connection', 'read_dns_logs'],
  dataclaw:       ['read_email_headers', 'scan_file_content', 'quarantine_file', 'block_share'],
  threatclaw:     ['read_alerts', 'correlate_incidents', 'isolate_host', 'create_incident', 'enrich_alert'],
  complianceclaw: ['read_controls', 'read_evidence', 'generate_report', 'create_finding'],
  default:        ['read_data', 'read_logs', 'create_alert', 'send_notification'],
};

const FREQUENCIES = [
  { value: 'manual',       label: 'Manual only' },
  { value: 'every_15min',  label: 'Every 15 minutes' },
  { value: 'hourly',       label: 'Hourly' },
  { value: 'every_6h',     label: 'Every 6 hours' },
  { value: 'daily',        label: 'Daily' },
  { value: 'weekly',       label: 'Weekly' },
  { value: 'monthly',      label: 'Monthly' },
];

const STEPS = ['Capability & Identity', 'Connectors & Actions', 'Governance', 'Schedule & Review'];

// ─── Step 1: Claw & Identity ─────────────────────────────────────────────────

function Step1({ form, set }: { form: any; set: (k: string, v: any) => void }) {
  const categories = Array.from(new Set(CLAWS.map(c => c.category)));
  const selected = CLAWS.find(c => c.value === form.claw);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1">
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
            Agent Name *
          </label>
          <input
            value={form.name}
            onChange={e => set('name', e.target.value)}
            placeholder="e.g. Cloud Exposure Daily Scan"
            className="w-full px-3 py-2 rounded-lg text-sm border outline-none focus:ring-1"
            style={{
              background: 'var(--rc-bg-elevated)',
              borderColor: 'var(--rc-border)',
              color: 'var(--rc-text-1)',
            }}
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
            Owner Name
          </label>
          <input
            value={form.owner_name}
            onChange={e => set('owner_name', e.target.value)}
            placeholder="e.g. SOC Team"
            className="w-full px-3 py-2 rounded-lg text-sm border outline-none"
            style={{
              background: 'var(--rc-bg-elevated)',
              borderColor: 'var(--rc-border)',
              color: 'var(--rc-text-1)',
            }}
          />
        </div>
      </div>

      <div className="space-y-1">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
          Description
        </label>
        <textarea
          value={form.description}
          onChange={e => set('description', e.target.value)}
          rows={2}
          placeholder="What does this agent do? What systems does it scan?"
          className="w-full px-3 py-2 rounded-lg text-sm border outline-none resize-none"
          style={{
            background: 'var(--rc-bg-elevated)',
            borderColor: 'var(--rc-border)',
            color: 'var(--rc-text-1)',
          }}
        />
      </div>

      <div className="space-y-2">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
          Select Capability Node *
        </label>
        {categories.map(cat => (
          <div key={cat} className="space-y-1">
            <p className="text-xs font-medium px-1" style={{ color: 'var(--rc-text-3)' }}>{cat}</p>
            <div className="grid grid-cols-3 gap-2">
              {CLAWS.filter(c => c.category === cat).map(claw => (
                <button
                  key={claw.value}
                  onClick={() => { set('claw', claw.value); set('category', claw.category); set('icon', claw.icon); }}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all"
                  style={{
                    background:   form.claw === claw.value ? `${claw.color}20` : 'var(--rc-bg-elevated)',
                    borderColor:  form.claw === claw.value ? claw.color : 'var(--rc-border)',
                    color:        form.claw === claw.value ? claw.color : 'var(--rc-text-2)',
                  }}
                >
                  <span>{claw.icon}</span>
                  {capabilityName(claw.value)}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>

      {selected && (
        <div className="rounded-lg border p-3 flex items-center gap-3"
          style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' }}>
          <span className="text-2xl">{selected.icon}</span>
          <div>
            <p className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>{capabilityName(selected.value)}</p>
            <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{selected.category}</p>
          </div>
          <Check className="w-4 h-4 ml-auto" style={{ color: selected.color }} />
        </div>
      )}
    </div>
  );
}

// ─── Step 2: Connectors & Actions ────────────────────────────────────────────

function Step2({ form, set }: { form: any; set: (k: string, v: any) => void }) {
  const connectors: string[] = form.allowed_connectors || [];
  const actions: string[] = form.allowed_actions || [];
  const availableActions = ACTION_OPTIONS[form.claw] || ACTION_OPTIONS.default;
  const connectorCategories = Array.from(new Set(CONNECTOR_OPTIONS.map(c => c.category)));

  const toggleConnector = (val: string) => {
    set('allowed_connectors', connectors.includes(val)
      ? connectors.filter(c => c !== val)
      : [...connectors, val]);
  };

  const toggleAction = (val: string) => {
    set('allowed_actions', actions.includes(val)
      ? actions.filter(a => a !== val)
      : [...actions, val]);
  };

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
          Connectors to Query
        </label>
        <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
          Select which data sources this agent can pull from. Only connected connectors will be active.
        </p>
        {connectorCategories.map(cat => (
          <div key={cat} className="space-y-1">
            <p className="text-xs font-medium px-1" style={{ color: 'var(--rc-text-3)' }}>{cat}</p>
            <div className="grid grid-cols-3 gap-2">
              {CONNECTOR_OPTIONS.filter(c => c.category === cat).map(conn => {
                const active = connectors.includes(conn.value);
                return (
                  <button key={conn.value} onClick={() => toggleConnector(conn.value)}
                    className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-xs transition-all"
                    style={{
                      background:  active ? 'rgba(99,102,241,0.12)' : 'var(--rc-bg-elevated)',
                      borderColor: active ? '#4f46e5' : 'var(--rc-border)',
                      color:       active ? '#818cf8' : 'var(--rc-text-2)',
                    }}>
                    <Plug className="w-3 h-3 flex-shrink-0" />
                    <span className="truncate">{conn.label}</span>
                    {active && <Check className="w-3 h-3 ml-auto flex-shrink-0" />}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="space-y-2">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
          Allowed Actions
        </label>
        <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
          Actions this agent may request. Trust Fabric will still gate each action at runtime.
        </p>
        <div className="flex flex-wrap gap-2">
          {availableActions.map(action => {
            const active = actions.includes(action);
            return (
              <button key={action} onClick={() => toggleAction(action)}
                className="px-3 py-1.5 rounded-lg border text-xs font-mono transition-all"
                style={{
                  background:  active ? 'rgba(34,197,94,0.12)' : 'var(--rc-bg-elevated)',
                  borderColor: active ? '#16a34a' : 'var(--rc-border)',
                  color:       active ? '#4ade80' : 'var(--rc-text-3)',
                }}>
                {active && <span className="mr-1">✓</span>}
                {action}
              </button>
            );
          })}
        </div>
      </div>

      <div className="space-y-1">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
          Scope Notes
        </label>
        <textarea
          value={form.scope_notes}
          onChange={e => set('scope_notes', e.target.value)}
          rows={2}
          placeholder="Describe the scope limits — which tenants, subscriptions, environments, or data sets"
          className="w-full px-3 py-2 rounded-lg text-sm border outline-none resize-none"
          style={{
            background: 'var(--rc-bg-elevated)',
            borderColor: 'var(--rc-border)',
            color: 'var(--rc-text-1)',
          }}
        />
      </div>
    </div>
  );
}

// ─── Step 3: Governance ───────────────────────────────────────────────────────

function Step3({ form, set }: { form: any; set: (k: string, v: any) => void }) {
  const modeOptions = [
    { value: 'monitor',    label: 'Monitor',    icon: Eye,       color: '#60a5fa', desc: 'Observe and log only. Zero writes.' },
    { value: 'assist',     label: 'Assist',     icon: UserCheck, color: '#a78bfa', desc: 'Propose actions, require human approval.' },
    { value: 'autonomous', label: 'Autonomous', icon: Zap,       color: '#4ade80', desc: 'Auto-execute pre-approved low-risk actions.' },
  ];

  const riskOptions = [
    { value: 'low',      label: 'Low',      color: '#4ade80' },
    { value: 'medium',   label: 'Medium',   color: '#facc15' },
    { value: 'high',     label: 'High',     color: '#fb923c' },
    { value: 'critical', label: 'Critical', color: '#f87171' },
  ];

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
          Execution Mode
        </label>
        <div className="grid grid-cols-3 gap-3">
          {modeOptions.map(m => {
            const Icon = m.icon;
            const active = form.execution_mode === m.value;
            return (
              <button key={m.value} onClick={() => set('execution_mode', m.value)}
                className="flex flex-col items-center gap-2 p-4 rounded-xl border text-center transition-all"
                style={{
                  background:  active ? `${m.color}15` : 'var(--rc-bg-elevated)',
                  borderColor: active ? m.color : 'var(--rc-border)',
                }}>
                <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                  style={{ background: active ? `${m.color}25` : 'var(--rc-bg-surface)' }}>
                  <Icon className="w-5 h-5" style={{ color: active ? m.color : 'var(--rc-text-3)' }} />
                </div>
                <p className="text-xs font-semibold" style={{ color: active ? m.color : 'var(--rc-text-2)' }}>
                  {m.label}
                </p>
                <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{m.desc}</p>
              </button>
            );
          })}
        </div>
      </div>

      <div className="space-y-2">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
          Risk Level
        </label>
        <div className="flex gap-3">
          {riskOptions.map(r => (
            <button key={r.value} onClick={() => set('risk_level', r.value)}
              className="flex-1 py-2 rounded-lg border text-xs font-semibold transition-all"
              style={{
                background:  form.risk_level === r.value ? `${r.color}20` : 'var(--rc-bg-elevated)',
                borderColor: form.risk_level === r.value ? r.color : 'var(--rc-border)',
                color:       form.risk_level === r.value ? r.color : 'var(--rc-text-3)',
              }}>
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1">
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
            Max Runtime (seconds)
          </label>
          <input type="number" value={form.max_runtime_sec}
            onChange={e => set('max_runtime_sec', parseInt(e.target.value))}
            className="w-full px-3 py-2 rounded-lg text-sm border outline-none"
            style={{
              background: 'var(--rc-bg-elevated)',
              borderColor: 'var(--rc-border)',
              color: 'var(--rc-text-1)',
            }}
          />
          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            {Math.floor(form.max_runtime_sec / 60)}m {form.max_runtime_sec % 60}s
          </p>
        </div>
        <div className="space-y-2 pt-1">
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
            Approval Required
          </label>
          <button onClick={() => set('requires_approval', !form.requires_approval)}
            className="flex items-center gap-3 px-3 py-2 rounded-lg border w-full text-sm transition-all"
            style={{
              background:  form.requires_approval ? 'rgba(167,139,250,0.12)' : 'var(--rc-bg-elevated)',
              borderColor: form.requires_approval ? '#7c3aed' : 'var(--rc-border)',
              color:       form.requires_approval ? '#a78bfa' : 'var(--rc-text-2)',
            }}>
            <Shield className="w-4 h-4" />
            {form.requires_approval ? 'Approval required' : 'No approval needed'}
          </button>
        </div>
      </div>

      <div className="rounded-xl border p-4"
        style={{ background: 'rgba(99,102,241,0.06)', borderColor: '#4f46e5' }}>
        <div className="flex items-start gap-3">
          <Info className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: '#818cf8' }} />
          <div className="text-xs space-y-1" style={{ color: 'var(--rc-text-2)' }}>
            <p className="font-semibold" style={{ color: '#818cf8' }}>Trust Fabric governs every run</p>
            <p>Regardless of execution mode, every action goes through CoreOS → Trust Fabric → Policy Engine → Connector Broker → Audit before execution.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Step 4: Schedule & Review ────────────────────────────────────────────────

function Step4({ form, set }: { form: any; set: (k: string, v: any) => void }) {
  const claw = CLAWS.find(c => c.value === form.claw);
  const selectedConnectors = CONNECTOR_OPTIONS.filter(c => (form.allowed_connectors || []).includes(c.value));

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
          Default Schedule
        </label>
        <div className="grid grid-cols-4 gap-2">
          {FREQUENCIES.map(f => (
            <button key={f.value} onClick={() => set('frequency', f.value)}
              className="py-2 px-3 rounded-lg border text-xs font-medium transition-all"
              style={{
                background:  form.frequency === f.value ? 'rgba(99,102,241,0.15)' : 'var(--rc-bg-elevated)',
                borderColor: form.frequency === f.value ? '#4f46e5' : 'var(--rc-border)',
                color:       form.frequency === f.value ? '#818cf8' : 'var(--rc-text-2)',
              }}>
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Review summary */}
      <div className="space-y-3">
        <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
          Review
        </p>

        <div className="rounded-xl border divide-y" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
          {[
            { label: 'Agent Name',      value: form.name || '(unnamed)' },
            { label: 'Capability Node', value: claw ? `${claw.icon} ${capabilityName(claw.value)}` : '—' },
            { label: 'Category',        value: form.category || '—' },
            { label: 'Execution Mode',  value: form.execution_mode.toUpperCase() },
            { label: 'Risk Level',      value: form.risk_level.toUpperCase() },
            { label: 'Max Runtime',     value: `${form.max_runtime_sec}s` },
            { label: 'Approval',        value: form.requires_approval ? 'Required' : 'Not required' },
            { label: 'Schedule',        value: FREQUENCIES.find(f => f.value === form.frequency)?.label || '—' },
            { label: 'Connectors',      value: selectedConnectors.length > 0 ? selectedConnectors.map(c => c.label).join(', ') : 'None selected' },
            { label: 'Actions',         value: (form.allowed_actions || []).length > 0 ? (form.allowed_actions || []).join(', ') : 'None selected' },
            { label: 'Owner',           value: form.owner_name || '—' },
          ].map(({ label, value }) => (
            <div key={label} className="flex items-center gap-4 px-4 py-2.5">
              <span className="text-xs w-28 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }}>{label}</span>
              <span className="text-xs font-medium" style={{ color: 'var(--rc-text-1)' }}>{value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Main Builder ─────────────────────────────────────────────────────────────

const DEFAULT_FORM = {
  name:               '',
  description:        '',
  claw:               '',
  category:           '',
  icon:               '🤖',
  execution_mode:     'monitor',
  risk_level:         'low',
  max_runtime_sec:    300,
  requires_approval:  false,
  allowed_actions:    [] as string[],
  allowed_connectors: [] as string[],
  scope_notes:        '',
  owner_name:         '',
  frequency:          'daily',
};

export default function AgentBuilderPage() {
  const router = useRouter();
  const [step, setStep]     = useState(0);
  const [form, setForm]     = useState({ ...DEFAULT_FORM });
  const [saving, setSaving] = useState(false);
  const [error, setError]   = useState<string | null>(null);

  const set = (k: string, v: any) => setForm(prev => ({ ...prev, [k]: v }));

  const canNext = () => {
    if (step === 0) return form.name.trim() !== '' && form.claw !== '';
    return true;
  };

  const handleCreate = async () => {
    setSaving(true);
    setError(null);
    try {
      const agent = await createAgent({
        name:               form.name,
        description:        form.description,
        claw:               form.claw,
        category:           form.category,
        icon:               form.icon,
        execution_mode:     form.execution_mode,
        risk_level:         form.risk_level,
        max_runtime_sec:    form.max_runtime_sec,
        requires_approval:  form.requires_approval,
        allowed_actions:    JSON.stringify(form.allowed_actions),
        allowed_connectors: JSON.stringify(form.allowed_connectors),
        scope_notes:        form.scope_notes,
        owner_name:         form.owner_name,
        status:             'active',
        is_builtin:         false,
      });

      // Create default schedule if not manual
      if (form.frequency !== 'manual') {
        await createSchedule({
          name:              `${form.name} — Default`,
          agent_id:          agent.id,
          frequency:         form.frequency,
          status:            'active',
          approval_required: form.requires_approval,
          owner_name:        form.owner_name,
        });
      }

      router.push('/agents');
    } catch (e: any) {
      setError(e.message || 'Failed to create agent');
      setSaving(false);
    }
  };

  const stepContent = [
    <Step1 key="s1" form={form} set={set} />,
    <Step2 key="s2" form={form} set={set} />,
    <Step3 key="s3" form={form} set={set} />,
    <Step4 key="s4" form={form} set={set} />,
  ];

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button onClick={() => router.push('/agents')}
          className="p-2 rounded-lg transition-all hover:opacity-70"
          style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}>
          <ChevronLeft className="w-4 h-4" />
        </button>
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--rc-text-1)' }}>
            Create Security Agent
          </h1>
          <p className="text-sm" style={{ color: 'var(--rc-text-3)' }}>
            Governed by Trust Fabric — every action goes through CoreOS before execution
          </p>
        </div>
      </div>

      {/* Step indicators */}
      <div className="flex items-center gap-2">
        {STEPS.map((label, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="flex items-center gap-2">
              <div
                className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold"
                style={{
                  background: i < step ? '#4ade80' : i === step ? 'var(--regent-600)' : 'var(--rc-bg-elevated)',
                  color:      i <= step ? '#fff' : 'var(--rc-text-3)',
                }}>
                {i < step ? <Check className="w-3.5 h-3.5" /> : i + 1}
              </div>
              <span className="text-xs font-medium hidden sm:block"
                style={{ color: i === step ? 'var(--rc-text-1)' : 'var(--rc-text-3)' }}>
                {label}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div className="flex-1 h-px w-8" style={{ background: i < step ? '#4ade80' : 'var(--rc-border)' }} />
            )}
          </div>
        ))}
      </div>

      {/* Step content */}
      <div className="rounded-xl border p-6"
        style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
        <h2 className="text-base font-semibold mb-5" style={{ color: 'var(--rc-text-1)' }}>
          {STEPS[step]}
        </h2>
        {stepContent[step]}
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-lg border px-4 py-3 text-sm flex items-center gap-2"
          style={{ background: 'rgba(239,68,68,0.08)', borderColor: '#dc2626', color: '#f87171' }}>
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => step > 0 ? setStep(step - 1) : router.push('/agents')}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-all hover:opacity-80"
          style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}>
          <ChevronLeft className="w-4 h-4" />
          {step === 0 ? 'Cancel' : 'Back'}
        </button>

        {step < STEPS.length - 1 ? (
          <button
            onClick={() => setStep(step + 1)}
            disabled={!canNext()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all"
            style={{
              background: canNext() ? 'var(--regent-600)' : 'var(--rc-bg-elevated)',
              color: canNext() ? '#fff' : 'var(--rc-text-3)',
              cursor: canNext() ? 'pointer' : 'not-allowed',
            }}>
            Next
            <ChevronRight className="w-4 h-4" />
          </button>
        ) : (
          <button
            onClick={handleCreate}
            disabled={saving}
            className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-semibold transition-all"
            style={{ background: 'var(--regent-600)', color: '#fff' }}>
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Bot className="w-4 h-4" />}
            {saving ? 'Creating…' : 'Create Agent'}
          </button>
        )}
      </div>
    </div>
  );
}
