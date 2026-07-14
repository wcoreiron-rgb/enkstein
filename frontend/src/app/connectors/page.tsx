'use client';
import { useEffect, useState, useMemo } from 'react';
import {
  Plug, ShieldCheck, CheckCircle, Clock, Ban, AlertTriangle,
  ChevronDown, ChevronUp, Key, Settings, Zap, X, Eye, EyeOff,
  Shield, Loader, Search,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';

// ── Brand logos via Simple Icons CDN ─────────────────────────────────────────
// Format: https://cdn.simpleicons.org/{slug}/{hex-color}

const BRAND_LOGOS: Record<string, { slug: string; color: string; bg: string; local?: string }> = {
  // Identity & Access
  entra_id:       { slug: 'microsoftazure',    color: '0078d4', bg: '#0d2d4d', local: '/Entra-ID-logo.png' },
  okta:           { slug: 'okta',              color: '007dc1', bg: '#00243d' },
  ping_identity:  { slug: 'pingidentity',      color: 'e1001a', bg: '#3d0007', local: '/ping-identity-logo.png' },
  auth0:          { slug: 'auth0',             color: 'eb5424', bg: '#3d1b0e', local: '/auth0-logo.png' },
  cyberark:       { slug: 'cyberark',          color: 'e21a23', bg: '#3d0609' },
  hashicorp_vault:{ slug: 'vault',             color: 'ffcf25', bg: '#3d2e00' },
  duo:            { slug: 'duo',               color: '6dc535', bg: '#1a3008', local: '/accounts-icon-duo-security-duo-security-logo-11563033627fbimdualw8.png' },

  // Security & SIEM
  sentinel:       { slug: 'microsoftazure',    color: '0078d4', bg: '#0d2d4d', local: '/icon-microsoft-sentinel.png' },
  splunk:         { slug: 'splunk',            color: '65a637', bg: '#192b0e', local: '/Splunk.png' },
  qradar:         { slug: 'ibm',               color: '1f70c1', bg: '#ffffff', local: '/ibm-qradar-logo.png' },
  elastic:        { slug: 'elastic',           color: '00bfb3', bg: '#003330', local: '/elastic-logo.jpg' },
  datadog:        { slug: 'datadog',           color: '632ca6', bg: '#1e0d33' },
  sumologic:      { slug: 'sumologic',         color: '000099', bg: '#00002e', local: '/sumo-logic-logo.png' },

  // Endpoint & EDR
  crowdstrike:    { slug: 'crowdstrike',       color: 'e8350b', bg: '#ffffff', local: '/crowdstrike-logo.png' },
  defender_endpoint: { slug: 'microsoftdefender', color: '00a4ef', bg: '#ffffff', local: '/defender-endpoint-logo.png' },
  sentinelone:    { slug: 'sentinelone',       color: '6a3ec2', bg: '#ffffff', local: '/SentinelOne.png' },
  carbonblack:    { slug: 'vmware',            color: '607078', bg: '#1a2023' },
  tanium:         { slug: 'tanium',            color: '00b140', bg: '#ffffff', local: '/tanium-logo.png' },

  // Cloud & Infrastructure
  aws_iam:        { slug: 'amazonaws',         color: 'ff9900', bg: '#ffffff', local: '/aws-identity.png' },
  azure_arm:      { slug: 'microsoftazure',    color: '0078d4', bg: '#ffffff', local: '/azure-arm.png' },
  gcp_iam:        { slug: 'googlecloud',       color: '4285f4', bg: '#ffffff', local: '/google-iam.png' },
  gcp_scc:        { slug: 'googlecloud',       color: '34a853', bg: '#ffffff', local: '/google-scc.jpg' },
  wiz:            { slug: 'wiz',               color: '00d4ff', bg: '#ffffff', local: '/Wiz-icon-NEW.png' },

  // Network & Zero Trust
  paloalto:       { slug: 'paloaltonetworks',  color: 'fa582d', bg: '#ffffff' },
  zscaler:        { slug: 'zscaler',           color: '1565c0', bg: '#ffffff', local: '/Zscaler_1080x1080.png' },
  cloudflare:     { slug: 'cloudflare',        color: 'f38020', bg: '#ffffff' },
  cisco_umbrella: { slug: 'cisco',             color: '1ba0d7', bg: '#082e3d' },
  netskope:       { slug: 'netskope',          color: '00b5e2', bg: '#ffffff', local: '/netskope.png' },

  // Data & DLP
  purview:        { slug: 'microsoftazure',    color: '0078d4', bg: '#ffffff', local: '/logo-microsoft-purview-.png.webp' },
  varonis:        { slug: 'varonis',           color: 'e02020', bg: '#ffffff', local: '/icon128x128.png' },
  nightfall:      { slug: 'nightfall',         color: 'a855f7', bg: '#2d1040' },
  bigid:          { slug: 'bigid',             color: 'ff6d00', bg: '#3d1a00' },

  // AI / LLM
  openai:         { slug: 'openai',            color: '74aa9c', bg: '#1a2e2c' },
  azure_openai:   { slug: 'openai',            color: '74aa9c', bg: '#1a2e2c' },
  anthropic:      { slug: 'anthropic',         color: 'd4a27f', bg: '#3d2510' },
  ollama:         { slug: 'ollama',            color: 'ffffff', bg: '#1a1a2e' },
  nvidia_nim:     { slug: 'nvidia',            color: '76b900', bg: '#162408' },

  // Dev & Collaboration
  github:         { slug: 'github',            color: 'ffffff', bg: '#1a1a2e' },
  gitlab:         { slug: 'gitlab',            color: 'fc6d26', bg: '#3d1d09' },
  slack:          { slug: 'slack',             color: '4a154b', bg: '#1a0820' },
  ms_teams:       { slug: 'microsoftteams',    color: '6264a7', bg: '#1a1b35' },
  jira:           { slug: 'jira',              color: '0052cc', bg: '#001a40' },
  pagerduty:      { slug: 'pagerduty',         color: '06ac38', bg: '#032e10' },
  servicenow:     { slug: 'servicenow',        color: '62d84e', bg: '#1a3a12' },

  // Threat Intel & Vuln
  tenable:        { slug: 'tenable',           color: '00a6ef', bg: '#00304d' },
  qualys:         { slug: 'qualys',            color: 'ed2024', bg: '#3d0609' },
  virustotal:     { slug: 'virustotal',        color: '394eff', bg: '#0a0f40' },
  recorded_future:{ slug: 'recordedfuture',    color: 'ff6600', bg: '#3d1a00' },

  // Compliance & GRC
  drata:          { slug: 'drata',             color: '6c47ff', bg: '#1d1040' },
  vanta:          { slug: 'vanta',             color: '4a60de', bg: '#0f1838' },
};

const BRAND_ALIASES: Record<string, string> = {
  msteams: 'ms_teams',
  teams: 'ms_teams',
  entra: 'entra_id',
  azureopenai: 'azure_openai',
  microsoftsentinel: 'sentinel',
  sentineloneedr: 'sentinelone',
  defender: 'defender_endpoint',
  microsoftdefender: 'defender_endpoint',
  nvidianim: 'nvidia_nim',
  vault: 'hashicorp_vault',
};

function resolveBrandKey(type: string, name: string): string | null {
  const raw = String(type || '').trim().toLowerCase();
  if (!raw) return null;
  if (BRAND_LOGOS[raw]) return raw;

  const normalized = raw.replace(/[^a-z0-9]/g, '');
  const alias = BRAND_ALIASES[normalized];
  if (alias && BRAND_LOGOS[alias]) return alias;

  // Keyword fallback for minor backend/provider key drift.
  const haystack = `${raw} ${String(name || '').toLowerCase()}`;
  const keywordMap: Array<[string, string]> = [
    ['nvidia', 'nvidia_nim'],
    ['azure openai', 'azure_openai'],
    ['openai', 'openai'],
    ['anthropic', 'anthropic'],
    ['ollama', 'ollama'],
    ['okta', 'okta'],
    ['crowdstrike', 'crowdstrike'],
    ['sentinelone', 'sentinelone'],
    ['defender', 'defender_endpoint'],
    ['github', 'github'],
    ['gitlab', 'gitlab'],
    ['slack', 'slack'],
    ['jira', 'jira'],
    ['servicenow', 'servicenow'],
    ['pagerduty', 'pagerduty'],
    ['splunk', 'splunk'],
    ['elastic', 'elastic'],
    ['datadog', 'datadog'],
    ['cloudflare', 'cloudflare'],
    ['zscaler', 'zscaler'],
    ['palo alto', 'paloalto'],
    ['cyberark', 'cyberark'],
    ['duo', 'duo'],
    ['tenable', 'tenable'],
    ['qualys', 'qualys'],
    ['virustotal', 'virustotal'],
  ];
  for (const [needle, key] of keywordMap) {
    if (haystack.includes(needle) && BRAND_LOGOS[key]) return key;
  }
  return null;
}

// ConnectorIcon — real brand logo from Simple Icons, styled initials fallback
function ConnectorIcon({ type, name, size = 32 }: { type: string; name: string; size?: number }) {
  const brandKey = resolveBrandKey(type, name);
  const brand = brandKey ? BRAND_LOGOS[brandKey] : undefined;
  const [imgError, setImgError] = useState(false);

  const initials = (name || type)
    .split(/[\s_-]+/)
    .slice(0, 2)
    .map((w: string) => w[0]?.toUpperCase() ?? '')
    .join('');

  const bg  = brand?.bg  ?? '#1e293b';
  const px  = `${size}px`;

  if (brand && !imgError) {
    return (
      <div
        style={{
          width: px, height: px,
          background: bg,
          borderRadius: '10px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
          padding: '6px',
        }}
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src={brand.local || `https://cdn.simpleicons.org/${brand.slug}/${brand.color}`}
          alt={name}
          width={size - 12}
          height={size - 12}
          onError={() => setImgError(true)}
          style={{ display: 'block', objectFit: 'contain' }}
        />
      </div>
    );
  }

  // Initials fallback
  const colors = ['#312e81','#1e3a5f','#14532d','#4a1942','#7c2d12','#1e3a5f','#3b0764'];
  const hash = Array.from(type).reduce((a, c) => a + c.charCodeAt(0), 0);
  const fallbackBg = colors[hash % colors.length];

  return (
    <div
      style={{
        width: px, height: px,
        background: fallbackBg,
        borderRadius: '10px',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0,
        fontSize: size * 0.35 + 'px',
        fontWeight: '700',
        color: '#fff',
        letterSpacing: '-0.02em',
      }}
    >
      {initials || '?'}
    </div>
  );
}

// ── Status / Risk styles ──────────────────────────────────────────────────────

const STATUS_STYLE: Record<string, { color: string; label: string; icon: typeof CheckCircle }> = {
  approved:   { color: 'text-green-400 bg-green-900/30 border-green-800',    label: 'Approved',   icon: CheckCircle },
  pending:    { color: 'text-yellow-400 bg-yellow-900/30 border-yellow-800', label: 'Pending',    icon: Clock },
  restricted: { color: 'text-orange-400 bg-orange-900/30 border-orange-800', label: 'Restricted', icon: AlertTriangle },
  blocked:    { color: 'text-red-400 bg-red-900/30 border-red-800',          label: 'Blocked',    icon: Ban },
};

const RISK_STYLE: Record<string, string> = {
  low:      'text-green-400 bg-green-900/30 border-green-800',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-800',
  high:     'text-orange-400 bg-orange-900/30 border-orange-800',
  critical: 'text-red-400 bg-red-900/30 border-red-800',
};

function trustColor(score: number) {
  if (score >= 90) return 'text-green-400';
  if (score >= 70) return 'text-blue-400';
  if (score >= 50) return 'text-yellow-400';
  return 'text-red-400';
}

function getCategory(connector: any): string {
  return connector.category || 'Other';
}

// ── Configure Modal ───────────────────────────────────────────────────────────

type Step = 'credentials' | 'review' | 'test' | 'done';

function ConfigureModal({ connector, onClose, onUpdate }: {
  connector: any; onClose: () => void; onUpdate: (c: any) => void;
}) {
  const [step, setStep]         = useState<Step>('credentials');
  const [fields, setFields]     = useState<any[]>([]);
  const [values, setValues]     = useState<Record<string, string>>({});
  const [showPwd, setShowPwd]   = useState<Record<string, boolean>>({});
  const [loading, setLoading]   = useState(true);
  const [loadErr, setLoadErr]   = useState<string | null>(null);
  const [saving, setSaving]     = useState(false);
  const [saveErr, setSaveErr]   = useState<string | null>(null);
  const [testing, setTesting]   = useState(false);
  const [testResult, setTestResult]     = useState<any>(null);
  const [policyResult, setPolicyResult] = useState<any>(null);

  useEffect(() => {
    setLoading(true);
    setLoadErr(null);
    apiFetch<any>(`/connectors/${connector.id}/fields`)
      .then(data => { setFields(data.fields || []); setLoading(false); })
      .catch(e  => { setLoadErr(e.message || 'Failed to load fields'); setLoading(false); });
  }, [connector.id]);

  const handleSave = async () => {
    setSaving(true);
    setSaveErr(null);
    try {
      const result = await apiFetch<any>(`/connectors/${connector.id}/configure`, {
        method: 'POST',
        body: JSON.stringify({ credentials: values }),
      });
      setPolicyResult(result);
      // Always advance — even if policy blocked, show the result in review step
      try {
        const updated = await apiFetch<any>(`/connectors/${connector.id}`);
        onUpdate(updated);
      } catch { /* non-fatal — connector card update can fail silently */ }
      setStep('review');
    } catch (e: any) {
      // Surface the real error so the user knows what went wrong
      const detail = e?.data?.detail || e?.message || 'Failed to save credentials';
      setSaveErr(typeof detail === 'string' ? detail : JSON.stringify(detail));
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    try {
      const result = await apiFetch<any>(`/connectors/${connector.id}/test`, { method: 'POST' });
      setTestResult(result);
      if (result.success) {
        try {
          const updated = await apiFetch<any>(`/connectors/${connector.id}`);
          onUpdate(updated);
        } catch { /* non-fatal */ }
      }
      setStep('done');
    } catch (e: any) {
      setTestResult({ success: false, message: e?.data?.detail || e?.message || 'Test failed' });
      setStep('done');
    } finally { setTesting(false); }
  };

  const approvedScopes: string[] = (() => { try { return JSON.parse(connector.approved_scopes || '[]'); } catch { return []; } })();
  // Allow saving if at least one value is filled, OR if no fields are required (no-auth connectors)
  const hasValues = !loading && (fields.length === 0 || Object.values(values).some(v => v.trim().length > 0));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.75)' }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="w-full max-w-xl rounded-2xl border shadow-2xl overflow-hidden"
        style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>

        {/* Header */}
        <div className="flex items-center gap-4 p-6 border-b" style={{ borderColor: 'var(--rc-border)' }}>
          <ConnectorIcon type={connector.connector_type} name={connector.name} size={48} />
          <div className="flex-1">
            <h2 className="text-lg font-bold" style={{ color: 'var(--rc-text-1)' }}>{connector.name}</h2>
            <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
              {getCategory(connector)} · {connector.connector_type} · Risk: {connector.risk_level}
            </p>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:opacity-70" style={{ color: 'var(--rc-text-3)' }}>
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Steps */}
        <div className="flex border-b" style={{ borderColor: 'var(--rc-border)' }}>
          {[
            { id: 'credentials', label: '1. Credentials' },
            { id: 'review',      label: '2. Policy Check' },
            { id: 'test',        label: '3. Test' },
            { id: 'done',        label: '4. Done' },
          ].map(s => (
            <div key={s.id} className="flex-1 py-2 text-center text-xs font-medium border-b-2 transition-colors"
              style={{
                borderColor: step === s.id ? 'var(--rc-accent)' : 'transparent',
                color: step === s.id ? 'var(--rc-accent)' : 'var(--rc-text-3)',
              }}>{s.label}</div>
          ))}
        </div>

        {/* Body */}
        <div className="p-6">
          {step === 'credentials' && (
            <div className="space-y-4">
              {loading && (
                <div className="flex items-center gap-2" style={{ color: 'var(--rc-text-3)' }}>
                  <Loader className="w-4 h-4 animate-spin" /> Loading fields…
                </div>
              )}
              {loadErr && (
                <div className="p-3 rounded-lg border text-sm text-red-400 bg-red-900/20 border-red-800">
                  ⚠ {loadErr}
                </div>
              )}
              {!loading && !loadErr && fields.length === 0 && (
                <div className="p-3 rounded-lg border text-sm" style={{ color: 'var(--rc-text-2)', borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
                  No credential fields required for this connector.
                </div>
              )}
              {!loading && fields.map(field => (
                <div key={field.name}>
                  <label className="block text-sm font-medium mb-1" style={{ color: 'var(--rc-text-2)' }}>
                    {field.label}
                    {field.help && <span className="ml-2 font-normal opacity-60">{field.help}</span>}
                  </label>
                  <div className="relative">
                    <input
                      type={field.type === 'secret' && !showPwd[field.name] ? 'password' : 'text'}
                      placeholder={field.hint || field.placeholder || ''}
                      value={values[field.name] || ''}
                      onChange={e => setValues(prev => ({ ...prev, [field.name]: e.target.value }))}
                      className="w-full px-3 py-2 rounded-lg border text-sm pr-10"
                      style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}
                    />
                    {field.type === 'secret' && (
                      <button type="button"
                        onClick={() => setShowPwd(prev => ({ ...prev, [field.name]: !prev[field.name] }))}
                        className="absolute right-2 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100"
                        style={{ color: 'var(--rc-text-2)' }}>
                        {showPwd[field.name] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    )}
                  </div>
                </div>
              ))}
              {saveErr && (
                <div className="p-3 rounded-lg border text-sm text-red-400 bg-red-900/20 border-red-800">
                  ⚠ {saveErr}
                </div>
              )}
            </div>
          )}

          {step === 'review' && policyResult && (
            <div className="space-y-3">
              <div className={`p-3 rounded-lg border text-sm ${policyResult.policy_decision === 'allowed' ? 'text-green-400 bg-green-900/20 border-green-800' : 'text-red-400 bg-red-900/20 border-red-800'}`}>
                <p className="font-semibold">{policyResult.policy_decision === 'allowed' ? '✅ Policy approved' : '🚫 Blocked by policy'}</p>
                {policyResult.policy_name && <p className="text-xs mt-1 opacity-70">Policy: {policyResult.policy_name}</p>}
              </div>
              {policyResult.is_configured && (
                <>
                  <p className="text-xs" style={{ color: 'var(--rc-text-2)' }}>
                    Credential hint: <code className="px-1.5 py-0.5 rounded text-xs" style={{ background: 'var(--rc-bg-elevated)' }}>{policyResult.credential_hint}</code>
                  </p>
                  {approvedScopes.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--rc-text-3)' }}>Approved scopes</p>
                      <div className="flex flex-wrap gap-1">
                        {approvedScopes.map(s => <span key={s} className="text-xs px-2 py-0.5 rounded border text-green-400 bg-green-900/20 border-green-800">{s}</span>)}
                      </div>
                    </div>
                  )}
                  <p className="text-xs p-3 rounded-lg border" style={{ color: 'var(--rc-text-2)', borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
                    <strong style={{ color: 'var(--rc-text-1)' }}>Next:</strong> Test the connection to verify your credentials work. Low-risk connectors auto-approve on a successful test. Medium/high-risk connectors stay pending for admin review.
                  </p>
                </>
              )}
            </div>
          )}

          {step === 'test' && (
            <div className="flex flex-col items-center py-6 space-y-4">
              <ConnectorIcon type={connector.connector_type} name={connector.name} size={64} />
              <p className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Ready to test connection</p>
              <p className="text-sm text-center" style={{ color: 'var(--rc-text-2)' }}>
                Makes a real, read-only API call to verify your credentials.
              </p>
            </div>
          )}

          {step === 'done' && testResult && (
            <div className={`p-4 rounded-xl border space-y-3 ${
              !testResult.success
                ? 'bg-red-900/20 border-red-800'
                : ['credential', 'service'].includes(testResult.verification_level)
                  ? 'bg-green-900/20 border-green-800'
                  : 'bg-amber-900/20 border-amber-800'
            }`}>
              <div className="flex items-center gap-2">
                {testResult.success && ['credential', 'service'].includes(testResult.verification_level)
                  ? <CheckCircle className="w-5 h-5 text-green-400" />
                  : <AlertTriangle className={`w-5 h-5 ${testResult.success ? 'text-amber-400' : 'text-red-400'}`} />}
                <p className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                  {!testResult.success
                    ? 'Connection failed'
                    : ['credential', 'service'].includes(testResult.verification_level)
                      ? 'Connection verified'
                      : 'Endpoint reachable, trust not verified'}
                </p>
              </div>
              <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>{testResult.message}</p>
              {testResult.success && !['credential', 'service'].includes(testResult.verification_level) && (
                <p className="text-xs p-2 rounded border text-amber-300 bg-amber-950/30 border-amber-800">
                  Marcellus will not auto-approve this connector until a provider-specific credential check succeeds.
                </p>
              )}
              {!testResult.success && (
                <p className="text-xs p-2 rounded border" style={{ color: 'var(--rc-text-3)', borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
                  Credentials are saved but the test failed. Check your credentials and try again, or approve manually if you're confident they're correct.
                </p>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
          <button onClick={onClose} className="text-sm px-4 py-2 rounded-lg hover:opacity-70" style={{ color: 'var(--rc-text-2)' }}>
            Cancel
          </button>
          <div className="flex gap-2">
            {step === 'credentials' && (
              <button onClick={handleSave} disabled={saving || !hasValues}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-medium hover:bg-indigo-500 disabled:opacity-40 transition-colors">
                {saving ? <Loader className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                {saving ? 'Saving…' : 'Save & Continue'}
              </button>
            )}
            {step === 'review' && (
              <button onClick={() => setStep('test')}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-medium hover:bg-indigo-500 transition-colors">
                Next: Test <ChevronDown className="w-4 h-4 rotate-[-90deg]" />
              </button>
            )}
            {step === 'test' && (
              <button onClick={handleTest} disabled={testing}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-medium hover:bg-indigo-500 disabled:opacity-40 transition-colors">
                {testing ? <Loader className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                {testing ? 'Testing…' : 'Test connection'}
              </button>
            )}
            {step === 'done' && !testResult?.success && (
              <button onClick={() => setStep('credentials')}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border hover:opacity-80"
                style={{ color: 'var(--rc-text-2)', borderColor: 'var(--rc-border-2)' }}>
                Re-enter credentials
              </button>
            )}
            {step === 'done' && testResult?.success && (
              <button onClick={onClose}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-green-700 text-white text-sm font-medium hover:bg-green-600 transition-colors">
                <CheckCircle className="w-4 h-4" /> Done
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Connector card ────────────────────────────────────────────────────────────

function ConnectorCard({ connector, onUpdate, onConfigure }: {
  connector: any; onUpdate: (c: any) => void; onConfigure: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [saving, setSaving]     = useState(false);

  const status     = STATUS_STYLE[connector.status] ?? STATUS_STYLE.pending;
  const StatusIcon = status.icon;
  const riskStyle  = RISK_STYLE[connector.risk_level] ?? RISK_STYLE.medium;
  const tscore     = connector.trust_score ?? 70;

  const approvedScopes: string[]  = (() => { try { return JSON.parse(connector.approved_scopes  || '[]'); } catch { return []; } })();
  const requestedScopes: string[] = (() => { try { return JSON.parse(connector.requested_scopes || '[]'); } catch { return []; } })();

  const changeStatus = async (newStatus: string) => {
    setSaving(true);
    try {
      const updated = await apiFetch<any>(`/connectors/${connector.id}`, {
        method: 'PATCH', body: JSON.stringify({ status: newStatus }),
      });
      onUpdate(updated);
    } finally { setSaving(false); }
  };

  return (
    <div className="border rounded-xl overflow-hidden transition-all"
      style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>

      {/* Main row */}
      <div className="p-4 flex items-center gap-3">
        <ConnectorIcon type={connector.connector_type} name={connector.name} size={40} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-semibold text-sm" style={{ color: 'var(--rc-text-1)' }}>{connector.name}</h3>
            {connector.is_configured && (
              <span className="text-xs flex items-center gap-1 text-green-400">
                <Key className="w-3 h-3" /> Configured
              </span>
            )}
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-3)' }}>
            {connector.category} · {connector.connector_type}
          </p>
        </div>

        {/* Trust score */}
        <div className="hidden md:flex flex-col items-center flex-shrink-0">
          <span className={`text-sm font-bold tabular-nums ${trustColor(tscore)}`}>{tscore.toFixed(0)}</span>
          <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>trust</span>
        </div>

        {/* Access flags */}
        <div className="hidden lg:flex items-center gap-2 text-xs flex-shrink-0">
          <span style={{ color: connector.shell_access ? '#b91c1c' : 'var(--rc-text-3)' }}>
            {connector.shell_access ? '⚠ Shell' : '✓ No shell'}
          </span>
          <span style={{ color: connector.network_access ? '#a16207' : 'var(--rc-text-3)' }}>
            {connector.network_access ? '🌐 Net' : '✓ Local'}
          </span>
        </div>

        <span className={`hidden sm:inline-flex items-center px-2 py-0.5 rounded border text-xs font-medium flex-shrink-0 ${riskStyle}`}>
          {connector.risk_level}
        </span>

        <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border text-xs font-semibold flex-shrink-0 ${status.color}`}>
          <StatusIcon className="w-3 h-3" /> {status.label}
        </span>

        <button onClick={onConfigure}
          className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors hover:opacity-80"
          style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border-2)', color: 'var(--rc-text-2)' }}>
          <Settings className="w-3.5 h-3.5" />
          {connector.is_configured ? 'Reconfigure' : 'Connect'}
        </button>

        <button onClick={() => setExpanded(!expanded)}
          className="flex-shrink-0 p-1.5 rounded-lg hover:opacity-70"
          style={{ color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)' }}>
          {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t px-4 pb-4 pt-4 space-y-4"
          style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
          <p className="text-sm leading-relaxed" style={{ color: 'var(--rc-text-2)' }}>{connector.description}</p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--rc-text-3)' }}>
                Approved Scopes ({approvedScopes.length})
              </p>
              {approvedScopes.length === 0
                ? <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>None approved yet</p>
                : <div className="flex flex-wrap gap-1">
                    {approvedScopes.map(s => (
                      <span key={s} className="text-xs px-2 py-0.5 rounded border text-green-400 bg-green-900/20 border-green-800">{s}</span>
                    ))}
                  </div>
              }
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--rc-text-3)' }}>
                Requested Scopes ({requestedScopes.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {requestedScopes.map(s => {
                  const ok = approvedScopes.includes(s);
                  return (
                    <span key={s} className={`text-xs px-2 py-0.5 rounded border ${ok ? 'text-green-400 bg-green-900/20 border-green-800' : 'text-yellow-400 bg-yellow-900/20 border-yellow-800'}`}>
                      {s}{!ok && ' ⏳'}
                    </span>
                  );
                })}
              </div>
            </div>
          </div>

          {connector.endpoint && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--rc-text-3)' }}>Endpoint</p>
              <code className="text-xs px-2 py-1 rounded" style={{ background: 'var(--rc-bg-surface)', color: 'var(--rc-text-2)' }}>
                {connector.endpoint}
              </code>
            </div>
          )}

          {/* Admin actions */}
          <div className="flex flex-wrap gap-2 pt-2 border-t" style={{ borderColor: 'var(--rc-border)' }}>
            <p className="w-full text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--rc-text-3)' }}>Admin actions</p>
            {connector.status !== 'approved'   && <button onClick={() => changeStatus('approved')}   disabled={saving} className="px-3 py-1.5 text-xs font-medium rounded-lg border text-green-400 bg-green-900/20 border-green-800 hover:bg-green-900/40 disabled:opacity-50">✓ Approve</button>}
            {connector.status !== 'restricted' && <button onClick={() => changeStatus('restricted')} disabled={saving} className="px-3 py-1.5 text-xs font-medium rounded-lg border text-orange-400 bg-orange-900/20 border-orange-800 hover:bg-orange-900/40 disabled:opacity-50">⚠ Restrict</button>}
            {connector.status !== 'blocked'    && <button onClick={() => changeStatus('blocked')}    disabled={saving} className="px-3 py-1.5 text-xs font-medium rounded-lg border text-red-400 bg-red-900/20 border-red-800 hover:bg-red-900/40 disabled:opacity-50">🚫 Block</button>}
            {connector.status !== 'pending'    && <button onClick={() => changeStatus('pending')}    disabled={saving} className="px-3 py-1.5 text-xs font-medium rounded-lg border hover:opacity-80 disabled:opacity-50" style={{ color: 'var(--rc-text-2)', borderColor: 'var(--rc-border-2)' }}>Reset to Pending</button>}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

const CATEGORY_ORDER = [
  'Identity & Access', 'Security & SIEM', 'Endpoint & EDR',
  'Cloud & Infrastructure', 'Network & Zero Trust', 'Data & DLP',
  'AI / LLM', 'Dev & Collaboration', 'Threat Intel & Vuln',
  'Compliance & GRC', 'Other',
];

export default function ConnectorsPage() {
  const [connectors, setConnectors]   = useState<any[]>([]);
  const [loading, setLoading]         = useState(true);
  const [category, setCategory]       = useState('ALL');
  const [search, setSearch]           = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [configuring, setConfiguring] = useState<any | null>(null);

  useEffect(() => {
    apiFetch<any[]>('/connectors')
      .then(setConnectors)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleUpdate = (updated: any) =>
    setConnectors(prev => prev.map(c => c.id === updated.id ? { ...c, ...updated } : c));

  const categories = useMemo(() => {
    const inData = new Set(connectors.map(c => getCategory(c)));
    return ['ALL', ...CATEGORY_ORDER.filter(cat => inData.has(cat))];
  }, [connectors]);

  const shown = useMemo(() => {
    return connectors.filter(c => {
      if (category !== 'ALL' && getCategory(c) !== category) return false;
      if (statusFilter !== 'ALL' && c.status !== statusFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return c.name.toLowerCase().includes(q)
          || (c.connector_type || '').toLowerCase().includes(q)
          || (c.description || '').toLowerCase().includes(q)
          || (c.category || '').toLowerCase().includes(q);
      }
      return true;
    });
  }, [connectors, category, statusFilter, search]);

  const counts = {
    total:      connectors.length,
    approved:   connectors.filter(c => c.status === 'approved').length,
    pending:    connectors.filter(c => c.status === 'pending').length,
    restricted: connectors.filter(c => c.status === 'restricted').length,
    blocked:    connectors.filter(c => c.status === 'blocked').length,
    configured: connectors.filter(c => c.is_configured).length,
  };

  const avgTrust = connectors.length
    ? Math.round(connectors.reduce((s, c) => s + (c.trust_score ?? 70), 0) / connectors.length)
    : 0;

  // Preview grid for the empty state — shows a sample of logos
  const PREVIEW_BRANDS = [
    'okta','crowdstrike','splunk','aws_iam','azure_arm','gcp_iam',
    'cloudflare','datadog','github','slack','paloalto','sentinelone',
  ];

  return (
    <div className="space-y-6">
      {configuring && (
        <ConfigureModal
          connector={configuring}
          onClose={() => setConfiguring(null)}
          onUpdate={c => { handleUpdate(c); /* keep modal open — user still needs to test */ }}
        />
      )}

      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
          <Plug className="text-blue-400" /> Connector Marketplace
        </h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
          Every integration must be registered, scoped, and approved before use · {counts.total} connectors across {categories.length - 1} categories
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
        {[
          { label: 'Total',      count: counts.total,      color: 'text-blue-400 bg-blue-900/20 border-blue-800' },
          { label: 'Configured', count: counts.configured,  color: 'text-indigo-400 bg-indigo-900/20 border-indigo-800' },
          { label: 'Approved',   count: counts.approved,    color: 'text-green-400 bg-green-900/20 border-green-800' },
          { label: 'Pending',    count: counts.pending,     color: 'text-yellow-400 bg-yellow-900/20 border-yellow-800' },
          { label: 'Restricted', count: counts.restricted,  color: 'text-orange-400 bg-orange-900/20 border-orange-800' },
          { label: 'Avg Trust',  count: avgTrust,           color: `${trustColor(avgTrust)} bg-slate-800/30 border-slate-700` },
        ].map(({ label, count, color }) => (
          <div key={label} className={`rounded-xl border p-3 text-center ${color}`}>
            <p className="text-xl font-bold">{count}</p>
            <p className="text-xs mt-0.5 opacity-80">{label}</p>
          </div>
        ))}
      </div>

      {/* Zero Trust banner */}
      <div className="bg-amber-900/20 border border-amber-700/40 rounded-xl p-4 flex gap-3">
        <ShieldCheck className="w-5 h-5 flex-shrink-0 mt-0.5 text-amber-300" />
        <div>
          <p className="text-sm font-semibold text-amber-300">Zero Trust Connector Principle</p>
          <p className="text-sm mt-1 text-amber-200/70">
            No connector has shell or credential access by default. Credentials are encrypted at rest and never stored in plaintext.
            Trust Fabric policy is enforced on every configure action. Low-risk connectors auto-approve on test pass; medium/high-risk require admin review.
          </p>
        </div>
      </div>

      {!loading && connectors.length === 0 && (
        <div className="rounded-xl border border-slate-700/40 p-8 text-center space-y-6" style={{ background: 'var(--rc-bg-surface)' }}>
          {/* Logo preview grid */}
          <div>
            <p className="text-sm font-semibold mb-4" style={{ color: 'var(--rc-text-2)' }}>42 enterprise integrations available</p>
            <div className="flex flex-wrap justify-center gap-3">
              {PREVIEW_BRANDS.map(type => (
                <ConnectorIcon key={type} type={type} name={type} size={40} />
              ))}
            </div>
          </div>
          <div>
            <p className="font-semibold text-yellow-400 mb-2">No connectors registered yet</p>
            <p className="text-sm mb-4" style={{ color: 'var(--rc-text-2)' }}>Run the migration then seed 42 enterprise connectors:</p>
            <div className="space-y-2 text-left max-w-lg mx-auto">
              <code className="block px-4 py-2 rounded text-green-400 text-sm" style={{ background: 'var(--rc-bg-elevated)' }}>
                docker compose exec backend python migrate_connectors_v2.py
              </code>
              <code className="block px-4 py-2 rounded text-green-400 text-sm" style={{ background: 'var(--rc-bg-elevated)' }}>
                docker compose exec backend python seed_connectors.py
              </code>
            </div>
          </div>
        </div>
      )}

      {connectors.length > 0 && (
        <>
          {/* Search + status filter */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--rc-text-3)' }} />
              <input
                type="text"
                placeholder="Search connectors…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-2 rounded-lg border text-sm"
                style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}
              />
            </div>
            <div className="flex gap-2 flex-wrap">
              {['ALL', 'approved', 'pending', 'restricted', 'blocked'].map(s => (
                <button key={s} onClick={() => setStatusFilter(s)}
                  className="px-3 py-2 rounded-lg text-xs font-medium transition-colors capitalize"
                  style={{
                    background: statusFilter === s ? 'var(--rc-accent)' : 'var(--rc-bg-surface)',
                    color: statusFilter === s ? 'white' : 'var(--rc-text-2)',
                    border: '1px solid var(--rc-border)',
                  }}>
                  {s === 'ALL' ? `All (${counts.total})` : s}
                </button>
              ))}
            </div>
          </div>

          {/* Category tabs */}
          <div className="flex flex-wrap gap-1.5 border-b pb-3" style={{ borderColor: 'var(--rc-border)' }}>
            {categories.map(cat => {
              const count = cat === 'ALL' ? connectors.length : connectors.filter(c => getCategory(c) === cat).length;
              return (
                <button key={cat} onClick={() => setCategory(cat)}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
                  style={{
                    background: category === cat ? 'var(--rc-accent)' : 'var(--rc-bg-elevated)',
                    color: category === cat ? 'white' : 'var(--rc-text-2)',
                  }}>
                  {cat} <span className="opacity-60 ml-1">{count}</span>
                </button>
              );
            })}
          </div>

          {/* Results count */}
          {(search || statusFilter !== 'ALL') && (
            <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
              Showing {shown.length} of {connectors.length} connectors
              {search && <> matching "<strong>{search}</strong>"</>}
            </p>
          )}

          {/* Connector list */}
          <div className="space-y-2">
            {shown.length === 0
              ? <p className="text-sm text-center py-8" style={{ color: 'var(--rc-text-3)' }}>No connectors match your filters.</p>
              : shown.map(c => (
                  <ConnectorCard key={c.id} connector={c} onUpdate={handleUpdate} onConfigure={() => setConfiguring(c)} />
                ))
            }
          </div>
        </>
      )}
    </div>
  );
}
