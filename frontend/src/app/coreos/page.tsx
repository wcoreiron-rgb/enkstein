'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  Cpu, Plug, Shield, Zap, AlertTriangle, CheckCircle,
  Clock, RefreshCw, Bell, Activity, Database, Lock,
  TrendingUp, ChevronRight, Radio,
} from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import { getDashboard, getConnectors, getPolicies, getEvents, getFindingsStats } from '@/lib/api';
import { capabilityName } from '@/lib/capability-names';

// ─── Platform capability modules ─────────────────────────────────────────────
// `claw` stays the persisted capability id (compatibility). Visible names are
// resolved via capabilityName(); only CoreOS carries an explicit displayName.

const MODULES: { claw: string; phase: number; desc: string; displayName?: string }[] = [
  // CoreOS foundations
  { claw: 'coreos',         displayName: 'CoreOS', phase: 1, desc: 'Platform foundation — identity registry, policy engine, telemetry bus, finding pipeline' },
  // Phase 1 — AI & Identity
  { claw: 'arcclaw',        phase: 1, desc: 'AI Security — prompt inspection, sensitive pattern detection, LLM governance' },
  { claw: 'identityclaw',   phase: 1, desc: 'Identity Security — governance of human and non-human identities, orphan detection' },
  // Phase 2 — Infrastructure
  { claw: 'cloudclaw',      phase: 2, desc: 'Cloud Security — AWS/Azure/GCP asset discovery, misconfiguration detection' },
  { claw: 'exposureclaw',   phase: 2, desc: 'Vulnerability Management — NVD CVE scanning, EPSS scoring, CISA KEV correlation' },
  { claw: 'threatclaw',     phase: 2, desc: 'Threat Intelligence — CISA KEV, MITRE ATT&CK, IOC correlation' },
  { claw: 'endpointclaw',   phase: 2, desc: 'Endpoint Security — CrowdStrike, Defender, SentinelOne detection ingestion' },
  { claw: 'accessclaw',     phase: 2, desc: 'Access Security — Okta, Entra ID risky user and MFA gap detection' },
  { claw: 'logclaw',        phase: 2, desc: 'Log Intelligence — Splunk SIEM notable event correlation and alerting' },
  { claw: 'netclaw',        phase: 2, desc: 'Network Security — lateral movement, traffic anomaly, firewall gap detection' },
  { claw: 'dataclaw',       phase: 2, desc: 'Data Security — sensitive data exposure, DLP policy enforcement' },
  { claw: 'appclaw',        phase: 2, desc: 'Application Security — SAST/DAST findings, dependency vulnerabilities' },
  { claw: 'saasclaw',       phase: 2, desc: 'SaaS Security — misconfigured SaaS apps, shadow IT, OAuth token sprawl' },
  // Phase 3 — Governance & Detection
  { claw: 'configclaw',     phase: 3, desc: 'Configuration Management — CIS benchmark gaps, hardening drift' },
  { claw: 'complianceclaw', phase: 3, desc: 'Compliance — SOC 2, NIST, ISO 27001 control gap tracking' },
  { claw: 'privacyclaw',    phase: 3, desc: 'Privacy — GDPR/CCPA data subject request tracking, PII exposure' },
  { claw: 'vendorclaw',     phase: 3, desc: 'Third-Party Risk — vendor assessment, supply chain security scoring' },
  { claw: 'userclaw',       phase: 3, desc: 'User Behaviour Analytics — anomalous access patterns, privilege escalation' },
  { claw: 'insiderclaw',    phase: 3, desc: 'Insider Threat — data staging, mass download, off-hours access detection' },
  { claw: 'automationclaw', phase: 3, desc: 'Automation Security — runbook governance, script/pipeline risk scoring' },
  { claw: 'attackpathclaw', phase: 3, desc: 'Attack Path Analysis — blast radius mapping, lateral movement chain detection' },
  { claw: 'devclaw',        phase: 3, desc: 'Dev Security — secrets in code, CI/CD misconfiguration, SBOM tracking' },
  { claw: 'intelclaw',      phase: 3, desc: 'Cyber Intelligence — dark web monitoring, threat actor TTPs, brand exposure' },
  { claw: 'recoveryclaw',   phase: 3, desc: 'Recovery & Resilience — backup validation, IR playbook execution tracking' },
];

// ─── Shared Services wired to the finding pipeline ───────────────────────────

const SHARED_SERVICES = [
  {
    name: 'Finding Pipeline',
    icon: Database,
    color: 'text-cyan-400',
    desc: 'Central upsert/dedup engine. All Capability Node scan results flow through here, with deduplication, lifecycle tracking, policy evaluation, and alerting.',
    status: 'active',
  },
  {
    name: 'Policy Evaluator',
    icon: Shield,
    color: 'text-purple-400',
    desc: 'Converts every Finding into a context dict and runs it through the Trust Fabric policy engine. Violations emit Events and can block/flag actions.',
    status: 'active',
  },
  {
    name: 'Alert Router',
    icon: Bell,
    color: 'text-yellow-400',
    desc: 'Routes critical findings and workflow notifications to configured channels (Slack, PagerDuty, Teams). Queries approved connectors from the registry at send time.',
    status: 'active',
  },
  {
    name: 'Auto-Scanner',
    icon: RefreshCw,
    color: 'text-green-400',
    desc: 'Fires Capability Node scans automatically when connectors are configured or tested. The scheduler runs priority capabilities first and secondary capabilities in parallel.',
    status: 'active',
  },
  {
    name: 'Workflow Runner',
    icon: Zap,
    color: 'text-orange-400',
    desc: 'Sequential multi-step orchestration engine. Supports agent_run, policy_check, condition, wait, and notify steps with full context passing between steps.',
    status: 'active',
  },
  {
    name: 'Security Copilot',
    icon: Radio,
    color: 'text-pink-400',
    desc: 'AI security analyst backed by real findings, live events, and connector context. It can send alerts, query the event bus, and explain risk posture across every capability.',
    status: 'active',
  },
];

// ─── Alert channel types detected from connector_type ─────────────────────────

const ALERT_CONNECTOR_TYPES = ['slack', 'pagerduty', 'teams', 'microsoft_teams'];

// ─── Component ────────────────────────────────────────────────────────────────

export default function CoreOSPage() {
  const [dashboard, setDashboard]     = useState<any>(null);
  const [connectors, setConnectors]   = useState<any[]>([]);
  const [policies, setPolicies]       = useState<any[]>([]);
  const [events, setEvents]           = useState<any[]>([]);
  const [findingsStats, setFindingsStats] = useState<any>(null);
  const [loading, setLoading]         = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => { setMounted(true); }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [dash, conns, pols, evts, findingStats] = await Promise.all([
        getDashboard().catch(() => null),
        getConnectors().catch(() => []),
        getPolicies().catch(() => []),
        getEvents({ limit: '8', sort: 'desc' }).catch(() => []),
        getFindingsStats().catch(() => null),
      ]);
      setDashboard(dash);
      setConnectors(conns ?? []);
      setPolicies(pols ?? []);
      setEvents(evts ?? []);
      setFindingsStats(findingStats);
      setLastRefresh(new Date());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Derived stats
  const approvedConnectorStatuses = new Set(['approved', 'active']);
  const activeConnectors   = connectors.filter(c => approvedConnectorStatuses.has(String(c.status).toLowerCase())).length;
  const pendingConnectors  = connectors.filter(c => c.status === 'pending').length;
  const alertConnectors    = connectors.filter(c => (
    ALERT_CONNECTOR_TYPES.includes(c.connector_type?.toLowerCase())
    && approvedConnectorStatuses.has(String(c.status).toLowerCase())
  ));
  const activePolicies     = policies.filter(p => p.is_active).length;
  const totalFindings      = findingsStats?.open_count
    ?? dashboard?.total_findings
    ?? dashboard?.high_risk_events
    ?? '—';
  const blockedActions     = dashboard?.blocked_actions_24h ?? '—';
  const riskScore          = dashboard?.platform_risk_score ?? null;
  const pendingApprovals   = dashboard?.pending_approvals ?? '—';
  const clawCount          = MODULES.filter(m => m.claw !== 'coreos').length;

  const riskColor = riskScore === null ? 'text-gray-400'
    : riskScore >= 75 ? 'text-red-400'
    : riskScore >= 50 ? 'text-orange-400'
    : riskScore >= 25 ? 'text-yellow-400'
    : 'text-green-400';

  return (
    <div className="space-y-8">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Cpu className="text-cyan-400" /> CoreOS
          </h1>
          <p className="text-gray-400 mt-1">
            Platform foundation — shared intelligence layer powering every Capability Node
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm text-gray-300 hover:bg-gray-700 disabled:opacity-50 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Platform Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Platform Risk Score"
          value={riskScore !== null ? `${riskScore.toFixed(0)}` : '—'}
          sub={riskScore !== null ? (riskScore >= 75 ? 'Critical' : riskScore >= 50 ? 'High' : riskScore >= 25 ? 'Medium' : 'Low') : 'No data'}
          icon={<TrendingUp className={`w-5 h-5 ${riskColor}`} />}
          valueClass={riskColor}
        />
        <StatCard
          label="Total Findings"
          value={String(totalFindings)}
          sub="across all capabilities"
          icon={<AlertTriangle className="w-5 h-5 text-orange-400" />}
          valueClass="text-orange-400"
        />
        <StatCard
          label="Blocked Actions (24h)"
          value={String(blockedActions)}
          sub="policy enforced"
          icon={<Lock className="w-5 h-5 text-red-400" />}
          valueClass="text-red-400"
        />
        <StatCard
          label="Pending Approvals"
          value={String(pendingApprovals)}
          sub="awaiting review"
          icon={<Clock className="w-5 h-5 text-yellow-400" />}
          valueClass="text-yellow-400"
        />
      </div>

      {/* Secondary stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Active Connectors"
          value={String(activeConnectors)}
          sub={pendingConnectors > 0 ? `${pendingConnectors} pending approval` : 'all approved'}
          icon={<Plug className="w-5 h-5 text-cyan-400" />}
          valueClass="text-cyan-400"
        />
        <StatCard
          label="Active Policies"
          value={String(activePolicies)}
          sub={`${policies.length} total defined`}
          icon={<Shield className="w-5 h-5 text-purple-400" />}
          valueClass="text-purple-400"
        />
        <StatCard
          label="Alert Channels"
          value={String(alertConnectors.length)}
          sub={alertConnectors.length > 0 ? alertConnectors.map(c => c.connector_type).join(', ') : 'none configured'}
          icon={<Bell className="w-5 h-5 text-yellow-400" />}
          valueClass="text-yellow-400"
        />
        <StatCard
          label="Registered Modules"
          value={String(MODULES.length)}
          sub={`CoreOS + ${clawCount} capability nodes`}
          icon={<Activity className="w-5 h-5 text-green-400" />}
          valueClass="text-green-400"
        />
      </div>

      {/* Module Registry */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" /> Module Registry
          </h2>
          <span className="text-xs text-gray-500">CoreOS + {clawCount} capability nodes registered</span>
        </div>

        {/* Phase 1 */}
        <PhaseGroup phase={1} label="Phase 1 — Foundation" modules={MODULES.filter(m => m.phase === 1)} />
        <PhaseGroup phase={2} label="Phase 2 — Infrastructure" modules={MODULES.filter(m => m.phase === 2)} />
        <PhaseGroup phase={3} label="Phase 3 — Governance & Detection" modules={MODULES.filter(m => m.phase === 3)} />
      </div>

      {/* Shared Services */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Zap className="w-4 h-4 text-orange-400" /> Shared Services
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">Cross-cutting services wired to every Capability Node endpoint</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-gray-800">
          {SHARED_SERVICES.map(svc => {
            const Icon = svc.icon;
            return (
              <div key={svc.name} className="bg-gray-900 px-6 py-4 flex gap-4">
                <div className="flex-shrink-0 mt-0.5">
                  <Icon className={`w-5 h-5 ${svc.color}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-white text-sm font-medium">{svc.name}</p>
                    <span className="w-1.5 h-1.5 rounded-full bg-green-400 flex-shrink-0" />
                    <span className="text-xs text-green-400">active</span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">{svc.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Connector Registry */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Plug className="w-4 h-4 text-gray-400" /> Connector Registry
          </h2>
          <div className="flex items-center gap-3 text-xs text-gray-500">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-400 inline-block" />{activeConnectors} active</span>
            {pendingConnectors > 0 && <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-400 inline-block" />{pendingConnectors} pending</span>}
          </div>
        </div>
        {connectors.length === 0 ? (
          <div className="px-6 py-8 text-center">
            <Plug className="w-8 h-8 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-500 text-sm">No connectors registered yet.</p>
            <p className="text-gray-600 text-xs mt-1">Every integration must be registered here before use. Plugging in a connector auto-triggers a scan sweep.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-6 py-3 text-left">Name</th>
                <th className="px-6 py-3 text-left">Type</th>
                <th className="px-6 py-3 text-left">Status</th>
                <th className="px-6 py-3 text-left">Risk</th>
                <th className="px-6 py-3 text-left">Shell</th>
                <th className="px-6 py-3 text-left">Network</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {connectors.map((c: any) => (
                <tr key={c.id} className="hover:bg-gray-800/50">
                  <td className="px-6 py-3 text-white">{c.name}</td>
                  <td className="px-6 py-3 text-gray-400">{c.connector_type}</td>
                  <td className="px-6 py-3"><RiskBadge value={c.status} /></td>
                  <td className="px-6 py-3"><RiskBadge value={c.risk_level} /></td>
                  <td className="px-6 py-3">
                    <span className={c.shell_access ? 'text-red-400' : 'text-green-400'}>
                      {c.shell_access ? '⚠ Yes' : 'No'}
                    </span>
                  </td>
                  <td className="px-6 py-3">
                    <span className={c.network_access ? 'text-yellow-400' : 'text-green-400'}>
                      {c.network_access ? 'Yes' : 'No'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>

      {/* Policy Engine + Alert Router side-by-side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

        {/* Policy Engine */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-purple-400" /> Policy Engine
            </h2>
          </div>
          <div className="px-6 py-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Active policies</span>
              <span className="text-white font-semibold">{activePolicies}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Total defined</span>
              <span className="text-white font-semibold">{policies.length}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Evaluation mode</span>
              <span className="text-xs bg-purple-900/40 text-purple-400 border border-purple-800 rounded px-2 py-0.5">enforce</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Trust Fabric</span>
              <span className="flex items-center gap-1 text-xs text-green-400">
                <CheckCircle className="w-3.5 h-3.5" /> wired to all capabilities
              </span>
            </div>
            {policies.slice(0, 3).map((p: any) => (
              <div key={p.id} className="flex items-center gap-2 pt-1 border-t border-gray-800">
                <ChevronRight className="w-3 h-3 text-gray-600 flex-shrink-0" />
                <span className="text-xs text-gray-400 truncate">{p.name}</span>
                <span className={`ml-auto text-xs ${p.is_active ? 'text-green-400' : 'text-gray-600'}`}>
                  {p.is_active ? 'on' : 'off'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Alert Router */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <Bell className="w-4 h-4 text-yellow-400" /> Alert Router
            </h2>
          </div>
          <div className="px-6 py-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Configured channels</span>
              <span className="text-white font-semibold">{alertConnectors.length}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Auto-routing</span>
              <span className="flex items-center gap-1 text-xs text-green-400">
                <CheckCircle className="w-3.5 h-3.5" /> critical + high findings
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Workflow notify steps</span>
              <span className="flex items-center gap-1 text-xs text-green-400">
                <CheckCircle className="w-3.5 h-3.5" /> wired
              </span>
            </div>
            {alertConnectors.length === 0 ? (
              <div className="pt-2 border-t border-gray-800">
                <p className="text-xs text-gray-600">No alert channels configured. Add a Slack, PagerDuty, or Teams connector to enable alert routing.</p>
              </div>
            ) : (
              alertConnectors.map((c: any) => (
                <div key={c.id} className="flex items-center gap-2 pt-1 border-t border-gray-800">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 flex-shrink-0" />
                  <span className="text-xs text-gray-300">{c.name}</span>
                  <RiskBadge value={c.connector_type} />
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Auto-Scanner */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <RefreshCw className="w-4 h-4 text-green-400" /> Auto-Scanner
          </h2>
        </div>
        <div className="px-6 py-5 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Sweep Schedule</p>
            <p className="text-white text-sm font-medium">Every 6 hours</p>
            <p className="text-xs text-gray-500 mt-0.5">Background scheduler loop on startup</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Trigger Events</p>
            <ul className="space-y-1">
              <li className="text-xs text-gray-400 flex items-center gap-1.5"><CheckCircle className="w-3.5 h-3.5 text-green-400" /> Connector configured</li>
              <li className="text-xs text-gray-400 flex items-center gap-1.5"><CheckCircle className="w-3.5 h-3.5 text-green-400" /> Connector tested &amp; approved</li>
              <li className="text-xs text-gray-400 flex items-center gap-1.5"><CheckCircle className="w-3.5 h-3.5 text-green-400" /> Manual sweep via API</li>
            </ul>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Execution Order</p>
            <p className="text-xs text-gray-400">Priority capabilities first: cloud, exposure, threat, endpoint, access, telemetry, and network</p>
            <p className="text-xs text-gray-500 mt-1">Secondary capabilities execute in bounded parallel groups</p>
          </div>
        </div>
      </div>

      {/* Recent Platform Events */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" /> Recent Platform Events
          </h2>
          <span className="text-xs text-gray-500">
            {mounted && lastRefresh ? `last refreshed ${lastRefresh.toLocaleTimeString()}` : 'loading…'}
          </span>
        </div>
        {events.length === 0 ? (
          <p className="px-6 py-6 text-gray-500 text-sm">No events yet — events appear here as capabilities scan and policies evaluate.</p>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-6 py-3 text-left">Time</th>
                <th className="px-6 py-3 text-left">Module</th>
                <th className="px-6 py-3 text-left">Action</th>
                <th className="px-6 py-3 text-left">Target</th>
                <th className="px-6 py-3 text-left">Severity</th>
                <th className="px-6 py-3 text-left">Outcome</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {events.map((e: any) => (
                <tr key={e.id} className="hover:bg-gray-800/50">
                  <td className="px-6 py-3 text-gray-500 text-xs whitespace-nowrap">
                    {mounted && e.timestamp ? new Date(e.timestamp).toLocaleString() : e.timestamp ? '…' : '—'}
                  </td>
                  <td className="px-6 py-3 text-gray-400 text-xs">{e.source_module ?? e.module ?? '—'}</td>
                  <td className="px-6 py-3 text-white text-xs">{e.action ?? '—'}</td>
                  <td className="px-6 py-3 text-gray-400 text-xs max-w-[200px] truncate">{e.target ?? e.description ?? '—'}</td>
                  <td className="px-6 py-3"><RiskBadge value={e.severity ?? 'info'} /></td>
                  <td className="px-6 py-3"><RiskBadge value={e.outcome ?? 'allowed'} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>

    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub, icon, valueClass }: {
  label: string; value: string; sub: string; icon: React.ReactNode; valueClass: string;
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
      <div className="flex items-start justify-between mb-2">
        <p className="text-xs text-gray-500">{label}</p>
        {icon}
      </div>
      <p className={`text-2xl font-bold ${valueClass}`}>{value}</p>
      <p className="text-xs text-gray-500 mt-1">{sub}</p>
    </div>
  );
}

function PhaseGroup({ phase, label, modules }: { phase: number; label: string; modules: typeof MODULES }) {
  const phaseColors: Record<number, string> = {
    1: 'text-cyan-400',
    2: 'text-green-400',
    3: 'text-purple-400',
  };
  return (
    <>
      <div className="px-6 py-2 bg-gray-800/40 border-b border-gray-800">
        <span className={`text-xs font-semibold uppercase tracking-wide ${phaseColors[phase] ?? 'text-gray-400'}`}>{label}</span>
      </div>
      {modules.map(m => (
        <div key={m.claw} className="px-6 py-3.5 flex items-center gap-4 border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors">
          <span className="w-2 h-2 rounded-full bg-green-400 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-white text-sm font-medium">
              {m.displayName ?? capabilityName(m.claw)}
              <span className="text-xs text-gray-500 ml-2 font-normal">{m.claw === 'coreos' ? 'Cortex' : 'Capability Node'}</span>
            </p>
            <p className="text-xs text-gray-400 mt-0.5 truncate">{m.desc}</p>
          </div>
          <span className="text-xs text-green-400 flex-shrink-0">active</span>
        </div>
      ))}
    </>
  );
}
