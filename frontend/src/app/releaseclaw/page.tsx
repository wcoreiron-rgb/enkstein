'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileCheck,
  GitBranch,
  PlayCircle,
  RefreshCw,
  Rocket,
  Shield,
  TerminalSquare,
  XCircle,
} from 'lucide-react';
import StatCard from '@/components/StatCard';
import { capabilityName } from '@/lib/capability-names';
import {
  approveRelease,
  executeRelease,
  getReleaseAdapters,
  getReleaseDeployments,
  getReleaseStats,
  getReleaseTemplates,
  preflightRelease,
} from '@/lib/api';

type ReleaseForm = {
  requested_by: string;
  source: string;
  environment: string;
  application: string;
  change_ref: string;
  deployment_type: string;
  mode: string;
  template_id: string;
  model_profile: string;
  classification: string;
  execution_plan_text: string;
  rollback_plan_text: string;
};

const initialForm: ReleaseForm = {
  requested_by: 'portal-user',
  source: 'github_actions',
  environment: 'prod',
  application: 'customer-api',
  change_ref: 'main',
  deployment_type: 'container',
  mode: 'APPROVAL_REQUIRED',
  template_id: 'github-actions-prod',
  model_profile: '',
  classification: 'internal',
  execution_plan_text: 'workflow_dispatch customer-api production',
  rollback_plan_text: 'revert to previous successful deployment artifact',
};

const sources = [
  'github_actions', 'gitlab_ci', 'jenkins', 'azure_devops', 'argocd', 'terraform_cloud',
  'aws_cli', 'azure_cli', 'gcloud_cli', 'kubernetes', 'helm', 'docker', 'docker_compose',
  'bash', 'powershell', 'python', 'node', 'ansible', 'webhook', 'custom',
];

const deploymentTypes = ['kubernetes', 'terraform', 'serverless', 'vm', 'container', 'full_stack', 'ai_stack', 'database', 'network', 'custom_script'];
const modes = ['DRY_RUN', 'PLAN_ONLY', 'APPROVAL_REQUIRED', 'CANARY', 'BLUE_GREEN', 'ROLLING', 'EMERGENCY_PATCH', 'FULL_STACK_PROVISION', 'AI_STACK_DEPLOY', 'ROLLBACK_ONLY'];

function statusTone(status: string) {
  if (status === 'blocked') return 'text-red-400 bg-red-950/30 border-red-800';
  if (status === 'approval_required') return 'text-yellow-300 bg-yellow-950/30 border-yellow-800';
  if (status === 'approved' || status === 'executed' || status === 'allowed') return 'text-green-300 bg-green-950/30 border-green-800';
  return 'text-cyan-300 bg-cyan-950/30 border-cyan-800';
}

function ScorePill({ score }: { score: number }) {
  const tone = score >= 85 ? 'text-red-300 bg-red-950/30 border-red-800'
    : score >= 70 ? 'text-orange-300 bg-orange-950/30 border-orange-800'
      : score >= 45 ? 'text-yellow-300 bg-yellow-950/30 border-yellow-800'
        : 'text-green-300 bg-green-950/30 border-green-800';
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${tone}`}>{Math.round(score)}</span>;
}

function parsePlan(text: string) {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((command, index) => ({ step: index + 1, command }));
}

export default function ReleaseClawPage() {
  const [stats, setStats] = useState<any>(null);
  const [templates, setTemplates] = useState<any[]>([]);
  const [adapters, setAdapters] = useState<any[]>([]);
  const [deployments, setDeployments] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [form, setForm] = useState<ReleaseForm>(initialForm);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [statsData, templateData, adapterData, deploymentData] = await Promise.all([
        getReleaseStats(),
        getReleaseTemplates(),
        getReleaseAdapters(),
        getReleaseDeployments(),
      ]);
      setStats(statsData);
      setTemplates(templateData);
      setAdapters(adapterData);
      setDeployments(deploymentData);
      setSelected((current: any) => current || deploymentData?.[0] || null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load Release Governance');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const adapter = useMemo(
    () => adapters.find((item) => item.id === form.source),
    [adapters, form.source],
  );

  async function runPreflight() {
    setBusy(true);
    setError(null);
    try {
      const body: any = {
        requested_by: form.requested_by,
        source: form.source,
        environment: form.environment,
        application: form.application,
        change_ref: form.change_ref,
        deployment_type: form.deployment_type,
        mode: form.mode,
        template_id: form.template_id || undefined,
        model_profile: form.model_profile || undefined,
        classification: form.classification,
        execution_plan: parsePlan(form.execution_plan_text),
        rollback_plan: parsePlan(form.rollback_plan_text),
        artifacts: [
          { name: `${form.application}:${form.change_ref}`, type: 'release_ref', metadata: { source: form.source } },
        ],
      };
      const result = await preflightRelease(body);
      setSelected(result);
      await load();
    } catch (e: any) {
      setError(e?.data?.detail || e?.message || 'Preflight failed');
    } finally {
      setBusy(false);
    }
  }

  async function approveSelected() {
    if (!selected?.id) return;
    setBusy(true);
    try {
      const result = await approveRelease(selected.id, { note: 'Approved from Release Governance UI' });
      setSelected(result);
      await load();
    } catch (e: any) {
      setError(e?.data?.detail || e?.message || 'Approval failed');
    } finally {
      setBusy(false);
    }
  }

  async function executeSelected() {
    if (!selected?.id) return;
    setBusy(true);
    try {
      const result = await executeRelease(selected.id);
      setSelected(result);
      await load();
    } catch (e: any) {
      setError(e?.data?.detail || e?.message || 'Execution handoff failed');
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return <div className="h-64 flex items-center justify-center" style={{ color: 'var(--rc-text-2)' }}>Loading Release Governance…</div>;
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
            <Rocket className="w-7 h-7 text-cyan-400" />
            Release Governance
          </h1>
          <p className="mt-1 text-sm max-w-4xl" style={{ color: 'var(--rc-text-2)' }}>
            Zero Trust deployment preflight for CI/CD, GitOps, cloud SDKs, CLIs, scripts, full-stack releases, and AI service stacks.
          </p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-3 py-2 rounded-lg border text-sm" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {error && <div className="rounded-xl border border-red-800 bg-red-950/20 p-4 text-sm text-red-300">{String(error)}</div>}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Deployment Gates" value={stats?.total_deployments ?? 0} icon={Rocket} color="indigo" sub="preflights generated" />
        <StatCard label="Templates" value={stats?.templates ?? templates.length} icon={FileCheck} color="green" sub="release patterns" />
        <StatCard label="Adapters" value={stats?.adapters ?? adapters.length} icon={TerminalSquare} color="indigo" sub="CI/CD + script paths" />
        <StatCard label="Blocked" value={stats?.by_status?.blocked ?? 0} icon={XCircle} color={(stats?.by_status?.blocked ?? 0) > 0 ? 'red' : 'green'} sub="requires clean preflight" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <section className="xl:col-span-1 rounded-xl border p-5" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
          <h2 className="font-semibold flex items-center gap-2 mb-4" style={{ color: 'var(--rc-text-1)' }}>
            <Shield className="w-4 h-4 text-cyan-400" /> Deployment Preflight
          </h2>
          <div className="space-y-3">
            {[
              ['requested_by', 'Requested by'],
              ['application', 'Application'],
              ['environment', 'Environment'],
              ['change_ref', 'Change ref'],
              ['model_profile', 'Model profile'],
              ['classification', 'Classification'],
            ].map(([key, label]) => (
              <label key={key} className="block">
                <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{label}</span>
                <input
                  value={(form as any)[key]}
                  onChange={(e) => setForm({ ...form, [key]: e.target.value })}
                  className="mt-1 w-full rounded-lg border px-3 py-2 text-sm outline-none"
                  style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}
                />
              </label>
            ))}

            <div className="grid grid-cols-2 gap-3">
              <label>
                <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Source</span>
                <select value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} className="mt-1 w-full rounded-lg border px-3 py-2 text-sm" style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
                  {sources.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <label>
                <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Type</span>
                <select value={form.deployment_type} onChange={(e) => setForm({ ...form, deployment_type: e.target.value })} className="mt-1 w-full rounded-lg border px-3 py-2 text-sm" style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
                  {deploymentTypes.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <label>
                <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Mode</span>
                <select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })} className="mt-1 w-full rounded-lg border px-3 py-2 text-sm" style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
                  {modes.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <label>
                <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Template</span>
                <select value={form.template_id} onChange={(e) => setForm({ ...form, template_id: e.target.value })} className="mt-1 w-full rounded-lg border px-3 py-2 text-sm" style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
                  <option value="">Auto</option>
                  {templates.map((t) => <option key={t.id} value={t.id}>{t.id}</option>)}
                </select>
              </label>
            </div>

            <label className="block">
              <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Execution plan</span>
              <textarea value={form.execution_plan_text} onChange={(e) => setForm({ ...form, execution_plan_text: e.target.value })} rows={3} className="mt-1 w-full rounded-lg border px-3 py-2 text-sm outline-none" style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }} />
            </label>
            <label className="block">
              <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Rollback plan</span>
              <textarea value={form.rollback_plan_text} onChange={(e) => setForm({ ...form, rollback_plan_text: e.target.value })} rows={2} className="mt-1 w-full rounded-lg border px-3 py-2 text-sm outline-none" style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }} />
            </label>

            <div className="rounded-lg border p-3 text-xs" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-elevated)' }}>
              Adapter: <span className="font-medium" style={{ color: 'var(--rc-text-1)' }}>{adapter?.label || form.source}</span>
              <br />
              Channel: {adapter?.execution_channel || 'exec_channel'}
            </div>

            <button disabled={busy} onClick={runPreflight} className="w-full flex items-center justify-center gap-2 rounded-lg bg-regent-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-regent-500 disabled:opacity-50">
              <PlayCircle className="w-4 h-4" /> Run Governed Preflight
            </button>
          </div>
        </section>

        <section className="xl:col-span-2 space-y-5">
          <div className="rounded-xl border p-5" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
                  <FileCheck className="w-4 h-4 text-green-400" /> Latest Gate Result
                </h2>
                <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>
                  Direct execution is disabled. Approved releases hand off to governed CI/CD or ExecChannels.
                </p>
              </div>
              {selected && <span className={`rounded-full border px-3 py-1 text-xs font-medium ${statusTone(selected.status)}`}>{selected.status}</span>}
            </div>

            {!selected ? (
              <div className="mt-6 rounded-xl border border-dashed p-8 text-center" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>
                Run a deployment preflight to create a release gate.
              </div>
            ) : (
              <div className="mt-5 space-y-5">
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                  <div className="rounded-lg border p-3" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
                    <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Risk</p>
                    <ScorePill score={selected.risk_score} />
                  </div>
                  <div className="rounded-lg border p-3" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
                    <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Source</p>
                    <p className="font-medium text-sm" style={{ color: 'var(--rc-text-1)' }}>{selected.source_label}</p>
                  </div>
                  <div className="rounded-lg border p-3" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
                    <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Environment</p>
                    <p className="font-medium text-sm" style={{ color: 'var(--rc-text-1)' }}>{selected.environment}</p>
                  </div>
                  <div className="rounded-lg border p-3" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-elevated)' }}>
                    <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Evidence hash</p>
                    <p className="font-mono text-xs truncate" style={{ color: 'var(--rc-text-1)' }}>{selected.evidence?.chain_of_custody?.bundle_hash || 'pending'}</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="rounded-lg border p-4" style={{ borderColor: 'var(--rc-border)' }}>
                    <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
                      <AlertTriangle className="w-4 h-4 text-yellow-400" /> Blockers / Warnings
                    </h3>
                    <div className="mt-3 space-y-2 text-sm" style={{ color: 'var(--rc-text-2)' }}>
                      {([...selected.blockers, ...selected.warnings].length ? [...selected.blockers, ...selected.warnings] : ['No blocking release issues detected.']).map((item: string) => (
                        <div key={item} className="rounded-md px-3 py-2" style={{ background: 'var(--rc-bg-elevated)' }}>{item}</div>
                      ))}
                    </div>
                  </div>
                  <div className="rounded-lg border p-4" style={{ borderColor: 'var(--rc-border)' }}>
                    <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
                      <CheckCircle2 className="w-4 h-4 text-green-400" /> Required Controls
                    </h3>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {selected.required_controls.map((control: string) => (
                        <span key={control} className="rounded-full px-2.5 py-1 text-xs" style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-2)' }}>{control}</span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="rounded-lg border p-4" style={{ borderColor: 'var(--rc-border)' }}>
                  <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
                    <GitBranch className="w-4 h-4 text-cyan-400" /> Capability Preflight Coverage
                  </h3>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {selected.required_claws.map((claw: string) => (
                      <span key={claw} className="rounded-full border px-2.5 py-1 text-xs" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}>{capabilityName(claw)}</span>
                    ))}
                  </div>
                </div>

                <div className="flex flex-wrap gap-3">
                  <button disabled={busy || selected.status === 'blocked' || selected.status === 'executed'} onClick={approveSelected} className="flex items-center gap-2 rounded-lg border px-4 py-2 text-sm disabled:opacity-50" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-1)' }}>
                    <Shield className="w-4 h-4" /> Approve
                  </button>
                  <button disabled={busy || selected.status === 'blocked' || selected.status === 'executed'} onClick={executeSelected} className="flex items-center gap-2 rounded-lg bg-regent-600 px-4 py-2 text-sm font-medium text-white hover:bg-regent-500 disabled:opacity-50">
                    <PlayCircle className="w-4 h-4" /> Execute Handoff
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="rounded-xl border overflow-hidden" style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}>
            <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--rc-border)' }}>
              <h2 className="font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
                <Clock className="w-4 h-4 text-cyan-400" /> Recent Deployment Gates
              </h2>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--rc-border)' }}>
              {deployments.length === 0 ? (
                <div className="p-6 text-sm" style={{ color: 'var(--rc-text-2)' }}>No preflights yet.</div>
              ) : deployments.map((dep) => (
                <button key={dep.id} onClick={() => setSelected(dep)} className="w-full px-5 py-3 text-left hover:opacity-80 grid grid-cols-1 md:grid-cols-[1.5fr_1fr_1fr_.8fr] gap-2 items-center">
                  <div>
                    <p className="font-medium text-sm" style={{ color: 'var(--rc-text-1)' }}>{dep.application}</p>
                    <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{dep.id}</p>
                  </div>
                  <span className="text-xs" style={{ color: 'var(--rc-text-2)' }}>{dep.source_label}</span>
                  <span className={`justify-self-start rounded-full border px-2 py-1 text-xs ${statusTone(dep.status)}`}>{dep.status}</span>
                  <ScorePill score={dep.risk_score} />
                </button>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
