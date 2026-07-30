'use client';
import { useCallback, useEffect, useState } from 'react';
import {
  Shield, RefreshCw, CheckCircle2, XCircle, HelpCircle, Info,
  Plug, Download, Wrench, AlertTriangle, Loader2, Sparkles,
} from 'lucide-react';
import {
  getControlSummary, getControlCoverage, getControlEvaluation,
  getControlCollectors, getProwlerStatus, getControlRemediationProposals,
  syncProwlerCatalog, syncNistCatalog, attachControlEvaluators,
  getAssessmentSummary,
} from '@/lib/api';
import SafeMarkdown from '@/components/markdown/SafeMarkdown';

const surface = { background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' };
const elevated = { background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' };
const text1 = { color: 'var(--rc-text-1)' };
const text2 = { color: 'var(--rc-text-2)' };
const text3 = { color: 'var(--rc-text-3)' };

const PILLAR_COLOR: Record<string, string> = {
  identity: 'bg-indigo-500',
  devices: 'bg-cyan-500',
  networks: 'bg-emerald-500',
  applications: 'bg-amber-500',
  data: 'bg-rose-500',
  visibility: 'bg-sky-500',
  automation: 'bg-violet-500',
  governance: 'bg-slate-400',
};

const VERDICT_META: Record<string, { label: string; cls: string; Icon: typeof CheckCircle2 }> = {
  pass: { label: 'Pass', cls: 'text-emerald-500', Icon: CheckCircle2 },
  fail: { label: 'Fail', cls: 'text-rose-500', Icon: XCircle },
  not_assessed: { label: 'Not assessed', cls: 'text-slate-400', Icon: HelpCircle },
  recommendation: { label: 'Recommendation', cls: 'text-amber-500', Icon: Info },
  error: { label: 'Error', cls: 'text-rose-600', Icon: AlertTriangle },
};

function labelOf(claw: string) {
  return claw.replace(/claw$/, '').replace(/^./, (c) => c.toUpperCase());
}

export default function ZeroTrustPage() {
  const [summary, setSummary] = useState<any>(null);
  const [coverage, setCoverage] = useState<any>(null);
  const [collectors, setCollectors] = useState<any>(null);
  const [prowler, setProwler] = useState<any>(null);
  const [evaluation, setEvaluation] = useState<any>(null);
  const [proposals, setProposals] = useState<any>(null);
  const [advisory, setAdvisory] = useState<any>(null);
  const [advisoryBusy, setAdvisoryBusy] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, c, col, p] = await Promise.all([
        getControlSummary(), getControlCoverage(),
        getControlCollectors(), getProwlerStatus(),
      ]);
      setSummary(s); setCoverage(c); setCollectors(col); setProwler(p);
    } catch (e: any) {
      setError(e?.message ?? 'Could not load the control catalog.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const openArm = useCallback(async (claw: string) => {
    setSelected(claw);
    setEvaluation(null);
    setProposals(null);
    // The narration belongs to the assessment being replaced, so it is cleared
    // rather than left on screen describing a different node.
    setAdvisory(null);
    try {
      const [ev, pr] = await Promise.all([
        getControlEvaluation(claw), getControlRemediationProposals(claw),
      ]);
      setEvaluation(ev); setProposals(pr);
    } catch (e: any) {
      setError(e?.message ?? 'Could not evaluate this Security Arm.');
    }
  }, []);

  const explain = useCallback(async (claw: string) => {
    setAdvisoryBusy(true);
    setAdvisory(null);
    try {
      setAdvisory(await getAssessmentSummary(claw));
    } catch (e: any) {
      // A narration failure must not read as an assessment failure.
      setAdvisory({
        available: false,
        reason: 'error',
        detail: e?.message ?? 'The summary could not be generated. The verdicts above are unaffected.',
      });
    } finally {
      setAdvisoryBusy(false);
    }
  }, []);

  const run = useCallback(async (key: string, fn: () => Promise<any>) => {
    setBusy(key);
    setError(null);
    try {
      await fn();
      await load();
      if (selected) await openArm(selected);
    } catch (e: any) {
      setError(e?.message ?? 'That action did not complete.');
    } finally {
      setBusy(null);
    }
  }, [load, openArm, selected]);

  const pillars = summary?.by_pillar ?? [];
  const maxPillar = Math.max(1, ...pillars.map((p: any) => p.controls ?? 0));

  return (
    <div className="p-6 space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2" style={text1}>
            <Shield className="h-5 w-5 text-indigo-500" />
            Zero Trust Control Coverage
          </h1>
          <p className="text-sm mt-1 max-w-2xl" style={text2}>
            CISA pillars, per-Arm control profiles, and the evidence collectors behind them.
            A control only passes when a collector ran and returned no violation.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ToolbarButton
            onClick={() => run('nist', syncNistCatalog)}
            disabled={busy !== null}
            busy={busy === 'nist'}
            Icon={Download}
            label="Sync NIST"
          />
          <ToolbarButton
            onClick={() => run('prowler', syncProwlerCatalog)}
            disabled={busy !== null || !prowler?.installed}
            busy={busy === 'prowler'}
            Icon={Download}
            label="Sync Prowler"
            title={prowler?.installed ? 'Import the Prowler check catalog' : 'Prowler is not installed on this host'}
          />
          <ToolbarButton
            onClick={() => run('attach', attachControlEvaluators)}
            disabled={busy !== null}
            busy={busy === 'attach'}
            Icon={Wrench}
            label="Attach collectors"
          />
          <ToolbarButton
            onClick={load}
            disabled={busy !== null}
            busy={loading}
            Icon={RefreshCw}
            label="Refresh"
          />
        </div>
      </header>

      {error && (
        <div
          className="rounded-xl border border-rose-500/40 px-4 py-3 text-sm text-rose-500"
          style={{ background: 'var(--rc-bg-surface)' }}
        >
          {error}
        </div>
      )}

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Controls in catalog" value={summary?.total ?? '—'} hint="NIST, Prowler, and authored" />
        <Stat label="Automated" value={summary?.automated ?? '—'} hint="Backed by a deterministic check" />
        <Stat
          label="Collectors ready"
          value={collectors ? `${collectors.ready_count}/${collectors.total}` : '—'}
          hint="Have a configured connector"
        />
        <Stat
          label="Prowler"
          value={prowler?.installed ? prowler.version ?? 'installed' : 'not installed'}
          hint={prowler?.installed ? `${(prowler.providers ?? []).length} providers` : 'Cloud posture unavailable'}
          tone={prowler?.installed ? 'good' : 'warn'}
        />
      </section>

      <section className="rounded-xl border p-4" style={surface}>
        <h2 className="text-sm font-semibold mb-3" style={text1}>Controls by CISA pillar</h2>
        <div className="space-y-2">
          {pillars.map((p: any) => (
            <div key={p.pillar} className="flex items-center gap-3">
              <span className="w-44 shrink-0 text-xs" style={text2}>{p.label}</span>
              <div className="h-2 flex-1 rounded" style={{ background: 'var(--rc-bg-elevated)' }}>
                <div
                  className={`h-2 rounded ${PILLAR_COLOR[p.pillar] ?? 'bg-slate-400'}`}
                  style={{ width: `${Math.round(100 * (p.controls ?? 0) / maxPillar)}%` }}
                />
              </div>
              <span className="w-12 shrink-0 text-right text-xs tabular-nums" style={text1}>{p.controls}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-xl border overflow-hidden" style={surface}>
        <div className="flex items-center justify-between border-b px-4 py-3" style={{ borderColor: 'var(--rc-border)' }}>
          <h2 className="text-sm font-semibold" style={text1}>Security Arm profiles</h2>
          <span className="text-xs" style={text3}>{coverage?.profile_version}</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide" style={text3}>
                <th className="px-4 py-2 font-medium">Security Arm</th>
                <th className="px-4 py-2 font-medium">NIST families</th>
                <th className="px-4 py-2 font-medium text-right">Controls</th>
                <th className="px-4 py-2 font-medium text-right">With evaluator</th>
                <th className="px-4 py-2 font-medium text-right">Collector ready</th>
                <th className="px-4 py-2 font-medium">Readiness</th>
              </tr>
            </thead>
            <tbody>
              {(coverage?.arms ?? []).map((arm: any) => (
                <tr
                  key={arm.claw}
                  onClick={() => openArm(arm.claw)}
                  className="cursor-pointer border-t transition-colors"
                  style={{
                    borderColor: 'var(--rc-border)',
                    background: selected === arm.claw ? 'var(--rc-panel-hover)' : 'transparent',
                  }}
                >
                  <td className="px-4 py-2" style={text1}>{labelOf(arm.claw)}</td>
                  <td className="px-4 py-2 text-xs uppercase" style={text3}>
                    {(arm.nist_families ?? []).join(' ') || '—'}
                  </td>
                  <td className="px-4 py-2 text-right tabular-nums" style={text2}>{arm.total}</td>
                  <td className="px-4 py-2 text-right tabular-nums" style={text2}>{arm.with_evaluator}</td>
                  <td className="px-4 py-2 text-right tabular-nums" style={text2}>{arm.collector_ready ?? 0}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-24 rounded" style={{ background: 'var(--rc-bg-elevated)' }}>
                        <div
                          className="h-1.5 rounded bg-emerald-500"
                          style={{ width: `${Math.min(100, arm.ready_percent ?? 0)}%` }}
                        />
                      </div>
                      <span className="text-xs tabular-nums" style={text2}>{arm.ready_percent ?? 0}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selected && (
        <section className="rounded-xl border overflow-hidden" style={surface}>
          <div className="flex items-center justify-between border-b px-4 py-3" style={{ borderColor: 'var(--rc-border)' }}>
            <h2 className="text-sm font-semibold" style={text1}>
              {labelOf(selected)} — control verdicts
            </h2>
            {evaluation && (
              <span className="text-xs" style={text2}>
                {evaluation.assessed} assessed of {evaluation.evaluated}
                {evaluation.pass_rate !== null && evaluation.pass_rate !== undefined
                  ? ` · ${evaluation.pass_rate}% passing`
                  : ' · no pass rate yet'}
              </span>
            )}
          </div>
          {!evaluation ? (
            <p className="px-4 py-6 text-sm" style={text3}>Evaluating…</p>
          ) : (
            <ul>
              {(evaluation.results ?? []).slice(0, 40).map((r: any) => {
                const meta = VERDICT_META[r.verdict] ?? VERDICT_META.not_assessed;
                const { Icon } = meta;
                return (
                  <li
                    key={r.control_id}
                    className="flex items-start gap-3 border-t px-4 py-2.5"
                    style={{ borderColor: 'var(--rc-border)' }}
                  >
                    <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${meta.cls}`} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm" style={text1}>{r.title}</p>
                      <p className="truncate text-xs" style={text3}>{r.control_id}</p>
                      <p className="text-xs" style={text2}>{r.reason}</p>
                    </div>
                    <span className={`shrink-0 text-xs ${meta.cls}`}>{meta.label}</span>
                  </li>
                );
              })}
            </ul>
          )}
          {proposals && proposals.actionable?.length > 0 && (
            <div className="border-t px-4 py-3" style={{ borderColor: 'var(--rc-border)' }}>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide" style={text3}>
                Failing controls with an executable remediation
              </p>
              <ul className="space-y-1">
                {proposals.actionable.map((a: any) => (
                  <li key={a.control_id} className="flex items-center justify-between gap-3 text-sm">
                    <span className="truncate" style={text1}>{a.title}</span>
                    <span className="shrink-0 text-xs" style={text3}>
                      {a.action_type} via {a.provider}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="border-t px-4 py-3" style={{ borderColor: 'var(--rc-border)' }}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide" style={text3}>
                  AI analysis and remediation plan
                </p>
                <p className="mt-0.5 text-xs" style={text2}>
                  Advisory only. Verdicts and the score above are computed deterministically
                  and are not changed by this summary.
                </p>
              </div>
              <button
                onClick={() => explain(selected)}
                disabled={advisoryBusy || !evaluation}
                className="inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm transition-colors disabled:opacity-50"
                style={{ ...elevated, color: 'var(--rc-text-1)' }}
              >
                {advisoryBusy
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                  : <Sparkles className="h-4 w-4 text-indigo-500" />}
                {advisoryBusy ? 'Analyzing…' : 'Explain this assessment'}
              </button>
            </div>

            {advisory && (
              <div className="mt-3 rounded-lg border p-3" style={{ background: 'var(--rc-panel-hover)', borderColor: 'var(--rc-border)' }}>
                {advisory.available ? (
                  <>
                    <div className="rc-md text-sm" style={text1}>
                      <SafeMarkdown content={String(advisory.summary ?? '')} />
                    </div>
                    <p className="mt-3 border-t pt-2 text-xs" style={{ ...text3, borderColor: 'var(--rc-border)' }}>
                      {advisory.provider ?? 'brain'}
                      {advisory.model ? ` · ${advisory.model}` : ''}
                      {' · read '}
                      {advisory.evidence_counts?.failing_controls ?? 0} failing controls,{' '}
                      {advisory.evidence_counts?.findings ?? 0} findings
                      {advisory.evidence_counts?.not_assessed
                        ? ` · ${advisory.evidence_counts.not_assessed} controls were never assessed`
                        : ''}
                    </p>
                  </>
                ) : (
                  <div className="flex items-start gap-2 text-sm" style={text2}>
                    {advisory.reason === 'no_failing_controls'
                      ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                      : <Info className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />}
                    <span>{advisory.detail ?? 'No summary is available for this assessment.'}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
      )}

      {collectors && (
        <section className="rounded-xl border p-4" style={surface}>
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold" style={text1}>
            <Plug className="h-4 w-4 text-indigo-500" />
            Evidence collectors
          </h2>
          <div className="grid gap-4 md:grid-cols-2">
            <CollectorList title="Ready" items={collectors.ready} ready />
            <CollectorList title="Awaiting a connector" items={collectors.blocked} />
          </div>
        </section>
      )}
    </div>
  );
}

function ToolbarButton({ onClick, disabled, busy, Icon, label, title }: {
  onClick: () => void; disabled: boolean; busy: boolean;
  Icon: typeof Download; label: string; title?: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm transition-colors disabled:opacity-50"
      style={{ ...elevated, color: 'var(--rc-text-1)' }}
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Icon className="h-4 w-4" />}
      {label}
    </button>
  );
}

function Stat({ label, value, hint, tone }: {
  label: string; value: string | number; hint?: string; tone?: 'good' | 'warn';
}) {
  const valueColor =
    tone === 'good' ? '#10b981' : tone === 'warn' ? '#f59e0b' : 'var(--rc-text-1)';
  return (
    <div className="rounded-xl border p-4" style={surface}>
      <p className="text-xs uppercase tracking-wide" style={text3}>{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums" style={{ color: valueColor }}>{value}</p>
      {hint && <p className="mt-1 text-xs" style={text3}>{hint}</p>}
    </div>
  );
}

function CollectorList({ title, items, ready }: {
  title: string; items: any[]; ready?: boolean;
}) {
  return (
    <div>
      <p className="mb-2 text-xs font-semibold uppercase tracking-wide" style={text3}>
        {title} ({items?.length ?? 0})
      </p>
      <ul className="space-y-1.5">
        {(items ?? []).map((c: any) => (
          <li key={c.evaluator_key} className="flex items-start gap-2 text-sm">
            <span
              className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${ready ? 'bg-emerald-500' : ''}`}
              style={ready ? undefined : { background: 'var(--rc-text-3)' }}
            />
            <div className="min-w-0">
              <p className="truncate" style={text1}>{c.evaluator_key}</p>
              <p className="truncate text-xs" style={text3}>
                {c.local ? 'Local scanner' : (c.connectors ?? []).join(', ') || 'No connector mapped'}
              </p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
