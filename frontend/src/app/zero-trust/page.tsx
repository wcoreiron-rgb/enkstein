'use client';
import { useCallback, useEffect, useState } from 'react';
import {
  Shield, RefreshCw, CheckCircle2, XCircle, HelpCircle, Info,
  Plug, Download, Wrench, AlertTriangle, Loader2,
} from 'lucide-react';
import {
  getControlSummary, getControlCoverage, getControlEvaluation,
  getControlCollectors, getProwlerStatus, getControlRemediationProposals,
  syncProwlerCatalog, syncNistCatalog, attachControlEvaluators,
} from '@/lib/api';

const PILLAR_COLOR: Record<string, string> = {
  identity: 'bg-indigo-500',
  devices: 'bg-cyan-500',
  networks: 'bg-emerald-500',
  applications: 'bg-amber-500',
  data: 'bg-rose-500',
  visibility: 'bg-sky-500',
  automation: 'bg-violet-500',
  governance: 'bg-slate-500',
};

const VERDICT_META: Record<string, { label: string; cls: string; Icon: typeof CheckCircle2 }> = {
  pass: { label: 'Pass', cls: 'text-emerald-400', Icon: CheckCircle2 },
  fail: { label: 'Fail', cls: 'text-rose-400', Icon: XCircle },
  not_assessed: { label: 'Not assessed', cls: 'text-slate-400', Icon: HelpCircle },
  recommendation: { label: 'Recommendation', cls: 'text-amber-400', Icon: Info },
  error: { label: 'Error', cls: 'text-rose-500', Icon: AlertTriangle },
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
    try {
      const [ev, pr] = await Promise.all([
        getControlEvaluation(claw), getControlRemediationProposals(claw),
      ]);
      setEvaluation(ev); setProposals(pr);
    } catch (e: any) {
      setError(e?.message ?? 'Could not evaluate this Security Arm.');
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
          <h1 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
            <Shield className="h-5 w-5 text-indigo-400" />
            Zero Trust Control Coverage
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            CISA pillars, per-Arm control profiles, and the evidence collectors behind them.
            A control only passes when a collector ran and returned no violation.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => run('nist', syncNistCatalog)}
            disabled={busy !== null}
            className="inline-flex items-center gap-2 rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700 disabled:opacity-50"
          >
            {busy === 'nist' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            Sync NIST
          </button>
          <button
            onClick={() => run('prowler', syncProwlerCatalog)}
            disabled={busy !== null || !prowler?.installed}
            title={prowler?.installed ? 'Import the Prowler check catalog' : 'Prowler is not installed on this host'}
            className="inline-flex items-center gap-2 rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700 disabled:opacity-50"
          >
            {busy === 'prowler' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            Sync Prowler
          </button>
          <button
            onClick={() => run('attach', attachControlEvaluators)}
            disabled={busy !== null}
            className="inline-flex items-center gap-2 rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700 disabled:opacity-50"
          >
            {busy === 'attach' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wrench className="h-4 w-4" />}
            Attach collectors
          </button>
          <button
            onClick={load}
            disabled={busy !== null}
            className="inline-flex items-center gap-2 rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700 disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </header>

      {error && (
        <div className="rounded border border-rose-800 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
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

      <section className="rounded border border-slate-800 bg-slate-900/60 p-4">
        <h2 className="text-sm font-semibold text-slate-200 mb-3">Controls by CISA pillar</h2>
        <div className="space-y-2">
          {pillars.map((p: any) => (
            <div key={p.pillar} className="flex items-center gap-3">
              <span className="w-44 shrink-0 text-xs text-slate-400">{p.label}</span>
              <div className="h-2 flex-1 rounded bg-slate-800">
                <div
                  className={`h-2 rounded ${PILLAR_COLOR[p.pillar] ?? 'bg-slate-500'}`}
                  style={{ width: `${Math.round(100 * (p.controls ?? 0) / maxPillar)}%` }}
                />
              </div>
              <span className="w-12 shrink-0 text-right text-xs tabular-nums text-slate-300">{p.controls}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded border border-slate-800 bg-slate-900/60">
        <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
          <h2 className="text-sm font-semibold text-slate-200">Security Arm profiles</h2>
          <span className="text-xs text-slate-500">{coverage?.profile_version}</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-slate-500">
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
                  className={`cursor-pointer border-t border-slate-800 hover:bg-slate-800/50 ${
                    selected === arm.claw ? 'bg-slate-800/70' : ''
                  }`}
                >
                  <td className="px-4 py-2 text-slate-200">{labelOf(arm.claw)}</td>
                  <td className="px-4 py-2 text-xs uppercase text-slate-500">
                    {(arm.nist_families ?? []).join(' ') || '—'}
                  </td>
                  <td className="px-4 py-2 text-right tabular-nums text-slate-300">{arm.total}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-slate-300">{arm.with_evaluator}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-slate-300">{arm.collector_ready ?? 0}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-24 rounded bg-slate-800">
                        <div
                          className="h-1.5 rounded bg-emerald-500"
                          style={{ width: `${Math.min(100, arm.ready_percent ?? 0)}%` }}
                        />
                      </div>
                      <span className="text-xs tabular-nums text-slate-400">{arm.ready_percent ?? 0}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selected && (
        <section className="rounded border border-slate-800 bg-slate-900/60">
          <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
            <h2 className="text-sm font-semibold text-slate-200">
              {labelOf(selected)} — control verdicts
            </h2>
            {evaluation && (
              <span className="text-xs text-slate-400">
                {evaluation.assessed} assessed of {evaluation.evaluated}
                {evaluation.pass_rate !== null && evaluation.pass_rate !== undefined
                  ? ` · ${evaluation.pass_rate}% passing`
                  : ' · no pass rate yet'}
              </span>
            )}
          </div>
          {!evaluation ? (
            <p className="px-4 py-6 text-sm text-slate-500">Evaluating…</p>
          ) : (
            <ul className="divide-y divide-slate-800">
              {(evaluation.results ?? []).slice(0, 40).map((r: any) => {
                const meta = VERDICT_META[r.verdict] ?? VERDICT_META.not_assessed;
                const { Icon } = meta;
                return (
                  <li key={r.control_id} className="flex items-start gap-3 px-4 py-2.5">
                    <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${meta.cls}`} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-slate-200">{r.title}</p>
                      <p className="truncate text-xs text-slate-500">{r.control_id}</p>
                      <p className="text-xs text-slate-400">{r.reason}</p>
                    </div>
                    <span className={`shrink-0 text-xs ${meta.cls}`}>{meta.label}</span>
                  </li>
                );
              })}
            </ul>
          )}
          {proposals && proposals.actionable?.length > 0 && (
            <div className="border-t border-slate-800 px-4 py-3">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                Failing controls with an executable remediation
              </p>
              <ul className="space-y-1">
                {proposals.actionable.map((a: any) => (
                  <li key={a.control_id} className="flex items-center justify-between gap-3 text-sm">
                    <span className="truncate text-slate-300">{a.title}</span>
                    <span className="shrink-0 text-xs text-slate-500">
                      {a.action_type} via {a.provider}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {collectors && (
        <section className="rounded border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Plug className="h-4 w-4 text-slate-400" />
            Evidence collectors
          </h2>
          <div className="grid gap-4 md:grid-cols-2">
            <CollectorList title="Ready" items={collectors.ready} tone="emerald" />
            <CollectorList title="Awaiting a connector" items={collectors.blocked} tone="slate" />
          </div>
        </section>
      )}
    </div>
  );
}

function Stat({ label, value, hint, tone }: {
  label: string; value: string | number; hint?: string; tone?: 'good' | 'warn';
}) {
  const valueCls =
    tone === 'good' ? 'text-emerald-400' : tone === 'warn' ? 'text-amber-400' : 'text-slate-100';
  return (
    <div className="rounded border border-slate-800 bg-slate-900/60 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${valueCls}`}>{value}</p>
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

function CollectorList({ title, items, tone }: {
  title: string; items: any[]; tone: 'emerald' | 'slate';
}) {
  const dot = tone === 'emerald' ? 'bg-emerald-500' : 'bg-slate-600';
  return (
    <div>
      <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
        {title} ({items?.length ?? 0})
      </p>
      <ul className="space-y-1.5">
        {(items ?? []).map((c: any) => (
          <li key={c.evaluator_key} className="flex items-start gap-2 text-sm">
            <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} />
            <div className="min-w-0">
              <p className="truncate text-slate-300">{c.evaluator_key}</p>
              <p className="truncate text-xs text-slate-500">
                {c.local ? 'Local scanner' : (c.connectors ?? []).join(', ') || 'No connector mapped'}
              </p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
