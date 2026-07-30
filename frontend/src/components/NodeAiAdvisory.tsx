'use client';

import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, Info, Loader2, RefreshCw, Sparkles } from 'lucide-react';
import { getAssessmentSummary } from '@/lib/api';
import SafeMarkdown from '@/components/markdown/SafeMarkdown';

type Props = {
  claw: string;
};

function nodeLabel(claw: string) {
  return claw.replace(/claw$/i, '').replace(/^./, (value) => value.toUpperCase());
}

export default function NodeAiAdvisory({ claw }: Props) {
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setBusy(true);
    try {
      setResult(await getAssessmentSummary(claw));
    } catch (error: any) {
      setResult({
        available: false,
        reason: 'error',
        detail: error?.message ?? 'AI analysis is unavailable. The assessment remains unchanged.',
      });
    } finally {
      setBusy(false);
    }
  }, [claw]);

  useEffect(() => { void load(); }, [load]);

  return (
    <section
      className="rounded-xl border p-4"
      style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}
      aria-label={`${nodeLabel(claw)} AI advisory`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-indigo-400" />
          <div>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
              AI analysis and remediation plan
            </h2>
            <p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>
              Advisory only. Deterministic verdicts and scores are never changed by the Brain.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => void load()}
          disabled={busy}
          className="inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs disabled:opacity-50"
          style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          {busy ? 'Analyzing…' : 'Refresh analysis'}
        </button>
      </div>

      {busy && !result ? (
        <p className="mt-4 text-sm" style={{ color: 'var(--rc-text-3)' }}>Reading the completed assessment…</p>
      ) : result?.available ? (
        <div className="mt-4">
          <div className="rc-md text-sm" style={{ color: 'var(--rc-text-1)' }}>
            <SafeMarkdown content={String(result.summary ?? '')} />
          </div>
          <p className="mt-3 border-t pt-2 text-xs" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}>
            {result.provider ?? 'Brain'}{result.model ? ` · ${result.model}` : ''}
            {' · '}{result.evidence_counts?.failing_controls ?? 0} failing controls
            {' · '}{result.evidence_counts?.findings ?? 0} findings
            {result.evidence_counts?.not_assessed ? ` · ${result.evidence_counts.not_assessed} not assessed` : ''}
          </p>
        </div>
      ) : result ? (
        <div className="mt-4 flex items-start gap-2 text-sm" style={{ color: 'var(--rc-text-2)' }}>
          {result.reason === 'no_failing_controls'
            ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
            : <Info className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />}
          <span>{result.detail ?? 'AI analysis is unavailable. The assessment remains unchanged.'}</span>
        </div>
      ) : null}
      {result?.engine && (result.engine.source || result.engine.provider || result.engine.model) ? (
        <p className="mt-3 border-t pt-2 text-xs" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}>
          Engine: {result.engine.source ?? 'governed fallback'}
          {result.engine.provider ? ` · ${result.engine.provider}` : ''}
          {result.engine.model ? ` · ${result.engine.model}` : ''}
        </p>
      ) : result?.engine_plan ? (
        <p className="mt-3 border-t pt-2 text-xs" style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-3)' }}>
          Engine plan: {result.engine_plan.map((item: any) => item.source).join(' → ')}
        </p>
      ) : null}
    </section>
  );
}
