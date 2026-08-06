'use client';

import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, CircleSlash, ExternalLink, Info, Loader2, MinusCircle, X, XCircle } from 'lucide-react';
import { getConnectorControlScope } from '@/lib/api';
import OverlayPortal from '@/components/OverlayPortal';

type Props = {
  connectorType: string;
  connectorName: string;
  onClose: () => void;
};

const CATALOG_URL =
  'https://github.com/wcoreiron-rgb/enkstein/blob/main/docs/evidence-and-connector-contract.md';

const VERDICT_STYLE: Record<string, { label: string; className: string; Icon: typeof CheckCircle2 }> = {
  pass: { label: 'Pass', className: 'text-emerald-500', Icon: CheckCircle2 },
  fail: { label: 'Fail', className: 'text-red-500', Icon: XCircle },
  not_assessed: { label: 'Not assessed', className: 'text-slate-400', Icon: MinusCircle },
};

export default function ConnectorControlScope({ connectorType, connectorName, onClose }: Props) {
  const [scope, setScope] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setScope(await getConnectorControlScope(connectorType));
    } catch (err: any) {
      setError(err?.message ?? 'Control scope could not be read.');
    } finally {
      setBusy(false);
    }
  }, [connectorType]);

  useEffect(() => { void load(); }, [load]);

  const counts = scope?.counts ?? { in_scope: 0, pass: 0, fail: 0, not_assessed: 0 };

  return (
    <OverlayPortal>
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40" role="dialog" aria-label={`${connectorName} control scope`}>
      <div
        className="flex h-full w-full max-w-2xl flex-col border-l"
        style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}
      >
        <header
          className="flex items-start justify-between gap-3 border-b p-4"
          style={{ borderColor: 'var(--rc-border)' }}
        >
          <div>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
              {connectorName} — controls in scope
            </h2>
            <p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>
              Verdicts are this tenant&apos;s live evidence. Catalog reference lives in the docs.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close control scope"
            className="rounded-lg p-1.5 hover:opacity-70"
            style={{ color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)' }}
          >
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto p-4">
          {busy ? (
            <p className="flex items-center gap-2 text-sm" style={{ color: 'var(--rc-text-3)' }}>
              <Loader2 className="h-4 w-4 animate-spin" /> Reading control scope…
            </p>
          ) : error ? (
            <div className="text-sm" style={{ color: 'var(--rc-text-2)' }}>
              <p>{error}</p>
              <button
                type="button"
                onClick={() => void load()}
                className="mt-3 rounded-lg border px-2.5 py-1.5 text-xs"
                style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
              >
                Retry
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {scope?.assesses_controls === false ? null : (
              <div className="grid grid-cols-4 gap-2">
                {([
                  ['In scope', counts.in_scope, 'var(--rc-text-1)'],
                  ['Pass', counts.pass, '#10b981'],
                  ['Fail', counts.fail, '#ef4444'],
                  ['Not assessed', counts.not_assessed, 'var(--rc-text-3)'],
                ] as const).map(([label, value, color]) => (
                  <div
                    key={label}
                    className="rounded-lg border p-2.5"
                    style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' }}
                  >
                    <p className="text-lg font-semibold tabular-nums" style={{ color }}>{value}</p>
                    <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{label}</p>
                  </div>
                ))}
              </div>
              )}

              {scope?.assesses_controls !== false && !scope?.configured && (
                <p
                  className="flex items-start gap-2 rounded-lg border p-2.5 text-xs"
                  style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
                >
                  <CircleSlash className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  This connector has no stored credential, so its controls stay Not assessed until it is configured.
                </p>
              )}

              {scope?.reason && (
                <p
                  className="flex items-start gap-2 rounded-lg border p-2.5 text-sm"
                  style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
                >
                  <Info className="mt-0.5 h-4 w-4 shrink-0" style={{ color: 'var(--rc-text-3)' }} />
                  <span>{scope.reason}</span>
                </p>
              )}

              {scope?.collectors?.length ? (
                <section>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--rc-text-3)' }}>
                    Evidence collectors
                  </h3>
                  <ul className="space-y-2">
                    {scope.collectors.map((item: any) => (
                      <li
                        key={item.evaluator_key}
                        className="rounded-lg border p-2.5 text-xs"
                        style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)' }}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <code style={{ color: 'var(--rc-text-1)' }}>{item.evaluator_key}</code>
                          <span className={item.ready ? 'text-emerald-500' : 'text-slate-400'}>
                            {item.ready ? 'Ready' : 'Blocked'}
                          </span>
                        </div>
                        <p className="mt-1">{item.description}</p>
                        {item.alternative_connectors?.length ? (
                          <p className="mt-1" style={{ color: 'var(--rc-text-3)' }}>
                            Also satisfied by: {item.alternative_connectors.join(', ')}
                          </p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}

              {scope?.controls?.length ? (
                <section>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--rc-text-3)' }}>
                    Controls ({scope.controls.length})
                  </h3>
                  <ul className="space-y-1.5">
                    {scope.controls.map((control: any) => {
                      const style = VERDICT_STYLE[control.verdict] ?? VERDICT_STYLE.not_assessed;
                      const { Icon } = style;
                      return (
                        <li
                          key={control.control_id}
                          className="rounded-lg border p-2.5"
                          style={{ background: 'var(--rc-bg-elevated)', borderColor: 'var(--rc-border)' }}
                        >
                          <div className="flex items-start gap-2">
                            <Icon className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${style.className}`} />
                            <div className="min-w-0 flex-1">
                              <p className="text-sm" style={{ color: 'var(--rc-text-1)' }}>{control.title}</p>
                              <p className="mt-0.5 text-xs" style={{ color: 'var(--rc-text-3)' }}>
                                {control.control_id} · {control.node} · {control.zt_pillar}
                                {control.recommendation_only ? ' · recommendation only' : ''}
                              </p>
                              {control.reason ? (
                                <p className="mt-1 text-xs" style={{ color: 'var(--rc-text-2)' }}>{control.reason}</p>
                              ) : null}
                            </div>
                            <span className={`shrink-0 text-xs font-medium ${style.className}`}>{style.label}</span>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </section>
              ) : null}
            </div>
          )}
        </div>

        <footer className="border-t p-4" style={{ borderColor: 'var(--rc-border)' }}>
          <a
            href={CATALOG_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 text-xs"
            style={{ color: 'var(--rc-text-2)' }}
          >
            <ExternalLink className="h-3.5 w-3.5" />
            Full control catalog and connector contract
          </a>
        </footer>
      </div>
    </div>
    </OverlayPortal>
  );
}
