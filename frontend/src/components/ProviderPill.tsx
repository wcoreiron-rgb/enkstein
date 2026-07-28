'use client';

/**
 * Provider status pill shown on every Capability Node page.
 *
 * It distinguishes three states an operator genuinely needs to tell apart:
 * connected, not yet connected, and unavailable — the last meaning the
 * provider has no live adapter, so configuring a credential for it would not
 * change what the node returns. Without that third state, an operator can
 * connect a key and reasonably conclude the product is broken when the node
 * keeps showing sample data.
 */
export interface ProviderStatus {
  provider: string;
  label: string;
  configured?: boolean;
  live_capable?: boolean;
  coverage?: string;
}

export function ProviderPill({ provider }: { provider: ProviderStatus }) {
  const connected = Boolean(provider.configured);
  // Older responses omit the field; assume capable rather than alarming the
  // operator about a provider that may well work.
  const capable = provider.live_capable !== false;

  if (connected) {
    return (
      <div
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs text-green-400 bg-green-900/20 border-green-700"
        title="Connected — this provider returns live tenant data."
      >
        <div className="w-1.5 h-1.5 rounded-full bg-green-500" />
        {provider.label}
      </div>
    );
  }

  if (!capable) {
    return (
      <div
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs border-amber-800/60"
        style={{ color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)' }}
        title="No live adapter yet. Connecting a credential will not change this node's results."
      >
        <div className="w-1.5 h-1.5 rounded-full bg-amber-600/70" />
        {provider.label}
        <span className="opacity-60">· no live adapter yet</span>
      </div>
    );
  }

  return (
    <div
      className="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs border-gray-700"
      style={{ color: 'var(--rc-text-3)', background: 'var(--rc-bg-elevated)' }}
      title="Not connected — add credentials to receive live data."
    >
      <div className="w-1.5 h-1.5 rounded-full bg-gray-600" />
      {provider.label}
      <span className="opacity-50">· not connected</span>
    </div>
  );
}

export default ProviderPill;
