'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeft,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  Cloud,
  Cpu,
  Download,
  ExternalLink,
  HardDrive,
  Loader2,
  Plug,
  RefreshCw,
  ShieldCheck,
  TerminalSquare,
  XCircle,
} from 'lucide-react';
import {
  getArcModels,
  getArcProviders,
  getBrainStatuses,
  getModelClawProfiles,
  downloadBrowserCompanion,
  launchCliLogin,
  openBrowserCompanionFolder,
  requestDesktopBrainAccess,
  startBrowserBrainPairing,
} from '@/lib/api';
import { readLastActiveConversation, workspaceRoutePath } from '@/lib/workspace-routes';
import { ExecutionOrb } from '@/components/ExecutionOrb';
import type { WorkspaceMode } from '@/lib/workspace-mode';

type BrainReadinessStatus = 'ready' | 'needs_setup' | 'unavailable' | 'policy_blocked';

type BrainStatus = {
  brain: string;
  available: boolean;
  authenticated: boolean;
  status?: BrainReadinessStatus;
  runtime?: string | null;
  account_type?: string | null;
  detail?: string | null;
  models?: string[];
  last_checked?: string | null;
};

type ProviderStatus = {
  provider: string;
  label: string;
  models?: string[];
  ready: boolean;
  setup?: string;
  cost?: string;
};

type ModelProfile = {
  name: string;
  provider: string;
  model: string;
  allowed_data_classes?: string[];
};

function Status({ ready, checking, status }: { ready: boolean; checking?: boolean; status?: BrainReadinessStatus }) {
  if (checking) {
    return <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: 'var(--rc-text-3)' }}><Loader2 className="h-4 w-4 animate-spin" />Checking…</span>;
  }
  if (status === 'policy_blocked') {
    return <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-600"><XCircle className="h-4 w-4" />Policy blocked</span>;
  }
  if (status === 'unavailable' && !ready) {
    return <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: 'var(--rc-text-3)' }}><XCircle className="h-4 w-4" />Unavailable</span>;
  }
  return ready ? (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-green-600"><CheckCircle2 className="h-4 w-4" />Ready</span>
  ) : (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-600"><XCircle className="h-4 w-4" />Needs setup</span>
  );
}

/** Model lists run from three entries to forty-four. Rendering them all inline
 * made a single card taller than the rest of the page, so the full list is
 * collapsed behind its own count and opened on demand. */
function ModelList({ models, label = 'models' }: { models: string[]; label?: string }) {
  const [open, setOpen] = useState(false);
  if (models.length === 0) return null;
  return (
    <div className="mt-3 border-t pt-2" style={{ borderColor: 'var(--rc-border)' }}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="inline-flex items-center gap-1.5 text-[11px] font-medium"
        style={{ color: 'var(--rc-text-2)' }}
      >
        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? 'rotate-180' : ''}`} />
        {models.length} {label}
      </button>
      {open && (
        <div className="mt-2 flex max-h-48 flex-wrap gap-1.5 overflow-y-auto pr-1">
          {models.map((name) => (
            <span
              key={name}
              className="rounded px-1.5 py-0.5 text-[10px]"
              style={{ background: 'var(--rc-bg-elevated)', color: 'var(--rc-text-3)' }}
            >
              {name}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

const LAUNCH_RETRY_ATTEMPTS = 3;
const LAUNCH_RETRY_DELAY_MS = 700;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export default function BrainConnectionsPage() {
  const [loading, setLoading] = useState(true);
  const [everLoaded, setEverLoaded] = useState(false);
  const [brains, setBrains] = useState<BrainStatus[]>([]);
  const [providers, setProviders] = useState<ProviderStatus[]>([]);
  const [profiles, setProfiles] = useState<ModelProfile[]>([]);
  const [models, setModels] = useState<Record<string, Array<{ id: string; name: string }>>>({});
  const [warnings, setWarnings] = useState<string[]>([]);
  const [requestingAccess, setRequestingAccess] = useState(false);
  const [pairingBrowser, setPairingBrowser] = useState(false);
  const [launchingCliLogin, setLaunchingCliLogin] = useState<string | null>(null);
  const [workspaceMode, setWorkspaceMode] = useState<WorkspaceMode>('chat');
  const [returnPath, setReturnPath] = useState('/marcellus/chat');
  const loadInFlight = useRef(false);

  useEffect(() => {
    const remembered = window.localStorage.getItem('marcellus-workspace-mode');
    const mode: WorkspaceMode = remembered === 'cowork' || remembered === 'security' ? remembered : 'chat';
    setWorkspaceMode(mode);
    setReturnPath(workspaceRoutePath(mode, readLastActiveConversation(mode)));
  }, []);

  /** Retries the Brain status fetch a bounded number of times so a Brain
   * Bridge that is still launching on app startup resolves to "ready"
   * shortly after, instead of leaving the page stuck on a stale failure. */
  const loadBrainsWithRetry = useCallback(async (): Promise<BrainStatus[] | null> => {
    for (let attempt = 0; attempt < LAUNCH_RETRY_ATTEMPTS; attempt += 1) {
      try {
        const rows = await getBrainStatuses(true);
        const bridgeUnavailable = rows.length > 0 && rows.every((row) => row.status === 'unavailable');
        if (!bridgeUnavailable || attempt === LAUNCH_RETRY_ATTEMPTS - 1) return rows;
        await delay(LAUNCH_RETRY_DELAY_MS);
      } catch (fetchError) {
        if (attempt === LAUNCH_RETRY_ATTEMPTS - 1) throw fetchError;
        await delay(LAUNCH_RETRY_DELAY_MS);
      }
    }
    return null;
  }, []);

  const load = useCallback(async () => {
    if (loadInFlight.current) return;
    loadInFlight.current = true;
    setLoading(true);
    try {
      const results = await Promise.allSettled([
        loadBrainsWithRetry(),
        getArcProviders(),
        getModelClawProfiles(),
        getArcModels(),
      ]);
      const nextWarnings: string[] = [];
      if (results[0].status === 'fulfilled') setBrains(results[0].value || []);
      else nextWarnings.push('Desktop subscription status is unavailable.');
      if (results[1].status === 'fulfilled') setProviders(results[1].value || []);
      else nextWarnings.push('Provider status is unavailable.');
      if (results[2].status === 'fulfilled') setProfiles(results[2].value || []);
      else nextWarnings.push('Model profiles are unavailable.');
      if (results[3].status === 'fulfilled') setModels(results[3].value || {});
      else nextWarnings.push('Live model discovery is unavailable.');
      setWarnings(nextWarnings);
    } finally {
      loadInFlight.current = false;
      setLoading(false);
      setEverLoaded(true);
    }
  }, [loadBrainsWithRetry]);

  useEffect(() => { void load(); }, [load]);

  /** Refreshes readiness whenever the user returns to this tab/window, since
   * setup (CLI login, desktop sign-in, Accessibility grant) usually happens
   * in another app or tab. */
  useEffect(() => {
    const onFocus = () => { void load(); };
    const onVisibility = () => { if (document.visibilityState === 'visible') void load(); };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [load]);

  const checkingBrains = loading && everLoaded;

  const subscriptionBrains = useMemo(() => [
    {
      id: 'codex_subscription',
      name: 'Codex Subscription',
      icon: TerminalSquare,
      instruction: 'Install Codex, run codex login, then relaunch Enkstein.',
    },
    {
      id: 'claude_subscription',
      name: 'Claude Subscription',
      icon: BrainCircuit,
      instruction: 'Install Claude Code, run claude and sign in, then relaunch Enkstein.',
    },
    {
      id: 'chatgpt_desktop',
      name: 'ChatGPT Desktop Session',
      icon: BrainCircuit,
      instruction: 'Install and sign in to ChatGPT, then grant Enkstein Accessibility access.',
    },
    {
      id: 'claude_desktop',
      name: 'Claude Desktop Session',
      icon: BrainCircuit,
      instruction: 'Install and sign in to Claude, then grant Enkstein Accessibility access.',
    },
    {
      id: 'chatgpt_browser',
      name: 'ChatGPT Browser Session',
      icon: Cloud,
      instruction: 'Install the Enkstein browser companion, pair it once, and keep a signed-in ChatGPT tab open.',
    },
    {
      id: 'claude_browser',
      name: 'Claude Browser Session',
      icon: Cloud,
      instruction: 'Install the Enkstein browser companion, pair it once, and keep a signed-in Claude tab open.',
    },
    {
      id: 'gemini_browser',
      name: 'Gemini Browser Session',
      icon: Cloud,
      instruction: 'Install the Enkstein browser companion, pair it once, and keep a signed-in Gemini tab open.',
    },
  ].map((entry) => ({ ...entry, status: brains.find((brain) => brain.brain === entry.id) }))
    /** Claude Code CLI is the preferred Claude Brain. Once it is genuinely
     * ready, the browser fallback is redundant and is hidden; ChatGPT and
     * Gemini browser sessions are always preserved as options. */
    .filter((entry) => !(entry.id === 'claude_browser' && brains.find((brain) => brain.brain === 'claude_subscription')?.status === 'ready'))
    /** Claude Desktop is only useful when the host Accessibility bridge can
     * find a compatible message field in the installed app version. */
    .filter((entry) => !(entry.id === 'claude_desktop' && (entry.status?.detail || '').includes('does not expose a compatible message field'))),
  [brains]);

  const requestDesktopAccess = async () => {
    setRequestingAccess(true);
    try {
      const result = await requestDesktopBrainAccess();
      setWarnings(result.granted ? [] : [result.detail]);
      await load();
    } catch (accessError) {
      setWarnings([accessError instanceof Error ? accessError.message : 'Desktop access could not be requested.']);
    } finally {
      setRequestingAccess(false);
    }
  };

  const pairBrowser = async () => {
    setPairingBrowser(true);
    try {
      const result = await startBrowserBrainPairing();
      if (!result.available || !result.setup_url) throw new Error(result.detail || 'Browser pairing is unavailable.');
      if (!result.opened) window.open(result.setup_url, '_blank', 'noopener,noreferrer');
      setWarnings(['Complete pairing in the browser, keep a supported signed-in AI tab open, then refresh.']);
    } catch (pairingError) {
      setWarnings([pairingError instanceof Error ? pairingError.message : 'Browser pairing could not start.']);
    } finally {
      setPairingBrowser(false);
    }
  };

  const signInToCli = async (brain: 'codex_subscription' | 'claude_subscription') => {
    setLaunchingCliLogin(brain);
    try {
      const result = await launchCliLogin(brain);
      if (!result.launched) throw new Error(result.detail || 'A terminal could not be opened for sign-in.');
      setWarnings([result.detail || 'Complete sign-in in the opened terminal window, then return here and refresh.']);
    } catch (loginError) {
      setWarnings([loginError instanceof Error ? loginError.message : 'CLI sign-in could not start.']);
    } finally {
      setLaunchingCliLogin(null);
    }
  };

  const openCompanion = async () => {
    // Downloading works from any browser that can reach the console. Revealing
    // the folder only helps an operator sitting at the host, so it is kept as
    // a fallback for when the download is unavailable.
    try {
      await downloadBrowserCompanion();
      setWarnings([
        'Unzip the download, then in Chrome or Edge open Extensions, enable Developer mode, choose Load unpacked, and select the unzipped enkstein-browser-companion folder. Return here and press Pair browser.',
      ]);
      return;
    } catch {
      // fall through to revealing the bundled folder
    }
    try {
      const result = await openBrowserCompanionFolder();
      if (!result.opened) throw new Error(result.detail || 'Browser companion folder could not be opened.');
      setWarnings(['In Chrome or Edge Extensions, enable Developer mode, choose Load unpacked, and select the opened browser-extension folder.']);
    } catch (openError) {
      setWarnings([openError instanceof Error ? openError.message : 'Browser companion folder could not be opened.']);
    }
  };

  const ollama = providers.find((provider) => provider.provider === 'ollama');
  const apiProviders = providers.filter((provider) => provider.provider !== 'ollama');
  /** The providers endpoint carries a static catalogue while live discovery
   * reports what is actually installed or reachable, and the two disagree
   * (Anthropic listed 3 against 6 discovered). Live discovery wins when it
   * returned anything for the provider. */
  const modelNames = useCallback(
    (provider: ProviderStatus): string[] => {
      const live = (models[provider.provider] || []).map((row) => row.name || row.id).filter(Boolean);
      return live.length ? live : provider.models || [];
    },
    [models],
  );
  const readyCount = subscriptionBrains.filter((brain) => brain.status?.available && brain.status.authenticated).length
    + providers.filter((provider) => provider.ready).length;

  return (
    <main className="min-h-[calc(100vh-4rem)] px-4 py-5 md:px-7" style={{ background: 'var(--rc-bg-base)' }}>
      <div className="mx-auto max-w-6xl">
        <header className="flex flex-wrap items-start justify-between gap-4 border-b pb-5" style={{ borderColor: 'var(--rc-border)' }}>
          <div>
            <Link href={returnPath} className="mb-3 inline-flex items-center gap-1.5 rounded-md border px-3 py-2 text-xs font-medium" style={{ color: 'var(--rc-text-2)', borderColor: 'var(--rc-border)' }}>
              <ArrowLeft className="h-3.5 w-3.5" />Return to {workspaceMode === 'cowork' ? 'Cowork' : workspaceMode === 'security' ? 'Security' : 'Chat'}
            </Link>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md text-white"
                style={{ background: 'var(--rc-brand)' }}><BrainCircuit className="h-5 w-5" /></div>
              <div>
                <h1 className="text-xl font-semibold" style={{ color: 'var(--rc-text-1)' }}>Brain Connections</h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-3)' }}>Choose how Enkstein reasons. Every request still passes through Trust Fabric.</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Link href="/connectors" className="inline-flex h-9 items-center gap-2 rounded-md border px-3 text-xs"
              style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}>
              <Plug className="h-4 w-4" />API Connectors
            </Link>
            <button type="button" onClick={() => void load()} disabled={loading} title="Refresh connections"
              className="flex h-9 w-9 items-center justify-center rounded-md border disabled:opacity-50"
              style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            </button>
          </div>
        </header>

        {/* Splits at md rather than sm: at ~700px the two columns are narrow
            enough that the constellation overflows its card. */}
        <section className="grid gap-3 py-5 md:grid-cols-2">
          {/* Ready Brains leads on its own, because the constellation needs
              room to read as a network rather than a smudge. The two counts
              that support it stack alongside in the same total height. */}
          <div className="rounded-md border p-4" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
            <div className="flex items-center justify-between">
              <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>Ready Brains</span>
              <BrainCircuit className="h-4 w-4" style={{ color: 'var(--rc-brand)' }} />
            </div>
            <div className="mt-2 flex items-center justify-between gap-3">
              <div>
                <p className="text-3xl font-semibold" style={{ color: 'var(--rc-text-1)' }}>{readyCount}</p>
                {/* Without this, the card keeps the stacked column's height and
                    the space the constellation would occupy reads as a load
                    that never finished. */}
                {readyCount === 0 && (
                  <p className="mt-2 max-w-xs text-xs" style={{ color: 'var(--rc-text-3)' }}>
                    No Brain is connected yet. Sign in to a subscription CLI, pair a browser
                    session, or approve a local profile below.
                  </p>
                )}
              </div>
              {/* The constellation depicts the connections themselves rather
                  than work in progress, so it runs whether or not a turn is in
                  flight. A zero count is the one case it would misrepresent:
                  nothing is connected, so nothing should look like it is. */}
              {readyCount > 0 && <ExecutionOrb activity="consensus" size={64} scale={168} />}
            </div>
          </div>
          <div className="grid gap-3">
            {[
              ['Approved Profiles', String(profiles.length), ShieldCheck],
              ['Discovered Models', String(
                Object.values(models).reduce((total, rows) => total + rows.length, 0)
                + brains.reduce((total, row) => total + (row.models?.length || 0), 0),
              ), Cpu],
            ].map(([label, value, Icon]) => (
              <div key={String(label)} className="rounded-md border p-4" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
                <div className="flex items-center justify-between"><span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{String(label)}</span><Icon className="h-4 w-4" style={{ color: 'var(--rc-brand)' }} /></div>
                <p className="mt-2 text-2xl font-semibold" style={{ color: 'var(--rc-text-1)' }}>{String(value)}</p>
              </div>
            ))}
          </div>
        </section>

        {warnings.length > 0 && (
          <div className="mb-5 rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-xs text-amber-700 dark:text-amber-300">
            {warnings.join(' ')}
          </div>
        )}

        <section className="mb-6">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Desktop subscriptions</h2>
              <p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>Use a vendor CLI or the visible signed-in desktop app. Enkstein never copies credentials or browser sessions.</p>
            </div>
            <button
              type="button"
              onClick={() => void requestDesktopAccess()}
              disabled={requestingAccess}
              className="inline-flex h-8 items-center gap-2 rounded-md border px-3 text-xs disabled:opacity-50"
              style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}
            >
              {requestingAccess ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
              Allow desktop apps
            </button>
            <button
              type="button"
              onClick={() => void openCompanion()}
              className="inline-flex h-8 items-center gap-2 rounded-md border px-3 text-xs"
              style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}
            >
              <Download className="h-3.5 w-3.5" />
              Download companion
            </button>
            <button
              type="button"
              onClick={() => void pairBrowser()}
              disabled={pairingBrowser}
              className="inline-flex h-8 items-center gap-2 rounded-md border px-3 text-xs disabled:opacity-50"
              style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-surface)' }}
            >
              {pairingBrowser ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Cloud className="h-3.5 w-3.5" />}
              Pair browser
            </button>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            {subscriptionBrains.map(({ id, name, icon: Icon, instruction, status }) => {
              const ready = Boolean(status?.available && status.authenticated);
              return (
                <article key={id} className="rounded-md border p-4" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3"><Icon className="h-5 w-5" style={{ color: 'var(--rc-brand)' }} /><div><h3 className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{name}</h3><p className="mt-0.5 text-[11px]" style={{ color: 'var(--rc-text-3)' }}>{status?.runtime || 'Desktop runtime'}</p></div></div>
                    <Status ready={ready} checking={checkingBrains} status={status?.status} />
                  </div>
                  <p className="mt-4 text-xs leading-5" style={{ color: 'var(--rc-text-2)' }}>{status?.detail || instruction}</p>
                  {status?.last_checked && <p className="mt-1 text-[10px]" style={{ color: 'var(--rc-text-3)' }}>Last checked {new Date(status.last_checked).toLocaleTimeString()}</p>}
                  {(id === 'codex_subscription' || id === 'claude_subscription') && !ready && (
                    <button
                      type="button"
                      onClick={() => void signInToCli(id)}
                      disabled={launchingCliLogin === id}
                      className="mt-3 inline-flex h-8 items-center gap-2 rounded-md border px-3 text-xs disabled:opacity-50"
                      style={{ borderColor: 'var(--rc-border)', color: 'var(--rc-text-2)', background: 'var(--rc-bg-elevated)' }}
                    >
                      {launchingCliLogin === id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <TerminalSquare className="h-3.5 w-3.5" />}
                      Sign in
                    </button>
                  )}
                  {id.endsWith('_desktop') && <p className="mt-2 text-[11px] leading-4" style={{ color: 'var(--rc-text-3)' }}>This option visibly opens the vendor app and remains subject to its normal plan and usage limits.</p>}
                  {id.endsWith('_browser') && <p className="mt-2 text-[11px] leading-4" style={{ color: 'var(--rc-text-3)' }}>This option uses only the visible signed-in page. Cookies and account tokens never enter Enkstein.</p>}
                  <ModelList models={status?.models || []} />
                </article>
              );
            })}
          </div>
        </section>

        <section className="mb-6">
          <h2 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>Local Brain</h2>
          <article className="mt-3 rounded-md border p-4" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex items-center gap-3"><HardDrive className="h-5 w-5" style={{ color: 'var(--rc-brand)' }} /><div><h3 className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>Ollama</h3><p className="mt-0.5 text-[11px]" style={{ color: 'var(--rc-text-3)' }}>Private models running on this computer</p></div></div>
              <Status ready={Boolean(ollama?.ready)} />
            </div>
            <p className="mt-4 text-xs leading-5" style={{ color: 'var(--rc-text-2)' }}>{ollama?.setup || 'Install Ollama and run: ollama pull llama3.2'}</p>
            {ollama && <ModelList models={modelNames(ollama)} label="models installed on this computer" />}
          </article>
        </section>

        <section>
          <div className="flex items-end justify-between gap-3">
            <div><h2 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>API Brains</h2><p className="mt-1 text-xs" style={{ color: 'var(--rc-text-3)' }}>Keys are verified through connector setup before a provider becomes ready.</p></div>
            <Link href="/modelclaw" className="inline-flex items-center gap-1 text-xs" style={{ color: 'var(--rc-brand)' }}>Advanced profiles <ExternalLink className="h-3.5 w-3.5" /></Link>
          </div>
          <div className="mt-3 divide-y rounded-md border" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
            {apiProviders.map((provider) => (
              <div key={provider.provider} className="px-4 py-3" style={{ borderColor: 'var(--rc-border)' }}>
                <div className="flex flex-wrap items-center gap-4">
                  <Cloud className="h-4 w-4 shrink-0" style={{ color: 'var(--rc-brand)' }} />
                  <div className="min-w-0 flex-1"><p className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{provider.label}</p><p className="mt-0.5 truncate text-[11px]" style={{ color: 'var(--rc-text-3)' }}>{provider.setup}</p></div>
                  <Status ready={provider.ready} />
                </div>
                <ModelList models={modelNames(provider)} />
              </div>
            ))}
            {!loading && apiProviders.length === 0 && <p className="p-4 text-xs" style={{ color: 'var(--rc-text-3)' }}>No API providers were returned by the runtime.</p>}
          </div>
        </section>
      </div>
    </main>
  );
}
