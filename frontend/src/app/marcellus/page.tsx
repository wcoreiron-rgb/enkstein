'use client';

import { useEffect, useState } from 'react';
import AIWorkspace from './ai-workspace';
import SecurityWorkspace from './security-workspace';
import { persistWorkspaceMode, resolveWorkspaceMode, syncWorkspaceHash, WORKSPACE_MODE_EVENT, WorkspaceMode } from '@/lib/workspace-mode';

export default function EnksteinPage() {
  const [mode, setMode] = useState<WorkspaceMode>('chat');

  useEffect(() => {
    // Resolves from the URL hash / localStorage: real navigation (initial
    // load, back/forward, a typed URL) and cross-tab storage updates.
    const syncMode = () => {
      const next = resolveWorkspaceMode();
      setMode(next);
      persistWorkspaceMode(next);
      syncWorkspaceHash(next);
    };
    // A same-tab mode switch (clicking a Sidebar workspace button) calls
    // pushWorkspaceModeState directly, bypassing Next's router entirely, so
    // no "hashchange" fires. That call has already updated the hash and
    // storage and dispatched this event; just apply the state.
    const onModeEvent = (event: Event) => {
      const detail = (event as CustomEvent<WorkspaceMode>).detail;
      if (detail) setMode(detail);
    };
    syncMode();
    window.addEventListener('hashchange', syncMode);
    window.addEventListener('popstate', syncMode);
    window.addEventListener('storage', syncMode);
    window.addEventListener(WORKSPACE_MODE_EVENT, onModeEvent);
    return () => {
      window.removeEventListener('hashchange', syncMode);
      window.removeEventListener('popstate', syncMode);
      window.removeEventListener('storage', syncMode);
      window.removeEventListener(WORKSPACE_MODE_EVENT, onModeEvent);
    };
  }, []);

  return (
    <div className="min-h-[calc(100vh-2rem)]">
      {mode === 'security'
        ? <SecurityWorkspace key="security" />
        : <AIWorkspace key={mode} mode={mode} />}
    </div>
  );
}
