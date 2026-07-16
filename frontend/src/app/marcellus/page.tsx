'use client';

import { useEffect, useState } from 'react';
import AIWorkspace from './ai-workspace';
import SecurityWorkspace from './security-workspace';

type WorkspaceMode = 'chat' | 'cowork' | 'security';

function modeFromHash(): WorkspaceMode {
  const value = window.location.hash.slice(1).toLowerCase();
  return value === 'cowork' || value === 'security' ? value : 'chat';
}

export default function EnksteinPage() {
  const [mode, setMode] = useState<WorkspaceMode>('chat');

  useEffect(() => {
    const syncMode = () => setMode(modeFromHash());
    syncMode();
    window.addEventListener('hashchange', syncMode);
    return () => window.removeEventListener('hashchange', syncMode);
  }, []);

  return (
    <div className="min-h-[calc(100vh-2rem)]">
      {mode === 'security' ? <SecurityWorkspace /> : <AIWorkspace mode={mode} />}
    </div>
  );
}
