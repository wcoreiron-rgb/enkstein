'use client';

import { useState } from 'react';
import { BriefcaseBusiness, MessageSquare, ShieldCheck } from 'lucide-react';
import AIWorkspace from './ai-workspace';
import SecurityWorkspace from './security-workspace';

type WorkspaceMode = 'chat' | 'cowork' | 'security';

const MODES: Array<{ id: WorkspaceMode; label: string; icon: React.ElementType }> = [
  { id: 'chat', label: 'Chat', icon: MessageSquare },
  { id: 'cowork', label: 'Cowork', icon: BriefcaseBusiness },
  { id: 'security', label: 'Security', icon: ShieldCheck },
];

export default function MarcellusPage() {
  const [mode, setMode] = useState<WorkspaceMode>('chat');

  return (
    <div className="min-h-[calc(100vh-2rem)]">
      <div className="sticky top-0 z-20 -mx-4 mb-5 border-b px-4 py-2 backdrop-blur md:-mx-6 md:px-6"
        style={{ background: 'color-mix(in srgb, var(--rc-bg) 88%, transparent)', borderColor: 'var(--rc-border)' }}>
        <div className="mx-auto flex max-w-7xl items-center justify-center">
          <div className="inline-flex rounded-md border p-1" style={{ borderColor: 'var(--rc-border)', background: 'var(--rc-bg-surface)' }}>
            {MODES.map(({ id, label, icon: Icon }) => {
              const active = mode === id;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => setMode(id)}
                  aria-pressed={active}
                  className="inline-flex h-9 min-w-28 items-center justify-center gap-2 rounded px-4 text-sm font-medium transition-colors"
                  style={{
                    background: active ? 'var(--rc-bg-elevated)' : 'transparent',
                    color: active ? 'var(--rc-text-1)' : 'var(--rc-text-3)',
                    boxShadow: active ? 'inset 0 0 0 1px var(--rc-border-2)' : 'none',
                  }}
                >
                  <Icon className="h-4 w-4" />
                  {label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {mode === 'security' ? <SecurityWorkspace /> : <AIWorkspace mode={mode} />}
    </div>
  );
}
