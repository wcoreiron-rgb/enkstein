'use client';

/** Sidebar tray for turns still running elsewhere in the app.
 *
 * Each running turn shows a live orb whose shape encodes the stage the runtime
 * actually reported, so "waiting on a Brain" looks different from "writing
 * files". A settled turn stays until its conversation is opened, so a reply
 * that arrived while the operator was somewhere else is never missed. */

import Link from 'next/link';
import { AlertTriangle, CheckCircle2, X } from 'lucide-react';
import { ExecutionOrb } from '@/components/ExecutionOrb';
import { useBackgroundTurns } from '@/components/BackgroundTurns';
import type { BackgroundTurn } from '@/components/BackgroundTurns';
import { workspaceRoutePath } from '@/lib/workspace-routes';

const MODE_LABEL: Record<BackgroundTurn['mode'], string> = {
  chat: 'Chat',
  cowork: 'Cowork',
  security: 'Security',
};

function turnHref(turn: BackgroundTurn): string {
  return workspaceRoutePath(turn.mode, {
    projectId: turn.projectId,
    conversationId: turn.conversationId,
  });
}

export default function BackgroundTurnTray() {
  const background = useBackgroundTurns();
  const turns = background?.turns ?? [];
  if (!background || turns.length === 0) return null;

  return (
    <div className="border-t px-3 py-3" style={{ borderColor: 'var(--rc-border)' }} data-testid="background-turn-tray">
      <p className="px-1 pb-1.5 text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>
        Running elsewhere
      </p>
      <ul className="space-y-1">
        {turns.map((turn) => (
          <li key={turn.conversationId}>
            <div className="flex items-center gap-2 rounded-md px-1.5 py-1.5" style={{ background: 'var(--rc-bg-elevated)' }}>
              <span className="flex h-5 w-5 shrink-0 items-center justify-center">
                {turn.status === 'running' ? (
                  <ExecutionOrb activity={turn.activity} size={20} />
                ) : turn.status === 'completed' ? (
                  <CheckCircle2 className="h-4 w-4" style={{ color: '#16a34a' }} aria-hidden="true" />
                ) : (
                  <AlertTriangle className="h-4 w-4" style={{ color: '#d97706' }} aria-hidden="true" />
                )}
              </span>
              <Link href={turnHref(turn)} className="min-w-0 flex-1" title={turn.detail || turn.label}>
                <span className="block truncate text-xs" style={{ color: 'var(--rc-text-1)' }}>{turn.title}</span>
                <span className="block truncate text-[10px]" style={{ color: 'var(--rc-text-3)' }}>
                  {MODE_LABEL[turn.mode]} · {turn.status === 'running'
                    ? turn.label
                    : turn.status === 'completed' ? 'Reply ready' : (turn.detail || 'Turn failed')}
                </span>
              </Link>
              <button
                type="button"
                onClick={() => (turn.status === 'running'
                  ? background.cancel(turn.conversationId)
                  : background.dismiss(turn.conversationId))}
                title={turn.status === 'running' ? 'Stop this turn' : 'Dismiss'}
                aria-label={turn.status === 'running'
                  ? `Stop the running turn in ${turn.title}`
                  : `Dismiss the finished turn in ${turn.title}`}
                className="flex h-5 w-5 shrink-0 items-center justify-center rounded"
                style={{ color: 'var(--rc-text-3)' }}
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
