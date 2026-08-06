'use client';

/** Turns that keep running after you navigate away.
 *
 * A governed turn used to be owned by the workspace page component, so opening
 * another conversation unmounted it and the in-flight request was abandoned:
 * the backend finished and persisted the reply, but nothing on screen ever
 * showed it and the operator had no way to know it was still working.
 *
 * This provider lives above the router in AuthBoundary, so it survives every
 * client-side navigation. It owns the request, its abort handle, and its live
 * activity, and hands them back to whichever workspace instance is mounted on
 * that conversation. Nothing about the governed turn itself changes here --
 * routing, policy, and persistence stay entirely server-side. This only moves
 * who holds the promise. */

import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import type { ExecutionActivity } from '@/components/ExecutionOrb';

export type BackgroundTurnStatus = 'running' | 'completed' | 'failed';

export type BackgroundTurn = {
  conversationId: string;
  /** Which workspace the turn belongs to, so a dot can be shown on the right
   *  mode even when the conversation itself is not in the visible list. */
  mode: 'chat' | 'cowork' | 'security';
  /** Cowork conversations cannot be addressed without their project. */
  projectId?: string | null;
  /** Operator-visible conversation title at the time the turn started. */
  title: string;
  status: BackgroundTurnStatus;
  /** Newest stage the runtime actually reported, used for the orb. */
  activity: ExecutionActivity;
  /** Newest human-readable step label. */
  label: string;
  startedAt: number;
  /** Set only once the turn settles, so a finished turn can be marked as
   *  unseen until its conversation is opened. */
  finishedAt?: number;
  /** Failure detail, already safe for display (the backend redacts). */
  detail?: string;
  /** True until the operator opens the conversation after it settles. */
  unread: boolean;
};

type BackgroundTurnsApi = {
  turns: BackgroundTurn[];
  running: BackgroundTurn[];
  /** Settled turns the operator has not looked at yet. */
  unread: BackgroundTurn[];
  get: (conversationId: string) => BackgroundTurn | undefined;
  start: (turn: {
    conversationId: string;
    mode: BackgroundTurn['mode'];
    projectId?: string | null;
    title: string;
    controller: AbortController;
  }) => void;
  progress: (conversationId: string, activity: ExecutionActivity, label: string) => void;
  settle: (conversationId: string, status: 'completed' | 'failed', detail?: string) => void;
  /** Called when a workspace mounts on this conversation, clearing its dot. */
  acknowledge: (conversationId: string) => void;
  /** Operator-requested stop. Aborts the owned request. */
  cancel: (conversationId: string) => void;
  /** Drops a settled turn from the tray entirely. */
  dismiss: (conversationId: string) => void;
};

const BackgroundTurnsContext = createContext<BackgroundTurnsApi | null>(null);

export function BackgroundTurnsProvider({ children }: { children: React.ReactNode }) {
  const [turns, setTurns] = useState<BackgroundTurn[]>([]);
  // Abort handles are refs, not state: aborting must not depend on a render
  // having flushed, and a controller is not renderable data.
  const controllers = useRef<Map<string, AbortController>>(new Map());

  const start = useCallback<BackgroundTurnsApi['start']>(({ conversationId, mode, projectId, title, controller }) => {
    controllers.current.set(conversationId, controller);
    setTurns((current) => [
      ...current.filter((turn) => turn.conversationId !== conversationId),
      {
        conversationId,
        mode,
        projectId: projectId ?? null,
        title,
        status: 'running',
        activity: 'planning',
        label: 'Planning governed turn',
        startedAt: Date.now(),
        unread: false,
      },
    ]);
  }, []);

  const progress = useCallback<BackgroundTurnsApi['progress']>((conversationId, activity, label) => {
    setTurns((current) => current.map((turn) => (
      turn.conversationId === conversationId && turn.status === 'running'
        ? { ...turn, activity, label }
        : turn
    )));
  }, []);

  const settle = useCallback<BackgroundTurnsApi['settle']>((conversationId, status, detail) => {
    controllers.current.delete(conversationId);
    setTurns((current) => current.map((turn) => (
      turn.conversationId === conversationId
        // Only a turn the operator is not currently watching becomes unread;
        // the workspace acknowledges its own conversation on mount.
        ? { ...turn, status, detail, finishedAt: Date.now(), unread: true }
        : turn
    )));
  }, []);

  const acknowledge = useCallback<BackgroundTurnsApi['acknowledge']>((conversationId) => {
    setTurns((current) => {
      // Returning the same array when nothing changed is load-bearing: the
      // workspace acknowledges from an effect keyed on the active
      // conversation, and a fresh array every time would re-run that effect
      // forever.
      const target = current.find((turn) => turn.conversationId === conversationId);
      if (!target) return current;
      // A settled turn the operator has now seen has nothing left to report,
      // so it leaves the tray rather than lingering as a read entry.
      if (target.status !== 'running') {
        return current.filter((turn) => turn.conversationId !== conversationId);
      }
      if (!target.unread) return current;
      return current.map((turn) => (
        turn.conversationId === conversationId ? { ...turn, unread: false } : turn
      ));
    });
  }, []);

  const cancel = useCallback<BackgroundTurnsApi['cancel']>((conversationId) => {
    controllers.current.get(conversationId)?.abort();
    controllers.current.delete(conversationId);
    setTurns((current) => current.filter((turn) => turn.conversationId !== conversationId));
  }, []);

  const dismiss = useCallback<BackgroundTurnsApi['dismiss']>((conversationId) => {
    setTurns((current) => current.filter((turn) => turn.conversationId !== conversationId));
  }, []);

  const value = useMemo<BackgroundTurnsApi>(() => ({
    turns,
    running: turns.filter((turn) => turn.status === 'running'),
    unread: turns.filter((turn) => turn.status !== 'running' && turn.unread),
    get: (conversationId) => turns.find((turn) => turn.conversationId === conversationId),
    start,
    progress,
    settle,
    acknowledge,
    cancel,
    dismiss,
  }), [turns, start, progress, settle, acknowledge, cancel, dismiss]);

  return <BackgroundTurnsContext.Provider value={value}>{children}</BackgroundTurnsContext.Provider>;
}

/** Returns null outside the provider, so a surface rendered on the login route
 *  (which has no provider above it) can degrade rather than throw. */
export function useBackgroundTurns(): BackgroundTurnsApi | null {
  return useContext(BackgroundTurnsContext);
}
