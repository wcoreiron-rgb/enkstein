/**
 * Enkstein useWebSocket hook
 *
 * Maintains a persistent WebSocket connection to the backend live feed.
 * Features:
 *  - Exponential back-off reconnection (1s → 2s → 4s … capped at 30s)
 *  - Max 10 reconnect attempts before giving up (status: 'failed')
 *  - Connection states: 'connecting' | 'connected' | 'disconnected' | 'failed'
 *  - Heartbeat ping every 30s to detect stale connections
 *  - Manual reconnect via returned `reconnect()` function
 *  - Wildcard subscribers (register with event type '*')
 *
 * Usage:
 *   const { status, lastEvent, reconnectCount, reconnect, subscribe } = useWebSocket();
 *
 *   // Listen for a specific event type
 *   subscribe('dashboard.refresh', () => refetchStats());
 *   subscribe('finding.created',   (data) => showToast(data));
 *   subscribe('workflow.completed', (data) => console.log(data));
 *
 * Event types emitted by the backend:
 *   connected         — welcome on connect
 *   ping              — server keepalive (ignored by this hook)
 *   finding.created   — new finding ingested
 *   finding.updated   — existing finding escalated
 *   agent.run_completed
 *   workflow.step
 *   workflow.completed
 *   dashboard.refresh — generic "re-fetch everything" signal
 */
'use client';

import { useEffect, useRef, useCallback, useState } from 'react';
import { getAuthToken } from '@/lib/auth';

type WSEvent = { type: string; timestamp: string; data: Record<string, unknown> };
type Handler = (data: Record<string, unknown>) => void;
export type WSStatus = 'connecting' | 'connected' | 'disconnected' | 'failed';

// The backend WebSocket URL.
// Next does not forward WS upgrades, so the browser connects to the backend
// port directly. The packaged launcher picks a free port at start time rather
// than always using 8000, so the port is discovered from /api/runtime-config
// (see `resolveWsPort`) instead of being assumed. For a hosted deployment,
// set NEXT_PUBLIC_WS_URL to the load balancer.
let discoveredWsPort: string | null = null;

export async function resolveWsPort(): Promise<void> {
  if (discoveredWsPort || process.env.NEXT_PUBLIC_WS_URL) return;
  try {
    const response = await fetch('/api/runtime-config', { cache: 'no-store' });
    if (!response.ok) return;
    const config = await response.json();
    if (typeof config?.wsPort === 'string') discoveredWsPort = config.wsPort;
  } catch {
    // Fall back to the default port below; a failed lookup must not stop the
    // console from loading.
  }
}

const getWebSocketConnection = (): { url: string; protocols?: string[] } => {
  const scheme = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss' : 'ws';
  const port = discoveredWsPort || '8000';
  const url = process.env.NEXT_PUBLIC_WS_URL ||
    (typeof window !== 'undefined'
      ? `${scheme}://${window.location.hostname}:${port}/api/v1/ws`
      : `ws://localhost:${port}/api/v1/ws`);
  if (typeof window === 'undefined') return { url };
  const token = getAuthToken();
  return token
    ? { url, protocols: ['marcellus-auth', token] }
    : { url };
};

const INITIAL_DELAY    = 1_000;   // 1 s first retry
const MAX_DELAY        = 30_000;  // 30 s cap
const BACKOFF_FACTOR   = 2;
const MAX_ATTEMPTS     = 10;
const HEARTBEAT_MS     = 30_000;  // 30 s ping interval

export interface UseWebSocketReturn {
  /** Connection status */
  status: WSStatus;
  /** True when the WS connection is currently open (convenience alias) */
  connected: boolean;
  /** The most recently received event (any type) */
  lastEvent: WSEvent | null;
  /** How many times we've attempted to reconnect since last successful connect */
  reconnectCount: number;
  /** Force an immediate reconnect (resets back-off and attempt counter) */
  reconnect: () => void;
  /**
   * Register a handler for a specific event type.
   * Returns an unsubscribe function — call it from a useEffect cleanup.
   */
  subscribe: (eventType: string, handler: Handler) => () => void;
}

export function useWebSocket(): UseWebSocketReturn {
  const [status, setStatus]               = useState<WSStatus>('connecting');
  const [lastEvent, setLastEvent]         = useState<WSEvent | null>(null);
  const [reconnectCount, setReconnectCount] = useState(0);

  // Map of eventType → Set<Handler>
  const handlersRef   = useRef<Map<string, Set<Handler>>>(new Map());
  const wsRef         = useRef<WebSocket | null>(null);
  const delayRef      = useRef(INITIAL_DELAY);
  const attemptsRef   = useRef(0);
  const timerRef      = useRef<ReturnType<typeof setTimeout> | null>(null);
  const heartbeatRef  = useRef<ReturnType<typeof setInterval> | null>(null);
  const unmountedRef  = useRef(false);
  // Distinguishes intentional close (unmount / manual reconnect) from unexpected drops
  const intentionalRef = useRef(false);

  const clearHeartbeat = () => {
    if (heartbeatRef.current) {
      clearInterval(heartbeatRef.current);
      heartbeatRef.current = null;
    }
  };

  const startHeartbeat = (ws: WebSocket) => {
    clearHeartbeat();
    heartbeatRef.current = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({ type: 'ping' }));
        } catch {
          // socket gone — onclose will handle reconnect
        }
      }
    }, HEARTBEAT_MS);
  };

  const connect = useCallback(() => {
    if (unmountedRef.current) return;

    setStatus('connecting');

    // Learn the launcher's chosen backend port before the first dial. Resolves
    // immediately once known, so reconnects are not delayed.
    void resolveWsPort().then(() => {
    if (unmountedRef.current) return;
    try {
      const connection = getWebSocketConnection();
      const ws = connection.protocols
        ? new WebSocket(connection.url, connection.protocols)
        : new WebSocket(connection.url);
      wsRef.current = ws;
      intentionalRef.current = false;

      ws.onopen = () => {
        if (unmountedRef.current) { ws.close(); return; }
        setStatus('connected');
        delayRef.current  = INITIAL_DELAY;
        attemptsRef.current = 0;
        setReconnectCount(0);
        startHeartbeat(ws);
      };

      ws.onmessage = (ev) => {
        if (unmountedRef.current) return;
        try {
          const event: WSEvent = JSON.parse(ev.data);
          if (event.type === 'ping' || event.type === 'pong') return;

          setLastEvent(event);

          // Fan-out to registered handlers
          const handlers = handlersRef.current.get(event.type);
          if (handlers) {
            handlers.forEach((h) => {
              try { h(event.data); } catch { /* never crash the connection */ }
            });
          }

          // Also fire wildcard handlers (registered as '*')
          const wildcards = handlersRef.current.get('*');
          if (wildcards) {
            wildcards.forEach((h) => {
              try { h(event.data); } catch { /* noop */ }
            });
          }
        } catch {
          // malformed JSON — ignore
        }
      };

      ws.onerror = () => {
        // onclose fires immediately after; we handle state there
      };

      ws.onclose = () => {
        clearHeartbeat();
        wsRef.current = null;

        // If unmounted or intentional close, don't reconnect
        if (unmountedRef.current || intentionalRef.current) {
          if (!unmountedRef.current) setStatus('disconnected');
          return;
        }

        setStatus('disconnected');

        // Check max attempts
        attemptsRef.current += 1;
        if (attemptsRef.current > MAX_ATTEMPTS) {
          setStatus('failed');
          return;
        }

        setReconnectCount(attemptsRef.current);

        // Exponential back-off
        const delay = delayRef.current;
        delayRef.current = Math.min(delay * BACKOFF_FACTOR, MAX_DELAY);
        timerRef.current = setTimeout(connect, delay);
      };
    } catch {
      // WebSocket constructor can throw in SSR / non-browser environments
    }
    });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Manual reconnect — resets everything and connects immediately
  const reconnect = useCallback(() => {
    if (timerRef.current) { clearTimeout(timerRef.current); timerRef.current = null; }
    clearHeartbeat();
    intentionalRef.current = true;
    wsRef.current?.close();
    delayRef.current    = INITIAL_DELAY;
    attemptsRef.current = 0;
    setReconnectCount(0);
    // Small tick so intentionalRef is read in the onclose before we reset it
    setTimeout(() => {
      intentionalRef.current = false;
      connect();
    }, 50);
  }, [connect]);

  useEffect(() => {
    unmountedRef.current = false;
    connect();

    return () => {
      unmountedRef.current = true;
      intentionalRef.current = true;
      if (timerRef.current) clearTimeout(timerRef.current);
      clearHeartbeat();
      wsRef.current?.close();
    };
  }, [connect]);

  const subscribe = useCallback((eventType: string, handler: Handler): (() => void) => {
    if (!handlersRef.current.has(eventType)) {
      handlersRef.current.set(eventType, new Set());
    }
    handlersRef.current.get(eventType)!.add(handler);

    return () => {
      handlersRef.current.get(eventType)?.delete(handler);
    };
  }, []);

  return {
    status,
    connected: status === 'connected',
    lastEvent,
    reconnectCount,
    reconnect,
    subscribe,
  };
}
