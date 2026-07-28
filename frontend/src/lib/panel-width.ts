const STORAGE_KEY = 'enkstein-cowork-panel-width';

export const MIN_PANEL_WIDTH = 260;
export const MAX_PANEL_WIDTH = 900;
export const DEFAULT_PANEL_WIDTH = 320;

export function clampPanelWidth(width: number): number {
  if (!Number.isFinite(width)) return DEFAULT_PANEL_WIDTH;
  return Math.min(MAX_PANEL_WIDTH, Math.max(MIN_PANEL_WIDTH, Math.round(width)));
}

/** Reads the user's chosen width for the Cowork project/review panel. Client-only,
 * like the runtime-group preference: it is a viewport layout choice, not tenant state. */
export function readStoredPanelWidth(): number {
  if (typeof window === 'undefined') return DEFAULT_PANEL_WIDTH;
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (!stored) return DEFAULT_PANEL_WIDTH;
  const parsed = Number.parseInt(stored, 10);
  return Number.isNaN(parsed) ? DEFAULT_PANEL_WIDTH : clampPanelWidth(parsed);
}

export function persistPanelWidth(width: number): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(STORAGE_KEY, String(clampPanelWidth(width)));
}
