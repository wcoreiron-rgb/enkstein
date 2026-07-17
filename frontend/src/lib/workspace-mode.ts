export type WorkspaceMode = 'chat' | 'cowork' | 'security';

const STORAGE_KEY = 'marcellus-workspace-mode';
const VALID_MODES: readonly WorkspaceMode[] = ['chat', 'cowork', 'security'];

/** Fired whenever the workspace mode is persisted in this tab. A same-page
 * mode switch calls the History API's pushState directly (see
 * pushWorkspaceModeState), which — unlike a real navigation or the
 * back/forward buttons — never fires the native "hashchange" event. Anything
 * that needs to react immediately to an in-tab mode switch (not just a
 * cross-tab "storage" event or a real navigation) must listen for this. */
export const WORKSPACE_MODE_EVENT = 'marcellus:workspace-mode-changed';

function isWorkspaceMode(value: string): value is WorkspaceMode {
  return (VALID_MODES as readonly string[]).includes(value);
}

function readHashMode(): WorkspaceMode | null {
  if (typeof window === 'undefined') return null;
  const value = window.location.hash.slice(1).toLowerCase();
  return isWorkspaceMode(value) ? value : null;
}

export function readStoredWorkspaceMode(): WorkspaceMode | null {
  if (typeof window === 'undefined') return null;
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored && isWorkspaceMode(stored) ? stored : null;
}

export function persistWorkspaceMode(mode: WorkspaceMode): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(STORAGE_KEY, mode);
  window.dispatchEvent(new CustomEvent<WorkspaceMode>(WORKSPACE_MODE_EVENT, { detail: mode }));
}

/** Resolves the active workspace mode: URL hash takes priority, then the last
 * remembered mode, then the default. Used so refresh/relaunch restores the
 * same workspace even if the hash is missing. */
export function resolveWorkspaceMode(defaultMode: WorkspaceMode = 'chat'): WorkspaceMode {
  return readHashMode() || readStoredWorkspaceMode() || defaultMode;
}

/** Normalizes the URL hash to match the resolved mode without adding a
 * history entry, so back/forward navigation is not polluted by silent
 * normalization on load. */
export function syncWorkspaceHash(mode: WorkspaceMode): void {
  if (typeof window === 'undefined') return;
  if (readHashMode() === mode) return;
  const url = `${window.location.pathname}${window.location.search}#${mode}`;
  window.history.replaceState(window.history.state, '', url);
}

/** Switches the workspace mode while already on `/marcellus`: pushes a new
 * history entry for the `#mode` hash directly via the History API, persists
 * the mode, and notifies listeners via WORKSPACE_MODE_EVENT. Deliberately
 * bypasses Next's Link/router — a same-page hash-only Link is treated by
 * Next as a real navigation and can redirect or abort mid-flight instead of
 * just updating the hash. Callers on a different page should use Next
 * router navigation to `/marcellus#mode` instead, since this only updates
 * the URL bar without mounting the workspace page. */
export function pushWorkspaceModeState(mode: WorkspaceMode): void {
  if (typeof window === 'undefined') return;
  if (readHashMode() !== mode) {
    const url = `${window.location.pathname}${window.location.search}#${mode}`;
    window.history.pushState(window.history.state, '', url);
  }
  persistWorkspaceMode(mode);
}
