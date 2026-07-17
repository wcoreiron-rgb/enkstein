export type RuntimeGroup = 'local' | 'hybrid' | 'cloud';

const STORAGE_KEY = 'marcellus-runtime-group';
const VALID_GROUPS: readonly RuntimeGroup[] = ['local', 'hybrid', 'cloud'];

function isRuntimeGroup(value: string): value is RuntimeGroup {
  return (VALID_GROUPS as readonly string[]).includes(value);
}

/** Reads the user's last-selected runtime group. This is a client-only
 * preference: there is no compatible existing storage column on
 * CortexConversation/CortexProject to persist it per conversation/project
 * without a schema migration, so each turn resends it explicitly and
 * "hybrid" (the legacy default) applies whenever nothing was ever chosen. */
export function readStoredRuntimeGroup(): RuntimeGroup {
  if (typeof window === 'undefined') return 'hybrid';
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored && isRuntimeGroup(stored) ? stored : 'hybrid';
}

export function persistRuntimeGroup(group: RuntimeGroup): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(STORAGE_KEY, group);
}
