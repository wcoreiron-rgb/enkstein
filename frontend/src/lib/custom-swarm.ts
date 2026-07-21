const STORAGE_KEY = 'marcellus-custom-swarm';

/** Reads the user's last-built custom swarm selection. Client-only, same
 * rationale as runtime-group.ts: there is no compatible existing storage
 * column to persist this per conversation/project without a schema
 * migration, so each turn resends the explicit source list and this is
 * only a convenience default for the next time the picker opens. */
export function readStoredCustomSwarm(): string[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
  } catch {
    return [];
  }
}

export function persistCustomSwarm(sources: string[]): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(sources));
}
