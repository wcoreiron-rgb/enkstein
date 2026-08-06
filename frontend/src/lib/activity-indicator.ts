/** Which activity indicator the execution timeline draws.
 *
 * "orb" paints a canvas animation whose shape encodes the stage in flight --
 * waiting on a Brain looks different from tokens actually arriving. "spinner"
 * is the original single rotating glyph, kept as a first-class choice rather
 * than a fallback so the orbs can be turned off without a rebuild.
 *
 * Client-only preference, mirroring the executor-preference storage pattern.
 * Nothing about the governed turn changes with this setting; it is presentation
 * only, and the step labels are identical either way. */
export type ActivityIndicator = 'orb' | 'spinner';

const STORAGE_KEY = 'enkstein-activity-indicator';
const VALID: readonly ActivityIndicator[] = ['orb', 'spinner'];

function isActivityIndicator(value: string): value is ActivityIndicator {
  return (VALID as readonly string[]).includes(value);
}

export function readStoredActivityIndicator(): ActivityIndicator {
  if (typeof window === 'undefined') return 'orb';
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored && isActivityIndicator(stored) ? stored : 'orb';
}

export function persistActivityIndicator(indicator: ActivityIndicator): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(STORAGE_KEY, indicator);
}
