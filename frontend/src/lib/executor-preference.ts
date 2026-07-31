/** Which governed Executor Cowork should use for commands, tests, and
 * verification.
 *
 * This is deliberately independent of the Brain selection: a browser or local
 * Ollama Brain can author changes while the Enkstein Local Runtime verifies
 * them, and Codex is one executor among others rather than a requirement.
 *
 * "auto" prefers the local runtime and falls back to Codex. An explicit choice
 * is never silently rerouted -- if the chosen executor is unavailable the turn
 * reports the verification as unavailable instead of quietly using the other
 * one. Client-only preference, mirroring the runtime-group storage pattern. */
export type ExecutorPreference = 'auto' | 'enkstein_local' | 'codex_app_server';

const STORAGE_KEY = 'marcellus-executor-preference';
const VALID: readonly ExecutorPreference[] = ['auto', 'enkstein_local', 'codex_app_server'];

function isExecutorPreference(value: string): value is ExecutorPreference {
  return (VALID as readonly string[]).includes(value);
}

export function readStoredExecutorPreference(): ExecutorPreference {
  if (typeof window === 'undefined') return 'auto';
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored && isExecutorPreference(stored) ? stored : 'auto';
}

export function persistExecutorPreference(preference: ExecutorPreference): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(STORAGE_KEY, preference);
}
