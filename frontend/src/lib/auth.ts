export const AUTH_TOKEN_KEY = 'marcellus_session_token';
export const REMEMBERED_EMAIL_KEY = 'marcellus_remembered_email';
export const CONSOLE_IDLE_TIMEOUT_MS = 30 * 60 * 1000;

export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;
  return window.sessionStorage.getItem(AUTH_TOKEN_KEY);
}

export function setAuthToken(token: string): void {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem('rc_token');
  window.sessionStorage.setItem(AUTH_TOKEN_KEY, token);
}

export function clearAuthToken(): void {
  if (typeof window === 'undefined') return;
  window.sessionStorage.removeItem(AUTH_TOKEN_KEY);
  window.localStorage.removeItem('rc_token');
}

export function lockConsole(): void {
  clearAuthToken();
  if (typeof window !== 'undefined') window.location.replace('/login');
}

export function getRememberedEmail(): string {
  if (typeof window === 'undefined') return '';
  return window.localStorage.getItem(REMEMBERED_EMAIL_KEY) || '';
}

export function rememberEmail(email: string): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(REMEMBERED_EMAIL_KEY, email.trim().toLowerCase());
}
