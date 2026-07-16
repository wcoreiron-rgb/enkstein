'use client';

import { FormEvent, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import QRCode from 'qrcode';
import { ArrowLeft, Check, Copy, KeyRound, Mail, ShieldCheck, Smartphone } from 'lucide-react';
import { getRememberedEmail, rememberEmail, setAuthToken } from '@/lib/auth';

const BASE = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/api/v1`
  : '/api/v1';

type View = 'loading' | 'setup' | 'enroll' | 'recovery-codes' | 'owner' | 'recovery' | 'email' | 'email-code';

const fieldStyle = {
  padding: '0.75rem 0.875rem', borderRadius: '0.5rem', border: '1px solid #cbd5e1',
  backgroundColor: '#ffffff', color: '#0f172a', fontSize: '0.9375rem', outline: 'none',
  width: '100%', boxSizing: 'border-box' as const,
};

async function responseDetail(response: Response, fallback: string): Promise<string> {
  try {
    const payload = await response.json();
    return typeof payload.detail === 'string' ? payload.detail : fallback;
  } catch { return fallback; }
}

export default function LoginPage() {
  const router = useRouter();
  const [view, setView] = useState<View>('loading');
  const [username, setUsername] = useState('owner');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [code, setCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [email, setEmail] = useState('');
  const [mailConfigured, setMailConfigured] = useState(false);
  const [enrollmentToken, setEnrollmentToken] = useState('');
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [manualSecret, setManualSecret] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [pendingAccessToken, setPendingAccessToken] = useState('');
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setEmail(getRememberedEmail());
    setUsername(localStorage.getItem('marcellus_owner_username') || 'owner');
    Promise.all([
      fetch(`${BASE}/auth/owner/status`, { cache: 'no-store' }).then(response => response.ok ? response.json() : null),
      fetch(`${BASE}/auth/email/status`, { cache: 'no-store' }).then(response => response.ok ? response.json() : null),
    ])
      .then(([owner, mail]) => {
        setMailConfigured(Boolean(mail?.enabled && mail?.delivery_configured));
        setView(owner?.setup_required ? 'setup' : 'owner');
      })
      .catch(() => { setError('Unable to reach the local Enkstein runtime.'); setView('owner'); });
  }, []);

  const finishLogin = (token: string) => {
    setAuthToken(token);
    router.replace('/dashboard');
  };

  const startSetup = async (event: FormEvent) => {
    event.preventDefault(); setError('');
    if (password !== passwordConfirm) { setError('Passwords do not match.'); return; }
    setLoading(true);
    try {
      const response = await fetch(`${BASE}/auth/owner/setup`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      if (!response.ok) { setError(await responseDetail(response, 'Unable to start owner setup.')); return; }
      const enrollment = await response.json();
      setEnrollmentToken(enrollment.enrollment_token);
      setManualSecret(enrollment.secret);
      setQrDataUrl(await QRCode.toDataURL(enrollment.otpauth_uri, { width: 220, margin: 1, errorCorrectionLevel: 'M' }));
      localStorage.setItem('marcellus_owner_username', username.trim());
      setCode(''); setView('enroll');
    } catch { setError('Unable to start owner setup.'); }
    finally { setLoading(false); }
  };

  const confirmSetup = async (event: FormEvent) => {
    event.preventDefault(); setError(''); setLoading(true);
    try {
      const response = await fetch(`${BASE}/auth/owner/setup/confirm`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enrollment_token: enrollmentToken, code }),
      });
      if (!response.ok) { setError(await responseDetail(response, 'Invalid Authenticator code.')); return; }
      const result = await response.json();
      setRecoveryCodes(result.recovery_codes || []);
      setPendingAccessToken(result.access_token);
      setView('recovery-codes');
    } catch { setError('Unable to confirm Authenticator enrollment.'); }
    finally { setLoading(false); }
  };

  const ownerLogin = async (event: FormEvent) => {
    event.preventDefault(); setError(''); setLoading(true);
    try {
      const response = await fetch(`${BASE}/auth/owner/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password, code }),
      });
      if (!response.ok) { setError(await responseDetail(response, 'Invalid owner credentials.')); return; }
      localStorage.setItem('marcellus_owner_username', username.trim());
      finishLogin((await response.json()).access_token);
    } catch { setError('Unable to sign in to the local runtime.'); }
    finally { setLoading(false); }
  };

  const recoveryLogin = async (event: FormEvent) => {
    event.preventDefault(); setError(''); setLoading(true);
    try {
      const response = await fetch(`${BASE}/auth/owner/recovery`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password, recovery_code: recoveryCode }),
      });
      if (!response.ok) { setError(await responseDetail(response, 'Invalid recovery credentials.')); return; }
      finishLogin((await response.json()).access_token);
    } catch { setError('Unable to use the recovery code.'); }
    finally { setLoading(false); }
  };

  const requestEmailCode = async (event: FormEvent) => {
    event.preventDefault(); setError(''); setLoading(true);
    try {
      const response = await fetch(`${BASE}/auth/email/request`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email.trim() }),
      });
      if (!response.ok) { setError(await responseDetail(response, 'Unable to send a sign-in code.')); return; }
      rememberEmail(email); setCode(''); setView('email-code');
    } catch { setError('Unable to reach Enkstein.'); }
    finally { setLoading(false); }
  };

  const verifyEmailCode = async (event: FormEvent) => {
    event.preventDefault(); setError(''); setLoading(true);
    try {
      const response = await fetch(`${BASE}/auth/email/verify`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email.trim(), code }),
      });
      if (!response.ok) { setError(await responseDetail(response, 'Invalid or expired sign-in code.')); return; }
      finishLogin((await response.json()).access_token);
    } catch { setError('Unable to verify the email code.'); }
    finally { setLoading(false); }
  };

  const copyRecoveryCodes = async () => {
    await navigator.clipboard.writeText(recoveryCodes.join('\n'));
    setCopied(true); setTimeout(() => setCopied(false), 1500);
  };

  const title = view === 'setup' ? 'Create the local owner' : view === 'enroll' ? 'Enroll Authenticator'
    : view === 'recovery-codes' ? 'Save recovery codes' : view === 'email' || view === 'email-code'
      ? 'Verified email access' : view === 'recovery' ? 'Owner recovery' : 'Unlock Enkstein';

  return (
    <main className="min-h-screen flex items-center justify-center bg-white p-4 text-slate-950">
      <section className="w-full max-w-sm border border-slate-200 bg-white p-7 shadow-sm" style={{ borderRadius: 8 }}>
        <header className="mb-7 text-center">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.png" alt="Enkstein" width={76} height={76} className="mx-auto mb-3" />
          <h1 className="text-xl font-semibold text-slate-950">{title}</h1>
          <p className="mt-1 text-sm text-slate-500">
            {view === 'setup' ? 'Secure this installation before the console opens.'
              : view === 'enroll' ? 'Scan once, then confirm the current code.'
                : view === 'recovery-codes' ? 'Each code works once. Store them offline.'
                  : 'The security runtime continues while this console is locked.'}
          </p>
        </header>

        {view === 'loading' && <div className="py-8 text-center text-sm text-slate-500">Checking local security state...</div>}

        {view === 'setup' && <form onSubmit={startSetup} className="space-y-4">
          <Field label="Owner username"><input required autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} style={fieldStyle} /></Field>
          <Field label="Owner password"><input type="password" required minLength={12} autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} style={fieldStyle} /><Hint>At least 12 characters. This stays encrypted on this Mac.</Hint></Field>
          <Field label="Confirm password"><input type="password" required minLength={12} autoComplete="new-password" value={passwordConfirm} onChange={e => setPasswordConfirm(e.target.value)} style={fieldStyle} /></Field>
          <Primary disabled={loading}>{loading ? 'Preparing enrollment...' : 'Continue to Authenticator'}</Primary>
        </form>}

        {view === 'enroll' && <form onSubmit={confirmSetup} className="space-y-4">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          {qrDataUrl && <img src={qrDataUrl} alt="Authenticator enrollment QR code" width={220} height={220} className="mx-auto border border-slate-200" />}
          <p className="break-all rounded-md bg-slate-50 p-2 text-center font-mono text-xs text-slate-600">{manualSecret}</p>
          <Field label="Current six-digit code"><CodeInput value={code} setValue={setCode} /></Field>
          <Primary disabled={loading || code.length !== 6}>{loading ? 'Confirming...' : 'Confirm and secure owner'}</Primary>
        </form>}

        {view === 'recovery-codes' && <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 font-mono text-sm text-amber-950">
            {recoveryCodes.map(value => <span key={value}>{value}</span>)}
          </div>
          <button type="button" onClick={copyRecoveryCodes} className="flex h-10 w-full items-center justify-center gap-2 border border-slate-300 text-sm font-medium text-slate-700" style={{ borderRadius: 6 }}>
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}{copied ? 'Copied' : 'Copy recovery codes'}
          </button>
          <Primary onClick={() => finishLogin(pendingAccessToken)}>I saved them, open Enkstein</Primary>
        </div>}

        {view === 'owner' && <form onSubmit={ownerLogin} className="space-y-4">
          <Field label="Owner username"><input required autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} style={fieldStyle} /></Field>
          <Field label="Password"><span className="relative block"><KeyRound className="absolute left-3 top-3.5 h-4 w-4 text-red-500" /><input type="password" required autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} style={{ ...fieldStyle, paddingLeft: '2.4rem' }} /></span></Field>
          <Field label="Authenticator code"><CodeInput value={code} setValue={setCode} /></Field>
          <Primary disabled={loading || code.length !== 6}>{loading ? 'Unlocking...' : 'Unlock Enkstein'}</Primary>
          <button type="button" onClick={() => { setView('recovery'); setError(''); }} className="w-full text-xs text-slate-500 hover:text-slate-800">Use a recovery code</button>
          {mailConfigured && <button type="button" onClick={() => { setView('email'); setError(''); }} className="flex w-full items-center justify-center gap-1 text-xs text-cyan-700"><Mail className="h-3 w-3" /> Email viewer sign-in</button>}
        </form>}

        {view === 'recovery' && <form onSubmit={recoveryLogin} className="space-y-4">
          <Field label="Owner username"><input required value={username} onChange={e => setUsername(e.target.value)} style={fieldStyle} /></Field>
          <Field label="Password"><input type="password" required value={password} onChange={e => setPassword(e.target.value)} style={fieldStyle} /></Field>
          <Field label="One-time recovery code"><input required value={recoveryCode} onChange={e => setRecoveryCode(e.target.value.toUpperCase())} placeholder="ABCD-1234" style={fieldStyle} /></Field>
          <Primary disabled={loading}>{loading ? 'Recovering...' : 'Use recovery code'}</Primary>
          <Back onClick={() => setView('owner')}>Authenticator sign-in</Back>
        </form>}

        {view === 'email' && <form onSubmit={requestEmailCode} className="space-y-4">
          <Field label="Email address"><span className="relative block"><Mail className="absolute left-3 top-3.5 h-4 w-4 text-cyan-600" /><input type="email" required autoComplete="email" value={email} onChange={e => setEmail(e.target.value)} style={{ ...fieldStyle, paddingLeft: '2.4rem' }} /></span></Field>
          <Primary disabled={loading}>{loading ? 'Sending...' : 'Email me a code'}</Primary>
          <Back onClick={() => setView('owner')}>Owner sign-in</Back>
        </form>}

        {view === 'email-code' && <form onSubmit={verifyEmailCode} className="space-y-4">
          <div className="flex gap-3 rounded-md border border-cyan-200 bg-cyan-50 p-3"><ShieldCheck className="h-5 w-5 shrink-0 text-cyan-700" /><p className="text-xs text-slate-700">Code sent to <strong>{email}</strong>.</p></div>
          <Field label="Email verification code"><CodeInput value={code} setValue={setCode} /></Field>
          <Primary disabled={loading || code.length !== 6}>{loading ? 'Verifying...' : 'Verify email'}</Primary>
          <Back onClick={() => setView('email')}>Use another email</Back>
        </form>}

        {error && <p role="alert" className="mt-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">{error}</p>}
      </section>
    </main>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="block space-y-1.5 text-sm text-slate-700"><span>{label}</span>{children}</label>;
}
function Hint({ children }: { children: React.ReactNode }) { return <span className="block text-xs text-slate-500">{children}</span>; }
function CodeInput({ value, setValue }: { value: string; setValue: (value: string) => void }) {
  return <span className="relative block"><Smartphone className="absolute left-3 top-3.5 h-4 w-4 text-red-500" /><input inputMode="numeric" autoComplete="one-time-code" required maxLength={6} pattern="[0-9]{6}" value={value} onChange={e => setValue(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="000000" className="text-center font-mono tracking-[0.3em]" style={{ ...fieldStyle, paddingLeft: '2.4rem' }} /></span>;
}
function Primary({ children, disabled, onClick }: { children: React.ReactNode; disabled?: boolean; onClick?: () => void }) {
  return <button type={onClick ? 'button' : 'submit'} onClick={onClick} disabled={disabled} className="h-11 w-full bg-red-600 font-medium text-white hover:bg-red-500 disabled:opacity-50" style={{ borderRadius: 6 }}>{children}</button>;
}
function Back({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return <button type="button" onClick={onClick} className="flex w-full items-center justify-center gap-1 text-xs text-slate-500 hover:text-slate-800"><ArrowLeft className="h-3 w-3" />{children}</button>;
}
