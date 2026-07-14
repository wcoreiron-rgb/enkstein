'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Sidebar from '@/components/Sidebar';
import { clearAuthToken, CONSOLE_IDLE_TIMEOUT_MS, getAuthToken, lockConsole } from '@/lib/auth';

const BASE = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/api/v1`
  : '/api/v1';

function PreparingRuntime() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-white px-6 text-slate-950">
      <div className="text-center">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/logo.png" alt="Marcellus" width={104} height={104} className="mx-auto mb-5" />
        <h1 className="text-2xl font-semibold">Marcellus</h1>
        <div className="mx-auto mt-5 h-5 w-5 animate-spin rounded-full border-2 border-slate-200 border-t-red-600" aria-hidden="true" />
        <p className="mt-3 text-sm text-slate-500">Preparing the Marcellus runtime...</p>
      </div>
    </main>
  );
}

export default function AuthBoundary({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [authorized, setAuthorized] = useState(false);
  const isLogin = pathname === '/login';

  useEffect(() => {
    let cancelled = false;
    window.localStorage.removeItem('rc_token');

    if (isLogin) {
      clearAuthToken();
      setAuthorized(false);
      return () => { cancelled = true; };
    }

    const token = getAuthToken();
    if (!token) {
      router.replace('/login');
      return () => { cancelled = true; };
    }

    setAuthorized(false);
    fetch(`${BASE}/auth/me`, {
      cache: 'no-store',
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(response => {
        if (!response.ok) throw new Error('Session is not valid');
        if (!cancelled) setAuthorized(true);
      })
      .catch(() => {
        clearAuthToken();
        if (!cancelled) router.replace('/login');
      });

    return () => { cancelled = true; };
  }, [isLogin, router]);

  useEffect(() => {
    if (!authorized || isLogin) return;
    let lastActivity = Date.now();
    let timer: ReturnType<typeof setTimeout>;
    const schedule = () => {
      clearTimeout(timer);
      timer = setTimeout(lockConsole, Math.max(0, CONSOLE_IDLE_TIMEOUT_MS - (Date.now() - lastActivity)));
    };
    const active = () => { lastActivity = Date.now(); schedule(); };
    const visible = () => {
      if (document.visibilityState === 'visible' && Date.now() - lastActivity >= CONSOLE_IDLE_TIMEOUT_MS) lockConsole();
    };
    const events: Array<keyof WindowEventMap> = ['pointerdown', 'keydown', 'wheel', 'touchstart'];
    events.forEach(event => window.addEventListener(event, active, { passive: true }));
    window.addEventListener('marcellus:lock', lockConsole);
    document.addEventListener('visibilitychange', visible);
    schedule();
    return () => {
      clearTimeout(timer);
      events.forEach(event => window.removeEventListener(event, active));
      window.removeEventListener('marcellus:lock', lockConsole);
      document.removeEventListener('visibilitychange', visible);
    };
  }, [authorized, isLogin]);

  if (isLogin) return <>{children}</>;
  if (!authorized) return <PreparingRuntime />;

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 overflow-auto p-8">{children}</main>
    </div>
  );
}
