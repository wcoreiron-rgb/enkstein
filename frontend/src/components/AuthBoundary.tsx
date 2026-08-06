'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Sidebar from '@/components/Sidebar';
import { BackgroundTurnsProvider } from '@/components/BackgroundTurns';
import { ExecutionOrb } from '@/components/ExecutionOrb';
import { clearAuthToken, CONSOLE_IDLE_TIMEOUT_MS, getAuthToken, lockConsole } from '@/lib/auth';

const BASE = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/api/v1`
  : '/api/v1';

function PreparingRuntime() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-white px-6 text-slate-950">
      <div className="text-center">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/enkstein-icon.png" alt="Enkstein" width={104} height={104} className="mx-auto mb-5" />
        <h1 className="text-2xl font-semibold">Enkstein</h1>
        {/* The launch screen is a fixed white surface regardless of the saved
            theme, so the orb is pinned to light ink rather than resolving a
            theme that has not been applied to this screen. */}
        <div className="mt-5 flex justify-center">
          <ExecutionOrb activity="planning" size={64} theme="light" scale={112} />
        </div>
        <p className="mt-3 text-sm text-slate-500">Preparing the Enkstein runtime...</p>
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
    // The provider sits above both the sidebar and the routed page, so a turn
    // it owns survives every client-side navigation between them.
    <BackgroundTurnsProvider>
      <div className="flex min-h-screen">
        <Sidebar />
        <main className="flex-1 overflow-auto p-8">{children}</main>
      </div>
    </BackgroundTurnsProvider>
  );
}
