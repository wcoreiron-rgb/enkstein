'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { resolveLegacyWorkspacePath } from '@/lib/workspace-routes';

/** `/marcellus` and `/marcellus#chat|cowork|security` are the pre-route
 * -addressable URLs. Old bookmarks must keep working, so this replaces them
 * with the stable path instead of rendering a workspace itself. */
export default function LegacyEnksteinPage() {
  const router = useRouter();

  useEffect(() => {
    router.replace(resolveLegacyWorkspacePath(window.location.hash));
  }, [router]);

  return null;
}
