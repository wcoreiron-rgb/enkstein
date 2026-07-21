'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

/** Copies text to the clipboard, preferring the async Clipboard API and
 * falling back to a hidden textarea + execCommand for browsers/contexts
 * where it's unavailable (the same fallback CodeBlock already used). Returns
 * a transient `copied` flag that clears itself after 2 seconds, so callers
 * can swap an icon/label without managing their own timer.
 */
export function useCopyToClipboard(): { copied: boolean; copy: (text: string) => Promise<void> } {
  const [copied, setCopied] = useState(false);
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (resetTimer.current) clearTimeout(resetTimer.current);
  }, []);

  const copy = useCallback(async (text: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'absolute';
        area.style.left = '-9999px';
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        document.body.removeChild(area);
      }
      setCopied(true);
      if (resetTimer.current) clearTimeout(resetTimer.current);
      resetTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      /* Clipboard was denied; leave the control in its idle state. */
    }
  }, []);

  return { copied, copy };
}
