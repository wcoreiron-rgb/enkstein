'use client';

import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';

/**
 * Renders an overlay as a direct child of `document.body`.
 *
 * A `position: fixed` element is normally positioned against the viewport, but
 * an ancestor with `backdrop-filter`, `filter`, `transform`, `perspective`, or
 * `contain` establishes a containing block and clamps it to that ancestor's box
 * instead. Liquid Glass gives every card a `backdrop-filter`, so a drawer
 * rendered inside a card collapses to the card's bounds and reads as embedded
 * content rather than a sheet over the page.
 *
 * WebKit enforces this; Blink currently does not. The packaged desktop app is
 * WKWebView, so the bug is invisible in Chromium-based testing and visible to
 * every user. Escaping to `document.body` removes the ancestor entirely, which
 * fixes it in both engines rather than relying on either one's behaviour.
 */
export default function OverlayPortal({ children }: { children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return null;
  return createPortal(children, document.body);
}
