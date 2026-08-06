'use client';

import dynamic from 'next/dynamic';
import { useEffect, useState } from 'react';
import type { OrbSize, OrbState, OrbTheme } from 'thinking-orbs';

/** Canvas-backed activity indicator, loaded only in the browser.
 *
 * The orb paints to a canvas and resolves the theme from the DOM, so there is
 * nothing meaningful to prerender and a server render would only produce a
 * blank element that flashes on hydration. */
const ThinkingOrb = dynamic(
  () => import('thinking-orbs').then((module) => module.ThinkingOrb),
  { ssr: false, loading: () => <OrbFallback /> },
);

/** The activity an orb depicts.
 *
 * These are Enkstein's own stages, not the library's vocabulary. Each one maps
 * to a state the runtime genuinely reports -- a turn is never shown as
 * "searching" because searching looks good on screen. */
export type ExecutionActivity =
  | 'planning'
  | 'gathering-context'
  | 'waiting-on-brain'
  | 'streaming'
  | 'writing-files'
  | 'verifying'
  | 'consensus';

/** Enkstein activity to shipped orb state.
 *
 * The mapping is deliberately not one-to-one with the library's nine states:
 * an Enkstein stage that has no honest analogue reuses a neighbouring one
 * rather than inventing a distinct animation that implies work nobody is
 * doing. */
const ACTIVITY_ORB: Record<ExecutionActivity, OrbState> = {
  // Deciding route, classification, and which Brains are eligible.
  planning: 'solving',
  // Context Compiler ranking and reading approved files.
  'gathering-context': 'searching',
  // Prompt has left Enkstein; the provider has not started returning tokens.
  'waiting-on-brain': 'breathing',
  // Tokens are actually arriving.
  streaming: 'composing',
  // The deterministic writer is touching the approved project root.
  'writing-files': 'shaping',
  // Executor running commands or tests after a write.
  verifying: 'working',
  // More than one Brain is answering and the judge is comparing them.
  consensus: 'connecting',
};

/** Screen-reader text. The orb is decorative on its own; the surrounding row
 * already carries the human-readable label, so this only has to name the
 * stage for a reader that lands on the graphic itself. */
const ACTIVITY_LABEL: Record<ExecutionActivity, string> = {
  planning: 'Planning the governed turn',
  'gathering-context': 'Gathering workspace context',
  'waiting-on-brain': 'Waiting for the Brain to respond',
  streaming: 'Receiving the response',
  'writing-files': 'Writing files to the project folder',
  verifying: 'Verifying the result',
  consensus: 'Comparing Brain results',
};

function OrbFallback({ size = 20 }: { size?: OrbSize }) {
  return <span aria-hidden="true" style={{ display: 'inline-block', width: size, height: size }} />;
}

/** True when the user has asked for reduced motion.
 *
 * A perpetually animating canvas is exactly what that setting exists to stop,
 * so the orb freezes on a single frame rather than being removed -- the state
 * it encodes is still information, and dropping it would lose meaning. */
function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(query.matches);
    const onChange = (event: MediaQueryListEvent) => setReduced(event.matches);
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);
  return reduced;
}

export function ExecutionOrb({
  activity,
  size = 20,
  paused = false,
  theme = 'auto',
  scale,
}: {
  activity: ExecutionActivity;
  size?: OrbSize;
  /** Freeze on the current frame, for a stage that has stopped advancing. */
  paused?: boolean;
  /** Defaults to resolving the host theme. Pin this only on a surface whose
   * background is fixed regardless of the saved theme, such as the launch
   * screen, where auto-detection would resolve a theme that screen is not
   * actually using. */
  theme?: OrbTheme;
  /** Rendered width in CSS pixels, overriding the preset's own size.
   *
   * The library ships two tuned presets, 64 and 20, and 64 is small next to
   * the 104px mark on the launch screen. The art is drawn with paths rather
   * than sampled from a bitmap, so painting the 64 preset into a larger box
   * stays crisp; only the tuning (dot count, speed) is fixed. Used for the
   * launch screen and nowhere else. */
  scale?: number;
}) {
  const reducedMotion = usePrefersReducedMotion();
  return (
    <ThinkingOrb
      state={ACTIVITY_ORB[activity]}
      size={size}
      theme={theme}
      paused={paused || reducedMotion}
      aria-label={ACTIVITY_LABEL[activity]}
      style={
        scale
          ? { flexShrink: 0, width: scale, height: scale }
          : { flexShrink: 0 }
      }
    />
  );
}

export { ACTIVITY_ORB, ACTIVITY_LABEL };
