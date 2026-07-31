'use client';
import { createContext, useContext, useEffect, useState } from 'react';

export type Theme = 'dark' | 'light' | 'liquid';

/** How much desktop Liquid Glass reveals.
 *
 * Exposed as three named levels rather than a free slider because the native
 * hosts compose discrete materials (DWM backdrop types on Windows,
 * NSVisualEffectView materials on macOS) rather than an arbitrary alpha. Each
 * level is clamped to a range that keeps text and controls readable. */
export type GlassLevel = 'subtle' | 'balanced' | 'clear';

export const GLASS_LEVELS: GlassLevel[] = ['subtle', 'balanced', 'clear'];

const THEME_ORDER: Theme[] = ['dark', 'light', 'liquid'];

const ThemeContext = createContext<{
  theme: Theme;
  toggle: () => void;
  glassLevel: GlassLevel;
  setGlassLevel: (level: GlassLevel) => void;
}>({ theme: 'dark', toggle: () => {}, glassLevel: 'balanced', setGlassLevel: () => {} });

function applyTheme(theme: Theme, glassLevel: GlassLevel) {
  const root = document.documentElement;
  root.classList.toggle('light', theme === 'light');
  root.classList.toggle('liquid', theme === 'liquid');
  root.dataset.theme = theme;
  // Always present so the native host reads one value; it only has an effect
  // under the liquid theme.
  root.dataset.glass = glassLevel;
  // The native host observes data-theme/data-glass, but a MutationObserver only
  // fires on change. Posting directly keeps the host in step on first paint and
  // when a value is re-selected.
  const bridge = (window as any).chrome?.webview;
  if (bridge?.postMessage) {
    try {
      bridge.postMessage({ channel: 'theme', theme, glass: glassLevel });
    } catch {
      // The host bridge is optional; the browser build has no native window.
    }
  }
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<Theme>('dark');
  const [glassLevel, setGlassLevelState] = useState<GlassLevel>('balanced');

  useEffect(() => {
    const saved = (localStorage.getItem('rc-theme') as Theme) || 'dark';
    const next = THEME_ORDER.includes(saved) ? saved : 'dark';
    const savedLevel = (localStorage.getItem('rc-glass') as GlassLevel) || 'balanced';
    const level = GLASS_LEVELS.includes(savedLevel) ? savedLevel : 'balanced';
    setTheme(next);
    setGlassLevelState(level);
    applyTheme(next, level);
  }, []);

  const toggle = () => {
    const next = THEME_ORDER[(THEME_ORDER.indexOf(theme) + 1) % THEME_ORDER.length];
    setTheme(next);
    localStorage.setItem('rc-theme', next);
    applyTheme(next, glassLevel);
  };

  const setGlassLevel = (level: GlassLevel) => {
    if (!GLASS_LEVELS.includes(level)) return;
    setGlassLevelState(level);
    localStorage.setItem('rc-glass', level);
    applyTheme(theme, level);
  };

  return (
    <ThemeContext.Provider value={{ theme, toggle, glassLevel, setGlassLevel }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);
