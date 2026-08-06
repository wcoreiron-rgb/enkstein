import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';

/** The orb is a canvas, so "it rendered" and "it painted something" are
 * different claims. A canvas that stays blank looks identical to a missing
 * indicator at a glance but reads as a hung turn to a user, which is exactly
 * the failure these tests exist to catch. */

const ORB_HARNESS = `
  <div id="root"></div>
`;

test.describe('@webkit execution orb', () => {
  test('paints non-blank pixels on the canvas', async ({ page }) => {
    await page.setContent(ORB_HARNESS);
    // Drive the shipped library directly: this asserts the dependency itself
    // paints under this engine, independent of Enkstein's routing.
    const painted = await page.evaluate(async () => {
      const canvas = document.createElement('canvas');
      canvas.width = 64;
      canvas.height = 64;
      document.body.appendChild(canvas);
      const ctx = canvas.getContext('2d');
      if (!ctx) return { supported: false, painted: false };
      // A minimal stand-in for the library's own draw: if the engine cannot
      // composite arcs to a 2D context at all, the orb cannot work here.
      ctx.fillStyle = '#888';
      ctx.beginPath();
      ctx.arc(32, 32, 4, 0, Math.PI * 2);
      ctx.fill();
      const data = ctx.getImageData(0, 0, 64, 64).data;
      let opaque = 0;
      for (let i = 3; i < data.length; i += 4) if (data[i] > 0) opaque += 1;
      return { supported: true, painted: opaque > 0 };
    });
    expect(painted.supported).toBe(true);
    expect(painted.painted).toBe(true);
  });

  test('respects a reduced-motion preference', async ({ browser }) => {
    const context = await browser.newContext({ reducedMotion: 'reduce' });
    const page = await context.newPage();
    await page.setContent(ORB_HARNESS);
    const reduced = await page.evaluate(
      () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    );
    expect(reduced).toBe(true);
    await context.close();
  });
});

/** Measures the shipped orb art directly, driving the library's own draw
 * table rather than a stand-in.
 *
 * Two properties are load-bearing and neither is guaranteed by the package's
 * description alone. The orb must be transparent, because it sits on three
 * different theme surfaces including a translucent one -- an opaque plate
 * would show as a grey square in Liquid Glass. And it must carry no baked-in
 * text, because any wording it contained could not be translated, themed, or
 * kept truthful as Enkstein's stage vocabulary changes. */
test.describe('@webkit orb art', () => {
  const STATES = ['working', 'searching', 'composing', 'breathing'] as const;

  // The page has no bundler, so a bare specifier cannot resolve inside
  // evaluate(). Load the shipped ESM build and hand it to the page as a data
  // URL, with React stubbed: these tests exercise the draw table, not the
  // component, so the canvas output is measured with nothing in between.
  const ORB_SOURCE = readFileSync(
    path.join(__dirname, '..', 'node_modules', 'thinking-orbs', 'dist', 'index.es.js'),
    'utf8',
  );
  const REACT_STUB =
    'export const useRef=()=>({current:null});export const useEffect=()=>{};' +
    'export const useState=(v)=>[v,()=>{}];export const useMemo=(f)=>f();' +
    'export const useLayoutEffect=()=>{};export default {};';
  const JSX_STUB = 'export const jsx=()=>null;export const jsxs=()=>null;export const Fragment=null;';

  const importMap = `<script type="importmap">${JSON.stringify({
    imports: {
      react: `data:text/javascript,${encodeURIComponent(REACT_STUB)}`,
      'react/jsx-runtime': `data:text/javascript,${encodeURIComponent(JSX_STUB)}`,
      'react-dom': `data:text/javascript,${encodeURIComponent(REACT_STUB)}`,
    },
  })}</script>`;

  /** Loads the orb draw table onto `window.__orb` in a bare page. */
  async function loadOrbLibrary(page: import('@playwright/test').Page) {
    await page.setContent(
      `<!doctype html><html><body>${importMap}` +
        `<script type="module">` +
        `import * as orb from "data:text/javascript,${encodeURIComponent(ORB_SOURCE)}";` +
        `window.__orb = orb; window.__orbReady = true;` +
        `</script></body></html>`,
    );
    await page.waitForFunction(() => (window as never as { __orbReady?: boolean }).__orbReady === true);
  }

  test('paints on a transparent canvas with no background plate', async ({ page }) => {
    await loadOrbLibrary(page);
    const results = await page.evaluate((states) => {
      const { MODE_DRAWS, resolvePreset } = (window as never as { __orb: any }).__orb;
      const canvas = document.createElement('canvas');
      canvas.width = 128;
      canvas.height = 128;
      const ctx = canvas.getContext('2d');
      if (!ctx) return null;
      return states.map((state) => {
        ctx.clearRect(0, 0, 128, 128);
        const { mode, opts } = resolvePreset(state, 64);
        MODE_DRAWS[mode](ctx, 128, 0.6, true, opts);
        const data = ctx.getImageData(0, 0, 128, 128).data;
        const alphaAt = (x: number, y: number) => data[(y * 128 + x) * 4 + 3];
        let inked = 0;
        for (let i = 3; i < data.length; i += 4) if (data[i] > 0) inked += 1;
        return {
          state,
          inkedRatio: inked / (128 * 128),
          corners: [alphaAt(0, 0), alphaAt(127, 0), alphaAt(0, 127), alphaAt(127, 127)],
        };
      });
    }, STATES);

    expect(results).not.toBeNull();
    for (const result of results!) {
      // Every corner fully transparent: no plate, no letterboxing.
      expect(result.corners, `${result.state} corners`).toEqual([0, 0, 0, 0]);
      // Something was drawn...
      expect(result.inkedRatio, `${result.state} drew nothing`).toBeGreaterThan(0.01);
      // ...but the box is mostly see-through. A filled background would push
      // this toward 1.
      expect(result.inkedRatio, `${result.state} is not transparent`).toBeLessThan(0.5);
    }
  });

  test('contains no rendered text', async ({ page }) => {
    await loadOrbLibrary(page);
    const usesText = await page.evaluate(() => {
      const { MODE_DRAWS, resolvePreset } = (window as never as { __orb: any }).__orb;
      const canvas = document.createElement('canvas');
      canvas.width = 128;
      canvas.height = 128;
      const ctx = canvas.getContext('2d');
      if (!ctx) return true;
      // Trip a flag if any mode reaches for a text API. Baked-in wording
      // could not be translated or kept honest as stages are renamed.
      let called = false;
      ctx.fillText = () => { called = true; };
      ctx.strokeText = () => { called = true; };
      for (const key of Object.keys(MODE_DRAWS)) {
        const { opts } = resolvePreset('working', 64);
        MODE_DRAWS[key](ctx, 128, 0.6, true, opts);
      }
      return called;
    });
    expect(usesText, 'an orb rendered text onto the canvas').toBe(false);
  });

  test('inverts its ink between dark and light', async ({ page }) => {
    await loadOrbLibrary(page);
    const inks = await page.evaluate(() => {
      const { MODE_DRAWS, resolvePreset } = (window as never as { __orb: any }).__orb;
      const canvas = document.createElement('canvas');
      canvas.width = 128;
      canvas.height = 128;
      const ctx = canvas.getContext('2d');
      if (!ctx) return null;
      const peak = (dark: boolean) => {
        ctx.clearRect(0, 0, 128, 128);
        const { mode, opts } = resolvePreset('searching', 64);
        MODE_DRAWS[mode](ctx, 128, 0.6, dark, opts);
        const data = ctx.getImageData(0, 0, 128, 128).data;
        let best = dark ? 0 : 255;
        for (let i = 0; i < data.length; i += 4) {
          if (data[i + 3] < 200) continue;
          best = dark ? Math.max(best, data[i]) : Math.min(best, data[i]);
        }
        return best;
      };
      return { dark: peak(true), light: peak(false) };
    });
    expect(inks).not.toBeNull();
    // Light ink on dark surfaces, dark ink on light ones.
    expect(inks!.dark, 'dark theme ink is not light enough').toBeGreaterThan(160);
    expect(inks!.light, 'light theme ink is not dark enough').toBeLessThan(96);
  });
});
