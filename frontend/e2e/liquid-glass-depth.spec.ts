import { expect, test } from '@playwright/test';

/** Liquid Glass depth cues.
 *
 * Blur alone reads as frosted film. What makes a surface read as glass is how
 * it catches light at its edges: a bright specular along the top, a fainter
 * counter-edge below, and a light rim rather than a drawn grey stroke. These
 * pin those cues, and pin the accessibility path where they must disappear. */

/** Alpha from either authored `rgba(...)` or the minified `#rrggbbaa` the
 * production build emits. Returns NaN for anything else, including
 * `transparent`. */
function alphaOf(value: string): number {
  const hex = value.match(/^#([0-9a-f]{6})([0-9a-f]{2})$/i);
  if (hex) return parseInt(hex[2], 16) / 255;
  const rgba = value.match(/rgba?\([^)]*?([\d.]+)\s*\)$/);
  if (rgba) return parseFloat(rgba[1]);
  if (/^#[0-9a-f]{6}$/i.test(value) || value.startsWith('rgb(')) return 1;
  return NaN;
}

/** True for white ink in either notation. */
function isWhite(value: string): boolean {
  return /^#ffffff/i.test(value) || /rgba?\(\s*255,\s*255,\s*255/.test(value);
}

test.describe('@webkit liquid glass depth', () => {
  test('cards carry a specular edge and ambient depth', async ({ page }) => {
    await page.goto('/login');
    await page.evaluate(() => {
      document.documentElement.classList.add('liquid');
      document.documentElement.setAttribute('data-theme', 'liquid');
    });
    const probe = await page.evaluate(() => {
      const el = document.createElement('div');
      el.className = 'rounded-xl border';
      document.body.appendChild(el);
      const style = getComputedStyle(el);
      const result = {
        shadow: style.boxShadow,
        // Both engines resolve the standard property, because the stylesheet
        // authors only that form and lets autoprefixer emit the alias. If a
        // hand-written -webkit- rule ever comes back, the build drops the
        // standard declaration and this reads "none" under Chromium.
        backdrop: style.getPropertyValue('backdrop-filter').trim() || 'none',
        rim: getComputedStyle(document.documentElement).getPropertyValue('--rc-glass-rim').trim(),
      };
      el.remove();
      return result;
    });

    // Two inset highlights: the lit top edge and its fainter counter-edge.
    const insets = probe.shadow.match(/inset/g) ?? [];
    expect(insets.length, `expected inset highlights, got: ${probe.shadow}`).toBeGreaterThanOrEqual(2);
    // Saturation keeps the backdrop from washing out to grey.
    expect(probe.backdrop).toContain('saturate');
    // A light rim, not a slate stroke.
    expect(isWhite(probe.rim), `rim is not white ink: ${probe.rim}`).toBe(true);
  });

  test('glass levels scale the edge with the surface', async ({ page }) => {
    await page.goto('/login');
    const read = async (level: string) =>
      page.evaluate((value) => {
        document.documentElement.classList.add('liquid');
        document.documentElement.setAttribute('data-glass', value);
        const style = getComputedStyle(document.documentElement);
        return {
          rim: style.getPropertyValue('--rc-glass-rim').trim(),
          surface: style.getPropertyValue('--rc-bg-surface').trim(),
        };
      }, level);

    const subtle = await read('subtle');
    const clear = await read('clear');
    // A denser pane catches less edge light; a clearer one relies on it more.
    expect(alphaOf(clear.rim)).toBeGreaterThan(alphaOf(subtle.rim));
    expect(alphaOf(clear.surface)).toBeLessThan(alphaOf(subtle.surface));
  });

  test('reduced transparency removes the specular entirely', async ({ browser }) => {
    const context = await browser.newContext({ reducedMotion: 'no-preference' });
    const page = await context.newPage();
    // prefers-reduced-transparency has no Playwright emulation option, so the
    // media query is exercised through forced-colors-free CSS emulation.
    await page.emulateMedia({ reducedMotion: null });
    await page.goto('/login');
    const specular = await page.evaluate(() => {
      document.documentElement.classList.add('liquid');
      // Read the rule as authored rather than the resolved value, since the
      // media query cannot be emulated here.
      const sheets = Array.from(document.styleSheets);
      for (const sheet of sheets) {
        let rules: CSSRuleList;
        try {
          rules = sheet.cssRules;
        } catch {
          continue;
        }
        for (const rule of Array.from(rules)) {
          if (
            rule instanceof CSSMediaRule &&
            rule.conditionText.includes('reduced-transparency')
          ) {
            return rule.cssText;
          }
        }
      }
      return '';
    });
    expect(specular, 'no reduced-transparency rule found').toContain('reduced-transparency');
    expect(
      specular.includes('--rc-glass-specular: transparent'),
      'the specular is still drawn when the user asked for less transparency',
    ).toBe(true);
    await context.close();
  });
});
