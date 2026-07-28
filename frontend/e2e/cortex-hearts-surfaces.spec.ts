import { test, expect } from './fixtures';

/**
 * Every Cortex & Hearts navigation entry must render without a server error.
 *
 * Findings shipped broken because a model column was never added to the local
 * database, and nothing caught it: the page had no test, and the API returned
 * 500 only against a database that predated the column. This walks each nav
 * route with the backend mocked to empty-but-valid payloads, so a route that
 * throws, 404s, or crashes on an empty response fails here rather than on an
 * operator's machine.
 */
const ROUTES = [
  '/marcellus/security', '/control-center', '/dashboard', '/findings', '/trust-fabric',
  '/coreos', '/policies', '/policy-packs', '/events', '/audit', '/connectors', '/agents',
  '/schedules', '/orchestrations', '/swarm', '/triggers', '/autonomy', '/remediation',
  '/runs', '/aegis', '/external-agents', '/model-router', '/model-cortex', '/memory',
  '/skill-packs', '/connectors/health', '/exchange', '/channel-gateway', '/exec-channels',
];

test('every Cortex & Hearts surface renders without a server error', async ({ page }) => {
  // Most surfaces read a bare array; a few read a keyed envelope. An empty
  // array satisfies the first and leaves the second on its `|| []` fallback,
  // which is exactly the empty-tenant path a new install starts from.
  const ENVELOPE = new Set(['remediation', 'exchange', 'skill-packs', 'channel-gateway', 'exec', 'health-summary', 'external-agents', 'model-router', 'missions']);
  await page.route('**/api/v1/**', (route) => {
    const url = route.request().url();
    const keyed = Array.from(ENVELOPE).some((k) => url.includes(k));
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: keyed
        ? JSON.stringify({
            total: 0, count: 0, actions: [], playbooks: [], packages: [],
            messages: [], agents: [], skill_packs: [], connectors: [],
            providers: [], requests: [], items: [],
          })
        : JSON.stringify([]),
    });
  });

  const failures: string[] = [];

  for (const route of ROUTES) {
    const errors: string[] = [];
    page.removeAllListeners('pageerror');
    page.on('pageerror', (e) => errors.push(e.message.slice(0, 140)));

    const response = await page.goto(route, { waitUntil: 'domcontentloaded' }).catch(() => null);
    await page.waitForTimeout(250);

    const status = response?.status() ?? 0;
    const body = await page.locator('body').innerText().catch(() => '');
    const problems: string[] = [];
    if (status >= 400) problems.push(`http ${status}`);
    if (/Application error|Internal Server Error/i.test(body)) problems.push('rendered crash');
    if (errors.length) problems.push(`pageerror: ${errors[0]}`);
    if (problems.length) failures.push(`${route} → ${problems.join(' | ')}`);
  }

  expect(failures, `\n${failures.join('\n')}\n`).toEqual([]);
});
