import { test } from './fixtures';
import { rmSync } from 'node:fs';
import {
  createWorkspaceStore,
  mockMarcellusWorkspace,
  mockTurnStream,
  seedArtifacts,
  type WorkspaceStore,
} from './marcellus-workspace-mocks';

/**
 * Records the 90-second product demo described in `docs/demo-video-script.md`.
 *
 * This is a recorder, not an assertion suite. It is excluded from the normal
 * run via the `@demo` tag so a CI failure never depends on cosmetic timing.
 *
 * Everything it shows is driven by the same mock harness the workspace specs
 * use, for two reasons. A live tenant has whatever state it happens to have,
 * which makes takes non-reproducible; and the script explicitly forbids
 * recording empty or simulated Security data, so the demo stays on Cowork and
 * Brain Connections where the mocked state is representative rather than
 * flattering.
 *
 *   npx playwright test demo-recording --project=demo
 *
 * Video lands in `test-results/`. Re-run freely; each run overwrites.
 */

const PROMPT = 'Review this repo and tell me what is unsafe.';

/** The script wants this shot to show breadth: a subscription CLI, a browser
 *  session, and local models, all reachable from one console. The workspace
 *  harness stubs this endpoint to an empty list, so the demo overrides it. */
const BRAINS = [
  { brain: 'codex_subscription', kind: 'subscription', available: true, authenticated: true, status: 'ready', runtime: 'Codex CLI', detail: 'Ready', models: ['gpt-5', 'gpt-5-mini'] },
  { brain: 'claude_subscription', kind: 'subscription', available: true, authenticated: true, status: 'ready', runtime: 'Claude Code CLI', detail: 'Ready', models: ['sonnet', 'opus', 'haiku'] },
  { brain: 'chatgpt_browser', kind: 'browser_session', available: true, authenticated: true, status: 'ready', runtime: 'Visible browser', detail: 'Signed-in tab paired. Cookies and account tokens never enter Enkstein.' },
  { brain: 'gemini_browser', kind: 'browser_session', available: true, authenticated: true, status: 'ready', runtime: 'Visible browser', detail: 'Signed-in tab paired. Cookies and account tokens never enter Enkstein.' },
  { brain: 'ollama_local', kind: 'local', available: true, authenticated: true, status: 'ready', runtime: 'Ollama', detail: 'On-device. Nothing leaves this machine.', models: ['qwen2.5-coder', 'gemma3', 'llama3.1'] },
];

const PROJECT_ID = 'project-demo';
const CONVERSATION_ID = 'conversation-demo';

/** Deliberate pacing. A demo reads as frantic at normal automation speed, so
 *  every step is followed by a hold long enough for a viewer to actually read
 *  what changed on screen. */
const BEAT = 900;
const HOLD = 2200;
const LONG_HOLD = 4200;

async function beat(page: import('@playwright/test').Page, ms = BEAT) {
  await page.waitForTimeout(ms);
}

/** Saves a still at each shot boundary. The video is the deliverable, but a
 *  frame that renders wrong is far easier to spot in a PNG than by scrubbing
 *  a webm, and these double as thumbnails/stills for a post. */
let shotIndex = 0;
async function shot(page: import('@playwright/test').Page, name: string) {
  shotIndex += 1;
  await page.screenshot({ path: `demo-stills/${String(shotIndex).padStart(2, '0')}-${name}.png` });
}

/** Moves the pointer in steps so the cursor reads as deliberate rather than
 *  teleporting between targets. */
async function glideTo(page: import('@playwright/test').Page, selector: string) {
  const box = await page.locator(selector).first().boundingBox();
  if (!box) return;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 24 });
  await beat(page, 400);
}

/** Types at human cadence. Playwright's default fill() would snap the whole
 *  string in at once, which looks synthetic on video. */
async function typeSlowly(page: import('@playwright/test').Page, selector: string, text: string) {
  await page.locator(selector).first().click();
  await page.locator(selector).first().type(text, { delay: 42 });
}

function seedStore(): WorkspaceStore {
  const store = createWorkspaceStore();
  const now = new Date().toISOString();

  store.projects.push({
    id: PROJECT_ID, tenant_id: 'default', owner_id: 'e2e-owner',
    name: 'payments-service', description: 'Bound local folder',
    kind: 'cowork', classification: 'internal', default_source: 'auto',
    status: 'active', created_at: now, updated_at: now,
  });

  store.conversations.push({
    id: CONVERSATION_ID, tenant_id: 'default', owner_id: 'e2e-owner',
    project_id: PROJECT_ID, title: 'Repository safety review', mode: 'cowork',
    classification: 'internal', selected_source: 'auto', status: 'active',
    message_count: 0, created_at: now, updated_at: now,
  });

  seedArtifacts(store, PROJECT_ID, [
    'src/server.ts', 'src/routes/checkout.ts', 'src/lib/db.ts',
    'infra/main.tf', '.env.example', 'README.md',
  ]);

  store.nativeWorkspace[PROJECT_ID] = {
    connected: true, name: 'payments-service', file_count: 6, synced_files: 6,
  };

  return store;
}

const ASSISTANT_REPLY = [
  'Three issues stand out, ordered by blast radius.',
  '',
  '1. `.env.example` carries a live-looking AWS key and a production database',
  '   password. Anything cloned from this repo inherits them.',
  '2. `src/routes/checkout.ts` logs the full request body on error, so card',
  '   metadata reaches your log sink.',
  '3. `infra/main.tf` opens 0.0.0.0/0 on the database security group.',
  '',
  'I have staged replacements for the first two. The Terraform change narrows',
  'ingress to the application subnet and needs your review before it applies.',
].join('\n');

/** Provenance is the shot the script calls the differentiator, so the record
 *  shows a real fallback: the cloud attempt is refused on classification and
 *  the local Brain answers instead. */
const GOVERNANCE = {
  outcome: 'allowed',
  policy_name: 'sensitivity-routing',
  reason: 'restricted content pinned to local execution',
  risk_score: 12,
  input_redacted: true,
  output_redacted: false,
  confidence: 0.94,
  runtime_group: 'hybrid',
  latency_ms: 2140,
  votes: [],
  context_manifest: {
    entries: [
      {
        artifact_id: 'artifact-env', path: '.env.example', disposition: 'sent_full',
        characters_sent: 412, estimated_tokens: 103, redacted: true,
        selection_reason: 'explicit_selection',
        citations: [{ line_start: 1, line_end: 14 }],
      },
      {
        artifact_id: 'artifact-checkout', path: 'src/routes/checkout.ts', disposition: 'sent_full',
        characters_sent: 2860, estimated_tokens: 715, redacted: false,
        selection_reason: 'explicit_selection',
        citations: [{ line_start: 1, line_end: 96 }],
      },
      {
        artifact_id: 'artifact-tf', path: 'infra/main.tf', disposition: 'sent_full',
        characters_sent: 1904, estimated_tokens: 476, redacted: false,
        selection_reason: 'explicit_selection',
        citations: [{ line_start: 1, line_end: 63 }],
      },
    ],
    total_characters_sent: 5176,
    budget_characters: 100000,
    total_estimated_tokens: 1294,
    destination: 'internal',
    selected_destination: 'profile:ollama_local · qwen2.5-coder',
    explicit: true,
    effective_classification: 'restricted',
    blocked: false,
    attempts: [
      { source: 'codex_cli', provider: 'codex', model: 'gpt-5', policy_outcome: 'denied', status: 'skipped', reason: 'restricted data may not leave this device' },
      { source: 'profile:ollama_local', provider: 'ollama', model: 'qwen2.5-coder', policy_outcome: 'allowed', status: 'completed' },
    ],
    fallback_reason: 'cloud Brain refused by sensitivity policy; local Brain answered',
  },
};

test('@demo record the product walkthrough', async ({ page }) => {
  test.setTimeout(180_000);

  // Clear prior stills so a shorter run cannot leave frames from an older take
  // interleaved with this one, which would be mistaken for a current shot.
  rmSync('demo-stills', { recursive: true, force: true });
  shotIndex = 0;

  const store = seedStore();
  await mockMarcellusWorkspace(page, store);
  // Registered after the workspace harness so it wins Playwright's LIFO order,
  // and with a trailing wildcard so the page's `?force=true` request matches.
  await page.route('**/api/v1/modelclaw/brains/status**', (route) => route.fulfill({ json: BRAINS }));
  await mockTurnStream(page, store, {
    conversationId: CONVERSATION_ID,
    assistantContent: ASSISTANT_REPLY,
    assistantGovernance: GOVERNANCE,
    userContent: PROMPT,
    provider: 'ollama',
    model: 'qwen2.5-coder',
  });

  // ── 0:00–0:10 · The problem ───────────────────────────────────────────────
  // Open on real work in a bound folder, with the question already framed.
  await page.goto(`/marcellus/cowork/${PROJECT_ID}/${CONVERSATION_ID}`, { waitUntil: 'networkidle' });
  await beat(page, HOLD);

  const composer = 'textarea';
  await typeSlowly(page, composer, PROMPT);
  await beat(page, HOLD);
  await shot(page, 'problem-cowork-prompt');

  // ── 0:10–0:25 · Bring your own brain ──────────────────────────────────────
  await page.goto('/marcellus/brains', { waitUntil: 'networkidle' });
  await beat(page, HOLD);
  await shot(page, 'brains-top');
  // Pan the readiness list rather than cutting, so the breadth registers.
  for (let y = 0; y < 3; y += 1) {
    await page.mouse.wheel(0, 320);
    await beat(page, 850);
  }
  await beat(page, HOLD);
  await shot(page, 'brains-scrolled');

  // ── 0:25–0:45 · Routing by sensitivity ────────────────────────────────────
  await page.goto(`/marcellus/cowork/${PROJECT_ID}/${CONVERSATION_ID}`, { waitUntil: 'networkidle' });
  await beat(page, HOLD);

  await glideTo(page, '[aria-label="Data classification"]');
  await page.selectOption('[aria-label="Data classification"]', 'restricted');
  await beat(page, HOLD);

  // Navigation cleared the composer, so restore the question. An empty canvas
  // makes this beat read as an abstract settings tour rather than a decision
  // being made about work already in flight.
  await typeSlowly(page, composer, PROMPT);
  await beat(page);

  await glideTo(page, '[aria-label="Runtime group"]');
  await page.selectOption('[aria-label="Runtime group"]', 'local');
  await beat(page, LONG_HOLD);
  await shot(page, 'restricted-pinned-local');

  // ── 0:45–1:05 · Approval, not autonomy ────────────────────────────────────
  await page.selectOption('[aria-label="Data classification"]', 'internal');
  await page.selectOption('[aria-label="Runtime group"]', 'hybrid');
  await beat(page);

  // Cowork defaults to the native Codex executor when Agent tools is on and a
  // folder is bound, which bypasses the governed turn stream. The demo is about
  // the governance record, so route through the Cortex Gateway path instead.
  const agentTools = page.getByRole('checkbox').first();
  if (await agentTools.isChecked()) {
    await glideTo(page, 'input[type="checkbox"]');
    await agentTools.uncheck();
    await beat(page);
  }

  // Focus is on the Agent tools checkbox after the previous step, so a bare
  // Enter would toggle that instead of submitting. Click into the composer,
  // then send.
  await page.locator(composer).first().click();
  await page.keyboard.press('Enter');

  // Wait for the reply itself rather than a fixed delay: a slow frame would
  // otherwise silently produce a take with no answer on screen.
  await page.getByText(/Three issues stand out/).first().waitFor({ timeout: 20_000 });
  await beat(page, HOLD);
  await shot(page, 'assistant-reply');

  // ── 1:05–1:20 · The receipt ───────────────────────────────────────────────
  // The script is explicit that this shot should be held longer than feels
  // comfortable, so the manifest gets the longest dwell in the take.
  const manifest = page.getByText(/Context sent ·/).first();
  await manifest.waitFor({ timeout: 10_000 });
  await manifest.scrollIntoViewIfNeeded();
  await beat(page, HOLD);
  await manifest.click();
  await page.getByText(/attempt 1: codex_cli/).first().waitFor({ timeout: 10_000 });
  await beat(page, LONG_HOLD);
  await shot(page, 'provenance-expanded');
  await beat(page, LONG_HOLD);

  // ── 1:20–1:30 · Close ─────────────────────────────────────────────────────
  await page.goto('/marcellus/chat', { waitUntil: 'networkidle' });
  await beat(page, LONG_HOLD);
  await shot(page, 'close');
});
