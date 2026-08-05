# Demo Video Script — 90 seconds

The one thing a viewer should leave with: **Enkstein is the governance layer
around the AI models you already use.** Not a better chatbot, not a better
coding agent — the thing that decides what those agents are allowed to see and
do, and proves it afterward.

Record at 1440x900, dark theme, 2x scale. Keep the cursor slow.

## Automated capture

The shot list below is scripted in
[demo-recording.spec.ts](../frontend/e2e/demo-recording.spec.ts), so a take is
reproducible rather than a performance you have to nail live:

```bash
cd frontend
npx playwright test demo-recording --project=demo
```

That writes `test-results/.../video.webm` at 2880x1800, plus a still at each
shot boundary in `demo-stills/`. Both are gitignored. Re-run freely; each run
clears the previous stills so takes cannot interleave.

It drives the same mock harness the workspace tests use. That is deliberate:
a live tenant has whatever state it happens to have, which makes takes
non-reproducible, and the guidance below forbids recording empty or simulated
Security data. Everything shown — a bound folder, ready Brains, the sensitivity
fallback — is representative of a working install rather than flattering to it.

The recorder is tagged `@demo` and excluded from the normal Playwright run, so
cosmetic timing drift in a demo never reads as a product regression.

Use the scripted take as the base layer and record voiceover over it. If you
would rather perform it by hand, the manual checklist still applies.

## Before you record

- [ ] `docker compose up` and confirm the UI loads
- [ ] Sign in so no login screen appears mid-take
- [ ] At least one Brain shows **Ready** in Brain Connections
- [ ] A small project folder bound in Cowork, with a planted secret:
      ```
      AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
      DB_PASSWORD=hunter2-prod-db
      ```
- [ ] Close other apps; hide notifications

## Shot list

**0:00–0:10 — The problem.** Open Cowork with the project selected. Type:
"Review this repo and tell me what is unsafe." Do not send yet. Voiceover or
caption: *You already use Codex or Claude for this. The question is what they
saw on the way.*

**0:10–0:25 — Bring your own brain.** Open Brain Connections. Pan slowly across
Codex, Claude, browser sessions, and local Ollama models. Land on the line that
says cookies and account tokens never enter Enkstein.

**0:25–0:45 — Routing by sensitivity.** Back in Cowork. Change the
classification dropdown from `internal` to `restricted`. Show the runtime group
pinning to local. Caption: *Restricted work never leaves the machine — it is a
policy decision, not a setting you have to remember.*

**0:45–1:05 — Approval, not autonomy.** Set classification back to `internal`,
send the review request, and let the response arrive. Expand the proposed
changes. Show the diff and the approve control. Caption: *The model proposes.
Enkstein writes, inside the folder you approved.*

**1:05–1:20 — The receipt.** Expand the provenance record under the reply:
which model answered, the policy outcome, what was redacted, files changed.
This is the shot that matters most; hold it longer than feels comfortable.

**1:20–1:30 — Close.** Cut to the Enkstein mark. Caption:
*Open source. Runs on your hardware. github.com/wcoreiron-rgb/enkstein*

## What not to do

- Do not show the Security dashboard with empty or simulated data. A zeroed
  risk score reads as a dead product.
- Do not speed-run the provenance panel. It is the differentiator; everything
  before it is setup.
- Do not claim live connector coverage the [Maturity Matrix](maturity-matrix.md)
  does not support. Overclaiming in a demo is the fastest way to lose a
  security audience.
- Do not record a take where a Brain shows "Needs setup" unless you are
  deliberately demonstrating the setup flow.
