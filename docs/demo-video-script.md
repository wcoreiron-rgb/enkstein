# Demo Video Script — 90 seconds

The one thing a viewer should leave with: **Enkstein is the governance layer
around the AI models you already use.** Not a better chatbot, not a better
coding agent — the thing that decides what those agents are allowed to see and
do, and proves it afterward.

Record at 1440x900, dark theme, 2x scale. Keep the cursor slow.

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
