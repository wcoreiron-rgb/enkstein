# Demo Narration — 90 seconds

Six beats, in recording order. Your 15-minute take ran long mostly because it
toured Security first; that section is the least self-explanatory and the
slowest to make legible on video, so it moves to the middle and gets one shot
rather than a tour.

The single idea a viewer should leave with: **Enkstein governs the AI tools you
already pay for.** Everything below serves that sentence.

Render the voiceover with [narrate_demo.sh](../scripts/narrate_demo.sh):

```bash
scripts/narrate_demo.sh "path/to/recording.mov"
```

That parses the beats below, renders each one with `say`, places it at its
scripted timecode, and writes `recording-narrated.mov` beside the source. Beat
text lives here and nowhere else, so editing this file changes the audio.

Each beat's target duration is the budget for the visuals, not a countdown to
read against — record the screen first, then fit narration to it. Narration
that runs past the last frame is truncated with a warning rather than
extending the clip.

Two flags worth knowing. `ENKSTEIN_NARRATION_VOICE` and
`ENKSTEIN_NARRATION_RATE` (default `Samantha` at 170wpm) change the voice
without editing the script. And the input must be a QuickTime `.mov` or `.mp4`
— AVFoundation cannot decode the `.webm` that the Playwright recorder emits,
so narrate a real screen recording, not the automated walkthrough capture.

---

## 1 · The problem (0:00–0:12)

**Screen.** Cowork, a real folder already bound, the question typed but unsent.

> You already use Codex, or Claude, or ChatGPT for work like this. The question
> nobody answers is what they saw on the way, and what they were allowed to do
> with it.

## 2 · Bring your own brain (0:12–0:28)

**Screen.** Brain Connections. Scroll once, slowly, past the subscription CLIs,
the browser sessions, and the local models.

> Enkstein is not another model. It connects the ones you have. A Codex or
> Claude subscription, a signed-in browser tab, or a local model running on
> this machine. Cookies and account tokens never enter Enkstein.

## 3 · Routing by sensitivity (0:28–0:45)

**Screen.** Back in Cowork. Change classification to `restricted` and let the
runtime pin itself to local. Hold.

> Mark the work restricted, and the cloud stops being an option. Not a warning,
> not a preference you have to remember. The policy decides, and the local
> model takes the job.

## 4 · Approval, not autonomy (0:45–1:00)

**Screen.** Set classification back to internal, send, let the answer arrive.

> Ask it to review the project, and it reads only what it is allowed to read.
> The model proposes the change. Enkstein writes it, inside the folder you
> approved, and nowhere else.

## 5 · The receipt (1:00–1:20)

**Screen.** Expand the provenance record. This is the longest hold in the
video. Do not rush it.

> Then it shows its work. Which model answered, and which one was refused.
> Every file that was sent, what was redacted before it left, and the policy
> that made the call. That record is the product.

## 6 · Close (1:20–1:30)

**Screen.** The Enkstein mark, or the Chat surface at rest.

> Enkstein. Open source, runs on your own hardware, and governs the AI you
> already use. On GitHub at wcoreiron dash r g b, slash Enkstein.

---

## Notes on delivery

The synthesized voice reads URLs and hyphens badly, which is why the closing
line spells out the repository path. If you swap in a different voice, check
that line first.

Beat 5 is the one that distinguishes the product. If the recording runs long,
cut from beats 1 and 2 rather than shortening the provenance hold.

Do not narrate over the Security dashboard with empty data. A zeroed risk score
with a confident voiceover reads as a dead product, which is worse than not
showing it.

## Recording the re-take

Record silent, in one pass, in this order. The narration is fitted afterwards,
so pauses between beats are free — take them.

1. **Cowork, question typed, not sent.** Folder already bound. Hold ~12s.
2. **Brain Connections.** One slow scroll past subscription CLIs, browser
   sessions, and local models. Hold ~16s.
3. **Back to Cowork.** Set classification to `restricted`; let the runtime pin
   itself to local. Hold on the pinned state ~17s.
4. **Set classification back to `internal` and send.** Let the answer arrive on
   screen. ~15s.
5. **Expand the provenance record.** The longest hold in the video, ~20s. Scroll
   the manifest so the per-file dispositions are legible.
6. **Rest.** The Enkstein mark or the Chat surface, ~10s.

Roughly 90 seconds of screen time. If a beat runs long, that is fine; if it
runs short, the next line of narration will start before the visual catches up.
