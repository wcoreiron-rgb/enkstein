# Demo GIF Script — "Enkstein in Cursor"

A 20–30 second screen recording for LinkedIn / README / X. Goal: show an AI
coding agent calling **governed** security tools — and an action getting
**blocked by policy** in real time. That "the AI tried, the governance stopped
it" moment is the whole pitch.

## Before you record

- [ ] Enkstein server running: `docker compose up` (backend reachable on :8000)
- [ ] `pip install enkstein-mcp` and add it to `~/.cursor/mcp.json` (see README)
- [ ] Restart Cursor; confirm the `enkstein` MCP server shows green in Settings → MCP
- [ ] Open a sample file with a planted secret, e.g. `demo.env`:
      ```
      AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
      DB_PASSWORD=hunter2-prod-db
      ```
- [ ] Screen recorder ready (macOS: CleanShot / Kap for GIF export; 1280×800, 2x)
- [ ] Hide noisy UI: close extra panels, zoom editor font to ~16px for legibility
- [ ] Light/dark: dark theme matches the brand and reads better as a GIF

## Shot list (≈25s)

| # | Time | Action on screen | Why |
|---|------|------------------|-----|
| 1 | 0–3s | Cursor open with `demo.env` visible (the planted secret on screen) | Sets context fast |
| 2 | 3–6s | Open the AI chat, type: **"Scan this file for exposed secrets using Enkstein."** | Shows it's the editor agent, not a separate app |
| 3 | 6–12s | Agent calls the `scan_text_for_secrets` tool — show the MCP tool-call chip/expander | Proves real tool calling, not a chat reply |
| 4 | 12–18s | Result returns: **Sensitive data detected: True · Risk 35 · Outcome: BLOCKED · Policy: Block High-Risk AI Prompts** | The hero moment — governance fired |
| 5 | 18–23s | Type: **"What's my current security posture?"** → posture summary streams back | Shows breadth beyond one tool |
| 6 | 23–25s | Quick cut to the Enkstein dashboard/audit log showing the event was recorded | Closes the loop: every action is audited |

## On-screen captions (optional, burn into the GIF)

- Shot 2: `Ask your editor's AI to scan with Enkstein`
- Shot 4: `⛔ Blocked by policy — governed in real time`
- Shot 6: `Every agent action is audited`

## End card (last frame, hold 2s)

```
Enkstein — AI security automation, governed by default.
github.com/wcoreiron-rgb/enkstein
```

## Export settings

- Format: GIF (LinkedIn autoplays) or MP4 (sharper; LinkedIn accepts both)
- Width: 1080–1280px · Length: ≤ 30s · Size: keep GIF < 8 MB (trim frames / 12–15 fps)
- Save to `docs/screenshots/demo-cursor.gif` and reference it at the top of the README

## Fallback (if the live blocked-by-policy moment is flaky on camera)

Record the `enkstein-cli` equivalent instead — it's deterministic:
```bash
enkstein status dashboard
# then in another pane, show the MCP scan via a quick python one-liner
```
Or screenshot the 4 key frames and post as a carousel instead of a GIF.
