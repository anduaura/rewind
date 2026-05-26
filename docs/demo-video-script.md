# Killer demo video — 90 seconds

The single most leveraged asset in a YC application. Replaces 10 pages of explanation. Goes at the top of the site, the top of the README, on Twitter, on the YC application's "1-minute video" slot.

## Goal

One viewer with no context understands the wedge in 90 seconds:
- Production incident happens
- Snapshot captures it
- AI agent replays it, fixes it, verifies the fix
- That last step is the thing nothing else does

## Constraints

- 90 seconds hard cap. YC video slot is 1 min; pad to 90s for the standalone version, cut to 60s for YC.
- No voiceover required for v1. Terminal speaks. Captions for context.
- Screen capture only. No talking head. Founder is the second video.
- Music: light, electronic, low. Lo-fi works. Drop on the success beat at the end.

## Structure (90 seconds)

| Time | Visual | Caption / sound |
|------|--------|----------------|
| 0:00–0:05 | Black frame, white text fades in | **"It's 3am. PagerDuty fires."** |
| 0:05–0:12 | Slack channel screenshot: red alert "API 500 rate spiked to 12%" with PagerDuty bot | (silence, ambient hum) |
| 0:12–0:18 | Cuts to terminal. Single line types out: `$ rewind flush --window 5m --output incident.rwd` | Caption: **"Snapshot the last 5 minutes of prod."** |
| 0:18–0:22 | Terminal output: `Flushed 47 events to incident.rwd (4.2 KB)` | (file appears in finder/file tree on right side) |
| 0:22–0:30 | Cut: `rewind inspect incident.rwd` — pretty-printed timeline scrolls: POST /orders → POST worker/run → 204 → 500 | Caption: **"The full causal chain. Including the 204 the API didn't handle."** |
| 0:30–0:35 | Terminal clears. Title card: **"Now hand it to Claude."** | (music ramps up subtly) |
| 0:35–0:42 | Terminal: `$ python agent.py` — first output: "Step 1 — confirm bug reproduces" → red "❌ status=500" | Caption: **"Step 1: the agent verifies the bug reproduces against current code."** |
| 0:42–0:52 | Terminal scrolls: Claude's `tool_use` showing the proposed patch — diff view of the 3 added lines | Caption: **"Step 2: the agent proposes a patch."** Side note bubble: *"It's reading the snapshot, not guessing from logs."* |
| 0:52–1:02 | Terminal: "Step 3 — apply patch and re-replay" → patch applies → green "✓ status=200, body matches" | Caption: **"Step 3: re-replay against patched code."** |
| 1:02–1:10 | Big green text fills screen: **VERIFIED FIX** with one line: "PR opened: github.com/.../pull/47" | Caption: **"Not 'I think this fixes it.' Verified."** Music swells, then drops. |
| 1:10–1:20 | Cut: split-screen comparison.<br>Left: "What every AI assistant ships: *a plausible narrative from logs.*"<br>Right: "What rewind enables: *re-execute the incident, patch, verify.*" | (silence — let it sit) |
| 1:20–1:28 | Logo + URL: **rewind.dev** (or current GitHub URL) | Caption: **"Open source. The substrate AI agents need to debug production."** |
| 1:28–1:30 | Fade out | (silence) |

## Asset list

Founder produces (~2 hours of work):

1. **Slack alert screenshot** (0:05–0:12) — use a real one if possible, redact service names. Else fabricate cleanly.
2. **Terminal recording** — use `asciinema` for the terminal segments, then convert to mp4 with `agg`. Avoids any laggy/jittery typing.
   - `rewind flush` segment
   - `rewind inspect` segment
   - `python agent.py` full output
3. **Title card slides** — Keynote/Figma/Canva. Three of them: "It's 3am. PagerDuty fires.", "Now hand it to Claude.", "VERIFIED FIX". Black background, white sans-serif, large.
4. **Logo slate** — rewind logo + URL. Existing if available, else 5 min in Figma.
5. **Music** — Artlist / Epidemic Sound: search "tense to triumphant electronic, 90 seconds". $20/month subscription if not already on one.

Tools:

- **Screen recording assembly**: ScreenStudio (Mac, $30 one-time) — built for this exact use case. Auto-zooms on terminal text, smooth cuts, captions built-in.
- **Captions**: ScreenStudio handles them. Otherwise CapCut.

## Production order (do in this order, not the timeline order)

1. **Record the terminal segments first.** This is the only thing that has to be right. Re-record until the typing pace + output is clean. Use asciinema → agg pipeline so it's deterministic.
2. **Build the title cards.** 5 min each in Figma.
3. **Edit in ScreenStudio.** Drop in the assets, set the timeline above, add captions, add music, render.
4. **Watch it on mute.** If the story is unclear on mute, the captions need fixing. YC partners often watch with sound off.
5. **Cut a 60s version for the YC slot.** Compress 1:10–1:30 into 1:00–1:05; drop the split-screen panel.

## What to A/B test once it's live

- Opening: "It's 3am" vs "Every AI debugger reads logs. None of them can re-run prod."
- Closing line: "The substrate AI agents need" vs "We open-sourced this"
- Length: 90s vs 60s — measure HN/Twitter watch-through

## Honest warning

The bug in the demo is the seeded `JSONDecodeError` from `agent-harness/fixtures`. That's fine for v1 — it's representative and the loop is what's being demonstrated.

For v2, replace with a bug found in a real OSS project the founder reproduced. Even one example of "this is a real Django bug, here's the rewind snapshot, here's the Claude PR" is worth 100× the seeded example for credibility. Schedule v2 for the week after the YC interview.

## What this video is *not*

Not a feature tour. Not a walkthrough of the CLI. Not an explanation of eBPF. Those are different videos for different audiences. This one video has one job: convince a YC partner in 90 seconds that this is the substrate AI debugging needs. Cut anything that doesn't serve that.

## Why this comes after the other items

This is item 3 in the must-haves but item 7 in the work order because it depends on:
- Item 5 (reposition) — the script uses the agent-substrate framing
- Item 4 (kill list) — the script doesn't mention any of the 58 cut features

Once those are decided, the script is ready to shoot. The founder records over a weekend; the video ships before the YC application deadline.
