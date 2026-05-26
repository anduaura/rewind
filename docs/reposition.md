# Reposition: incident replay → deterministic substrate for AI debugging agents

## Why reposition

Today's pitch is "deterministic incident replay for distributed systems." Honest, accurate, sells a $50M outcome. Speedscale-but-open-source. Real but not venture-scale in 2026.

The agent harness already proves the bigger story: a `.rwd` snapshot is the only thing on the market that lets an AI agent *re-execute* a production incident, patch the code, and prove the patch works. Every other "AI incident assistant" reads logs and produces a plausible narrative. None can verify.

That is the $1B+ story. Lead with it.

## New positioning (one-liner)

**Before:** Deterministic replay of distributed system incidents.

**After:** The deterministic substrate AI agents need to debug production.

## New hero (drop into `site/index.html` line 399 and around)

```html
<div class="hero-badge">
  <span class="dot"></span>
  Open source · The substrate for AI debugging agents
</div>

<h1>Your AI agent can read logs.<br>It can't re-run prod.</h1>

<p class="hero-sub">
  rewind captures a production incident with eBPF — every inter-service
  call, every DB query, every syscall — and freezes it into a single
  <code>.rwd</code> file. An agent can re-execute that incident on a
  laptop, patch the code, and verify the patch passes. Hard pass/fail,
  not a plausible narrative.
</p>

<div class="hero-actions">
  <a class="btn btn-primary" href="…/agent-harness">
    Watch an agent fix a bug →
  </a>
  <a class="btn btn-ghost" href="…">
    View on GitHub
  </a>
</div>
```

## New README opening (drop in at line 3)

```markdown
# rewind

**Deterministic incident replay. The substrate AI debugging agents run on.**

Production incidents are gone the moment they end. Your logs describe what
happened. Your traces show timing. Neither lets you *re-execute* the failure
— so neither lets an AI agent verify a fix.

rewind freezes the incident. An eBPF agent captures every inter-service call,
DB query, and non-deterministic syscall into a single `.rwd` file. That file
is replayable, deterministically, on a laptop. An AI agent can re-run the
incident, propose a patch, re-run again, and produce a hard pass/fail.

See [`agent-harness/`](agent-harness/) for a 60-line demo where Claude
reproduces a real 500 error, writes the fix, and proves it works — all
against a frozen production snapshot.
```

## New section order on the site

Currently: Hero → Problem → How it works → Causal chain → Containers → Regulated industries → Purpose-built → Quickstart → CTA.

Proposed:
1. **Hero** — AI agent framing
2. **The agent demo** — full screencast/embed of `agent-harness` running. *This is the page.*
3. **Why agents need this** — three-up: read logs (everyone has this) → understand traces (everyone has this) → re-execute incident (only rewind). The argument is the diagram.
4. **How the capture works** — eBPF, zero instrumentation. Brief.
5. **Open source + run it yourself** — for the bottom-up SRE who lands here from HN. They still matter, but they're not the lead.
6. ~~Regulated industries section~~ — **delete**. Enterprise compliance posture is fine in docs, but it dilutes the agent story.

## What the agent-harness needs to become the headline

The agent harness is the strongest asset in the repo. To carry the new positioning it needs three upgrades:

1. **A 60-second screencast embedded above the fold.** Terminal output → claude.ai conversation → diff → green check. No voiceover required; the terminal speaks.
2. **One real bug, not a seeded 204.** Replace `fixtures/incident-204.rwd` with a bug found in a real OSS project (e.g. a Django app, a Flask service) where the rewind capture caught it. Founder credibility skyrockets.
3. **"Try it yourself" — one command.** `npx rewind-agent-demo` or `cargo run -p agent-harness-demo`. No API key dance, no Python venv. The friction kills the share rate.

## Why this works for a YC application

The single best signal a YC partner looks for in 2026 is: *what does AI being good at code mean for your wedge?* Most observability companies have no answer. They have to bolt an "AI assistant" on top of logs they already had — same data, slightly different UX.

rewind's answer is structural. The product is the *thing AI agents need that does not exist today*. Not an AI feature. An AI substrate. Different category, different multiple.

## What this does NOT change

- The eBPF capture work. Still the moat.
- The k8s / collection server / CO-RE engineering. Still required.
- The open-source license. Substrate has to be open or no one trusts it.

## Risk

The replay-on-laptop angle was the second-best pitch. If repositioning fails to land with design partners, fall back is easy — same product, two stories.

## Decision

Ship the new positioning when:
- The agent-harness has a working screencast (item 3 in `yc-funding-todos.md`)
- At least one design partner has watched the demo and said "I want this"

Until both, keep current site live but draft `site/index-agent.html` ready to swap.
