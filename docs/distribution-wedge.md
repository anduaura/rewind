# Distribution wedge: not bottom-up SRE

## Why this matters

Bottom-up adoption to platform/SRE teams is the slowest GTM in B2B infra. The persona has no budget, is allergic to vendor calls, and switches stacks once per CTO change. Honeycomb took 6 years. Datadog took 8. Lightstep got acquired.

rewind has a better path: be an *integration*, not a *standalone purchase*. Embed where the SRE already lives during an incident. They never bought rewind — they bought PagerDuty / incident.io / Datadog, and `rewind flush` happened to fire automatically.

## Three wedge candidates, ranked

### 1. Incident-response platforms — **highest priority**

The exact moment a `.rwd` snapshot is most valuable is the exact moment PagerDuty / incident.io / FireHydrant / Rootly fires. Build the integration where the user already is.

**Target ranked:**
- **incident.io** — most modern, most developer-mode, easiest to ship a custom integration. Founders are technical (ex-Monzo). Public extensibility platform.
- **FireHydrant** — second pick. Strong Slack/dev-first culture, has a workflow/integration model.
- **Rootly** — third. YC company, founder-friendly.
- **PagerDuty** — largest market but slowest partner program. Save for once one of the smaller three is live.

**Integration spec — incident.io v1:**
```
On incident-created webhook:
  → rewind API: POST /flush
    { snapshot_name: "incident-{incident.id}",
      window: 5min,
      services: <auto-detect> }
  → on success, post Slack message in incident channel:
    "📦 Snapshot captured: {url}/ui/incident-{incident.id}"
  → embed timeline preview inline (rewind already has this)
```

Outcome: every SEV-2+ incident in incident.io customers automatically gets a `.rwd`. SREs see the value without ever installing anything beyond the agent.

### 2. Hosting platforms — **second priority**

Customers on opinionated PaaS (Fly, Render, Railway) have small ops teams and high tolerance for new tools — easier first customers than enterprises.

**Target:**
- **Fly.io** — best fit. Their model is "deploy a container, we run it." rewind agent is also a container. Bundle as an opt-in addon: `fly addon create rewind`.
- **Railway** — newer, more receptive to integrations, smaller customer base but high love-rate.
- **Render** — third pick.

**Pitch to Fly:** "Every Fly app gets a `flyctl rewind capture` command. We pay you per-customer-active-month, you get a debugging story you don't have today."

Less likely to land than (1) but bigger if it does.

### 3. AI debugging agents — **emerging, watch closely**

If the agent-substrate positioning is right, the second-order distribution is: companies building autonomous code agents (Cognition / Devin, Factory, Cursor's agent mode, Claude Code itself) need a way for those agents to *verify* fixes in production-shaped environments. `.rwd` is that.

**Target:**
- **Factory** — building enterprise AI coding agents, explicitly debugging-focused
- **Cognition (Devin)** — debug-and-fix is the marquee demo, would benefit from a verification substrate
- **Sourcegraph (Cody / Amp)** — agent infra company, possible distribution partner

This is the most strategic but the least mature category. Right now there is no buyer — these companies are still building. Position rewind so that when they need this, the answer is obvious.

## Why this beats "talk to more SREs"

Direct SRE bottom-up:
- 1 demo → 1 user → 6mo trial → maybe a $500/mo team license
- Effective CAC: ~40 hours of founder time per paying team

incident.io integration:
- 1 integration ship → every incident.io customer eligible → 5-10% activate
- incident.io has ~1000 paying companies. 5% = 50 leads, all pre-qualified, all in active incident workflows.
- Effective CAC: ~2 weeks of eng time, near-zero per-customer marginal.

This is the only path that doesn't require the founder to become a full-time SDR.

## Concrete next 30 days

| Week | Action |
|------|--------|
| 1 | Cold email incident.io founders. Pitch: "We have an open-source eBPF incident-replay tool. It would integrate naturally with your incident-created webhook. Want a 15-min demo?" |
| 1 | Same email to FireHydrant + Rootly founders. Parallel, not serial. |
| 2 | Ship the incident.io integration regardless of response — webhook receiver + Slack message poster is ~200 LOC. Demo-ready before the call. |
| 3 | Cold email Fly.io platform team. Pitch: "Opt-in debugging snapshot capture for every Fly app." Reference the working integration with incident.io as proof of momentum. |
| 4 | Apply to YC with three integrations either live or in late-stage build. Story: "we don't sell to SREs, we appear in tools they already pay for." |

## What this changes about the product

Almost nothing. The capture/replay engine is the same. Two additions:
- `rewind server` gains a `/webhooks/incident-io` endpoint (and friends) that calls `flush` on the agent
- A Slack/Block-Kit posting flow that includes a deep link to `/ui/<snapshot>`

Both are < 1 week of work. Both are dual-use — they also work for any customer's homegrown alerting.

## What this requires of the founder

Stop building. Start cold-emailing. Every hour spent on milestone #64 is an hour not spent on the integration that gets rewind into 1000 companies' incident response workflows by default.

## The trap

Do not try to *partner* with PagerDuty in month one. Their BD cycle is 6+ months and you have no leverage. Ship the incident.io integration first. Use it as proof. Then PagerDuty wants you, not the other way around.
