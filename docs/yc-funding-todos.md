# YC Funding TODOs

Source: YC-partner review. Items that flip the partner from "interview" to "fund."

Tags:
- **[FOUNDER]** — only the founder can do (sales, recruiting, customer dev)
- **[DRAFT]** — Claude can draft, founder ships
- **[BUILD]** — Claude can fully execute in-repo

## Must-haves

### 1. 3+ design partners actively using rewind on real incidents [FOUNDER]
- 3 prod users running `rewind flush` against real services
- One quote: "shipped fix in 20min vs usual 4hr"
- Without this, nothing else matters

### 2. Co-founder [FOUNDER]
- Target: ex-Datadog/Honeycomb/Lightstep SRE with enterprise sales scars
- Or: ex-eBPF kernel engineer (Cilium/Isovalent)
- Job: "talk to 5 SREs/day"

### 3. 90-second killer replay video [FOUNDER + DRAFT]
- Real incident → replay reproduces → agent patches → PR opens
- Public, HN-able
- Claude can draft the script + storyboard; founder records

## Strong signals

### 4. Kill list: cut milestones to 5 [DRAFT]
- Pick 5 milestones that matter, delete the other ~58
- Write the public "we cut X because Y" post
- Founder discipline > velocity

### 5. Reposition: incident replay → deterministic substrate for AI debugging agents [DRAFT + BUILD]
- Rewrite README opening, site headline, pitch
- Lead with `agent-harness` demo
- "$50M outcome → $1B+ outcome" framing
- BUILD: site/index.html + README rewrite

### 6. Pick coverage-ceiling stance [DRAFT]
- Either: "75% is enough, here's design-partner data"
- Or: "we're cracking thread scheduling via rr-style syscall recording"
- Don't be vague

### 7. Distribution wedge that isn't bottom-up SRE [DRAFT]
- Target: PagerDuty / incident.io / FireHydrant integration
- Or: Fly / Render / Railway bundling
- Draft outreach email + integration spec

## Nice-to-haves

### 8. Real eBPF overhead numbers under load [BUILD]
- E22 marked "Done" — find or generate the graph
- p50/p95/p99 service latency with/without agent
- Memory + CPU at 1k req/s

### 9. One paying customer at any price [FOUNDER]
- $500/mo from a seed-stage YC co
- Proves card-swipe

### 10. Technical blog post with 500+ HN upvotes [DRAFT]
- "How we replay distributed-system incidents with eBPF + libfaketime"
- Or: "We let Claude debug prod with a deterministic snapshot"
- Claude drafts, founder posts

## Out of scope (stop building)

- More enterprise checklist features
- More protocols (MongoDB, Kafka already overkill pre-PMF)
- More polish on web UI

---

## Work order

DOABLE-NOW (no founder input needed): 4, 5, 6, 7, 8, 10
NEEDS FOUNDER: 1, 2, 3 (script only), 9

Run in order: 4 → 5 → 6 → 7 → 10 → 8 → 3-script
