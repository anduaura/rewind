# Kill list — the 5 milestones that matter (and the 58 that don't)

The roadmap has 63 "Done" milestones. That is not focus, that is a checklist. A YC partner reading it asks: *what did you cut?* The honest answer right now is "nothing." That is the bug.

This doc fixes that.

## The 5 that matter

These are the only milestones that move a design-partner conversation forward in 2026. Everything else is built for an imagined enterprise buyer who has not signed.

| # | Milestone | Why it stays |
|---|-----------|-------------|
| 1 | **Capture → Replay end-to-end (E1, E2, E3 + 21)** | The product. CO-RE for kernel portability, libfaketime host-side injection so customer images don't change, ≥512-byte body capture so real GraphQL/JSON works. Without these, replay doesn't work on a real prod stack. |
| 2 | **Agent harness (`agent-harness/`)** | The wedge. Substrate for AI debugging agents. This is the only feature that justifies a 2026 fundraise — incident replay alone is a $50M outcome, agent substrate is $1B+. |
| 3 | **Service attribution in Kubernetes (E4)** | Required for design partner #1. Without pod→service mapping in k8s, the snapshot is unreadable. Everything `rewind report` / `rewind timeline` / web UI / agent harness depends on this being correct. |
| 4 | **`rewind report` + `rewind timeline` (47, 48)** | The artifact a design partner shares with their team after an incident. This is what gets the second user inside the customer's org. Distribution channel disguised as a feature. |
| 5 | **Central collection server, minimal (30)** | Replaces `kubectl cp`. The smallest possible cloud surface — upload + list + download. No SSO, no RBAC, no HA, no TLS until a paying customer asks. |

## The 58 to cut (or freeze)

Group these by why they were built. Most are real engineering with no customer pull.

### Built for an imagined enterprise buyer (freeze)
27 encryption at rest · 28 audit log · 32 RBAC · 42 TLS · 43 integrity verify · 44 rate limit · 51 SSO/OIDC · 52 secret manager (vault/aws/azure) · 53 compliance export · 54 GDPR delete · 56 HA replicas · 57 webhook HMAC · 58 read/write RBAC · 59 server integration tests

→ Real answer: "we'll do these after a customer signs an MSA requiring them, not before."

### Built because the checklist had a box (delete)
38 Grafana dashboards · 39 Kafka capture · 40 Homebrew/apt/rpm packages · 41 post-hoc PII scrub · 45 CI/CD GitHub Action · 46 structured logging JSON · 55 Prometheus alerting rules · 49 Slack/webhook notification · 50 snapshot search

→ Real answer: "we will rebuild on demand. shipping these without customer pull is a tell."

### Adjacent features competing with the core (defer)
10 MongoDB · 11 Postgres row snapshot · 12 gRPC HPACK · 14 Jaeger export · 33 VS Code extension · 34 replay diff · 35 SaaS web UI · 37 cloud storage sink · 61 replay validation · 62 service attribution v1 · 63 `rewind diff`

→ Real answer: "every protocol/format/integration past Postgres+Redis is a feature for the second design partner. don't build for them yet."

### Defensible but premature (keep design, ship later)
22 eBPF overhead docs · 24 `/healthz` `/metrics` · 25 PII redact config · 26 multi-arch docker · 29 PagerDuty webhook trigger · 31 retention/TTL · 36 seccomp/AppArmor

→ Real answer: "needed for prod, but not needed *before* a design partner is in prod."

## The cuts in one sentence

> We stop shipping enterprise features until an enterprise customer signs the contract that needs them.

## What this changes about the next 4 weeks

- Stop writing Rust unless it makes capture/replay/k8s-attribution more reliable.
- Every Friday: did one design partner run `rewind flush` against real prod this week?
  - If yes, what broke? Fix that first.
  - If no, the whole roadmap is wrong. Stop building. Talk to 5 SREs.
- All "[Done]" milestones in CLAUDE.md outside the 5 above get a `[FROZEN]` tag.
- Public post: "we cut 58 features. here's what we kept and why." This is itself a distribution event — engineers respect ruthless founders, this is on-brand for an eBPF tool.

## The trap to avoid

Velocity is not progress. 94 commits in 7 days that ship features nobody asked for is worse than 3 commits a week that ship what one design partner needs. The repo currently looks like the former.
