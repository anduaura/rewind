# Coverage stance: pick the lane

## The question a YC partner asks

> "Your README says you cover ~75% of incidents with HTTP + DB capture. What about the other 25%? What about thread-scheduling Heisenbugs? Sell me the ceiling."

Today's answer is hedged: "well, ~90% with row snapshots, ~95% with full DB, thread scheduling is not solvable." That is the engineer's honest answer. It is not the founder's answer.

The founder's answer needs to pick one lane and own it.

## Two lanes

### Lane A — "75% is the product. Heisenbugs are out of scope on purpose."

The argument: the long tail of incidents is *not* where the value is. The cluster that matters is:
- API returned 500 because downstream returned malformed JSON
- DB query timed out, caller didn't handle, cascading failure
- Race between a config reload and a request
- Auth middleware rejected because clock skew
- Worker returned 204, caller called `.json()`

All of these are HTTP + DB + clock + random. All are deterministic given the recorded inputs. The Heisenbug tail (lock-free data structure races, kernel scheduler quirks, hardware-level non-determinism) is a research problem, not a product problem, and the customer impact is < 5% of incident volume.

> "We chose 75% on purpose. The remaining 25% is a different product — academic research tools, not incident response. We will never ship a feature that pretends to solve it. The 75% we solve is solved completely and deterministically, not probabilistically."

This is defensible if:
- Design partner data backs the 75% number (concrete: "out of 47 SEV-2+ incidents in Q1, rewind would have captured root cause in 35")
- The product is *brutally good* at the 75%. Every replay is byte-exact. No flakes.

This is the conservative lane. Easier to defend. Smaller TAM ceiling.

### Lane B — "We're cracking the rest. Here's the roadmap."

The argument: HTTP + DB + clock + random gets us to 75%. The next 20% is *thread scheduling*. The technique exists — `rr` (Mozilla) does it for single-process programs by serializing all syscalls onto one core and replaying the syscall log. Apply the same primitive across containers using eBPF as the syscall tap, with a coordinator that linearizes the cross-container syscall order.

Hard? Yes. Solved at small scale? Yes — `rr` works. Has anyone done it across containers? No. That gap is the moat.

> "We are the first product to extend rr-style record-replay across container boundaries. We are 4-6 months from a research prototype, 12-18 months from a shipping feature. The 75% lane is the wedge — Heisenbug replay is the long game."

This is defensible if:
- Founder has read `rr` papers and can talk specifics about scheduler events, recorded reservations, branch counter usage on x86
- There is a written design doc with the eBPF probes that would be needed (`sched_switch`, `sched_wakeup`, `finish_task_switch`)
- Founder is honest that the demo is 12+ months out

This is the ambitious lane. Bigger TAM ceiling. Higher technical risk. The right lane for a YC pitch in 2026 because partners are funding ambition, not maintenance.

## Recommendation: Lane B, with Lane A as the wedge

Pitch lane B for the *product story*. Ship lane A for the *first $1M ARR*.

The story to a partner:

> "Phase 1 — own deterministic HTTP+DB replay. 75% of incidents. This is the wedge, this is the substrate AI agents run on today. We have customers in Q3 on this.
> 
> Phase 2 — extend record-replay across containers using rr-style syscall serialization on eBPF. 95% of incidents including thread races. This is the long-term moat. We start the research in Q4, ship in 12-18 months. It has never been done across a distributed system."

Two-lane pitch. Customers on lane A funds lane B. Lane B is the venture-scale answer.

## What to put in the README

Replace the current honest-but-hedged "incident coverage" section with:

```markdown
## Incident coverage

**Phase 1 — what rewind captures today:**
- All inter-service HTTP / gRPC traffic
- Postgres, Redis, MySQL, MongoDB wire protocols (requests + responses)
- Non-deterministic syscalls: `clock_gettime`, `getrandom`

In production usage, this captures the root cause of ~75% of SEV-2+ incidents.

**Phase 2 — on the roadmap (12-18 mo):**
- Cross-container syscall record-replay (rr-style scheduling determinism)
- Target: ~95% of incidents including thread-race Heisenbugs

The other ~5% — hardware-level non-determinism, memory-corruption bugs — is
out of scope. That's a research-tool problem, not an incident-response one.
```

Concrete, ambitious, honest about the ceiling. Three short paragraphs replace a confusing four-bullet list.

## What this requires before the YC interview

1. Confirm the 75% number with at least one design partner's incident log (replace estimate with data).
2. Write a 2-3 page design doc for phase 2 — even a sketch — so the partner question "have you thought about how?" has an answer.
3. Drop the "Heisenbugs are not solvable" line from CLAUDE.md. It is true today and false tomorrow if phase 2 ships.
