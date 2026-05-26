# We let Claude debug a production incident. It actually worked.

*Draft — for personal blog / Hacker News. ~1500 words. Target: 500+ HN upvotes.*

---

Every observability vendor in 2026 has shipped an "AI incident assistant." They all do the same thing: read your logs, read your traces, produce a plausible-sounding narrative about what went wrong, and link to a runbook.

It is theater. The agent has never seen the incident. The agent cannot reproduce the incident. The agent is *guessing* from text, and there is no way to know whether the guess is right until a human re-runs the bug in staging. The agent's PR description says "I think this is the cause." That's not a fix. That's a prompt.

The reason it's theater is that the incident is *gone*. The state is gone, the timing is gone, the network reality is gone. You have a low-resolution shadow of what happened (logs) and you have to debug the shadow.

We've been working on the boring fix. Capture the incident *completely*, in production, with zero code changes. Save it as a single file. Hand the file to an AI agent. Now the agent can re-run the bug as many times as it wants. It can patch the code, re-run, and produce a hard pass/fail.

It works.

---

## The setup

Our open-source tool is called rewind. It's an eBPF agent that attaches to running containers (no SDK, no code change) and captures three things:

1. **Every inter-service network call** — full HTTP request, response, status, timestamps. Plus DB wire protocol traffic — Postgres, Redis, MySQL — request + response.
2. **Every non-deterministic syscall** — `clock_gettime` (so the replay knows what time the service thought it was), `getrandom` (so anything seeded by randomness comes back the same).
3. **Trace context** — `traceparent` headers, so events across multiple services stitch into one timeline.

All of that goes into an in-memory ring buffer. When an alert fires, you call `rewind flush` and the last 5 minutes get written to a single `.rwd` file (basically a JSON timeline).

Now you have an incident on disk.

Replay is the dual:
1. Override the clock inside the replayed containers (libfaketime, injected from the host — no image change).
2. Override outbound network calls with the recorded responses (a small mock server).
3. Re-execute the triggering request.

The service runs exactly the same code path it ran in prod, against exactly the same observed inputs. Deterministically.

## The bug

To demo this honestly, we need a real-feeling bug, not a contrived one. Here's the scenario:

An API service hands off jobs to a worker:

```python
@app.post("/orders")
def create_order():
    job_id = save_job_to_db()
    resp = requests.post(f"{WORKER_URL}/run", json={"job_id": job_id}, timeout=5)
    worker_result = resp.json()
    return {"job_id": job_id, "status": "ok", "worker_result": worker_result}
```

For months, the worker returned a JSON object. The API parsed it, nobody died.

A worker redeploy: the worker team optimized the "nothing to do" path. Instead of returning `{}`, it now returns `204 No Content` with an empty body.

The API now does `resp.json()` on an empty body. `JSONDecodeError`. 500 to the client.

The logs look like this:

```
[ERROR] requests.exceptions.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
  File "requests/models.py", line 978, in json
```

…which tells you something failed to parse JSON. It does not tell you that the worker started returning 204. To figure that out, you have to either be lucky (a teammate remembers the worker deploy) or grep through worker logs at the right minute, or — if you're in the modern stack — wait for a Datadog AI assistant to read both sides of the trace and *guess* that the bodies don't match.

## What we did

We captured the incident with rewind. The `.rwd` file contains:
- The inbound `POST /orders` request and the 500 response
- The outbound call to the worker — which the snapshot shows as a 204
- The `clock_gettime` value the API saw
- The full timeline, in order

Total file size: 4.2 KB.

We wrote a 200-line harness. It does this:

1. Load the snapshot.
2. Run the service code against the snapshot — confirm the 500 reproduces.
3. Send the snapshot + the source file to Claude with a single tool: `patch_file(path, new_content, explanation)`.
4. Wait for Claude to call the tool.
5. Apply the patch to a sandbox copy of the source.
6. Re-run the snapshot against the patched code.
7. If the response is 2xx and matches the recorded shape, it's a verified fix. If not, send the new error back to Claude and try again.

We ran it. Here's what happened.

---

**Attempt 1.** Claude reads the snapshot. It sees the recorded worker response is `HTTP 204` with an empty body. It sees `resp.json()` immediately after. It writes:

```python
if resp.status_code == 204 or not resp.content:
    worker_result = None
else:
    worker_result = resp.json()
```

Harness applies the patch, re-runs the replay. Status 200. Body matches.

Total wall time: 11 seconds.

The PR Claude opened (we wired it up to gh CLI) said:

> Fix `JSONDecodeError` when worker returns `204 No Content`.
>
> **Reproduction:** verified against snapshot `incident-204.rwd`.
> **Fix:** guard `resp.json()` with `resp.status_code != 204 and resp.content`.
> **Verification:** re-ran the snapshot after applying the patch. Status code now 200, response body matches recorded shape.

That last line is the one that matters. Not "I think this fixes it." *I reproduced this. I applied this fix. The replay now passes.*

## Why this is different

I want to be specific about what's new here, because "AI fixes bug" is a tired claim.

What's new is the **substrate**. The agent has a deterministic, replayable artifact to experiment against. It is not reasoning about the bug from text. It is *running* the bug. It runs it again and again, with different patches, until one passes. The success criterion is a real `200 == 200` check, not a model's confidence score.

This changes the trust calculus. The PR is not "please review this and verify in staging." The PR is "I verified this against the captured incident. Here is the snapshot. Re-run it yourself if you want."

That's a fundamentally different reviewing experience. The reviewer can take 30 seconds to re-run the replay and confirm. They don't have to redo the reasoning.

And the agent can attempt this at 3am, with no human in the loop, and you wake up to a PR that is either green or honestly marked "I tried, couldn't fix it, here are the three patches that didn't work and why." That second outcome is *also* valuable — you've narrowed the search space without burning your morning.

## What it doesn't do

A few things we're deliberately not claiming:

**Bugs that aren't in the captured layer can't be fixed.** If the bug is a CPU-pinned race in a Rust async runtime, rewind won't help — we capture HTTP, DB, and a small set of syscalls. We don't capture thread scheduling (yet). That's a research problem we want to take on next, but it isn't solved today. Realistically, the layer we *do* capture accounts for around 75% of incidents we see in distributed systems. Microservice-to-microservice issues, database response handling, clock skew, random-seeded behavior. The hard kernel-level Heisenbugs are 5%.

**Replay isn't free.** The current implementation requires Docker Compose. We have an experiment running for Kubernetes replay but it's not shippable yet.

**This was one bug.** We seeded it. We picked a category we know we handle well (HTTP body parsing). We are not claiming this generalizes to every bug. We are claiming the loop — capture → replay → agent patch → re-replay → verified — is now mechanically possible, where before it was not.

## Why we're open sourcing it

Two reasons.

One, the substrate has to be open. Nobody is going to install a proprietary kernel-level capture agent. Trust requires the source.

Two, the most interesting use case isn't a single team debugging their own incidents. It's a *standard format* for incident snapshots that any AI agent — Claude, GPT, an open-weights model running on someone's laptop — can consume. If `.rwd` becomes the "PNG of incidents," every agent inherits the ability to verify production fixes. That only works if it's open.

## How to try it

The agent harness is in [`agent-harness/`](https://github.com/anduaura/rewind/tree/main/agent-harness). It runs against a real Anthropic API key. The seeded bug is included. End-to-end takes about 30 seconds and uses ~$0.05 of Claude credits.

```bash
git clone https://github.com/anduaura/rewind
cd rewind/agent-harness
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...
python agent.py
```

The full rewind tool — the eBPF capture agent and the replay engine — is in the parent repo. It needs Linux 5.10+ and root for the eBPF probes. There's a [getting-started guide](https://github.com/anduaura/rewind/blob/main/docs/getting-started.md) that walks through capturing a real incident from a Docker Compose stack.

I'd love to hear from anyone who tries this against a real incident. Email is in my profile. We're looking for design partners — specifically teams running on Kubernetes who want to be the first to put rewind in front of their actual SEV-2 pipeline.

---

*rewind is Apache 2.0. The agent harness is a demo, not a product — yet.*

---

## Editorial notes (delete before posting)

- HN headline candidates, ordered:
  1. "We let Claude debug a production incident. It actually worked."
  2. "Show HN: Deterministic replay for distributed systems, built so AI agents can verify fixes"
  3. "Capturing production incidents so an LLM can rerun them"
- Post Tuesday or Wednesday 8-10am Pacific for max HN reach.
- First comment should be the technical "how does this differ from rr/Speedscale/GoReplay" — pre-write it, drop in first.
- Have second post ready: the deep-dive on libfaketime host-side injection (E2). That's catnip for the systems crowd.
