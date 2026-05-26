# agent-harness

End-to-end demo: an AI agent fixes a production incident using a `.rwd` snapshot
as its execution substrate.

This is the smallest possible loop that demonstrates the difference between
*narrating* an incident from logs and *experimenting* against the actual frozen
incident.

## The loop

```
.rwd snapshot ─┐
               ├─► replay (in-process)  ─► confirms bug reproduces
service code ──┘                          ▼
                                          ▼
                                  Claude (via tool_use)
                                          ▼
                                   proposes patch
                                          ▼
                                  apply to sandbox copy
                                          ▼
                                replay against patched code
                                          ▼
                              if 2xx ► VERIFIED FIX
                              if 5xx ► retry (up to N times)
```

The agent gets a hard pass/fail signal — not a vibe.

## The seeded bug

`fixtures/service/app.py` is an API service that fans out to a worker:

```python
resp = requests.post(f"{WORKER_URL}/run", json={"job_id": job_id}, timeout=5)
worker_result = resp.json()    # crashes when worker returns 204 No Content
```

The worker was redeployed and now returns `204 No Content` for some responses.
The API blindly calls `.json()` on the response, raising `JSONDecodeError`
and producing a 500.

`fixtures/incident-204.rwd` is the snapshot captured at the moment the incident
fired. It contains the inbound request, the outbound call to the worker, the
worker's 204 response, and the 500 that came back to the client.

From logs alone you would see:
```
ERROR Expecting value: line 1 column 1 (char 0)
  File "requests/models.py", line 978, in json
```
…which tells you something failed to parse JSON, but not what or why. From the
`.rwd` replay you can see exactly: the worker returned 204 with an empty body.

## Run it

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...
python agent.py
```

Expected output:

```
────────────────────────────────────────────────────────────────────────
Step 1 — confirm the bug reproduces against current code
────────────────────────────────────────────────────────────────────────
  status_code=500 passed=False
  details:    service raised JSONDecodeError: Expecting value: ...

────────────────────────────────────────────────────────────────────────
Step 2.1 — ask Claude for a patch
────────────────────────────────────────────────────────────────────────
  agent proposes patching: app.py
  agent explanation:
    The worker now returns 204 No Content for some responses, and the
    API blindly calls .json() on the response which fails on an empty
    body. Guard against 204/empty bodies before parsing.

────────────────────────────────────────────────────────────────────────
Step 3.1 — apply patch and re-replay
────────────────────────────────────────────────────────────────────────
  sandbox: /tmp/rewind-agent-xxxxxx/app.py
  status_code=200 passed=True
  details:    ok
  body:       {"job_id":7,"status":"ok","worker_result":null}

────────────────────────────────────────────────────────────────────────
VERIFIED — replay is green after the agent's patch
────────────────────────────────────────────────────────────────────────
```

## What this proves

Every observability vendor's "AI incident assistant" can read logs and produce
a plausible narrative of what went wrong. None of them can verify that the
narrative is correct, because the incident is gone.

This harness shows what a `.rwd` snapshot unlocks: the agent doesn't just
*describe* the failure, it *re-runs* it, patches the code, *re-runs* it again,
and reports a hard pass/fail. The PR it opens isn't "I think this might fix it"
— it's "I reproduced this, applied this fix, and the replay now passes."

That's the difference between an agent you have to fully second-guess and an
agent you can actually trust to act.

## Files

- `agent.py`      — the harness: read snapshot, ask Claude, apply patch, verify
- `replay.py`     — in-process replay (real one is `rewind replay` against Docker Compose)
- `fixtures/service/app.py`  — the buggy service that's the target of the patch
- `fixtures/incident-204.rwd` — the captured incident snapshot

## Honest scope

This harness is intentionally minimal:

- The replay runs in-process against a mocked worker (not the full Docker stack).
  The real `rewind replay` boots the whole Compose stack with the clock pinned
  and outbound calls intercepted.
- One file is patched per attempt. A real agent would touch multiple files,
  add tests, and run them.
- The bug is seeded. The point is to show the loop, not benchmark agent quality.

The substrate is the hard part. The agent loop is the legible, easy part that
makes the substrate obviously valuable.
