"""Agent-driven incident fix.

End-to-end loop:
  1. Read a .rwd snapshot and the service source code
  2. Replay against the snapshot -> confirm the bug reproduces
  3. Ask Claude to propose a patch (structured tool_use, single file)
  4. Apply the patch to a sandbox copy of the service
  5. Replay against the sandbox copy -> verify the fix

Exits 0 if the agent's first proposed patch makes the replay pass.

Usage:
  pip install -r requirements.txt
  export ANTHROPIC_API_KEY=sk-...
  python agent.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import textwrap
from pathlib import Path

from anthropic import Anthropic

from replay import replay

HERE = Path(__file__).parent
SNAPSHOT = HERE / "fixtures" / "incident-204.rwd"
SERVICE = HERE / "fixtures" / "service" / "app.py"

MODEL = os.environ.get("AGENT_MODEL", "claude-sonnet-4-6")
MAX_ITERATIONS = int(os.environ.get("AGENT_MAX_ITERATIONS", "3"))

SYSTEM_PROMPT = """You are an autonomous SRE agent.

You are given a deterministic replay of a production incident — a .rwd
snapshot file captured by the rewind eBPF agent — plus the source code of the
service that crashed during the incident.

Your job: identify the root cause and propose a single-file patch that fixes
the bug. The patch will be applied verbatim and then the snapshot will be
replayed against the patched code. If the replay produces a 2xx response, the
fix is verified. If not, you have one more attempt.

Be conservative. Make the smallest change that fixes the observed failure.
Do not refactor. Do not add unrelated improvements. The patch must keep the
service contract (route paths, response shape) unchanged."""

PATCH_TOOL = {
    "name": "propose_patch",
    "description": (
        "Propose a single-file patch to fix the bug. The new_content replaces the "
        "entire file contents verbatim."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Relative path of the file being patched.",
            },
            "new_content": {
                "type": "string",
                "description": "Full new contents of the file.",
            },
            "explanation": {
                "type": "string",
                "description": "1-3 sentence explanation of the root cause and the fix.",
            },
        },
        "required": ["file_path", "new_content", "explanation"],
    },
}


def summarise_snapshot(snapshot: dict) -> str:
    lines = [
        f"Services: {', '.join(snapshot['services'])}",
        f"Recorded events: {len(snapshot['events'])}",
        "",
        "Event timeline:",
    ]
    for i, ev in enumerate(snapshot["events"], 1):
        if ev["type"] == "http":
            direction = ev["direction"]
            status = ev["status_code"]
            body = ev.get("body")
            body_str = (
                f" body={body[:120]!r}" if body else " body=<empty>"
            )
            status_str = f" status={status}" if status is not None else " status=<request>"
            lines.append(
                f"  {i}. HTTP {direction} {ev['method']} {ev['path']}"
                f"{status_str}{body_str}"
            )
        else:
            lines.append(f"  {i}. {ev['type']} event")
    return "\n".join(lines)


def write_sandbox(service_path: Path) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="rewind-agent-"))
    dest = tmp / service_path.name
    shutil.copy(service_path, dest)
    return dest


def print_banner(msg: str):
    print()
    print("─" * 72)
    print(msg)
    print("─" * 72)


def main() -> int:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 2

    client = Anthropic()

    print_banner("Step 1 — confirm the bug reproduces against current code")
    baseline = replay(SNAPSHOT, SERVICE)
    print(f"  status_code={baseline.status_code} passed={baseline.passed}")
    print(f"  details:    {baseline.details}")
    if baseline.passed:
        print("the snapshot already passes — nothing to fix")
        return 0

    snapshot = json.loads(SNAPSHOT.read_text())
    summary = summarise_snapshot(snapshot)
    service_source = SERVICE.read_text()

    user_prompt = textwrap.dedent(f"""\
        ## Snapshot summary

        {summary}

        ## Raw .rwd snapshot

        ```json
        {json.dumps(snapshot, indent=2)}
        ```

        ## Service source ({SERVICE.name})

        ```python
        {service_source}
        ```

        ## What the replay showed

        Replaying this snapshot against the current code produced:
          status_code = {baseline.status_code}
          details     = {baseline.details}
          body        = {baseline.body[:300]}

        Propose a single-file patch via the propose_patch tool that makes the
        replay return a 2xx status.""")

    for attempt in range(1, MAX_ITERATIONS + 1):
        print_banner(f"Step 2.{attempt} — ask Claude for a patch")
        resp = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=[PATCH_TOOL],
            tool_choice={"type": "tool", "name": "propose_patch"},
            messages=[{"role": "user", "content": user_prompt}],
        )

        tool_use = next(
            (b for b in resp.content if getattr(b, "type", None) == "tool_use"),
            None,
        )
        if tool_use is None:
            print("agent did not call propose_patch — aborting")
            return 1

        patch = tool_use.input
        print(f"  agent proposes patching: {patch['file_path']}")
        print(f"  agent explanation:")
        for line in textwrap.wrap(patch["explanation"], width=70):
            print(f"    {line}")

        print_banner(f"Step 3.{attempt} — apply patch and re-replay")
        sandbox = write_sandbox(SERVICE)
        sandbox.write_text(patch["new_content"])
        print(f"  sandbox: {sandbox}")

        result = replay(SNAPSHOT, sandbox)
        print(f"  status_code={result.status_code} passed={result.passed}")
        print(f"  details:    {result.details}")
        print(f"  body:       {result.body[:200]}")

        if result.passed:
            print_banner("VERIFIED — replay is green after the agent's patch")
            print("This is a verified fix, not a suspected one.")
            print(f"Patch applied at: {sandbox}")
            return 0

        print(f"  replay still failing after attempt {attempt}/{MAX_ITERATIONS}")
        user_prompt += textwrap.dedent(f"""\

            ## Attempt {attempt} feedback

            Your previous patch was applied but the replay still failed:
              status_code = {result.status_code}
              details     = {result.details}
              body        = {result.body[:300]}

            Try again with a different approach.""")

    print_banner("FAILED — agent could not produce a passing patch")
    return 1


if __name__ == "__main__":
    sys.exit(main())
