"""In-process replay.

Loads the API service module, intercepts outbound HTTP calls so they return the
responses recorded in the .rwd snapshot, then re-fires the recorded inbound
request and reports whether the service crashes.

This is a faithful (if minimal) implementation of what `rewind replay` does for
the full Docker Compose stack.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch


@dataclass
class ReplayResult:
    passed: bool
    status_code: int
    body: str
    details: str


def _load_module(service_path: Path):
    """Load fixtures/service/app.py as a fresh module each time so patches re-apply."""
    spec = importlib.util.spec_from_file_location("api_under_test", service_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["api_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


def _recorded_outbound_response(snapshot: dict) -> dict[str, Any]:
    """Find the outbound HTTP response (status_code != null) in the snapshot."""
    for ev in snapshot["events"]:
        if (
            ev.get("type") == "http"
            and ev.get("direction") == "outbound"
            and ev.get("status_code") is not None
        ):
            return ev
    raise RuntimeError("snapshot has no recorded outbound response")


def _recorded_inbound_request(snapshot: dict) -> dict[str, Any]:
    """Find the inbound HTTP request (status_code == null) in the snapshot."""
    for ev in snapshot["events"]:
        if (
            ev.get("type") == "http"
            and ev.get("direction") == "inbound"
            and ev.get("status_code") is None
        ):
            return ev
    raise RuntimeError("snapshot has no recorded inbound request")


def replay(snapshot_path: Path, service_path: Path) -> ReplayResult:
    snapshot = json.loads(snapshot_path.read_text())
    outbound = _recorded_outbound_response(snapshot)
    inbound = _recorded_inbound_request(snapshot)

    class MockResponse:
        def __init__(self, status: int, body: str):
            self.status_code = status
            self.text = body
            self._body = body

        def json(self):
            # Matches requests' real behaviour: empty body raises JSONDecodeError.
            return json.loads(self._body)

    def fake_post(url, *args, **kwargs):
        return MockResponse(outbound["status_code"], outbound.get("body") or "")

    mod = _load_module(service_path)

    with patch.object(mod.requests, "post", side_effect=fake_post):
        client = mod.app.test_client()
        try:
            resp = client.post(
                inbound["path"],
                data=inbound.get("body") or "",
                content_type="application/json",
            )
            status = resp.status_code
            body = resp.get_data(as_text=True)
        except Exception as e:
            return ReplayResult(
                passed=False,
                status_code=500,
                body="",
                details=f"service raised {type(e).__name__}: {e}",
            )

    passed = 200 <= status < 300
    details = "ok" if passed else f"non-2xx response: {status}"
    return ReplayResult(passed=passed, status_code=status, body=body, details=details)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--snapshot", required=True, type=Path)
    p.add_argument("--service", required=True, type=Path)
    a = p.parse_args()
    r = replay(a.snapshot, a.service)
    print(f"status={r.status_code} passed={r.passed}")
    print(f"details: {r.details}")
    print(f"body: {r.body[:200]}")
    sys.exit(0 if r.passed else 1)
