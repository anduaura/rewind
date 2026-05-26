"""Sanity tests for the in-process replay.

Verifies the harness mechanics independently of the LLM:
 - The seeded buggy code reproduces the recorded 500.
 - A trivially-patched version makes the replay pass.

Run: python -m pytest test_replay.py -q
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from replay import replay

HERE = Path(__file__).parent
SNAPSHOT = HERE / "fixtures" / "incident-204.rwd"
SERVICE = HERE / "fixtures" / "service" / "app.py"

PATCHED_APP = '''\
import os
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
WORKER_URL = os.getenv("WORKER_URL", "http://worker:8081")


@app.route("/process", methods=["POST"])
def process():
    payload = request.get_json(force=True)
    job_id = payload.get("job_id", 0)

    resp = requests.post(
        f"{WORKER_URL}/run",
        json={"job_id": job_id},
        timeout=5,
    )
    worker_result = resp.json() if resp.status_code != 204 and resp.text else None

    return jsonify({
        "job_id": job_id,
        "status": "ok",
        "worker_result": worker_result,
    })
'''


def test_buggy_code_reproduces_incident():
    r = replay(SNAPSHOT, SERVICE)
    assert not r.passed
    assert r.status_code == 500


def test_patched_code_makes_replay_pass(tmp_path):
    patched = tmp_path / "app.py"
    patched.write_text(PATCHED_APP)
    r = replay(SNAPSHOT, patched)
    assert r.passed
    assert r.status_code == 200
