"""API service — receives requests and delegates work to the worker."""
import os
import time
import random
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
WORKER_URL = os.getenv("WORKER_URL", "http://worker:8081")


@app.route("/process", methods=["POST"])
def process():
    payload = request.get_json(force=True)
    job_id = payload.get("job_id", random.randint(1000, 9999))

    # Outbound call to worker — this is what rewind will capture.
    resp = requests.post(
        f"{WORKER_URL}/run",
        json={"job_id": job_id, "ts": time.time_ns()},
        timeout=5,
    )
    result = resp.json()

    return jsonify({"job_id": job_id, "status": "ok", "worker_result": result})


@app.route("/health")
def health():
    return jsonify({"service": "api", "ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
