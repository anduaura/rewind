"""API service.

Receives /process requests, fans out to the worker, returns the result.
"""
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
    worker_result = resp.json()

    return jsonify({
        "job_id": job_id,
        "status": "ok",
        "worker_result": worker_result,
    })


@app.route("/health")
def health():
    return jsonify({"service": "api", "ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
