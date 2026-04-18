"""Worker service — does the actual processing."""
import time
import random
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/run", methods=["POST"])
def run():
    payload = request.get_json(force=True)
    job_id = payload.get("job_id")

    # Simulate work with a non-deterministic sleep and random result.
    # rewind records clock_gettime + getrandom so replay produces the same values.
    duration_ms = random.randint(10, 50)
    time.sleep(duration_ms / 1000)

    return jsonify({
        "job_id": job_id,
        "processed_at": time.time_ns(),
        "duration_ms": duration_ms,
        "result": random.randint(1, 1_000_000),
    })


@app.route("/health")
def health():
    return jsonify({"service": "worker", "ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
