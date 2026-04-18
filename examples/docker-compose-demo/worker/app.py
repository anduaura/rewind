"""Worker service — processes jobs, persists results to Postgres, caches in Redis."""
import json
import os
import random
import time

import psycopg2
import redis as redis_lib
from flask import Flask, jsonify, request

app = Flask(__name__)

pg = psycopg2.connect(
    host=os.getenv("POSTGRES_HOST", "postgres"),
    dbname=os.getenv("POSTGRES_DB", "demo"),
    user=os.getenv("POSTGRES_USER", "postgres"),
    password=os.getenv("POSTGRES_PASSWORD", "secret"),
)
cache = redis_lib.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)


@app.route("/run", methods=["POST"])
def run():
    payload = request.get_json(force=True)
    job_id = payload.get("job_id", random.randint(1000, 9999))
    cache_key = f"job:{job_id}"

    # Check Redis cache first — rewind records this getrandom + clock + Redis GET.
    cached = cache.get(cache_key)
    if cached:
        return jsonify(json.loads(cached))

    # Simulate non-deterministic work.
    duration_ms = random.randint(10, 50)
    time.sleep(duration_ms / 1000)
    result = random.randint(1, 1_000_000)
    processed_at = time.time_ns()

    # Persist to Postgres — rewind records this INSERT via Postgres wire protocol.
    with pg.cursor() as cur:
        cur.execute(
            "INSERT INTO jobs (job_id, result, created_at) VALUES (%s, %s, NOW())",
            (job_id, result),
        )
    pg.commit()

    response = {
        "job_id": job_id,
        "result": result,
        "processed_at": processed_at,
        "duration_ms": duration_ms,
    }

    # Cache for 5 minutes — rewind records this SETEX via Redis RESP.
    cache.setex(cache_key, 300, json.dumps(response))

    return jsonify(response)


@app.route("/health")
def health():
    try:
        with pg.cursor() as cur:
            cur.execute("SELECT 1")
        cache.ping()
        return jsonify({"service": "worker", "ok": True})
    except Exception as e:
        return jsonify({"service": "worker", "ok": False, "error": str(e)}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
