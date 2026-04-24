/**
 * k6 load test for the rewind collection server.
 *
 * Scenarios:
 *   smoke   — 1 VU × 30 s: sanity check, all requests must succeed
 *   load    — ramp to 50 VU over 5 m: sustained production-like traffic
 *   stress  — ramp to 200 VU over 10 m: find saturation point
 *   spike   — instant 500 VU for 30 s: test burst resilience
 *
 * Usage:
 *   # Install k6: https://k6.io/docs/get-started/installation/
 *
 *   # Smoke (default):
 *   k6 run tests/load/k6-server.js
 *
 *   # Load test with env overrides:
 *   BASE_URL=http://collector:9092 TOKEN=mytoken SCENARIO=load \
 *     k6 run tests/load/k6-server.js
 *
 *   # Stress test with HTML report:
 *   SCENARIO=stress k6 run --out json=results.json tests/load/k6-server.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ── Configuration ─────────────────────────────────────────────────────────────

const BASE_URL  = __ENV.BASE_URL  || 'http://127.0.0.1:9092';
const TOKEN     = __ENV.TOKEN     || '';
const SCENARIO  = __ENV.SCENARIO  || 'smoke';

const HEADERS = TOKEN
  ? { 'Content-Type': 'application/octet-stream', Authorization: `Bearer ${TOKEN}` }
  : { 'Content-Type': 'application/octet-stream' };

const READ_HEADERS = TOKEN
  ? { Authorization: `Bearer ${TOKEN}` }
  : {};

// ── Synthetic snapshot (~10 KB) ───────────────────────────────────────────────

function makeSnapshot(sizeKb = 10) {
  const base = JSON.stringify({
    version: 1,
    recorded_at_ns: 1745489581000000000,
    services: ['load-test'],
    events: [{
      type: 'http',
      timestamp_ns: 1745489581001000000,
      direction: 'inbound',
      method: 'GET',
      path: '/health',
      status_code: 200,
      service: 'load-test',
      trace_id: null,
      body: null,
      headers: [],
    }],
  });
  const pad = ' '.repeat(Math.max(0, sizeKb * 1024 - base.length));
  return base + pad;
}

const SNAPSHOT_BODY = makeSnapshot(10);

// ── Custom metrics ────────────────────────────────────────────────────────────

const uploadDuration   = new Trend('upload_duration_ms',   true);
const listDuration     = new Trend('list_duration_ms',     true);
const downloadDuration = new Trend('download_duration_ms', true);
const uploadErrors     = new Counter('upload_errors');
const listErrors       = new Counter('list_errors');
const downloadErrors   = new Counter('download_errors');
const errorRate        = new Rate('error_rate');

// ── Scenario definitions ──────────────────────────────────────────────────────

const SCENARIOS = {
  smoke: {
    executor: 'constant-vus',
    vus: 1,
    duration: '30s',
  },
  load: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m',  target: 10  },  // ramp up
      { duration: '3m',  target: 50  },  // sustained
      { duration: '1m',  target: 0   },  // ramp down
    ],
  },
  stress: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m',  target: 50  },
      { duration: '3m',  target: 100 },
      { duration: '3m',  target: 200 },
      { duration: '2m',  target: 0   },
    ],
  },
  spike: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '10s', target: 500 },   // instant spike
      { duration: '30s', target: 500 },   // hold
      { duration: '10s', target: 0   },   // recovery
    ],
  },
};

export const options = {
  scenarios: { [SCENARIO]: SCENARIOS[SCENARIO] || SCENARIOS.smoke },
  thresholds: {
    // Overall error rate must be < 1 %.
    error_rate:           ['rate<0.01'],
    // Upload p95 < 500 ms under load.
    upload_duration_ms:   ['p(95)<500'],
    // List p95 < 200 ms.
    list_duration_ms:     ['p(95)<200'],
    // Download p95 < 500 ms.
    download_duration_ms: ['p(95)<500'],
  },
};

// ── VU loop ───────────────────────────────────────────────────────────────────

export default function () {
  const vuId = __VU;
  const iter = __ITER;
  const snapName = `load-${vuId}-${iter}.rwd`;

  // --- Upload ---
  const uploadRes = http.post(
    `${BASE_URL}/snapshots`,
    SNAPSHOT_BODY,
    {
      headers: { ...HEADERS, 'X-Rewind-Snapshot': snapName },
      tags: { name: 'upload' },
    }
  );
  uploadDuration.add(uploadRes.timings.duration);
  const uploadOk = check(uploadRes, { 'upload 201': (r) => r.status === 201 });
  if (!uploadOk) {
    uploadErrors.add(1);
    errorRate.add(1);
  } else {
    errorRate.add(0);
  }

  // --- List ---
  const listRes = http.get(`${BASE_URL}/snapshots`, {
    headers: READ_HEADERS,
    tags: { name: 'list' },
  });
  listDuration.add(listRes.timings.duration);
  const listOk = check(listRes, { 'list 200': (r) => r.status === 200 });
  if (!listOk) {
    listErrors.add(1);
    errorRate.add(1);
  } else {
    errorRate.add(0);
  }

  // --- Download ---
  const dlRes = http.get(`${BASE_URL}/snapshots/${snapName}`, {
    headers: READ_HEADERS,
    tags: { name: 'download' },
  });
  downloadDuration.add(dlRes.timings.duration);
  const dlOk = check(dlRes, { 'download 200': (r) => r.status === 200 });
  if (!dlOk) {
    downloadErrors.add(1);
    errorRate.add(1);
  } else {
    errorRate.add(0);
  }

  sleep(0.1); // 100 ms think time between cycles
}

// ── Teardown: print a summary link ───────────────────────────────────────────

export function handleSummary(data) {
  const ok = data.metrics.error_rate ? data.metrics.error_rate.values.rate < 0.01 : true;
  console.log(`\nLoad test complete. Pass: ${ok}`);
  return {
    stdout: JSON.stringify(data, null, 2),
  };
}
