//! Load test for the rewind collection server.
//!
//! Runs N virtual users in parallel, each cycling through upload → list →
//! download for the requested duration. Reports throughput, latency
//! percentiles, and error rate; exits 1 if the error rate exceeds
//! --max-error-pct.
//!
//! Usage:
//!   # Start the server first:
//!   rewind server --listen 127.0.0.1:9092 --storage /tmp/rwd-load --token tok
//!
//!   # Run the load test:
//!   cargo run --bin load_test -- --url http://127.0.0.1:9092 --token tok
//!   cargo run --bin load_test -- --concurrency 50 --duration-secs 60

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use clap::Parser;
use reqwest::Client;

#[derive(Parser, Debug)]
#[command(about = "Load-test the rewind collection server")]
struct Args {
    /// Base URL of the collection server.
    #[arg(long, default_value = "http://127.0.0.1:9092")]
    url: String,

    /// Bearer token for authentication (omit for open servers).
    #[arg(long)]
    token: Option<String>,

    /// Number of concurrent virtual users.
    #[arg(long, default_value_t = 10)]
    concurrency: usize,

    /// How long to run the test, in seconds.
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,

    /// Synthetic snapshot size in KB.
    #[arg(long, default_value_t = 10)]
    snapshot_kb: usize,

    /// Fail if error percentage exceeds this threshold.
    #[arg(long, default_value_t = 1.0)]
    max_error_pct: f64,
}

// ── Metrics ───────────────────────────────────────────────────────────────────

struct Counters {
    uploads: AtomicU64,
    lists: AtomicU64,
    downloads: AtomicU64,
    errors: AtomicU64,
}

impl Counters {
    fn new() -> Self {
        Self {
            uploads: AtomicU64::new(0),
            lists: AtomicU64::new(0),
            downloads: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    fn total_ok(&self) -> u64 {
        self.uploads.load(Ordering::Relaxed)
            + self.lists.load(Ordering::Relaxed)
            + self.downloads.load(Ordering::Relaxed)
    }
}

// ── Synthetic snapshot ────────────────────────────────────────────────────────

fn make_snapshot(size_kb: usize) -> Vec<u8> {
    let base = serde_json::json!({
        "version": 1,
        "recorded_at_ns": 1_745_489_581_000_000_000u64,
        "services": ["load-test"],
        "events": [{
            "type": "http",
            "timestamp_ns": 1_745_489_581_001_000_000u64,
            "direction": "inbound",
            "method": "GET",
            "path": "/health",
            "status_code": 200,
            "service": "load-test",
            "trace_id": null,
            "body": null,
            "headers": []
        }]
    });
    let mut v = serde_json::to_vec_pretty(&base).unwrap();
    let target = size_kb * 1024;
    if v.len() < target {
        v.extend(std::iter::repeat(b' ').take(target - v.len()));
    }
    v
}

// ── Statistics ────────────────────────────────────────────────────────────────

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * pct / 100.0).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

// ── Virtual user loop ─────────────────────────────────────────────────────────

async fn virtual_user(
    vu_id: usize,
    client: Client,
    base_url: String,
    token: Option<String>,
    snapshot: Arc<Vec<u8>>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    latencies: Arc<tokio::sync::Mutex<Vec<f64>>>,
) {
    let mut local_lats: Vec<f64> = Vec::new();
    let mut iteration = 0u64;

    macro_rules! auth {
        ($req:expr) => {
            if let Some(tok) = &token {
                $req.header("authorization", format!("Bearer {tok}"))
            } else {
                $req
            }
        };
    }

    while !stop.load(Ordering::Relaxed) {
        let snap_name = format!("load-{vu_id:03}-{iteration:06}.rwd");

        // Upload
        let t = Instant::now();
        let req = auth!(client
            .post(format!("{base_url}/snapshots"))
            .header("content-type", "application/octet-stream")
            .header("x-rewind-snapshot", &snap_name)
            .body(snapshot.as_ref().clone()));
        match req.send().await {
            Ok(r) if r.status().as_u16() == 201 || r.status().is_success() => {
                counters.uploads.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        local_lats.push(t.elapsed().as_secs_f64() * 1000.0);

        if stop.load(Ordering::Relaxed) {
            break;
        }

        // List
        let t = Instant::now();
        let req = auth!(client.get(format!("{base_url}/snapshots")));
        match req.send().await {
            Ok(r) if r.status().is_success() => {
                counters.lists.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        local_lats.push(t.elapsed().as_secs_f64() * 1000.0);

        if stop.load(Ordering::Relaxed) {
            break;
        }

        // Download the snapshot we just uploaded
        let t = Instant::now();
        let req = auth!(client.get(format!("{base_url}/snapshots/{snap_name}")));
        match req.send().await {
            Ok(r) if r.status().is_success() => {
                counters.downloads.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        local_lats.push(t.elapsed().as_secs_f64() * 1000.0);

        iteration += 1;
    }

    latencies.lock().await.extend(local_lats);
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let base_url = args.url.trim_end_matches('/').to_string();

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build reqwest client");

    println!("rewind load test");
    println!("  target:      {base_url}");
    println!("  concurrency: {} VU", args.concurrency);
    println!("  duration:    {}s", args.duration_secs);
    println!("  snapshot:    {} KB", args.snapshot_kb);
    println!();

    // Health check
    let health_url = format!("{base_url}/healthz");
    match client.get(&health_url).send().await {
        Ok(r) if r.status().is_success() => println!("  healthz: OK"),
        Ok(r) => {
            eprintln!("  healthz returned {} — is the server running?", r.status());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("  Cannot reach {base_url}: {e}");
            std::process::exit(1);
        }
    }
    println!("  Running…\n");

    let snapshot = Arc::new(make_snapshot(args.snapshot_kb));
    let counters = Arc::new(Counters::new());
    let stop = Arc::new(AtomicBool::new(false));
    let latencies: Arc<tokio::sync::Mutex<Vec<f64>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let start = Instant::now();
    let duration = Duration::from_secs(args.duration_secs);

    // Spawn virtual users
    let mut tasks = Vec::new();
    for vu_id in 0..args.concurrency {
        tasks.push(tokio::spawn(virtual_user(
            vu_id,
            client.clone(),
            base_url.clone(),
            args.token.clone(),
            Arc::clone(&snapshot),
            Arc::clone(&counters),
            Arc::clone(&stop),
            Arc::clone(&latencies),
        )));
    }

    // Progress ticker — prints a line every 5 s
    {
        let counters = Arc::clone(&counters);
        let stop = Arc::clone(&stop);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let ok = counters.total_ok();
                let err = counters.errors.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs();
                let rps = if elapsed > 0 { ok / elapsed } else { 0 };
                println!("  t={elapsed:3}s  ok={ok}  err={err}  {rps} req/s");
            }
        });
    }

    tokio::time::sleep(duration).await;
    stop.store(true, Ordering::Relaxed);
    for t in tasks {
        let _ = t.await;
    }

    // ── Results ───────────────────────────────────────────────────────────────

    let elapsed = start.elapsed().as_secs_f64();
    let uploads = counters.uploads.load(Ordering::Relaxed);
    let lists = counters.lists.load(Ordering::Relaxed);
    let downloads = counters.downloads.load(Ordering::Relaxed);
    let errors = counters.errors.load(Ordering::Relaxed);
    let total_ok = uploads + lists + downloads;
    let total_all = total_ok + errors;
    let throughput = total_ok as f64 / elapsed;
    let error_pct = if total_all > 0 {
        errors as f64 / total_all as f64 * 100.0
    } else {
        0.0
    };

    let mut lats = latencies.lock().await;
    lats.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = percentile(&lats, 50.0);
    let p90 = percentile(&lats, 90.0);
    let p95 = percentile(&lats, 95.0);
    let p99 = percentile(&lats, 99.0);
    let max_lat = lats.last().copied().unwrap_or(0.0);
    let avg_lat = if lats.is_empty() {
        0.0
    } else {
        lats.iter().sum::<f64>() / lats.len() as f64
    };

    println!();
    println!("── Results ─────────────────────────────────────────────────────");
    println!("  Duration:     {elapsed:.1}s");
    println!("  Concurrency:  {} VU", args.concurrency);
    println!("  Uploads:      {uploads}");
    println!("  Lists:        {lists}");
    println!("  Downloads:    {downloads}");
    println!("  Errors:       {errors}  ({error_pct:.2}%)");
    println!("  Throughput:   {throughput:.1} req/s");
    println!("  Latency avg:  {avg_lat:.1}ms");
    println!("  Latency p50:  {p50:.1}ms");
    println!("  Latency p90:  {p90:.1}ms");
    println!("  Latency p95:  {p95:.1}ms");
    println!("  Latency p99:  {p99:.1}ms");
    println!("  Latency max:  {max_lat:.1}ms");
    println!("────────────────────────────────────────────────────────────────");

    if error_pct > args.max_error_pct {
        eprintln!(
            "FAIL  error rate {error_pct:.2}% exceeds threshold {:.2}%",
            args.max_error_pct
        );
        std::process::exit(1);
    } else {
        println!("PASS  error rate {error_pct:.2}% within threshold {:.2}%", args.max_error_pct);
    }
}
