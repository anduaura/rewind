// Copyright 2026 The rewind Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Benchmarks for .rwd snapshot serialisation / deserialisation.
//! Run with: cargo bench --bench snapshot

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rewind::store::snapshot::{DbRecord, Event, HttpRecord, Snapshot, SyscallRecord};

fn make_snapshot(n: usize) -> Snapshot {
    let mut s = Snapshot::new(vec!["api".to_string(), "worker".to_string()]);
    for i in 0..n {
        let ts = i as u64 * 1_000_000;
        // Mix of event types to represent a realistic incident window.
        match i % 3 {
            0 => s.events.push(Event::Http(HttpRecord {
                timestamp_ns: ts,
                direction: "inbound".to_string(),
                method: "POST".to_string(),
                path: "/api/run".to_string(),
                status_code: Some(200),
                service: "api".to_string(),
                trace_id: Some(
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
                ),
                body: None,
                headers: Vec::new(),
            })),
            1 => s.events.push(Event::Db(DbRecord {
                timestamp_ns: ts,
                protocol: "postgres".to_string(),
                query: "INSERT INTO jobs (job_id, result) VALUES ($1, $2)".to_string(),
                response: Some("INSERT 0 1".to_string()),
                service: "worker".to_string(),
                pid: 42,
            })),
            _ => s.events.push(Event::Syscall(SyscallRecord {
                timestamp_ns: ts,
                kind: "getrandom".to_string(),
                return_value: 8,
                pid: 42,
            })),
        }
    }
    s
}

fn bench_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot");
    let path = std::env::temp_dir().join("rewind_bench_write.rwd");

    for &n in &[100, 1_000, 10_000] {
        let snapshot = make_snapshot(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            criterion::BenchmarkId::new("write", n),
            &snapshot,
            |b, s| {
                b.iter(|| s.write(black_box(&path), None).unwrap());
            },
        );
    }
    group.finish();
}

fn bench_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot");
    let path = std::env::temp_dir().join("rewind_bench_read.rwd");

    for &n in &[100, 1_000, 10_000] {
        let snapshot = make_snapshot(n);
        snapshot.write(&path, None).unwrap();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(criterion::BenchmarkId::new("read", n), &n, |b, _| {
            b.iter(|| black_box(Snapshot::read(&path, None)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_write, bench_read);
criterion_main!(benches);
