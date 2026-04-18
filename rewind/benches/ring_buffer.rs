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

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rewind::capture::ring::RingBuffer;
use rewind::store::snapshot::{Event, SyscallRecord};
use std::time::Duration;

fn make_syscall(i: u64) -> Event {
    Event::Syscall(SyscallRecord {
        timestamp_ns: i * 1_000_000,
        kind: "clock_gettime".to_string(),
        return_value: i,
        pid: 1234,
    })
}

fn bench_push(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(1));

    group.bench_function("push/within_capacity", |b| {
        let mut ring = RingBuffer::new(200_000);
        let mut i = 0u64;
        b.iter(|| {
            ring.push(black_box(make_syscall(i)));
            i += 1;
        });
    });

    group.bench_function("push/at_capacity_evict", |b| {
        // Pre-fill to capacity so every push triggers an eviction.
        let mut ring = RingBuffer::new(1_000);
        for i in 0..1_000u64 {
            ring.push(make_syscall(i));
        }
        let mut i = 1_000u64;
        b.iter(|| {
            ring.push(black_box(make_syscall(i)));
            i += 1;
        });
    });

    group.finish();
}

fn bench_drain(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");

    group.bench_function("drain_window/5m/10k_events", |b| {
        let mut ring = RingBuffer::new(200_000);
        for i in 0..10_000u64 {
            ring.push(make_syscall(i));
        }
        b.iter(|| {
            black_box(ring.drain_window(Duration::from_secs(300)));
        });
    });

    group.bench_function("drain_all/10k_events", |b| {
        let mut ring = RingBuffer::new(200_000);
        for i in 0..10_000u64 {
            ring.push(make_syscall(i));
        }
        b.iter(|| {
            black_box(ring.drain_window(Duration::MAX));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_push, bench_drain);
criterion_main!(benches);
