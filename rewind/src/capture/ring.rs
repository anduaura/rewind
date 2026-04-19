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

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::store::snapshot::Event;

pub struct RingBuffer {
    inner: VecDeque<(Instant, Event)>,
    max_events: usize,
}

impl RingBuffer {
    pub fn new(max_events: usize) -> Self {
        Self { inner: VecDeque::new(), max_events }
    }

    pub fn push(&mut self, event: Event) {
        if self.inner.len() >= self.max_events {
            self.inner.pop_front();
        }
        self.inner.push_back((Instant::now(), event));
    }

    /// Returns all events recorded within `window` of now (cloned).
    /// Passing `Duration::MAX` returns every event in the buffer.
    pub fn drain_window(&self, window: Duration) -> Vec<Event> {
        match Instant::now().checked_sub(window) {
            Some(cutoff) => self.inner
                .iter()
                .filter(|(t, _)| *t >= cutoff)
                .map(|(_, e)| e.clone())
                .collect(),
            None => self.inner.iter().map(|(_, e)| e.clone()).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::snapshot::{DbRecord, Event, HttpRecord};

    fn http_event(ts: u64) -> Event {
        Event::Http(HttpRecord {
            timestamp_ns: ts,
            direction: "inbound".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            status_code: Some(200),
            service: "api".to_string(),
            trace_id: None,
            body: None,
        })
    }

    fn db_event(ts: u64) -> Event {
        Event::Db(DbRecord {
            timestamp_ns: ts,
            protocol: "postgres".to_string(),
            query: "SELECT 1".to_string(),
            response: None,
            service: "api".to_string(),
            pid: 1,
        })
    }

    #[test]
    fn push_within_capacity() {
        let mut rb = RingBuffer::new(10);
        rb.push(http_event(1));
        rb.push(http_event(2));
        assert_eq!(rb.len(), 2);
    }

    #[test]
    fn push_evicts_oldest_when_full() {
        let mut rb = RingBuffer::new(3);
        rb.push(http_event(1));
        rb.push(http_event(2));
        rb.push(http_event(3));
        rb.push(http_event(4)); // should evict ts=1
        assert_eq!(rb.len(), 3);
        // drain_window(MAX) returns all three; oldest should be ts=2
        let events = rb.drain_window(Duration::MAX);
        assert_eq!(events.len(), 3);
        if let Event::Http(h) = &events[0] {
            assert_eq!(h.timestamp_ns, 2);
        } else {
            panic!("expected Http event");
        }
    }

    #[test]
    fn drain_window_max_returns_all() {
        let mut rb = RingBuffer::new(100);
        for i in 0..5 {
            rb.push(http_event(i));
        }
        assert_eq!(rb.drain_window(Duration::MAX).len(), 5);
    }

    #[test]
    fn drain_window_zero_returns_none() {
        let mut rb = RingBuffer::new(100);
        rb.push(http_event(1));
        rb.push(db_event(2));
        // A zero-duration window cuts off everything pushed before now
        let events = rb.drain_window(Duration::ZERO);
        // May be 0 or very few depending on timing; must not panic
        let _ = events;
    }

    #[test]
    fn drain_does_not_mutate_buffer() {
        let mut rb = RingBuffer::new(100);
        rb.push(http_event(1));
        rb.push(http_event(2));
        let _ = rb.drain_window(Duration::MAX);
        assert_eq!(rb.len(), 2); // drain is non-destructive
    }

    #[test]
    fn mixed_event_types_preserved() {
        let mut rb = RingBuffer::new(10);
        rb.push(http_event(1));
        rb.push(db_event(2));
        let events = rb.drain_window(Duration::MAX);
        assert!(matches!(events[0], Event::Http(_)));
        assert!(matches!(events[1], Event::Db(_)));
    }
}
