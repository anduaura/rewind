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
}
