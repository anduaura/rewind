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

//! Replay result comparison — compares the recorded response from a snapshot
//! against the actual response produced during replay.
//!
//! JSON bodies are compared field-by-field (recursive); non-JSON bodies are
//! compared as trimmed strings.  The outcome is printed to stdout and the
//! engine exits with code 1 when any divergence is found.

use serde_json::Value;

// ── Public types ──────────────────────────────────────────────────────────────

/// The complete outcome of a replay comparison.
#[derive(Debug)]
pub struct ReplayOutcome {
    pub recorded_status: Option<u16>,
    pub actual_status:   u16,
    pub status_ok:       bool,
    pub body:            BodyComparison,
}

#[derive(Debug)]
pub enum BodyComparison {
    /// Both bodies identical JSON.
    JsonMatch,
    /// Both parsed as JSON; specific fields differ.
    JsonDivergence(Vec<FieldDiff>),
    /// Neither body is JSON; strings are identical.
    TextMatch,
    /// Neither body is JSON; strings differ.
    TextDivergence { recorded: String, actual: String },
    /// No recorded response in snapshot to compare against.
    NoBaseline,
}

/// A single field that differed between the recorded and actual JSON.
#[derive(Debug, PartialEq)]
pub struct FieldDiff {
    /// Dot-separated JSON path, e.g. `data.user.id` or `errors[0].message`.
    pub path:     String,
    pub recorded: String,
    pub actual:   String,
}

impl ReplayOutcome {
    /// Returns `true` if status and body both match (no divergences).
    pub fn is_match(&self) -> bool {
        self.status_ok
            && matches!(
                self.body,
                BodyComparison::JsonMatch | BodyComparison::TextMatch | BodyComparison::NoBaseline
            )
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Compare the recorded response (may be absent) against the actual replay
/// response.  `recorded_body` is `None` when the snapshot didn't capture a
/// response body (headers-only capture).
pub fn compare(
    recorded_status: Option<u16>,
    recorded_body:   Option<&str>,
    actual_status:   u16,
    actual_body:     &str,
) -> ReplayOutcome {
    let status_ok = recorded_status.map(|s| s == actual_status).unwrap_or(true);

    let body = match recorded_body {
        None => BodyComparison::NoBaseline,
        Some(rec) => compare_bodies(rec, actual_body),
    };

    ReplayOutcome { recorded_status, actual_status, status_ok, body }
}

fn compare_bodies(recorded: &str, actual: &str) -> BodyComparison {
    let rec_trimmed = recorded.trim();
    let act_trimmed = actual.trim();

    match (
        serde_json::from_str::<Value>(rec_trimmed),
        serde_json::from_str::<Value>(act_trimmed),
    ) {
        (Ok(rec_val), Ok(act_val)) => {
            let mut diffs = Vec::new();
            json_diff(&rec_val, &act_val, "", &mut diffs);
            if diffs.is_empty() {
                BodyComparison::JsonMatch
            } else {
                BodyComparison::JsonDivergence(diffs)
            }
        }
        _ => {
            if rec_trimmed == act_trimmed {
                BodyComparison::TextMatch
            } else {
                BodyComparison::TextDivergence {
                    recorded: rec_trimmed.to_string(),
                    actual:   act_trimmed.to_string(),
                }
            }
        }
    }
}

// ── JSON recursive diff ───────────────────────────────────────────────────────

fn json_diff(rec: &Value, act: &Value, path: &str, out: &mut Vec<FieldDiff>) {
    match (rec, act) {
        (Value::Object(r_map), Value::Object(a_map)) => {
            // Keys present in recorded but missing or changed in actual.
            for (key, r_val) in r_map {
                let child_path = child_path(path, key);
                match a_map.get(key) {
                    Some(a_val) => json_diff(r_val, a_val, &child_path, out),
                    None => out.push(FieldDiff {
                        path:     child_path,
                        recorded: json_display(r_val),
                        actual:   "(missing)".to_string(),
                    }),
                }
            }
            // Keys present in actual but absent from recorded.
            for key in a_map.keys() {
                if !r_map.contains_key(key) {
                    out.push(FieldDiff {
                        path:     child_path(path, key),
                        recorded: "(missing)".to_string(),
                        actual:   json_display(&a_map[key]),
                    });
                }
            }
        }
        (Value::Array(r_arr), Value::Array(a_arr)) => {
            let len = r_arr.len().max(a_arr.len());
            for i in 0..len {
                let idx_path = format!("{path}[{i}]");
                match (r_arr.get(i), a_arr.get(i)) {
                    (Some(rv), Some(av)) => json_diff(rv, av, &idx_path, out),
                    (Some(rv), None) => out.push(FieldDiff {
                        path:     idx_path,
                        recorded: json_display(rv),
                        actual:   "(missing)".to_string(),
                    }),
                    (None, Some(av)) => out.push(FieldDiff {
                        path:     idx_path,
                        recorded: "(missing)".to_string(),
                        actual:   json_display(av),
                    }),
                    (None, None) => {}
                }
            }
        }
        _ => {
            if rec != act {
                out.push(FieldDiff {
                    path:     if path.is_empty() { "(root)".to_string() } else { path.to_string() },
                    recorded: json_display(rec),
                    actual:   json_display(act),
                });
            }
        }
    }
}

fn child_path(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_string()
    } else {
        format!("{parent}.{key}")
    }
}

fn json_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null      => "null".to_string(),
        other            => other.to_string(),
    }
}

// ── Console output ────────────────────────────────────────────────────────────

const RULE: &str = "───────────────────────────────────────────────────────────";

pub fn print_outcome(outcome: &ReplayOutcome) {
    println!();
    println!("── Replay result {RULE}");

    // Status line
    match outcome.recorded_status {
        Some(rs) if rs == outcome.actual_status => {
            println!("  status:   {} ✓", outcome.actual_status);
        }
        Some(rs) => {
            println!(
                "  status:   {} (recorded: {rs})  ✗ MISMATCH",
                outcome.actual_status
            );
        }
        None => {
            println!("  status:   {} (no baseline)", outcome.actual_status);
        }
    }

    // Body section
    match &outcome.body {
        BodyComparison::JsonMatch => {
            println!("  body:     ✓ JSON identical");
        }
        BodyComparison::TextMatch => {
            println!("  body:     ✓ identical");
        }
        BodyComparison::NoBaseline => {
            println!("  body:     (no baseline — run with --capture-bodies to enable)");
        }
        BodyComparison::JsonDivergence(diffs) => {
            println!("  body:     ✗ JSON divergence ({} field(s))", diffs.len());
            println!();
            println!("  {:<40} {:<30} actual", "path", "recorded");
            println!("  {}", "-".repeat(85));
            for d in diffs {
                println!(
                    "  {:<40} {:<30} {}",
                    truncate_display(&d.path, 40),
                    truncate_display(&d.recorded, 30),
                    truncate_display(&d.actual, 40),
                );
            }
        }
        BodyComparison::TextDivergence { recorded, actual } => {
            println!("  body:     ✗ text divergence");
            println!("  recorded: {}", truncate_display(recorded, 200));
            println!("  actual:   {}", truncate_display(actual, 200));
        }
    }

    println!("{RULE}");

    if !outcome.is_match() {
        println!("DIVERGED — replay did not reproduce the recorded response");
    } else {
        println!("MATCH — replay reproduced the recorded response");
    }
}

fn truncate_display(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_match_no_body() {
        let out = compare(Some(200), None, 200, "");
        assert!(out.is_match());
        assert!(out.status_ok);
        assert!(matches!(out.body, BodyComparison::NoBaseline));
    }

    #[test]
    fn status_mismatch() {
        let out = compare(Some(200), None, 500, "");
        assert!(!out.is_match());
        assert!(!out.status_ok);
    }

    #[test]
    fn no_recorded_status_always_ok() {
        let out = compare(None, None, 404, "");
        assert!(out.status_ok);
    }

    #[test]
    fn json_bodies_identical() {
        let body = r#"{"status":"ok","id":42}"#;
        let out = compare(Some(200), Some(body), 200, body);
        assert!(matches!(out.body, BodyComparison::JsonMatch));
        assert!(out.is_match());
    }

    #[test]
    fn json_bodies_key_differs() {
        let rec = r#"{"status":"ok","id":42}"#;
        let act = r#"{"status":"error","id":42}"#;
        let out = compare(Some(200), Some(rec), 200, act);
        let BodyComparison::JsonDivergence(diffs) = &out.body else {
            panic!("expected JsonDivergence");
        };
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "status");
        assert_eq!(diffs[0].recorded, "ok");
        assert_eq!(diffs[0].actual, "error");
    }

    #[test]
    fn json_bodies_missing_key_in_actual() {
        let rec = r#"{"a":1,"b":2}"#;
        let act = r#"{"a":1}"#;
        let out = compare(Some(200), Some(rec), 200, act);
        let BodyComparison::JsonDivergence(diffs) = &out.body else {
            panic!("expected JsonDivergence");
        };
        assert!(diffs.iter().any(|d| d.path == "b" && d.actual == "(missing)"));
    }

    #[test]
    fn json_bodies_extra_key_in_actual() {
        let rec = r#"{"a":1}"#;
        let act = r#"{"a":1,"b":2}"#;
        let out = compare(Some(200), Some(rec), 200, act);
        let BodyComparison::JsonDivergence(diffs) = &out.body else {
            panic!("expected JsonDivergence");
        };
        assert!(diffs.iter().any(|d| d.path == "b" && d.recorded == "(missing)"));
    }

    #[test]
    fn json_nested_diff() {
        let rec = r#"{"data":{"user":{"id":"abc"}}}"#;
        let act = r#"{"data":{"user":{"id":"xyz"}}}"#;
        let out = compare(Some(200), Some(rec), 200, act);
        let BodyComparison::JsonDivergence(diffs) = &out.body else {
            panic!("expected JsonDivergence");
        };
        assert_eq!(diffs[0].path, "data.user.id");
    }

    #[test]
    fn json_array_element_differs() {
        let rec = r#"{"items":[1,2,3]}"#;
        let act = r#"{"items":[1,9,3]}"#;
        let out = compare(Some(200), Some(rec), 200, act);
        let BodyComparison::JsonDivergence(diffs) = &out.body else {
            panic!("expected JsonDivergence");
        };
        assert_eq!(diffs[0].path, "items[1]");
        assert_eq!(diffs[0].recorded, "2");
        assert_eq!(diffs[0].actual, "9");
    }

    #[test]
    fn text_bodies_identical() {
        let out = compare(Some(200), Some("pong"), 200, "pong");
        assert!(matches!(out.body, BodyComparison::TextMatch));
    }

    #[test]
    fn text_bodies_differ() {
        let out = compare(Some(200), Some("pong"), 200, "error");
        assert!(matches!(out.body, BodyComparison::TextDivergence { .. }));
        assert!(!out.is_match());
    }

    #[test]
    fn text_bodies_trimmed_before_compare() {
        let out = compare(Some(200), Some("pong\n"), 200, "pong");
        assert!(matches!(out.body, BodyComparison::TextMatch));
    }

    #[test]
    fn child_path_empty_parent() {
        assert_eq!(child_path("", "key"), "key");
    }

    #[test]
    fn child_path_nested() {
        assert_eq!(child_path("data.user", "id"), "data.user.id");
    }
}
