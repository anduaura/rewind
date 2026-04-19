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

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};

use crate::cli::ReplayArgs;
use crate::replay::network::MockServer;
use crate::store::snapshot::{Event, HttpRecord, Snapshot};

pub async fn run(args: ReplayArgs) -> Result<()> {
    let snapshot = Snapshot::read(&args.snapshot)?;

    println!("rewind replay");
    println!("  snapshot: {}", args.snapshot.display());
    println!("  compose:  {}", args.compose.display());
    println!("  events:   {}", snapshot.events.len());

    // Outbound responses are what the services called out to during the incident.
    // MockServer will serve these back during replay so real network is never hit.
    let outbound_responses: Vec<HttpRecord> = snapshot
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Http(h) if h.status_code.is_some() => Some(h.clone()),
            _ => None,
        })
        .collect();

    // The trigger is the first inbound request — the call that kicked off the
    // incident. We re-execute exactly this at the end of replay.
    let trigger = snapshot
        .events
        .iter()
        .find_map(|e| match e {
            Event::Http(h) if h.direction == "inbound" && h.status_code.is_none() => {
                Some(h.clone())
            }
            _ => None,
        })
        .context("snapshot contains no inbound trigger request")?;

    println!("  trigger:  {} {}", trigger.method, trigger.path);
    println!(
        "  mocking:  {} outbound responses",
        outbound_responses.len()
    );
    println!();

    // ── 1. Start MockServer ──────────────────────────────────────────────────
    //
    // Bind to port 0 first so the OS picks a free port; pass the listener to
    // MockServer so we know the port before starting compose.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mock_port = listener.local_addr()?.port();
    let mock_proxy = format!("http://127.0.0.1:{mock_port}");

    let mock_server = MockServer::new(outbound_responses);
    tokio::spawn(async move {
        if let Err(e) = mock_server.serve(listener).await {
            eprintln!("MockServer error: {e}");
        }
    });

    // ── 2. Clock override ────────────────────────────────────────────────────
    //
    // libfaketime reads FAKETIME from the environment. We inject it into every
    // container via a docker-compose override file so the replay services see
    // the same wall clock as during recording.
    let faketime = ns_to_faketime(snapshot.recorded_at_ns);
    println!("  clock:    {faketime}");

    // ── 3. Write compose override ────────────────────────────────────────────
    let override_path = write_compose_override(&args.compose, &faketime, &mock_proxy)
        .context("failed to write docker-compose override")?;

    // ── 4. Bring up services ─────────────────────────────────────────────────
    println!("Starting services…");
    docker_compose_up(&args.compose, &override_path).context("docker compose up failed")?;

    // ── 5. Wait for the trigger service to be healthy ────────────────────────
    let service = if trigger.service.is_empty() {
        snapshot
            .services
            .first()
            .map(|s| s.as_str())
            .unwrap_or("api")
            .to_string()
    } else {
        trigger.service.clone()
    };

    let port = read_service_port(&args.compose, &service)
        .with_context(|| format!("could not find port for service '{service}'"))?;

    wait_healthy(port)
        .await
        .with_context(|| format!("service '{service}' did not become healthy"))?;

    // ── 6. Re-execute the triggering request ─────────────────────────────────
    println!(
        "Re-executing: {} http://127.0.0.1:{}{}",
        trigger.method, port, trigger.path
    );

    let url = format!("http://127.0.0.1:{}{}", port, trigger.path);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let builder = match trigger.method.as_str() {
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        _ => client.get(&url),
    };
    let builder = match &trigger.body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(body.clone()),
        None => builder,
    };

    let resp = builder.send().await.context("trigger request failed")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    println!();
    println!("── Replay result ──────────────────────────────────────────");
    println!("  status: {status}");
    println!("  body:   {}", truncate(&body, 300));
    println!("───────────────────────────────────────────────────────────");

    // Clean up temporary override file.
    let _ = std::fs::remove_file(&override_path);

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Convert a nanosecond Unix timestamp to libfaketime's `@YYYY-MM-DD HH:MM:SS` format.
fn ns_to_faketime(ns: u64) -> String {
    let secs = (ns / 1_000_000_000) as i64;
    let dt = Utc.timestamp_opt(secs, 0).single().unwrap_or_else(Utc::now);
    format!("@{}", dt.format("%Y-%m-%d %H:%M:%S"))
}

/// Write a docker-compose override that injects FAKETIME + HTTP_PROXY into
/// every service so they use the recorded clock and route outbound HTTP through
/// MockServer. libfaketime must be installed in the container images.
fn write_compose_override(compose: &Path, faketime: &str, mock_proxy: &str) -> Result<PathBuf> {
    let compose_str = std::fs::read_to_string(compose)
        .with_context(|| format!("cannot read {}", compose.display()))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&compose_str)?;

    let service_names: Vec<String> = doc["services"]
        .as_mapping()
        .map(|m| {
            m.keys()
                .filter_map(|k| k.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut services_map = serde_yaml::Mapping::new();
    for name in &service_names {
        let env = serde_yaml::Value::Mapping({
            let mut m = serde_yaml::Mapping::new();
            let kv = [
                ("FAKETIME", faketime),
                // libfaketime intercepts clock calls via LD_PRELOAD.
                // The path is the standard Debian/Ubuntu location.
                (
                    "LD_PRELOAD",
                    "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
                ),
                ("HTTP_PROXY", mock_proxy),
                ("HTTPS_PROXY", mock_proxy),
                // Exclude localhost from the proxy so intra-host calls still work.
                ("NO_PROXY", "127.0.0.1,localhost"),
            ];
            for (k, v) in kv {
                m.insert(sv(k), sv(v));
            }
            m
        });

        services_map.insert(
            sv(name),
            serde_yaml::Value::Mapping({
                let mut m = serde_yaml::Mapping::new();
                m.insert(sv("environment"), env);
                m
            }),
        );
    }

    let override_doc = serde_yaml::Value::Mapping({
        let mut m = serde_yaml::Mapping::new();
        m.insert(sv("services"), serde_yaml::Value::Mapping(services_map));
        m
    });

    let override_path = compose
        .parent()
        .unwrap_or(Path::new("."))
        .join("docker-compose.rewind-replay.yml");

    std::fs::write(&override_path, serde_yaml::to_string(&override_doc)?)?;
    Ok(override_path)
}

fn sv(s: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(s.to_string())
}

fn docker_compose_up(compose: &Path, override_file: &Path) -> Result<()> {
    let status = Command::new("docker")
        .args([
            "compose",
            "-f",
            compose.to_str().unwrap(),
            "-f",
            override_file.to_str().unwrap(),
            "up",
            "-d",
            "--force-recreate",
        ])
        .status()
        .context("docker compose not found — is Docker installed?")?;

    if !status.success() {
        anyhow::bail!("docker compose up exited with {status}");
    }
    Ok(())
}

/// Read the host-side port for a service from the compose file.
/// Expects port entries in "HOST:CONTAINER" or plain "PORT" format.
fn read_service_port(compose: &Path, service: &str) -> Result<u16> {
    let doc: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(compose)?)?;

    let ports = doc["services"][service]["ports"]
        .as_sequence()
        .with_context(|| format!("no ports defined for service '{service}'"))?;

    let entry = ports
        .first()
        .and_then(|v| v.as_str())
        .with_context(|| format!("port entry for '{service}' is not a string"))?;

    // "8080:8080" → take the host side (before ':')
    entry
        .split(':')
        .next()
        .unwrap()
        .parse::<u16>()
        .context("invalid port number")
}

async fn wait_healthy(port: u16) -> Result<()> {
    let url = format!("http://127.0.0.1:{port}/health");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;

    print!("  Waiting for :{port}");
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            println!(" ready");
            return Ok(());
        }
        print!(".");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    anyhow::bail!("timed out waiting for :{port} to become healthy")
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
