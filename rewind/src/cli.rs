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

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rewind",
    about = "Deterministic replay of distributed system incidents"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Attach to a Docker Compose stack — auto-detects services from compose file
    Attach(AttachArgs),
    /// Record inter-service traffic and syscalls to a .rwd snapshot
    Record(RecordArgs),
    /// Flush the in-memory ring buffer to disk (triggered capture)
    Flush(FlushArgs),
    /// Replay a .rwd snapshot deterministically against a local Docker Compose setup
    Replay(ReplayArgs),
    /// Print the contents of a .rwd snapshot
    Inspect(InspectArgs),
    /// Export a .rwd snapshot to OTLP JSON (pipe to any OpenTelemetry collector)
    Export(ExportArgs),
    /// Upload a .rwd snapshot to cloud object storage (s3://, gs://, az://)
    Push(PushArgs),
    /// Run an HTTP webhook server that triggers flush when PagerDuty/Opsgenie fires
    Webhook(WebhookArgs),
    /// Run the central collection server — agents push snapshots here over HTTP
    Server(ServerArgs),
    /// Push a snapshot to a central rewind server (replaces kubectl cp)
    PushAgent(PushAgentArgs),
    /// Enforce max-age and max-size retention policies on a snapshot directory
    Retention(RetentionArgs),
}

#[derive(Args)]
pub struct AttachArgs {
    /// Docker Compose file to read services from
    #[arg(long, short = 'f', default_value = "docker-compose.yml")]
    pub compose: PathBuf,

    /// Output file path
    #[arg(long, short, default_value = "incident.rwd")]
    pub output: PathBuf,

    /// Capture request/response bodies (increases snapshot size significantly)
    #[arg(long)]
    pub capture_bodies: bool,

    /// Header names to redact (comma-separated). Empty = default safe list
    /// (authorization, cookie, set-cookie, x-api-key, x-auth-token, proxy-authorization)
    #[arg(long, value_delimiter = ',')]
    pub redact_headers: Vec<String>,

    /// Only capture traffic to these path prefixes (comma-separated; empty = all)
    #[arg(long, value_delimiter = ',')]
    pub allow_paths: Vec<String>,

    /// Encrypt the snapshot at rest with this passphrase (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct RecordArgs {
    /// Comma-separated list of service names to watch
    #[arg(long, value_delimiter = ',')]
    pub services: Vec<String>,

    /// Output file path
    #[arg(long, short, default_value = "incident.rwd")]
    pub output: PathBuf,

    /// Capture request/response bodies (increases snapshot size significantly)
    #[arg(long)]
    pub capture_bodies: bool,

    /// Header names to redact (comma-separated). Empty = default safe list
    /// (authorization, cookie, set-cookie, x-api-key, x-auth-token, proxy-authorization)
    #[arg(long, value_delimiter = ',')]
    pub redact_headers: Vec<String>,

    /// Only capture traffic to these path prefixes (comma-separated; empty = all)
    #[arg(long, value_delimiter = ',')]
    pub allow_paths: Vec<String>,

    /// Encrypt the snapshot at rest with this passphrase (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct FlushArgs {
    /// How far back to include (e.g. "5m", "30s")
    #[arg(long, default_value = "5m")]
    pub window: String,

    /// Output file path
    #[arg(long, short, default_value = "incident.rwd")]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReplayArgs {
    /// Path to the .rwd snapshot file
    pub snapshot: PathBuf,

    /// Docker Compose file to replay against
    #[arg(long, default_value = "docker-compose.yml")]
    pub compose: PathBuf,

    /// Decryption passphrase for encrypted snapshots (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Path to the .rwd snapshot file
    pub snapshot: PathBuf,

    /// Decryption passphrase for encrypted snapshots (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Path to the .rwd snapshot file
    pub snapshot: PathBuf,

    /// Output format: otlp (default) or jaeger
    #[arg(long, default_value = "otlp")]
    pub format: String,

    /// Write output to file instead of stdout
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Decryption passphrase for encrypted snapshots (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct PushArgs {
    /// Path to the .rwd snapshot file
    pub snapshot: PathBuf,

    /// Destination URL: s3://bucket/key, gs://bucket/key, or az://container/key.
    /// A trailing slash appends the snapshot filename automatically.
    pub destination: String,
}

#[derive(Args)]
pub struct WebhookArgs {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0:9091")]
    pub listen: String,

    /// Output directory for auto-triggered snapshots
    #[arg(long, default_value = ".")]
    pub output_dir: PathBuf,

    /// Flush window to capture on alert (e.g. "5m", "30s")
    #[arg(long, default_value = "5m")]
    pub window: String,

    /// Optional shared secret — webhook requests must include
    /// X-Rewind-Secret: <secret> header (or REWIND_WEBHOOK_SECRET env var)
    #[arg(long, env = "REWIND_WEBHOOK_SECRET")]
    pub secret: Option<String>,
}

#[derive(Args)]
pub struct ServerArgs {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0:9092")]
    pub listen: String,

    /// Directory to store received snapshots
    #[arg(long, default_value = "/var/rewind/snapshots")]
    pub storage: PathBuf,

    /// Bearer token for upload/download auth (or REWIND_SERVER_TOKEN env var)
    #[arg(long, env = "REWIND_SERVER_TOKEN")]
    pub token: Option<String>,
}

#[derive(Args)]
pub struct PushAgentArgs {
    /// Path to the .rwd snapshot file to push
    pub snapshot: PathBuf,

    /// URL of the rewind collection server (e.g. http://collector:9092)
    #[arg(long)]
    pub server: String,

    /// Bearer token (or REWIND_SERVER_TOKEN env var)
    #[arg(long, env = "REWIND_SERVER_TOKEN")]
    pub token: Option<String>,
}

#[derive(Args)]
pub struct RetentionArgs {
    /// Directory containing .rwd snapshot files
    #[arg(long, default_value = "/var/rewind/snapshots")]
    pub dir: PathBuf,

    /// Delete snapshots older than this duration (e.g. 7d, 24h, 30m)
    #[arg(long)]
    pub max_age: Option<String>,

    /// Delete oldest snapshots until total size is under this limit (e.g. 10GB, 500MB)
    #[arg(long)]
    pub max_size: Option<String>,

    /// Actually delete files (default: dry-run, only prints what would be deleted)
    #[arg(long)]
    pub delete: bool,

    /// Print result as JSON
    #[arg(long)]
    pub json: bool,
}
