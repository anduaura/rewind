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
    /// Log format: `text` (human-readable, default) or `json` (structured, for log aggregators)
    #[arg(long, global = true, env = "REWIND_LOG_FORMAT", default_value = "text")]
    pub log_format: String,

    /// Log level filter (e.g. `info`, `debug`, `warn`). Overridden by RUST_LOG env var.
    #[arg(long, global = true, env = "REWIND_LOG", default_value = "info")]
    pub log_level: String,

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
    /// Compare two .rwd snapshots and surface divergences
    Diff(DiffArgs),
    /// Scrub PII from a .rwd snapshot — redact headers, strip bodies, filter paths
    Scrub(ScrubArgs),
    /// Verify snapshot integrity against its SHA-256 manifest
    Verify(VerifyArgs),
    /// Generate a human-readable incident report (Markdown or HTML) from a snapshot
    Report(ReportArgs),
    /// Render a Mermaid or ASCII sequence diagram of the inter-service request flow
    Timeline(TimelineArgs),
    /// Send a Slack / webhook notification with a snapshot summary after a flush
    Notify(NotifyArgs),
    /// Search a directory of .rwd snapshots for events matching given criteria
    Search(SearchArgs),
    /// Generate a compliance evidence report (encryption, access control, audit log, retention)
    Compliance(ComplianceArgs),
    /// Redact or delete snapshots containing a specific user's data (GDPR Art. 17)
    GdprDelete(GdprDeleteArgs),
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

    /// Skip response comparison (just run the replay, do not diff)
    #[arg(long)]
    pub no_diff: bool,
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

    /// HMAC-SHA256 signing secret for verified webhook sources.
    /// When set, every request must include a valid X-Hub-Signature-256 or
    /// X-PagerDuty-Signature header.  Takes precedence over --secret.
    #[arg(long, env = "REWIND_WEBHOOK_HMAC_SECRET")]
    pub hmac_secret: Option<String>,
}

#[derive(Args)]
pub struct ServerArgs {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0:9092")]
    pub listen: String,

    /// Directory to store received snapshots (local filesystem)
    #[arg(long, default_value = "/var/rewind/snapshots")]
    pub storage: PathBuf,

    /// Shared-storage URL for HA / multi-replica deployments.
    /// Accepts s3://bucket/prefix, gs://bucket/prefix, az://container/prefix.
    /// When set, --storage is ignored and all snapshots are stored in object storage,
    /// making every replica stateless and safe to scale with an HPA.
    #[arg(long)]
    pub storage_url: Option<String>,

    /// Unique identifier for this server instance (used for leader election).
    /// Defaults to the hostname.  Set to the Pod name in Kubernetes.
    #[arg(long, env = "REWIND_INSTANCE_ID")]
    pub instance_id: Option<String>,

    /// Single Bearer token for upload/download auth (or REWIND_SERVER_TOKEN env var)
    #[arg(long, env = "REWIND_SERVER_TOKEN")]
    pub token: Option<String>,

    /// Path to JSON token registry for RBAC: {"<token>": "<team>", ...}
    /// When set, each token maps to a team namespace; takes precedence over --token
    #[arg(long)]
    pub tokens_file: Option<PathBuf>,

    /// Path to TLS certificate file (PEM). Enables HTTPS when provided with --tls-key.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Path to TLS private key file (PEM)
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Maximum snapshot upload size in megabytes (0 = unlimited)
    #[arg(long, default_value = "100")]
    pub max_snapshot_mb: u64,

    /// Max snapshot uploads per minute per source IP (0 = unlimited)
    #[arg(long, default_value = "10")]
    pub rate_limit: u32,

    /// OIDC issuer URL for JWT Bearer-token validation
    /// (e.g. https://dev-xyz.okta.com or https://accounts.google.com).
    /// When set, incoming Bearer tokens are validated as RS256 JWTs against
    /// the issuer's JWKS endpoint.  JWKS keys are cached for 5 minutes then
    /// refreshed on the next request.
    #[arg(long)]
    pub oidc_issuer: Option<String>,

    /// Expected `aud` claim in incoming JWTs (required when --oidc-issuer is set)
    #[arg(long)]
    pub oidc_audience: Option<String>,

    /// JWT claim name to use as the RBAC team (default: `team`).
    /// Falls back to the `sub` claim when the named claim is absent.
    #[arg(long, default_value = "team")]
    pub oidc_team_claim: String,
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

#[derive(Args)]
pub struct DiffArgs {
    /// Baseline .rwd snapshot (the reference recording)
    pub baseline: PathBuf,

    /// Candidate .rwd snapshot (the one being compared)
    pub candidate: PathBuf,

    /// Output result as JSON
    #[arg(long)]
    pub json: bool,

    /// Exit 0 even when divergences are found (useful in scripts)
    #[arg(long)]
    pub allow_divergence: bool,

    /// Decryption passphrase for encrypted snapshots (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct ScrubArgs {
    /// Source .rwd snapshot (read-only; original is never modified)
    pub snapshot: PathBuf,

    /// Destination for the scrubbed snapshot
    pub output: PathBuf,

    /// Header names to redact (comma-separated). Empty = default safe list
    /// (authorization, cookie, set-cookie, x-api-key, x-auth-token, proxy-authorization)
    #[arg(long, value_delimiter = ',')]
    pub redact_headers: Vec<String>,

    /// Only keep HTTP/gRPC events with these path prefixes (comma-separated; empty = keep all)
    #[arg(long, value_delimiter = ',')]
    pub allow_paths: Vec<String>,

    /// Strip all request/response bodies (sets to null)
    #[arg(long)]
    pub redact_body: bool,

    /// Print scrub summary as JSON
    #[arg(long)]
    pub json: bool,

    /// Decryption passphrase (also used to re-encrypt output; overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct ReportArgs {
    /// Path to the .rwd snapshot file
    pub snapshot: PathBuf,

    /// Output format: `md` (Markdown, default) or `html`
    #[arg(long, default_value = "md")]
    pub format: String,

    /// Write report to file instead of stdout
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Decryption passphrase for encrypted snapshots (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct TimelineArgs {
    /// Path to the .rwd snapshot file
    pub snapshot: PathBuf,

    /// Output format: `mermaid` (default, paste into any Markdown renderer) or `ascii`
    #[arg(long, default_value = "mermaid")]
    pub format: String,

    /// Write diagram to file instead of stdout
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Decryption passphrase for encrypted snapshots (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct NotifyArgs {
    /// Path to the .rwd snapshot file to summarise
    pub snapshot: PathBuf,

    /// Slack Incoming Webhook URL (or REWIND_SLACK_URL env var)
    #[arg(long, env = "REWIND_SLACK_URL")]
    pub slack_url: Option<String>,

    /// Generic HTTP webhook URL (JSON POST). Use --slack-url for Slack-formatted payloads.
    #[arg(long)]
    pub webhook_url: Option<String>,

    /// Extra message appended to the notification (e.g. runbook link)
    #[arg(long, short)]
    pub message: Option<String>,

    /// Maximum number of timeline steps to include in the notification (0 = all)
    #[arg(long, default_value = "5")]
    pub timeline_lines: usize,

    /// Print the JSON payload to stdout without sending it (useful for debugging)
    #[arg(long)]
    pub dry_run: bool,

    /// Decryption passphrase for encrypted snapshots (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct SearchArgs {
    /// Directory containing .rwd snapshot files to search
    pub dir: PathBuf,

    /// Filter: HTTP/gRPC path must contain this string (case-insensitive)
    #[arg(long)]
    pub path: Option<String>,

    /// Filter: HTTP status code must equal this value (e.g. 500)
    #[arg(long)]
    pub status: Option<u16>,

    /// Filter: HTTP method must match (case-insensitive, e.g. POST)
    #[arg(long)]
    pub method: Option<String>,

    /// Filter: DB query must contain this string (case-insensitive)
    #[arg(long)]
    pub query: Option<String>,

    /// Filter: snapshot must involve this service name (case-insensitive substring)
    #[arg(long)]
    pub service: Option<String>,

    /// Filter: DB protocol must match (e.g. postgres, redis, mysql)
    #[arg(long)]
    pub protocol: Option<String>,

    /// Output results as JSON
    #[arg(long)]
    pub json: bool,

    /// Decryption passphrase for encrypted snapshots (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to the .rwd snapshot file to verify
    pub snapshot: PathBuf,

    /// Write a new SHA-256 manifest (<snapshot>.sha256) instead of checking one
    #[arg(long)]
    pub write: bool,

    /// Exit 0 when no manifest file exists (instead of exit 2)
    #[arg(long)]
    pub allow_missing: bool,

    /// Print result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct ComplianceArgs {
    /// Directory containing .rwd snapshot files (or per-team subdirectories)
    #[arg(long, default_value = "/var/rewind/snapshots")]
    pub snapshot_dir: PathBuf,

    /// Path to the audit log file (default: /var/log/rewind/audit.log or REWIND_AUDIT_LOG)
    #[arg(long)]
    pub audit_log: Option<PathBuf>,

    /// Path to the RBAC token registry JSON file (for access-control assessment)
    #[arg(long)]
    pub tokens_file: Option<PathBuf>,

    /// OIDC issuer URL configured on the server (for access-control assessment)
    #[arg(long)]
    pub oidc_issuer: Option<String>,

    /// Single Bearer token configured on the server (for access-control assessment)
    #[arg(long)]
    pub token: Option<String>,

    /// TLS certificate path configured on the server (for transport-security assessment)
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Encryption key/URI (plain passphrase or vault://|aws://|azure:// URI)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,

    /// Retention max-age value configured on the server (e.g. 30d)
    #[arg(long)]
    pub max_age: Option<String>,

    /// Retention max-size value configured on the server (e.g. 10GB)
    #[arg(long)]
    pub max_size: Option<String>,

    /// Output format: `json` (default) or `markdown`
    #[arg(long)]
    pub format: Option<String>,

    /// Write report to this file instead of stdout
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct GdprDeleteArgs {
    /// Directory of .rwd snapshots to scan (supports flat and per-team layouts)
    #[arg(long, default_value = "/var/rewind/snapshots")]
    pub dir: PathBuf,

    /// User identifier to search for across all text fields in every event
    #[arg(long)]
    pub user_id: String,

    /// Decryption passphrase for encrypted snapshots (overrides REWIND_SNAPSHOT_KEY)
    #[arg(long, env = "REWIND_SNAPSHOT_KEY")]
    pub key: Option<String>,

    /// Actually perform the redaction/deletion (default: dry run, exits 1 if matches found)
    #[arg(long)]
    pub execute: bool,

    /// Delete entire snapshots that contain matches instead of redacting in place
    #[arg(long)]
    pub delete_snapshots: bool,

    /// Emit results as JSON
    #[arg(long)]
    pub json: bool,
}
