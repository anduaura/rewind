# Configuration reference

All configuration is via CLI flags and environment variables. Environment variables take precedence over defaults but are overridden by explicit flags.

## Global flags

Available on every subcommand.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--log-format` | `REWIND_LOG_FORMAT` | `text` | Log output format: `text` (human-readable) or `json` (for log aggregators) |
| `--log-level` | `REWIND_LOG` | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace`. Overridden by `RUST_LOG`. |

## `rewind attach`

Auto-detect services from a Docker Compose file and start capturing.

```bash
sudo rewind attach [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `-f`, `--compose` | `docker-compose.yml` | Docker Compose file to read service names from |
| `-o`, `--output` | `incident.rwd` | Output path for `rewind flush` |
| `--capture-bodies` | off | Capture HTTP request/response bodies (up to 512 bytes each) |
| `--redact-headers` | (safe list) | Comma-separated header names to redact. Default safe list: `authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `proxy-authorization` |
| `--allow-paths` | (all) | Only capture events for these path prefixes (comma-separated). Empty = capture all paths |
| `--key` | `$REWIND_SNAPSHOT_KEY` | Encryption passphrase for snapshots at rest (AES-256-GCM via age) |

## `rewind record`

Start capturing for a specific set of service names (without a compose file).

```bash
sudo rewind record --services api,worker [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--services` | (required) | Comma-separated service or container names to watch |
| `-o`, `--output` | `incident.rwd` | Output path for `rewind flush` |
| `--capture-bodies` | off | Capture HTTP request/response bodies |
| `--redact-headers` | (safe list) | Header names to redact |
| `--allow-paths` | (all) | Path prefix allow-list |
| `--key` | `$REWIND_SNAPSHOT_KEY` | Encryption passphrase |

## `rewind flush`

Dump the agent's in-memory ring buffer to a `.rwd` file. The agent must be running (`rewind record` or `rewind attach`).

```bash
rewind flush [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--window` | `5m` | How far back to include. Accepts `5m`, `30s`, `2h`, or bare seconds (`120`) |
| `-o`, `--output` | `incident.rwd` | Output file path |

## `rewind replay`

Replay a snapshot against a local Docker Compose stack.

```bash
rewind replay <SNAPSHOT> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `<SNAPSHOT>` | (required) | Path to the `.rwd` snapshot |
| `--compose` | `docker-compose.yml` | Docker Compose file to replay against |
| `--key` | `$REWIND_SNAPSHOT_KEY` | Decryption passphrase |
| `--no-diff` | off | Skip response comparison — just run the replay |
| `--no-faketime` | off | Skip clock override (replay with real wall clock). Use when libfaketime is unavailable or the incident is not time-sensitive |

### How replay works

1. Reads the snapshot and identifies the triggering inbound request.
2. Starts a mock HTTP server on a random port. All outbound calls from replayed services are intercepted and answered with recorded responses.
3. Writes a `docker-compose.rewind-replay.yml` override that:
   - Sets `FAKETIME` + `LD_PRELOAD` to override the wall clock (if libfaketime is found on the host)
   - Sets `HTTP_PROXY` / `HTTPS_PROXY` to route outbound calls through the mock server
4. Runs `docker compose up --force-recreate` with both the original compose file and the override.
5. Polls `GET /health` on the trigger service until it returns 2xx (up to 10 seconds).
6. Re-fires the triggering request.
7. Compares the actual response to the recorded response and prints a diff.
8. Exits 0 on match, 1 on divergence. Use `--no-diff` to always exit 0.

### Clock override

If `libfaketime` is available on the host, rewind volume-mounts it into each container at `/run/rewind/libfaketime.so.1` and sets `LD_PRELOAD` accordingly. No changes to container images are required.

Install libfaketime on the host:

```bash
# Ubuntu / Debian
sudo apt install faketime

# RHEL / Fedora
sudo dnf install libfaketime
```

## `rewind inspect`

Print the contents of a snapshot in human-readable form.

```bash
rewind inspect <SNAPSHOT> [--key PASSPHRASE]
```

## `rewind export`

Export a snapshot to OpenTelemetry traces.

```bash
rewind export <SNAPSHOT> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `otlp` | Output format: `otlp` (OTLP JSON) or `jaeger` (Jaeger JSON) |
| `-o`, `--output` | (stdout) | Write to file instead of stdout |
| `--key` | `$REWIND_SNAPSHOT_KEY` | Decryption passphrase |

## `rewind diff`

Compare two snapshots without running a replay.

```bash
rewind diff <BASELINE> <CANDIDATE> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--json` | off | Output divergences as JSON |
| `--allow-divergence` | off | Exit 0 even when divergences are found |
| `--key` | `$REWIND_SNAPSHOT_KEY` | Decryption passphrase |

## `rewind scrub`

Redact PII from a snapshot without decrypting/re-encrypting the original.

```bash
rewind scrub <SNAPSHOT> <OUTPUT> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--redact-headers` | (safe list) | Header names to redact |
| `--allow-paths` | (all) | Only keep events matching these path prefixes |
| `--redact-body` | off | Strip all request/response bodies |
| `--json` | off | Print scrub summary as JSON |
| `--key` | `$REWIND_SNAPSHOT_KEY` | Decryption passphrase (also used to re-encrypt output) |

## `rewind report`

Generate a Markdown or HTML incident report.

```bash
rewind report <SNAPSHOT> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `md` | Output format: `md` or `html` |
| `-o`, `--output` | (stdout) | Write to file |
| `--key` | `$REWIND_SNAPSHOT_KEY` | Decryption passphrase |

## `rewind timeline`

Render a sequence diagram of the inter-service request flow.

```bash
rewind timeline <SNAPSHOT> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `mermaid` | Output format: `mermaid` (paste into GitHub / Notion) or `ascii` |
| `-o`, `--output` | (stdout) | Write to file |
| `--key` | `$REWIND_SNAPSHOT_KEY` | Decryption passphrase |

## `rewind notify`

Send a Slack or webhook notification with a snapshot summary.

```bash
rewind notify <SNAPSHOT> [OPTIONS]
```

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--slack-url` | `REWIND_SLACK_URL` | — | Slack Incoming Webhook URL |
| `--webhook-url` | — | — | Generic HTTP webhook (JSON POST) |
| `--message` | — | — | Extra text appended to the notification |
| `--timeline-lines` | — | `5` | Max timeline entries in the notification |
| `--dry-run` | — | off | Print the JSON payload without sending |
| `--key` | `$REWIND_SNAPSHOT_KEY` | — | Decryption passphrase |

## `rewind search`

Search a directory of snapshots for events matching given criteria.

```bash
rewind search <DIR> [OPTIONS]
```

| Flag | Description |
|---|---|
| `--path SUBSTR` | HTTP/gRPC path must contain this string (case-insensitive) |
| `--status CODE` | HTTP status code must equal this value |
| `--method METHOD` | HTTP method must match (case-insensitive) |
| `--query SUBSTR` | DB query must contain this string (case-insensitive) |
| `--service NAME` | Event must involve this service name (case-insensitive substring) |
| `--protocol PROTO` | DB protocol: `postgres`, `redis`, `mysql`, `mongodb`, `kafka` |
| `--json` | Output results as JSON |
| `--key` | Decryption passphrase |

Filters are ANDed: a snapshot must match all specified filters to appear in results.

## `rewind server`

Run the central collection server. Agents push snapshots here over HTTP.

```bash
rewind server [OPTIONS]
```

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--listen` | — | `0.0.0.0:9092` | Address to listen on |
| `--storage` | — | `/var/rewind/snapshots` | Local snapshot directory |
| `--storage-url` | — | — | Object storage URL for HA: `s3://bucket/prefix`, `gs://bucket/prefix`, `az://container/prefix` |
| `--token` | `REWIND_SERVER_TOKEN` | — | Single Bearer token for auth |
| `--tokens-file` | — | — | JSON file mapping tokens to team names for RBAC: `{"<token>": "<team>"}` |
| `--tls-cert` | — | — | TLS certificate path (PEM). Enables HTTPS when paired with `--tls-key` |
| `--tls-key` | — | — | TLS private key path (PEM) |
| `--max-snapshot-mb` | — | `100` | Max upload size in MB (0 = unlimited) |
| `--rate-limit` | — | `10` | Max uploads per minute per source IP (0 = unlimited) |
| `--oidc-issuer` | — | — | OIDC issuer URL for JWT validation (e.g. `https://dev-xyz.okta.com`) |
| `--oidc-audience` | — | — | Expected `aud` claim in incoming JWTs |
| `--oidc-team-claim` | — | `team` | JWT claim to use as the RBAC team |

### Server API endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/snapshots` | write token | Upload a `.rwd` snapshot (multipart/form-data `file` field) |
| `GET` | `/snapshots` | read token | List all snapshots (JSON array) |
| `GET` | `/snapshots/{name}` | read token | Download a specific snapshot |
| `DELETE` | `/snapshots/{name}` | admin token | Delete a snapshot |
| `GET` | `/healthz` | none | Health probe (returns `{"status":"ok"}`) |
| `GET` | `/metrics` | none | Prometheus metrics |

### RBAC

When `--tokens-file` is set, each token is scoped to a team. Agents can only upload snapshots for their own services; read tokens can only list and download. Three permission levels:

| Level | Allowed operations |
|---|---|
| `write` | Upload snapshots |
| `read` | List and download snapshots |
| `admin` | All operations including delete |

```json
{
  "agent-token-abc": {"team": "payments", "level": "write"},
  "dev-token-xyz":   {"team": "payments", "level": "read"},
  "ops-token-123":   {"team": "*",        "level": "admin"}
}
```

## `rewind webhook`

HTTP server that triggers a flush when PagerDuty or Opsgenie fires an alert.

```bash
rewind webhook [OPTIONS]
```

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--listen` | — | `0.0.0.0:9091` | Address to listen on |
| `--output-dir` | — | `.` | Directory for auto-triggered snapshots |
| `--window` | — | `5m` | Flush window to capture on alert |
| `--secret` | `REWIND_WEBHOOK_SECRET` | — | Simple shared-secret check (`X-Rewind-Secret` header) |
| `--hmac-secret` | `REWIND_WEBHOOK_HMAC_SECRET` | — | HMAC-SHA256 secret for PagerDuty/Opsgenie signature verification. Takes precedence over `--secret`. |

## `rewind push`

Upload a snapshot to cloud object storage.

```bash
rewind push <SNAPSHOT> <DESTINATION>
```

Destination formats:
- `s3://my-bucket/snapshots/` — AWS S3 (uses `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`)
- `gs://my-bucket/snapshots/` — Google Cloud Storage (uses `GOOGLE_APPLICATION_CREDENTIALS`)
- `az://my-container/snapshots/` — Azure Blob Storage (uses `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_KEY`)

A trailing `/` appends the snapshot filename automatically.

## `rewind verify`

Verify snapshot integrity against its SHA-256 manifest.

```bash
rewind verify <SNAPSHOT> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--write` | off | Write a new manifest (`<snapshot>.sha256`) instead of checking |
| `--allow-missing` | off | Exit 0 when no manifest file exists |
| `--json` | off | Print result as JSON |

## `rewind retention`

Enforce max-age and max-size policies on a snapshot directory.

```bash
rewind retention [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--dir` | `/var/rewind/snapshots` | Directory containing `.rwd` files |
| `--max-age DURATION` | — | Delete snapshots older than this (e.g. `7d`, `24h`, `30m`) |
| `--max-size SIZE` | — | Delete oldest until under this total size (e.g. `10GB`, `500MB`) |
| `--delete` | off | Actually delete files. Without this flag, runs as a dry-run |
| `--json` | off | Print result as JSON |

## `rewind compliance`

Generate a compliance evidence report (encryption, RBAC, audit log, retention).

```bash
rewind compliance [OPTIONS]
```

| Flag | Description |
|---|---|
| `--snapshot-dir DIR` | Directory of snapshots to assess |
| `--audit-log PATH` | Path to the audit log file |
| `--tokens-file PATH` | RBAC token registry for access-control assessment |
| `--oidc-issuer URL` | OIDC issuer configured on the server |
| `--tls-cert PATH` | TLS certificate path for transport-security assessment |
| `--key VALUE` | Encryption key or URI for encryption assessment |
| `--max-age DURATION` | Retention max-age configured on the server |
| `--max-size SIZE` | Retention max-size configured on the server |
| `--format FORMAT` | `json` (default) or `markdown` |
| `--output PATH` | Write report to file instead of stdout |

## `rewind gdpr-delete`

Scan snapshots for a specific user ID and redact or delete matching events.

```bash
rewind gdpr-delete --user-id <ID> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--dir` | `/var/rewind/snapshots` | Directory to scan |
| `--user-id` | (required) | User identifier to search for (matched against all text fields) |
| `--execute` | off | Actually perform redaction. Without this, runs as a dry-run |
| `--delete-snapshots` | off | Delete entire snapshots containing matches instead of redacting in-place |
| `--json` | off | Emit results as JSON |
| `--key` | `$REWIND_SNAPSHOT_KEY` | Decryption passphrase |

## Environment variables summary

| Variable | Used by | Description |
|---|---|---|
| `REWIND_SNAPSHOT_KEY` | record, flush, replay, inspect, export, diff, scrub, server | Encryption/decryption passphrase |
| `REWIND_LOG_FORMAT` | all | Log format: `text` or `json` |
| `REWIND_LOG` | all | Log level (also controlled by `RUST_LOG`) |
| `REWIND_SERVER_TOKEN` | server, push-agent | Bearer token for the collection server |
| `REWIND_SLACK_URL` | notify | Slack Incoming Webhook URL |
| `REWIND_WEBHOOK_SECRET` | webhook | Simple shared-secret for webhook auth |
| `REWIND_WEBHOOK_HMAC_SECRET` | webhook | HMAC-SHA256 secret for PagerDuty/Opsgenie |
| `RUST_LOG` | all | Overrides `--log-level` if set (standard `tracing` env filter) |
