# rewind VS Code Extension

Browse, inspect, and replay `.rwd` snapshot files produced by [rewind](https://github.com/anduaura/rewind) directly from VS Code.

## Features

- **Custom editor** — open any `.rwd` file to see a formatted event timeline (HTTP, gRPC, DB, syscall) with counts and timestamps.
- **One-click replay** — press **▶ Replay** in the editor or right-click a `.rwd` in the Explorer to run `rewind replay` in the integrated terminal.
- **Terminal inspect** — run `rewind inspect` with full CLI output.
- **Encrypted snapshots** — set `rewind.snapshotKey` in settings to decrypt age-encrypted snapshots.

## Requirements

The `rewind` CLI must be installed and on your `PATH`, or set `rewind.executablePath` to the full path.

## Extension Settings

| Setting | Default | Description |
|---|---|---|
| `rewind.executablePath` | `rewind` | Path to the rewind CLI |
| `rewind.composeFile` | `docker-compose.yml` | Default Compose file for replay |
| `rewind.snapshotKey` | `` | Decryption passphrase for encrypted snapshots |

## Usage

1. Open any `.rwd` file — the custom viewer opens automatically.
2. Right-click a `.rwd` in the Explorer → **Rewind: Open Snapshot** or **Rewind: Replay Snapshot**.
3. Use the Command Palette (`Ctrl+Shift+P`) → search "Rewind".
