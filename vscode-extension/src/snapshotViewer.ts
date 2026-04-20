// Copyright 2026 The rewind Authors. Apache-2.0.

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as cp from 'child_process';

// ── Types matching the .rwd JSON schema ──────────────────────────────────────

interface Snapshot {
    version: number;
    recorded_at_ns: number;
    services: string[];
    events: Event[];
}

type Event =
    | { type: 'http'; timestamp_ns: number; direction: string; method: string; path: string; status_code?: number; service: string; trace_id?: string }
    | { type: 'db'; timestamp_ns: number; protocol: string; query: string; response?: string; service: string; pid: number }
    | { type: 'syscall'; timestamp_ns: number; kind: string; return_value: number; pid: number }
    | { type: 'grpc'; timestamp_ns: number; path: string; service: string; pid: number };

// ── Custom editor provider ────────────────────────────────────────────────────

export class SnapshotViewerProvider
    implements vscode.CustomReadonlyEditorProvider<SnapshotDocument> {

    constructor(private readonly context: vscode.ExtensionContext) {}

    async openCustomDocument(
        uri: vscode.Uri,
        _openContext: vscode.CustomDocumentOpenContext,
        _token: vscode.CancellationToken
    ): Promise<SnapshotDocument> {
        return new SnapshotDocument(uri);
    }

    async resolveCustomEditor(
        document: SnapshotDocument,
        webviewPanel: vscode.WebviewPanel,
        _token: vscode.CancellationToken
    ): Promise<void> {
        webviewPanel.webview.options = { enableScripts: true };

        const snapshot = await document.load();
        webviewPanel.webview.html = renderHtml(snapshot, document.uri);

        webviewPanel.webview.onDidReceiveMessage(async (msg) => {
            if (msg.command === 'replay') {
                await vscode.commands.executeCommand(
                    'rewind.replaySnapshot',
                    document.uri
                );
            } else if (msg.command === 'inspect') {
                await vscode.commands.executeCommand(
                    'rewind.inspectSnapshot',
                    document.uri
                );
            }
        });
    }
}

// ── Document ─────────────────────────────────────────────────────────────────

class SnapshotDocument implements vscode.CustomDocument {
    constructor(public readonly uri: vscode.Uri) {}

    async load(): Promise<Snapshot | null> {
        try {
            const raw = fs.readFileSync(this.uri.fsPath);
            // Try to decrypt if REWIND_SNAPSHOT_KEY is set (best-effort).
            const key = vscode.workspace.getConfiguration('rewind').get<string>('snapshotKey', '');
            if (key && isEncrypted(raw)) {
                return await decryptAndParse(this.uri.fsPath, key);
            }
            return JSON.parse(raw.toString('utf8')) as Snapshot;
        } catch {
            return null;
        }
    }

    dispose(): void {}
}

function isEncrypted(data: Buffer): boolean {
    return data.slice(0, 18).toString('ascii') === 'age-encryption.org';
}

async function decryptAndParse(filePath: string, key: string): Promise<Snapshot | null> {
    return new Promise((resolve) => {
        const config = vscode.workspace.getConfiguration('rewind');
        const exe = config.get<string>('executablePath', 'rewind');
        // Use `rewind inspect` JSON output (future: add --json flag).
        // For now, fall back to returning null — the webview shows a decrypt message.
        resolve(null);
    });
}

// ── HTML renderer ─────────────────────────────────────────────────────────────

function renderHtml(snapshot: Snapshot | null, uri: vscode.Uri): string {
    const filename = path.basename(uri.fsPath);

    if (!snapshot) {
        return `<!DOCTYPE html><html><body style="font-family:monospace;padding:20px">
<h2>⚠ Could not parse ${escHtml(filename)}</h2>
<p>The file may be encrypted. Set <code>rewind.snapshotKey</code> in VS Code settings
or run <b>Rewind: Inspect Snapshot (CLI)</b> from the command palette.</p>
<button onclick="postMessage({command:'inspect'})">Open in Terminal</button>
<script>const vscode = acquireVsCodeApi();
function postMessage(m){vscode.postMessage(m)}</script>
</body></html>`;
    }

    const ts = nsToDate(snapshot.recorded_at_ns);
    const counts = countEvents(snapshot.events);
    const rows = snapshot.events.map(renderEventRow).join('\n');

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body { font-family: monospace; font-size: 13px; padding: 16px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
  h2 { color: var(--vscode-textLink-foreground); margin-bottom: 4px; }
  .meta { color: var(--vscode-descriptionForeground); margin-bottom: 16px; }
  .badge { display:inline-block; padding:2px 6px; border-radius:4px; margin-right:4px; font-size:11px; }
  .http   { background:#1e4d78; color:#7ec8f7; }
  .db     { background:#4d2e1a; color:#f0a060; }
  .grpc   { background:#2d3a1a; color:#a0d060; }
  .syscall{ background:#3a1a3a; color:#d0a0f0; }
  table { width:100%; border-collapse:collapse; margin-top:12px; }
  th { text-align:left; padding:4px 8px; border-bottom:1px solid var(--vscode-panel-border); color:var(--vscode-descriptionForeground); font-weight:normal; }
  td { padding:3px 8px; border-bottom:1px solid var(--vscode-widget-shadow); vertical-align:top; }
  tr:hover td { background: var(--vscode-list-hoverBackground); }
  .ts { color: var(--vscode-descriptionForeground); width:130px; }
  .actions { margin-bottom:16px; }
  button { padding:6px 14px; margin-right:8px; cursor:pointer; background:var(--vscode-button-background); color:var(--vscode-button-foreground); border:none; border-radius:3px; }
  button:hover { background:var(--vscode-button-hoverBackground); }
</style>
</head>
<body>
<h2>📦 ${escHtml(filename)}</h2>
<div class="meta">
  v${snapshot.version} &nbsp;·&nbsp; ${escHtml(ts)} &nbsp;·&nbsp;
  services: <b>${snapshot.services.map(escHtml).join(', ')}</b>
  &nbsp;&nbsp;
  <span class="badge http">HTTP ${counts.http}</span>
  <span class="badge grpc">gRPC ${counts.grpc}</span>
  <span class="badge db">DB ${counts.db}</span>
  <span class="badge syscall">syscall ${counts.syscall}</span>
</div>
<div class="actions">
  <button onclick="vscode.postMessage({command:'replay'})">▶ Replay</button>
  <button onclick="vscode.postMessage({command:'inspect'})">🔍 Inspect in Terminal</button>
</div>
<table>
  <thead><tr>
    <th>Timestamp</th><th>Type</th><th>Details</th><th>Service</th>
  </tr></thead>
  <tbody>
${rows}
  </tbody>
</table>
<script>const vscode = acquireVsCodeApi();</script>
</body>
</html>`;
}

function renderEventRow(ev: Event): string {
    const ts = formatNs(ev.timestamp_ns);
    switch (ev.type) {
        case 'http': {
            const status = ev.status_code ? ` → ${ev.status_code}` : '';
            const detail = `${ev.direction === 'inbound' ? '← ' : '→ '}${escHtml(ev.method)} ${escHtml(ev.path)}${status}`;
            return row(ts, 'http', detail, ev.service);
        }
        case 'db':
            return row(ts, 'db', `[${escHtml(ev.protocol)}] ${escHtml(ev.query)}`, ev.service);
        case 'grpc':
            return row(ts, 'grpc', escHtml(ev.path), ev.service);
        case 'syscall':
            return row(ts, 'syscall', `${escHtml(ev.kind)} → ${ev.return_value}`, `pid:${ev.pid}`);
    }
}

function row(ts: string, type: string, detail: string, service: string): string {
    return `    <tr>
      <td class="ts">${ts}</td>
      <td><span class="badge ${type}">${type}</span></td>
      <td>${detail}</td>
      <td>${escHtml(service)}</td>
    </tr>`;
}

function countEvents(events: Event[]): Record<string, number> {
    const counts: Record<string, number> = { http: 0, db: 0, grpc: 0, syscall: 0 };
    for (const e of events) counts[e.type] = (counts[e.type] ?? 0) + 1;
    return counts;
}

function nsToDate(ns: number): string {
    const ms = ns / 1_000_000;
    return new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC');
}

function formatNs(ns: number): string {
    return `${(ns / 1_000_000).toFixed(3)} ms`;
}

function escHtml(s: string): string {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
