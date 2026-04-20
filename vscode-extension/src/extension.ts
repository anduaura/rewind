// Copyright 2026 The rewind Authors. Apache-2.0.

import * as vscode from 'vscode';
import { SnapshotViewerProvider } from './snapshotViewer';

export function activate(context: vscode.ExtensionContext): void {
    // Custom editor for .rwd files.
    context.subscriptions.push(
        vscode.window.registerCustomEditorProvider(
            'rewind.snapshotViewer',
            new SnapshotViewerProvider(context),
            { webviewOptions: { retainContextWhenHidden: true } }
        )
    );

    // Open snapshot command (opens the custom editor).
    context.subscriptions.push(
        vscode.commands.registerCommand('rewind.openSnapshot', (uri: vscode.Uri) => {
            vscode.commands.executeCommand(
                'vscode.openWith',
                uri,
                'rewind.snapshotViewer'
            );
        })
    );

    // Replay snapshot in integrated terminal.
    context.subscriptions.push(
        vscode.commands.registerCommand('rewind.replaySnapshot', async (uri: vscode.Uri) => {
            const config = vscode.workspace.getConfiguration('rewind');
            const exe = config.get<string>('executablePath', 'rewind');
            const compose = config.get<string>('composeFile', 'docker-compose.yml');
            const key = config.get<string>('snapshotKey', '');

            let cmd = `${exe} replay "${uri.fsPath}" --compose "${compose}"`;
            if (key) {
                cmd += ` --key "${key}"`;
            }

            const terminal = vscode.window.createTerminal('rewind replay');
            terminal.show();
            terminal.sendText(cmd);
        })
    );

    // Inspect snapshot in integrated terminal.
    context.subscriptions.push(
        vscode.commands.registerCommand('rewind.inspectSnapshot', async (uri: vscode.Uri) => {
            const config = vscode.workspace.getConfiguration('rewind');
            const exe = config.get<string>('executablePath', 'rewind');
            const key = config.get<string>('snapshotKey', '');

            let cmd = `${exe} inspect "${uri.fsPath}"`;
            if (key) {
                cmd += ` --key "${key}"`;
            }

            const terminal = vscode.window.createTerminal('rewind inspect');
            terminal.show();
            terminal.sendText(cmd);
        })
    );
}

export function deactivate(): void {}
