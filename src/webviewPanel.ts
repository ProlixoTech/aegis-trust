// src/webviewPanel.ts - Dumb Webview Adapter for Prolixo Aegis Personal v0.1 Prototype
//
// THIS WEBVIEW IS A DUMB RENDERER.
//
// It may only:
//   - Render AegisUiState received from StateManager via { command: "state" }.
//   - Render RiskScanResult received from Orchestrator via { command: "riskScan" }.
//   - Send { command: "restore" } when the user clicks Restore.
//   - Send { command: "ready" } when it first loads, to request current state.
//
// It must NOT:
//   - Read files, write files, or access .aegis/.
//   - Create snapshots, verify hashes, or decide restore success.
//   - Run the risk scan itself.
//   - Own authoritative state. State and scan results come from the extension host.
//
// LIFECYCLE RULE (Phase 3-A addition):
//   When the panel opens or "ready" fires, the extension host sends BOTH:
//     1. { command: "state", state: AegisUiState }         -> protection status
//     2. { command: "riskScan", result: RiskScanResult }   -> scan results (if available)
//   The Webview JS caches the last received scan result and re-renders on new state.
//
// Phase 5-E changes (wording only, no logic changes):
//   1. Added INACTIVE entry to STATUS_CONFIG in the JS renderer.
//      INACTIVE is used exclusively when no workspace folder is open.
//      It renders as "Aegis: No Folder Open" with a neutral grey colour.
//      No state machine transitions apply to INACTIVE - it is display-only.
//   2. Changed Risk Scan card title from "First-run Risk Scan" to
//      "Workspace Risk Scan". Behaviour is unchanged.
//
// Messages extension -> webview:
//   { command: "state",    state: AegisUiState   }
//   { command: "riskScan", result: RiskScanResult }
// Messages webview -> extension:
//   { command: "restore" } | { command: "ready" }

import * as vscode from "vscode";
import { AegisUiState } from "../packages/aegis-core";
import { RiskScanResult } from "./riskScan";

function logWebviewPanelError(message: string, detail?: unknown): void {
  console.error(...(typeof detail === "undefined" ? [message] : [message, detail]));
}

export class AegisWebviewPanel {
  private static _instance: AegisWebviewPanel | undefined;

  private readonly _panel: vscode.WebviewPanel;
  private _onRestore:          () => Promise<void>;
  private _getCurrentState:    () => AegisUiState;
  /** Phase 3-A: getter for the cached risk scan result. Returns null if scan hasn't run. */
  private _getRiskScanResult:  () => RiskScanResult | null;

  private constructor(
    panel:              vscode.WebviewPanel,
    onRestore:          () => Promise<void>,
    getCurrentState:    () => AegisUiState,
    getRiskScanResult:  () => RiskScanResult | null
  ) {
    this._panel             = panel;
    this._onRestore         = onRestore;
    this._getCurrentState   = getCurrentState;
    this._getRiskScanResult = getRiskScanResult;
    panel.webview.html    = this._buildHtml();

    // Handle messages from the Webview
    panel.webview.onDidReceiveMessage(async (msg: { command: string }) => {
      try {
        if (msg.command === "restore") {
          await this._onRestore();
        } else if (msg.command === "ready") {
          // Webview loaded (or its JS context reinitialized).
          // Send both current protection state AND risk scan result.
          this._postState(this._getCurrentState());
          const scanResult = this._getRiskScanResult();
          if (scanResult) {
            this._postRiskScan(scanResult);
          }
        }
      } catch (err) {
        logWebviewPanelError("[Aegis] Webview message handler error:", err);
      }
    });

    // When the panel is disposed, clear the singleton
    panel.onDidDispose(() => {
      AegisWebviewPanel._instance = undefined;
    });

    // Send initial state + risk scan immediately.
    // setTimeout ensures Webview script is ready to receive.
    setTimeout(() => {
      this._postState(this._getCurrentState());
      const scanResult = this._getRiskScanResult();
      if (scanResult) {
        this._postRiskScan(scanResult);
      }
    }, 100);
  }

// Public API

  /**
   * Open or reveal the Aegis Protection Panel.
   *
 * getCurrentState:   called at "ready" time - always live StateManager state.
 * getRiskScanResult: called at "ready" time - always cached scan result.
   * Both getters are updated on every show() call to avoid stale closures.
   */
  static show(
    state:             AegisUiState,
    onRestore:         () => Promise<void>,
    getCurrentState:   () => AegisUiState,
    getRiskScanResult: () => RiskScanResult | null
  ): AegisWebviewPanel {
    if (AegisWebviewPanel._instance) {
      AegisWebviewPanel._instance._onRestore         = onRestore;
      AegisWebviewPanel._instance._getCurrentState   = getCurrentState;
      AegisWebviewPanel._instance._getRiskScanResult = getRiskScanResult;
      AegisWebviewPanel._instance._panel.reveal(vscode.ViewColumn.One);
      AegisWebviewPanel._instance._postState(state);
      // Also send cached scan result when panel is revealed
      const scanResult = getRiskScanResult();
      if (scanResult) {
        AegisWebviewPanel._instance._postRiskScan(scanResult);
      }
      return AegisWebviewPanel._instance;
    }

    const panel = vscode.window.createWebviewPanel(
      "aegisProtectionPanel",
      "Aegis Protection",
      vscode.ViewColumn.One,
      {
        enableScripts:           true,
        retainContextWhenHidden: true,
      }
    );

    AegisWebviewPanel._instance = new AegisWebviewPanel(
      panel, onRestore, getCurrentState, getRiskScanResult
    );
    return AegisWebviewPanel._instance;
  }

  /** Push a protection state update to an open panel. No-op if closed. */
  static pushState(state: AegisUiState): void {
    AegisWebviewPanel._instance?._postState(state);
  }

  /** Phase 3-A: Push risk scan results to an open panel. No-op if closed. */
  static pushRiskScan(result: RiskScanResult): void {
    AegisWebviewPanel._instance?._postRiskScan(result);
  }

  /** True if the panel is currently open. */
  static isOpen(): boolean {
    return AegisWebviewPanel._instance !== undefined;
  }

// Internal

  private _postState(state: AegisUiState): void {
    try {
      void this._panel.webview.postMessage({ command: "state", state }).then(undefined, () => undefined);
    } catch {
    // Panel may have been disposed - safe to swallow
    }
  }

  private _postRiskScan(result: RiskScanResult): void {
    try {
      void this._panel.webview.postMessage({ command: "riskScan", result }).then(undefined, () => undefined);
    } catch {
    // Panel may have been disposed - safe to swallow
    }
  }

  private _buildHtml(): string {
    const nonce = getNonce();
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
<title>Aegis Protection</title>
<style nonce="${nonce}">
  :root {
    --safe:      #4CAF50;
    --warning:   #FF9800;
    --blocked:   #F44336;
    --restoring: #2196F3;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 14px;
    color: var(--vscode-foreground, #ccc);
    background: var(--vscode-editor-background, #1e1e1e);
    padding: 24px;
    max-width: 480px;
    margin: 0 auto;
  }
  .card {
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 20px;
    background: var(--vscode-editorWidget-background, #252526);
  }
  .header {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 8px;
  }
  .msg {
    font-size: 13px;
    line-height: 1.6;
    color: var(--vscode-descriptionForeground, #aaa);
  }
  .btn {
    display: block;
    width: 100%;
    padding: 10px 16px;
    margin-bottom: 10px;
    border: none;
    border-radius: 5px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    text-align: center;
    transition: opacity 0.15s;
  }
  .btn:hover:not(:disabled) { opacity: 0.85; }
  .btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .btn-restore {
    background: var(--vscode-button-background, #0e639c);
    color:      var(--vscode-button-foreground, #fff);
  }
  .hint {
    font-size: 11px;
    color: var(--vscode-descriptionForeground, #666);
    text-align: center;
    margin-top: 12px;
  }

        /* Phase 3-A: Risk Scan section */
  .risk-card {
    border-radius: 6px;
    padding: 14px 18px;
    margin-bottom: 16px;
    background: var(--vscode-editorWidget-background, #252526);
    border-left: 3px solid #888;
  }
  .risk-title {
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--vscode-descriptionForeground, #888);
    margin-bottom: 4px;
  }
  .risk-subtitle {
    font-size: 11px;
    color: var(--vscode-descriptionForeground, #999);
    margin-bottom: 10px;
  }
  .risk-list {
    list-style: none;
    padding: 0;
    margin: 0 0 8px 0;
  }
  .risk-list li {
    padding: 5px 0;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    font-size: 12px;
    line-height: 1.5;
  }
  .risk-list li:last-child { border-bottom: none; }
  .risk-path {
    font-family: monospace;
    font-size: 12px;
    color: var(--vscode-foreground, #ddd);
    font-weight: 600;
  }
  .risk-reason {
    color: var(--vscode-descriptionForeground, #999);
    font-size: 11px;
    margin-top: 1px;
  }
  .risk-empty {
    font-size: 12px;
    color: var(--vscode-descriptionForeground, #888);
    font-style: italic;
  }
  .risk-footer {
    font-size: 10px;
    color: var(--vscode-descriptionForeground, #666);
    margin-top: 8px;
  }
</style>
</head>
<body>

  <!-- Protection status card (unchanged from Phase 2-A) -->
  <div class="card" id="statusCard">
    <div class="header">
      <span id="statusIcon"></span>
      <span id="statusLabel">Loading...</span>
    </div>
    <p class="msg" id="statusMsg"></p>
    <p class="msg" id="licenseTierMsg"></p>
        <p class="msg" id="licenseCapabilitiesMsg"></p>
  </div>

  <button class="btn btn-restore" id="restoreBtn" disabled>
    Restore Last Safe State
  </button>

  <!-- Phase 3-A: Workspace Risk Scan section (hidden until scan result arrives) -->
  <!-- Phase 5-E: title changed from "First-run Risk Scan" to "Workspace Risk Scan" -->
  <div class="risk-card" id="riskCard" style="display:none;">
    <div class="risk-title">Workspace Risk Scan</div>
    <p class="risk-subtitle">Top files to review before AI edits:</p>
    <ul class="risk-list" id="riskList"></ul>
    <div class="risk-footer" id="riskFooter">
      Static scan only - Top-level/1-level - Local only - No file contents read
    </div>
  </div>

  <p class="hint">
    Aegis v0.1 Prototype - Local only - No network calls
  </p>

<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();

  const card       = document.getElementById('statusCard');
  const icon       = document.getElementById('statusIcon');
  const label      = document.getElementById('statusLabel');
  const msg        = document.getElementById('statusMsg');
  const tierMsg    = document.getElementById('licenseTierMsg');
      const capMsg     = document.getElementById('licenseCapabilitiesMsg');
  const restoreBtn = document.getElementById('restoreBtn');
  const riskCard   = document.getElementById('riskCard');
  const riskList   = document.getElementById('riskList');
  const riskFooter = document.getElementById('riskFooter');

  // Phase 5-E: added INACTIVE entry for the no-folder-open display state.
  // INACTIVE is never held by StateManager. It is used only when extension.ts
  // passes status: "INACTIVE" in the no-folder-open inline state object.
  // Restore button remains disabled for INACTIVE (restoreAvailable: false).
  const STATUS_CONFIG = {
    SAFE:      { color: '#4CAF50', icon: 'OK', label: 'Safe'           },
    WARNING:   { color: '#FF9800', icon: '!',  label: 'Warning'        },
    BLOCKED:   { color: '#F44336', icon: 'X',  label: 'Blocked'        },
    RESTORING: { color: '#2196F3', icon: '~',  label: 'Restoring'      },
    INACTIVE:  { color: '#888888', icon: '-',  label: 'No Folder Open' },
  };

  // Render protection state
  function render(state) {
    const cfg = STATUS_CONFIG[state.status] || STATUS_CONFIG.SAFE;

    card.style.borderLeft = '5px solid ' + cfg.color;
    icon.textContent  = cfg.icon;
    icon.style.color  = cfg.color;
    label.textContent = 'Aegis: ' + cfg.label;
    label.style.color = cfg.color;
    msg.textContent   = state.message || '';
    tierMsg.textContent = state.licenseTier ? 'License tier: ' + String(state.licenseTier) : '';
      capMsg.textContent = state.licenseCapabilities && state.licenseCapabilities.length ? 'License capabilities: ' + state.licenseCapabilities.map(String).join(', ') : '';

    const canRestore = state.restoreAvailable && !state.isProcessing;
    restoreBtn.disabled = !canRestore;
    restoreBtn.textContent = state.isProcessing
      ? 'Restoring...'
      : 'Restore Last Safe State';
  }

  // Render risk scan results
  // Only whitelisted fields (path, reason) are rendered.
  // No file contents. No raw secrets. Paths are relative.
  function renderRiskScan(result) {
    while (riskList.firstChild) {
      riskList.removeChild(riskList.firstChild);
    }

    if (!result || !result.items || result.items.length === 0) {
      const li = document.createElement('li');
      li.className = 'risk-empty';
      li.textContent = 'No high-risk files detected by static scan.';
      riskList.appendChild(li);
    } else {
      result.items.forEach(function(item, idx) {
        const li = document.createElement('li');
        // Render only the two safe whitelisted fields: path and reason.
        // item.score is intentionally not shown to users.
        const pathDiv = document.createElement('div');
        pathDiv.className = 'risk-path';
        pathDiv.textContent = (idx + 1) + '. ' + String(item.path);

        const reasonDiv = document.createElement('div');
        reasonDiv.className = 'risk-reason';
        reasonDiv.textContent = String(item.reason);

        li.appendChild(pathDiv);
        li.appendChild(reasonDiv);
        riskList.appendChild(li);
      });
    }

    // Show cap note if scan was capped
    let footerText = 'Static scan only \u00b7 Top-level/1-level \u00b7 Local only \u00b7 No file contents read';
    if (result && result.capped) {
      footerText = 'Scan capped at 500 top-level entries. ' + footerText;
    }
    riskFooter.textContent = footerText;

    riskCard.style.display = 'block';
  }


  // Message router
  window.addEventListener('message', function(event) {
    const m = event.data;
    if (!m) { return; }
    if (m.command === 'state' && m.state) {
      render(m.state);
    } else if (m.command === 'riskScan' && m.result !== undefined) {
      renderRiskScan(m.result);
    }
  });

  // Send restore command
  restoreBtn.addEventListener('click', function() {
    if (!restoreBtn.disabled) {
      vscode.postMessage({ command: 'restore' });
    }
  });

  // Tell extension host we are ready
  vscode.postMessage({ command: 'ready' });
</script>
</body>
</html>`;
  }
}

function getNonce(): string {
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let text = "";
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
