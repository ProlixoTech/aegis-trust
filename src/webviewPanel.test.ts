import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const source = readFileSync(join(process.cwd(), "src", "webviewPanel.ts"), "utf8");

test("webviewPanel keeps singleton lifecycle and explicit show entrypoint", () => {
  assert.ok(source.includes("export class AegisWebviewPanel"));
  assert.ok(source.includes("private static _instance: AegisWebviewPanel | undefined"));
  assert.ok(source.includes("private constructor("));
  assert.ok(source.includes("static show("));
  assert.ok(source.includes("AegisWebviewPanel._instance._onRestore         = onRestore"));
  assert.ok(source.includes("AegisWebviewPanel._instance._getCurrentState   = getCurrentState"));
  assert.ok(source.includes("AegisWebviewPanel._instance._getRiskScanResult = getRiskScanResult"));
  assert.ok(source.includes("AegisWebviewPanel._instance._panel.reveal(vscode.ViewColumn.One)"));
  assert.ok(source.includes("AegisWebviewPanel._instance = undefined"));
});

test("webviewPanel creates the protection webview with retained context", () => {
  assert.ok(source.includes("vscode.window.createWebviewPanel("));
  assert.ok(source.includes('"aegisProtectionPanel"'));
  assert.ok(source.includes('"Aegis Protection"'));
  assert.ok(source.includes("vscode.ViewColumn.One"));
  assert.ok(source.includes("enableScripts:           true"));
  assert.ok(source.includes("retainContextWhenHidden: true"));
});

test("webviewPanel handles only restore and ready messages from webview", () => {
  assert.ok(source.includes("panel.webview.onDidReceiveMessage(async (msg: { command: string }) => {"));
  assert.ok(source.includes('if (msg.command === "restore")'));
  assert.ok(source.includes("await this._onRestore();"));
  assert.ok(source.includes('} else if (msg.command === "ready")'));
  assert.ok(source.includes("this._postState(this._getCurrentState());"));
  assert.ok(source.includes("const scanResult = this._getRiskScanResult();"));
  assert.ok(source.includes("this._postRiskScan(scanResult);"));
  assert.doesNotMatch(source, /msg\.command === ["']write["']/);
  assert.doesNotMatch(source, /msg\.command === ["']snapshot["']/);
  assert.doesNotMatch(source, /msg\.command === ["']scan["']/);
});

test("webviewPanel posts state and riskScan messages only through explicit helpers", () => {
  assert.ok(source.includes('this._panel.webview.postMessage({ command: "state", state })'));
  assert.ok(source.includes('this._panel.webview.postMessage({ command: "riskScan", result })'));
  assert.ok(source.includes("static pushState(state: AegisUiState): void"));
  assert.ok(source.includes("AegisWebviewPanel._instance?._postState(state);"));
  assert.ok(source.includes("static pushRiskScan(result: RiskScanResult): void"));
  assert.ok(source.includes("AegisWebviewPanel._instance?._postRiskScan(result);"));
  assert.ok(source.includes("static isOpen(): boolean"));
});

test("webviewPanel sends initial state and cached risk scan after creation and reveal", () => {
  assert.ok(source.includes("setTimeout(() => {"));
  assert.ok(source.includes("}, 100);"));
  assert.ok(source.includes("AegisWebviewPanel._instance._postState(state);"));
  assert.ok(source.includes("const scanResult = getRiskScanResult();"));
  assert.ok(source.includes("AegisWebviewPanel._instance._postRiskScan(scanResult);"));
});

test("webviewPanel html declares local-only CSP and no network posture", () => {
  assert.ok(source.includes("Content-Security-Policy"));
  assert.ok(source.includes("default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';"));
  assert.ok(source.includes('<style nonce="${nonce}">'));
  assert.ok(source.includes('<script nonce="${nonce}">'));
  assert.doesNotMatch(source, /unsafe-inline/);
  assert.ok(source.includes("Aegis v0.1 Prototype"));
  assert.ok(source.includes("Local only"));
  assert.ok(source.includes("No network calls"));
  assert.doesNotMatch(source, /https?:\/\//);
  assert.doesNotMatch(source, /fetch\s*\(/);
  assert.doesNotMatch(source, /XMLHttpRequest/);
});

test("webviewPanel renderer supports status and inactive display states", () => {
  assert.ok(source.includes("const STATUS_CONFIG = {"));
  assert.ok(source.includes("SAFE:"));
  assert.ok(source.includes("WARNING:"));
  assert.ok(source.includes("BLOCKED:"));
  assert.ok(source.includes("RESTORING:"));
  assert.ok(source.includes("INACTIVE:"));
  assert.ok(source.includes("const canRestore = state.restoreAvailable && !state.isProcessing;"));
  assert.ok(source.includes("restoreBtn.disabled = !canRestore;"));
  assert.ok(source.includes("msg.textContent   = state.message || '';"));
  assert.ok(source.includes("licenseTierMsg"));
  assert.ok(source.includes("licenseCapabilitiesMsg"));
  assert.ok(source.includes("capMsg.textContent = state.licenseCapabilities && state.licenseCapabilities.length ?"));
  assert.ok(source.includes("tierMsg.textContent = state.licenseTier ? 'License tier: ' + String(state.licenseTier) : '';"));
});

test("webviewPanel risk scan renderer limits displayed fields without HTML insertion", () => {
  assert.ok(source.includes("function renderRiskScan(result)"));
  assert.ok(source.includes("Only whitelisted fields (path, reason) are rendered."));
  assert.ok(source.includes("item.score is intentionally not shown to users."));
  assert.ok(source.includes("pathDiv.textContent = (idx + 1) + '. ' + String(item.path);"));
  assert.ok(source.includes("reasonDiv.textContent = String(item.reason);"));
  assert.ok(source.includes("riskList.removeChild(riskList.firstChild);"));
  assert.equal(source.match(/\.innerHTML/g)?.length ?? 0, 0);
  assert.ok(!source.includes("riskList.innerHTML = '';"));
  assert.ok(!source.includes("li.innerHTML ="));
});

test("webviewPanel client script sends only restore and ready commands to extension host", () => {
  assert.ok(source.includes("vscode.postMessage({ command: 'restore' });"));
  assert.ok(source.includes("vscode.postMessage({ command: 'ready' });"));
  assert.equal(source.match(/vscode\.postMessage/g)?.length, 2);
  assert.ok(source.includes("window.addEventListener('message'"));
  assert.ok(source.includes("if (m.command === 'state' && m.state)"));
  assert.ok(source.includes("render(m.state);"));
  assert.ok(source.includes("} else if (m.command === 'riskScan' && m.result !== undefined)"));
  assert.ok(source.includes("renderRiskScan(m.result);"));
});
