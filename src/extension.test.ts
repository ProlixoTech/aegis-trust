import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const source = readFileSync(join(process.cwd(), "src", "extension.ts"), "utf8");

function indexOfRequired(text: string): number {
  const index = source.indexOf(text);
  assert.notEqual(index, -1, text);
  return index;
}

test("extension registers public commands before initialization attempt", () => {
  const activateIndex = indexOfRequired("export async function activate(context: vscode.ExtensionContext): Promise<void>");
  const protectedTerminalIndex = indexOfRequired('vscode.commands.registerCommand("aegis.protectedTerminal"');
  const gatewayIndex = indexOfRequired('vscode.commands.registerCommand("aegis.aegisExecutionGatewayMvp0"');
  const reviewIndex = indexOfRequired('vscode.commands.registerCommand("aegis.reviewAiCommandOrAction"');
  const panelIndex = indexOfRequired('vscode.commands.registerCommand("aegis.showProtectionPanel"');
  const statusIndex = indexOfRequired('vscode.commands.registerCommand("aegis.phase1.status"');
  const restoreIndex = indexOfRequired('vscode.commands.registerCommand("aegis.phase1.restoreLastSafeState"');
  const receiptIndex = indexOfRequired('vscode.commands.registerCommand("aegis.generateWorkReceipt"');
  const baselineIndex = indexOfRequired('vscode.commands.registerCommand("aegis.registerCleanBaseline"');
  const initializeIndex = indexOfRequired("await initializeAegisOnce(context);");

  assert.ok(activateIndex < protectedTerminalIndex);
  assert.ok(protectedTerminalIndex < initializeIndex);
  assert.ok(gatewayIndex < initializeIndex);
  assert.ok(reviewIndex < initializeIndex);
  assert.ok(panelIndex < initializeIndex);
  assert.ok(statusIndex < initializeIndex);
  assert.ok(restoreIndex < initializeIndex);
  assert.ok(receiptIndex < initializeIndex);
  assert.ok(baselineIndex < initializeIndex);
});

test("extension no-folder protection panel uses INACTIVE state and no risk scan", () => {
  assert.ok(source.includes("if (!_initialized || !_stateMgr || !_engine || !_stores)"));
  assert.ok(source.includes('status: "INACTIVE"'));
  assert.ok(source.includes('message: "Open a folder first to use Aegis."'));
  assert.ok(source.includes("restoreAvailable: false"));
  assert.ok(source.includes("isProcessing: false"));
  assert.ok(source.includes("() => null   // no risk scan without a workspace"));
  assert.ok(source.includes("Open a folder first to use Aegis."));
});

test("extension deactivate disposes state, watchers, and debounce timers", () => {
  assert.ok(source.includes("export async function deactivate(): Promise<void>"));
  assert.ok(source.includes("_stateMgr?.dispose();"));
  assert.ok(source.includes("_watchers.forEach(w => w.dispose());"));
  assert.ok(source.includes("_watchers = [];"));
  assert.ok(source.includes("_debounceTimers.forEach(t => clearTimeout(t));"));
  assert.ok(source.includes("_debounceTimers.clear();"));
});

test("extension onWillSave captures only protected targets with alias and restore guards", () => {
  assert.ok(source.includes("vscode.workspace.onWillSaveTextDocument((event) => {"));
  assert.ok(source.includes("const absPath = event.document.uri.fsPath;"));
  assert.ok(source.includes("if (!isProtectedTargetFile(absPath, protectedRelPaths, projectRoot)) { return; }"));
  assert.ok(source.includes("if (isInsideAegisDir(absPath, aegisDir))                { return; }"));
  assert.ok(source.includes("REALPATH_TARGET_BINDING_RUNTIME_GUARD_V1"));
  assert.ok(source.includes("const realpathBinding = describeRealpathTargetBinding(absPath, projectRoot);"));
  assert.equal((source.match(/describeRealpathTargetBinding\(absPath, projectRoot\)/g) ?? []).length, 2);
  assert.ok(source.includes("realpathBinding.mayBeSymlinkOrJunction || realpathBinding.mayHaveHardlinkAlias || realpathBinding.mayResolveThroughAlias"));
  assert.ok(source.includes("stateMgr.setWarning("));
  assert.ok(source.includes("if (engine.isRestoring(absPath))                        { return; }"));
  assert.ok(source.includes("event.waitUntil("));
  assert.ok(source.includes("engine.capturePreSave(absPath).catch((err) => {"));
});

test("extension onDidSave delegates to handleDidSave with protected target context", () => {
  assert.ok(source.includes("vscode.workspace.onDidSaveTextDocument(async (doc) => {"));
  assert.ok(source.includes("await handleDidSave(doc, projectRoot, aegisDir, engine, stores, stateMgr, ledger, protectedRelPaths);"));
  assert.ok(source.includes("async function handleDidSave("));
  assert.ok(source.includes("protectedRelPaths: ReadonlyArray<string>"));
});

test("extension watcher setup resets stale watchers and debounce timers before installing target watchers", () => {
  assert.ok(source.includes("_watchers.forEach(w => w.dispose());"));
  assert.ok(source.includes("_watchers = [];"));
  assert.ok(source.includes("_debounceTimers.forEach(t => clearTimeout(t));"));
  assert.ok(source.includes("_debounceTimers.clear();"));
  assert.ok(source.includes("for (const target of getProtectedTargets())"));
  assert.ok(source.includes("new vscode.RelativePattern("));
  assert.ok(source.includes("vscode.workspace.createFileSystemWatcher("));
  assert.ok(source.includes("/* ignoreCreateEvents */ true"));
  assert.ok(source.includes("/* ignoreChangeEvents */ false"));
  assert.ok(source.includes("/* ignoreDeleteEvents */ false"));
  assert.ok(source.includes('scheduleWatcherAction(target, "delete", projectRoot, aegisDir, stores, stateMgr, ledger);'));
  assert.ok(source.includes('scheduleWatcherAction(target, "change", projectRoot, aegisDir, stores, stateMgr, ledger);'));
  assert.ok(source.includes("_watchers.push(watcher);"));
});

test("extension startup guards do not silently claim safe on rehydration or ledger failure", () => {
  assert.ok(source.includes("await rehydrateStateOnActivation(projectRoot, aegisDir, stores, stateMgr);"));
  assert.ok(source.includes("Do NOT fall back to SAFE on rehydration failure."));
  assert.ok(source.includes("Aegis could not verify workspace safety on activation."));
  assert.ok(source.includes("LEDGER_STARTUP_INTEGRITY_EXTENSION_WIRING_RUNTIME_GUARD_V1"));
  assert.ok(source.includes("const ledgerStartupIntegrity = await _ledger.verifyStartupIntegrity();"));
  assert.ok(source.includes('ledgerStartupIntegrity.issueCode === "RECOVERED_MALFORMED_LEDGER_TAIL"'));
  assert.ok(source.includes("Aegis recovered a malformed ledger tail on startup."));
  assert.ok(source.includes("Aegis ledger integrity could not be verified on startup."));
  assert.ok(source.includes("Aegis ledger integrity check failed on startup."));
});

test("extension risk scan runs after initialization and remains non-fatal", () => {
  assert.ok(source.includes("_riskScanResult = await runRiskScan(projectRoot);"));
  assert.ok(source.includes("AegisWebviewPanel.pushRiskScan(_riskScanResult);"));
  assert.ok(source.includes("Risk scan failed (non-fatal)"));
});

test("extension baseline marker helpers use durable utf8 temp-write and best-effort directory sync", () => {
  assert.ok(source.includes("function baselineMarkerPath(aegisDir: string, markerFileName: string): string"));
  assert.ok(source.includes("return nodePath.join(aegisDir, markerFileName);"));
  assert.ok(source.includes("async function readBaselineMarker(aegisDir: string, markerFileName: string): Promise<boolean>"));
  assert.ok(source.includes("return parsed.registered === true;"));
  assert.ok(source.includes("async function writeExtensionDurableUtf8File(targetPath: string, content: string): Promise<void>"));
  assert.ok(source.includes("EXTENSION_CRASH_SAFE_DURABLE_WRITE_RUNTIME_GUARD_V1"));
  assert.ok(source.includes("await handle.writeFile(content, \"utf8\");"));
  assert.ok(source.includes("await handle.sync();"));
  assert.ok(source.includes("await fs.promises.rename(tempPath, targetPath);"));
  assert.ok(source.includes("await bestEffortSyncExtensionDirectory(targetDir);"));
  assert.ok(source.includes("try { await fs.promises.unlink(tempPath); } catch { /* best effort cleanup */ }"));
  assert.ok(source.includes("EXTENSION_DIRECTORY_SYNC_BEST_EFFORT_GUARD_V1"));
});

test("extension handleDidSave gates first registration, degraded index, and missing pre-save baseline", () => {
  assert.ok(source.includes("if (!isProtectedTargetFile(absPath, protectedRelPaths, projectRoot)) { return; }"));
  assert.ok(source.includes("if (isInsideAegisDir(absPath, aegisDir))                { return; }"));
  assert.ok(source.includes("const relPath = nodePath.relative(projectRoot, absPath).replace(/\\\\/g, \"/\");"));
  assert.ok(source.includes("const target = getTargetByRelPath(relPath);"));
  assert.ok(source.includes("const store = stores.get(target.target_id);"));
  assert.ok(source.includes("const baseline = engine.consumePending(absPath);"));
  assert.ok(source.includes("but no pre-save baseline is available"));
  assert.ok(source.includes("const markerRegistered = await readBaselineMarker(aegisDir, target.marker_file);"));
  assert.ok(source.includes("protected-change registration index read threw"));
  assert.ok(source.includes("const indexHasBaseline = !!(existingIndex &&"));
  assert.ok(source.includes("const isFirstRegistration = !markerRegistered && !indexExists;"));
  assert.ok(source.includes("const isMarkerLossReregistration = !markerRegistered && indexHasBaseline;"));
  assert.ok(source.includes("const isDegradedIndex = indexExists && !indexHasBaseline;"));
  assert.ok(source.includes("restore index is degraded"));
  assert.ok(source.includes("if (isFirstRegistration || isMarkerLossReregistration)"));
  assert.ok(source.includes("postSaveContent = await fs.promises.readFile(absPath, \"utf8\");"));
  assert.ok(source.includes("if (postSaveContent.trim().length === 0)"));
  assert.ok(source.includes("store.createBaselineSnapshotFromContent("));
  assert.ok(source.includes("const markerWritten = await writeBaselineMarker(aegisDir, target.marker_file, relPath);"));
  assert.ok(source.includes("recreateBaselineSnapshotAfterMarkerLossOrNull("));
  assert.ok(source.includes("store.recreateBaselineSnapshotAfterMarkerLoss("));
  assert.ok(source.includes("baseline_registration marker_failure snapshot_created append threw"));
  assert.ok(source.includes("baseline_registration snapshot_created append threw"));
  assert.ok(source.includes("pre_save_snapshot_created append threw"));
  assert.ok(source.includes("_ledger.append(event).catch(() => false)"));
  assert.ok(source.includes("protected-change audit snapshot creation threw"));
  assert.ok(source.includes("createSnapshotOrNull(store, baseline, target.relative_path)"));
  assert.ok(source.includes("baseline snapshot creation threw"));
  assert.ok(source.includes("baseline registration snapshot creation threw"));
  assert.ok(source.includes("baseline bulk snapshot creation threw"));
});
test("extension public command callbacks keep command-specific error guards", () => {
  const guardedCommands = [
    ["aegis.aegisExecutionGatewayMvp0", "[Aegis] aiExecutionGateway command callback error:"],
    ["aegis.reviewAiCommandOrAction", "[Aegis] reviewAiCommand command callback error:"],
    ["aegis.showProtectionPanel", "[Aegis] showProtectionPanel error:"],
    ["aegis.phase1.status", "[Aegis] status command error:"],
    ["aegis.phase1.restoreLastSafeState", "[Aegis] restoreLastSafeState command error:"],
    ["aegis.generateWorkReceipt", "[Aegis] generateWorkReceipt command error:"],
    ["aegis.registerCleanBaseline", "[Aegis] registerCleanBaseline command error:"],
  ];

  for (const [command, errorMarker] of guardedCommands) {
    const commandIndex = indexOfRequired(`vscode.commands.registerCommand("${command}"`);
    const errorIndex = indexOfRequired(errorMarker);
    assert.ok(commandIndex < errorIndex, `${command} should keep its command-specific error guard`);
  }

  assert.ok(source.includes('showWarningMessageBestEffort("Aegis could not complete verified restore.");'));
  assert.ok(source.includes('showWarningMessageBestEffort("Aegis could not generate the Work Receipt.");'));
  assert.ok(source.includes('showWarningMessageBestEffort("Aegis could not complete baseline registration.");'));
});
test("extension public commands keep no-folder guard messages", () => {
  const noFolderMarkers = [
    'showInformationMessageBestEffort("Open a folder first to use Aegis Phase 1.");',
    'showWarningMessageBestEffort("Open a folder first to use Aegis Phase 1.");',
    'showWarningMessageBestEffort("Open a folder first to use Aegis.");',
  ];

  for (const marker of noFolderMarkers) {
    assert.ok(source.includes(marker), marker);
  }

  assert.ok(indexOfRequired('vscode.commands.registerCommand("aegis.phase1.status"') < indexOfRequired('showInformationMessageBestEffort("Open a folder first to use Aegis Phase 1.");'));
  assert.ok(indexOfRequired('vscode.commands.registerCommand("aegis.phase1.restoreLastSafeState"') < indexOfRequired('showWarningMessageBestEffort("Open a folder first to use Aegis Phase 1.");'));
  const receiptCommandIndex = indexOfRequired('vscode.commands.registerCommand("aegis.generateWorkReceipt"');
  const receiptCommandEndIndex = indexOfRequired('vscode.commands.registerCommand("aegis.registerCleanBaseline"');
  const receiptCommandBlock = source.slice(receiptCommandIndex, receiptCommandEndIndex);
  assert.ok(receiptCommandBlock.includes('showWarningMessageBestEffort("Open a folder first to use Aegis.");'));
});
test("extension handleRestore keeps in-flight guard and final release", () => {
  const restoreIndex = indexOfRequired("async function handleRestore(): Promise<void>");
  const receiptIndex = indexOfRequired("async function handleGenerateReceipt(): Promise<void>");
  const restoreBlock = source.slice(restoreIndex, receiptIndex);

  function restoreBlockIndexOfRequired(text: string): number {
    const index = restoreBlock.indexOf(text);
    assert.notEqual(index, -1, text);
    return index;
  }

  const guardIndex = restoreBlockIndexOfRequired("if (_restoreCommandInFlight) {");
  const waitWarningIndex = restoreBlockIndexOfRequired('showWarningMessageBestEffort("Aegis restore is already running. Please wait.");');
  const setTrueIndex = restoreBlockIndexOfRequired("_restoreCommandInFlight = true;");
  const setRestoringIndex = restoreBlockIndexOfRequired("_stateMgr.setRestoring();");
  const releaseIndex = restoreBlock.lastIndexOf("_restoreCommandInFlight = false;");

  assert.ok(guardIndex < waitWarningIndex);
  assert.ok(waitWarningIndex < setTrueIndex);
  assert.ok(setTrueIndex < setRestoringIndex);
  assert.ok(setRestoringIndex < releaseIndex);
});


test("extension repairs a missing activity marker only for complete existing baselines", () => {
  const registrationIndex = indexOfRequired(
    "async function handleRegisterCleanBaseline(): Promise<void>"
  );
  const registrationBlock = source.slice(registrationIndex);

  const missingGateIndex = registrationBlock.indexOf(
    "activityMarkerMissing === true"
  );
  const initializeIndex = registrationBlock.indexOf(
    "await initActivityMarker(aegisDir);"
  );

  assert.ok(registrationBlock.includes("let   registeredTargetCount = 0;"));
  assert.ok(registrationBlock.includes("let   activityMarkerInitialized = false;"));
  assert.ok(registrationBlock.includes("if (markerPresent && indexHasBaseline) {"));
  assert.ok(/let\s+presentTargetCount\s*=\s*0;/.test(registrationBlock));
  assert.ok(/presentTargetCount\+\+;/.test(registrationBlock));
  assert.ok(
    /presentTargetCount\s*>\s*0\s*&&\s*registeredTargetCount\s*===\s*presentTargetCount/.test(
      registrationBlock
    )
  );
  assert.ok(
    registrationBlock.indexOf("presentTargetCount++;") <
      registrationBlock.indexOf("const store = _stores.get(target.target_id);")
  );
  assert.ok(registrationBlock.includes("anyFailed === false"));
  assert.ok(registrationBlock.includes("activityMarkerInitialized = true;"));
  assert.ok(registrationBlock.includes(
    "Aegis: Activity marker restored for existing clean baselines."
  ));
  assert.ok(registrationBlock.includes(
    "if (anySuccess || activityMarkerInitialized) {"
  ));
  assert.ok(missingGateIndex >= 0);
  assert.ok(initializeIndex > missingGateIndex);
});


test("extension status command includes current license tier readout", () => {
  assert.ok(source.includes('import { getCapabilitiesForTier, getLicenseTier, isCapabilityAvailableForTier, type LicenseCapability, type LicenseTier } from "./licenseTier";'));
  assert.ok(source.includes("const tier = _licenseTier;"));
  assert.ok(source.includes('const capabilities = getCapabilitiesForTier(tier).join(", ");'));
  assert.ok(source.includes("`Aegis: ${s.status} - ${s.message} (tier: ${tier}; capabilities: ${capabilities})`"));
});

test("extension attaches cached license tier to webview panel state", () => {
  assert.ok(source.includes('let _licenseTier: LicenseTier = "free";'));
  assert.ok(source.includes("function withLicenseTier(state: AegisUiState): AegisUiState"));
  assert.ok(source.includes("licenseCapabilities: getCapabilitiesForTier(_licenseTier)"));
  assert.ok(source.includes("AegisWebviewPanel.pushState(withLicenseTier(state));"));
  assert.ok(source.includes("() => withLicenseTier(_stateMgr!.getState())"));
});

test("extension command callbacks check license capabilities before gated handlers", () => {
  assert.ok(source.includes('import { getCapabilitiesForTier, getLicenseTier, isCapabilityAvailableForTier, type LicenseCapability, type LicenseTier } from "./licenseTier";'));
  assert.ok(source.includes("function isCurrentLicenseCapabilityAvailable(capability: LicenseCapability): boolean"));
  assert.ok(source.includes("return isCapabilityAvailableForTier(_licenseTier, capability);"));
  assert.ok(source.includes('isCurrentLicenseCapabilityAvailable("protectedTerminal")'));
  assert.ok(source.includes('isCurrentLicenseCapabilityAvailable("aiExecutionGatewayMvp0")'));
  assert.ok(source.includes('isCurrentLicenseCapabilityAvailable("workReceipt")'));
  assert.ok(source.includes('isCurrentLicenseCapabilityAvailable("aiCommandReview")'));
  assert.ok(source.includes('isCurrentLicenseCapabilityAvailable("coreProtection")'));
  assert.equal((source.match(/not available for the current license tier/g) ?? []).length, 11);
  assert.ok(source.includes("Aegis Protected Terminal is not available for the current license tier."));
  assert.ok(source.includes("Aegis AI Execution Gateway MVP-0 is not available for the current license tier."));
  assert.ok(source.includes("Aegis Review AI Command is not available for the current license tier."));
  assert.ok(source.includes("Aegis core protection is not available for the current license tier."));
  assert.ok(source.includes("Aegis Work Receipt is not available for the current license tier."));
  assert.ok(source.includes("Aegis trusted local verification is not available for the current license tier."));
});

test("extension license capability gates run before command handlers", () => {
  function assertGateBeforeHandler(commandMarker: string, gateMarker: string, handlerMarker: string): void {
    const commandIndex = indexOfRequired(commandMarker);
    const gateIndex = source.indexOf(gateMarker, commandIndex);
    const handlerIndex = source.indexOf(handlerMarker, commandIndex);
    assert.ok(gateIndex > commandIndex, `${gateMarker} should appear after ${commandMarker}`);
    assert.ok(handlerIndex > gateIndex, `${handlerMarker} should appear after ${gateMarker}`);
  }

  assertGateBeforeHandler('vscode.commands.registerCommand("aegis.protectedTerminal"', 'isCurrentLicenseCapabilityAvailable("protectedTerminal")', "await handleProtectedTerminalMvp0();");
  assertGateBeforeHandler('vscode.commands.registerCommand("aegis.aegisExecutionGatewayMvp0"', 'isCurrentLicenseCapabilityAvailable("aiExecutionGatewayMvp0")', "await handleAegisExecutionGatewayMvp0(");
  assertGateBeforeHandler('vscode.commands.registerCommand("aegis.reviewAiCommandOrAction"', 'isCurrentLicenseCapabilityAvailable("aiCommandReview")', "await handleReviewAiCommandOrAction();");
  assertGateBeforeHandler('vscode.commands.registerCommand("aegis.showProtectionPanel"', 'isCurrentLicenseCapabilityAvailable("coreProtection")', "withLicenseTier(_stateMgr.getState())");
  assertGateBeforeHandler('vscode.commands.registerCommand("aegis.phase1.restoreLastSafeState"', 'isCurrentLicenseCapabilityAvailable("coreProtection")', "await handleRestore();");
  assertGateBeforeHandler('vscode.commands.registerCommand("aegis.generateWorkReceipt"', 'isCurrentLicenseCapabilityAvailable("workReceipt")', "await handleGenerateReceipt();");
  assertGateBeforeHandler('vscode.commands.registerCommand("aegis.registerCleanBaseline"', 'isCurrentLicenseCapabilityAvailable("coreProtection")', "await handleRegisterCleanBaseline();");
});

test("extension initializes cached license tier before gated public commands", () => {
  const tierInitIndex = indexOfRequired("_licenseTier = await getLicenseTier();");

  assert.ok(indexOfRequired("export async function activate(context: vscode.ExtensionContext): Promise<void>") < tierInitIndex);
  assert.ok(tierInitIndex < indexOfRequired('vscode.commands.registerCommand("aegis.protectedTerminal"'));
  assert.ok(tierInitIndex < indexOfRequired('vscode.commands.registerCommand("aegis.aegisExecutionGatewayMvp0"'));
  assert.ok(tierInitIndex < indexOfRequired('vscode.commands.registerCommand("aegis.reviewAiCommandOrAction"'));
  assert.ok(tierInitIndex < indexOfRequired('vscode.commands.registerCommand("aegis.showProtectionPanel"'));
  assert.ok(tierInitIndex < indexOfRequired('vscode.commands.registerCommand("aegis.phase1.restoreLastSafeState"'));
  assert.ok(tierInitIndex < indexOfRequired('vscode.commands.registerCommand("aegis.generateWorkReceipt"'));
  assert.ok(tierInitIndex < indexOfRequired('vscode.commands.registerCommand("aegis.registerCleanBaseline"'));
});

test("extension defaults cached license tier to free when initialization fails", () => {
  const activateIndex = indexOfRequired("export async function activate(context: vscode.ExtensionContext): Promise<void>");
  const tierInitIndex = source.indexOf("_licenseTier = await getLicenseTier();", activateIndex);
  const fallbackWarningIndex = source.indexOf("[Aegis] license tier initialization failed; defaulting to free:", tierInitIndex);
  const freeFallbackIndex = source.indexOf('_licenseTier = "free";', fallbackWarningIndex);
  const firstGatedCommandIndex = source.indexOf('vscode.commands.registerCommand("aegis.protectedTerminal"', freeFallbackIndex);

  assert.ok(tierInitIndex > activateIndex);
  assert.ok(fallbackWarningIndex > tierInitIndex);
  assert.ok(freeFallbackIndex > fallbackWarningIndex);
  assert.ok(firstGatedCommandIndex > freeFallbackIndex);
});
test("extension showProtectionPanel keeps no-folder inactive panel before workspace license gate", () => {
  const panelCommandIndex = indexOfRequired('vscode.commands.registerCommand("aegis.showProtectionPanel"');
  const noFolderPanelIndex = source.indexOf("AegisWebviewPanel.show(", panelCommandIndex);
  const noFolderMessageIndex = source.indexOf('message: "Open a folder first to use Aegis."', panelCommandIndex);
  const gateIndex = source.indexOf('isCurrentLicenseCapabilityAvailable("coreProtection")', panelCommandIndex);
  const workspacePanelIndex = source.indexOf("withLicenseTier(_stateMgr.getState())", gateIndex);

  assert.ok(noFolderPanelIndex > panelCommandIndex);
  assert.ok(noFolderMessageIndex > noFolderPanelIndex);
  assert.ok(gateIndex > noFolderMessageIndex);
  assert.ok(workspacePanelIndex > gateIndex);
});

test("extension review command combines compliance before runtime controller review without direct mutation", () => {
  const handlerIndex = indexOfRequired("async function handleReviewAiCommandOrAction(): Promise<void>");
  const handlerEndIndex = indexOfRequired("function clearSafetyKernelV31WarnTimeout(sessionId: string): void");
  const initialGateIndex = source.indexOf("const initialGateResult = evaluateActionQuality(", handlerIndex);
  const complianceIndex = source.indexOf("const complianceResult =", initialGateIndex);
  const combineIndex = source.indexOf("combineReviewAiCommandMvp0WithActionQuality(", complianceIndex);
  const reviewIndex = source.indexOf("_safetyKernelV31RuntimeController.review(", combineIndex);
  const reviewBlock = source.slice(handlerIndex, handlerEndIndex);

  assert.ok(initialGateIndex > handlerIndex);
  assert.ok(complianceIndex > initialGateIndex);
  assert.ok(combineIndex > complianceIndex);
  assert.ok(reviewIndex > combineIndex);
  assert.equal(source.split("_safetyKernelV31RuntimeController.review(").length - 1, 2);
  assert.ok(source.includes('"NO_FOLDER_REVIEW_FALLBACK=True"'));
  assert.ok(source.includes('"REVIEW_RUNTIME_CONNECTED=True"'));
  assert.ok(source.includes('"EXECUTION_RUNTIME_CONNECTED=False"'));
  assert.ok(source.includes('"RAW_APPROVAL_NONCE_EXPOSED=False"'));
  assert.ok(source.includes('"AUTOMATIC_EXECUTION_ALLOWED=False"'));
  assert.ok(source.includes('"EXECUTION_AUTHORITY_GRANTED=False"'));
  assert.ok(!reviewBlock.includes("buildSafetyKernelV31DiagnosticInputBuilderResult("));
  assert.ok(!reviewBlock.includes("formatSafetyKernelV31DiagnosticOutput("));
  assert.ok(!reviewBlock.includes("_safetyKernelV31RuntimeController.confirmWarnSession("));
  assert.ok(!reviewBlock.includes("_safetyKernelV31RuntimeController.completeAllowedExecutionSession("));
  assert.ok(!reviewBlock.includes("_safetyKernelV31RuntimeController.terminateWarnSession("));
});
test("extension registers read-only Safety Kernel v3.1 session command", () => {
  const handlerIndex = indexOfRequired("async function handleReadSafetyKernelV31Session(): Promise<void>");
  const commandIndex = indexOfRequired('vscode.commands.registerCommand("aegis.readSafetyKernelV31Session"');
  const gateIndex = source.indexOf('isCurrentLicenseCapabilityAvailable("aiCommandReview")', commandIndex);
  const callIndex = source.indexOf("await handleReadSafetyKernelV31Session();", gateIndex);
  const readIndex = source.indexOf("_safetyKernelV31RuntimeController.readSession(sessionId)", handlerIndex);
  const initializeIndex = indexOfRequired("await initializeAegisOnce(context);");

  assert.ok(commandIndex < initializeIndex);
  assert.ok(gateIndex > commandIndex);
  assert.ok(callIndex > gateIndex);
  assert.ok(readIndex > handlerIndex);
  assert.equal(source.split('vscode.commands.registerCommand("aegis.readSafetyKernelV31Session"').length - 1, 1);
  assert.equal(source.split("_safetyKernelV31RuntimeController.readSession(").length - 1, 4);
  assert.ok(source.includes("48 lowercase hexadecimal characters"));
  assert.ok(source.includes('"RAW_APPROVAL_NONCE_EXPOSED=False"'));
  assert.ok(source.includes('"EXECUTION_RUNTIME_CONNECTED=False"'));
  assert.ok(source.includes('"AUTOMATIC_EXECUTION_ALLOWED=False"'));
  assert.ok(source.includes('"EXECUTION_AUTHORITY_GRANTED=False"'));
});

test("extension registers explicit WARN confirm and cancel session commands without execution completion authority", () => {
  const confirmHandlerIndex = indexOfRequired("async function handleConfirmSafetyKernelV31WarnSession(): Promise<void>");
  const cancelHandlerIndex = indexOfRequired("async function handleCancelSafetyKernelV31WarnSession(): Promise<void>");
  const confirmCommandIndex = indexOfRequired('vscode.commands.registerCommand("aegis.confirmSafetyKernelV31WarnSession"');
  const cancelCommandIndex = indexOfRequired('vscode.commands.registerCommand("aegis.cancelSafetyKernelV31WarnSession"');
  const initializeIndex = indexOfRequired("await initializeAegisOnce(context);");
  const confirmGateIndex = source.indexOf('isCurrentLicenseCapabilityAvailable("aiCommandReview")', confirmCommandIndex);
  const cancelGateIndex = source.indexOf('isCurrentLicenseCapabilityAvailable("aiCommandReview")', cancelCommandIndex);
  const confirmCallIndex = source.indexOf("await handleConfirmSafetyKernelV31WarnSession();", confirmGateIndex);
  const cancelCallIndex = source.indexOf("await handleCancelSafetyKernelV31WarnSession();", cancelGateIndex);
  const confirmReadIndex = source.indexOf("_safetyKernelV31RuntimeController.readSession(sessionId)", confirmHandlerIndex);
  const cancelReadIndex = source.indexOf("_safetyKernelV31RuntimeController.readSession(sessionId)", cancelHandlerIndex);
  const confirmIndex = source.indexOf("_safetyKernelV31RuntimeController.confirmWarnSession(sessionId)", confirmHandlerIndex);
  const terminateIndex = source.indexOf("_safetyKernelV31RuntimeController.terminateWarnSession(", cancelHandlerIndex);

  assert.ok(confirmCommandIndex < initializeIndex);
  assert.ok(cancelCommandIndex < initializeIndex);
  assert.ok(confirmGateIndex > confirmCommandIndex);
  assert.ok(cancelGateIndex > cancelCommandIndex);
  assert.ok(confirmCallIndex > confirmGateIndex);
  assert.ok(cancelCallIndex > cancelGateIndex);
  assert.ok(confirmReadIndex > confirmHandlerIndex);
  assert.ok(confirmIndex > confirmReadIndex);
  assert.ok(cancelReadIndex > cancelHandlerIndex);
  assert.ok(terminateIndex > cancelReadIndex);
  assert.equal(source.split('vscode.commands.registerCommand("aegis.confirmSafetyKernelV31WarnSession"').length - 1, 1);
  assert.equal(source.split('vscode.commands.registerCommand("aegis.cancelSafetyKernelV31WarnSession"').length - 1, 1);
  assert.equal(source.split("_safetyKernelV31RuntimeController.confirmWarnSession(").length - 1, 1);
  assert.equal(source.split("_safetyKernelV31RuntimeController.terminateWarnSession(").length - 1, 2);
  assert.equal(source.split('session.lifecyclePhase !== "WARN_PENDING"').length - 1, 3);
  assert.ok(source.includes('"cancel_by_user"'));
  assert.ok(source.includes('"SAFETY_KERNEL_V31_WARN_CONFIRMED=True"'));
  assert.ok(source.includes('"SAFETY_KERNEL_V31_WARN_CANCELLED=True"'));
  assert.ok(source.includes('"CONFIRMATION_EXECUTED_ACTION=False"'));
  assert.ok(source.includes('"CANCELLATION_EXECUTED_ACTION=False"'));
  assert.ok(!source.includes("_safetyKernelV31RuntimeController.completeAllowedExecutionSession("));
});

test("extension schedules evidence-first WARN timeout termination and clears timeout timers", () => {
  const timerMapIndex = indexOfRequired('const _safetyKernelV31WarnTimeoutTimers = new Map<string, ReturnType<typeof setTimeout>>();');
  const clearHelperIndex = indexOfRequired("function clearSafetyKernelV31WarnTimeout(sessionId: string): void");
  const scheduleHelperIndex = indexOfRequired("function scheduleSafetyKernelV31WarnTimeout(");
  const readHandlerIndex = indexOfRequired("async function handleReadSafetyKernelV31Session(): Promise<void>");
  const scheduleBlock = source.slice(scheduleHelperIndex, readHandlerIndex);
  const confirmHandlerIndex = indexOfRequired("async function handleConfirmSafetyKernelV31WarnSession(): Promise<void>");
  const cancelHandlerIndex = indexOfRequired("async function handleCancelSafetyKernelV31WarnSession(): Promise<void>");
  const confirmTransitionIndex = source.indexOf("_safetyKernelV31RuntimeController.confirmWarnSession(sessionId)", confirmHandlerIndex);
  const cancelTransitionIndex = source.indexOf("_safetyKernelV31RuntimeController.terminateWarnSession(", cancelHandlerIndex);
  const confirmClearIndex = source.indexOf("clearSafetyKernelV31WarnTimeout(sessionId);", confirmHandlerIndex);
  const cancelClearIndex = source.indexOf("clearSafetyKernelV31WarnTimeout(sessionId);", cancelHandlerIndex);
  const deactivateIndex = indexOfRequired("export async function deactivate(): Promise<void>");
  const deactivateTimerClearIndex = source.indexOf("_safetyKernelV31WarnTimeoutTimers.forEach(t => clearTimeout(t));", deactivateIndex);
  const deactivateMapClearIndex = source.indexOf("_safetyKernelV31WarnTimeoutTimers.clear();", deactivateIndex);

  assert.ok(clearHelperIndex > timerMapIndex);
  assert.ok(scheduleHelperIndex > clearHelperIndex);
  assert.ok(scheduleBlock.includes("_safetyKernelV31RuntimeController.readSession(sessionId)"));
  assert.ok(scheduleBlock.includes('session.lifecyclePhase !== "WARN_PENDING"'));
  assert.ok(scheduleBlock.includes("session.expiresAt !== expiresAt"));
  assert.ok(scheduleBlock.includes("Date.parse(expiresAt) - Date.now()"));
  assert.match(
    scheduleBlock,
    /_safetyKernelV31RuntimeController\.terminateWarnSession\(\s*sessionId,\s*"timeout_expired"\s*\)/
  );
  assert.equal(source.split("scheduleSafetyKernelV31WarnTimeout(runtimeResult.session);").length - 1, 2);
  assert.ok(confirmClearIndex > confirmTransitionIndex);
  assert.ok(cancelClearIndex > cancelTransitionIndex);
  assert.ok(deactivateTimerClearIndex > deactivateIndex);
  assert.ok(deactivateMapClearIndex > deactivateTimerClearIndex);
  assert.ok(!source.includes("_safetyKernelV31RuntimeController.completeAllowedExecutionSession("));
});

test("package exposes Safety Kernel session read, WARN confirm, and WARN cancel commands exactly once", () => {
  const packageJson = readFileSync(join(process.cwd(), "package.json"), "utf8");

  assert.equal(packageJson.split('"onCommand:aegis.readSafetyKernelV31Session"').length - 1, 1);
  assert.equal(packageJson.split('"command":  "aegis.readSafetyKernelV31Session"').length - 1, 1);
  assert.equal(packageJson.split('"title":  "Aegis: Read Safety Kernel v3.1 Session"').length - 1, 1);
  assert.equal(packageJson.split('"onCommand:aegis.confirmSafetyKernelV31WarnSession"').length - 1, 1);
  assert.equal(packageJson.split('"command":  "aegis.confirmSafetyKernelV31WarnSession"').length - 1, 1);
  assert.equal(packageJson.split('"title":  "Aegis: Confirm Safety Kernel v3.1 WARN Session"').length - 1, 1);
  assert.equal(packageJson.split('"onCommand:aegis.cancelSafetyKernelV31WarnSession"').length - 1, 1);
  assert.equal(packageJson.split('"command":  "aegis.cancelSafetyKernelV31WarnSession"').length - 1, 1);
  assert.equal(packageJson.split('"title":  "Aegis: Cancel Safety Kernel v3.1 WARN Session"').length - 1, 1);
});

test("AI Gateway delegates to runtime controller review only without execution authority", () => {
  const handlerIndex = indexOfRequired("async function handleAegisExecutionGatewayMvp0(rawEnvelope?: string): Promise<void>");
  const actionQualityIndex = source.indexOf("evaluateAiExecutionGatewayMvp0ActionQuality(proposed);", handlerIndex);
  const gateIndex = source.indexOf("enforceAiExecutionGatewayMvp0EffectPreflight(", actionQualityIndex);
  const guardIndex = source.indexOf("if (_safetyKernelV31RuntimeController) {", gateIndex);
  const reviewIndex = source.indexOf("_safetyKernelV31RuntimeController.review(", guardIndex);
  const adapterIndex = source.indexOf('adapter_id: "aegis-ai-execution-gateway-mvp0-runtime-controller"', reviewIndex);
  const receiptIndex = source.indexOf("runtimeControllerReviewConnected: gatewayRuntimeControllerReviewConnected", adapterIndex);
  const finalInfoIndex = source.indexOf("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed.", receiptIndex);
  const gatewayBlock = source.slice(handlerIndex, finalInfoIndex);
  assert.ok(actionQualityIndex > handlerIndex);
  assert.ok(gateIndex > actionQualityIndex);
  assert.ok(guardIndex > gateIndex);
  assert.ok(reviewIndex > guardIndex);
  assert.ok(adapterIndex > reviewIndex);
  assert.ok(receiptIndex > adapterIndex);
  assert.ok(finalInfoIndex > receiptIndex);
  assert.equal(source.split("_safetyKernelV31RuntimeController.review(").length - 1, 2);
  assert.equal(source.split("aegis-ai-execution-gateway-mvp0-runtime-controller").length - 1, 1);
  assert.ok(gatewayBlock.includes("gatewayRuntimeControllerClipboardSummary = runtimeResult.output.clipboardSummary"));
  assert.ok(gatewayBlock.includes("gatewayRuntimeSessionId = runtimeResult.session?.sessionId ??"));
  assert.ok(!gatewayBlock.includes("_safetyKernelV31RuntimeController.confirmWarnSession("));
  assert.ok(!gatewayBlock.includes("_safetyKernelV31RuntimeController.completeAllowedExecutionSession("));
  assert.ok(!gatewayBlock.includes("_safetyKernelV31RuntimeController.terminateWarnSession("));
  assert.ok(!gatewayBlock.includes("EXECUTION_AUTHORITY_GRANTED=True"));
});

test("extension connects A2r readers and A2p Node process bootstrap after canonical authority hydration or creation", () => {
  const storeIndex = indexOfRequired("_stores      = new Map<string, SnapshotStore>();");
  const persistenceIndex = source.indexOf(
    "_canonicalAuthorityPersistence =",
    storeIndex
  );
  const loadIndex = source.indexOf(
    "const persistedCanonicalAuthority =",
    persistenceIndex
  );
  const createIndex = source.indexOf(
    "CanonicalAuthorityStateStore.create({",
    loadIndex
  );
  const readersIndex = source.indexOf(
    "createSafetyKernelV31SnapshotTargetIndexReaderCollection({",
    createIndex
  );
  const bootstrapIndex = source.indexOf(
    "createSafetyKernelV31NodeProcessExtensionBootstrapComposition({",
    readersIndex
  );
  const runtimeAssignmentIndex = source.indexOf(
    "_safetyKernelV31RuntimeController =",
    bootstrapIndex
  );

  assert.ok(persistenceIndex > storeIndex);
  assert.ok(loadIndex > persistenceIndex);
  assert.ok(createIndex > loadIndex);
  assert.ok(readersIndex > createIndex);
  assert.ok(bootstrapIndex > readersIndex);
  assert.ok(runtimeAssignmentIndex > bootstrapIndex);
  assert.ok(source.includes('import { spawnNodeProcess } from "./nodeProcessExecutionAdapter";'));
  assert.ok(source.includes("nodeProcessSpawner: spawnNodeProcess"));
  assert.ok(source.includes(".nodeProcessExtensionComposition"));
  assert.ok(source.includes(".extensionComposition"));
  assert.ok(source.includes(".runtimeController"));
  assert.equal(
    (source.match(/SafetyKernelV31RuntimeController\.createForAegisDir\(aegisDir\)/g) ?? []).length,
    0
  );
});

test("trusted local verification command remains isolated and fail-closed", () => {
  const packageJson = require("node:fs").readFileSync(
    require("node:path").join(__dirname, "..", "package.json"),
    "utf8"
  );

  const commandIndex = indexOfRequired(
    'vscode.commands.registerCommand("aegis.runTrustedLocalVerification"'
  );

  const initializeIndex = indexOfRequired(
    "await initializeAegisOnce(context);"
  );

  assert.ok(commandIndex < initializeIndex);

  assert.equal(
    source.split(
      'vscode.commands.registerCommand("aegis.runTrustedLocalVerification"'
    ).length - 1,
    1
  );

  assert.equal(
    packageJson.split(
      '"onCommand:aegis.runTrustedLocalVerification"'
    ).length - 1,
    1
  );

  assert.equal(
    packageJson.split(
      '"command":  "aegis.runTrustedLocalVerification"'
    ).length - 1,
    1
  );

  assert.ok(
    source.includes(
      "TRUSTED_VERIFICATION_REFUSED_NON_ISOLATED_WORKSPACE"
    )
  );

  assert.ok(
    source.includes(
      "TRUSTED_VERIFICATION_REQUIRES_FRESH_ISOLATED_WORKSPACE"
    )
  );

  assert.ok(
    source.includes(
      "TRUSTED_VERIFICATION_RESTORE_ROUND_TRIP_FAILED"
    )
  );

  assert.ok(
    source.includes(
      "EMERGENCY_RESTORE_ATTEMPTED=True"
    )
  );
});

test("extension marker-loss registration verifies the new baseline before clearing blocked state", () => {
  const handleStart = source.indexOf("async function handleDidSave(");
  const handleEnd = source.indexOf(
    "async function recreateBaselineSnapshotAfterMarkerLossOrNull(",
    handleStart
  );

  assert.ok(handleStart >= 0);
  assert.ok(handleEnd > handleStart);

  const block = source.slice(handleStart, handleEnd);

  function requiredIndex(text: string): number {
    const index = block.indexOf(text);
    assert.notEqual(index, -1, text);
    return index;
  }

  const markerWriteIndex = requiredIndex(
    "const markerWritten = await writeBaselineMarker(aegisDir, target.marker_file, relPath);"
  );
  const markerFailureIndex = requiredIndex("if (!markerWritten) {");
  const markerFailureReturnIndex = block.indexOf("return;", markerFailureIndex);

  const verificationReadIndex = requiredIndex(
    "const verifiedRegistrationIndex = await readSnapshotIndexOrNull("
  );
  const expectedHashIndex = requiredIndex(
    "const expectedRegistrationHash = sha256OfString(postSaveContent);"
  );
  const baselineHashCheckIndex = requiredIndex(
    "verifiedRegistrationIndex.baseline_content_sha256 !== expectedRegistrationHash"
  );
  const rollingHashCheckIndex = requiredIndex(
    "verifiedRegistrationIndex.content_sha256 !== expectedRegistrationHash"
  );
  const verificationFailureReturnIndex = block.indexOf(
    "return;",
    rollingHashCheckIndex
  );
  const safeIndex = requiredIndex(
    'stateMgr.setSafe("Aegis is protecting this workspace.");'
  );
  const informationIndex = block.indexOf(
    "showInformationMessageBestEffort(",
    safeIndex
  );
  const successReturnIndex = block.indexOf("return;", informationIndex);

  assert.ok(markerWriteIndex < markerFailureIndex);
  assert.ok(markerFailureIndex < markerFailureReturnIndex);
  assert.ok(markerFailureReturnIndex < verificationReadIndex);
  assert.ok(verificationReadIndex < expectedHashIndex);
  assert.ok(expectedHashIndex < baselineHashCheckIndex);
  assert.ok(baselineHashCheckIndex < rollingHashCheckIndex);
  assert.ok(rollingHashCheckIndex < verificationFailureReturnIndex);
  assert.ok(verificationFailureReturnIndex < safeIndex);
  assert.ok(safeIndex < informationIndex);
  assert.ok(informationIndex < successReturnIndex);

  assert.ok(
    block.includes(
      "snapshotHash:   verifiedRegistrationIndex.content_sha256"
    )
  );
});

// E-P0-4-ACTIVITY-MARKER-RECOVERY-REGRESSION
async function readExtensionSourceForActivityMarkerRecovery(): Promise<string> {
  const fs = await import("fs/promises");
  const nodePath = await import("path");

  return await fs.readFile(
    nodePath.join(process.cwd(), "src", "extension.ts"),
    "utf8"
  );
}

test("automatic registration initializes a missing activity marker before SAFE", async () => {
  const source = await readExtensionSourceForActivityMarkerRecovery();
  const branchStart = source.indexOf(
    "if (isFirstRegistration || isMarkerLossReregistration) {"
  );
  const initIndex = source.indexOf(
    "await initActivityMarker(aegisDir);",
    branchStart
  );
  const safeIndex = source.indexOf(
    '"Aegis is protecting this workspace."',
    branchStart
  );

  assert.ok(branchStart >= 0);
  assert.ok(initIndex > branchStart);
  assert.ok(safeIndex > initIndex);
});

test("marker-loss re-registration uses the activity marker recovery branch", async () => {
  const source = await readExtensionSourceForActivityMarkerRecovery();
  const classificationIndex = source.indexOf(
    "const isMarkerLossReregistration = !markerRegistered && indexHasBaseline;"
  );
  const sharedBranchIndex = source.indexOf(
    "if (isFirstRegistration || isMarkerLossReregistration) {"
  );
  const initIndex = source.indexOf(
    "await initActivityMarker(aegisDir);",
    sharedBranchIndex
  );

  assert.ok(classificationIndex >= 0);
  assert.ok(sharedBranchIndex > classificationIndex);
  assert.ok(initIndex > sharedBranchIndex);
});

test("automatic registration preserves an existing activity marker", async () => {
  const source = await readExtensionSourceForActivityMarkerRecovery();
  const branchStart = source.indexOf(
    "if (isFirstRegistration || isMarkerLossReregistration) {"
  );
  const pathIndex = source.indexOf(
    "automaticRegistrationActivityMarkerPath",
    branchStart
  );
  const accessIndex = source.indexOf(
    "await fs.promises.access(automaticRegistrationActivityMarkerPath);",
    pathIndex
  );
  const missingGateIndex = source.indexOf(
    "if (automaticRegistrationActivityMarkerMissing) {",
    accessIndex
  );
  const initIndex = source.indexOf(
    "await initActivityMarker(aegisDir);",
    missingGateIndex
  );

  assert.ok(pathIndex > branchStart);
  assert.ok(accessIndex > pathIndex);
  assert.ok(missingGateIndex > accessIndex);
  assert.ok(initIndex > missingGateIndex);
});

test("activity marker creation failure warns and prevents SAFE", async () => {
  const source = await readExtensionSourceForActivityMarkerRecovery();
  const branchStart = source.indexOf(
    "if (isFirstRegistration || isMarkerLossReregistration) {"
  );
  const warningIndex = source.indexOf(
    "baseline registered, but activity marker could not be written.",
    branchStart
  );
  const returnIndex = source.indexOf("return;", warningIndex);
  const safeIndex = source.indexOf(
    '"Aegis is protecting this workspace."',
    branchStart
  );

  assert.ok(warningIndex > branchStart);
  assert.ok(returnIndex > warningIndex);
  assert.ok(safeIndex > returnIndex);
});
// I_P0_1_WORKSPACE_TRUST_STATIC_TESTS_BEGIN
const iP01WorkspaceTrustPackage = JSON.parse(
  readFileSync(join(process.cwd(), "package.json"), "utf8")
);

test("I-P0-1 manifest declares limited untrusted workspace support", () => {
  assert.equal(
    iP01WorkspaceTrustPackage.capabilities?.untrustedWorkspaces?.supported,
    "limited"
  );

  assert.equal(
    iP01WorkspaceTrustPackage.capabilities?.untrustedWorkspaces?.description,
    "Aegis remains active in Restricted Mode but blocks all Aegis operations until the workspace is trusted."
  );
});

test("I-P0-1 all public command callbacks begin with the shared workspace trust guard", () => {
  const commandIds = [
    "aegis.protectedTerminal",
    "aegis.aegisExecutionGatewayMvp0",
    "aegis.runTrustedLocalVerification",
    "aegis.reviewAiCommandOrAction",
    "aegis.readSafetyKernelV31Session",
    "aegis.confirmSafetyKernelV31WarnSession",
    "aegis.cancelSafetyKernelV31WarnSession",
    "aegis.showProtectionPanel",
    "aegis.phase1.status",
    "aegis.phase1.restoreLastSafeState",
    "aegis.generateWorkReceipt",
    "aegis.registerCleanBaseline",
  ];

  const guard =
    "if (!ensureAegisWorkspaceTrustedForCommand()) { return; }";

  for (let index = 0; index < commandIds.length; index += 1) {
    const commandAnchor =
      `vscode.commands.registerCommand("${commandIds[index]}"`;

    const commandStart = source.indexOf(commandAnchor);
    assert.ok(commandStart >= 0, commandAnchor);

    const commandEnd =
      index + 1 < commandIds.length
        ? source.indexOf(
            `vscode.commands.registerCommand("${commandIds[index + 1]}"`,
            commandStart + commandAnchor.length
          )
        : source.indexOf(
            "const trustGrantDisposable",
            commandStart + commandAnchor.length
          );

    assert.ok(commandEnd > commandStart, commandIds[index]);

    const commandBlock = source.slice(commandStart, commandEnd);
    const arrowIndex = commandBlock.indexOf("=>");
    const guardIndex = commandBlock.indexOf(guard);

    assert.ok(arrowIndex >= 0, commandIds[index]);
    assert.ok(guardIndex > arrowIndex, commandIds[index]);

    assert.ok(
      guardIndex - arrowIndex < 180,
      `${commandIds[index]} trust guard must be the first callback action`
    );
  }

  assert.equal(source.split(guard).length - 1, 12);
});

test("I-P0-1 activation and initialization use serialized workspace trust gates", () => {
  assert.ok(
    source.includes(
      "const I_P0_1_WORKSPACE_TRUST_RESTRICTED_MODE_WARNING ="
    )
  );

  assert.ok(
    source.includes(
      "return vscode.workspace.isTrusted !== false;"
    )
  );

  assert.ok(
    source.includes(
      "let _workspaceTrustInitializationPromise: Promise<void> | null = null;"
    )
  );

  assert.ok(
    source.includes(
      "vscode.workspace.onDidGrantWorkspaceTrust?.(() =>"
    )
  );

  assert.ok(
    source.includes(
      "await initializeAegisOnce(context);"
    )
  );

  const initializeStart = source.indexOf(
    "async function initializeAegis(context: vscode.ExtensionContext): Promise<void> {"
  );

  const trustIndex = source.indexOf(
    "if (!isAegisWorkspaceTrusted()) {",
    initializeStart
  );

  const initializedIndex = source.indexOf(
    "if (_initialized) {",
    initializeStart
  );

  const foldersIndex = source.indexOf(
    "const folders = vscode.workspace.workspaceFolders;",
    initializeStart
  );

  assert.ok(initializeStart >= 0);
  assert.ok(trustIndex > initializeStart);
  assert.ok(initializedIndex > trustIndex);
  assert.ok(foldersIndex > initializedIndex);
});
// I_P0_1_WORKSPACE_TRUST_STATIC_TESTS_END

test("C-09 extension loads or creates the canonical authority snapshot before verifier readers", () => {
  assert.ok(
    source.includes(
      'import { CanonicalAuthorityStateFilePersistence } from "./canonicalAuthorityStateFilePersistence";'
    )
  );

  assert.ok(
    source.includes(
      '"canonical-authority-state.json"'
    )
  );

  assert.ok(
    source.includes(
      "await _canonicalAuthorityPersistence"
    )
  );

  assert.ok(
    source.includes(
      ".load();"
    )
  );

  assert.ok(
    source.includes(
      "CANONICAL_AUTHORITY_WORKSPACE_BINDING_MISMATCH"
    )
  );

  const pathIndex =
    indexOfRequired(
      "const canonicalAuthoritySnapshotPath ="
    );

  const loadIndex =
    indexOfRequired(
      "const persistedCanonicalAuthority ="
    );

  const readersIndex =
    indexOfRequired(
      "createSafetyKernelV31SnapshotTargetIndexReaderCollection({"
    );

  assert.ok(pathIndex < loadIndex);
  assert.ok(loadIndex < readersIndex);
});

test("C-09 extension persists every canonical authority mutation path", () => {
  const persistenceReasons = [
    "safety-kernel-sync",
    "ai-action-update",
    "visible-state-sync",
    "artifact-id-update",
    "artifact-id-rollback",
  ];

  for (
    const reason of
    persistenceReasons
  ) {
    const reasonPattern =
      new RegExp(
        "queueCanonicalAuthorityPersistence\\(\\s*\"" +
          reason +
          "\"",
        "g"
      );

    assert.equal(
      (
        source.match(
          reasonPattern
        ) ?? []
      ).length,
      1,
      reason
    );
  }

  assert.equal(
    source.split(
      "queueCanonicalAuthorityPersistence("
    ).length - 1,
    6
  );
});

test("C-09 canonical authority persistence uses a serialized detached snapshot queue and fail-closed warning", () => {
  assert.ok(
    source.includes(
      "let _canonicalAuthorityPersistenceQueue: Promise<void> = Promise.resolve();"
    )
  );

  assert.ok(
    source.includes(
      "store.serializeSnapshotEnvelope()"
    )
  );

  assert.ok(
    source.includes(
      ".hydrateSnapshotJson("
    )
  );

  assert.ok(
    source.includes(
      "_canonicalAuthorityPersistenceQueue\n      .then(() =>"
    )
  );

  assert.ok(
    source.includes(
      "Aegis could not persist canonical authority state."
    )
  );

  assert.ok(
    source.includes(
      "Authority continuity cannot be confirmed."
    )
  );
});

test("C-09 extension deactivation drains the stable persistence queue tail before clearing canonical globals", () => {
  const deactivateIndex =
    indexOfRequired(
      "export async function deactivate(): Promise<void>"
    );

  const loopIndex =
    source.indexOf(
      "while (true) {",
      deactivateIndex
    );

  const captureIndex =
    source.indexOf(
      "const pendingPersistence =",
      loopIndex
    );

  const queueCaptureIndex =
    source.indexOf(
      "_canonicalAuthorityPersistenceQueue;",
      captureIndex
    );

  const awaitIndex =
    source.indexOf(
      "await pendingPersistence;",
      queueCaptureIndex
    );

  const stableComparisonIndex =
    source.indexOf(
      "pendingPersistence ===",
      awaitIndex
    );

  const currentQueueIndex =
    source.indexOf(
      "_canonicalAuthorityPersistenceQueue",
      stableComparisonIndex
    );

  const breakIndex =
    source.indexOf(
      "break;",
      currentQueueIndex
    );

  const persistenceClearIndex =
    source.indexOf(
      "_canonicalAuthorityPersistence = null;",
      breakIndex
    );

  const queueResetIndex =
    source.indexOf(
      "_canonicalAuthorityPersistenceQueue = Promise.resolve();",
      persistenceClearIndex
    );

  const stateClearIndex =
    source.indexOf(
      "_canonicalAuthorityState = null;",
      queueResetIndex
    );

  assert.ok(loopIndex > deactivateIndex);
  assert.ok(captureIndex > loopIndex);
  assert.ok(queueCaptureIndex > captureIndex);
  assert.ok(awaitIndex > queueCaptureIndex);
  assert.ok(stableComparisonIndex > awaitIndex);
  assert.ok(currentQueueIndex > stableComparisonIndex);
  assert.ok(breakIndex > currentQueueIndex);
  assert.ok(persistenceClearIndex > breakIndex);
  assert.ok(queueResetIndex > persistenceClearIndex);
  assert.ok(stateClearIndex > queueResetIndex);
});

// C10-A4B2B4 EXTENSION SERVER RULESET CONNECTION TESTS BEGIN

test("C10-A4B2B4 imports production server ruleset factories exactly once and resolves the extension root safely", () => {
  assert.equal(
    source.split(
      'from "./serverRulesetExtensionProductionSupplyAdapter"'
    ).length - 1,
    1
  );

  assert.equal(
    source.split(
      'from "./serverRulesetExtensionProductionComposition"'
    ).length - 1,
    1
  );

  const rootResolverIndex =
    indexOfRequired(
      "function resolveServerRulesetExtensionRoot("
    );

  const extensionUriIndex =
    source.indexOf(
      "context.extensionUri?.fsPath",
      rootResolverIndex
    );

  const extensionPathIndex =
    source.indexOf(
      "context.extensionPath",
      extensionUriIndex
    );

  const packageRootFallbackIndex =
    source.indexOf(
      'nodePath.resolve(\n    __dirname,\n    ".."\n  )',
      extensionPathIndex
    );

  assert.ok(
    extensionUriIndex >
      rootResolverIndex
  );

  assert.ok(
    extensionPathIndex >
      extensionUriIndex
  );

  assert.ok(
    packageRootFallbackIndex >
      extensionPathIndex
  );
});

test("C10-A4B2B4 maps license tiers and initializes the production server ruleset connection before initialized state", () => {
  const channelFunctionIndex =
    indexOfRequired(
      "function serverRulesetDistributionChannelForLicenseTier("
    );

  const proIndex =
    source.indexOf(
      'tier === "pro"',
      channelFunctionIndex
    );

  const strictIndex =
    source.indexOf(
      '"fast-strict"',
      proIndex
    );

  const stableIndex =
    source.indexOf(
      '"free-stable"',
      strictIndex
    );

  assert.ok(
    proIndex >
      channelFunctionIndex
  );

  assert.ok(
    strictIndex >
      proIndex
  );

  assert.ok(
    stableIndex >
      strictIndex
  );

  const initializeAegisIndex =
    indexOfRequired(
      "async function initializeAegis(context: vscode.ExtensionContext): Promise<void> {"
    );

  const projectRootIndex =
    source.indexOf(
      "_projectRoot = projectRoot;",
      initializeAegisIndex
    );

  const connectionIndex =
    source.indexOf(
      "await initializeServerRulesetProductionConnection(context, projectRoot);",
      projectRootIndex
    );

  const initializedIndex =
    source.indexOf(
      "_initialized = true;",
      connectionIndex
    );

  assert.ok(
    projectRootIndex >
      initializeAegisIndex
  );

  assert.ok(
    connectionIndex >
      projectRootIndex
  );

  assert.ok(
    initializedIndex >
      connectionIndex
  );

  const connectionInitializerIndex =
    indexOfRequired(
      "async function initializeServerRulesetProductionConnection("
    );

  const disabledIndex =
    source.indexOf(
      'adapter.status ===\n      "DISABLED"',
      connectionInitializerIndex
    );

  const rejectedIndex =
    source.indexOf(
      'adapter.status ===\n      "REJECTED"',
      disabledIndex
    );

  const compositionIndex =
    source.indexOf(
      "createServerRulesetExtensionProductionComposition(",
      rejectedIndex
    );

  assert.ok(
    disabledIndex >
      connectionInitializerIndex
  );

  assert.ok(
    rejectedIndex >
      disabledIndex
  );

  assert.ok(
    compositionIndex >
      rejectedIndex
  );
});

test("C10-A4B2B4 inserts the production server ruleset gate after workspace rules and before workflow drift and runtime review", () => {
  const handlerIndex =
    indexOfRequired(
      "async function handleAegisExecutionGatewayMvp0(rawEnvelope?: string): Promise<void>"
    );

  const userRuleIndex =
    source.indexOf(
      "evaluateAiExecutionGatewayMvp0UserDefinedRules(proposed, userRuleSet);",
      handlerIndex
    );

  const disabledGateIndex =
    source.indexOf(
      '_serverRulesetProductionAdapterStatus ===\n    "DISABLED"',
      userRuleIndex
    );

  const rejectedGateIndex =
    source.indexOf(
      '_serverRulesetProductionAdapterStatus ===\n    "REJECTED"',
      disabledGateIndex
    );

  const productionEvaluationIndex =
    source.indexOf(
      ".evaluate(\n            proposed",
      rejectedGateIndex
    );

  const productionDecisionIndex =
    source.indexOf(
      "serverRulesetResult.blocked ||",
      productionEvaluationIndex
    );

  const workflowDriftIndex =
    source.indexOf(
      "detectAiExecutionGatewayMvp0WorkflowDrift(proposed);",
      productionDecisionIndex
    );

  const actionQualityIndex =
    source.indexOf(
      "evaluateAiExecutionGatewayMvp0ActionQuality(proposed);",
      workflowDriftIndex
    );

  const runtimeReviewIndex =
    source.indexOf(
      "_safetyKernelV31RuntimeController.review(",
      actionQualityIndex
    );

  assert.ok(
    userRuleIndex >
      handlerIndex
  );

  assert.ok(
    disabledGateIndex >
      userRuleIndex
  );

  assert.ok(
    rejectedGateIndex >
      disabledGateIndex
  );

  assert.ok(
    productionEvaluationIndex >
      rejectedGateIndex
  );

  assert.ok(
    productionDecisionIndex >
      productionEvaluationIndex
  );

  assert.ok(
    workflowDriftIndex >
      productionDecisionIndex
  );

  assert.ok(
    actionQualityIndex >
      workflowDriftIndex
  );

  assert.ok(
    runtimeReviewIndex >
      actionQualityIndex
  );

  const connectionBlock =
    source.slice(
      disabledGateIndex,
      workflowDriftIndex
    );

  assert.match(
    connectionBlock,
    /writeServerRulesetProductionBlockedReceipt/
  );

  assert.match(
    connectionBlock,
    /SERVER_RULESET_SUPPLY_ISSUE=/
  );

  assert.match(
    connectionBlock,
    /return;/
  );

  assert.doesNotMatch(
    connectionBlock,
    /\b(?:spawnNodeProcess|completeAllowedExecutionSession|coordinateAllowedExecutionSession|bindAllowedExecutionSessionAuthority)\b/
  );
});

test("C10-A4B2B4 fails closed on production connection errors and resets all production server ruleset state during deactivation", () => {
  const initializerIndex =
    indexOfRequired(
      "async function initializeServerRulesetProductionConnection("
    );

  const blockedReceiptBuilderIndex =
    source.indexOf(
      "function buildServerRulesetProductionConnectionBlockedReceiptLines(",
      initializerIndex
    );

  const initializerBlock =
    source.slice(
      initializerIndex,
      blockedReceiptBuilderIndex
    );

  assert.match(
    initializerBlock,
    /_serverRulesetProductionAdapterStatus\s*=\s*\n\s*"REJECTED"/
  );

  assert.match(
    initializerBlock,
    /_serverRulesetProductionAdapterIssue\s*=\s*\n\s*"DEPENDENCIES_INVALID"/
  );

  assert.match(
    initializerBlock,
    /_serverRulesetProductionAdapterIssue\s*=\s*\n\s*"PERSISTENCE_INITIALIZATION_FAILED"/
  );

  const deactivateIndex =
    indexOfRequired(
      "export async function deactivate(): Promise<void>"
    );

  const resetIndex =
    source.indexOf(
      "resetServerRulesetProductionConnection();",
      deactivateIndex
    );

  const stateDisposeIndex =
    source.indexOf(
      "_stateMgr?.dispose();",
      resetIndex
    );

  assert.ok(
    resetIndex >
      deactivateIndex
  );

  assert.ok(
    stateDisposeIndex >
      resetIndex
  );

  const resetFunctionIndex =
    indexOfRequired(
      "function resetServerRulesetProductionConnection(): void"
    );

  const resetFunctionEnd =
    source.indexOf(
      "async function initializeServerRulesetProductionConnection(",
      resetFunctionIndex
    );

  const resetBlock =
    source.slice(
      resetFunctionIndex,
      resetFunctionEnd
    );

  assert.match(
    resetBlock,
    /_serverRulesetProductionComposition\s*=\s*\n\s*null/
  );

  assert.match(
    resetBlock,
    /_serverRulesetProductionAdapterStatus\s*=\s*\n\s*"DISABLED"/
  );

  assert.match(
    resetBlock,
    /_serverRulesetProductionAdapterIssue\s*=\s*\n\s*"CANONICAL_TRUST_MATERIAL_ABSENT"/
  );

  assert.match(
    resetBlock,
    /_serverRulesetExtensionRoot\s*=\s*\n\s*null/
  );
});

// C10-A4B2B4 EXTENSION SERVER RULESET CONNECTION TESTS END
