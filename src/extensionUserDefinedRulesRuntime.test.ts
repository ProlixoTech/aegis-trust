import test from "node:test";
import assert from "node:assert/strict";
import Module from "node:module";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("extension Gateway MVP-0 loads and enforces workspace user-defined rules at runtime", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  let reviewCalls = 0;
  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("user-defined rule gate did not block runtime review");
    },
  };
  const root = mkdtempSync(join(tmpdir(), "aegis-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Remove-Item ./protected-file",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: blocked by a user-defined workspace rule.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /USER_DEFINED_RULE_GATE_ENFORCED=True/);
    assert.match(clipboardText, /USER_DEFINED_RULE_BLOCKED=True/);
    assert.match(clipboardText, /USER_DEFINED_RULE_SET_ID=owner-rules/);
    assert.match(clipboardText, /USER_DEFINED_RULE_MATCH=Remove-Item/);
    assert.match(clipboardText, /EXECUTION_NOT_PERFORMED=True/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 returns early without side effects for cancelled or whitespace AI action envelope input", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  let reviewCalls = 0;
  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("user-defined rule gate did not block runtime review");
    },
  };
  const root = mkdtempSync(join(tmpdir(), "aegis-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const inputValues: Array<string | undefined> = [undefined, " \t\r\n "];

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string | undefined> => inputValues.shift(),
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    const warningsBefore = warnings.length;
    const infosBefore = infos.length;
    const timersBefore = scheduledTimers.length;
    const clipboardBefore = clipboardText;
    await callback();
    await callback();
    assert.equal(inputValues.length, 0);
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, timersBefore);
    assert.equal(warnings.length, warningsBefore);
    assert.equal(infos.length, infosBefore);
    assert.equal(clipboardText, clipboardBefore);

  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 blocks missing proposed command before runtime review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  let reviewCalls = 0;
  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("user-defined rule gate did not block runtime review");
    },
  };
  const root = mkdtempSync(join(tmpdir(), "aegis-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: invalid AI action envelope blocked.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /ENVELOPE_VALID=False/);
    assert.match(clipboardText, /ENVELOPE_ERROR=MISSING_PROPOSED_COMMAND/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 blocks blank proposedCommand without alias fallback before runtime review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  let reviewCalls = 0;
  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("user-defined rule gate did not block runtime review");
    },
  };
  const root = mkdtempSync(join(tmpdir(), "aegis-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "   ", command: "Get-Content package.json", action: "Get-Content README.md" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: invalid AI action envelope blocked.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /ENVELOPE_VALID=False/);
    assert.match(clipboardText, /ENVELOPE_ERROR=MISSING_PROPOSED_COMMAND/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 blocks missing AI connector source before runtime review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  let reviewCalls = 0;
  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("user-defined rule gate did not block runtime review");
    },
  };
  const root = mkdtempSync(join(tmpdir(), "aegis-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({ intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "Get-Content package.json" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: invalid AI action envelope blocked.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /ENVELOPE_VALID=False/);
    assert.match(clipboardText, /ENVELOPE_ERROR=INVALID_OR_MISSING_SOURCE/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 blocks invalid JSON AI action envelope before runtime review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  let reviewCalls = 0;
  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("user-defined rule gate did not block runtime review");
    },
  };
  const root = mkdtempSync(join(tmpdir(), "aegis-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = "{";

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: invalid AI action envelope blocked.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /ENVELOPE_VALID=False/);
    assert.match(clipboardText, /ENVELOPE_ERROR=INVALID_JSON_ENVELOPE/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects unsupported workspace user-defined rule schema before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-invalid-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "Get-Content package.json" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({ capsuleSchemaVersion: "1.0.0", capsuleKind: "HANDOFF_RESUME", firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1", firstCommandHash: "test-command-hash", knownPreconditions: [], forbiddenFirstActions: [], capabilityManifestVersion: "0.1.0-mvp0", policyVersion: "safety-kernel-v3.1-local-client-mvp0", approvalNonceRequired: true, receiptRequired: true }), "utf8");
  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({ schemaVersion: 2, ruleSetId: "owner-rules", blockedCommandSubstrings: [] }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }
  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }
  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }
  class ReceiptWriter { async ensureDirs(): Promise<void> {} }
  const runtimeController = { review: async () => { reviewCalls++; throw new Error("unexpected review call"); } };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: { workspaceFolders: [{ uri: { fsPath: root } }], onWillSaveTextDocument: () => disposable, onDidSaveTextDocument: () => disposable, createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }) },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: user-defined rule set is invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_GATE_ENFORCED=True/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_SET_VALID=False/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_ERROR=UNSUPPORTED_SCHEMA_VERSION/);
    assert.match(clipboardWrites[0] ?? "", /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardWrites[0] ?? "", /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects invalid JSON workspace user-defined rule set before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-invalid-json-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "Get-Content package.json" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({ capsuleSchemaVersion: "1.0.0", capsuleKind: "HANDOFF_RESUME", firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1", firstCommandHash: "test-command-hash", knownPreconditions: [], forbiddenFirstActions: [], capabilityManifestVersion: "0.1.0-mvp0", policyVersion: "safety-kernel-v3.1-local-client-mvp0", approvalNonceRequired: true, receiptRequired: true }), "utf8");
  writeFileSync(join(root, "AEGIS-USER-RULES.json"), "{", "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }
  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }
  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }
  class ReceiptWriter { async ensureDirs(): Promise<void> {} }
  const runtimeController = { review: async () => { reviewCalls++; throw new Error("unexpected review call"); } };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: { workspaceFolders: [{ uri: { fsPath: root } }], onWillSaveTextDocument: () => disposable, onDidSaveTextDocument: () => disposable, createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }) },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: user-defined rule set is invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_GATE_ENFORCED=True/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_SET_VALID=False/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_ERROR=INVALID_JSON_USER_RULE_SET/);
    assert.match(clipboardWrites[0] ?? "", /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardWrites[0] ?? "", /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects invalid blocked workspace user-defined rule before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-invalid-blocked-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "Get-Content package.json" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({ capsuleSchemaVersion: "1.0.0", capsuleKind: "HANDOFF_RESUME", firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1", firstCommandHash: "test-command-hash", knownPreconditions: [], forbiddenFirstActions: [], capabilityManifestVersion: "0.1.0-mvp0", policyVersion: "safety-kernel-v3.1-local-client-mvp0", approvalNonceRequired: true, receiptRequired: true }), "utf8");
  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({ schemaVersion: 1, ruleSetId: "owner-rules", blockedCommandSubstrings: ["   "] }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }
  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }
  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }
  class ReceiptWriter { async ensureDirs(): Promise<void> {} }
  const runtimeController = { review: async () => { reviewCalls++; throw new Error("unexpected review call"); } };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: { workspaceFolders: [{ uri: { fsPath: root } }], onWillSaveTextDocument: () => disposable, onDidSaveTextDocument: () => disposable, createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }) },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: user-defined rule set is invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_GATE_ENFORCED=True/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_SET_VALID=False/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_ERROR=INVALID_BLOCKED_RULE/);
    assert.match(clipboardWrites[0] ?? "", /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardWrites[0] ?? "", /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-string blocked workspace user-defined rule before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-non-string-blocked-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "Get-Content package.json" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({ capsuleSchemaVersion: "1.0.0", capsuleKind: "HANDOFF_RESUME", firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1", firstCommandHash: "test-command-hash", knownPreconditions: [], forbiddenFirstActions: [], capabilityManifestVersion: "0.1.0-mvp0", policyVersion: "safety-kernel-v3.1-local-client-mvp0", approvalNonceRequired: true, receiptRequired: true }), "utf8");
  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({ schemaVersion: 1, ruleSetId: "owner-rules", blockedCommandSubstrings: [123] }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }
  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }
  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }
  class ReceiptWriter { async ensureDirs(): Promise<void> {} }
  const runtimeController = { review: async () => { reviewCalls++; throw new Error("unexpected review call"); } };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: { workspaceFolders: [{ uri: { fsPath: root } }], onWillSaveTextDocument: () => disposable, onDidSaveTextDocument: () => disposable, createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }) },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: user-defined rule set is invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_GATE_ENFORCED=True/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_SET_VALID=False/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_ERROR=BLOCKED_RULE_NOT_STRING/);
    assert.match(clipboardWrites[0] ?? "", /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardWrites[0] ?? "", /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects too many blocked workspace user-defined rules before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-too-many-blocked-user-rules-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "Get-Content package.json" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({ capsuleSchemaVersion: "1.0.0", capsuleKind: "HANDOFF_RESUME", firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1", firstCommandHash: "test-command-hash", knownPreconditions: [], forbiddenFirstActions: [], capabilityManifestVersion: "0.1.0-mvp0", policyVersion: "safety-kernel-v3.1-local-client-mvp0", approvalNonceRequired: true, receiptRequired: true }), "utf8");
  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({ schemaVersion: 1, ruleSetId: "owner-rules", blockedCommandSubstrings: Array.from({ length: 101 }, (_, index) => `blocked-${index}`) }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }
  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }
  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }
  class ReceiptWriter { async ensureDirs(): Promise<void> {} }
  const runtimeController = { review: async () => { reviewCalls++; throw new Error("unexpected review call"); } };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: { workspaceFolders: [{ uri: { fsPath: root } }], onWillSaveTextDocument: () => disposable, onDidSaveTextDocument: () => disposable, createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }) },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: user-defined rule set is invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_GATE_ENFORCED=True/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_SET_VALID=False/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_ERROR=TOO_MANY_BLOCKED_RULES/);
    assert.match(clipboardWrites[0] ?? "", /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardWrites[0] ?? "", /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-array blocked workspace user-defined rules before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-non-array-blocked-user-rules-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "Get-Content package.json" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({ capsuleSchemaVersion: "1.0.0", capsuleKind: "HANDOFF_RESUME", firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1", firstCommandHash: "test-command-hash", knownPreconditions: [], forbiddenFirstActions: [], capabilityManifestVersion: "0.1.0-mvp0", policyVersion: "safety-kernel-v3.1-local-client-mvp0", approvalNonceRequired: true, receiptRequired: true }), "utf8");
  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({ schemaVersion: 1, ruleSetId: "owner-rules", blockedCommandSubstrings: "not-an-array" }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }
  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }
  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }
  class ReceiptWriter { async ensureDirs(): Promise<void> {} }
  const runtimeController = { review: async () => { reviewCalls++; throw new Error("unexpected review call"); } };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: { workspaceFolders: [{ uri: { fsPath: root } }], onWillSaveTextDocument: () => disposable, onDidSaveTextDocument: () => disposable, createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }) },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: user-defined rule set is invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_GATE_ENFORCED=True/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_SET_VALID=False/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_ERROR=BLOCKED_RULES_NOT_ARRAY/);
    assert.match(clipboardWrites[0] ?? "", /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardWrites[0] ?? "", /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects invalid workspace user-defined rule set id before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-invalid-user-rule-set-id-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "Get-Content package.json" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({ capsuleSchemaVersion: "1.0.0", capsuleKind: "HANDOFF_RESUME", firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1", firstCommandHash: "test-command-hash", knownPreconditions: [], forbiddenFirstActions: [], capabilityManifestVersion: "0.1.0-mvp0", policyVersion: "safety-kernel-v3.1-local-client-mvp0", approvalNonceRequired: true, receiptRequired: true }), "utf8");
  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({ schemaVersion: 1, ruleSetId: "   ", blockedCommandSubstrings: [] }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }
  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }
  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }
  class ReceiptWriter { async ensureDirs(): Promise<void> {} }
  const runtimeController = { review: async () => { reviewCalls++; throw new Error("unexpected review call"); } };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: { workspaceFolders: [{ uri: { fsPath: root } }], onWillSaveTextDocument: () => disposable, onDidSaveTextDocument: () => disposable, createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }) },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: user-defined rule set is invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_GATE_ENFORCED=True/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_SET_VALID=False/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_ERROR=INVALID_RULE_SET_ID/);
    assert.match(clipboardWrites[0] ?? "", /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardWrites[0] ?? "", /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects array workspace user-defined rule set before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-array-user-rule-set-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({ source: "ai_connector", intent: "propose_terminal_command", actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY", capabilityId: "ai_gateway_review_only", proposedCommand: "Get-Content package.json" });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({ capsuleSchemaVersion: "1.0.0", capsuleKind: "HANDOFF_RESUME", firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1", firstCommandHash: "test-command-hash", knownPreconditions: [], forbiddenFirstActions: [], capabilityManifestVersion: "0.1.0-mvp0", policyVersion: "safety-kernel-v3.1-local-client-mvp0", approvalNonceRequired: true, receiptRequired: true }), "utf8");
  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify([]), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }
  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }
  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }
  class ReceiptWriter { async ensureDirs(): Promise<void> {} }
  const runtimeController = { review: async () => { reviewCalls++; throw new Error("unexpected review call"); } };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: { workspaceFolders: [{ uri: { fsPath: root } }], onWillSaveTextDocument: () => disposable, onDidSaveTextDocument: () => disposable, createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }) },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: user-defined rule set is invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_GATE_ENFORCED=True/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_SET_VALID=False/);
    assert.match(clipboardWrites[0] ?? "", /USER_DEFINED_RULE_ERROR=RULE_SET_NOT_OBJECT/);
    assert.match(clipboardWrites[0] ?? "", /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardWrites[0] ?? "", /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 contains best-effort failure-warning exceptions after input prompt failure without output or execution authority", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const originalConsoleError = console.error;
  const errorMessages: string[] = [];
  console.error = (...data: unknown[]): void => { errorMessages.push(String(data[0])); };
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-review-exception-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => { void envelope; throw new Error("simulated AI Gateway input prompt failure"); },
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); throw new Error("simulated AI Gateway failure warning failure"); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          const authorityBindingComposition = {
            readPort: {
              readCurrentBinding: async () => ({
                authorityRevision: 1,
                workspaceId: "runtime-test-workspace",
                snapshotBindingSha256: "a".repeat(64),
              }),
            },
            verifier: {
              verify: async () => "verified" as const,
            },
          };

          return {
            authorityBindingComposition,
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0 could not complete review.");
    assert.deepEqual(clipboardWrites, []);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.deepEqual(errorMessages, ["[Aegis] aiExecutionGatewayMvp0 error:"]);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    console.error = originalConsoleError;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 contains input prompt exceptions before runtime review without output or execution authority", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-review-exception-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => { void envelope; throw new Error("simulated AI Gateway input prompt failure"); },
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0 could not complete review.");
    assert.deepEqual(clipboardWrites, []);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 uses default intent fallback for runtime controller review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-review-exception-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  let reviewedIntent = "";
  const envelope = JSON.stringify({
    source: "ai_connector",
    targetPath: "package.json",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async (input: { intent: string }) => {
      reviewedIntent = input.intent;
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 1);
    assert.equal(reviewedIntent, "ai_gateway_mvp0_runtime_controller_review");
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0 could not complete review.");
    assert.deepEqual(clipboardWrites, []);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 uses unspecified target fallback for runtime controller review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-review-exception-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  let reviewedTarget = "";
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async (input: { target: string }) => {
      reviewedTarget = input.target;
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 1);
    assert.equal(reviewedTarget, "unspecified-ai-gateway-mvp0-target");
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0 could not complete review.");
    assert.deepEqual(clipboardWrites, []);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 contains final clipboard write failure without success output or execution authority", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-review-exception-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  let clipboardWriteAttempts = 0;
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  let reviewedInput: Record<string, string> | null = null;
  let reviewedGateResult: Record<string, unknown> | null = null;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    targetPath: "package.json",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async (input: Record<string, string>, gateResult: Record<string, unknown>) => {
      reviewedInput = input;
      reviewedGateResult = gateResult;
      reviewCalls++;
      return { output: { clipboardSummary: "RUNTIME_REVIEW_SUMMARY=True" } };
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { void value; clipboardWriteAttempts++; throw new Error("simulated AI Gateway final clipboard write failure"); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 1);
    const captured = reviewedInput as unknown as Record<string, string>;
    assert.match(captured.action_id, /^aegis-action-[a-f0-9]{64}$/);
    assert.equal(captured.target, "package.json");
    assert.equal(captured.intent, "propose_terminal_command");
    assert.equal(captured.proposed_action, "Get-Content package.json");
    assert.match(captured.context_hash, /^sha256:[a-f0-9]{64}$/);
    assert.equal(Number.isNaN(Date.parse(captured.timestamp)), false);
    assert.equal(captured.adapter_id, "aegis-ai-execution-gateway-mvp0-runtime-controller");
    assert.equal(captured.policy_version, "safety-kernel-v31-runtime-controller-review-v1");
    assert.equal(captured.human_readable_summary, "Review AI Execution Gateway MVP-0 envelope through Safety Kernel v3.1 Runtime Controller.");
    const capturedGateResult = reviewedGateResult as unknown as Record<string, unknown>;
    assert.equal(capturedGateResult.status, "ALLOW");

    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0 could not complete review.");
    assert.equal(clipboardWriteAttempts, 1);
    assert.equal(clipboardWrites.length, 0);
    assert.deepEqual(clipboardWrites, []);



    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 contains final success information failure after receipt write without execution authority", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-review-exception-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let informationAttempts = 0;
  const clipboardWrites: string[] = [];
  let clipboardWriteAttempts = 0;
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  let reviewedInput: Record<string, string> | null = null;
  let reviewedGateResult: Record<string, unknown> | null = null;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    targetPath: "package.json",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async (input: Record<string, string>, gateResult: Record<string, unknown>) => {
      reviewedInput = input;
      reviewedGateResult = gateResult;
      reviewCalls++;
      return { output: { clipboardSummary: "RUNTIME_REVIEW_SUMMARY=True" } };
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { if (message === "Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed.") { informationAttempts++; throw new Error("simulated AI Gateway final success information failure"); } infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWriteAttempts++; clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 1);
    const captured = reviewedInput as unknown as Record<string, string>;
    assert.match(captured.action_id, /^aegis-action-[a-f0-9]{64}$/);
    assert.equal(captured.target, "package.json");
    assert.equal(captured.intent, "propose_terminal_command");
    assert.equal(captured.proposed_action, "Get-Content package.json");
    assert.match(captured.context_hash, /^sha256:[a-f0-9]{64}$/);
    assert.equal(Number.isNaN(Date.parse(captured.timestamp)), false);
    assert.equal(captured.adapter_id, "aegis-ai-execution-gateway-mvp0-runtime-controller");
    assert.equal(captured.policy_version, "safety-kernel-v31-runtime-controller-review-v1");
    assert.equal(captured.human_readable_summary, "Review AI Execution Gateway MVP-0 envelope through Safety Kernel v3.1 Runtime Controller.");
    const capturedGateResult = reviewedGateResult as unknown as Record<string, unknown>;
    assert.equal(capturedGateResult.status, "ALLOW");

    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0 could not complete review.");
    assert.equal(clipboardWriteAttempts, 1);
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0], /REVIEW_RUNTIME_CONNECTED=True/);
    assert.match(clipboardWrites[0], /EXECUTION_RUNTIME_CONNECTED=False/);
    assert.equal(clipboardWrites[0].includes("EXECUTION_AUTHORITY_GRANTED=True"), false);



    assert.equal(informationAttempts, 1);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 maps complete Runtime Controller review input contract", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-review-exception-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  let reviewedInput: Record<string, string> | null = null;
  let reviewedGateResult: Record<string, unknown> | null = null;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    targetPath: "package.json",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async (input: Record<string, string>, gateResult: Record<string, unknown>) => {
      reviewedInput = input;
      reviewedGateResult = gateResult;
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 1);
    const captured = reviewedInput as unknown as Record<string, string>;
    assert.match(captured.action_id, /^aegis-action-[a-f0-9]{64}$/);
    assert.equal(captured.target, "package.json");
    assert.equal(captured.intent, "propose_terminal_command");
    assert.equal(captured.proposed_action, "Get-Content package.json");
    assert.match(captured.context_hash, /^sha256:[a-f0-9]{64}$/);
    assert.equal(Number.isNaN(Date.parse(captured.timestamp)), false);
    assert.equal(captured.adapter_id, "aegis-ai-execution-gateway-mvp0-runtime-controller");
    assert.equal(captured.policy_version, "safety-kernel-v31-runtime-controller-review-v1");
    assert.equal(captured.human_readable_summary, "Review AI Execution Gateway MVP-0 envelope through Safety Kernel v3.1 Runtime Controller.");
    const capturedGateResult = reviewedGateResult as unknown as Record<string, unknown>;
    assert.equal(capturedGateResult.status, "ALLOW");
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0 could not complete review.");
    assert.deepEqual(clipboardWrites, []);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 contains runtime controller review exceptions without output or execution authority", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-review-exception-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 1);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0 could not complete review.");
    assert.deepEqual(clipboardWrites, []);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 blocks runtime controller initialization failure without output or execution authority", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-review-exception-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let createCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => { createCalls++; throw new Error("simulated AI Gateway runtime controller initialization failure"); } } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(createCalls, 1);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0 requires Safety Kernel v3.1 Runtime Controller.");
    assert.deepEqual(clipboardWrites, []);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects a noncanonical bootstrap firstRequiredAction before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-invalid-bootstrap-action-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    firstRequiredAction: "RUN_UNVERIFIED_MUTATION",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects a noncanonical bootstrap capsuleSchemaVersion before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-invalid-bootstrap-action-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "0.0.0",
      firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects a noncanonical bootstrap capsuleKind before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-invalid-bootstrap-action-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
      capsuleKind: "RECOVERY_RESUME",
      firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects a blank bootstrap firstCommandHash before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-blank-command-hash-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "   ",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-array bootstrap knownPreconditions before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-array-known-preconditions-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: {},
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-array bootstrap forbiddenFirstActions before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-array-forbidden-first-actions-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: {},
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects a blank bootstrap capabilityManifestVersion before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-blank-capability-manifest-version-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "   ",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects a blank bootstrap policyVersion before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-blank-policy-version-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "   ",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap approvalNonceRequired false before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-approval-nonce-required-false-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: false,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing approvalNonceRequired before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-approval-nonce-required-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap receiptRequired false before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-receipt-required-false-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: false,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing receiptRequired before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-receipt-required-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing firstCommandHash before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-first-command-hash-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing capabilityManifestVersion before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-capability-manifest-version-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing policyVersion before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-policy-version-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing knownPreconditions before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-known-preconditions-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing forbiddenFirstActions before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-forbidden-first-actions-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing capsuleSchemaVersion before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-capsule-schema-version-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing capsuleKind before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-capsule-kind-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects bootstrap missing firstRequiredAction before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-missing-first-required-action-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-string bootstrap capsuleSchemaVersion before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-string-capsule-schema-version-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: 1,
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-string bootstrap capsuleKind before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-string-capsule-kind-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: 1,
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-string bootstrap firstRequiredAction before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-string-first-required-action-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: 1,
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-string bootstrap firstCommandHash before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-string-first-command-hash-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: 1,
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-string bootstrap capabilityManifestVersion before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-string-capability-manifest-version-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: 1,
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-string bootstrap policyVersion before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-string-policy-version-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: 1,
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-boolean bootstrap approvalNonceRequired before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-boolean-approval-nonce-required-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: 1,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects non-boolean bootstrap receiptRequired before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-non-boolean-receipt-required-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: 1,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INCOMPLETE/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects absent bootstrap capsule before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-absent-bootstrap-capsule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE-unused.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_ABSENT/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 rejects invalid JSON bootstrap capsule before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-gateway-invalid-json-bootstrap-capsule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  const clipboardWrites: string[] = [];
  const disposable = { dispose(): void {} };
  let reviewCalls = 0;
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE-unused.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), "{", "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object { return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false }; }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> { return { removed: 0, failed: 0 }; }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("simulated AI Gateway runtime controller review failure");
    },
  };

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return {
        commands: { registerCommand: (id: string, callback: () => Promise<void>) => { callbacks.set(id, callback); return disposable; } },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => { warnings.push(message); },
          showInformationMessage: async (message: string): Promise<void> => { infos.push(message); },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({ onDidDelete(): void {}, onDidChange(): void {}, dispose(): void {} }),
        },
        env: { clipboard: { readText: async (): Promise<string> => "", writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }
    if (request === "./licenseTier") return { getLicenseTier: async () => "free", getCapabilitiesForTier: () => [], isCapabilityAvailableForTier: () => true };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") return { AegisWebviewPanel: { show(): void {}, pushState(): void {}, pushRiskScan(): void {} } };
    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as { activate(context: unknown): Promise<void> };
    await extension.activate({ subscriptions: { push(): void {} } });
    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);
    assert.equal(warnings.at(-1), "Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    assert.equal(clipboardWrites.length, 1);
    assert.match(clipboardWrites[0] ?? "", /BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INVALID_JSON/);
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 accepts action alias before no-authorized-surface rejection", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  let reviewCalls = 0;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-no-authorized-surface-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "UNAUTHORIZED_ACTION_ID",
    capabilityId: "UNAUTHORIZED_CAPABILITY_ID",
    action: "Remove-Item ./protected-file",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") {
      return { SafetyKernelV31RuntimeController: { createForAegisDir: () => ({ review: async () => { reviewCalls++; throw new Error("unexpected pre-review Runtime Controller call"); } }) } };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: no authorized surface for this action.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /AUTHORIZED_SURFACE_GATE_ENFORCED=True/);
    assert.match(clipboardText, /AUTHORIZED_SURFACE_EXISTS=False/);
    assert.match(clipboardText, /SURFACE_DECISION=BLOCKED_NO_AUTHORIZED_SURFACE/);
    assert.match(clipboardText, /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.match(clipboardText, /USER_APPROVAL_OVERRIDES=False/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});


test("extension Gateway MVP-0 accepts command alias before no-authorized-surface rejection", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  let reviewCalls = 0;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-no-authorized-surface-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "UNAUTHORIZED_ACTION_ID",
    capabilityId: "UNAUTHORIZED_CAPABILITY_ID",
    command: "Remove-Item ./protected-file",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") {
      return { SafetyKernelV31RuntimeController: { createForAegisDir: () => ({ review: async () => { reviewCalls++; throw new Error("unexpected pre-review Runtime Controller call"); } }) } };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: no authorized surface for this action.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /AUTHORIZED_SURFACE_GATE_ENFORCED=True/);
    assert.match(clipboardText, /AUTHORIZED_SURFACE_EXISTS=False/);
    assert.match(clipboardText, /SURFACE_DECISION=BLOCKED_NO_AUTHORIZED_SURFACE/);
    assert.match(clipboardText, /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.match(clipboardText, /USER_APPROVAL_OVERRIDES=False/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});


test("extension Gateway MVP-0 ignores non-string proposedCommand and accepts command alias at runtime", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  let reviewCalls = 0;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-no-authorized-surface-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "UNAUTHORIZED_ACTION_ID",
    capabilityId: "UNAUTHORIZED_CAPABILITY_ID",
    proposedCommand: { value: "vsce package" },
    command: "Remove-Item ./protected-file",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") {
      return { SafetyKernelV31RuntimeController: { createForAegisDir: () => ({ review: async () => { reviewCalls++; throw new Error("unexpected pre-review Runtime Controller call"); } }) } };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: no authorized surface for this action.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /AUTHORIZED_SURFACE_GATE_ENFORCED=True/);
    assert.match(clipboardText, /AUTHORIZED_SURFACE_EXISTS=False/);
    assert.match(clipboardText, /SURFACE_DECISION=BLOCKED_NO_AUTHORIZED_SURFACE/);
    assert.match(clipboardText, /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.match(clipboardText, /USER_APPROVAL_OVERRIDES=False/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});


test("extension Gateway MVP-0 rejects no authorized surface before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  let reviewCalls = 0;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-no-authorized-surface-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "UNAUTHORIZED_ACTION_ID",
    capabilityId: "UNAUTHORIZED_CAPABILITY_ID",
    proposedCommand: "Remove-Item ./protected-file",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") {
      return { SafetyKernelV31RuntimeController: { createForAegisDir: () => ({ review: async () => { reviewCalls++; throw new Error("unexpected pre-review Runtime Controller call"); } }) } };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: no authorized surface for this action.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /AUTHORIZED_SURFACE_GATE_ENFORCED=True/);
    assert.match(clipboardText, /AUTHORIZED_SURFACE_EXISTS=False/);
    assert.match(clipboardText, /SURFACE_DECISION=BLOCKED_NO_AUTHORIZED_SURFACE/);
    assert.match(clipboardText, /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.match(clipboardText, /USER_APPROVAL_OVERRIDES=False/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});


test("extension Gateway MVP-0 prefers proposedCommand over command and action aliases at runtime", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  let reviewCalls = 0;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-workflow-drift-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "vsce package",
    command: "Get-Content package.json",
    action: "Get-Content README.md",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") {
      return { SafetyKernelV31RuntimeController: { createForAegisDir: () => ({ review: async () => { reviewCalls++; throw new Error("unexpected pre-review Runtime Controller call"); } }) } };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: workflow drift blocked before execution.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /GIT_DEPENDENT_WORKFLOW_BLOCKED=True/);
    assert.match(clipboardText, /AI_WORKFLOW_DRIFT_BLOCKED=True/);
    assert.match(clipboardText, /SANITIZED_COMMAND_PREVIEW=vsce package/);
    assert.equal(clipboardText.includes("WORKFLOW_DRIFT_PATTERN=/\\bvsce\\s+package\\b/i"), true);
    assert.match(clipboardText, /GATEWAY_HANDOFF_BLOCKED=True/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});



test("extension Gateway MVP-0 prefers command alias over action alias at runtime", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  let reviewCalls = 0;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-workflow-drift-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    command: "vsce package",
    action: "Get-Content README.md",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") {
      return { SafetyKernelV31RuntimeController: { createForAegisDir: () => ({ review: async () => { reviewCalls++; throw new Error("unexpected pre-review Runtime Controller call"); } }) } };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: workflow drift blocked before execution.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /GIT_DEPENDENT_WORKFLOW_BLOCKED=True/);
    assert.match(clipboardText, /AI_WORKFLOW_DRIFT_BLOCKED=True/);
    assert.match(clipboardText, /SANITIZED_COMMAND_PREVIEW=vsce package/);
    assert.equal(clipboardText.includes("WORKFLOW_DRIFT_PATTERN=/\\bvsce\\s+package\\b/i"), true);
    assert.match(clipboardText, /GATEWAY_HANDOFF_BLOCKED=True/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});



test("extension Gateway MVP-0 rejects workflow drift before review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  let reviewCalls = 0;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-workflow-drift-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "vsce package",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") {
      return { SafetyKernelV31RuntimeController: { createForAegisDir: () => ({ review: async () => { reviewCalls++; throw new Error("unexpected pre-review Runtime Controller call"); } }) } };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: workflow drift blocked before execution.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /GIT_DEPENDENT_WORKFLOW_BLOCKED=True/);
    assert.match(clipboardText, /AI_WORKFLOW_DRIFT_BLOCKED=True/);
    assert.equal(clipboardText.includes("WORKFLOW_DRIFT_PATTERN=/\\bvsce\\s+package\\b/i"), true);
    assert.match(clipboardText, /GATEWAY_HANDOFF_BLOCKED=True/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});



test("extension Gateway MVP-0 completes allowed action-quality review without execution", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const originalClearTimeout = globalThis.clearTimeout;
  type RuntimeTimer = { timer: ReturnType<typeof setTimeout>; callback: () => void | Promise<void> };
  const scheduledTimers: RuntimeTimer[] = [];
  const clearedTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-allowed-reviewed-only-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "Get-Content package.json",
  });
  let inputValue = envelope;

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push({ timer, callback });
    return timer;
  }) as unknown) as typeof setTimeout;
  globalThis.clearTimeout = ((timer: ReturnType<typeof setTimeout>) => {
    clearedTimers.push(timer);
  }) as typeof clearTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => inputValue,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
          showTextDocument: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          openTextDocument: async (value: unknown): Promise<unknown> => value,
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
      deactivate(): void;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    const confirmCommand = callbacks.get("aegis.confirmSafetyKernelV31WarnSession");
    const cancelCommand = callbacks.get("aegis.cancelSafetyKernelV31WarnSession");
    assert.ok(confirmCommand);
    assert.ok(cancelCommand);
    await callback();
    const firstGatewayReceipt = clipboardText;
    const firstSessionId = firstGatewayReceipt.match(/SESSION_ID=([a-f0-9]{48})/)?.[1] ?? "";
    const firstApprovalNonceSha256 = firstGatewayReceipt.match(/APPROVAL_NONCE_SHA256=([a-f0-9]{64})/)?.[1] ?? "";
    assert.match(firstSessionId, /^[a-f0-9]{48}$/);
    assert.match(firstApprovalNonceSha256, /^[a-f0-9]{64}$/);
    assert.equal(scheduledTimers.length, 1);
    const expiredGatewayWarnTimer = scheduledTimers[0];
    await expiredGatewayWarnTimer.callback();
    assert.equal(warnings.includes("Aegis Safety Kernel WARN session expired; no action was executed."), true);
    assert.equal(clipboardText.includes("EXECUTION_AUTHORITY_GRANTED=True"), false);
    await callback();
    const secondGatewayReceipt = clipboardText;
    const secondSessionId = secondGatewayReceipt.match(/SESSION_ID=([a-f0-9]{48})/)?.[1] ?? "";
    const secondApprovalNonceSha256 = secondGatewayReceipt.match(/APPROVAL_NONCE_SHA256=([a-f0-9]{64})/)?.[1] ?? "";
    assert.match(secondSessionId, /^[a-f0-9]{48}$/);
    assert.match(secondApprovalNonceSha256, /^[a-f0-9]{64}$/);
    assert.notEqual(secondSessionId, firstSessionId);
    assert.notEqual(secondApprovalNonceSha256, firstApprovalNonceSha256);
    assert.equal(scheduledTimers.length, 2);
    const gatewayWarnTimer = scheduledTimers[1].timer;

    inputValue = secondSessionId;
    await confirmCommand();
    const confirmedGatewayReceipt = clipboardText;
    assert.equal(clearedTimers.includes(gatewayWarnTimer), true);
    assert.match(confirmedGatewayReceipt, /SAFETY_KERNEL_V31_WARN_CONFIRMED=True/);
    assert.match(confirmedGatewayReceipt, /EVENT=WARN_CONFIRMED/);
    assert.match(confirmedGatewayReceipt, /EVIDENCE_COMMITTED=True/);
    assert.match(confirmedGatewayReceipt, /CONFIRMATION_EXECUTED_ACTION=False/);
    assert.match(confirmedGatewayReceipt, /EXECUTION_AUTHORITY_GRANTED=False/);
    assert.equal(infos.includes("Aegis Safety Kernel WARN session confirmed; no action was executed."), true);

    inputValue = envelope;
    await callback();
    const thirdGatewayReceipt = clipboardText;
    const thirdSessionId = thirdGatewayReceipt.match(/SESSION_ID=([a-f0-9]{48})/)?.[1] ?? "";
    assert.match(thirdSessionId, /^[a-f0-9]{48}$/);
    assert.notEqual(thirdSessionId, secondSessionId);
    assert.equal(scheduledTimers.length, 3);
    const cancelGatewayWarnTimer = scheduledTimers[2].timer;

    inputValue = thirdSessionId;
    await cancelCommand();
    const cancelledGatewayReceipt = clipboardText;
    assert.equal(clearedTimers.includes(cancelGatewayWarnTimer), true);
    assert.match(cancelledGatewayReceipt, /SAFETY_KERNEL_V31_WARN_CANCELLED=True/);
    assert.match(cancelledGatewayReceipt, /EVIDENCE_COMMITTED=True/);
    assert.match(cancelledGatewayReceipt, /CANCELLATION_EXECUTED_ACTION=False/);
    assert.match(cancelledGatewayReceipt, /EXECUTION_AUTHORITY_GRANTED=False/);
    assert.equal(infos.includes("Aegis Safety Kernel WARN session cancelled with evidence; no action was executed."), true);

    clipboardText = secondGatewayReceipt;
    extension.deactivate();
    assert.equal(clearedTimers.includes(gatewayWarnTimer), true);

    assert.equal(warnings.filter((message) => message === "Aegis Safety Kernel WARN session expired; no action was executed.").length, 1);
    assert.equal(
      infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."),
      true,
    );
    assert.match(clipboardText, /AUTHORIZED_SURFACE_EXISTS=True/);
    assert.match(clipboardText, /SURFACE_DECISION=REVIEWED_ONLY_NO_EXECUTION/);
    assert.match(clipboardText, /AI_WORKFLOW_DRIFT_BLOCKED=False/);
    assert.match(clipboardText, /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardText, /AUTO_EXECUTE_DISABLED=True/);
    assert.match(clipboardText, /GATEWAY_HANDOFF_BLOCKED=False/);
    assert.match(clipboardText, /SAFETY_KERNEL_V31_TRANSACTION_OUTPUT=True/);
    assert.match(clipboardText, /ACTION_ID=AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY/);
    assert.match(clipboardText, /DECISION=WARN/);
    assert.match(clipboardText, /LIFECYCLE_PHASE=WARN_PENDING/);
    assert.match(clipboardText, /NONCE_CONSUMED=False/);
    assert.match(clipboardText, /EVIDENCE_COMMITTED=True/);
    assert.match(clipboardText, /SESSION_PHASE=WARN_PENDING/);
    assert.match(clipboardText, /COMMAND_DELEGATION_CONNECTED=True/);
    assert.match(clipboardText, /RUNTIME_CONTROLLER_AVAILABLE=True/);
    assert.match(clipboardText, /SESSION_ID=[a-f0-9]{48}/);
    assert.match(clipboardText, /APPROVAL_NONCE_SHA256=[a-f0-9]{64}/);
    assert.match(clipboardText, /RAW_APPROVAL_NONCE_EXPOSED=False/);
    assert.match(clipboardText, /EVIDENCE_REASON=success/);
    assert.match(clipboardText, /PARENT_ENVELOPE_INVALIDATED=False/);
    assert.match(clipboardText, /CHILD_NONCES_REQUIRED=False/);
    assert.match(clipboardText, /RUNTIME_CONNECTED=False/);
    assert.match(clipboardText, /AUTOMATIC_EXECUTION_ALLOWED=False/);
    assert.equal(clipboardText.includes("EXECUTION_AUTHORITY_GRANTED=True"), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 blocks REVIEW_NEEDED action-quality handoff without execution", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  const root = mkdtempSync(join(tmpdir(), "aegis-review-needed-reviewed-only-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    proposedCommand: "please inspect this later",
  });

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(scheduledTimers.length, 0);

    assert.equal(warnings.length, 0);
    assert.equal(
      infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."),
      true,
    );
    assert.match(clipboardText, /AUTHORIZED_SURFACE_EXISTS=True/);
    assert.match(clipboardText, /SURFACE_DECISION=REVIEWED_ONLY_NO_EXECUTION/);
    assert.match(clipboardText, /AI_WORKFLOW_DRIFT_BLOCKED=False/);
    assert.match(clipboardText, /EXECUTION_NOT_PERFORMED=True/);
    assert.match(clipboardText, /AUTO_EXECUTE_DISABLED=True/);
    assert.match(clipboardText, /ACTION_QUALITY_GATE_STATUS=REVIEW_NEEDED/);
    assert.match(clipboardText, /ACTION_QUALITY_GATE_RULE=DEFAULT_REVIEW_NEEDED/);
    assert.match(clipboardText, /GATEWAY_HANDOFF_BLOCKED=True/);
    assert.match(clipboardText, /SAFETY_KERNEL_V31_TRANSACTION_OUTPUT=True/);
    assert.match(clipboardText, /ACTION_ID=AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY/);
    assert.match(clipboardText, /DECISION=REQUIRE_REVIEW/);
    assert.match(clipboardText, /LIFECYCLE_PHASE=REQUIRE_REVIEW/);
    assert.match(clipboardText, /NONCE_CONSUMED=True/);
    assert.match(clipboardText, /EVIDENCE_COMMITTED=True/);
    assert.match(clipboardText, /COMMAND_DELEGATION_CONNECTED=True/);
    assert.match(clipboardText, /RUNTIME_CONTROLLER_AVAILABLE=True/);
    assert.match(clipboardText, /SESSION_ID=\r?\n/);
    assert.match(clipboardText, /SESSION_PHASE=\r?\n/);
    assert.match(clipboardText, /APPROVAL_NONCE_SHA256=[a-f0-9]{64}/);
    assert.match(clipboardText, /RAW_APPROVAL_NONCE_EXPOSED=False/);
    assert.match(clipboardText, /RUNTIME_CONNECTED=False/);
    assert.match(clipboardText, /AUTOMATIC_EXECUTION_ALLOWED=False/);
    assert.match(clipboardText, /EVIDENCE_REASON=success/);
    assert.match(clipboardText, /PARENT_ENVELOPE_INVALIDATED=False/);
    assert.match(clipboardText, /CHILD_NONCES_REQUIRED=False/);
    assert.match(clipboardText, /RAW_PROPOSED_ACTION_FULL_OUTPUT_DISABLED=True/);
    assert.match(clipboardText, /SANITIZED_COMMAND_PREVIEW=please inspect this later/);
    assert.equal(clipboardText.includes("EXECUTION_AUTHORITY_GRANTED=True"), false);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});

test("extension Gateway MVP-0 blocks raw terminal command without Action Envelope before runtime review", async () => {
  type Loader = (request: string, parent: unknown, isMain: boolean) => unknown;
  const moduleLoader = Module as unknown as { _load: Loader };
  const originalLoad = moduleLoader._load;
  const originalSetTimeout = globalThis.setTimeout;
  const scheduledTimers: Array<ReturnType<typeof setTimeout>> = [];
  let reviewCalls = 0;
  const runtimeController = {
    review: async () => {
      reviewCalls++;
      throw new Error("user-defined rule gate did not block runtime review");
    },
  };
  const root = mkdtempSync(join(tmpdir(), "aegis-user-rule-runtime-"));
  const callbacks = new Map<string, () => Promise<void>>();
  const warnings: string[] = [];
  const infos: string[] = [];
  let clipboardText = "";
  const disposable = { dispose(): void {} };
  const envelope = "Get-Content package.json";

  writeFileSync(join(root, "AEGIS-HANDOFF-CAPSULE.json"), JSON.stringify({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
  }), "utf8");

  writeFileSync(join(root, "AEGIS-USER-RULES.json"), JSON.stringify({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["Remove-Item"],
  }), "utf8");

  class StateManager {
    onDidChangeState(): typeof disposable { return disposable; }
    getState(): object {
      return { status: "SAFE", message: "test", restoreAvailable: false, isProcessing: false };
    }
    setSafe(): void {}
    setWarning(): void {}
    setBlocked(): void {}
    dispose(): void {}
  }

  class SnapshotStore {
    async ensureDirs(): Promise<void> {}
    async recoverStartupArtifacts(): Promise<{ removed: number; failed: number }> {
      return { removed: 0, failed: 0 };
    }
    async readIndex(): Promise<null> { return null; }
  }

  class LedgerWriter {
    async ensureDirs(): Promise<void> {}
    async verifyStartupIntegrity(): Promise<{ ok: boolean }> { return { ok: true }; }
  }

  class ReceiptWriter {
    async ensureDirs(): Promise<void> {}
  }

  globalThis.setTimeout = (((_callback: () => void | Promise<void>) => {
    const timer = { timerId: scheduledTimers.length + 1 } as unknown as ReturnType<typeof setTimeout>;
    scheduledTimers.push(timer);
    return timer;
  }) as unknown) as typeof setTimeout;

  moduleLoader._load = function (
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    if (request === "vscode") {
      return {
        commands: {
          registerCommand: (id: string, callback: () => Promise<void>) => {
            callbacks.set(id, callback);
            return disposable;
          },
        },
        window: {
          showInputBox: async (): Promise<string> => envelope,
          showWarningMessage: async (message: string): Promise<void> => {
            warnings.push(message);
          },
          showInformationMessage: async (message: string): Promise<void> => {
            infos.push(message);
          },
          showErrorMessage: async (): Promise<void> => {},
        },
        workspace: {
          workspaceFolders: [{ uri: { fsPath: root } }],
          onWillSaveTextDocument: () => disposable,
          onDidSaveTextDocument: () => disposable,
          createFileSystemWatcher: () => ({
            onDidDelete(): void {},
            onDidChange(): void {},
            dispose(): void {},
          }),
        },
        env: {
          clipboard: {
            readText: async (): Promise<string> => "",
            writeText: async (value: string): Promise<void> => {
              clipboardText = value;
            },
          },
        },
        Uri: { file: (value: string) => ({ fsPath: value }) },
        RelativePattern: class {},
        ViewColumn: { One: 1 },
      };
    }

    if (request === "./licenseTier") {
      return {
        getLicenseTier: async () => "free",
        getCapabilitiesForTier: () => [],
        isCapabilityAvailableForTier: () => true,
      };
    }

    if (request === "./envCoreEngine") return { EnvCoreEngine: class {} };
    if (request === "./snapshotStore") return { SnapshotStore };
    if (request === "./stateManager") return { StateManager };
    if (request === "./ledgerWriter") return { LedgerWriter };
    if (request === "./receiptWriter") return { ReceiptWriter };
    if (request === "./nodeProcessExecutionAdapter") {
      return {
        spawnNodeProcess: (): never => {
          throw new Error("UNEXPECTED_A2S_NODE_PROCESS_SPAWN");
        },
      };
    }

    if (request === "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory") {
      return {
        createSafetyKernelV31SnapshotTargetIndexReaderCollection: (): readonly unknown[] => [],
      };
    }

    if (request === "./safetyKernelV31NodeProcessExtensionBootstrapComposition") {
      return {
        createSafetyKernelV31NodeProcessExtensionBootstrapComposition: (input: { aegisDir: string }) => {
          const runtimeModule = moduleLoader._load(
            "./safetyKernelV31RuntimeController",
            parent,
            isMain
          ) as {
            SafetyKernelV31RuntimeController: {
              createForAegisDir(aegisDir: string): unknown;
            };
          };

          const runtimeController =
            runtimeModule.SafetyKernelV31RuntimeController.createForAegisDir(
              input.aegisDir
            );

          return {
            nodeProcessExtensionComposition: {
              extensionComposition: {
                runtimeController,
              },
            },
          };
        },
      };
    }
    if (request === "./safetyKernelV31RuntimeController") return { SafetyKernelV31RuntimeController: { createForAegisDir: () => runtimeController } };
    if (request === "./riskScan") return { runRiskScan: async () => null };
    if (request === "./webviewPanel") {
      return {
        AegisWebviewPanel: {
          show(): void {},
          pushState(): void {},
          pushRiskScan(): void {},
        },
      };
    }

    return originalLoad.call(moduleLoader, request, parent, isMain);
  };

  const extensionPath = require.resolve("./extension");
  const platformAdapterPath = require.resolve("./vscodePlatformAdapter");
  delete require.cache[extensionPath];
  delete require.cache[platformAdapterPath];

  try {
    const extension = require("./extension") as {
      activate(context: unknown): Promise<void>;
    };

    await extension.activate({
      subscriptions: { push(): void {} },
    });

    const callback = callbacks.get("aegis.aegisExecutionGatewayMvp0");
    assert.ok(callback);
    await callback();
    assert.equal(reviewCalls, 0);
    assert.equal(scheduledTimers.length, 0);

    assert.equal(
      warnings.at(-1),
      "Aegis AI Execution Gateway MVP-0: invalid AI action envelope blocked.",
     );
    assert.equal(infos.includes("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed."), false);
    assert.match(clipboardText, /ENVELOPE_VALID=False/);
    assert.match(clipboardText, /ENVELOPE_ERROR=INVALID_JSON_ENVELOPE/);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    moduleLoader._load = originalLoad;
    delete require.cache[extensionPath];
    delete require.cache[platformAdapterPath];
    rmSync(root, { recursive: true, force: true });
  }
});
