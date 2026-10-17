import test from "node:test";
import assert from "node:assert/strict";
import Module from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

type Loader = (
  request: string,
  parent: unknown,
  isMain: boolean
) => unknown;

type ExtensionModule = {
  activate(context: unknown): Promise<void>;
  deactivate(): Promise<void>;
};

type Deferred = {
  promise: Promise<void>;
  resolve(): void;
};

type DelayControl = {
  gate: Deferred;
  started: Deferred;
};

type PersistenceControl = {
  loadCount: number;
  saveCount: number;
  activeSaveCount: number;
  maximumConcurrentSaveCount: number;
  loadedStates: Array<Record<string, unknown>>;
  savedStates: Array<Record<string, unknown>>;
  saveStartOrder: number[];
  saveCompletionOrder: number[];
  delayNextSave: DelayControl | null;
  failNextSave: boolean;
  failureObserved: Deferred | null;
  delayAfterFailure: DelayControl | null;
};

const actualStateManagerModule =
  require("./stateManager") as {
    StateManager: new () => {
      readonly onDidChangeState: (
        listener: (
          state: {
            status: string;
            message: string;
            restoreAvailable: boolean;
            isProcessing: boolean;
          }
        ) => unknown
      ) => {
        dispose(): void;
      };

      getState(): {
        status: string;
        message: string;
        restoreAvailable: boolean;
        isProcessing: boolean;
      };

      setWarning(message: string): void;

      setBlocked(
        message: string,
        path?: string,
        snapshotId?: string
      ): void;

      dispose(): void;
    };
  };

const actualPersistenceModule =
  require("./canonicalAuthorityStateFilePersistence") as {
    CanonicalAuthorityStateFilePersistence: new (
      snapshotPath: string
    ) => {
      load(): Promise<
        | {
            getState(): Record<string, unknown>;
          }
        | null
      >;

      save(
        store: {
          getState(): Record<string, unknown>;
        }
      ): Promise<void>;
    };
  };

const actualCanonicalModule =
  require("./canonicalAuthorityState") as {
    CanonicalAuthorityStateStore: {
      hydrateSnapshotJson(
        serialized: string
      ): {
        getState(): Record<string, unknown>;
      };
    };
  };

const ActualStateManager =
  actualStateManagerModule.StateManager;

const ActualPersistence =
  actualPersistenceModule
    .CanonicalAuthorityStateFilePersistence;

let activeWorkspaceRoot = "";

let activePersistenceControl:
  PersistenceControl | null = null;

const trackingStateManagers:
  TrackingStateManager[] = [];

function deferred(): Deferred {
  let resolvePromise:
    (() => void) | null = null;

  const promise =
    new Promise<void>(resolve => {
      resolvePromise = resolve;
    });

  return {
    promise,

    resolve(): void {
      if (resolvePromise === null) {
        throw new Error(
          "DEFERRED_RESOLVER_UNAVAILABLE"
        );
      }

      const resolver =
        resolvePromise;

      resolvePromise = null;
      resolver();
    },
  };
}

function createPersistenceControl():
PersistenceControl {
  return {
    loadCount: 0,
    saveCount: 0,
    activeSaveCount: 0,
    maximumConcurrentSaveCount: 0,
    loadedStates: [],
    savedStates: [],
    saveStartOrder: [],
    saveCompletionOrder: [],
    delayNextSave: null,
    failNextSave: false,
    failureObserved: null,
    delayAfterFailure: null,
  };
}

class TrackingStateManager
  extends ActualStateManager {
  readonly warningMessages:
    string[] = [];

  constructor() {
    super();

    trackingStateManagers.push(
      this
    );
  }

  setWarning(
    message: string
  ): void {
    this.warningMessages.push(
      message
    );

    super.setWarning(
      message
    );
  }
}

class InstrumentedPersistence
  extends ActualPersistence {
  async load(): Promise<
    | {
        getState(): Record<string, unknown>;
      }
    | null
  > {
    const control =
      activePersistenceControl;

    if (control === null) {
      throw new Error(
        "PERSISTENCE_CONTROL_UNAVAILABLE"
      );
    }

    control.loadCount++;

    const loaded =
      await super.load();

    if (loaded !== null) {
      control.loadedStates.push(
        structuredClone(
          loaded.getState()
        )
      );
    }

    return loaded;
  }

  async save(
    store: {
      getState(): Record<string, unknown>;
    }
  ): Promise<void> {
    const control =
      activePersistenceControl;

    if (control === null) {
      throw new Error(
        "PERSISTENCE_CONTROL_UNAVAILABLE"
      );
    }

    const saveNumber =
      ++control.saveCount;

    control.activeSaveCount++;

    control.maximumConcurrentSaveCount =
      Math.max(
        control.maximumConcurrentSaveCount,
        control.activeSaveCount
      );

    control.saveStartOrder.push(
      saveNumber
    );

    control.savedStates.push(
      structuredClone(
        store.getState()
      )
    );

    try {
      const delay =
        control.delayNextSave;

      if (delay !== null) {
        control.delayNextSave = null;
        delay.started.resolve();
        await delay.gate.promise;
      }

      if (control.failNextSave) {
        control.failNextSave = false;

        if (
          control.delayAfterFailure !== null
        ) {
          control.delayNextSave =
            control.delayAfterFailure;

          control.delayAfterFailure =
            null;
        }

        control.failureObserved
          ?.resolve();

        throw new Error(
          "SIMULATED_CANONICAL_PERSISTENCE_FAILURE"
        );
      }

      await super.save(store);

      control.saveCompletionOrder.push(
        saveNumber
      );
    } finally {
      control.activeSaveCount--;
    }
  }
}

function createUniversalProxy():
unknown {
  let proxy: unknown;

  const callable =
    (): unknown => proxy;

  proxy = new Proxy(
    callable,
    {
      get(
        _target,
        property
      ): unknown {
        if (property === "then") {
          return undefined;
        }

        if (
          property ===
          Symbol.iterator
        ) {
          return function* ():
          Generator<never> {}
        }

        if (property === "dispose") {
          return (): void => {};
        }

        return proxy;
      },

      apply(): unknown {
        return proxy;
      },

      construct(): object {
        return proxy as object;
      },
    }
  );

  return proxy;
}

function createUniversalObject(
  initial:
    Record<PropertyKey, unknown>
): Record<PropertyKey, unknown> {
  const fallback =
    createUniversalProxy();

  return new Proxy(
    initial,
    {
      get(
        target,
        property
      ): unknown {
        if (
          Reflect.has(
            target,
            property
          )
        ) {
          return Reflect.get(
            target,
            property
          );
        }

        if (property === "then") {
          return undefined;
        }

        return fallback;
      },
    }
  );
}

function createVscodeMock():
Record<PropertyKey, unknown> {
  const disposable = {
    dispose(): void {},
  };

  class RuntimeEventEmitter {
    private readonly listeners =
      new Set<
        (value: unknown) => unknown
      >();

    readonly event = (
      listener:
        (value: unknown) => unknown
    ): {
      dispose(): void;
    } => {
      this.listeners.add(
        listener
      );

      return {
        dispose:
          (): void => {
            this.listeners.delete(
              listener
            );
          },
      };
    };

    fire(
      value: unknown
    ): void {
      for (
        const listener of
        this.listeners
      ) {
        listener(
          value
        );
      }
    }

    dispose(): void {
      this.listeners.clear();
    }
  }

  return createUniversalObject({
    commands: {
      registerCommand():
      {
        dispose(): void;
      } {
        return disposable;
      },

      async executeCommand():
      Promise<undefined> {
        return undefined;
      },
    },

    window: {
      async showWarningMessage():
      Promise<undefined> {
        return undefined;
      },

      async showInformationMessage():
      Promise<undefined> {
        return undefined;
      },

      async showErrorMessage():
      Promise<undefined> {
        return undefined;
      },

      async showInputBox():
      Promise<undefined> {
        return undefined;
      },

      async showTextDocument():
      Promise<undefined> {
        return undefined;
      },

      createOutputChannel(): {
        appendLine(
          value: string
        ): void;

        dispose(): void;
      } {
        return {
          appendLine(): void {},
          dispose(): void {},
        };
      },
    },

    workspace: {
      get workspaceFolders():
      Array<{
        uri: {
          fsPath: string;
        };
      }> {
        return [
          {
            uri: {
              fsPath:
                activeWorkspaceRoot,
            },
          },
        ];
      },

      isTrusted: true,

      onDidGrantWorkspaceTrust():
      {
        dispose(): void;
      } {
        return disposable;
      },

      onWillSaveTextDocument():
      {
        dispose(): void;
      } {
        return disposable;
      },

      onDidSaveTextDocument():
      {
        dispose(): void;
      } {
        return disposable;
      },

      createFileSystemWatcher():
      {
        onDidCreate():
        {
          dispose(): void;
        };

        onDidChange():
        {
          dispose(): void;
        };

        onDidDelete():
        {
          dispose(): void;
        };

        dispose(): void;
      } {
        return {
          onDidCreate:
            () =>
              disposable,

          onDidChange:
            () =>
              disposable,

          onDidDelete:
            () =>
              disposable,

          dispose(): void {},
        };
      },

      async openTextDocument(
        value: unknown
      ): Promise<unknown> {
        return value;
      },

      getConfiguration(): {
        get<T>(
          key: string,
          fallback?: T
        ): T | undefined;

        update():
        Promise<void>;
      } {
        return {
          get<T>(
            _key: string,
            fallback?: T
          ): T | undefined {
            return fallback;
          },

          async update():
          Promise<void> {},
        };
      },
    },

    env: {
      clipboard: {
        async readText():
        Promise<string> {
          return "";
        },

        async writeText():
        Promise<void> {},
      },
    },

    Uri: {
      file(
        value: string
      ): {
        fsPath: string;
      } {
        return {
          fsPath: value,
        };
      },

      joinPath(
        base: {
          fsPath?: string;
        },
        ...parts: string[]
      ): {
        fsPath: string;
      } {
        return {
          fsPath: path.join(
            base.fsPath ?? "",
            ...parts
          ),
        };
      },
    },

    RelativePattern:
      class RuntimeRelativePattern {
        constructor(
          readonly base: unknown,
          readonly pattern: string
        ) {}
      },

    EventEmitter:
      RuntimeEventEmitter,

    Disposable: {
      from(
        ...values:
          Array<{
            dispose(): void;
          }>
      ): {
        dispose(): void;
      } {
        return {
          dispose(): void {
            for (
              const value of
              values
            ) {
              value.dispose();
            }
          },
        };
      },
    },

    ViewColumn: {
      One: 1,
    },
  });
}

function createRuntimeController():
Record<PropertyKey, unknown> {
  return createUniversalObject({
    readSession():
    null {
      return null;
    },

    async review():
    Promise<{
      session: null;
    }> {
      return {
        session: null,
      };
    },

    async terminateWarnSession():
    Promise<Record<string, never>> {
      return {};
    },

    async confirmWarnSession():
    Promise<Record<string, never>> {
      return {};
    },

    async completeAllowedExecutionSession():
    Promise<Record<string, never>> {
      return {};
    },

    bindAllowedExecutionSessionAuthority():
    {
      authorityBound: boolean;
    } {
      return {
        authorityBound: false,
      };
    },
  });
}

function installModuleHarness():
{
  restore(): void;
} {
  const moduleLoader =
    Module as unknown as {
      _load: Loader;
    };

  const originalLoad =
    moduleLoader._load;

  moduleLoader._load =
    function (
      request: string,
      parent: unknown,
      isMain: boolean
    ): unknown {
      if (request === "vscode") {
        return createVscodeMock();
      }

      if (
        request ===
        "./licenseTier"
      ) {
        return {
          getLicenseTier:
            async () => "free",

          getCapabilitiesForTier:
            () => [
              "coreProtection",
              "aiExecutionGatewayMvp0",
              "aiCommandReview",
              "workReceipt",
              "protectedTerminal",
            ],

          isCapabilityAvailableForTier:
            () => true,
        };
      }

      if (
        request ===
        "./stateManager"
      ) {
        return {
          StateManager:
            TrackingStateManager,
        };
      }

      if (
        request ===
        "../packages/aegis-core"
      ) {
        const actualCoreModule =
          Reflect.apply(
            originalLoad,
            moduleLoader,
            [
              request,
              parent,
              isMain,
            ]
          ) as Record<string, unknown>;

        return {
          ...actualCoreModule,
          StateManager:
            TrackingStateManager,
        };
      }

      if (
        request ===
        "./canonicalAuthorityStateFilePersistence"
      ) {
        return {
          CanonicalAuthorityStateFilePersistence:
            InstrumentedPersistence,
        };
      }

      if (
        request ===
        "./riskScan"
      ) {
        return {
          runRiskScan:
            async () => null,
        };
      }

      if (
        request ===
        "./webviewPanel"
      ) {
        return {
          AegisWebviewPanel: {
            show(): void {},
            pushState(): void {},
            pushRiskScan(): void {},
          },
        };
      }

      if (
        request ===
        "./nodeProcessExecutionAdapter"
      ) {
        return {
          spawnNodeProcess():
          never {
            throw new Error(
              "UNEXPECTED_NODE_PROCESS_SPAWN"
            );
          },
        };
      }

      if (
        request ===
        "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory"
      ) {
        return {
          createSafetyKernelV31SnapshotTargetIndexReaderCollection:
            (): readonly unknown[] =>
              [],
        };
      }

      if (
        request ===
        "./safetyKernelV31NodeProcessExtensionBootstrapComposition"
      ) {
        return {
          createSafetyKernelV31NodeProcessExtensionBootstrapComposition:
            () => {
              const readPort =
                createUniversalObject({
                  async readCurrentBinding():
                  Promise<{
                    authorityRevision:
                      number;

                    workspaceId:
                      string;

                    snapshotBindingSha256:
                      string;
                  }> {
                    return {
                      authorityRevision: 1,
                      workspaceId:
                        "runtime-test-workspace",
                      snapshotBindingSha256:
                        "a".repeat(64),
                    };
                  },
                });

              const composition =
                createUniversalObject({
                  readPort,
                  verifier:
                    createUniversalProxy(),
                });

              return createUniversalObject({
                nodeProcessExtensionComposition:
                  composition,

                extensionComposition:
                  composition,

                runtimeController:
                  createRuntimeController(),
              });
            },
        };
      }

      if (
        request.includes(
          "sessionHandoff"
        ) &&
        request.includes(
          "Composition"
        )
      ) {
        return createUniversalObject({});
      }

      if (
        request.includes(
          "safetyKernelV31Authority"
        ) &&
        request.includes(
          "Composition"
        )
      ) {
        return createUniversalObject({});
      }

      return originalLoad.call(
        moduleLoader,
        request,
        parent,
        isMain
      );
    };

  return {
    restore(): void {
      moduleLoader._load =
        originalLoad;
    },
  };
}

function createWorkspace(
  label: string
): string {
  const workspace =
    fs.mkdtempSync(
      path.join(
        os.tmpdir(),
        "aegis-c09-" +
          label +
          "-"
      )
    );

  fs.writeFileSync(
    path.join(
      workspace,
      ".env"
    ),
    "AEGIS_RUNTIME_TEST=TRUE\n",
    "utf8"
  );

  fs.writeFileSync(
    path.join(
      workspace,
      "package.json"
    ),
    JSON.stringify(
      {
        name:
          "aegis-c09-runtime-test",

        private: true,
      },
      null,
      2
    ) + "\n",
    "utf8"
  );

  return workspace;
}

function snapshotPathFor(
  workspace: string
): string {
  return path.join(
    workspace,
    ".aegis",
    "canonical-authority-state.json"
  );
}

function latestStateManager():
TrackingStateManager {
  const instance =
    trackingStateManagers.at(-1);

  if (!instance) {
    throw new Error(
      "TRACKING_STATE_MANAGER_NOT_CREATED"
    );
  }

  return instance;
}

async function loadAndActivateExtension(
  workspace: string,
  control:
    PersistenceControl
): Promise<ExtensionModule> {
  activeWorkspaceRoot =
    workspace;

  activePersistenceControl =
    control;

  const extensionPath =
    require.resolve(
      "./extension"
    );

  delete require.cache[
    extensionPath
  ];

  // AEGIS_C09_PURGE_PRELOADED_CORE_CACHE
  for (const cachedModulePath of Object.keys(require.cache)) {
    if (/[\\/]packages[\\/]aegis-core[\\/]/.test(cachedModulePath)) {
      delete require.cache[cachedModulePath];
    }
  }

  const extension =
    require(
      "./extension"
    ) as ExtensionModule;

  await extension.activate({
    subscriptions: {
      push(): void {},
    },
  });

  return extension;
}

async function deactivateAndUnload(
  extension:
    ExtensionModule | null
): Promise<void> {
  if (extension !== null) {
    await extension.deactivate();
  }

  const extensionPath =
    require.resolve(
      "./extension"
    );

  delete require.cache[
    extensionPath
  ];
}

function stateRevision(
  state:
    Record<string, unknown>
): number {
  const revision =
    state.revision;

  if (
    typeof revision !==
      "number" ||
    !Number.isInteger(
      revision
    )
  ) {
    throw new Error(
      "CANONICAL_REVISION_NOT_INTEGER"
    );
  }

  return revision;
}

function assertStateContainsStatus(
  state:
    Record<string, unknown>,
  expectedStatus:
    string
): void {
  assert.ok(
    JSON.stringify(
      state
    ).includes(
      expectedStatus
    ),
    "Expected canonical state to contain status " +
      expectedStatus
  );
}

test(
  "C-09 extension persists and reloads canonical authority through a real runtime round trip",
  async () => {
    const harness =
      installModuleHarness();

    const workspace =
      createWorkspace(
        "round-trip"
      );

    let extension:
      ExtensionModule | null =
        null;

    try {
      const firstControl =
        createPersistenceControl();

      extension =
        await loadAndActivateExtension(
          workspace,
          firstControl
        );

      const snapshotPath =
        snapshotPathFor(
          workspace
        );

      assert.equal(
        fs.existsSync(
          snapshotPath
        ),
        true
      );

      const stateManager =
        latestStateManager();

      stateManager.setWarning(
        "C09_RUNTIME_ROUND_TRIP_WARNING"
      );

      await deactivateAndUnload(
        extension
      );

      extension = null;

      const persistedText =
        fs.readFileSync(
          snapshotPath,
          "utf8"
        );

      const persistedStore =
        actualCanonicalModule
          .CanonicalAuthorityStateStore
          .hydrateSnapshotJson(
            persistedText
          );

      const persistedState =
        persistedStore.getState();

      assertStateContainsStatus(
        persistedState,
        "WARNING"
      );

      const persistedRevision =
        stateRevision(
          persistedState
        );

      const secondControl =
        createPersistenceControl();

      extension =
        await loadAndActivateExtension(
          workspace,
          secondControl
        );

      assert.ok(
        secondControl.loadCount >= 1
      );

      assert.ok(
        secondControl
          .loadedStates
          .length >= 1
      );

      const loadedState =
        secondControl
          .loadedStates[0];

      assert.equal(
        stateRevision(
          loadedState
        ),
        persistedRevision
      );

      assertStateContainsStatus(
        loadedState,
        "WARNING"
      );

      await deactivateAndUnload(
        extension
      );

      extension = null;
    }
    finally {
      await deactivateAndUnload(
        extension
      ).catch(
        () => undefined
      );

      harness.restore();

      fs.rmSync(
        workspace,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "C-09 extension fails closed for malformed tampered and cross-workspace canonical snapshots",
  async () => {
    const harness =
      installModuleHarness();

    const sourceWorkspace =
      createWorkspace(
        "fail-closed-source"
      );

    const workspaces:
      string[] = [
        sourceWorkspace,
      ];

    let extension:
      ExtensionModule | null =
        null;

    const originalConsoleError =
      console.error;

    const originalConsoleWarn =
      console.warn;

    console.error =
      (): void => {};

    console.warn =
      (): void => {};

    try {
      const sourceControl =
        createPersistenceControl();

      extension =
        await loadAndActivateExtension(
          sourceWorkspace,
          sourceControl
        );

      await deactivateAndUnload(
        extension
      );

      extension = null;

      const validSnapshot =
        fs.readFileSync(
          snapshotPathFor(
            sourceWorkspace
          ),
          "utf8"
        );

      const tamperedSnapshot =
        validSnapshot.replace(
          /"revision":(\d+)/,
          (
            _match,
            value: string
          ) =>
            '"revision":' +
            String(
              Number(value) + 1
            )
        );

      assert.notEqual(
        tamperedSnapshot,
        validSnapshot
      );

      const cases = [
        {
          label:
            "malformed",

          content:
            "{\n",
        },

        {
          label:
            "tampered",

          content:
            tamperedSnapshot,
        },

        {
          label:
            "cross-workspace",

          content:
            validSnapshot,
        },
      ] as const;

      for (
        const testCase of
        cases
      ) {
        const workspace =
          createWorkspace(
            testCase.label
          );

        workspaces.push(
          workspace
        );

        const snapshotPath =
          snapshotPathFor(
            workspace
          );

        fs.mkdirSync(
          path.dirname(
            snapshotPath
          ),
          {
            recursive: true,
          }
        );

        fs.writeFileSync(
          snapshotPath,
          testCase.content,
          "utf8"
        );

        const beforeBytes =
          fs.readFileSync(
            snapshotPath
          );

        const control =
          createPersistenceControl();

        extension =
          await loadAndActivateExtension(
            workspace,
            control
          );

        await deactivateAndUnload(
          extension
        );

        extension = null;

        const afterBytes =
          fs.readFileSync(
            snapshotPath
          );

        assert.deepEqual(
          afterBytes,
          beforeBytes,
          testCase.label
        );

        assert.equal(
          control.saveCount,
          0,
          testCase.label
        );

        assert.equal(
          control.loadCount,
          1,
          testCase.label
        );
      }
    }
    finally {
      console.error =
        originalConsoleError;

      console.warn =
        originalConsoleWarn;

      await deactivateAndUnload(
        extension
      ).catch(
        () => undefined
      );

      harness.restore();

      for (
        const workspace of
        workspaces
      ) {
        fs.rmSync(
          workspace,
          {
            recursive: true,
            force: true,
          }
        );
      }
    }
  }
);

test(
  "C-09 extension serializes queued saves reports failures and drains the stable persistence tail before deactivation",
  async () => {
    const harness =
      installModuleHarness();

    const workspaces:
      string[] = [];

    let extension:
      ExtensionModule | null =
        null;

    const unhandled:
      unknown[] = [];

    const onUnhandled =
      (reason: unknown):
      void => {
        unhandled.push(
          reason
        );
      };

    process.on(
      "unhandledRejection",
      onUnhandled
    );

    try {
      const queueWorkspace =
        createWorkspace(
          "queue-drain"
        );

      workspaces.push(
        queueWorkspace
      );

      const queueControl =
        createPersistenceControl();

      extension =
        await loadAndActivateExtension(
          queueWorkspace,
          queueControl
        );

      const baselineSaveCount =
        queueControl
          .savedStates
          .length;

      const gate =
        deferred();

      const started =
        deferred();

      queueControl.delayNextSave = {
        gate,
        started,
      };

      const stateManager =
        latestStateManager();

      stateManager.setWarning(
        "C09_RUNTIME_DELAYED_SAVE"
      );

      stateManager.setBlocked(
        "C09_RUNTIME_QUEUED_SAVE"
      );

      let deactivationSettled =
        false;

      const deactivation =
        extension
          .deactivate()
          .then(() => {
            deactivationSettled =
              true;
          });

      await started.promise;
      await Promise.resolve();

      assert.equal(
        deactivationSettled,
        false
      );

      assert.equal(
        queueControl
          .maximumConcurrentSaveCount,
        1
      );

      gate.resolve();

      await deactivation;

      extension = null;

      const mutationStates =
        queueControl
          .savedStates
          .slice(
            baselineSaveCount
          );

      assert.ok(
        mutationStates.length >= 2
      );

      const mutationRevisions =
        mutationStates.map(
          stateRevision
        );

      for (
        let index = 1;
        index <
        mutationRevisions.length;
        index++
      ) {
        assert.ok(
          mutationRevisions[index] >
            mutationRevisions[
              index - 1
            ]
        );
      }

      assert.deepEqual(
        queueControl
          .saveCompletionOrder,
        [
          ...queueControl
            .saveCompletionOrder,
        ].sort(
          (
            left,
            right
          ) =>
            left - right
        )
      );

      assert.equal(
        queueControl
          .maximumConcurrentSaveCount,
        1
      );

      await deactivateAndUnload(
        null
      );

      const failureWorkspace =
        createWorkspace(
          "failure-drain"
        );

      workspaces.push(
        failureWorkspace
      );

      const failureControl =
        createPersistenceControl();

      extension =
        await loadAndActivateExtension(
          failureWorkspace,
          failureControl
        );

      const failureStateManager =
        latestStateManager();

      const failureObserved =
        deferred();

      const retryGate =
        deferred();

      const retryStarted =
        deferred();

      failureControl
        .failureObserved =
          failureObserved;

      failureControl
        .failNextSave =
          true;

      failureControl
        .delayAfterFailure = {
          gate:
            retryGate,

          started:
            retryStarted,
        };

      failureStateManager.setBlocked(
        "C09_RUNTIME_FAILURE_TRIGGER"
      );

      await failureObserved.promise;

      let failureDeactivationSettled =
        false;

      const failureDeactivation =
        extension
          .deactivate()
          .then(() => {
            failureDeactivationSettled =
              true;
          });

      await retryStarted.promise;
      await Promise.resolve();

      assert.equal(
        failureStateManager
          .warningMessages
          .some(
            message =>
              message.includes(
                "Authority continuity cannot be confirmed."
              )
          ),
        true
      );

      assert.equal(
        failureDeactivationSettled,
        false
      );

      retryGate.resolve();

      await failureDeactivation;

      extension = null;

      await new Promise<void>(
        resolve => {
          setImmediate(
            resolve
          );
        }
      );

      assert.deepEqual(
        unhandled,
        []
      );

      assert.equal(
        failureControl
          .maximumConcurrentSaveCount,
        1
      );
    }
    finally {
      process.off(
        "unhandledRejection",
        onUnhandled
      );

      await deactivateAndUnload(
        extension
      ).catch(
        () => undefined
      );

      harness.restore();

      for (
        const workspace of
        workspaces
      ) {
        fs.rmSync(
          workspace,
          {
            recursive: true,
            force: true,
          }
        );
      }
    }
  }
);