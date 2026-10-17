import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  NodeProcessExecutionAdapter,
  type NodeProcessSpawner,
} from "./nodeProcessExecutionAdapter";

import type {
  SafetyKernelV31CanonicalAuthorityReader,
  SafetyKernelV31SnapshotTargetIndexReader,
} from "../packages/aegis-core";

import {
  SafetyKernelV31TransactionService,
} from "../packages/aegis-core";

import {
  SafetyKernelV31TransactionSessionStore,
} from "../packages/aegis-core";

import {
  SafetyKernelV31AllowedExecutionSessionBindingStore,
} from "../packages/aegis-core";

import {
  SAFETY_KERNEL_V31_NODE_PROCESS_EXTENSION_BOOTSTRAP_COMPOSITION_INVARIANT,
  createSafetyKernelV31NodeProcessExtensionBootstrapComposition,
} from "./safetyKernelV31NodeProcessExtensionBootstrapComposition";

interface HarnessCounters {
  authorityReads: number;
  indexReads: number;
  spawnCalls: number;
}

function createHarness() {
  const tempRoot =
    fs.mkdtempSync(
      path.join(
        os.tmpdir(),
        "aegis-a2p-bootstrap-"
      )
    );

  const projectRoot =
    path.join(
      tempRoot,
      "workspace"
    );

  const aegisDir =
    path.join(
      projectRoot,
      ".aegis"
    );

  const counters: HarnessCounters = {
    authorityReads: 0,
    indexReads: 0,
    spawnCalls: 0,
  };

  const authorityReader:
    SafetyKernelV31CanonicalAuthorityReader = {
      getState(): never {
        counters.authorityReads += 1;
        throw new Error(
          "AUTHORITY_READ_DURING_COMPOSITION"
        );
      },
    };

  const targetReader:
    SafetyKernelV31SnapshotTargetIndexReader = {
      targetId: "target-a",
      relativePath: "src/example.ts",
      snapshotIndexFile: "target-a.json",

      async readIndex(): Promise<never> {
        counters.indexReads += 1;
        throw new Error(
          "INDEX_READ_DURING_COMPOSITION"
        );
      },
    };

  const targetReaders =
    [targetReader] as const;

  const nodeProcessSpawner:
    NodeProcessSpawner = () => {
      counters.spawnCalls += 1;
      throw new Error(
        "NODE_PROCESS_SPAWNER_CALLED_DURING_COMPOSITION"
      );
    };

  const composition =
    createSafetyKernelV31NodeProcessExtensionBootstrapComposition({
      authorityReader,
      targetReaders,
      projectRoot,
      aegisDir,
      nodeProcessSpawner,
    });

  return {
    tempRoot,
    projectRoot,
    aegisDir,
    counters,
    authorityReader,
    targetReaders,
    nodeProcessSpawner,
    composition,
  };
}

function cleanup(tempRoot: string): void {
  fs.rmSync(
    tempRoot,
    {
      recursive: true,
      force: true,
    }
  );
}

test("A2p invariant remains detached, explicit-spawner-only, and development-before-connection", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_NODE_PROCESS_EXTENSION_BOOTSTRAP_COMPOSITION_INVARIANT,
    {
      DEVELOPMENT_COMPLETE_BEFORE_CONNECTION: true,
      REQUIRED_INPUT_COUNT: 5,
      OPTIONAL_INPUT_COUNT: 0,
      REQUIRED_NODE_PROCESS_SPAWNER_INPUT: true,
      DEFAULT_REAL_SPAWNER_USED: false,
      NODE_PROCESS_EXECUTION_ADAPTER_CONSTRUCTED_EXACTLY_ONCE: true,
      NODE_PROCESS_ADAPTER_RECEIVES_EXACT_INPUT_SPAWNER: true,
      TRANSACTION_SERVICE_CREATE_FOR_AEGIS_DIR_CALLED_EXACTLY_ONCE: true,
      TRANSACTION_SESSION_STORE_CONSTRUCTED_EXACTLY_ONCE: true,
      ALLOWED_EXECUTION_BINDING_STORE_CONSTRUCTED_EXACTLY_ONCE: true,
      A2F_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2G_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2H_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2I_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2J_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2K_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2L_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2M_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2N_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2O_FACTORY_CALLED_EXACTLY_ONCE: true,
      INPUT_REFERENCES_CLONED: false,
      CONSTRUCTED_REFERENCES_REUSED_UNCHANGED: true,
      AUTHORITY_READ_DURING_COMPOSITION: false,
      INDEX_READ_DURING_COMPOSITION: false,
      BASELINE_FILE_READ_DURING_COMPOSITION: false,
      NODE_PROCESS_SPAWNER_CALLED_DURING_COMPOSITION: false,
      REVIEW_CALL_DURING_COMPOSITION: false,
      SESSION_CREATED_DURING_COMPOSITION: false,
      BINDING_REGISTERED_DURING_COMPOSITION: false,
      AUTHORITY_BOUND_DURING_COMPOSITION: false,
      COORDINATION_CALL_DURING_COMPOSITION: false,
      EXECUTION_CALL_DURING_COMPOSITION: false,
      EVIDENCE_WRITE_DURING_COMPOSITION: false,
      RECEIPT_WRITE_DURING_COMPOSITION: false,
      LEDGER_WRITE_DURING_COMPOSITION: false,
      AEGIS_DIR_FILE_CREATION_DURING_COMPOSITION: false,
      OUTPUT_OBJECT_FROZEN: true,
      EXTENSION_TS_MODIFIED: false,
      EXTENSION_ACTIVATION_CONNECTED: false,
      VSCODE_COMMAND_REGISTRATION_DURING_COMPOSITION: false,
      VSCODE_SUBSCRIPTION_MUTATION_DURING_COMPOSITION: false,
      EXISTING_EXTENSION_REVIEW_ONLY_PATH_UNCHANGED: true,
      DIRECT_RUNTIME_CONTROLLER_BOOTSTRAP_UNCHANGED: true,
      CONNECTION_SPECIFIC_READER_ADAPTER_DEVELOPMENT_COMPLETE: false,
      CONNECTION_ALLOWED_AFTER_A2P: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
      FULL_L5C_COMPLETE: false,
      PRODUCT_PASS: false,
      FINAL_PASS: false,
      RELEASE_READY: false,
      UPLOAD_READY: false,
    }
  );
});

test("factory returns one frozen detached bootstrap with exact constructed root types", () => {
  const harness = createHarness();

  try {
    const composition = harness.composition;

    assert.equal(
      Object.isFrozen(composition),
      true
    );

    assert.equal(
      composition.nodeProcessExecutionAdapter
        instanceof NodeProcessExecutionAdapter,
      true
    );

    assert.equal(
      composition.transactionService
        instanceof SafetyKernelV31TransactionService,
      true
    );

    assert.equal(
      composition.transactionSessionStore
        instanceof SafetyKernelV31TransactionSessionStore,
      true
    );

    assert.equal(
      composition.allowedExecutionBindingStore
        instanceof SafetyKernelV31AllowedExecutionSessionBindingStore,
      true
    );

    assert.equal(
      fs.existsSync(harness.aegisDir),
      false
    );

    assert.deepEqual(
      harness.counters,
      {
        authorityReads: 0,
        indexReads: 0,
        spawnCalls: 0,
      }
    );
  } finally {
    cleanup(harness.tempRoot);
  }
});

test("factory forwards exact authority, target, path, and required spawner references without cloning", () => {
  const harness = createHarness();

  try {
    const readPort =
      harness.composition
        .authorityBindingComposition
        .readPort as unknown as {
          readonly authorityReader:
            SafetyKernelV31CanonicalAuthorityReader;
          readonly targetReaders:
            readonly SafetyKernelV31SnapshotTargetIndexReader[];
          readonly projectRoot: string;
          readonly snapshotsDir: string;
        };

    const adapter =
      harness.composition
        .nodeProcessExecutionAdapter as unknown as {
          readonly spawnProcess:
            NodeProcessSpawner;
        };

    assert.equal(
      readPort.authorityReader,
      harness.authorityReader
    );

    assert.equal(
      readPort.targetReaders,
      harness.targetReaders
    );

    assert.equal(
      readPort.projectRoot,
      path.resolve(harness.projectRoot)
    );

    assert.equal(
      readPort.snapshotsDir,
      path.resolve(
        harness.aegisDir,
        "snapshots"
      )
    );

    assert.equal(
      adapter.spawnProcess,
      harness.nodeProcessSpawner
    );

    assert.deepEqual(
      harness.counters,
      {
        authorityReads: 0,
        indexReads: 0,
        spawnCalls: 0,
      }
    );
  } finally {
    cleanup(harness.tempRoot);
  }
});

test("factory builds the exact A2f through A2o composition graph with unchanged references", () => {
  const harness = createHarness();

  try {
    const root = harness.composition;

    const a2o =
      root.nodeProcessExtensionComposition;

    const a2n =
      a2o.nodeProcessRuntimeControllerComposition;

    const a2m =
      a2n.nodeProcessTransactionReviewPipelineComposition;

    const a2l =
      a2m.nodeProcessAllowedExecutionCoordinatorComposition;

    const a2k =
      a2l.nodeProcessExecutionAdapterComposition;

    const a2j =
      a2k.extensionComposition;

    const a2i =
      a2j.runtimeControllerComposition;

    const a2h =
      a2i.transactionReviewPipelineComposition;

    const a2g =
      a2h.allowedExecutionCoordinatorComposition;

    const a2f =
      a2g.authorityBindingComposition;

    assert.equal(
      a2f,
      root.authorityBindingComposition
    );

    assert.equal(
      a2k.nodeProcessExecutionAdapter,
      root.nodeProcessExecutionAdapter
    );

    assert.equal(
      a2l.nodeProcessExecutionAdapterComposition,
      a2k
    );

    assert.equal(
      a2m.nodeProcessAllowedExecutionCoordinatorComposition,
      a2l
    );

    assert.equal(
      a2n.nodeProcessTransactionReviewPipelineComposition,
      a2m
    );

    assert.equal(
      a2o.nodeProcessRuntimeControllerComposition,
      a2n
    );

    assert.equal(
      a2o.extensionComposition.runtimeControllerComposition,
      a2n.runtimeControllerComposition
    );

    assert.equal(
      a2j.runtimeControllerComposition,
      a2i
    );

    assert.equal(
      a2i.transactionReviewPipelineComposition,
      a2h
    );

    assert.equal(
      a2h.allowedExecutionCoordinatorComposition,
      a2g
    );

    assert.equal(
      a2g.authorityBindingComposition,
      a2f
    );

    assert.deepEqual(
      harness.counters,
      {
        authorityReads: 0,
        indexReads: 0,
        spawnCalls: 0,
      }
    );
  } finally {
    cleanup(harness.tempRoot);
  }
});

test("both pipeline branches reuse the exact service and stores without review, execution, evidence, or filesystem effects", () => {
  const harness = createHarness();

  try {
    const root = harness.composition;

    const a2o =
      root.nodeProcessExtensionComposition;

    const a2n =
      a2o.nodeProcessRuntimeControllerComposition;

    const a2m =
      a2n.nodeProcessTransactionReviewPipelineComposition;

    const finalPipeline =
      a2m.transactionReviewPipelineComposition
        .pipeline as unknown as {
          readonly transactionService:
            SafetyKernelV31TransactionService;
          readonly transactionSessionStore:
            SafetyKernelV31TransactionSessionStore;
          readonly allowedExecutionBindingStore:
            SafetyKernelV31AllowedExecutionSessionBindingStore;
        };

    const initialPipeline =
      a2m.nodeProcessAllowedExecutionCoordinatorComposition
        .nodeProcessExecutionAdapterComposition
        .extensionComposition
        .runtimeControllerComposition
        .transactionReviewPipelineComposition
        .pipeline as unknown as {
          readonly transactionService:
            SafetyKernelV31TransactionService;
          readonly transactionSessionStore:
            SafetyKernelV31TransactionSessionStore;
          readonly allowedExecutionBindingStore:
            SafetyKernelV31AllowedExecutionSessionBindingStore;
        };

    const finalCoordinator =
      a2m.transactionReviewPipelineComposition
        .allowedExecutionCoordinatorComposition
        .coordinator as unknown as {
          readonly execution: unknown;
          readonly bindingVerifier: unknown;
        };

    assert.equal(
      finalPipeline.transactionService,
      root.transactionService
    );

    assert.equal(
      finalPipeline.transactionSessionStore,
      root.transactionSessionStore
    );

    assert.equal(
      finalPipeline.allowedExecutionBindingStore,
      root.allowedExecutionBindingStore
    );

    assert.equal(
      initialPipeline.transactionService,
      root.transactionService
    );

    assert.equal(
      initialPipeline.transactionSessionStore,
      root.transactionSessionStore
    );

    assert.equal(
      initialPipeline.allowedExecutionBindingStore,
      root.allowedExecutionBindingStore
    );

    assert.equal(
      finalCoordinator.execution,
      root.nodeProcessExecutionAdapter
    );

    assert.equal(
      finalCoordinator.bindingVerifier,
      root.authorityBindingComposition.verifier
    );

    assert.equal(
      root.transactionSessionStore.size,
      0
    );

    assert.equal(
      root.allowedExecutionBindingStore.size,
      0
    );

    assert.equal(
      fs.existsSync(harness.aegisDir),
      false
    );

    assert.deepEqual(
      harness.counters,
      {
        authorityReads: 0,
        indexReads: 0,
        spawnCalls: 0,
      }
    );
  } finally {
    cleanup(harness.tempRoot);
  }
});