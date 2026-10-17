import test from "node:test";
import assert from "node:assert/strict";

import type {
  AegisExecutionPort,
  AegisExecutionRequest,
  AegisExecutionResult,
} from "../packages/aegis-core";

import {
  SafetyKernelV31AllowedExecutionCoordinator,
  type SafetyKernelV31AllowedExecutionBindingVerifier,
} from "./safetyKernelV31AllowedExecutionCoordinator";

import type {
  SafetyKernelV31AuthoritySnapshotBindingComposition,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition,
} from "./safetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition";

import {
  SafetyKernelV31TransactionReviewPipeline,
  type SafetyKernelV31TransactionReviewPipelineAllowedExecutionCoordinationPort,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31TransactionService,
} from "../packages/aegis-core";

import {
  SafetyKernelV31TransactionSessionStore,
} from "../packages/aegis-core";

import {
  SafetyKernelV31AllowedExecutionSessionBindingStore,
} from "../packages/aegis-core";

import {
  SAFETY_KERNEL_V31_NODE_PROCESS_TRANSACTION_REVIEW_PIPELINE_COMPOSITION_INVARIANT,
  createSafetyKernelV31NodeProcessTransactionReviewPipelineComposition,
} from "./safetyKernelV31NodeProcessTransactionReviewPipelineComposition";

function createNoCallInputs(): {
  transactionService:
    SafetyKernelV31TransactionService;

  transactionSessionStore:
    SafetyKernelV31TransactionSessionStore;

  allowedExecutionBindingStore:
    SafetyKernelV31AllowedExecutionSessionBindingStore;

  nodeProcessAllowedExecutionCoordinatorComposition:
    SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition;

  counters: {
    reviewCalls: number;
    executionCalls: number;
    verificationCalls: number;
    authorityReads: number;
    processSpawnerCalls: number;
  };
} {
  const counters = {
    reviewCalls: 0,
    executionCalls: 0,
    verificationCalls: 0,
    authorityReads: 0,
    processSpawnerCalls: 0,
  };

  const transactionService = {
    async reviewAndCommit(): Promise<never> {
      counters.reviewCalls += 1;

      throw new Error(
        "REVIEW_DURING_COMPOSITION"
      );
    },
  } as unknown as SafetyKernelV31TransactionService;

  const transactionSessionStore =
    new SafetyKernelV31TransactionSessionStore();

  const allowedExecutionBindingStore =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  const execution:
    AegisExecutionPort = {
      async execute(
        _request: AegisExecutionRequest
      ): Promise<AegisExecutionResult> {
        counters.executionCalls += 1;

        throw new Error(
          "EXECUTION_DURING_COMPOSITION"
        );
      },
    };

  const verifier:
    SafetyKernelV31AllowedExecutionBindingVerifier = {
      async verify() {
        counters.verificationCalls += 1;

        throw new Error(
          "VERIFICATION_DURING_COMPOSITION"
        );
      },
    };

  const coordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      execution,
      verifier
    );

  const authorityBindingComposition = {
    readPort: {
      async readCurrentBinding(): Promise<never> {
        counters.authorityReads += 1;

        throw new Error(
          "AUTHORITY_READ_DURING_COMPOSITION"
        );
      },
    },
    verifier,
  } as unknown as SafetyKernelV31AuthoritySnapshotBindingComposition;

  const allowedExecutionCoordinatorComposition =
    Object.freeze({
      coordinator,
      authorityBindingComposition,
    });

  const nodeProcessExecutionAdapterComposition =
    Object.freeze({
      nodeProcessExecutionAdapter: execution,
      extensionComposition: Object.freeze({}),
    });

  const nodeProcessAllowedExecutionCoordinatorComposition =
    Object.freeze({
      allowedExecutionCoordinatorComposition,
      nodeProcessExecutionAdapterComposition,
    }) as unknown as
      SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition;

  return {
    transactionService,
    transactionSessionStore,
    allowedExecutionBindingStore,
    nodeProcessAllowedExecutionCoordinatorComposition,
    counters,
  };
}

test("node process pipeline composition invariant remains detached and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_NODE_PROCESS_TRANSACTION_REVIEW_PIPELINE_COMPOSITION_INVARIANT,
    {
      A2H_FACTORY_CALLED_EXACTLY_ONCE: true,
      NEW_PIPELINE_CONSTRUCTED_EXACTLY_ONCE: true,
      PIPELINE_RECEIVES_EXACT_TRANSACTION_SERVICE_REFERENCE: true,
      PIPELINE_RECEIVES_EXACT_TRANSACTION_SESSION_STORE_REFERENCE: true,
      PIPELINE_RECEIVES_EXACT_ALLOWED_EXECUTION_BINDING_STORE_REFERENCE: true,
      PIPELINE_RECEIVES_EXACT_A2L_COORDINATOR_COMPOSITION_REFERENCE: true,
      A2L_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      TRANSACTION_SERVICE_REFERENCE_CLONED: false,
      TRANSACTION_SESSION_STORE_REFERENCE_CLONED: false,
      ALLOWED_EXECUTION_BINDING_STORE_REFERENCE_CLONED: false,
      A2L_COMPOSITION_REFERENCE_CLONED: false,
      OUTPUT_OBJECT_FROZEN: true,
      A2L_COORDINATOR_CONNECTED_TO_NEW_PIPELINE: true,
      REVIEW_CALL_DURING_COMPOSITION: false,
      EXECUTION_CALL_DURING_COMPOSITION: false,
      COORDINATION_CALL_DURING_COMPOSITION: false,
      VERIFICATION_CALL_DURING_COMPOSITION: false,
      AUTHORITY_READ_DURING_COMPOSITION: false,
      INDEX_READ_DURING_COMPOSITION: false,
      BASELINE_FILE_READ_DURING_COMPOSITION: false,
      SESSION_CREATED_DURING_COMPOSITION: false,
      SESSION_CLAIM_CREATED_DURING_COMPOSITION: false,
      BINDING_REGISTERED_DURING_COMPOSITION: false,
      NODE_PROCESS_SPAWNER_CALLED_DURING_COMPOSITION: false,
      DEFAULT_PIPELINE_FACTORY_MODIFIED: false,
      DEFAULT_RUNTIME_CONTROLLER_FACTORY_MODIFIED: false,
      RUNTIME_CONTROLLER_CONNECTED: false,
      EXTENSION_ACTIVATION_CONNECTED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("factory returns a frozen pipeline and A2l composition bundle", () => {
  const inputs = createNoCallInputs();

  const composition =
    createSafetyKernelV31NodeProcessTransactionReviewPipelineComposition({
      transactionService:
        inputs.transactionService,
      transactionSessionStore:
        inputs.transactionSessionStore,
      allowedExecutionBindingStore:
        inputs.allowedExecutionBindingStore,
      nodeProcessAllowedExecutionCoordinatorComposition:
        inputs.nodeProcessAllowedExecutionCoordinatorComposition,
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    composition.transactionReviewPipelineComposition
      .pipeline instanceof
      SafetyKernelV31TransactionReviewPipeline,
    true
  );

  assert.equal(
    composition.nodeProcessAllowedExecutionCoordinatorComposition,
    inputs.nodeProcessAllowedExecutionCoordinatorComposition
  );
});

test("new pipeline receives the exact four dependency references", () => {
  const inputs = createNoCallInputs();

  const composition =
    createSafetyKernelV31NodeProcessTransactionReviewPipelineComposition({
      transactionService:
        inputs.transactionService,
      transactionSessionStore:
        inputs.transactionSessionStore,
      allowedExecutionBindingStore:
        inputs.allowedExecutionBindingStore,
      nodeProcessAllowedExecutionCoordinatorComposition:
        inputs.nodeProcessAllowedExecutionCoordinatorComposition,
    });

  const pipelineInternals =
    composition.transactionReviewPipelineComposition
      .pipeline as unknown as {
        readonly transactionService:
          SafetyKernelV31TransactionService;

        readonly transactionSessionStore:
          SafetyKernelV31TransactionSessionStore;

        readonly allowedExecutionBindingStore:
          SafetyKernelV31AllowedExecutionSessionBindingStore | null;

        readonly allowedExecutionCoordinator:
          SafetyKernelV31TransactionReviewPipelineAllowedExecutionCoordinationPort | null;
      };

  assert.equal(
    pipelineInternals.transactionService,
    inputs.transactionService
  );

  assert.equal(
    pipelineInternals.transactionSessionStore,
    inputs.transactionSessionStore
  );

  assert.equal(
    pipelineInternals.allowedExecutionBindingStore,
    inputs.allowedExecutionBindingStore
  );

  assert.equal(
    pipelineInternals.allowedExecutionCoordinator,
    inputs.nodeProcessAllowedExecutionCoordinatorComposition
      .allowedExecutionCoordinatorComposition
      .coordinator
  );
});

test("composition performs no review, execution, coordination, verification, or state mutation", () => {
  const inputs = createNoCallInputs();

  const composition =
    createSafetyKernelV31NodeProcessTransactionReviewPipelineComposition({
      transactionService:
        inputs.transactionService,
      transactionSessionStore:
        inputs.transactionSessionStore,
      allowedExecutionBindingStore:
        inputs.allowedExecutionBindingStore,
      nodeProcessAllowedExecutionCoordinatorComposition:
        inputs.nodeProcessAllowedExecutionCoordinatorComposition,
    });

  const coordinatorInternals =
    inputs.nodeProcessAllowedExecutionCoordinatorComposition
      .allowedExecutionCoordinatorComposition
      .coordinator as unknown as {
        readonly claimedSessions:
          Set<string>;
      };

  assert.equal(inputs.counters.reviewCalls, 0);
  assert.equal(inputs.counters.executionCalls, 0);
  assert.equal(inputs.counters.verificationCalls, 0);
  assert.equal(inputs.counters.authorityReads, 0);
  assert.equal(inputs.counters.processSpawnerCalls, 0);
  assert.equal(inputs.transactionSessionStore.size, 0);
  assert.equal(inputs.allowedExecutionBindingStore.size, 0);
  assert.equal(coordinatorInternals.claimedSessions.size, 0);

  assert.equal(
    composition.transactionReviewPipelineComposition
      .pipeline instanceof
      SafetyKernelV31TransactionReviewPipeline,
    true
  );
});

test("A2l and nested coordinator composition references are reused unchanged", () => {
  const inputs = createNoCallInputs();

  const a2lComposition =
    inputs.nodeProcessAllowedExecutionCoordinatorComposition;

  const allowedExecutionCoordinatorComposition =
    a2lComposition.allowedExecutionCoordinatorComposition;

  const coordinator =
    allowedExecutionCoordinatorComposition.coordinator;

  const authorityBindingComposition =
    allowedExecutionCoordinatorComposition
      .authorityBindingComposition;

  const composition =
    createSafetyKernelV31NodeProcessTransactionReviewPipelineComposition({
      transactionService:
        inputs.transactionService,
      transactionSessionStore:
        inputs.transactionSessionStore,
      allowedExecutionBindingStore:
        inputs.allowedExecutionBindingStore,
      nodeProcessAllowedExecutionCoordinatorComposition:
        a2lComposition,
    });

  assert.equal(
    composition.nodeProcessAllowedExecutionCoordinatorComposition,
    a2lComposition
  );

  assert.equal(
    composition.transactionReviewPipelineComposition
      .allowedExecutionCoordinatorComposition,
    allowedExecutionCoordinatorComposition
  );

  assert.equal(
    composition.transactionReviewPipelineComposition
      .allowedExecutionCoordinatorComposition
      .coordinator,
    coordinator
  );

  assert.equal(
    composition.transactionReviewPipelineComposition
      .allowedExecutionCoordinatorComposition
      .authorityBindingComposition,
    authorityBindingComposition
  );

  assert.equal(inputs.counters.reviewCalls, 0);
  assert.equal(inputs.counters.executionCalls, 0);
  assert.equal(inputs.counters.verificationCalls, 0);
});