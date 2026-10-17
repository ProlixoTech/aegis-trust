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
} from "./safetyKernelV31AuthoritySnapshotBindingComposition";

import type {
  SafetyKernelV31AllowedExecutionCoordinatorComposition,
} from "./safetyKernelV31AllowedExecutionCoordinatorComposition";

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
  SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_COMPOSITION_INVARIANT,
  createSafetyKernelV31TransactionReviewPipelineComposition,
} from "./safetyKernelV31TransactionReviewPipelineComposition";

function createNoCallInputs(): {
  transactionService:
    SafetyKernelV31TransactionService;

  transactionSessionStore:
    SafetyKernelV31TransactionSessionStore;

  allowedExecutionBindingStore:
    SafetyKernelV31AllowedExecutionSessionBindingStore;

  allowedExecutionCoordinatorComposition:
    SafetyKernelV31AllowedExecutionCoordinatorComposition;

  counters: {
    reviewCalls: number;
    executionCalls: number;
    verificationCalls: number;
    authorityReads: number;
    indexReads: number;
  };
} {
  const counters = {
    reviewCalls: 0,
    executionCalls: 0,
    verificationCalls: 0,
    authorityReads: 0,
    indexReads: 0,
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
    }) as SafetyKernelV31AllowedExecutionCoordinatorComposition;

  return {
    transactionService,
    transactionSessionStore,
    allowedExecutionBindingStore,
    allowedExecutionCoordinatorComposition,
    counters,
  };
}

test("pipeline composition invariant remains detached and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_COMPOSITION_INVARIANT,
    {
      PIPELINE_CONSTRUCTED_EXACTLY_ONCE: true,
      PIPELINE_RECEIVES_EXACT_TRANSACTION_SERVICE_INSTANCE: true,
      PIPELINE_RECEIVES_EXACT_TRANSACTION_SESSION_STORE_INSTANCE: true,
      PIPELINE_RECEIVES_EXACT_BINDING_STORE_INSTANCE: true,
      PIPELINE_RECEIVES_EXACT_A2G_COORDINATOR_INSTANCE: true,
      A2G_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      TRANSACTION_SERVICE_REFERENCE_CLONED: false,
      SESSION_STORE_REFERENCE_CLONED: false,
      BINDING_STORE_REFERENCE_CLONED: false,
      A2G_COMPOSITION_REFERENCE_CLONED: false,
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
      CACHE_CREATED: false,
      OUTPUT_OBJECT_FROZEN: true,
      DEFAULT_PIPELINE_FACTORY_MODIFIED: false,
      RUNTIME_CONTROLLER_CONNECTED: false,
      EXTENSION_CONNECTED: false,
      NODE_PROCESS_ADAPTER_CONNECTED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("factory returns a frozen pipeline and A2g composition bundle", () => {
  const inputs = createNoCallInputs();

  const composition =
    createSafetyKernelV31TransactionReviewPipelineComposition({
      transactionService:
        inputs.transactionService,
      transactionSessionStore:
        inputs.transactionSessionStore,
      allowedExecutionBindingStore:
        inputs.allowedExecutionBindingStore,
      allowedExecutionCoordinatorComposition:
        inputs.allowedExecutionCoordinatorComposition,
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    composition.pipeline instanceof
      SafetyKernelV31TransactionReviewPipeline,
    true
  );

  assert.equal(
    composition.allowedExecutionCoordinatorComposition,
    inputs.allowedExecutionCoordinatorComposition
  );
});

test("pipeline receives the exact four dependency instances", () => {
  const inputs = createNoCallInputs();

  const composition =
    createSafetyKernelV31TransactionReviewPipelineComposition({
      transactionService:
        inputs.transactionService,
      transactionSessionStore:
        inputs.transactionSessionStore,
      allowedExecutionBindingStore:
        inputs.allowedExecutionBindingStore,
      allowedExecutionCoordinatorComposition:
        inputs.allowedExecutionCoordinatorComposition,
    });

  const internals =
    composition.pipeline as unknown as {
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
    internals.transactionService,
    inputs.transactionService
  );

  assert.equal(
    internals.transactionSessionStore,
    inputs.transactionSessionStore
  );

  assert.equal(
    internals.allowedExecutionBindingStore,
    inputs.allowedExecutionBindingStore
  );

  assert.equal(
    internals.allowedExecutionCoordinator,
    inputs.allowedExecutionCoordinatorComposition.coordinator
  );
});

test("composition performs no review, execute, coordinate, verify, or state mutation", () => {
  const inputs = createNoCallInputs();

  const composition =
    createSafetyKernelV31TransactionReviewPipelineComposition({
      transactionService:
        inputs.transactionService,
      transactionSessionStore:
        inputs.transactionSessionStore,
      allowedExecutionBindingStore:
        inputs.allowedExecutionBindingStore,
      allowedExecutionCoordinatorComposition:
        inputs.allowedExecutionCoordinatorComposition,
    });

  const coordinatorInternals =
    inputs.allowedExecutionCoordinatorComposition
      .coordinator as unknown as {
        readonly claimedSessions:
          Set<string>;
      };

  assert.equal(
    inputs.counters.reviewCalls,
    0
  );

  assert.equal(
    inputs.counters.executionCalls,
    0
  );

  assert.equal(
    inputs.counters.verificationCalls,
    0
  );

  assert.equal(
    inputs.counters.authorityReads,
    0
  );

  assert.equal(
    inputs.counters.indexReads,
    0
  );

  assert.equal(
    inputs.transactionSessionStore.size,
    0
  );

  assert.equal(
    inputs.allowedExecutionBindingStore.size,
    0
  );

  assert.equal(
    coordinatorInternals.claimedSessions.size,
    0
  );

  assert.equal(
    composition.pipeline instanceof
      SafetyKernelV31TransactionReviewPipeline,
    true
  );
});

test("A2g composition reference is reused unchanged", () => {
  const inputs = createNoCallInputs();

  const coordinator =
    inputs.allowedExecutionCoordinatorComposition
      .coordinator;

  const authorityBindingComposition =
    inputs.allowedExecutionCoordinatorComposition
      .authorityBindingComposition;

  const composition =
    createSafetyKernelV31TransactionReviewPipelineComposition({
      transactionService:
        inputs.transactionService,
      transactionSessionStore:
        inputs.transactionSessionStore,
      allowedExecutionBindingStore:
        inputs.allowedExecutionBindingStore,
      allowedExecutionCoordinatorComposition:
        inputs.allowedExecutionCoordinatorComposition,
    });

  assert.equal(
    composition.allowedExecutionCoordinatorComposition,
    inputs.allowedExecutionCoordinatorComposition
  );

  assert.equal(
    composition.allowedExecutionCoordinatorComposition
      .coordinator,
    coordinator
  );

  assert.equal(
    composition.allowedExecutionCoordinatorComposition
      .authorityBindingComposition,
    authorityBindingComposition
  );

  assert.equal(
    inputs.counters.reviewCalls,
    0
  );

  assert.equal(
    inputs.counters.executionCalls,
    0
  );

  assert.equal(
    inputs.counters.verificationCalls,
    0
  );
});