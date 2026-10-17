import test from "node:test";
import assert from "node:assert/strict";

import {
  SafetyKernelV31RuntimeController,
} from "./safetyKernelV31RuntimeController";

import type {
  SafetyKernelV31TransactionReviewPipeline,
} from "./safetyKernelV31TransactionReviewPipeline";

import type {
  SafetyKernelV31TransactionReviewPipelineComposition,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition,
} from "./safetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition";

import type {
  SafetyKernelV31NodeProcessTransactionReviewPipelineComposition,
} from "./safetyKernelV31NodeProcessTransactionReviewPipelineComposition";

import {
  SAFETY_KERNEL_V31_NODE_PROCESS_RUNTIME_CONTROLLER_COMPOSITION_INVARIANT,
  createSafetyKernelV31NodeProcessRuntimeControllerComposition,
} from "./safetyKernelV31NodeProcessRuntimeControllerComposition";

function createNoCallInput(): {
  nodeProcessTransactionReviewPipelineComposition:
    SafetyKernelV31NodeProcessTransactionReviewPipelineComposition;

  transactionReviewPipelineComposition:
    SafetyKernelV31TransactionReviewPipelineComposition;

  nodeProcessAllowedExecutionCoordinatorComposition:
    SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition;

  pipeline:
    SafetyKernelV31TransactionReviewPipeline;

  counters: {
    reviewCalls: number;
    readSessionCalls: number;
    confirmWarnCalls: number;
    completeAllowedExecutionCalls: number;
    bindAuthorityCalls: number;
    coordinationCalls: number;
    abortCalls: number;
    terminateWarnCalls: number;
    processSpawnerCalls: number;
  };
} {
  const counters = {
    reviewCalls: 0,
    readSessionCalls: 0,
    confirmWarnCalls: 0,
    completeAllowedExecutionCalls: 0,
    bindAuthorityCalls: 0,
    coordinationCalls: 0,
    abortCalls: 0,
    terminateWarnCalls: 0,
    processSpawnerCalls: 0,
  };

  const pipeline = {
    async review(): Promise<never> {
      counters.reviewCalls += 1;

      throw new Error(
        "REVIEW_DURING_COMPOSITION"
      );
    },

    readSession(): never {
      counters.readSessionCalls += 1;

      throw new Error(
        "READ_SESSION_DURING_COMPOSITION"
      );
    },

    async confirmWarnSession(): Promise<never> {
      counters.confirmWarnCalls += 1;

      throw new Error(
        "CONFIRM_WARN_DURING_COMPOSITION"
      );
    },

    async completeAllowedExecutionSession(): Promise<never> {
      counters.completeAllowedExecutionCalls += 1;

      throw new Error(
        "COMPLETE_ALLOWED_EXECUTION_DURING_COMPOSITION"
      );
    },

    bindAllowedExecutionSessionAuthority(): never {
      counters.bindAuthorityCalls += 1;

      throw new Error(
        "BIND_AUTHORITY_DURING_COMPOSITION"
      );
    },

    async coordinateAllowedExecutionSession(): Promise<never> {
      counters.coordinationCalls += 1;

      throw new Error(
        "COORDINATION_DURING_COMPOSITION"
      );
    },

    async abortAllowedExecutionSession(): Promise<never> {
      counters.abortCalls += 1;

      throw new Error(
        "ABORT_DURING_COMPOSITION"
      );
    },

    async terminateWarnSession(): Promise<never> {
      counters.terminateWarnCalls += 1;

      throw new Error(
        "TERMINATE_WARN_DURING_COMPOSITION"
      );
    },
  } as unknown as SafetyKernelV31TransactionReviewPipeline;

  const allowedExecutionCoordinatorComposition =
    Object.freeze({
      coordinator: Object.freeze({}),
      authorityBindingComposition: Object.freeze({}),
    });

  const transactionReviewPipelineComposition =
    Object.freeze({
      pipeline,
      allowedExecutionCoordinatorComposition,
    }) as unknown as
      SafetyKernelV31TransactionReviewPipelineComposition;

  const nodeProcessExecutionAdapterComposition =
    Object.freeze({
      nodeProcessExecutionAdapter: Object.freeze({
        async execute(): Promise<never> {
          counters.processSpawnerCalls += 1;

          throw new Error(
            "NODE_PROCESS_SPAWNER_DURING_COMPOSITION"
          );
        },
      }),
      extensionComposition: Object.freeze({}),
    });

  const nodeProcessAllowedExecutionCoordinatorComposition =
    Object.freeze({
      allowedExecutionCoordinatorComposition,
      nodeProcessExecutionAdapterComposition,
    }) as unknown as
      SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition;

  const nodeProcessTransactionReviewPipelineComposition =
    Object.freeze({
      transactionReviewPipelineComposition,
      nodeProcessAllowedExecutionCoordinatorComposition,
    }) as unknown as
      SafetyKernelV31NodeProcessTransactionReviewPipelineComposition;

  return {
    nodeProcessTransactionReviewPipelineComposition,
    transactionReviewPipelineComposition,
    nodeProcessAllowedExecutionCoordinatorComposition,
    pipeline,
    counters,
  };
}

test("node process Runtime Controller composition invariant remains detached from Extension and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_NODE_PROCESS_RUNTIME_CONTROLLER_COMPOSITION_INVARIANT,
    {
      A2I_FACTORY_CALLED_EXACTLY_ONCE: true,
      NEW_RUNTIME_CONTROLLER_CONSTRUCTED_EXACTLY_ONCE: true,
      RUNTIME_CONTROLLER_RECEIVES_EXACT_A2M_PIPELINE_INSTANCE: true,
      A2M_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      A2M_COMPOSITION_REFERENCE_CLONED: false,
      PIPELINE_REFERENCE_CLONED: false,
      OUTPUT_OBJECT_FROZEN: true,
      A2M_PIPELINE_CONNECTED_TO_NEW_RUNTIME_CONTROLLER: true,
      NODE_PROCESS_ADAPTER_BACKED_PIPELINE_CONNECTED_TO_RUNTIME_CONTROLLER: true,
      REVIEW_CALL_DURING_COMPOSITION: false,
      READ_SESSION_CALL_DURING_COMPOSITION: false,
      CONFIRM_WARN_CALL_DURING_COMPOSITION: false,
      COMPLETE_ALLOWED_EXECUTION_CALL_DURING_COMPOSITION: false,
      BIND_AUTHORITY_CALL_DURING_COMPOSITION: false,
      COORDINATION_CALL_DURING_COMPOSITION: false,
      ABORT_CALL_DURING_COMPOSITION: false,
      TERMINATE_WARN_CALL_DURING_COMPOSITION: false,
      EXECUTION_CALL_DURING_COMPOSITION: false,
      VERIFICATION_CALL_DURING_COMPOSITION: false,
      AUTHORITY_READ_DURING_COMPOSITION: false,
      INDEX_READ_DURING_COMPOSITION: false,
      BASELINE_FILE_READ_DURING_COMPOSITION: false,
      SESSION_CREATED_DURING_COMPOSITION: false,
      SESSION_CLAIM_CREATED_DURING_COMPOSITION: false,
      BINDING_REGISTERED_DURING_COMPOSITION: false,
      NODE_PROCESS_SPAWNER_CALLED_DURING_COMPOSITION: false,
      CACHE_CREATED: false,
      NEW_RUNTIME_CONTROLLER_CONNECTED_TO_EXTENSION_ACTIVATION: false,
      EXISTING_EXTENSION_REVIEW_ONLY_PATH_UNCHANGED: true,
      DEFAULT_RUNTIME_CONTROLLER_FACTORY_MODIFIED: false,
      DEFAULT_PIPELINE_FACTORY_MODIFIED: false,
      EXTENSION_FILE_MODIFIED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("factory returns a frozen Runtime Controller and A2m composition bundle", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessRuntimeControllerComposition({
      nodeProcessTransactionReviewPipelineComposition:
        inputs.nodeProcessTransactionReviewPipelineComposition,
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    composition.runtimeControllerComposition
      .runtimeController instanceof
      SafetyKernelV31RuntimeController,
    true
  );

  assert.equal(
    composition.nodeProcessTransactionReviewPipelineComposition,
    inputs.nodeProcessTransactionReviewPipelineComposition
  );
});

test("new Runtime Controller receives the exact A2m Pipeline instance", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessRuntimeControllerComposition({
      nodeProcessTransactionReviewPipelineComposition:
        inputs.nodeProcessTransactionReviewPipelineComposition,
    });

  const runtimeControllerInternals =
    composition.runtimeControllerComposition
      .runtimeController as unknown as {
        readonly pipeline: unknown;
      };

  assert.equal(
    runtimeControllerInternals.pipeline,
    inputs.pipeline
  );

  assert.equal(
    runtimeControllerInternals.pipeline,
    inputs.nodeProcessTransactionReviewPipelineComposition
      .transactionReviewPipelineComposition
      .pipeline
  );

  assert.equal(
    composition.runtimeControllerComposition
      .transactionReviewPipelineComposition,
    inputs.transactionReviewPipelineComposition
  );
});

test("composition performs no controller, Pipeline, execution, verification, or state calls", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessRuntimeControllerComposition({
      nodeProcessTransactionReviewPipelineComposition:
        inputs.nodeProcessTransactionReviewPipelineComposition,
    });

  assert.equal(inputs.counters.reviewCalls, 0);
  assert.equal(inputs.counters.readSessionCalls, 0);
  assert.equal(inputs.counters.confirmWarnCalls, 0);
  assert.equal(inputs.counters.completeAllowedExecutionCalls, 0);
  assert.equal(inputs.counters.bindAuthorityCalls, 0);
  assert.equal(inputs.counters.coordinationCalls, 0);
  assert.equal(inputs.counters.abortCalls, 0);
  assert.equal(inputs.counters.terminateWarnCalls, 0);
  assert.equal(inputs.counters.processSpawnerCalls, 0);

  assert.equal(
    composition.runtimeControllerComposition
      .runtimeController instanceof
      SafetyKernelV31RuntimeController,
    true
  );
});

test("A2m and all nested composition references are reused unchanged", () => {
  const inputs = createNoCallInput();

  const a2mComposition =
    inputs.nodeProcessTransactionReviewPipelineComposition;

  const transactionReviewPipelineComposition =
    a2mComposition.transactionReviewPipelineComposition;

  const nodeProcessAllowedExecutionCoordinatorComposition =
    a2mComposition.nodeProcessAllowedExecutionCoordinatorComposition;

  const pipeline =
    transactionReviewPipelineComposition.pipeline;

  const allowedExecutionCoordinatorComposition =
    transactionReviewPipelineComposition
      .allowedExecutionCoordinatorComposition;

  const composition =
    createSafetyKernelV31NodeProcessRuntimeControllerComposition({
      nodeProcessTransactionReviewPipelineComposition:
        a2mComposition,
    });

  assert.equal(
    composition.nodeProcessTransactionReviewPipelineComposition,
    a2mComposition
  );

  assert.equal(
    composition.runtimeControllerComposition
      .transactionReviewPipelineComposition,
    transactionReviewPipelineComposition
  );

  assert.equal(
    composition.runtimeControllerComposition
      .transactionReviewPipelineComposition
      .pipeline,
    pipeline
  );

  assert.equal(
    composition.runtimeControllerComposition
      .transactionReviewPipelineComposition
      .allowedExecutionCoordinatorComposition,
    allowedExecutionCoordinatorComposition
  );

  assert.equal(
    composition.nodeProcessTransactionReviewPipelineComposition
      .nodeProcessAllowedExecutionCoordinatorComposition,
    nodeProcessAllowedExecutionCoordinatorComposition
  );

  assert.equal(inputs.counters.reviewCalls, 0);
  assert.equal(inputs.counters.coordinationCalls, 0);
  assert.equal(inputs.counters.processSpawnerCalls, 0);
});