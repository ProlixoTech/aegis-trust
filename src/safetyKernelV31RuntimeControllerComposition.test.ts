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

import {
  SAFETY_KERNEL_V31_RUNTIME_CONTROLLER_COMPOSITION_INVARIANT,
  createSafetyKernelV31RuntimeControllerComposition,
} from "./safetyKernelV31RuntimeControllerComposition";

function createNoCallInput(): {
  transactionReviewPipelineComposition:
    SafetyKernelV31TransactionReviewPipelineComposition;

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
  };

  const pipeline = {
    async review(): Promise<never> {
      counters.reviewCalls += 1;
      throw new Error("REVIEW_DURING_COMPOSITION");
    },

    readSession(): never {
      counters.readSessionCalls += 1;
      throw new Error("READ_SESSION_DURING_COMPOSITION");
    },

    async confirmWarnSession(): Promise<never> {
      counters.confirmWarnCalls += 1;
      throw new Error("CONFIRM_WARN_DURING_COMPOSITION");
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
      throw new Error("ABORT_DURING_COMPOSITION");
    },

    async terminateWarnSession(): Promise<never> {
      counters.terminateWarnCalls += 1;
      throw new Error(
        "TERMINATE_WARN_DURING_COMPOSITION"
      );
    },
  } as unknown as SafetyKernelV31TransactionReviewPipeline;

  const transactionReviewPipelineComposition =
    Object.freeze({
      pipeline,
      allowedExecutionCoordinatorComposition:
        Object.freeze({}),
    }) as unknown as SafetyKernelV31TransactionReviewPipelineComposition;

  return {
    transactionReviewPipelineComposition,
    pipeline,
    counters,
  };
}

test("runtime controller composition invariant remains detached and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_RUNTIME_CONTROLLER_COMPOSITION_INVARIANT,
    {
      RUNTIME_CONTROLLER_CONSTRUCTED_EXACTLY_ONCE: true,
      RUNTIME_CONTROLLER_RECEIVES_EXACT_A2H_PIPELINE_INSTANCE: true,
      A2H_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      A2H_COMPOSITION_REFERENCE_CLONED: false,
      PIPELINE_REFERENCE_CLONED: false,
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
      CACHE_CREATED: false,
      OUTPUT_OBJECT_FROZEN: true,
      DEFAULT_RUNTIME_CONTROLLER_FACTORY_MODIFIED: false,
      DEFAULT_PIPELINE_FACTORY_MODIFIED: false,
      RUNTIME_CONNECTED: false,
      EXTENSION_CONNECTED: false,
      NODE_PROCESS_ADAPTER_CONNECTED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("factory returns a frozen Runtime Controller and A2h composition bundle", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31RuntimeControllerComposition({
      transactionReviewPipelineComposition:
        inputs.transactionReviewPipelineComposition,
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    composition.runtimeController instanceof
      SafetyKernelV31RuntimeController,
    true
  );

  assert.equal(
    composition.transactionReviewPipelineComposition,
    inputs.transactionReviewPipelineComposition
  );
});

test("Runtime Controller receives the exact A2h Pipeline instance", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31RuntimeControllerComposition({
      transactionReviewPipelineComposition:
        inputs.transactionReviewPipelineComposition,
    });

  const internals =
    composition.runtimeController as unknown as {
      readonly pipeline: unknown;
    };

  assert.equal(
    internals.pipeline,
    inputs.pipeline
  );

  assert.equal(
    internals.pipeline,
    inputs.transactionReviewPipelineComposition.pipeline
  );
});

test("composition performs no controller, Pipeline execution, or state calls", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31RuntimeControllerComposition({
      transactionReviewPipelineComposition:
        inputs.transactionReviewPipelineComposition,
    });

  assert.equal(inputs.counters.reviewCalls, 0);
  assert.equal(inputs.counters.readSessionCalls, 0);
  assert.equal(inputs.counters.confirmWarnCalls, 0);
  assert.equal(
    inputs.counters.completeAllowedExecutionCalls,
    0
  );
  assert.equal(inputs.counters.bindAuthorityCalls, 0);
  assert.equal(inputs.counters.coordinationCalls, 0);
  assert.equal(inputs.counters.abortCalls, 0);
  assert.equal(inputs.counters.terminateWarnCalls, 0);

  assert.equal(
    composition.runtimeController instanceof
      SafetyKernelV31RuntimeController,
    true
  );
});

test("A2h composition reference is reused unchanged", () => {
  const inputs = createNoCallInput();

  const pipeline =
    inputs.transactionReviewPipelineComposition.pipeline;

  const allowedExecutionCoordinatorComposition =
    inputs.transactionReviewPipelineComposition
      .allowedExecutionCoordinatorComposition;

  const composition =
    createSafetyKernelV31RuntimeControllerComposition({
      transactionReviewPipelineComposition:
        inputs.transactionReviewPipelineComposition,
    });

  assert.equal(
    composition.transactionReviewPipelineComposition,
    inputs.transactionReviewPipelineComposition
  );

  assert.equal(
    composition.transactionReviewPipelineComposition.pipeline,
    pipeline
  );

  assert.equal(
    composition.transactionReviewPipelineComposition
      .allowedExecutionCoordinatorComposition,
    allowedExecutionCoordinatorComposition
  );

  assert.equal(inputs.counters.reviewCalls, 0);
  assert.equal(inputs.counters.readSessionCalls, 0);
  assert.equal(inputs.counters.coordinationCalls, 0);
});