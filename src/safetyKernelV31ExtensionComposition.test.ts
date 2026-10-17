import test from "node:test";
import assert from "node:assert/strict";

import type {
  SafetyKernelV31RuntimeController,
} from "./safetyKernelV31RuntimeController";

import type {
  SafetyKernelV31RuntimeControllerComposition,
} from "./safetyKernelV31RuntimeControllerComposition";

import {
  SAFETY_KERNEL_V31_EXTENSION_COMPOSITION_INVARIANT,
  createSafetyKernelV31ExtensionComposition,
} from "./safetyKernelV31ExtensionComposition";

function createNoCallInput(): {
  runtimeControllerComposition:
    SafetyKernelV31RuntimeControllerComposition;

  runtimeController:
    SafetyKernelV31RuntimeController;

  transactionReviewPipelineComposition:
    SafetyKernelV31RuntimeControllerComposition[
      "transactionReviewPipelineComposition"
    ];

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

  const runtimeController = {
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
  } as unknown as SafetyKernelV31RuntimeController;

  const transactionReviewPipelineComposition =
    Object.freeze({
      pipeline: Object.freeze({}),
      allowedExecutionCoordinatorComposition:
        Object.freeze({}),
    }) as unknown as SafetyKernelV31RuntimeControllerComposition[
      "transactionReviewPipelineComposition"
    ];

  const runtimeControllerComposition =
    Object.freeze({
      runtimeController,
      transactionReviewPipelineComposition,
    }) as SafetyKernelV31RuntimeControllerComposition;

  return {
    runtimeControllerComposition,
    runtimeController,
    transactionReviewPipelineComposition,
    counters,
  };
}

test("extension composition invariant remains detached and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_EXTENSION_COMPOSITION_INVARIANT,
    {
      RUNTIME_CONTROLLER_REFERENCE_REUSED_UNCHANGED: true,
      A2I_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      RUNTIME_CONTROLLER_REFERENCE_CLONED: false,
      A2I_COMPOSITION_REFERENCE_CLONED: false,
      EXTENSION_ACTIVATE_CALLED_DURING_COMPOSITION: false,
      EXTENSION_DEACTIVATE_CALLED_DURING_COMPOSITION: false,
      VSCODE_COMMAND_REGISTRATION_DURING_COMPOSITION: false,
      VSCODE_SUBSCRIPTION_MUTATION_DURING_COMPOSITION: false,
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
      EXTENSION_FILE_MODIFIED: false,
      EXTENSION_RUNTIME_CONNECTED: false,
      DEFAULT_RUNTIME_CONTROLLER_FACTORY_MODIFIED: false,
      DEFAULT_PIPELINE_FACTORY_MODIFIED: false,
      NODE_PROCESS_ADAPTER_MODIFIED: false,
      NODE_PROCESS_ADAPTER_CONNECTED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("factory returns a frozen Runtime Controller and A2i bundle", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31ExtensionComposition({
      runtimeControllerComposition:
        inputs.runtimeControllerComposition,
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    composition.runtimeController,
    inputs.runtimeController
  );

  assert.equal(
    composition.runtimeControllerComposition,
    inputs.runtimeControllerComposition
  );
});

test("factory returns the exact A2i Runtime Controller reference", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31ExtensionComposition({
      runtimeControllerComposition:
        inputs.runtimeControllerComposition,
    });

  assert.equal(
    composition.runtimeController,
    inputs.runtimeControllerComposition.runtimeController
  );

  assert.equal(
    composition.runtimeController,
    inputs.runtimeController
  );
});

test("composition performs no Extension, controller, or state calls", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31ExtensionComposition({
      runtimeControllerComposition:
        inputs.runtimeControllerComposition,
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
    composition.runtimeController,
    inputs.runtimeController
  );
});

test("A2i composition reference is reused unchanged", () => {
  const inputs = createNoCallInput();

  const runtimeController =
    inputs.runtimeControllerComposition.runtimeController;

  const transactionReviewPipelineComposition =
    inputs.runtimeControllerComposition
      .transactionReviewPipelineComposition;

  const composition =
    createSafetyKernelV31ExtensionComposition({
      runtimeControllerComposition:
        inputs.runtimeControllerComposition,
    });

  assert.equal(
    composition.runtimeControllerComposition,
    inputs.runtimeControllerComposition
  );

  assert.equal(
    composition.runtimeControllerComposition
      .runtimeController,
    runtimeController
  );

  assert.equal(
    composition.runtimeControllerComposition
      .transactionReviewPipelineComposition,
    transactionReviewPipelineComposition
  );

  assert.equal(
    composition.runtimeControllerComposition
      .transactionReviewPipelineComposition,
    inputs.transactionReviewPipelineComposition
  );

  assert.equal(inputs.counters.reviewCalls, 0);
  assert.equal(inputs.counters.coordinationCalls, 0);
});