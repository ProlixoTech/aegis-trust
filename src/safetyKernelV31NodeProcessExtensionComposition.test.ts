import test from "node:test";
import assert from "node:assert/strict";

import type {
  SafetyKernelV31RuntimeController,
} from "./safetyKernelV31RuntimeController";

import type {
  SafetyKernelV31RuntimeControllerComposition,
} from "./safetyKernelV31RuntimeControllerComposition";

import type {
  SafetyKernelV31NodeProcessRuntimeControllerComposition,
} from "./safetyKernelV31NodeProcessRuntimeControllerComposition";

import {
  SAFETY_KERNEL_V31_NODE_PROCESS_EXTENSION_COMPOSITION_INVARIANT,
  createSafetyKernelV31NodeProcessExtensionComposition,
} from "./safetyKernelV31NodeProcessExtensionComposition";

function createNoCallInput(): {
  nodeProcessRuntimeControllerComposition:
    SafetyKernelV31NodeProcessRuntimeControllerComposition;

  runtimeControllerComposition:
    SafetyKernelV31RuntimeControllerComposition;

  runtimeController:
    SafetyKernelV31RuntimeController;

  transactionReviewPipelineComposition:
    SafetyKernelV31RuntimeControllerComposition[
      "transactionReviewPipelineComposition"
    ];

  nodeProcessTransactionReviewPipelineComposition:
    SafetyKernelV31NodeProcessRuntimeControllerComposition[
      "nodeProcessTransactionReviewPipelineComposition"
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

  const runtimeController = {
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
  } as unknown as SafetyKernelV31RuntimeController;

  const transactionReviewPipelineComposition =
    Object.freeze({
      pipeline: Object.freeze({}),
      allowedExecutionCoordinatorComposition:
        Object.freeze({}),
    }) as unknown as
      SafetyKernelV31RuntimeControllerComposition[
        "transactionReviewPipelineComposition"
      ];

  const runtimeControllerComposition =
    Object.freeze({
      runtimeController,
      transactionReviewPipelineComposition,
    }) as SafetyKernelV31RuntimeControllerComposition;

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
      allowedExecutionCoordinatorComposition:
        transactionReviewPipelineComposition
          .allowedExecutionCoordinatorComposition,
      nodeProcessExecutionAdapterComposition,
    });

  const nodeProcessTransactionReviewPipelineComposition =
    Object.freeze({
      transactionReviewPipelineComposition,
      nodeProcessAllowedExecutionCoordinatorComposition,
    }) as unknown as
      SafetyKernelV31NodeProcessRuntimeControllerComposition[
        "nodeProcessTransactionReviewPipelineComposition"
      ];

  const nodeProcessRuntimeControllerComposition =
    Object.freeze({
      runtimeControllerComposition,
      nodeProcessTransactionReviewPipelineComposition,
    }) as SafetyKernelV31NodeProcessRuntimeControllerComposition;

  return {
    nodeProcessRuntimeControllerComposition,
    runtimeControllerComposition,
    runtimeController,
    transactionReviewPipelineComposition,
    nodeProcessTransactionReviewPipelineComposition,
    counters,
  };
}

test("node process Extension composition invariant remains detached from activation and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_NODE_PROCESS_EXTENSION_COMPOSITION_INVARIANT,
    {
      A2J_FACTORY_CALLED_EXACTLY_ONCE: true,
      NEW_EXTENSION_COMPOSITION_CONSTRUCTED_EXACTLY_ONCE: true,
      EXTENSION_COMPOSITION_RECEIVES_EXACT_A2N_RUNTIME_CONTROLLER_COMPOSITION:
        true,
      A2N_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      A2N_COMPOSITION_REFERENCE_CLONED: false,
      RUNTIME_CONTROLLER_COMPOSITION_REFERENCE_CLONED: false,
      RUNTIME_CONTROLLER_REFERENCE_CLONED: false,
      OUTPUT_OBJECT_FROZEN: true,
      EXTENSION_COMPOSITION_CONNECTED_TO_A2N_RUNTIME_CONTROLLER: true,
      EXTENSION_ACTIVATION_CONNECTED: false,
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
      NODE_PROCESS_SPAWNER_CALLED_DURING_COMPOSITION: false,
      CACHE_CREATED: false,
      EXTENSION_TS_MODIFIED: false,
      DIRECT_CREATE_FOR_AEGIS_DIR_BOOTSTRAP_MODIFIED: false,
      EXISTING_EXTENSION_REVIEW_ONLY_PATH_UNCHANGED: true,
      DEFAULT_EXTENSION_COMPOSITION_FACTORY_MODIFIED: false,
      DEFAULT_RUNTIME_CONTROLLER_FACTORY_MODIFIED: false,
      DEFAULT_PIPELINE_FACTORY_MODIFIED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("factory returns a frozen Extension and A2n composition bundle", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessExtensionComposition({
      nodeProcessRuntimeControllerComposition:
        inputs.nodeProcessRuntimeControllerComposition,
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    Object.isFrozen(composition.extensionComposition),
    true
  );

  assert.equal(
    composition.nodeProcessRuntimeControllerComposition,
    inputs.nodeProcessRuntimeControllerComposition
  );
});

test("Extension composition receives the exact A2n Runtime Controller composition", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessExtensionComposition({
      nodeProcessRuntimeControllerComposition:
        inputs.nodeProcessRuntimeControllerComposition,
    });

  assert.equal(
    composition.extensionComposition
      .runtimeControllerComposition,
    inputs.runtimeControllerComposition
  );

  assert.equal(
    composition.extensionComposition.runtimeController,
    inputs.runtimeController
  );

  assert.equal(
    composition.extensionComposition.runtimeController,
    inputs.runtimeControllerComposition.runtimeController
  );
});

test("composition performs no Extension activation, controller, Pipeline, execution, or state calls", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessExtensionComposition({
      nodeProcessRuntimeControllerComposition:
        inputs.nodeProcessRuntimeControllerComposition,
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
    composition.extensionComposition.runtimeController,
    inputs.runtimeController
  );
});

test("A2n and all nested composition references are reused unchanged", () => {
  const inputs = createNoCallInput();

  const a2nComposition =
    inputs.nodeProcessRuntimeControllerComposition;

  const runtimeControllerComposition =
    a2nComposition.runtimeControllerComposition;

  const nodeProcessTransactionReviewPipelineComposition =
    a2nComposition
      .nodeProcessTransactionReviewPipelineComposition;

  const transactionReviewPipelineComposition =
    runtimeControllerComposition
      .transactionReviewPipelineComposition;

  const runtimeController =
    runtimeControllerComposition.runtimeController;

  const composition =
    createSafetyKernelV31NodeProcessExtensionComposition({
      nodeProcessRuntimeControllerComposition:
        a2nComposition,
    });

  assert.equal(
    composition.nodeProcessRuntimeControllerComposition,
    a2nComposition
  );

  assert.equal(
    composition.extensionComposition.runtimeControllerComposition,
    runtimeControllerComposition
  );

  assert.equal(
    composition.extensionComposition.runtimeController,
    runtimeController
  );

  assert.equal(
    composition.nodeProcessRuntimeControllerComposition
      .nodeProcessTransactionReviewPipelineComposition,
    nodeProcessTransactionReviewPipelineComposition
  );

  assert.equal(
    composition.extensionComposition
      .runtimeControllerComposition
      .transactionReviewPipelineComposition,
    transactionReviewPipelineComposition
  );

  assert.equal(inputs.counters.reviewCalls, 0);
  assert.equal(inputs.counters.coordinationCalls, 0);
  assert.equal(inputs.counters.processSpawnerCalls, 0);
});