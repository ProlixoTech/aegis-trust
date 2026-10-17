import test from "node:test";
import assert from "node:assert/strict";

import type {
  NodeProcessExecutionAdapter,
} from "./nodeProcessExecutionAdapter";

import type {
  SafetyKernelV31NodeProcessExecutionAdapterComposition,
} from "./safetyKernelV31NodeProcessExecutionAdapterComposition";

import {
  SAFETY_KERNEL_V31_NODE_PROCESS_ALLOWED_EXECUTION_COORDINATOR_COMPOSITION_INVARIANT,
  createSafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition,
} from "./safetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition";

function createNoCallInput(): {
  readonly nodeProcessExecutionAdapterComposition:
    SafetyKernelV31NodeProcessExecutionAdapterComposition;

  readonly nodeProcessExecutionAdapter:
    NodeProcessExecutionAdapter;

  readonly authorityBindingComposition:
    object;

  readonly counters: {
    adapterExecuteCalls: number;
    verifierCalls: number;
    coordinatorExecuteAllowedCalls: number;
  };
} {
  const counters = {
    adapterExecuteCalls: 0,
    verifierCalls: 0,
    coordinatorExecuteAllowedCalls: 0,
  };

  const nodeProcessExecutionAdapter = {
    async execute(): Promise<never> {
      counters.adapterExecuteCalls += 1;

      throw new Error(
        "NODE_ADAPTER_EXECUTE_DURING_COMPOSITION"
      );
    },
  } as unknown as NodeProcessExecutionAdapter;

  const verifier = Object.freeze({
    verify(): never {
      counters.verifierCalls += 1;

      throw new Error(
        "VERIFIER_CALLED_DURING_COMPOSITION"
      );
    },
  });

  const authorityBindingComposition =
    Object.freeze({
      verifier,
      readPort: Object.freeze({}),
    });

  const existingCoordinator = Object.freeze({
    async executeAllowed(): Promise<never> {
      counters.coordinatorExecuteAllowedCalls += 1;

      throw new Error(
        "EXISTING_COORDINATOR_EXECUTE_ALLOWED_DURING_COMPOSITION"
      );
    },
  });

  const allowedExecutionCoordinatorComposition =
    Object.freeze({
      coordinator: existingCoordinator,
      authorityBindingComposition,
    });

  const transactionReviewPipelineComposition =
    Object.freeze({
      transactionReviewPipeline: Object.freeze({}),
      allowedExecutionCoordinatorComposition,
    });

  const runtimeControllerComposition =
    Object.freeze({
      runtimeController: Object.freeze({}),
      transactionReviewPipelineComposition,
    });

  const extensionComposition =
    Object.freeze({
      runtimeController: Object.freeze({}),
      runtimeControllerComposition,
    });

  const nodeProcessExecutionAdapterComposition =
    Object.freeze({
      nodeProcessExecutionAdapter,
      extensionComposition,
    }) as unknown as
      SafetyKernelV31NodeProcessExecutionAdapterComposition;

  return {
    nodeProcessExecutionAdapterComposition,
    nodeProcessExecutionAdapter,
    authorityBindingComposition,
    counters,
  };
}

test("A2l invariant preserves scoped Coordinator injection and detached runtime boundaries", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_NODE_PROCESS_ALLOWED_EXECUTION_COORDINATOR_COMPOSITION_INVARIANT,
    {
      A2G_FACTORY_CALLED_EXACTLY_ONCE: true,
      NEW_COORDINATOR_CONSTRUCTED_EXACTLY_ONCE: true,
      NEW_COORDINATOR_RECEIVES_EXACT_A2K_NODE_ADAPTER: true,
      AUTHORITY_BINDING_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      A2K_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      A2K_COMPOSITION_REFERENCE_CLONED: false,
      AUTHORITY_BINDING_COMPOSITION_REFERENCE_CLONED: false,
      OUTPUT_OBJECT_FROZEN: true,
      NODE_ADAPTER_WIRED_AS_NEW_COORDINATOR_EXECUTION_PORT: true,
      NODE_ADAPTER_EXECUTE_CALLED_DURING_COMPOSITION: false,
      NODE_PROCESS_SPAWNER_CALLED_DURING_COMPOSITION: false,
      COORDINATOR_EXECUTE_ALLOWED_CALLED_DURING_COMPOSITION: false,
      VERIFIER_CALLED_DURING_COMPOSITION: false,
      AUTHORITY_READ_DURING_COMPOSITION: false,
      INDEX_READ_DURING_COMPOSITION: false,
      BASELINE_FILE_READ_DURING_COMPOSITION: false,
      SESSION_CREATED_DURING_COMPOSITION: false,
      SESSION_CLAIM_CREATED_DURING_COMPOSITION: false,
      BINDING_REGISTERED_DURING_COMPOSITION: false,
      REVIEW_CALL_DURING_COMPOSITION: false,
      COORDINATION_CALL_DURING_COMPOSITION: false,
      EXTENSION_ACTIVATE_CALLED_DURING_COMPOSITION: false,
      EXTENSION_DEACTIVATE_CALLED_DURING_COMPOSITION: false,
      VSCODE_COMMAND_REGISTRATION_DURING_COMPOSITION: false,
      VSCODE_SUBSCRIPTION_MUTATION_DURING_COMPOSITION: false,
      PIPELINE_CONNECTED_TO_NEW_COORDINATOR: false,
      RUNTIME_CONTROLLER_CONNECTED_TO_NEW_COORDINATOR: false,
      EXTENSION_CONNECTED_TO_NEW_COORDINATOR: false,
      DEFAULT_COORDINATOR_FACTORY_MODIFIED: false,
      DEFAULT_PIPELINE_FACTORY_MODIFIED: false,
      DEFAULT_RUNTIME_CONTROLLER_FACTORY_MODIFIED: false,
      EXTENSION_FILE_MODIFIED: false,
      NODE_PROCESS_ADAPTER_FILE_MODIFIED: false,
      A2G_SOURCE_MODIFIED: false,
      END_TO_END_EXECUTION_RUNTIME_CONNECTED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("factory returns a frozen new Coordinator and A2k composition bundle", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition({
      nodeProcessExecutionAdapterComposition:
        inputs.nodeProcessExecutionAdapterComposition,
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    Object.isFrozen(
      composition.allowedExecutionCoordinatorComposition
    ),
    true
  );

  assert.equal(
    composition.nodeProcessExecutionAdapterComposition,
    inputs.nodeProcessExecutionAdapterComposition
  );
});

test("new Coordinator receives the exact A2k Node Process Adapter", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition({
      nodeProcessExecutionAdapterComposition:
        inputs.nodeProcessExecutionAdapterComposition,
    });

  const coordinator =
    composition
      .allowedExecutionCoordinatorComposition
      .coordinator as unknown as {
        readonly execution: unknown;
      };

  assert.equal(
    coordinator.execution,
    inputs.nodeProcessExecutionAdapter
  );

  assert.equal(
    inputs.counters.adapterExecuteCalls,
    0
  );
});

test("composition performs no execution, verification, coordination, or state calls", () => {
  const inputs = createNoCallInput();

  createSafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition({
    nodeProcessExecutionAdapterComposition:
      inputs.nodeProcessExecutionAdapterComposition,
  });

  assert.equal(
    inputs.counters.adapterExecuteCalls,
    0
  );

  assert.equal(
    inputs.counters.verifierCalls,
    0
  );

  assert.equal(
    inputs.counters.coordinatorExecuteAllowedCalls,
    0
  );
});

test("nested authority-binding and A2k references are reused unchanged", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition({
      nodeProcessExecutionAdapterComposition:
        inputs.nodeProcessExecutionAdapterComposition,
    });

  assert.equal(
    composition
      .allowedExecutionCoordinatorComposition
      .authorityBindingComposition,
    inputs.authorityBindingComposition
  );

  assert.equal(
    composition.nodeProcessExecutionAdapterComposition,
    inputs.nodeProcessExecutionAdapterComposition
  );

  assert.equal(
    inputs.counters.adapterExecuteCalls,
    0
  );

  assert.equal(
    inputs.counters.verifierCalls,
    0
  );
});