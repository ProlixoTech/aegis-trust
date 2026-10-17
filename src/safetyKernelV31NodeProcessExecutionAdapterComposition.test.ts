import test from "node:test";
import assert from "node:assert/strict";

import type {
  NodeProcessExecutionAdapter,
} from "./nodeProcessExecutionAdapter";

import type {
  SafetyKernelV31ExtensionComposition,
} from "./safetyKernelV31ExtensionComposition";

import {
  SAFETY_KERNEL_V31_NODE_PROCESS_EXECUTION_ADAPTER_COMPOSITION_INVARIANT,
  createSafetyKernelV31NodeProcessExecutionAdapterComposition,
} from "./safetyKernelV31NodeProcessExecutionAdapterComposition";

function createNoCallInput(): {
  nodeProcessExecutionAdapter:
    NodeProcessExecutionAdapter;

  extensionComposition:
    SafetyKernelV31ExtensionComposition;

  counters: {
    adapterExecuteCalls: number;
    extensionPropertyReads: number;
  };
} {
  const counters = {
    adapterExecuteCalls: 0,
    extensionPropertyReads: 0,
  };

  const nodeProcessExecutionAdapter = {
    async execute(): Promise<never> {
      counters.adapterExecuteCalls += 1;
      throw new Error(
        "NODE_ADAPTER_EXECUTE_DURING_COMPOSITION"
      );
    },
  } as unknown as NodeProcessExecutionAdapter;

  const extensionCompositionTarget =
    Object.freeze({
      runtimeController: Object.freeze({}),
      runtimeControllerComposition:
        Object.freeze({}),
    }) as unknown as SafetyKernelV31ExtensionComposition;

  const extensionComposition =
    new Proxy(
      extensionCompositionTarget,
      {
        get(target, property, receiver): unknown {
          counters.extensionPropertyReads += 1;

          return Reflect.get(
            target,
            property,
            receiver
          );
        },
      }
    );

  return {
    nodeProcessExecutionAdapter,
    extensionComposition,
    counters,
  };
}

test("node adapter composition invariant remains detached and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_NODE_PROCESS_EXECUTION_ADAPTER_COMPOSITION_INVARIANT,
    {
      NODE_ADAPTER_REFERENCE_REUSED_UNCHANGED: true,
      A2J_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      NODE_ADAPTER_REFERENCE_CLONED: false,
      A2J_COMPOSITION_REFERENCE_CLONED: false,
      NODE_ADAPTER_CONSTRUCTED_DURING_COMPOSITION: false,
      NODE_ADAPTER_EXECUTE_CALLED_DURING_COMPOSITION: false,
      NODE_PROCESS_SPAWNER_CALLED_DURING_COMPOSITION: false,
      OUTPUT_OBJECT_FROZEN: true,
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
      EXECUTION_PORT_CALL_DURING_COMPOSITION: false,
      VERIFICATION_CALL_DURING_COMPOSITION: false,
      AUTHORITY_READ_DURING_COMPOSITION: false,
      INDEX_READ_DURING_COMPOSITION: false,
      BASELINE_FILE_READ_DURING_COMPOSITION: false,
      SESSION_CREATED_DURING_COMPOSITION: false,
      SESSION_CLAIM_CREATED_DURING_COMPOSITION: false,
      BINDING_REGISTERED_DURING_COMPOSITION: false,
      CACHE_CREATED: false,
      EXTENSION_FILE_MODIFIED: false,
      NODE_PROCESS_ADAPTER_FILE_MODIFIED: false,
      PLATFORM_PORTS_FILE_MODIFIED: false,
      DEFAULT_FACTORY_MODIFIED: false,
      NODE_ADAPTER_INJECTED_INTO_COORDINATOR: false,
      NODE_ADAPTER_INJECTED_INTO_PIPELINE: false,
      NODE_ADAPTER_INJECTED_INTO_RUNTIME_CONTROLLER: false,
      NODE_ADAPTER_INJECTED_INTO_EXTENSION: false,
      NODE_PROCESS_ADAPTER_RUNTIME_CONNECTED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("factory returns a frozen Node adapter and A2j bundle", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessExecutionAdapterComposition({
      nodeProcessExecutionAdapter:
        inputs.nodeProcessExecutionAdapter,
      extensionComposition:
        inputs.extensionComposition,
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    composition.nodeProcessExecutionAdapter,
    inputs.nodeProcessExecutionAdapter
  );

  assert.equal(
    composition.extensionComposition,
    inputs.extensionComposition
  );
});

test("factory returns the exact supplied Node adapter reference", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessExecutionAdapterComposition({
      nodeProcessExecutionAdapter:
        inputs.nodeProcessExecutionAdapter,
      extensionComposition:
        inputs.extensionComposition,
    });

  assert.equal(
    composition.nodeProcessExecutionAdapter,
    inputs.nodeProcessExecutionAdapter
  );

  assert.equal(
    inputs.counters.adapterExecuteCalls,
    0
  );
});

test("composition performs no adapter, Extension, controller, or state calls", () => {
  const inputs = createNoCallInput();

  const composition =
    createSafetyKernelV31NodeProcessExecutionAdapterComposition({
      nodeProcessExecutionAdapter:
        inputs.nodeProcessExecutionAdapter,
      extensionComposition:
        inputs.extensionComposition,
    });

  assert.equal(
    inputs.counters.adapterExecuteCalls,
    0
  );

  assert.equal(
    inputs.counters.extensionPropertyReads,
    0
  );

  assert.equal(
    composition.nodeProcessExecutionAdapter,
    inputs.nodeProcessExecutionAdapter
  );

  assert.equal(
    composition.extensionComposition,
    inputs.extensionComposition
  );
});

test("A2j composition reference is reused unchanged", () => {
  const inputs = createNoCallInput();

  const extensionComposition =
    inputs.extensionComposition;

  const nodeProcessExecutionAdapter =
    inputs.nodeProcessExecutionAdapter;

  const composition =
    createSafetyKernelV31NodeProcessExecutionAdapterComposition({
      nodeProcessExecutionAdapter,
      extensionComposition,
    });

  assert.equal(
    composition.extensionComposition,
    extensionComposition
  );

  assert.equal(
    composition.nodeProcessExecutionAdapter,
    nodeProcessExecutionAdapter
  );

  assert.equal(
    inputs.counters.adapterExecuteCalls,
    0
  );

  assert.equal(
    inputs.counters.extensionPropertyReads,
    0
  );
});