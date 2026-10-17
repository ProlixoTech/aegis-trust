import type {
  NodeProcessExecutionAdapter,
} from "./nodeProcessExecutionAdapter";

import type {
  SafetyKernelV31ExtensionComposition,
} from "./safetyKernelV31ExtensionComposition";

export interface SafetyKernelV31NodeProcessExecutionAdapterCompositionInput {
  readonly nodeProcessExecutionAdapter:
    NodeProcessExecutionAdapter;

  readonly extensionComposition:
    SafetyKernelV31ExtensionComposition;
}

export interface SafetyKernelV31NodeProcessExecutionAdapterComposition {
  readonly nodeProcessExecutionAdapter:
    NodeProcessExecutionAdapter;

  readonly extensionComposition:
    SafetyKernelV31ExtensionComposition;
}

export const
  SAFETY_KERNEL_V31_NODE_PROCESS_EXECUTION_ADAPTER_COMPOSITION_INVARIANT =
    Object.freeze({
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
    } as const);

export function createSafetyKernelV31NodeProcessExecutionAdapterComposition(
  input:
    SafetyKernelV31NodeProcessExecutionAdapterCompositionInput
): SafetyKernelV31NodeProcessExecutionAdapterComposition {
  return Object.freeze({
    nodeProcessExecutionAdapter:
      input.nodeProcessExecutionAdapter,
    extensionComposition:
      input.extensionComposition,
  });
}