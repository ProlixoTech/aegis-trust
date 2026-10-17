import type {
  SafetyKernelV31RuntimeController,
} from "./safetyKernelV31RuntimeController";

import type {
  SafetyKernelV31RuntimeControllerComposition,
} from "./safetyKernelV31RuntimeControllerComposition";

export interface SafetyKernelV31ExtensionCompositionInput {
  readonly runtimeControllerComposition:
    SafetyKernelV31RuntimeControllerComposition;
}

export interface SafetyKernelV31ExtensionComposition {
  readonly runtimeController:
    SafetyKernelV31RuntimeController;

  readonly runtimeControllerComposition:
    SafetyKernelV31RuntimeControllerComposition;
}

export const SAFETY_KERNEL_V31_EXTENSION_COMPOSITION_INVARIANT =
  Object.freeze({
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
  } as const);

export function createSafetyKernelV31ExtensionComposition(
  input: SafetyKernelV31ExtensionCompositionInput
): SafetyKernelV31ExtensionComposition {
  return Object.freeze({
    runtimeController:
      input.runtimeControllerComposition.runtimeController,
    runtimeControllerComposition:
      input.runtimeControllerComposition,
  });
}