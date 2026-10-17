import {
  createSafetyKernelV31ExtensionComposition,
} from "./safetyKernelV31ExtensionComposition";

import type {
  SafetyKernelV31ExtensionComposition,
} from "./safetyKernelV31ExtensionComposition";

import type {
  SafetyKernelV31NodeProcessRuntimeControllerComposition,
} from "./safetyKernelV31NodeProcessRuntimeControllerComposition";

export interface SafetyKernelV31NodeProcessExtensionCompositionInput {
  readonly nodeProcessRuntimeControllerComposition:
    SafetyKernelV31NodeProcessRuntimeControllerComposition;
}

export interface SafetyKernelV31NodeProcessExtensionComposition {
  readonly extensionComposition:
    SafetyKernelV31ExtensionComposition;

  readonly nodeProcessRuntimeControllerComposition:
    SafetyKernelV31NodeProcessRuntimeControllerComposition;
}

export const
  SAFETY_KERNEL_V31_NODE_PROCESS_EXTENSION_COMPOSITION_INVARIANT =
    Object.freeze({
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
    } as const);

export function createSafetyKernelV31NodeProcessExtensionComposition(
  input:
    SafetyKernelV31NodeProcessExtensionCompositionInput
): SafetyKernelV31NodeProcessExtensionComposition {
  const nodeProcessRuntimeControllerComposition =
    input.nodeProcessRuntimeControllerComposition;

  const extensionComposition =
    createSafetyKernelV31ExtensionComposition({
      runtimeControllerComposition:
        nodeProcessRuntimeControllerComposition
          .runtimeControllerComposition,
    });

  return Object.freeze({
    extensionComposition,
    nodeProcessRuntimeControllerComposition,
  });
}