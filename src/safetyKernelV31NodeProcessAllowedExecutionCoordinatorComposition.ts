import {
  createSafetyKernelV31AllowedExecutionCoordinatorComposition,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31AllowedExecutionCoordinatorComposition,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31NodeProcessExecutionAdapterComposition,
} from "./safetyKernelV31NodeProcessExecutionAdapterComposition";

export interface SafetyKernelV31NodeProcessAllowedExecutionCoordinatorCompositionInput {
  readonly nodeProcessExecutionAdapterComposition:
    SafetyKernelV31NodeProcessExecutionAdapterComposition;
}

export interface SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition {
  readonly allowedExecutionCoordinatorComposition:
    SafetyKernelV31AllowedExecutionCoordinatorComposition;

  readonly nodeProcessExecutionAdapterComposition:
    SafetyKernelV31NodeProcessExecutionAdapterComposition;
}

export const
  SAFETY_KERNEL_V31_NODE_PROCESS_ALLOWED_EXECUTION_COORDINATOR_COMPOSITION_INVARIANT =
    Object.freeze({
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
    } as const);

export function createSafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition(
  input:
    SafetyKernelV31NodeProcessAllowedExecutionCoordinatorCompositionInput
): SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition {
  const nodeProcessExecutionAdapterComposition =
    input.nodeProcessExecutionAdapterComposition;

  const authorityBindingComposition =
    nodeProcessExecutionAdapterComposition
      .extensionComposition
      .runtimeControllerComposition
      .transactionReviewPipelineComposition
      .allowedExecutionCoordinatorComposition
      .authorityBindingComposition;

  const allowedExecutionCoordinatorComposition =
    createSafetyKernelV31AllowedExecutionCoordinatorComposition({
      execution:
        nodeProcessExecutionAdapterComposition
          .nodeProcessExecutionAdapter,
      authorityBindingComposition,
    });

  return Object.freeze({
    allowedExecutionCoordinatorComposition,
    nodeProcessExecutionAdapterComposition,
  });
}