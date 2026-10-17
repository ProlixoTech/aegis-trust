import {
  createSafetyKernelV31RuntimeControllerComposition,
} from "./safetyKernelV31RuntimeControllerComposition";

import type {
  SafetyKernelV31RuntimeControllerComposition,
} from "./safetyKernelV31RuntimeControllerComposition";

import type {
  SafetyKernelV31NodeProcessTransactionReviewPipelineComposition,
} from "./safetyKernelV31NodeProcessTransactionReviewPipelineComposition";

export interface SafetyKernelV31NodeProcessRuntimeControllerCompositionInput {
  readonly nodeProcessTransactionReviewPipelineComposition:
    SafetyKernelV31NodeProcessTransactionReviewPipelineComposition;
}

export interface SafetyKernelV31NodeProcessRuntimeControllerComposition {
  readonly runtimeControllerComposition:
    SafetyKernelV31RuntimeControllerComposition;

  readonly nodeProcessTransactionReviewPipelineComposition:
    SafetyKernelV31NodeProcessTransactionReviewPipelineComposition;
}

export const
  SAFETY_KERNEL_V31_NODE_PROCESS_RUNTIME_CONTROLLER_COMPOSITION_INVARIANT =
    Object.freeze({
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
    } as const);

export function createSafetyKernelV31NodeProcessRuntimeControllerComposition(
  input:
    SafetyKernelV31NodeProcessRuntimeControllerCompositionInput
): SafetyKernelV31NodeProcessRuntimeControllerComposition {
  const nodeProcessTransactionReviewPipelineComposition =
    input.nodeProcessTransactionReviewPipelineComposition;

  const runtimeControllerComposition =
    createSafetyKernelV31RuntimeControllerComposition({
      transactionReviewPipelineComposition:
        nodeProcessTransactionReviewPipelineComposition
          .transactionReviewPipelineComposition,
    });

  return Object.freeze({
    runtimeControllerComposition,
    nodeProcessTransactionReviewPipelineComposition,
  });
}