import {
  SafetyKernelV31RuntimeController,
} from "./safetyKernelV31RuntimeController";

import type {
  SafetyKernelV31TransactionReviewPipelineComposition,
} from "../packages/aegis-core";

export interface SafetyKernelV31RuntimeControllerCompositionInput {
  readonly transactionReviewPipelineComposition:
    SafetyKernelV31TransactionReviewPipelineComposition;
}

export interface SafetyKernelV31RuntimeControllerComposition {
  readonly runtimeController:
    SafetyKernelV31RuntimeController;

  readonly transactionReviewPipelineComposition:
    SafetyKernelV31TransactionReviewPipelineComposition;
}

export const SAFETY_KERNEL_V31_RUNTIME_CONTROLLER_COMPOSITION_INVARIANT =
  Object.freeze({
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
  } as const);

export function createSafetyKernelV31RuntimeControllerComposition(
  input: SafetyKernelV31RuntimeControllerCompositionInput
): SafetyKernelV31RuntimeControllerComposition {
  const runtimeController =
    new SafetyKernelV31RuntimeController(
      input.transactionReviewPipelineComposition.pipeline
    );

  return Object.freeze({
    runtimeController,
    transactionReviewPipelineComposition:
      input.transactionReviewPipelineComposition,
  });
}