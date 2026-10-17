import {
  SafetyKernelV31TransactionReviewPipeline,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31TransactionService,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31TransactionSessionStore,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31AllowedExecutionSessionBindingStore,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31AllowedExecutionCoordinatorComposition,
} from "./safetyKernelV31AllowedExecutionCoordinatorComposition";

export interface SafetyKernelV31TransactionReviewPipelineCompositionInput {
  readonly transactionService:
    SafetyKernelV31TransactionService;

  readonly transactionSessionStore:
    SafetyKernelV31TransactionSessionStore;

  readonly allowedExecutionBindingStore:
    SafetyKernelV31AllowedExecutionSessionBindingStore;

  readonly allowedExecutionCoordinatorComposition:
    SafetyKernelV31AllowedExecutionCoordinatorComposition;
}

export interface SafetyKernelV31TransactionReviewPipelineComposition {
  readonly pipeline:
    SafetyKernelV31TransactionReviewPipeline;

  readonly allowedExecutionCoordinatorComposition:
    SafetyKernelV31AllowedExecutionCoordinatorComposition;
}

export const SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_COMPOSITION_INVARIANT =
  Object.freeze({
    PIPELINE_CONSTRUCTED_EXACTLY_ONCE: true,
    PIPELINE_RECEIVES_EXACT_TRANSACTION_SERVICE_INSTANCE: true,
    PIPELINE_RECEIVES_EXACT_TRANSACTION_SESSION_STORE_INSTANCE: true,
    PIPELINE_RECEIVES_EXACT_BINDING_STORE_INSTANCE: true,
    PIPELINE_RECEIVES_EXACT_A2G_COORDINATOR_INSTANCE: true,
    A2G_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
    TRANSACTION_SERVICE_REFERENCE_CLONED: false,
    SESSION_STORE_REFERENCE_CLONED: false,
    BINDING_STORE_REFERENCE_CLONED: false,
    A2G_COMPOSITION_REFERENCE_CLONED: false,
    REVIEW_CALL_DURING_COMPOSITION: false,
    EXECUTION_CALL_DURING_COMPOSITION: false,
    COORDINATION_CALL_DURING_COMPOSITION: false,
    VERIFICATION_CALL_DURING_COMPOSITION: false,
    AUTHORITY_READ_DURING_COMPOSITION: false,
    INDEX_READ_DURING_COMPOSITION: false,
    BASELINE_FILE_READ_DURING_COMPOSITION: false,
    SESSION_CREATED_DURING_COMPOSITION: false,
    SESSION_CLAIM_CREATED_DURING_COMPOSITION: false,
    BINDING_REGISTERED_DURING_COMPOSITION: false,
    CACHE_CREATED: false,
    OUTPUT_OBJECT_FROZEN: true,
    DEFAULT_PIPELINE_FACTORY_MODIFIED: false,
    RUNTIME_CONTROLLER_CONNECTED: false,
    EXTENSION_CONNECTED: false,
    NODE_PROCESS_ADAPTER_CONNECTED: false,
    RECEIPT_CONNECTED: false,
    LEDGER_CONNECTED: false,
    REAL_PROCESS_EXECUTION_REQUIRED: false,
    REAL_COMMAND_EXECUTION_REQUIRED: false,
  } as const);

export function createSafetyKernelV31TransactionReviewPipelineComposition(
  input: SafetyKernelV31TransactionReviewPipelineCompositionInput
): SafetyKernelV31TransactionReviewPipelineComposition {
  const pipeline =
    new SafetyKernelV31TransactionReviewPipeline(
      input.transactionService,
      input.transactionSessionStore,
      input.allowedExecutionBindingStore,
      input.allowedExecutionCoordinatorComposition.coordinator
    );

  return Object.freeze({
    pipeline,
    allowedExecutionCoordinatorComposition:
      input.allowedExecutionCoordinatorComposition,
  });
}