import {
  createSafetyKernelV31TransactionReviewPipelineComposition,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31TransactionReviewPipelineComposition,
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
  SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition,
} from "./safetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition";

export interface SafetyKernelV31NodeProcessTransactionReviewPipelineCompositionInput {
  readonly transactionService:
    SafetyKernelV31TransactionService;

  readonly transactionSessionStore:
    SafetyKernelV31TransactionSessionStore;

  readonly allowedExecutionBindingStore:
    SafetyKernelV31AllowedExecutionSessionBindingStore;

  readonly nodeProcessAllowedExecutionCoordinatorComposition:
    SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition;
}

export interface SafetyKernelV31NodeProcessTransactionReviewPipelineComposition {
  readonly transactionReviewPipelineComposition:
    SafetyKernelV31TransactionReviewPipelineComposition;

  readonly nodeProcessAllowedExecutionCoordinatorComposition:
    SafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition;
}

export const
  SAFETY_KERNEL_V31_NODE_PROCESS_TRANSACTION_REVIEW_PIPELINE_COMPOSITION_INVARIANT =
    Object.freeze({
      A2H_FACTORY_CALLED_EXACTLY_ONCE: true,
      NEW_PIPELINE_CONSTRUCTED_EXACTLY_ONCE: true,
      PIPELINE_RECEIVES_EXACT_TRANSACTION_SERVICE_REFERENCE: true,
      PIPELINE_RECEIVES_EXACT_TRANSACTION_SESSION_STORE_REFERENCE: true,
      PIPELINE_RECEIVES_EXACT_ALLOWED_EXECUTION_BINDING_STORE_REFERENCE: true,
      PIPELINE_RECEIVES_EXACT_A2L_COORDINATOR_COMPOSITION_REFERENCE: true,
      A2L_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      TRANSACTION_SERVICE_REFERENCE_CLONED: false,
      TRANSACTION_SESSION_STORE_REFERENCE_CLONED: false,
      ALLOWED_EXECUTION_BINDING_STORE_REFERENCE_CLONED: false,
      A2L_COMPOSITION_REFERENCE_CLONED: false,
      OUTPUT_OBJECT_FROZEN: true,
      A2L_COORDINATOR_CONNECTED_TO_NEW_PIPELINE: true,
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
      NODE_PROCESS_SPAWNER_CALLED_DURING_COMPOSITION: false,
      DEFAULT_PIPELINE_FACTORY_MODIFIED: false,
      DEFAULT_RUNTIME_CONTROLLER_FACTORY_MODIFIED: false,
      RUNTIME_CONTROLLER_CONNECTED: false,
      EXTENSION_ACTIVATION_CONNECTED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    } as const);

export function createSafetyKernelV31NodeProcessTransactionReviewPipelineComposition(
  input:
    SafetyKernelV31NodeProcessTransactionReviewPipelineCompositionInput
): SafetyKernelV31NodeProcessTransactionReviewPipelineComposition {
  const nodeProcessAllowedExecutionCoordinatorComposition =
    input.nodeProcessAllowedExecutionCoordinatorComposition;

  const transactionReviewPipelineComposition =
    createSafetyKernelV31TransactionReviewPipelineComposition({
      transactionService:
        input.transactionService,
      transactionSessionStore:
        input.transactionSessionStore,
      allowedExecutionBindingStore:
        input.allowedExecutionBindingStore,
      allowedExecutionCoordinatorComposition:
        nodeProcessAllowedExecutionCoordinatorComposition
          .allowedExecutionCoordinatorComposition,
    });

  return Object.freeze({
    transactionReviewPipelineComposition,
    nodeProcessAllowedExecutionCoordinatorComposition,
  });
}