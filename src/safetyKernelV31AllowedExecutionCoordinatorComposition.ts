import type {
  AegisExecutionPort,
} from "./platformPorts";

import {
  SafetyKernelV31AllowedExecutionCoordinator,
} from "./safetyKernelV31AllowedExecutionCoordinator";

import type {
  SafetyKernelV31AuthoritySnapshotBindingComposition,
} from "./safetyKernelV31AuthoritySnapshotBindingComposition";

export interface SafetyKernelV31AllowedExecutionCoordinatorCompositionInput {
  readonly execution:
    AegisExecutionPort;

  readonly authorityBindingComposition:
    SafetyKernelV31AuthoritySnapshotBindingComposition;
}

export interface SafetyKernelV31AllowedExecutionCoordinatorComposition {
  readonly coordinator:
    SafetyKernelV31AllowedExecutionCoordinator;

  readonly authorityBindingComposition:
    SafetyKernelV31AuthoritySnapshotBindingComposition;
}

export const SAFETY_KERNEL_V31_ALLOWED_EXECUTION_COORDINATOR_COMPOSITION_INVARIANT =
  Object.freeze({
    COORDINATOR_CONSTRUCTED_EXACTLY_ONCE: true,
    COORDINATOR_RECEIVES_EXACT_EXECUTION_PORT_INSTANCE: true,
    COORDINATOR_RECEIVES_EXACT_A2F_VERIFIER_INSTANCE: true,
    A2F_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
    EXECUTION_PORT_REFERENCE_CLONED: false,
    A2F_COMPOSITION_REFERENCE_CLONED: false,
    EXECUTION_CALL_DURING_COMPOSITION: false,
    VERIFICATION_CALL_DURING_COMPOSITION: false,
    AUTHORITY_READ_DURING_COMPOSITION: false,
    INDEX_READ_DURING_COMPOSITION: false,
    BASELINE_FILE_READ_DURING_COMPOSITION: false,
    SESSION_CLAIM_CREATED_DURING_COMPOSITION: false,
    CACHE_CREATED: false,
    OUTPUT_OBJECT_FROZEN: true,
    PIPELINE_CONNECTED: false,
    RUNTIME_CONTROLLER_CONNECTED: false,
    EXTENSION_CONNECTED: false,
    NODE_PROCESS_ADAPTER_CONNECTED: false,
    RECEIPT_CONNECTED: false,
    LEDGER_CONNECTED: false,
    REAL_PROCESS_EXECUTION_REQUIRED: false,
    REAL_COMMAND_EXECUTION_REQUIRED: false,
  } as const);

export function createSafetyKernelV31AllowedExecutionCoordinatorComposition(
  input: SafetyKernelV31AllowedExecutionCoordinatorCompositionInput
): SafetyKernelV31AllowedExecutionCoordinatorComposition {
  const coordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      input.execution,
      input.authorityBindingComposition.verifier
    );

  return Object.freeze({
    coordinator,
    authorityBindingComposition:
      input.authorityBindingComposition,
  });
}