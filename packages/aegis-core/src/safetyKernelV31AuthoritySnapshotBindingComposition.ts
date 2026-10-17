import {
  SafetyKernelV31AuthoritySnapshotBindingVerifier,
} from "./safetyKernelV31AuthoritySnapshotBindingVerifier";

import {
  SafetyKernelV31AuthoritySnapshotBindingReadPort,
  type SafetyKernelV31CanonicalAuthorityReader,
  type SafetyKernelV31SnapshotTargetIndexReader,
} from "./safetyKernelV31AuthoritySnapshotBindingReadPort";

export interface SafetyKernelV31AuthoritySnapshotBindingCompositionInput {
  readonly authorityReader:
    SafetyKernelV31CanonicalAuthorityReader;

  readonly targetReaders:
    readonly SafetyKernelV31SnapshotTargetIndexReader[];

  readonly projectRoot: string;
  readonly aegisDir: string;
}

export interface SafetyKernelV31AuthoritySnapshotBindingComposition {
  readonly readPort:
    SafetyKernelV31AuthoritySnapshotBindingReadPort;

  readonly verifier:
    SafetyKernelV31AuthoritySnapshotBindingVerifier;
}

export const SAFETY_KERNEL_V31_AUTHORITY_SNAPSHOT_BINDING_COMPOSITION_INVARIANT =
  Object.freeze({
    READ_PORT_CONSTRUCTED_EXACTLY_ONCE: true,
    VERIFIER_CONSTRUCTED_EXACTLY_ONCE: true,
    VERIFIER_RECEIVES_RETURNED_READ_PORT_INSTANCE: true,
    INPUT_REFERENCES_CLONED: false,
    AUTHORITY_READ_DURING_COMPOSITION: false,
    INDEX_READ_DURING_COMPOSITION: false,
    BASELINE_FILE_READ_DURING_COMPOSITION: false,
    CACHE_CREATED: false,
    OUTPUT_OBJECT_FROZEN: true,
    EXTENSION_CONNECTED: false,
    RUNTIME_CONTROLLER_CONNECTED: false,
    PIPELINE_CONNECTED: false,
    COORDINATOR_CONNECTED: false,
    NODE_PROCESS_ADAPTER_CONNECTED: false,
    RECEIPT_CONNECTED: false,
    LEDGER_CONNECTED: false,
    REAL_PROCESS_EXECUTION_REQUIRED: false,
    REAL_COMMAND_EXECUTION_REQUIRED: false,
  } as const);

export function createSafetyKernelV31AuthoritySnapshotBindingComposition(
  input: SafetyKernelV31AuthoritySnapshotBindingCompositionInput
): SafetyKernelV31AuthoritySnapshotBindingComposition {
  const readPort =
    new SafetyKernelV31AuthoritySnapshotBindingReadPort(
      input.authorityReader,
      input.targetReaders,
      input.projectRoot,
      input.aegisDir
    );

  const verifier =
    new SafetyKernelV31AuthoritySnapshotBindingVerifier(
      readPort
    );

  return Object.freeze({
    readPort,
    verifier,
  });
}