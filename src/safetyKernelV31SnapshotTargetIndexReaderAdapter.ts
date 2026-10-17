import type {
  ProtectedTarget,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31SnapshotTargetIndexReader,
} from "../packages/aegis-core";

import type {
  SnapshotStore,
} from "./snapshotStore";

export interface SafetyKernelV31SnapshotTargetIndexReaderAdapterInput {
  readonly target:
    Pick<
      ProtectedTarget,
      | "target_id"
      | "relative_path"
      | "snapshot_index_file"
    >;

  readonly snapshotStore:
    Pick<SnapshotStore, "readIndex">;
}

export const
  SAFETY_KERNEL_V31_SNAPSHOT_TARGET_INDEX_READER_ADAPTER_INVARIANT =
    Object.freeze({
      TARGET_METADATA_SOURCE_IS_PROTECTED_TARGET: true,
      INDEX_SOURCE_IS_SNAPSHOT_STORE: true,
      TARGET_ID_MAPPED_WITHOUT_TRANSFORMATION: true,
      RELATIVE_PATH_MAPPED_WITHOUT_TRANSFORMATION: true,
      SNAPSHOT_INDEX_FILE_MAPPED_WITHOUT_TRANSFORMATION: true,
      READ_INDEX_DELEGATED_ON_EVERY_CALL: true,
      READ_INDEX_DELEGATION_COUNT_PER_CALL: 1,
      SOURCE_PROMISE_RETURNED_UNCHANGED: true,
      RESOLUTION_RETURNED_UNCHANGED: true,
      REJECTION_RETURNED_UNCHANGED: true,
      READ_INDEX_DURING_CREATION: false,
      FILE_READ_DURING_CREATION: false,
      JSON_PARSE_DURING_CREATION: false,
      DIRECTORY_CREATION_DURING_CREATION: false,
      CACHE_CREATED: false,
      ERROR_SWALLOWED: false,
      INDEX_TRANSFORMED: false,
      METADATA_VALIDATION_DUPLICATED: false,
      OUTPUT_OBJECT_FROZEN: true,
      TARGET_READER_ARRAY_CREATED: false,
      STORE_MAP_CREATED: false,
      PROTECTED_TARGET_REGISTRY_READ_DURING_CREATION: false,
      A2P_FACTORY_CALLED: false,
      EXTENSION_TS_MODIFIED: false,
      EXTENSION_ACTIVATION_CONNECTED: false,
      VSCODE_IMPORTED: false,
      COMMAND_REGISTERED: false,
      SUBSCRIPTION_MUTATED: false,
      NODE_PROCESS_EXECUTION_PERFORMED: false,
      REVIEW_CALL_PERFORMED: false,
      EVIDENCE_WRITTEN: false,
      RECEIPT_WRITTEN: false,
      LEDGER_WRITTEN: false,
      CONNECTION_READY: false,
      FULL_L5C_COMPLETE: false,
      PRODUCT_PASS: false,
      FINAL_PASS: false,
      RELEASE_READY: false,
      UPLOAD_READY: false,
    } as const);

export function createSafetyKernelV31SnapshotTargetIndexReaderAdapter(
  input:
    SafetyKernelV31SnapshotTargetIndexReaderAdapterInput
): SafetyKernelV31SnapshotTargetIndexReader {
  return Object.freeze({
    targetId:
      input.target.target_id,

    relativePath:
      input.target.relative_path,

    snapshotIndexFile:
      input.target.snapshot_index_file,

    readIndex(): Promise<unknown> {
      return input.snapshotStore.readIndex();
    },
  });
}