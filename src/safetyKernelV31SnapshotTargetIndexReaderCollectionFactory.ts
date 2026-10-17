import type {
  ProtectedTarget,
} from "../packages/aegis-core";

import type {
  SafetyKernelV31SnapshotTargetIndexReader,
} from "../packages/aegis-core";

import {
  createSafetyKernelV31SnapshotTargetIndexReaderAdapter,
} from "./safetyKernelV31SnapshotTargetIndexReaderAdapter";

import type {
  SnapshotStore,
} from "./snapshotStore";

export interface SafetyKernelV31SnapshotTargetIndexReaderCollectionFactoryInput {
  readonly targets:
    readonly Pick<
      ProtectedTarget,
      | "target_id"
      | "relative_path"
      | "snapshot_index_file"
    >[];

  readonly stores:
    ReadonlyMap<
      string,
      Pick<SnapshotStore, "readIndex">
    >;
}

export const
  SAFETY_KERNEL_V31_SNAPSHOT_TARGET_INDEX_READER_COLLECTION_FACTORY_INVARIANT =
    Object.freeze({
      TARGET_ITERATION_SOURCE_IS_INPUT_TARGETS: true,
      TARGET_ORDER_PRESERVED: true,
      STORE_LOOKUP_KEY_IS_TARGET_ID: true,
      STORE_LOOKUP_COUNT_PER_TARGET: 1,
      ADAPTER_FACTORY_CALL_COUNT_PER_TARGET: 1,
      ADAPTER_TARGET_REFERENCE_PASSED_UNCHANGED: true,
      ADAPTER_STORE_REFERENCE_PASSED_UNCHANGED: true,
      OUTPUT_ARRAY_FROZEN: true,
      OUTPUT_READER_OBJECTS_FROZEN_BY_A2Q: true,
      EMPTY_TARGET_ARRAY_RETURNS_FROZEN_EMPTY_ARRAY: true,
      UNUSED_EXTRA_STORES_IGNORED: true,
      MISSING_STORE_THROWS: true,
      MISSING_STORE_ERROR:
        "MISSING_SNAPSHOT_STORE_FOR_TARGET",
      PARTIAL_RESULT_RETURNED_ON_MISSING_STORE: false,
      READ_INDEX_DURING_CREATION: false,
      FILE_READ_DURING_CREATION: false,
      JSON_PARSE_DURING_CREATION: false,
      DIRECTORY_CREATION_DURING_CREATION: false,
      SNAPSHOT_STORE_CONSTRUCTION_ALLOWED: false,
      PROTECTED_TARGET_REGISTRY_READ_DURING_CREATION: false,
      GET_PROTECTED_TARGETS_CALL_ALLOWED: false,
      DUPLICATE_TARGET_VALIDATION_ALLOWED: false,
      METADATA_VALIDATION_DUPLICATED: false,
      CACHE_CREATED: false,
      ERROR_SWALLOWED: false,
      A2P_FACTORY_CALLED: false,
      NODE_PROCESS_EXECUTION_PERFORMED: false,
      REVIEW_CALL_PERFORMED: false,
      EVIDENCE_WRITTEN: false,
      RECEIPT_WRITTEN: false,
      LEDGER_WRITTEN: false,
      EXTENSION_TS_MODIFIED: false,
      EXTENSION_ACTIVATION_CONNECTED: false,
      VSCODE_IMPORTED: false,
      COMMAND_REGISTERED: false,
      SUBSCRIPTION_MUTATED: false,
      CONNECTION_READY: false,
      FULL_L5C_COMPLETE: false,
      PRODUCT_PASS: false,
      FINAL_PASS: false,
      RELEASE_READY: false,
      UPLOAD_READY: false,
    } as const);

export function createSafetyKernelV31SnapshotTargetIndexReaderCollection(
  input:
    SafetyKernelV31SnapshotTargetIndexReaderCollectionFactoryInput
): readonly SafetyKernelV31SnapshotTargetIndexReader[] {
  const readers:
    SafetyKernelV31SnapshotTargetIndexReader[] = [];

  for (const target of input.targets) {
    const snapshotStore =
      input.stores.get(target.target_id);

    if (!snapshotStore) {
      throw new Error(
        "MISSING_SNAPSHOT_STORE_FOR_TARGET"
      );
    }

    readers.push(
      createSafetyKernelV31SnapshotTargetIndexReaderAdapter({
        target,
        snapshotStore,
      })
    );
  }

  return Object.freeze(readers);
}