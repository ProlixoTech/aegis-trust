import assert from "node:assert/strict";
import test from "node:test";

import type {
  ProtectedTarget,
} from "./protectedTargets";

import type {
  SnapshotStore,
} from "./snapshotStore";

import {
  SAFETY_KERNEL_V31_SNAPSHOT_TARGET_INDEX_READER_COLLECTION_FACTORY_INVARIANT,
  createSafetyKernelV31SnapshotTargetIndexReaderCollection,
} from "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory";

type CollectionTarget =
  Pick<
    ProtectedTarget,
    | "target_id"
    | "relative_path"
    | "snapshot_index_file"
  >;

type CollectionStore =
  Pick<SnapshotStore, "readIndex">;

class CountingStoreMap
  extends Map<string, CollectionStore> {
  readonly getKeys: string[] = [];

  override get(key: string):
    CollectionStore | undefined {
    this.getKeys.push(key);
    return super.get(key);
  }
}

test("A2r invariant remains a detached ordered collection factory with no connection or creation-time I/O", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_SNAPSHOT_TARGET_INDEX_READER_COLLECTION_FACTORY_INVARIANT,
    {
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
    }
  );
});

test("empty targets return one frozen empty array without store lookup", () => {
  const stores =
    new CountingStoreMap();

  const readers =
    createSafetyKernelV31SnapshotTargetIndexReaderCollection({
      targets: [],
      stores,
    });

  assert.equal(
    Object.isFrozen(readers),
    true
  );

  assert.deepEqual(
    readers,
    []
  );

  assert.deepEqual(
    stores.getKeys,
    []
  );
});

test("factory preserves raw target order including duplicate ids, performs one exact target-id lookup per target, and creates frozen readers without reading indexes", () => {
  const targets:
    readonly CollectionTarget[] = [
      {
        target_id: " target-b ",
        relative_path: " src/b.ts ",
        snapshot_index_file: " b-index.json ",
      },
      {
        target_id: "target-a",
        relative_path: "src/a-first.ts",
        snapshot_index_file: "a-first-index.json",
      },
      {
        target_id: "target-a",
        relative_path: "src/a-second.ts",
        snapshot_index_file: "a-second-index.json",
      },
    ];

  let firstReadCount = 0;
  let secondReadCount = 0;

  const firstStore: CollectionStore = {
    readIndex():
      ReturnType<SnapshotStore["readIndex"]> {
      firstReadCount += 1;
      return Promise.resolve(null);
    },
  };

  const secondStore: CollectionStore = {
    readIndex():
      ReturnType<SnapshotStore["readIndex"]> {
      secondReadCount += 1;
      return Promise.resolve(null);
    },
  };

  const stores =
    new CountingStoreMap([
      [" target-b ", firstStore],
      ["target-a", secondStore],
    ]);

  const readers =
    createSafetyKernelV31SnapshotTargetIndexReaderCollection({
      targets,
      stores,
    });

  assert.equal(
    Object.isFrozen(readers),
    true
  );

  assert.equal(
    readers.length,
    3
  );

  assert.deepEqual(
    stores.getKeys,
    [" target-b ", "target-a", "target-a"]
  );

  assert.deepEqual(
    readers.map(reader => reader.targetId),
    [" target-b ", "target-a", "target-a"]
  );

  assert.deepEqual(
    readers.map(reader => reader.relativePath),
    [" src/b.ts ", "src/a-first.ts", "src/a-second.ts"]
  );

  assert.deepEqual(
    readers.map(reader => reader.snapshotIndexFile),
    [
      " b-index.json ",
      "a-first-index.json",
      "a-second-index.json",
    ]
  );

  assert.equal(
    Object.isFrozen(readers[0]),
    true
  );

  assert.equal(
    Object.isFrozen(readers[1]),
    true
  );

  assert.equal(
    Object.isFrozen(readers[2]),
    true
  );

  assert.equal(
    firstReadCount,
    0
  );

  assert.equal(
    secondReadCount,
    0
  );
});

test("reader delegation uses the exact matched store references and ignores unused extra stores", async () => {
  const target: CollectionTarget = {
    target_id: "target-a",
    relative_path: "src/a.ts",
    snapshot_index_file: "a-index.json",
  };

  const sourcePromise:
    ReturnType<SnapshotStore["readIndex"]> =
      Promise.resolve(null);

  let selectedReadCount = 0;
  let extraReadCount = 0;

  const selectedStore: CollectionStore = {
    readIndex():
      ReturnType<SnapshotStore["readIndex"]> {
      selectedReadCount += 1;
      return sourcePromise;
    },
  };

  const extraStore: CollectionStore = {
    readIndex():
      ReturnType<SnapshotStore["readIndex"]> {
      extraReadCount += 1;
      return Promise.resolve(null);
    },
  };

  const stores =
    new CountingStoreMap([
      ["target-a", selectedStore],
      ["unused-extra", extraStore],
    ]);

  const readers =
    createSafetyKernelV31SnapshotTargetIndexReaderCollection({
      targets: [target],
      stores,
    });

  assert.deepEqual(
    stores.getKeys,
    ["target-a"]
  );

  const returnedPromise =
    readers[0].readIndex();

  assert.equal(
    returnedPromise,
    sourcePromise
  );

  assert.equal(
    await returnedPromise,
    null
  );

  assert.equal(
    selectedReadCount,
    1
  );

  assert.equal(
    extraReadCount,
    0
  );
});

test("missing store throws the exact error after one lookup per visited target without index reads or partial return", () => {
  const targets:
    readonly CollectionTarget[] = [
      {
        target_id: "target-a",
        relative_path: "src/a.ts",
        snapshot_index_file: "a-index.json",
      },
      {
        target_id: "target-missing",
        relative_path: "src/missing.ts",
        snapshot_index_file: "missing-index.json",
      },
    ];

  let readCount = 0;

  const existingStore: CollectionStore = {
    readIndex():
      ReturnType<SnapshotStore["readIndex"]> {
      readCount += 1;
      return Promise.resolve(null);
    },
  };

  const stores =
    new CountingStoreMap([
      ["target-a", existingStore],
    ]);

  assert.throws(
    () =>
      createSafetyKernelV31SnapshotTargetIndexReaderCollection({
        targets,
        stores,
      }),
    error =>
      error instanceof Error &&
      error.message ===
        "MISSING_SNAPSHOT_STORE_FOR_TARGET"
  );

  assert.deepEqual(
    stores.getKeys,
    ["target-a", "target-missing"]
  );

  assert.equal(
    readCount,
    0
  );
});