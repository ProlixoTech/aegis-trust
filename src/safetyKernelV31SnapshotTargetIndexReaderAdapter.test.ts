import assert from "node:assert/strict";
import test from "node:test";

import type {
  ProtectedTarget,
} from "./protectedTargets";

import type {
  SnapshotStore,
} from "./snapshotStore";

import {
  SAFETY_KERNEL_V31_SNAPSHOT_TARGET_INDEX_READER_ADAPTER_INVARIANT,
  createSafetyKernelV31SnapshotTargetIndexReaderAdapter,
} from "./safetyKernelV31SnapshotTargetIndexReaderAdapter";

type AdapterTarget =
  Pick<
    ProtectedTarget,
    | "target_id"
    | "relative_path"
    | "snapshot_index_file"
  >;

type AdapterStore =
  Pick<SnapshotStore, "readIndex">;

test("A2q invariant remains a detached one-reader adapter with no connection or creation-time I/O", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_SNAPSHOT_TARGET_INDEX_READER_ADAPTER_INVARIANT,
    {
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
    }
  );
});

test("factory returns one frozen reader with exact unvalidated metadata and no read during creation", () => {
  const target: AdapterTarget = {
    target_id: " target-a ",
    relative_path: "src/example.ts",
    snapshot_index_file: " index-a.json ",
  };

  let readCount = 0;

  const snapshotStore: AdapterStore = {
    readIndex():
      ReturnType<SnapshotStore["readIndex"]> {
      readCount += 1;
      return Promise.resolve(null);
    },
  };

  const reader =
    createSafetyKernelV31SnapshotTargetIndexReaderAdapter({
      target,
      snapshotStore,
    });

  assert.equal(
    Object.isFrozen(reader),
    true
  );

  assert.equal(
    reader.targetId,
    target.target_id
  );

  assert.equal(
    reader.relativePath,
    target.relative_path
  );

  assert.equal(
    reader.snapshotIndexFile,
    target.snapshot_index_file
  );

  assert.equal(
    readCount,
    0
  );
});

test("readIndex delegates exactly once per call and returns each distinct source promise unchanged without caching", async () => {
  const target: AdapterTarget = {
    target_id: "target-a",
    relative_path: "src/example.ts",
    snapshot_index_file: "index-a.json",
  };

  const firstPromise:
    ReturnType<SnapshotStore["readIndex"]> =
      Promise.resolve(null);

  const secondPromise:
    ReturnType<SnapshotStore["readIndex"]> =
      Promise.resolve(null);

  assert.notEqual(
    firstPromise,
    secondPromise
  );

  let readCount = 0;

  const snapshotStore: AdapterStore = {
    readIndex():
      ReturnType<SnapshotStore["readIndex"]> {
      readCount += 1;

      return readCount === 1
        ? firstPromise
        : secondPromise;
    },
  };

  const reader =
    createSafetyKernelV31SnapshotTargetIndexReaderAdapter({
      target,
      snapshotStore,
    });

  const firstReturned =
    reader.readIndex();

  assert.equal(
    readCount,
    1
  );

  assert.equal(
    firstReturned,
    firstPromise
  );

  const secondReturned =
    reader.readIndex();

  assert.equal(
    readCount,
    2
  );

  assert.equal(
    secondReturned,
    secondPromise
  );

  assert.equal(
    await firstReturned,
    null
  );

  assert.equal(
    await secondReturned,
    null
  );
});

test("readIndex preserves the exact resolved value without transformation", async () => {
  const target: AdapterTarget = {
    target_id: "target-a",
    relative_path: "src/example.ts",
    snapshot_index_file: "index-a.json",
  };

  const indexValue = null;

  const sourcePromise:
    ReturnType<SnapshotStore["readIndex"]> =
      Promise.resolve(indexValue);

  let readCount = 0;

  const snapshotStore: AdapterStore = {
    readIndex():
      ReturnType<SnapshotStore["readIndex"]> {
      readCount += 1;
      return sourcePromise;
    },
  };

  const reader =
    createSafetyKernelV31SnapshotTargetIndexReaderAdapter({
      target,
      snapshotStore,
    });

  const returnedPromise =
    reader.readIndex();

  const resolvedValue =
    await returnedPromise;

  assert.equal(
    returnedPromise,
    sourcePromise
  );

  assert.equal(
    resolvedValue,
    indexValue
  );

  assert.equal(
    readCount,
    1
  );
});

test("readIndex preserves the exact rejection without swallowing or replacing it", async () => {
  const target: AdapterTarget = {
    target_id: "target-a",
    relative_path: "src/example.ts",
    snapshot_index_file: "index-a.json",
  };

  const expectedError =
    new Error("SNAPSHOT_INDEX_READ_FAILED");

  let readCount = 0;

  let sourcePromise:
    ReturnType<SnapshotStore["readIndex"]> |
    undefined;

  const snapshotStore: AdapterStore = {
    readIndex():
      ReturnType<SnapshotStore["readIndex"]> {
      readCount += 1;
      sourcePromise = Promise.reject(expectedError);
      return sourcePromise;
    },
  };

  const reader =
    createSafetyKernelV31SnapshotTargetIndexReaderAdapter({
      target,
      snapshotStore,
    });

  const returnedPromise =
    reader.readIndex();

  assert.equal(
    returnedPromise,
    sourcePromise
  );

  await assert.rejects(
    returnedPromise,
    error => error === expectedError
  );

  assert.equal(
    readCount,
    1
  );
});