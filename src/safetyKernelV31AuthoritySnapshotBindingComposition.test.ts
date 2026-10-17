import test from "node:test";
import assert from "node:assert/strict";
import * as path from "path";

import {
  SAFETY_KERNEL_V31_AUTHORITY_SNAPSHOT_BINDING_COMPOSITION_INVARIANT,
  createSafetyKernelV31AuthoritySnapshotBindingComposition,
} from "./safetyKernelV31AuthoritySnapshotBindingComposition";

import {
  SafetyKernelV31AuthoritySnapshotBindingVerifier,
  type SafetyKernelV31AuthoritySnapshotBindingReadback,
} from "../packages/aegis-core";

import {
  SafetyKernelV31AuthoritySnapshotBindingReadPort,
  type SafetyKernelV31CanonicalAuthorityReader,
  type SafetyKernelV31SnapshotTargetIndexReader,
} from "./safetyKernelV31AuthoritySnapshotBindingReadPort";

const WORKSPACE_ID =
  "sha256:" + "a".repeat(64);

const SNAPSHOT_BINDING_SHA256 =
  "sha256:" + "b".repeat(64);

function createNoReadInputs(): {
  authorityReader:
    SafetyKernelV31CanonicalAuthorityReader;

  targetReaders:
    readonly SafetyKernelV31SnapshotTargetIndexReader[];

  counters: {
    authorityReads: number;
    indexReads: number;
  };
} {
  const counters = {
    authorityReads: 0,
    indexReads: 0,
  };

  const authorityReader:
    SafetyKernelV31CanonicalAuthorityReader = {
      getState(): unknown {
        counters.authorityReads += 1;

        throw new Error(
          "AUTHORITY_READ_DURING_COMPOSITION"
        );
      },
    };

  const targetReaders:
    readonly SafetyKernelV31SnapshotTargetIndexReader[] = [
      {
        targetId: "env_default",
        relativePath: ".env",
        snapshotIndexFile:
          "latest-safe-snapshot.json",

        async readIndex(): Promise<unknown> {
          counters.indexReads += 1;

          throw new Error(
            "INDEX_READ_DURING_COMPOSITION"
          );
        },
      },
    ];

  return {
    authorityReader,
    targetReaders,
    counters,
  };
}

test("composition invariant remains detached and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_AUTHORITY_SNAPSHOT_BINDING_COMPOSITION_INVARIANT,
    {
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
    }
  );
});

test("factory returns a frozen read-port and verifier bundle", () => {
  const inputs = createNoReadInputs();

  const composition =
    createSafetyKernelV31AuthoritySnapshotBindingComposition({
      authorityReader:
        inputs.authorityReader,
      targetReaders:
        inputs.targetReaders,
      projectRoot: "/workspace",
      aegisDir: "/workspace/.aegis",
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    composition.readPort instanceof
      SafetyKernelV31AuthoritySnapshotBindingReadPort,
    true
  );

  assert.equal(
    composition.verifier instanceof
      SafetyKernelV31AuthoritySnapshotBindingVerifier,
    true
  );

  assert.equal(
    inputs.counters.authorityReads,
    0
  );

  assert.equal(
    inputs.counters.indexReads,
    0
  );
});

test("verifier uses the exact returned read-port instance", async () => {
  const inputs = createNoReadInputs();

  const composition =
    createSafetyKernelV31AuthoritySnapshotBindingComposition({
      authorityReader:
        inputs.authorityReader,
      targetReaders:
        inputs.targetReaders,
      projectRoot: "/workspace",
      aegisDir: "/workspace/.aegis",
    });

  let returnedReadPortCalls = 0;

  composition.readPort.readCurrentBinding =
    async (): Promise<SafetyKernelV31AuthoritySnapshotBindingReadback> => {
      returnedReadPortCalls += 1;

      return {
        authorityRevision: 3,
        workspaceId: WORKSPACE_ID,
        snapshotBindingSha256:
          SNAPSHOT_BINDING_SHA256,
      };
    };

  const binding = {
    authorityRevision: 3,
    workspaceId: WORKSPACE_ID,
    snapshotBindingSha256:
      SNAPSHOT_BINDING_SHA256,
  } as Parameters<
    typeof composition.verifier.verify
  >[0];

  assert.equal(
    await composition.verifier.verify(binding),
    "verified"
  );

  assert.equal(
    returnedReadPortCalls,
    1
  );

  assert.equal(
    inputs.counters.authorityReads,
    0
  );

  assert.equal(
    inputs.counters.indexReads,
    0
  );
});

test("composition construction performs no authority or index reads", () => {
  const inputs = createNoReadInputs();

  createSafetyKernelV31AuthoritySnapshotBindingComposition({
    authorityReader:
      inputs.authorityReader,
    targetReaders:
      inputs.targetReaders,
    projectRoot: "/workspace",
    aegisDir: "/workspace/.aegis",
  });

  assert.equal(
    inputs.counters.authorityReads,
    0
  );

  assert.equal(
    inputs.counters.indexReads,
    0
  );
});

test("input references and path arguments are forwarded to the read port", () => {
  const inputs = createNoReadInputs();

  const projectRoot =
    path.join(
      process.cwd(),
      "workspace-forwarding"
    );

  const aegisDir =
    path.join(
      projectRoot,
      ".aegis"
    );

  const composition =
    createSafetyKernelV31AuthoritySnapshotBindingComposition({
      authorityReader:
        inputs.authorityReader,
      targetReaders:
        inputs.targetReaders,
      projectRoot,
      aegisDir,
    });

  const internals =
    composition.readPort as unknown as {
      readonly authorityReader:
        SafetyKernelV31CanonicalAuthorityReader;

      readonly targetReaders:
        readonly SafetyKernelV31SnapshotTargetIndexReader[];

      readonly projectRoot: string;
      readonly snapshotsDir: string;
    };

  assert.equal(
    internals.authorityReader,
    inputs.authorityReader
  );

  assert.equal(
    internals.targetReaders,
    inputs.targetReaders
  );

  assert.equal(
    internals.projectRoot,
    path.resolve(projectRoot)
  );

  assert.equal(
    internals.snapshotsDir,
    path.resolve(
      aegisDir,
      "snapshots"
    )
  );

  assert.equal(
    inputs.counters.authorityReads,
    0
  );

  assert.equal(
    inputs.counters.indexReads,
    0
  );
});