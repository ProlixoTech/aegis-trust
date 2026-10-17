import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  SAFETY_KERNEL_V31_AUTHORITY_SNAPSHOT_BINDING_READ_PORT_INVARIANT,
  SafetyKernelV31AuthoritySnapshotBindingReadPort,
  SafetyKernelV31CanonicalAuthorityReader,
  SafetyKernelV31SnapshotTargetIndexReader,
} from "./safetyKernelV31AuthoritySnapshotBindingReadPort";

const WORKSPACE_ID =
  "sha256:" + "a".repeat(64);

function normalizePath(value: string): string {
  return value.replace(/\\/g, "/").toLowerCase();
}

function sha256(value: Buffer | string): string {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

function encodeField(name: string, value: string): string {
  return (
    name +
    ":" +
    Buffer.byteLength(value, "utf8") +
    ":" +
    value
  );
}

function expectedAggregateHash(
  entries: ReadonlyArray<{
    targetId: string;
    relativePath: string;
    snapshotIndexFile: string;
    baselineSnapshotFile: string;
    baselineContentSha256: string;
  }>
): string {
  const sorted = [...entries].sort((left, right) =>
    left.targetId < right.targetId
      ? -1
      : left.targetId > right.targetId
        ? 1
        : 0
  );

  const lines = [
    encodeField(
      "domain",
      "aegis-authority-snapshot-binding-v1"
    ),
    encodeField(
      "targetCount",
      String(sorted.length)
    ),
  ];

  sorted.forEach((entry, index) => {
    const prefix = "target[" + index + "]";

    lines.push(
      encodeField(
        prefix + ".targetId",
        entry.targetId
      ),
      encodeField(
        prefix + ".relativePath",
        entry.relativePath
      ),
      encodeField(
        prefix + ".snapshotIndexFile",
        entry.snapshotIndexFile
      ),
      encodeField(
        prefix + ".baselineSnapshotFile",
        entry.baselineSnapshotFile
      ),
      encodeField(
        prefix + ".baselineContentSha256",
        entry.baselineContentSha256
      )
    );
  });

  return (
    "sha256:" +
    sha256(lines.join("\n"))
  );
}

class FakeAuthorityReader
  implements SafetyKernelV31CanonicalAuthorityReader {
  calls = 0;

  constructor(
    readonly state: {
      revision: number;
      workspaceId: string;
      protectedTargets: string[];
    }
  ) {}

  getState(): unknown {
    this.calls += 1;

    return {
      revision: this.state.revision,
      workspaceId: this.state.workspaceId,
      protectedTargets:
        [...this.state.protectedTargets],
    };
  }
}

interface TargetFixture {
  readonly reader:
    SafetyKernelV31SnapshotTargetIndexReader;
  readonly index:
    Record<string, unknown>;
  readonly baselinePath: string;
  readonly relativeBaselinePath: string;
  readonly targetAbsPath: string;
  readonly counters: {
    indexReads: number;
  };
}

function createTargetFixture(
  projectRoot: string,
  aegisDir: string,
  targetId: string,
  relativePath: string,
  snapshotIndexFile: string,
  content: string
): TargetFixture {
  const targetAbsPath =
    path.resolve(projectRoot, relativePath);

  const snapshotDirectory =
    path.join(
      aegisDir,
      "snapshots",
      targetId,
      "files"
    );

  fs.mkdirSync(snapshotDirectory, {
    recursive: true,
  });

  const baselinePath =
    path.join(
      snapshotDirectory,
      targetId + ".snapshot"
    );

  fs.writeFileSync(
    baselinePath,
    content
  );

  const index: Record<string, unknown> = {
    snapshot_id: "rolling-id",
    original_path: targetAbsPath,
    normalized_key:
      normalizePath(targetAbsPath),
    source: "baseline_registration",
    created_at: "2026-01-01T00:00:00.000Z",
    baseline_snapshot_file:
      baselinePath,
    baseline_content_sha256:
      sha256(Buffer.from(content, "utf8")),
    snapshot_file: baselinePath + ".rolling",
    content_sha256: "b".repeat(64),
  };

  const counters = {
    indexReads: 0,
  };

  const reader:
    SafetyKernelV31SnapshotTargetIndexReader = {
      targetId,
      relativePath,
      snapshotIndexFile,

      async readIndex(): Promise<unknown> {
        counters.indexReads += 1;
        return { ...index };
      },
    };

  return {
    reader,
    index,
    baselinePath,
    relativeBaselinePath:
      path
        .relative(
          path.join(aegisDir, "snapshots"),
          baselinePath
        )
        .replace(/\\/g, "/"),
    targetAbsPath,
    counters,
  };
}

function createTempLayout(): {
  root: string;
  projectRoot: string;
  aegisDir: string;
} {
  const root =
    fs.mkdtempSync(
      path.join(
        os.tmpdir(),
        "aegis-authority-snapshot-binding-"
      )
    );

  const projectRoot =
    path.join(root, "workspace");

  const aegisDir =
    path.join(projectRoot, ".aegis");

  fs.mkdirSync(
    path.join(aegisDir, "snapshots"),
    { recursive: true }
  );

  return {
    root,
    projectRoot,
    aegisDir,
  };
}

test("read-port invariant remains detached and fail-closed", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_AUTHORITY_SNAPSHOT_BINDING_READ_PORT_INVARIANT,
    {
      AUTHORITY_STATE_READ_ON_EVERY_CALL: true,
      EACH_INDEX_READ_ON_EVERY_CALL: true,
      NULL_INDEX_SKIPPED_AS_UNREGISTERED: true,
      AT_LEAST_ONE_REGISTERED_INDEX_REQUIRED: true,
      NON_NULL_MALFORMED_INDEX_REJECTED: true,
      BASELINE_FILE_BYTES_READ_ON_EVERY_CALL: true,
      STATE_CACHE_ALLOWED: false,
      AUTHORITY_TARGET_SET_EXACT_MATCH_REQUIRED: true,
      DUPLICATE_TARGET_ID_REJECTED: true,
      DUPLICATE_INDEX_FILENAME_REJECTED: true,
      ORIGINAL_PATH_BINDING_REQUIRED: true,
      NORMALIZED_KEY_BINDING_REQUIRED: true,
      BASELINE_PATH_MUST_BE_ABSOLUTE: true,
      BASELINE_PATH_MUST_BE_INSIDE_SNAPSHOTS: true,
      BASELINE_REALPATH_CONTAINMENT_REQUIRED: true,
      BASELINE_FILE_SHA256_RECHECK_REQUIRED: true,
      ROLLING_FIELDS_INCLUDED_IN_AGGREGATE: false,
      SNAPSHOT_ID_INCLUDED_IN_AGGREGATE: false,
      CREATED_AT_INCLUDED_IN_AGGREGATE: false,
      EXTENSION_CONNECTED: false,
      NODE_PROCESS_ADAPTER_CONNECTED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("exact immutable multi-target aggregate is deterministic", async () => {
  const layout = createTempLayout();

  try {
    const first = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    const second = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "package_json",
      "package.json",
      "latest-safe-snapshot.package_json.json",
      "{\"name\":\"test\"}\n"
    );

    const authority =
      new FakeAuthorityReader({
        revision: 7,
        workspaceId: WORKSPACE_ID,
        protectedTargets: [
          "env_default",
          "package_json",
        ],
      });

    const port =
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [second.reader, first.reader],
        layout.projectRoot,
        layout.aegisDir
      );

    const result =
      await port.readCurrentBinding();

    assert.deepEqual(result, {
      authorityRevision: 7,
      workspaceId: WORKSPACE_ID,
      snapshotBindingSha256:
        expectedAggregateHash([
          {
            targetId: "env_default",
            relativePath: ".env",
            snapshotIndexFile:
              "latest-safe-snapshot.json",
            baselineSnapshotFile:
              first.relativeBaselinePath,
            baselineContentSha256:
              String(
                first.index
                  .baseline_content_sha256
              ),
          },
          {
            targetId: "package_json",
            relativePath: "package.json",
            snapshotIndexFile:
              "latest-safe-snapshot.package_json.json",
            baselineSnapshotFile:
              second.relativeBaselinePath,
            baselineContentSha256:
              String(
                second.index
                  .baseline_content_sha256
              ),
          },
        ]),
    });
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("every call reads fresh authority, indexes, and baseline bytes", async () => {
  const layout = createTempLayout();

  try {
    const fixture = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    const authority =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: ["env_default"],
      });

    const port =
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [fixture.reader],
        layout.projectRoot,
        layout.aegisDir
      );

    const first =
      await port.readCurrentBinding();

    authority.state.revision = 2;

    fs.writeFileSync(
      fixture.baselinePath,
      "A=2\n"
    );

    fixture.index.baseline_content_sha256 =
      sha256(Buffer.from("A=2\n", "utf8"));

    const second =
      await port.readCurrentBinding();

    assert.equal(first.authorityRevision, 1);
    assert.equal(second.authorityRevision, 2);
    assert.notEqual(
      first.snapshotBindingSha256,
      second.snapshotBindingSha256
    );
    assert.equal(authority.calls, 2);
    assert.equal(fixture.counters.indexReads, 2);
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("target reader input order does not change the aggregate", async () => {
  const layout = createTempLayout();

  try {
    const first = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    const second = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "package_json",
      "package.json",
      "latest-safe-snapshot.package_json.json",
      "{}\n"
    );

    const createAuthority = () =>
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: [
          "package_json",
          "env_default",
        ],
      });

    const forward =
      await new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        createAuthority(),
        [first.reader, second.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding();

    const reverse =
      await new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        createAuthority(),
        [second.reader, first.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding();

    assert.equal(
      forward.snapshotBindingSha256,
      reverse.snapshotBindingSha256
    );
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("authority protected-target set must exactly match target readers", async () => {
  const layout = createTempLayout();

  try {
    const fixture = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    const authority =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: [
          "env_default",
          "package_json",
        ],
      });

    const port =
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [fixture.reader],
        layout.projectRoot,
        layout.aegisDir
      );

    await assert.rejects(
      port.readCurrentBinding(),
      /AUTHORITY_PROTECTED_TARGET_SET_MISMATCH/
    );
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("duplicate target ids and index filenames are rejected", async () => {
  const layout = createTempLayout();

  try {
    const first = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    const duplicateIdReader = {
      ...first.reader,
      relativePath: ".env.local",
      snapshotIndexFile:
        "latest-safe-snapshot.env-local.json",
    };

    const authorityForDuplicateId =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: ["env_default"],
      });

    await assert.rejects(
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authorityForDuplicateId,
        [first.reader, duplicateIdReader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding(),
      /DUPLICATE_TARGET_ID/
    );

    const second = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "package_json",
      "package.json",
      "latest-safe-snapshot.package_json.json",
      "{}\n"
    );

    const duplicateIndexReader = {
      ...second.reader,
      snapshotIndexFile:
        first.reader.snapshotIndexFile,
    };

    const authorityForDuplicateIndex =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: [
          "env_default",
          "package_json",
        ],
      });

    await assert.rejects(
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authorityForDuplicateIndex,
        [first.reader, duplicateIndexReader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding(),
      /DUPLICATE_SNAPSHOT_INDEX_FILENAME/
    );
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("non-null malformed snapshot indexes fail closed", async () => {
  const layout = createTempLayout();

  try {
    const authority =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: ["env_default"],
      });

    for (const value of [
      undefined,
      {},
      {
        original_path:
          path.join(layout.projectRoot, ".env"),
      },
    ]) {
      const reader:
        SafetyKernelV31SnapshotTargetIndexReader = {
          targetId: "env_default",
          relativePath: ".env",
          snapshotIndexFile:
            "latest-safe-snapshot.json",
          async readIndex(): Promise<unknown> {
            return value;
          },
        };

      await assert.rejects(
        new SafetyKernelV31AuthoritySnapshotBindingReadPort(
          authority,
          [reader],
          layout.projectRoot,
          layout.aegisDir
        ).readCurrentBinding()
      );
    }
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("original path and normalized key bindings are enforced", async () => {
  const layout = createTempLayout();

  try {
    const fixture = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    const authority =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: ["env_default"],
      });

    fixture.index.original_path =
      path.join(layout.projectRoot, ".env.local");

    await assert.rejects(
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [fixture.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding(),
      /INDEX_ORIGINAL_PATH_BINDING_MISMATCH/
    );

    fixture.index.original_path =
      fixture.targetAbsPath;

    fixture.index.normalized_key =
      normalizePath(
        path.join(
          layout.projectRoot,
          ".env.local"
        )
      );

    await assert.rejects(
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [fixture.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding(),
      /INDEX_NORMALIZED_KEY_BINDING_MISMATCH/
    );
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("baseline path must be absolute and lexically inside snapshots", async () => {
  const layout = createTempLayout();

  try {
    const fixture = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    const authority =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: ["env_default"],
      });

    fixture.index.baseline_snapshot_file =
      "relative.snapshot";

    await assert.rejects(
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [fixture.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding(),
      /BASELINE_SNAPSHOT_FILE_NOT_ABSOLUTE/
    );

    const outsidePath =
      path.join(layout.root, "outside.snapshot");

    fs.writeFileSync(outsidePath, "A=1\n");

    fixture.index.baseline_snapshot_file =
      outsidePath;

    await assert.rejects(
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [fixture.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding(),
      /BASELINE_SNAPSHOT_PATH_OUTSIDE_SNAPSHOTS/
    );
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("baseline symlink escape is rejected by realpath containment", async () => {
  const layout = createTempLayout();

  try {
    const fixture = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    const outsidePath =
      path.join(layout.root, "outside.snapshot");

    fs.writeFileSync(outsidePath, "A=1\n");

    const linkPath =
      path.join(
        layout.aegisDir,
        "snapshots",
        "escape.snapshot"
      );

    fs.symlinkSync(outsidePath, linkPath);

    fixture.index.baseline_snapshot_file =
      linkPath;

    const authority =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: ["env_default"],
      });

    await assert.rejects(
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [fixture.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding(),
      /BASELINE_SNAPSHOT_REALPATH_OUTSIDE_SNAPSHOTS/
    );
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("baseline file byte hash is rechecked", async () => {
  const layout = createTempLayout();

  try {
    const fixture = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    fs.writeFileSync(
      fixture.baselinePath,
      "TAMPERED=1\n"
    );

    const authority =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: ["env_default"],
      });

    await assert.rejects(
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [fixture.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding(),
      /BASELINE_SNAPSHOT_SHA256_MISMATCH/
    );
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("rolling fields, snapshot id, and created time do not affect aggregate", async () => {
  const layout = createTempLayout();

  try {
    const fixture = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    const authority =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: ["env_default"],
      });

    const port =
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [fixture.reader],
        layout.projectRoot,
        layout.aegisDir
      );

    const first =
      await port.readCurrentBinding();

    fixture.index.snapshot_id =
      "different-snapshot-id";
    fixture.index.created_at =
      "2099-12-31T23:59:59.999Z";
    fixture.index.snapshot_file =
      "/different/rolling/file";
    fixture.index.content_sha256 =
      "f".repeat(64);

    const second =
      await port.readCurrentBinding();

    assert.equal(
      first.snapshotBindingSha256,
      second.snapshotBindingSha256
    );
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("valid index plus null index aggregates only the registered target", async () => {
  const layout = createTempLayout();

  try {
    const valid = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    let missingReads = 0;

    const missingReader:
      SafetyKernelV31SnapshotTargetIndexReader = {
        targetId: "env_local",
        relativePath: ".env.local",
        snapshotIndexFile:
          "latest-safe-snapshot.env_local.json",

        async readIndex(): Promise<unknown> {
          missingReads += 1;
          return null;
        },
      };

    const authority =
      new FakeAuthorityReader({
        revision: 9,
        workspaceId: WORKSPACE_ID,
        protectedTargets: [
          "env_default",
          "env_local",
        ],
      });

    const result =
      await new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [missingReader, valid.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding();

    assert.deepEqual(result, {
      authorityRevision: 9,
      workspaceId: WORKSPACE_ID,
      snapshotBindingSha256:
        expectedAggregateHash([
          {
            targetId: "env_default",
            relativePath: ".env",
            snapshotIndexFile:
              "latest-safe-snapshot.json",
            baselineSnapshotFile:
              valid.relativeBaselinePath,
            baselineContentSha256:
              String(
                valid.index
                  .baseline_content_sha256
              ),
          },
        ]),
    });

    assert.equal(
      valid.counters.indexReads,
      1
    );

    assert.equal(missingReads, 1);
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("null and valid reader order does not change the aggregate", async () => {
  const layout = createTempLayout();

  try {
    const valid = createTargetFixture(
      layout.projectRoot,
      layout.aegisDir,
      "env_default",
      ".env",
      "latest-safe-snapshot.json",
      "A=1\n"
    );

    let missingReads = 0;

    const missingReader:
      SafetyKernelV31SnapshotTargetIndexReader = {
        targetId: "env_local",
        relativePath: ".env.local",
        snapshotIndexFile:
          "latest-safe-snapshot.env_local.json",

        async readIndex(): Promise<unknown> {
          missingReads += 1;
          return null;
        },
      };

    const createAuthority = () =>
      new FakeAuthorityReader({
        revision: 10,
        workspaceId: WORKSPACE_ID,
        protectedTargets: [
          "env_local",
          "env_default",
        ],
      });

    const forward =
      await new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        createAuthority(),
        [valid.reader, missingReader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding();

    const reverse =
      await new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        createAuthority(),
        [missingReader, valid.reader],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding();

    assert.equal(
      forward.snapshotBindingSha256,
      reverse.snapshotBindingSha256
    );

    assert.equal(
      valid.counters.indexReads,
      2
    );

    assert.equal(missingReads, 2);
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});

test("all null snapshot indexes fail closed after every reader is checked", async () => {
  const layout = createTempLayout();

  try {
    const readCounts = {
      envDefault: 0,
      envLocal: 0,
    };

    const envDefault:
      SafetyKernelV31SnapshotTargetIndexReader = {
        targetId: "env_default",
        relativePath: ".env",
        snapshotIndexFile:
          "latest-safe-snapshot.json",

        async readIndex(): Promise<unknown> {
          readCounts.envDefault += 1;
          return null;
        },
      };

    const envLocal:
      SafetyKernelV31SnapshotTargetIndexReader = {
        targetId: "env_local",
        relativePath: ".env.local",
        snapshotIndexFile:
          "latest-safe-snapshot.env_local.json",

        async readIndex(): Promise<unknown> {
          readCounts.envLocal += 1;
          return null;
        },
      };

    const authority =
      new FakeAuthorityReader({
        revision: 1,
        workspaceId: WORKSPACE_ID,
        protectedTargets: [
          "env_default",
          "env_local",
        ],
      });

    await assert.rejects(
      new SafetyKernelV31AuthoritySnapshotBindingReadPort(
        authority,
        [envLocal, envDefault],
        layout.projectRoot,
        layout.aegisDir
      ).readCurrentBinding(),
      /NO_REGISTERED_SNAPSHOT_INDEXES/
    );

    assert.deepEqual(readCounts, {
      envDefault: 1,
      envLocal: 1,
    });
  } finally {
    fs.rmSync(layout.root, {
      recursive: true,
      force: true,
    });
  }
});
