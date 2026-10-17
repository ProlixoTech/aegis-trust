import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  FileServerRulesetFreshnessAnchorStore,
  MAX_SERVER_RULESET_FRESHNESS_ANCHOR_FILE_BYTES,
  SERVER_RULESET_FRESHNESS_ANCHOR_DIRECTORY_RELATIVE_PATH,
  SERVER_RULESET_FRESHNESS_ANCHOR_FILE_NAME,
  SERVER_RULESET_FRESHNESS_ANCHOR_LOCK_FILE_NAME,
  type ServerRulesetFreshnessAnchorCommitInput,
  type ServerRulesetFreshnessAnchorRecordV1,
} from "./serverRulesetFreshnessAnchorStore";

function root(
  prefix: string
): string {
  return fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      prefix
    )
  );
}

function cleanup(
  directory: string
): void {
  fs.rmSync(
    directory,
    {
      recursive: true,
      force: true,
    }
  );
}

function sha256(
  value: string
): string {
  return crypto
    .createHash("sha256")
    .update(
      Buffer.from(value, "utf8")
    )
    .digest("hex");
}

function delay(
  milliseconds: number
): Promise<void> {
  return new Promise(
    resolve =>
      setTimeout(
        resolve,
        milliseconds
      )
  );
}

function requireAnchor(
  value:
    ServerRulesetFreshnessAnchorRecordV1 |
    null,
  label: string
): ServerRulesetFreshnessAnchorRecordV1 {
  if (value === null) {
    throw new Error(
      "EXPECTED_NON_NULL_" +
      label +
      "_ANCHOR"
    );
  }

  return value;
}

interface AnchorOptions {
  readonly packageId?: string;
  readonly rulesetId?: string;
  readonly sequence?: number;
  readonly version?: number;
  readonly counter?: number;
  readonly anchoredAtEpochMs?: number;
}

function anchor(
  options: AnchorOptions = {}
): ServerRulesetFreshnessAnchorRecordV1 {
  return {
    packageSha256:
      sha256(
        options.packageId ??
        "package-1"
      ),
    rulesetSha256:
      sha256(
        options.rulesetId ??
        "ruleset-1"
      ),
    highestIntermediateSequence:
      options.sequence ?? 1,
    rulesetVersion:
      options.version ?? 1,
    monotonicCounter:
      options.counter ?? 1,
    anchoredAtEpochMs:
      options.anchoredAtEpochMs ??
      1_000,
  };
}

function input(
  overrides:
    Partial<ServerRulesetFreshnessAnchorCommitInput> = {}
): ServerRulesetFreshnessAnchorCommitInput {
  return {
    nowEpochMs: 10_000,
    current:
      anchor({
        packageId:
          "current-package-1",
        rulesetId:
          "current-ruleset-1",
      }),
    lkg:
      anchor({
        packageId:
          "lkg-package-1",
        rulesetId:
          "lkg-ruleset-1",
      }),
    ...overrides,
  };
}

test("freshness anchor store exposes exact directory anchor and lock paths", () => {
  const directory =
    root("aegis-c10a4b2b1-paths-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    assert.equal(
      store.directoryPath,
      path.join(
        directory,
        SERVER_RULESET_FRESHNESS_ANCHOR_DIRECTORY_RELATIVE_PATH
      )
    );

    assert.equal(
      store.anchorPath,
      path.join(
        directory,
        ".aegis",
        "server-ruleset",
        SERVER_RULESET_FRESHNESS_ANCHOR_FILE_NAME
      )
    );

    assert.equal(
      store.lockPath,
      path.join(
        directory,
        ".aegis",
        "server-ruleset",
        SERVER_RULESET_FRESHNESS_ANCHOR_LOCK_FILE_NAME
      )
    );

    assert.equal(
      fs.existsSync(
        store.anchorPath
      ),
      false
    );
  } finally {
    cleanup(directory);
  }
});

test("freshness anchor store first commit and read round trip without input mutation", async () => {
  const directory =
    root("aegis-c10a4b2b1-first-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    assert.equal(
      await store.readAnchors(),
      null
    );

    const value = input();
    const before =
      JSON.stringify(value);

    assert.deepEqual(
      await store.commitAnchors(
        value
      ),
      {
        status: "COMMITTED",
        error: null,
      }
    );

    assert.equal(
      JSON.stringify(value),
      before
    );

    const stored =
      await store.readAnchors();

    assert.equal(
      stored?.schemaVersion,
      1
    );

    assert.deepEqual(
      stored?.current,
      value.current
    );

    assert.deepEqual(
      stored?.lkg,
      value.lkg
    );
  } finally {
    cleanup(directory);
  }
});

test("identical freshness anchor commit is unchanged and preserves mtime", async () => {
  const directory =
    root("aegis-c10a4b2b1-idempotent-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const value = input();

    assert.equal(
      (
        await store.commitAnchors(
          value
        )
      ).status,
      "COMMITTED"
    );

    const before =
      fs.statSync(
        store.anchorPath
      ).mtimeMs;

    await delay(25);

    assert.deepEqual(
      await store.commitAnchors(
        value
      ),
      {
        status: "UNCHANGED",
        error: null,
      }
    );

    assert.equal(
      fs.statSync(
        store.anchorPath
      ).mtimeMs,
      before
    );
  } finally {
    cleanup(directory);
  }
});

test("same package identity accepts forward online reanchor", async () => {
  const directory =
    root("aegis-c10a4b2b1-forward-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const first = input();

    await store.commitAnchors(
      first
    );

    const firstCurrent =
      requireAnchor(
        first.current,
        "CURRENT"
      );

    const advancedCurrent = {
      ...firstCurrent,
      anchoredAtEpochMs:
        2_000,
    };

    const result =
      await store.commitAnchors({
        nowEpochMs: 10_000,
        current:
          advancedCurrent,
        lkg:
          first.lkg,
      });

    assert.equal(
      result.status,
      "COMMITTED"
    );

    assert.equal(
      (
        await store.readAnchors()
      )?.current
        ?.anchoredAtEpochMs,
      2_000
    );
  } finally {
    cleanup(directory);
  }
});

test("same package identity rejects backward online reanchor", async () => {
  const directory =
    root("aegis-c10a4b2b1-backward-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const first =
      input({
        current:
          anchor({
            packageId:
              "current-package-1",
            rulesetId:
              "current-ruleset-1",
            anchoredAtEpochMs:
              2_000,
          }),
      });

    await store.commitAnchors(
      first
    );

    const firstCurrent =
      requireAnchor(
        first.current,
        "CURRENT"
      );

    const result =
      await store.commitAnchors({
        nowEpochMs: 10_000,
        current: {
          ...firstCurrent,
          anchoredAtEpochMs:
            1_999,
        },
        lkg:
          first.lkg,
      });

    assert.equal(
      result.status,
      "REJECTED"
    );

    assert.equal(
      result.error,
      "CURRENT_FRESHNESS_ANCHOR_TIME_DOWNGRADE"
    );
  } finally {
    cleanup(directory);
  }
});

test("freshness anchor store rejects intermediate sequence downgrade", async () => {
  const directory =
    root("aegis-c10a4b2b1-sequence-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const first =
      input({
        current:
          anchor({
            packageId:
              "package-2",
            rulesetId:
              "ruleset-2",
            sequence: 2,
            version: 2,
            counter: 2,
          }),
      });

    await store.commitAnchors(
      first
    );

    const result =
      await store.commitAnchors({
        nowEpochMs: 10_000,
        current:
          anchor({
            packageId:
              "package-3",
            rulesetId:
              "ruleset-3",
            sequence: 1,
            version: 3,
            counter: 3,
            anchoredAtEpochMs:
              2_000,
          }),
        lkg:
          first.lkg,
      });

    assert.equal(
      result.error,
      "CURRENT_INTERMEDIATE_SEQUENCE_DOWNGRADE"
    );
  } finally {
    cleanup(directory);
  }
});

test("freshness anchor store rejects ruleset version downgrade", async () => {
  const directory =
    root("aegis-c10a4b2b1-version-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const first =
      input({
        current:
          anchor({
            packageId:
              "package-4",
            rulesetId:
              "ruleset-4",
            sequence: 2,
            version: 4,
            counter: 4,
          }),
      });

    await store.commitAnchors(
      first
    );

    const result =
      await store.commitAnchors({
        nowEpochMs: 10_000,
        current:
          anchor({
            packageId:
              "package-5",
            rulesetId:
              "ruleset-5",
            sequence: 3,
            version: 3,
            counter: 5,
            anchoredAtEpochMs:
              2_000,
          }),
        lkg:
          first.lkg,
      });

    assert.equal(
      result.error,
      "CURRENT_RULESET_VERSION_DOWNGRADE"
    );
  } finally {
    cleanup(directory);
  }
});

test("freshness anchor store rejects monotonic counter downgrade", async () => {
  const directory =
    root("aegis-c10a4b2b1-counter-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const first =
      input({
        current:
          anchor({
            packageId:
              "package-6",
            rulesetId:
              "ruleset-6",
            sequence: 2,
            version: 4,
            counter: 8,
          }),
      });

    await store.commitAnchors(
      first
    );

    const result =
      await store.commitAnchors({
        nowEpochMs: 10_000,
        current:
          anchor({
            packageId:
              "package-7",
            rulesetId:
              "ruleset-7",
            sequence: 3,
            version: 5,
            counter: 7,
            anchoredAtEpochMs:
              2_000,
          }),
        lkg:
          first.lkg,
      });

    assert.equal(
      result.error,
      "CURRENT_RULESET_COUNTER_DOWNGRADE"
    );
  } finally {
    cleanup(directory);
  }
});

test("equal trust tuple with another package hash is rejected as rebound", async () => {
  const directory =
    root("aegis-c10a4b2b1-rebound-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const first =
      input({
        current:
          anchor({
            packageId:
              "package-8",
            rulesetId:
              "ruleset-8",
            sequence: 4,
            version: 6,
            counter: 9,
          }),
      });

    await store.commitAnchors(
      first
    );

    const result =
      await store.commitAnchors({
        nowEpochMs: 10_000,
        current:
          anchor({
            packageId:
              "package-9",
            rulesetId:
              "ruleset-9",
            sequence: 4,
            version: 6,
            counter: 9,
            anchoredAtEpochMs:
              2_000,
          }),
        lkg:
          first.lkg,
      });

    assert.equal(
      result.error,
      "CURRENT_TRUST_TUPLE_HASH_REBOUND"
    );
  } finally {
    cleanup(directory);
  }
});

test("non-null current and LKG freshness anchor deletion is rejected", async () => {
  const directory =
    root("aegis-c10a4b2b1-delete-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const first = input();

    await store.commitAnchors(
      first
    );

    const currentDeletion =
      await store.commitAnchors({
        nowEpochMs: 10_000,
        current: null,
        lkg:
          first.lkg,
      });

    assert.equal(
      currentDeletion.error,
      "CURRENT_FRESHNESS_ANCHOR_DELETE_REJECTED"
    );

    const lkgDeletion =
      await store.commitAnchors({
        nowEpochMs: 10_000,
        current:
          first.current,
        lkg: null,
      });

    assert.equal(
      lkgDeletion.error,
      "LKG_FRESHNESS_ANCHOR_DELETE_REJECTED"
    );
  } finally {
    cleanup(directory);
  }
});

test("future current and LKG freshness anchors are rejected before directory creation", async () => {
  const directory =
    root("aegis-c10a4b2b1-future-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const currentFuture =
      await store.commitAnchors(
        input({
          nowEpochMs: 10_000,
          current:
            anchor({
              anchoredAtEpochMs:
                10_001,
            }),
        })
      );

    assert.equal(
      currentFuture.error,
      "CURRENT_FRESHNESS_ANCHOR_IN_FUTURE"
    );

    const lkgFuture =
      await store.commitAnchors(
        input({
          nowEpochMs: 10_000,
          current:
            anchor({
              anchoredAtEpochMs:
                9_999,
            }),
          lkg:
            anchor({
              anchoredAtEpochMs:
                10_001,
            }),
        })
      );

    assert.equal(
      lkgFuture.error,
      "LKG_FRESHNESS_ANCHOR_IN_FUTURE"
    );

    assert.equal(
      fs.existsSync(
        store.directoryPath
      ),
      false
    );
  } finally {
    cleanup(directory);
  }
});

test("corrupt JSON and unknown document fields fail closed", async () => {
  const corruptDirectory =
    root("aegis-c10a4b2b1-corrupt-");

  const schemaDirectory =
    root("aegis-c10a4b2b1-schema-");

  try {
    const corruptStore =
      new FileServerRulesetFreshnessAnchorStore(
        corruptDirectory
      );

    await corruptStore.commitAnchors(
      input()
    );

    fs.writeFileSync(
      corruptStore.anchorPath,
      "{invalid-json",
      "utf8"
    );

    await assert.rejects(
      () =>
        corruptStore.readAnchors(),
      /INVALID_SERVER_RULESET_FRESHNESS_ANCHOR_JSON/
    );

    const schemaStore =
      new FileServerRulesetFreshnessAnchorStore(
        schemaDirectory
      );

    await schemaStore.commitAnchors(
      input()
    );

    const parsed =
      JSON.parse(
        fs.readFileSync(
          schemaStore.anchorPath,
          "utf8"
        )
      ) as Record<string, unknown>;

    parsed.execute =
      "child-process";

    fs.writeFileSync(
      schemaStore.anchorPath,
      JSON.stringify(
        parsed,
        null,
        2
      ) + "\n",
      "utf8"
    );

    await assert.rejects(
      () =>
        schemaStore.readAnchors(),
      /INVALID_SERVER_RULESET_FRESHNESS_ANCHOR_DOCUMENT/
    );
  } finally {
    cleanup(corruptDirectory);
    cleanup(schemaDirectory);
  }
});

test("symlink freshness anchor file and symlink Aegis directory fail closed", async () => {
  const fileDirectory =
    root("aegis-c10a4b2b1-symlink-file-");

  const fileOutside =
    root("aegis-c10a4b2b1-outside-file-");

  const directoryRoot =
    root("aegis-c10a4b2b1-symlink-dir-");

  const directoryOutside =
    root("aegis-c10a4b2b1-outside-dir-");

  try {
    const fileStore =
      new FileServerRulesetFreshnessAnchorStore(
        fileDirectory
      );

    fs.mkdirSync(
      fileStore.directoryPath,
      {
        recursive: true,
      }
    );

    const outsideFile =
      path.join(
        fileOutside,
        "freshness-anchor.json"
      );

    fs.writeFileSync(
      outsideFile,
      "{}",
      "utf8"
    );

    fs.symlinkSync(
      outsideFile,
      fileStore.anchorPath
    );

    await assert.rejects(
      () =>
        fileStore.readAnchors(),
      /UNTRUSTED_SERVER_RULESET_FRESHNESS_ANCHOR_FILE_METADATA/
    );

    fs.symlinkSync(
      directoryOutside,
      path.join(
        directoryRoot,
        ".aegis"
      ),
      "dir"
    );

    const directoryStore =
      new FileServerRulesetFreshnessAnchorStore(
        directoryRoot
      );

    await assert.rejects(
      () =>
        directoryStore.readAnchors(),
      /INVALID_AEGIS_DIRECTORY_METADATA/
    );
  } finally {
    cleanup(fileDirectory);
    cleanup(fileOutside);
    cleanup(directoryRoot);
    cleanup(directoryOutside);
  }
});

test("oversized freshness anchor file is rejected", async () => {
  const directory =
    root("aegis-c10a4b2b1-oversized-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    fs.mkdirSync(
      store.directoryPath,
      {
        recursive: true,
      }
    );

    fs.writeFileSync(
      store.anchorPath,
      "x".repeat(
        MAX_SERVER_RULESET_FRESHNESS_ANCHOR_FILE_BYTES +
        1
      ),
      "utf8"
    );

    await assert.rejects(
      () =>
        store.readAnchors(),
      /UNTRUSTED_SERVER_RULESET_FRESHNESS_ANCHOR_FILE_METADATA/
    );
  } finally {
    cleanup(directory);
  }
});

test("concurrent identical freshness anchor commits produce one physical commit", async () => {
  const directory =
    root("aegis-c10a4b2b1-concurrent-");

  try {
    const value = input();

    const results =
      await Promise.all(
        Array.from(
          {
            length: 24,
          },
          () =>
            new FileServerRulesetFreshnessAnchorStore(
              directory
            ).commitAnchors(
              value
            )
        )
      );

    assert.equal(
      results.filter(
        result =>
          result.status ===
          "COMMITTED"
      ).length,
      1
    );

    assert.equal(
      results.filter(
        result =>
          result.status ===
          "UNCHANGED"
      ).length,
      23
    );

    assert.equal(
      (
        await new FileServerRulesetFreshnessAnchorStore(
          directory
        ).readAnchors()
      )?.current
        ?.packageSha256,
      value.current
        ?.packageSha256
    );
  } finally {
    cleanup(directory);
  }
});

test("rejected commit preserves content and atomic cleanup plus read-only lookup preserve mtime", async () => {
  const directory =
    root("aegis-c10a4b2b1-atomic-");

  try {
    const store =
      new FileServerRulesetFreshnessAnchorStore(
        directory
      );

    const first =
      input({
        current:
          anchor({
            packageId:
              "atomic-package",
            rulesetId:
              "atomic-ruleset",
            anchoredAtEpochMs:
              2_000,
          }),
      });

    await store.commitAnchors(
      first
    );

    const bytesBefore =
      fs.readFileSync(
        store.anchorPath
      );

    const mtimeBefore =
      fs.statSync(
        store.anchorPath
      ).mtimeMs;

    const firstCurrent =
      requireAnchor(
        first.current,
        "CURRENT"
      );

    await delay(25);

    const rejected =
      await store.commitAnchors({
        nowEpochMs: 10_000,
        current: {
          ...firstCurrent,
          anchoredAtEpochMs:
            1_000,
        },
        lkg:
          first.lkg,
      });

    assert.equal(
      rejected.status,
      "REJECTED"
    );

    assert.deepEqual(
      fs.readFileSync(
        store.anchorPath
      ),
      bytesBefore
    );

    assert.equal(
      fs.statSync(
        store.anchorPath
      ).mtimeMs,
      mtimeBefore
    );

    const names =
      fs.readdirSync(
        store.directoryPath
      );

    assert.equal(
      names.some(
        name =>
          name.endsWith(".tmp")
      ),
      false
    );

    assert.equal(
      fs.existsSync(
        store.lockPath
      ),
      false
    );

    await delay(25);
    await store.readAnchors();

    assert.equal(
      fs.statSync(
        store.anchorPath
      ).mtimeMs,
      mtimeBefore
    );
  } finally {
    cleanup(directory);
  }
});
