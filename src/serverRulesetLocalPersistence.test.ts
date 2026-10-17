import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  canonicalizeServerRulesetValue,
  type ServerRulesetTrustState,
} from "./serverRulesetTrustProvider";

import {
  FileServerRulesetLocalPersistence,
  MAX_SERVER_RULESET_STATE_FILE_BYTES,
  SERVER_RULESET_DIRECTORY_RELATIVE_PATH,
} from "./serverRulesetLocalPersistence";

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

interface SnapshotOptions {
  readonly sequence?: number;
  readonly rulesetVersion?: number;
  readonly monotonicCounter?: number;
  readonly ruleValue?: string;
}

function snapshot(
  options: SnapshotOptions = {}
): {
  readonly state: ServerRulesetTrustState;
  readonly packageText: string;
} {
  const sequence =
    options.sequence ?? 1;

  const rulesetVersion =
    options.rulesetVersion ?? 1;

  const monotonicCounter =
    options.monotonicCounter ?? 1;

  const ruleset = {
    schemaVersion: 1,
    rulesetId:
      "ruleset-" +
      rulesetVersion.toString(10),
    rulesetVersion,
    monotonicCounter,
    notBefore:
      "2026-07-01T00:00:00.000Z",
    notAfter:
      "2026-08-31T00:00:00.000Z",
    rules: [
      {
        ruleId: "rule-1",
        category:
          "catastrophic",
        pattern:
          options.ruleValue ??
          "delete-all",
      },
    ],
  };

  const packageText =
    JSON.stringify({
      schemaVersion: 1,
      intermediateCertificate: {
        keyId:
          "intermediate-" +
          sequence.toString(10),
      },
      ruleset,
      rulesetSignature:
        "fixture",
    });

  const state:
    ServerRulesetTrustState = {
      highestIntermediateSequence:
        sequence,
      intermediateKeyId:
        "intermediate-" +
        sequence.toString(10),
      intermediateKeySha256:
        sha256(
          "intermediate-key-" +
          sequence.toString(10)
        ),
      activeRuleset: {
        rulesetVersion,
        monotonicCounter,
        notBefore:
          ruleset.notBefore,
        notAfter:
          ruleset.notAfter,
      },
      rulesetSha256:
        sha256(
          canonicalizeServerRulesetValue(
            ruleset
          )
        ),
    };

  return {
    state,
    packageText,
  };
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

test("first snapshot commit and read use the exact collision-safe paths", async () => {
  const directory =
    root("aegis-c10a3a-first-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    assert.equal(
      store.directoryPath,
      path.join(
        directory,
        SERVER_RULESET_DIRECTORY_RELATIVE_PATH
      )
    );

    assert.equal(
      store.statePath,
      path.join(
        directory,
        ".aegis",
        "server-ruleset",
        "state.json"
      )
    );

    assert.equal(
      store.lkgPath,
      path.join(
        directory,
        ".aegis",
        "server-ruleset",
        "lkg.json"
      )
    );

    assert.equal(
      store.lockPath,
      path.join(
        directory,
        ".aegis",
        "server-ruleset",
        "accept.lock"
      )
    );

    const input = snapshot();

    assert.deepEqual(
      await store.commitSnapshot(
        input
      ),
      {
        status: "COMMITTED",
        error: null,
      }
    );

    const stored =
      await store.readSnapshot();

    assert.equal(
      stored?.state
        .highestIntermediateSequence,
      1
    );

    assert.equal(
      stored?.lkg.packageText,
      input.packageText
    );

    assert.equal(
      stored?.state
        .lkgPackageSha256,
      stored?.lkg.packageSha256
    );
  } finally {
    cleanup(directory);
  }
});

test("identical snapshot is unchanged and preserves mtimes", async () => {
  const directory =
    root("aegis-c10a3a-idempotent-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    const input = snapshot();

    assert.equal(
      (
        await store.commitSnapshot(
          input
        )
      ).status,
      "COMMITTED"
    );

    const stateBefore =
      fs.statSync(
        store.statePath
      ).mtimeMs;

    const lkgBefore =
      fs.statSync(
        store.lkgPath
      ).mtimeMs;

    await delay(25);

    assert.deepEqual(
      await store.commitSnapshot(
        input
      ),
      {
        status: "UNCHANGED",
        error: null,
      }
    );

    assert.equal(
      fs.statSync(
        store.statePath
      ).mtimeMs,
      stateBefore
    );

    assert.equal(
      fs.statSync(
        store.lkgPath
      ).mtimeMs,
      lkgBefore
    );
  } finally {
    cleanup(directory);
  }
});

test("intermediate sequence downgrade is rejected", async () => {
  const directory =
    root("aegis-c10a3a-sequence-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    assert.equal(
      (
        await store.commitSnapshot(
          snapshot({
            sequence: 2,
            rulesetVersion: 2,
            monotonicCounter: 2,
          })
        )
      ).status,
      "COMMITTED"
    );

    const result =
      await store.commitSnapshot(
        snapshot({
          sequence: 1,
          rulesetVersion: 3,
          monotonicCounter: 3,
        })
      );

    assert.equal(
      result.status,
      "REJECTED"
    );

    assert.equal(
      result.error,
      "PERSISTED_INTERMEDIATE_SEQUENCE_DOWNGRADE"
    );
  } finally {
    cleanup(directory);
  }
});

test("ruleset version downgrade is rejected", async () => {
  const directory =
    root("aegis-c10a3a-version-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    await store.commitSnapshot(
      snapshot({
        sequence: 1,
        rulesetVersion: 4,
        monotonicCounter: 4,
      })
    );

    const result =
      await store.commitSnapshot(
        snapshot({
          sequence: 2,
          rulesetVersion: 3,
          monotonicCounter: 5,
        })
      );

    assert.equal(
      result.error,
      "PERSISTED_RULESET_VERSION_DOWNGRADE"
    );
  } finally {
    cleanup(directory);
  }
});

test("ruleset monotonic counter downgrade is rejected", async () => {
  const directory =
    root("aegis-c10a3a-counter-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    await store.commitSnapshot(
      snapshot({
        sequence: 1,
        rulesetVersion: 4,
        monotonicCounter: 8,
      })
    );

    const result =
      await store.commitSnapshot(
        snapshot({
          sequence: 2,
          rulesetVersion: 5,
          monotonicCounter: 7,
        })
      );

    assert.equal(
      result.error,
      "PERSISTED_RULESET_COUNTER_DOWNGRADE"
    );
  } finally {
    cleanup(directory);
  }
});

test("same ruleset version and counter with another hash is rejected", async () => {
  const directory =
    root("aegis-c10a3a-rebound-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    await store.commitSnapshot(
      snapshot({
        sequence: 1,
        rulesetVersion: 6,
        monotonicCounter: 9,
        ruleValue: "first",
      })
    );

    const result =
      await store.commitSnapshot(
        snapshot({
          sequence: 2,
          rulesetVersion: 6,
          monotonicCounter: 9,
          ruleValue: "second",
        })
      );

    assert.equal(
      result.error,
      "PERSISTED_RULESET_HASH_REBOUND"
    );
  } finally {
    cleanup(directory);
  }
});

test("corrupt state JSON fails closed", async () => {
  const directory =
    root("aegis-c10a3a-corrupt-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    await store.commitSnapshot(
      snapshot()
    );

    fs.writeFileSync(
      store.statePath,
      "{invalid-json",
      "utf8"
    );

    await assert.rejects(
      () => store.readSnapshot(),
      /INVALID_SERVER_RULESET_STATE_JSON/
    );
  } finally {
    cleanup(directory);
  }
});

test("state exact-key schema rejects unknown fields", async () => {
  const directory =
    root("aegis-c10a3a-schema-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    await store.commitSnapshot(
      snapshot()
    );

    const parsed =
      JSON.parse(
        fs.readFileSync(
          store.statePath,
          "utf8"
        )
      ) as Record<string, unknown>;

    parsed.execute =
      "child-process";

    fs.writeFileSync(
      store.statePath,
      JSON.stringify(
        parsed,
        null,
        2
      ) + "\n",
      "utf8"
    );

    await assert.rejects(
      () => store.readSnapshot(),
      /INVALID_SERVER_RULESET_STATE/
    );
  } finally {
    cleanup(directory);
  }
});

test("state and LKG package hash mismatch fails closed", async () => {
  const directory =
    root("aegis-c10a3a-linkage-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    await store.commitSnapshot(
      snapshot()
    );

    const parsed =
      JSON.parse(
        fs.readFileSync(
          store.statePath,
          "utf8"
        )
      ) as Record<string, unknown>;

    parsed.lkgPackageSha256 =
      "a".repeat(64);

    fs.writeFileSync(
      store.statePath,
      JSON.stringify(
        parsed,
        null,
        2
      ) + "\n",
      "utf8"
    );

    await assert.rejects(
      () => store.readSnapshot(),
      /SERVER_RULESET_STATE_LKG_HASH_MISMATCH/
    );
  } finally {
    cleanup(directory);
  }
});

test("symlink state file is rejected", async () => {
  const directory =
    root("aegis-c10a3a-symlink-file-");

  const outside =
    root("aegis-c10a3a-outside-file-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    fs.mkdirSync(
      store.directoryPath,
      {
        recursive: true,
      }
    );

    const outsideState =
      path.join(
        outside,
        "state.json"
      );

    fs.writeFileSync(
      outsideState,
      "{}",
      "utf8"
    );

    fs.symlinkSync(
      outsideState,
      store.statePath
    );

    fs.writeFileSync(
      store.lkgPath,
      "{}",
      "utf8"
    );

    await assert.rejects(
      () => store.readSnapshot(),
      /UNTRUSTED_SERVER_RULESET_FILE_METADATA/
    );
  } finally {
    cleanup(directory);
    cleanup(outside);
  }
});

test("symlink Aegis directory is rejected", async () => {
  const directory =
    root("aegis-c10a3a-symlink-dir-");

  const outside =
    root("aegis-c10a3a-outside-dir-");

  try {
    fs.symlinkSync(
      outside,
      path.join(
        directory,
        ".aegis"
      ),
      "dir"
    );

    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    const result =
      await store.commitSnapshot(
        snapshot()
      );

    assert.equal(
      result.status,
      "REJECTED"
    );

    assert.equal(
      result.error,
      "INVALID_AEGIS_DIRECTORY_METADATA"
    );
  } finally {
    cleanup(directory);
    cleanup(outside);
  }
});

test("oversized state file is rejected", async () => {
  const directory =
    root("aegis-c10a3a-oversized-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    fs.mkdirSync(
      store.directoryPath,
      {
        recursive: true,
      }
    );

    fs.writeFileSync(
      store.statePath,
      "x".repeat(
        MAX_SERVER_RULESET_STATE_FILE_BYTES +
        1
      ),
      "utf8"
    );

    fs.writeFileSync(
      store.lkgPath,
      "{}",
      "utf8"
    );

    await assert.rejects(
      () => store.readSnapshot(),
      /UNTRUSTED_SERVER_RULESET_FILE_METADATA/
    );
  } finally {
    cleanup(directory);
  }
});

test("concurrent identical commits produce exactly one physical commit", async () => {
  const directory =
    root("aegis-c10a3a-concurrent-");

  try {
    const input = snapshot();

    const results =
      await Promise.all(
        Array.from(
          {
            length: 24,
          },
          () =>
            new FileServerRulesetLocalPersistence(
              directory
            ).commitSnapshot(
              input
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
      (
        await new FileServerRulesetLocalPersistence(
          directory
        ).readSnapshot()
      )?.state.activeRuleset
        .rulesetVersion,
      1
    );
  } finally {
    cleanup(directory);
  }
});

test("unavailable accept lock fails closed", async () => {
  const directory =
    root("aegis-c10a3a-lock-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    fs.mkdirSync(
      store.directoryPath,
      {
        recursive: true,
      }
    );

    fs.writeFileSync(
      store.lockPath,
      "occupied\n",
      "utf8"
    );

    const result =
      await store.commitSnapshot(
        snapshot()
      );

    assert.equal(
      result.status,
      "REJECTED"
    );

    assert.notEqual(
      result.error,
      null
    );
  } finally {
    cleanup(directory);
  }
});

test("atomic commit removes temporary files and lock", async () => {
  const directory =
    root("aegis-c10a3a-cleanup-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    assert.equal(
      (
        await store.commitSnapshot(
          snapshot()
        )
      ).status,
      "COMMITTED"
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
  } finally {
    cleanup(directory);
  }
});

test("read-only snapshot lookup does not change files or mtimes", async () => {
  const directory =
    root("aegis-c10a3a-readonly-");

  try {
    const store =
      new FileServerRulesetLocalPersistence(
        directory
      );

    await store.commitSnapshot(
      snapshot()
    );

    const stateBefore =
      fs.readFileSync(
        store.statePath
      );

    const lkgBefore =
      fs.readFileSync(
        store.lkgPath
      );

    const stateMtimeBefore =
      fs.statSync(
        store.statePath
      ).mtimeMs;

    const lkgMtimeBefore =
      fs.statSync(
        store.lkgPath
      ).mtimeMs;

    await delay(25);
    await store.readSnapshot();

    assert.deepEqual(
      fs.readFileSync(
        store.statePath
      ),
      stateBefore
    );

    assert.deepEqual(
      fs.readFileSync(
        store.lkgPath
      ),
      lkgBefore
    );

    assert.equal(
      fs.statSync(
        store.statePath
      ).mtimeMs,
      stateMtimeBefore
    );

    assert.equal(
      fs.statSync(
        store.lkgPath
      ).mtimeMs,
      lkgMtimeBefore
    );
  } finally {
    cleanup(directory);
  }
});
