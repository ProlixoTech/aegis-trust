import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CanonicalAuthorityStateStore,
} from "./canonicalAuthorityState";
import {
  CanonicalAuthorityStateFilePersistence,
  createNodeCanonicalAuthorityStateFileOperations,
} from "./canonicalAuthorityStateFilePersistence";
import {
  getProtectedTargets,
} from "./protectedTargets";

const workspaceId =
  "sha256:" +
  "a".repeat(64);

function createStore(
  timestamp: string
): CanonicalAuthorityStateStore {
  return CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets:
      getProtectedTargets(),
    initialUserVisibleState:
      "SAFE",
    timestamp,
  });
}

async function createTemporaryRoot():
  Promise<string> {
  return mkdtemp(
    join(
      tmpdir(),
      "aegis-canonical-authority-persistence-"
    )
  );
}

test("canonical authority file persistence saves and restores an equivalent detached state", async () => {
  const root =
    await createTemporaryRoot();

  try {
    const snapshotPath =
      join(
        root,
        "canonical-authority.json"
      );

    const persistence =
      new CanonicalAuthorityStateFilePersistence(
        snapshotPath
      );

    const store =
      createStore(
        "2026-07-26T18:00:00.000Z"
      );

    await persistence.save(store);

    const hydrated =
      await persistence.load();

    assert.notEqual(
      hydrated,
      null
    );

    assert.deepEqual(
      hydrated?.getState(),
      store.getState()
    );

    assert.notEqual(
      hydrated?.getState(),
      hydrated?.getState()
    );
  } finally {
    await rm(
      root,
      {
        recursive: true,
        force: true,
      }
    );
  }
});

test("canonical authority file persistence writes deterministic bytes for an unchanged state", async () => {
  const root =
    await createTemporaryRoot();

  try {
    const snapshotPath =
      join(
        root,
        "canonical-authority.json"
      );

    const persistence =
      new CanonicalAuthorityStateFilePersistence(
        snapshotPath
      );

    const store =
      createStore(
        "2026-07-26T18:01:00.000Z"
      );

    await persistence.save(store);

    const first =
      await readFile(
        snapshotPath,
        "utf8"
      );

    await persistence.save(store);

    const second =
      await readFile(
        snapshotPath,
        "utf8"
      );

    assert.equal(
      second,
      first
    );

    assert.equal(
      first,
      store.serializeSnapshotEnvelope()
    );
  } finally {
    await rm(
      root,
      {
        recursive: true,
        force: true,
      }
    );
  }
});

test("canonical authority file persistence returns null when no snapshot exists", async () => {
  const root =
    await createTemporaryRoot();

  try {
    const persistence =
      new CanonicalAuthorityStateFilePersistence(
        join(
          root,
          "missing.json"
        )
      );

    assert.equal(
      await persistence.load(),
      null
    );
  } finally {
    await rm(
      root,
      {
        recursive: true,
        force: true,
      }
    );
  }
});

test("canonical authority file persistence rejects payload hash tampering", async () => {
  const root =
    await createTemporaryRoot();

  try {
    const snapshotPath =
      join(
        root,
        "canonical-authority.json"
      );

    const persistence =
      new CanonicalAuthorityStateFilePersistence(
        snapshotPath
      );

    await persistence.save(
      createStore(
        "2026-07-26T18:02:00.000Z"
      )
    );

    const envelope =
      JSON.parse(
        await readFile(
          snapshotPath,
          "utf8"
        )
      ) as Record<string, unknown>;

    envelope.payloadSha256 =
      "sha256:" +
      "0".repeat(64);

    await writeFile(
      snapshotPath,
      JSON.stringify(envelope),
      "utf8"
    );

    await assert.rejects(
      () =>
        persistence.load(),
      /CANONICAL_AUTHORITY_SNAPSHOT_HASH_MISMATCH/
    );
  } finally {
    await rm(
      root,
      {
        recursive: true,
        force: true,
      }
    );
  }
});

test("canonical authority file persistence rejects malformed JSON", async () => {
  const root =
    await createTemporaryRoot();

  try {
    const snapshotPath =
      join(
        root,
        "canonical-authority.json"
      );

    await writeFile(
      snapshotPath,
      "{not-valid-json",
      "utf8"
    );

    const persistence =
      new CanonicalAuthorityStateFilePersistence(
        snapshotPath
      );

    await assert.rejects(
      () =>
        persistence.load(),
      /INVALID_CANONICAL_AUTHORITY_SNAPSHOT_JSON/
    );
  } finally {
    await rm(
      root,
      {
        recursive: true,
        force: true,
      }
    );
  }
});

test("canonical authority file persistence preserves the existing snapshot and removes its temporary file when rename fails", async () => {
  const root =
    await createTemporaryRoot();

  try {
    const snapshotPath =
      join(
        root,
        "canonical-authority.json"
      );

    const initialPersistence =
      new CanonicalAuthorityStateFilePersistence(
        snapshotPath
      );

    await initialPersistence.save(
      createStore(
        "2026-07-26T18:03:00.000Z"
      )
    );

    const originalBytes =
      await readFile(
        snapshotPath,
        "utf8"
      );

    const operations =
      createNodeCanonicalAuthorityStateFileOperations();

    const failingPersistence =
      new CanonicalAuthorityStateFilePersistence(
        snapshotPath,
        {
          ...operations,

          rename: async () => {
            throw new Error(
              "SIMULATED_CANONICAL_AUTHORITY_RENAME_FAILURE"
            );
          },
        }
      );

    await assert.rejects(
      () =>
        failingPersistence.save(
          createStore(
            "2026-07-26T18:04:00.000Z"
          )
        ),
      /SIMULATED_CANONICAL_AUTHORITY_RENAME_FAILURE/
    );

    assert.equal(
      await readFile(
        snapshotPath,
        "utf8"
      ),
      originalBytes
    );

    const directoryEntries =
      await readdir(root);

    assert.deepEqual(
      directoryEntries.sort(),
      [
        "canonical-authority.json",
      ]
    );
  } finally {
    await rm(
      root,
      {
        recursive: true,
        force: true,
      }
    );
  }
});