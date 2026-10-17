import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { SnapshotStore } from "./snapshotStore";
import { EnvCoreEngine } from "./envCoreEngine";
import type { BaselineEntry, LatestSafeSnapshotIndex, SnapshotManifest } from "../packages/aegis-core";

function makeTempAegisDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "aegis-snapshot-store-"));
}

function removeTempAegisDir(aegisDir: string): void {
  fs.rmSync(aegisDir, { recursive: true, force: true });
}

function sha256(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function readJson<T>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

function indexPath(aegisDir: string): string {
  return path.join(aegisDir, "latest-safe-snapshot.json");
}

function normalizedKey(absPath: string): string {
  return absPath.toLowerCase().replace(/\\/g, "/");
}

test("snapshotStore baseline registration writes verified baseline index and manifest without raw content", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const content = "API_KEY=secret\n";
    const absPath = path.join(aegisDir, "workspace", ".env");

    const snapshotId = await store.createBaselineSnapshotFromContent(content, absPath, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    assert.equal(index.snapshot_id, snapshotId);
    assert.equal(index.source, "baseline_registration");
    assert.equal(index.original_path, absPath);
    assert.equal(index.baseline_content_sha256, sha256(content));
    assert.equal(index.content_sha256, sha256(content));
    assert.equal(index.baseline_snapshot_file, index.snapshot_file);
    assert.equal(fs.readFileSync(index.baseline_snapshot_file, "utf8"), content);

    const manifestPath = path.join(aegisDir, "snapshots", snapshotId, "manifest.json");
    const manifestText = fs.readFileSync(manifestPath, "utf8");
    const manifest = JSON.parse(manifestText) as SnapshotManifest;

    assert.equal(manifest.snapshot_id, snapshotId);
    assert.equal(manifest.source, "baseline_registration");
    assert.equal(manifest.content_sha256, sha256(content));
    assert.equal(manifest.snapshot_file, index.snapshot_file);
    assert.doesNotMatch(manifestText, /API_KEY=secret/);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore refuses to overwrite an existing immutable baseline registration", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const absPath = path.join(aegisDir, "workspace", ".env");
    const firstContent = "SAFE_BASELINE=1\n";

    const firstSnapshotId = await store.createBaselineSnapshotFromContent(firstContent, absPath, ".env");
    if (firstSnapshotId === null) {
      assert.fail("expected first baseline snapshot id");
    }

    const secondSnapshotId = await store.createBaselineSnapshotFromContent("CONTAMINATED=1\n", absPath, ".env");
    assert.equal(secondSnapshotId, null);

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    assert.equal(index.snapshot_id, firstSnapshotId);
    assert.equal(index.baseline_content_sha256, sha256(firstContent));
    assert.equal(fs.readFileSync(index.baseline_snapshot_file, "utf8"), firstContent);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore rolling snapshot preserves immutable baseline fields", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const absPath = path.join(aegisDir, "workspace", ".env");
    const baselineContent = "BASELINE=1\n";

    const baselineSnapshotId = await store.createBaselineSnapshotFromContent(baselineContent, absPath, ".env");
    if (baselineSnapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const baselineIndex = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    const rollingContent = "PRE_SAVE_ROLLING=1\n";
    const rollingBaseline: BaselineEntry = {
      originalAbsPath: absPath,
      normalizedKey: normalizedKey(absPath),
      content: rollingContent,
      sha256: sha256(rollingContent),
      capturedAt: "2026-01-01T00:00:00.000Z",
      source: "pre_save_disk",
    };

    const rollingSnapshotId = await store.createSnapshot(rollingBaseline, ".env");
    if (rollingSnapshotId === null) {
      assert.fail("expected rolling snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    assert.equal(index.snapshot_id, rollingSnapshotId);
    assert.equal(index.baseline_snapshot_file, baselineIndex.baseline_snapshot_file);
    assert.equal(index.baseline_content_sha256, sha256(baselineContent));
    assert.equal(index.content_sha256, sha256(rollingContent));
    assert.notEqual(index.snapshot_file, baselineIndex.snapshot_file);
    assert.equal(fs.readFileSync(index.snapshot_file, "utf8"), rollingContent);
    assert.equal(fs.readFileSync(index.baseline_snapshot_file, "utf8"), baselineContent);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore refuses rolling snapshot creation when immutable baseline index is missing", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const absPath = path.join(aegisDir, "workspace", ".env");
    const content = "PRE_SAVE_WITHOUT_INDEX=1\n";
    const rollingBaseline: BaselineEntry = {
      originalAbsPath: absPath,
      normalizedKey: normalizedKey(absPath),
      content,
      sha256: sha256(content),
      capturedAt: "2026-01-01T00:00:00.000Z",
      source: "pre_save_disk",
    };

    const errorCalls: any[][] = [];
    const originalConsoleError = console.error;
    console.error = (...args: any[]) => {
      errorCalls.push(args);
    };

    let snapshotId: string | null = null;
    try {
      snapshotId = await store.createSnapshot(rollingBaseline, ".env");
    } finally {
      console.error = originalConsoleError;
    }

    assert.equal(snapshotId, null);
    assert.deepEqual(errorCalls, [[
      "[Aegis] createSnapshot: no existing index found. Cannot create protected-change snapshot without immutable baseline fields. Re-register baseline.",
    ]]);
    assert.equal(fs.existsSync(indexPath(aegisDir)), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});
test("snapshotStore startup recovery removes durable temp files and preserves unrelated files", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const nestedDir = path.join(aegisDir, "snapshots", "nested");
    fs.mkdirSync(nestedDir, { recursive: true });

    const rootTemp = path.join(aegisDir, ".latest-safe-snapshot.json.123.456.tmp");
    const nestedTemp = path.join(nestedDir, ".snapshot.json.789.101.tmp");
    const unrelatedRoot = path.join(aegisDir, "keep.tmp");
    const unrelatedNested = path.join(nestedDir, ".snapshot.json.tmp");

    fs.writeFileSync(rootTemp, "root-temp", "utf8");
    fs.writeFileSync(nestedTemp, "nested-temp", "utf8");
    fs.writeFileSync(unrelatedRoot, "keep-root", "utf8");
    fs.writeFileSync(unrelatedNested, "keep-nested", "utf8");

    const result = await store.recoverStartupArtifacts();

    assert.deepEqual(result, { scanned: 2, removed: 2, failed: 0 });
    assert.equal(fs.existsSync(rootTemp), false);
    assert.equal(fs.existsSync(nestedTemp), false);
    assert.equal(fs.readFileSync(unrelatedRoot, "utf8"), "keep-root");
    assert.equal(fs.readFileSync(unrelatedNested, "utf8"), "keep-nested");
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore readIndex returns parsed index, null only for ENOENT, and rejects invalid JSON", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    assert.equal(await store.readIndex(), null);

    const absPath = path.join(aegisDir, "workspace", ".env");
    const snapshotId = await store.createBaselineSnapshotFromContent("READ_INDEX=1\n", absPath, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const parsed = await store.readIndex();
    if (parsed === null) {
      assert.fail("expected parsed index");
    }
    assert.equal(parsed.snapshot_id, snapshotId);

    fs.writeFileSync(indexPath(aegisDir), "{invalid", "utf8");

    await assert.rejects(
      store.readIndex(),
      error =>
        error instanceof SyntaxError
    );
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore writes verified immutable baseline content", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const baselineContent = "RESTORE_BASELINE=1\n";
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent(baselineContent, target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const result = await store.restore(engine);

    assert.equal(result.success, true);
    assert.equal(result.message, "Aegis restored file from verified baseline snapshot.");
    assert.equal(result.restoredAbsPath, target);
    assert.equal(result.lockedAbsPath, target);
    assert.equal(fs.readFileSync(target, "utf8"), baselineContent);
    assert.equal(engine.isRestoring(target), true);
    engine.removeRestoring(target);
    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore rejects tampered target binding before disk write", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const expectedTarget = path.join(aegisDir, "workspace", ".env");
    const tamperedTarget = path.join(aegisDir, "outside", ".env");
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", expectedTarget);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent("BINDING_BASELINE=1\n", expectedTarget, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    index.original_path = tamperedTarget;
    fs.writeFileSync(indexPath(aegisDir), JSON.stringify(index, null, 2), "utf8");
    fs.mkdirSync(path.dirname(expectedTarget), { recursive: true });
    fs.writeFileSync(expectedTarget, "CONTAMINATED=1\n", "utf8");

    const result = await store.restore(engine);

    assert.equal(result.success, false);
    assert.equal(result.message, "Aegis: Restore target binding mismatch - restore cancelled before disk write.");
    assert.equal(fs.existsSync(tamperedTarget), false);
    assert.equal(fs.readFileSync(expectedTarget, "utf8"), "CONTAMINATED=1\n");
    assert.equal(engine.isRestoring(expectedTarget), false);
    assert.equal(engine.isRestoring(tamperedTarget), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore rejects tampered immutable baseline content before disk write", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent("BASELINE=1\n", target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    const baselinePath = index.baseline_snapshot_file;
    if (!baselinePath) {
      assert.fail("expected immutable baseline snapshot path");
    }

    fs.writeFileSync(baselinePath, "TAMPERED_BASELINE=1\n", "utf8");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const result = await store.restore(engine);

    assert.equal(result.success, false);
    assert.equal(result.message, "Aegis: Baseline snapshot SHA-256 mismatch - restore cancelled.");
    assert.equal(fs.readFileSync(target, "utf8"), "CONTAMINATED=1\n");
    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore rejects index missing immutable baseline fields before disk write", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent("BASELINE=1\n", target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    const legacyIndex = {
      ...index,
      baseline_snapshot_file: undefined,
      baseline_content_sha256: undefined,
    };
    fs.writeFileSync(indexPath(aegisDir), JSON.stringify(legacyIndex, null, 2), "utf8");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const result = await store.restore(engine);

    assert.equal(result.success, false);
    assert.equal(result.message, "Aegis: Restore index is missing immutable baseline fields. Re-register the baseline by deleting .aegis and saving the protected file again.");
    assert.equal(fs.readFileSync(target, "utf8"), "CONTAMINATED=1\n");
    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore rejects missing immutable baseline file before disk write", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent("BASELINE=1\n", target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    const baselinePath = index.baseline_snapshot_file;
    if (!baselinePath) {
      assert.fail("expected immutable baseline snapshot path");
    }

    fs.unlinkSync(baselinePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const result = await store.restore(engine);

    assert.equal(result.success, false);
    assert.match(result.message, /Could not read baseline snapshot file/);
    assert.equal(fs.readFileSync(target, "utf8"), "CONTAMINATED=1\n");
    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore rejects missing index before disk write", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const result = await store.restore(engine);

    assert.equal(result.success, false);
    assert.match(result.message, /No safe snapshot found/);
    assert.equal(fs.readFileSync(target, "utf8"), "CONTAMINATED=1\n");
    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore reports durable target write failure and keeps restore lock", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const blockedParent = path.join(aegisDir, "blocked-parent");
    const target = path.join(blockedParent, ".env");
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent("BASELINE=1\n", target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    fs.writeFileSync(blockedParent, "NOT_A_DIRECTORY\n", "utf8");

    const result = await store.restore(engine);

    assert.equal(result.success, false);
    assert.match(result.message, /could not complete verified restore/);
    assert.equal(result.lockedAbsPath, target);
    assert.equal(engine.isRestoring(target), true);

    engine.removeRestoring(target);
    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});
test("snapshotStore restore releases internal in-flight guard after write failure", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const blockedParent = path.join(aegisDir, "blocked-parent");
    const target = path.join(blockedParent, ".env");
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent("BASELINE=1\n", target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    fs.writeFileSync(blockedParent, "NOT_A_DIRECTORY\n", "utf8");

    const first = await store.restore(engine);

    assert.equal(first.success, false);
    assert.equal(engine.isRestoring(target), true);
    engine.removeRestoring(target);
    fs.unlinkSync(blockedParent);

    const second = await store.restore(engine);

    assert.equal(second.success, true);
    assert.equal(fs.readFileSync(target, "utf8"), "BASELINE=1\n");
    assert.equal(engine.isRestoring(target), true);

    engine.removeRestoring(target);
    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore rejects concurrent invocation while first restore is in flight", async () => {
  const aegisDir = makeTempAegisDir();
  let releaseReadIndex = () => {};

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const baselineContent = "RESTORE_BASELINE=1\n";
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const firstEngine = new EnvCoreEngine();
    const secondEngine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent(baselineContent, target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const originalReadIndex = store.readIndex.bind(store);
    let signalReadIndexStarted = () => {};
    const readIndexGate = new Promise<void>((resolve) => {
      releaseReadIndex = () => resolve();
    });
    const readIndexStarted = new Promise<void>((resolve) => {
      signalReadIndexStarted = () => resolve();
    });

    store.readIndex = async () => {
      signalReadIndexStarted();
      await readIndexGate;
      return originalReadIndex();
    };

    const firstRestore = store.restore(firstEngine);
    await readIndexStarted;

    const secondResult = await store.restore(secondEngine);

    assert.equal(secondResult.success, false);
    assert.equal(secondResult.message, "Aegis restore is already running.");
    assert.equal(secondResult.lockedAbsPath, undefined);
    assert.equal(secondEngine.isRestoring(target), false);

    releaseReadIndex();
    const firstResult = await firstRestore;

    assert.equal(firstResult.success, true);
    assert.equal(firstResult.lockedAbsPath, target);
    assert.equal(firstEngine.isRestoring(target), true);

    firstEngine.removeRestoring(target);
    assert.equal(firstEngine.isRestoring(target), false);
  } finally {
    releaseReadIndex();
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore reports target readback failure and keeps restore lock", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const baselineContent = "RESTORE_BASELINE=1\n";
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent(baselineContent, target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const readFileDescriptor = Object.getOwnPropertyDescriptor(fs.promises, "readFile");
    if (readFileDescriptor === undefined) {
      assert.fail("expected fs.promises.readFile descriptor");
    }

    const originalReadFile = fs.promises.readFile.bind(fs.promises);
    Object.defineProperty(fs.promises, "readFile", {
      configurable: true,
      writable: true,
      value: async (...args: any[]) => {
        if (args[0] === target) {
          throw new Error("simulated restore readback failure");
        }
        return (originalReadFile as (...readArgs: any[]) => Promise<unknown>)(...args);
      },
    });

    try {
      const result = await store.restore(engine);

      assert.equal(result.success, false);
      assert.equal(result.message, "Aegis: Could not read back restored file: Error: simulated restore readback failure");
      assert.equal(result.lockedAbsPath, target);
      assert.equal(fs.readFileSync(target, "utf8"), baselineContent);
      assert.equal(engine.isRestoring(target), true);
    } finally {
      Object.defineProperty(fs.promises, "readFile", readFileDescriptor);
      engine.removeRestoring(target);
    }

    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore reports post-write content mismatch and keeps restore lock", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const baselineContent = "RESTORE_BASELINE=1\n";
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent(baselineContent, target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const readFileDescriptor = Object.getOwnPropertyDescriptor(fs.promises, "readFile");
    if (readFileDescriptor === undefined) {
      assert.fail("expected fs.promises.readFile descriptor");
    }

    const originalReadFile = fs.promises.readFile.bind(fs.promises);
    Object.defineProperty(fs.promises, "readFile", {
      configurable: true,
      writable: true,
      value: async (...args: any[]) => {
        if (args[0] === target) {
          return "POST_WRITE_MISMATCH=1\n";
        }
        return (originalReadFile as (...readArgs: any[]) => Promise<unknown>)(...args);
      },
    });

    try {
      const result = await store.restore(engine);

      assert.equal(result.success, false);
      assert.equal(result.message, "Aegis could not complete verified restore. Content mismatch.");
      assert.equal(result.lockedAbsPath, target);
      assert.equal(fs.readFileSync(target, "utf8"), baselineContent);
      assert.equal(engine.isRestoring(target), true);
    } finally {
      Object.defineProperty(fs.promises, "readFile", readFileDescriptor);
      engine.removeRestoring(target);
    }

    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore reports post-write SHA-256 mismatch and keeps restore lock", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const baselineContent = "RESTORE_BASELINE=1\n";
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent(baselineContent, target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const index = await store.readIndex();
    if (index === null) {
      assert.fail("expected restore index");
    }
    store.readIndex = async () => index;

    const readFileDescriptor = Object.getOwnPropertyDescriptor(fs.promises, "readFile");
    if (readFileDescriptor === undefined) {
      assert.fail("expected fs.promises.readFile descriptor");
    }

    const originalReadFile = fs.promises.readFile.bind(fs.promises);
    Object.defineProperty(fs.promises, "readFile", {
      configurable: true,
      writable: true,
      value: async (...args: any[]) => {
        const value = await (originalReadFile as (...readArgs: any[]) => Promise<unknown>)(...args);
        if (args[0] === target) {
          index.baseline_content_sha256 = "0".repeat(64);
        }
        return value;
      },
    });

    try {
      const result = await store.restore(engine);

      assert.equal(result.success, false);
      assert.equal(result.message, "Aegis could not complete verified restore. SHA-256 mismatch against baseline.");
      assert.equal(result.lockedAbsPath, target);
      assert.equal(fs.readFileSync(target, "utf8"), baselineContent);
      assert.equal(engine.isRestoring(target), true);
    } finally {
      Object.defineProperty(fs.promises, "readFile", readFileDescriptor);
      engine.removeRestoring(target);
    }

    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});


test("snapshotStore restore reports index read exception and releases internal guard", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    store.readIndex = async () => {
      throw new Error("simulated restore index read failure");
    };

    const first = await store.restore(engine);

    assert.equal(first.success, false);
    assert.equal(first.message, "Aegis: Could not read restore index: Error: simulated restore index read failure");
    assert.equal(first.lockedAbsPath, undefined);
    assert.equal(engine.isRestoring(target), false);

    store.readIndex = async () => null;
    const second = await store.restore(engine);

    assert.equal(second.success, false);
    assert.equal(second.message, "Aegis: No safe snapshot found. Save the protected file once to create one.");
    assert.equal(second.lockedAbsPath, undefined);
    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore reports baseline snapshot read failure and releases internal guard", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const baselineContent = "RESTORE_BASELINE=1\n";
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent(baselineContent, target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const index = await store.readIndex();
    if (index === null) {
      assert.fail("expected restore index");
    }

    const readFileDescriptor = Object.getOwnPropertyDescriptor(fs.promises, "readFile");
    if (readFileDescriptor === undefined) {
      assert.fail("expected fs.promises.readFile descriptor");
    }

    const originalReadFile = fs.promises.readFile.bind(fs.promises);
    Object.defineProperty(fs.promises, "readFile", {
      configurable: true,
      writable: true,
      value: async (...args: any[]) => {
        if (args[0] === index.baseline_snapshot_file) {
          throw new Error("simulated baseline snapshot read failure");
        }
        return (originalReadFile as (...readArgs: any[]) => Promise<unknown>)(...args);
      },
    });

    try {
      const first = await store.restore(engine);

      assert.equal(first.success, false);
      assert.equal(first.message, "Aegis: Could not read baseline snapshot file: Error: simulated baseline snapshot read failure");
      assert.equal(first.lockedAbsPath, undefined);
      assert.equal(engine.isRestoring(target), false);
    } finally {
      Object.defineProperty(fs.promises, "readFile", readFileDescriptor);
    }

    const second = await store.restore(engine);

    assert.equal(second.success, true);
    assert.equal(second.lockedAbsPath, target);
    assert.equal(fs.readFileSync(target, "utf8"), baselineContent);
    assert.equal(engine.isRestoring(target), true);

    engine.removeRestoring(target);
    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore restore reports deterministic outer catch failure and keeps restore lock", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const target = path.join(aegisDir, "workspace", ".env");
    const baselineContent = "RESTORE_BASELINE=1\n";
    const store = new SnapshotStore(aegisDir, "latest-safe-snapshot.json", target);
    const engine = new EnvCoreEngine();

    const snapshotId = await store.createBaselineSnapshotFromContent(baselineContent, target, ".env");
    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "CONTAMINATED=1\n", "utf8");

    const mkdirDescriptor = Object.getOwnPropertyDescriptor(fs.promises, "mkdir");
    if (mkdirDescriptor === undefined) {
      assert.fail("expected fs.promises.mkdir descriptor");
    }

    const originalMkdir = fs.promises.mkdir.bind(fs.promises);
    Object.defineProperty(fs.promises, "mkdir", {
      configurable: true,
      writable: true,
      value: async (...args: any[]) => {
        if (args[0] === path.dirname(target)) {
          throw new Error("simulated restore outer catch failure");
        }
        return (originalMkdir as (...mkdirArgs: any[]) => Promise<unknown>)(...args);
      },
    });

    try {
      const result = await store.restore(engine);

      assert.equal(result.success, false);
      assert.equal(result.message, "Aegis could not complete verified restore: Error: simulated restore outer catch failure");
      assert.equal(result.lockedAbsPath, target);
      assert.equal(engine.isRestoring(target), true);
    } finally {
      Object.defineProperty(fs.promises, "mkdir", mkdirDescriptor);
      engine.removeRestoring(target);
    }

    assert.equal(engine.isRestoring(target), false);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore readIndex preserves non-ENOENT read failures", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store =
      new SnapshotStore(aegisDir);

    fs.mkdirSync(
      indexPath(aegisDir),
      { recursive: true }
    );

    await assert.rejects(
      store.readIndex(),
      error =>
        error instanceof Error &&
        (
          error as {
            readonly code?: unknown;
          }
        ).code !== "ENOENT"
    );
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore dedicated marker-loss baseline re-registration replaces the baseline only through the recovery method", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const absPath = path.join(aegisDir, "workspace", ".env");
    const originalContent = "ORIGINAL_BASELINE=1\n";
    const replacementContent = "REREGISTERED_BASELINE=1\n";

    const originalSnapshotId = await store.createBaselineSnapshotFromContent(
      originalContent,
      absPath,
      ".env"
    );

    if (originalSnapshotId === null) {
      assert.fail("expected original baseline snapshot id");
    }

    const recoverySnapshotId = await store.recreateBaselineSnapshotAfterMarkerLoss(
      replacementContent,
      absPath,
      ".env"
    );

    if (recoverySnapshotId === null) {
      assert.fail("expected marker-loss recovery snapshot id");
    }

    assert.notEqual(recoverySnapshotId, originalSnapshotId);

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));

    assert.equal(index.snapshot_id, recoverySnapshotId);
    assert.equal(index.source, "baseline_registration");
    assert.equal(index.baseline_content_sha256, sha256(replacementContent));
    assert.equal(index.content_sha256, sha256(replacementContent));
    assert.equal(index.baseline_snapshot_file, index.snapshot_file);
    assert.equal(
      fs.readFileSync(index.baseline_snapshot_file, "utf8"),
      replacementContent
    );

    const ordinaryOverwriteAttempt =
      await store.createBaselineSnapshotFromContent(
        "UNAPPROVED_OVERWRITE=1\n",
        absPath,
        ".env"
      );

    assert.equal(ordinaryOverwriteAttempt, null);

    const indexAfterRejectedOverwrite =
      readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));

    assert.equal(
      indexAfterRejectedOverwrite.baseline_content_sha256,
      sha256(replacementContent)
    );
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore marker-loss recovery rejects a missing existing baseline snapshot and preserves the index", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const absPath = path.join(aegisDir, "workspace", ".env");
    const content = "BASELINE_MISSING_TEST=1\n";

    const snapshotId = await store.createBaselineSnapshotFromContent(
      content,
      absPath,
      ".env"
    );

    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    const indexBeforeRecovery = fs.readFileSync(indexPath(aegisDir), "utf8");

    fs.unlinkSync(index.baseline_snapshot_file);

    const result = await store.recreateBaselineSnapshotAfterMarkerLoss(
      "NEW_CONTENT=1\n",
      absPath,
      ".env"
    );

    assert.equal(result, null);
    assert.equal(
      fs.readFileSync(indexPath(aegisDir), "utf8"),
      indexBeforeRecovery
    );
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore marker-loss recovery rejects a tampered existing baseline snapshot and preserves the index", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const absPath = path.join(aegisDir, "workspace", ".env");
    const content = "BASELINE_TAMPER_TEST=1\n";

    const snapshotId = await store.createBaselineSnapshotFromContent(
      content,
      absPath,
      ".env"
    );

    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    const indexBeforeRecovery = fs.readFileSync(indexPath(aegisDir), "utf8");

    fs.writeFileSync(
      index.baseline_snapshot_file,
      "TAMPERED_BASELINE=1\n",
      "utf8"
    );

    const result = await store.recreateBaselineSnapshotAfterMarkerLoss(
      "NEW_CONTENT=1\n",
      absPath,
      ".env"
    );

    assert.equal(result, null);
    assert.equal(
      fs.readFileSync(indexPath(aegisDir), "utf8"),
      indexBeforeRecovery
    );
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore marker-loss recovery rejects a baseline snapshot outside the snapshots directory and preserves the index", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const absPath = path.join(aegisDir, "workspace", ".env");
    const content = "BASELINE_OUTSIDE_PATH_TEST=1\n";

    const snapshotId = await store.createBaselineSnapshotFromContent(
      content,
      absPath,
      ".env"
    );

    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    const outsidePath = path.join(aegisDir, "outside-baseline.env");

    fs.writeFileSync(outsidePath, content, "utf8");

    const redirectedIndex: LatestSafeSnapshotIndex = {
      ...index,
      baseline_snapshot_file: outsidePath,
    };

    fs.writeFileSync(
      indexPath(aegisDir),
      JSON.stringify(redirectedIndex, null, 2),
      "utf8"
    );

    const indexBeforeRecovery = fs.readFileSync(indexPath(aegisDir), "utf8");

    const result = await store.recreateBaselineSnapshotAfterMarkerLoss(
      "NEW_CONTENT=1\n",
      absPath,
      ".env"
    );

    assert.equal(result, null);
    assert.equal(
      fs.readFileSync(indexPath(aegisDir), "utf8"),
      indexBeforeRecovery
    );
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("snapshotStore marker-loss recovery rejects a registered target binding mismatch and preserves the index", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const store = new SnapshotStore(aegisDir);
    const absPath = path.join(aegisDir, "workspace", ".env");
    const content = "BASELINE_BINDING_TEST=1\n";

    const snapshotId = await store.createBaselineSnapshotFromContent(
      content,
      absPath,
      ".env"
    );

    if (snapshotId === null) {
      assert.fail("expected baseline snapshot id");
    }

    const index = readJson<LatestSafeSnapshotIndex>(indexPath(aegisDir));
    const otherPath = path.join(aegisDir, "workspace", ".env.other");

    const redirectedIndex: LatestSafeSnapshotIndex = {
      ...index,
      original_path: otherPath,
      normalized_key: normalizedKey(otherPath),
    };

    fs.writeFileSync(
      indexPath(aegisDir),
      JSON.stringify(redirectedIndex, null, 2),
      "utf8"
    );

    const indexBeforeRecovery = fs.readFileSync(indexPath(aegisDir), "utf8");

    const result = await store.recreateBaselineSnapshotAfterMarkerLoss(
      "NEW_CONTENT=1\n",
      absPath,
      ".env"
    );

    assert.equal(result, null);
    assert.equal(
      fs.readFileSync(indexPath(aegisDir), "utf8"),
      indexBeforeRecovery
    );
  } finally {
    removeTempAegisDir(aegisDir);
  }
});
