import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { EnvCoreEngine } from "./envCoreEngine";
import { normalizePathForKey, sha256OfString } from "./pathUtils";

test("envCoreEngine captures existing disk content as pre-save baseline and consumes once", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-env-core-"));
  const envPath = path.join(tempDir, ".env");

  try {
    fs.writeFileSync(envPath, "SAFE_VALUE=before-save\n", "utf8");

    const engine = new EnvCoreEngine();
    await engine.capturePreSave(envPath);

    const entry = engine.consumePending(envPath);
    assert.ok(entry);
    assert.equal(entry.originalAbsPath, envPath);
    assert.equal(entry.normalizedKey, normalizePathForKey(envPath));
    assert.equal(entry.content, "SAFE_VALUE=before-save\n");
    assert.equal(entry.sha256, sha256OfString("SAFE_VALUE=before-save\n"));
    assert.equal(entry.source, "pre_save_disk");
    assert.equal(typeof entry.capturedAt, "string");
    assert.equal(engine.consumePending(envPath), undefined);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("envCoreEngine records initial creation baseline for missing files without throwing", async () => {
  const missingPath = path.join(os.tmpdir(), "aegis-missing-env-core", ".env");
  fs.rmSync(path.dirname(missingPath), { recursive: true, force: true });

  const engine = new EnvCoreEngine();
  await engine.capturePreSave(missingPath);

  const entry = engine.consumePending(missingPath);
  assert.ok(entry);
  assert.equal(entry.originalAbsPath, missingPath);
  assert.equal(entry.normalizedKey, normalizePathForKey(missingPath));
  assert.equal(entry.content, "");
  assert.equal(entry.sha256, sha256OfString(""));
  assert.equal(entry.source, "initial_creation");
  assert.equal(engine.consumePending(missingPath), undefined);
});

test("envCoreEngine restoring keys are normalized and removable", () => {
  const engine = new EnvCoreEngine();
  const originalPath = "C:\\Workspace\\.ENV";
  const equivalentPath = "c:/workspace/.env";

  assert.equal(engine.isRestoring(originalPath), false);

  engine.addRestoring(originalPath);
  assert.equal(engine.isRestoring(originalPath), true);
  assert.equal(engine.isRestoring(equivalentPath), true);

  engine.removeRestoring(equivalentPath);
  assert.equal(engine.isRestoring(originalPath), false);
  assert.equal(engine.isRestoring(equivalentPath), false);
});
test("envCoreEngine clears stale pending baseline after read failure", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-env-core-fail-"));
  const envPath = path.join(dir, ".env");

  try {
    fs.writeFileSync(envPath, "SAFE=1\n", "utf8");

    const engine = new EnvCoreEngine();
    await engine.capturePreSave(envPath);

    const errors: unknown[][] = [];
    const fsModule = require("fs") as typeof fs;
    t.mock.method(fsModule, "readFileSync", () => {
      throw new Error("MOCK_READ_FAILURE");
    });
    t.mock.method(console, "error", (...args: unknown[]) => {
      errors.push(args);
    });

    await engine.capturePreSave(envPath);

    assert.equal(engine.consumePending(envPath), undefined);
    assert.equal(errors.length, 1);
    assert.equal(errors[0]?.[0], "[Aegis] Pre-save baseline capture failed:");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
