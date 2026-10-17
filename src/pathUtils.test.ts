import test from "node:test";
import assert from "node:assert/strict";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";

import {
  describeRealpathTargetBinding,
  isEnvFile,
  isInsideAegisDir,
  isProtectedTargetFile,
  normalizePathForKey,
  sha256OfString,
  toSnapshotFilename,
} from "./pathUtils";
import { newSnapshotId } from "./pathUtils";

test("pathUtils normalizes keys and hashes strings deterministically", () => {
  assert.equal(normalizePathForKey("C:\\Users\\Admin\\.ENV"), "c:/users/admin/.env");
  assert.equal(
    sha256OfString("abc"),
    "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD".toLowerCase(),
  );
});

test("pathUtils detects env files and Aegis directory membership", () => {
  assert.equal(isEnvFile(path.join("workspace", ".ENV")), true);
  assert.equal(isEnvFile(path.join("workspace", ".env.local")), false);

  assert.equal(isInsideAegisDir("C:\\repo\\.aegis\\state.json", "C:\\repo\\.aegis"), true);
  assert.equal(isInsideAegisDir("C:\\repo\\.aegis-extra\\state.json", "C:\\repo\\.aegis"), false);
});

test("pathUtils converts relative paths to snapshot filenames", () => {
  assert.equal(toSnapshotFilename(".env"), "_env.snapshot");
  assert.equal(toSnapshotFilename(".env.local"), "_env_local.snapshot");
  assert.equal(toSnapshotFilename("config/.env"), "config__env.snapshot");
});

test("pathUtils binds protected target checks to workspace root when supplied", () => {
  const root = "C:\\workspace";
  const targets = [".env", ".env.local", "config/.env"];

  assert.equal(isProtectedTargetFile("C:\\workspace\\.env", targets, root), true);
  assert.equal(isProtectedTargetFile("C:\\workspace\\.env.local", targets, root), true);
  assert.equal(isProtectedTargetFile("C:\\workspace\\config\\.env", targets, root), true);
  assert.equal(isProtectedTargetFile("C:\\other\\.env", targets, root), false);
  assert.equal(isProtectedTargetFile("C:\\workspace\\nested\\.env", [".env"], root), false);
  assert.equal(isProtectedTargetFile("C:\\workspace\\.env", ["C:\\absolute\\.env"], root), false);
});

test("pathUtils preserves legacy basename protected target matching without workspace root", () => {
  assert.equal(isProtectedTargetFile("C:\\other\\.env", [".env"]), true);
  assert.equal(isProtectedTargetFile("C:\\other\\not-env.txt", [".env"]), false);
});

test("pathUtils reports unresolved realpath binding without throwing", () => {
  const missingPath = path.join("C:\\definitely-missing-aegis-path", "missing.env");
  const info = describeRealpathTargetBinding(missingPath);

  assert.equal(info.originalPath, missingPath);
  assert.equal(info.normalizedOriginalPathKey, normalizePathForKey(missingPath));
  assert.equal(info.realpath, null);
  assert.equal(info.normalizedRealpathKey, null);
  assert.equal(info.lstatFileId, null);
  assert.equal(info.mayBeSymlinkOrJunction, false);
  assert.equal(info.hardlinkCount, null);
  assert.equal(info.mayHaveHardlinkAlias, false);
  assert.equal(info.mayResolveThroughAlias, false);
  assert.equal(typeof info.unresolvedReason, "string");
});

test("pathUtils reports realpath binding for an existing file", () => {
  const info = describeRealpathTargetBinding(__filename);

  assert.equal(info.originalPath, __filename);
  assert.equal(typeof info.realpath, "string");
  assert.equal(info.normalizedRealpathKey, normalizePathForKey(info.realpath!));
  assert.equal(typeof info.lstatFileId, "string");
  assert.equal(info.unresolvedReason, null);
});

test("pathUtils generates unique snapshot ids",()=>{const a=newSnapshotId();const b=newSnapshotId();assert.match(a,/^snapshot_\d{8}_\d{6}_[0-9a-f]{8}$/);assert.notEqual(a,b);});

test("pathUtils resolves workspace aliases without accepting unsafe child aliases", () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-s1-alias-"));
  try {
    const ws = path.join(base, "workspace");
    const alias = path.join(base, "root-alias");
    const outside = path.join(base, "outside");
    fs.mkdirSync(ws);
    fs.mkdirSync(outside);
    const env = path.join(ws, ".env");
    fs.writeFileSync(env, "FIXTURE_ONLY");
    fs.writeFileSync(path.join(outside, ".env"), "FIXTURE_ONLY");
    fs.symlinkSync(ws, alias, "dir");
    const rootAlias = describeRealpathTargetBinding(path.join(alias, ".env"), alias);
    assert.equal(rootAlias.unresolvedReason, null);
    assert.equal(rootAlias.mayResolveThroughAlias, false);
    assert.equal(describeRealpathTargetBinding(env, ws).mayResolveThroughAlias, false);
    assert.equal(describeRealpathTargetBinding(path.join(alias, ".env")).mayResolveThroughAlias, true);
    fs.symlinkSync(outside, path.join(ws, "linked-dir"), "dir");
    assert.equal(
      describeRealpathTargetBinding(path.join(ws, "linked-dir", ".env"), ws).mayResolveThroughAlias,
      true
    );
    fs.symlinkSync(env, path.join(ws, "file-link"));
    assert.equal(
      describeRealpathTargetBinding(path.join(ws, "file-link"), ws).mayBeSymlinkOrJunction,
      true
    );
    assert.equal(
      describeRealpathTargetBinding(path.join(outside, ".env"), ws).mayResolveThroughAlias,
      true
    );
    fs.linkSync(env, path.join(ws, "hardlink"));
    assert.equal(
      describeRealpathTargetBinding(path.join(ws, "hardlink"), ws).mayHaveHardlinkAlias,
      true
    );
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});
