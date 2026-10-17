import test from "node:test";
import assert from "node:assert/strict";

import {
  getDefaultProtectedTarget,
  getEnvProtectedTarget,
  getProtectedTargets,
  getTargetById,
  getTargetByRelPath,
} from "./protectedTargets";

test("protectedTargets registry preserves expected order and protected surface", () => {
  const targets = getProtectedTargets();

  assert.equal(targets.length, 11);
  assert.deepEqual(
    targets.map(target => target.target_id),
    [
      "env_default",
      "env_local",
      "package_json",
      "tsconfig_json",
      "source_extension_ts",
      "source_snapshotStore_ts",
      "source_ledgerWriter_ts",
      "source_receiptWriter_ts",
      "source_aiComplianceGate_ts",
      "source_protectedTargets_ts",
      "source_pathUtils_ts",
    ]
  );
  assert.deepEqual(
    targets.map(target => target.relative_path),
    [
      ".env",
      ".env.local",
      "package.json",
      "tsconfig.json",
      "src/extension.ts",
      "src/snapshotStore.ts",
      "src/ledgerWriter.ts",
      "src/receiptWriter.ts",
      "src/aiComplianceGate.ts",
      "src/protectedTargets.ts",
      "src/pathUtils.ts",
    ]
  );
});

test("protectedTargets default and env helpers return the .env target", () => {
  const defaultTarget = getDefaultProtectedTarget();
  const envTarget = getEnvProtectedTarget();

  assert.equal(defaultTarget, envTarget);
  assert.equal(defaultTarget.target_id, "env_default");
  assert.equal(defaultTarget.relative_path, ".env");
  assert.equal(defaultTarget.target_type, "secret_config");
  assert.equal(defaultTarget.risk_level, "high");
  assert.equal(defaultTarget.snapshot_index_file, "latest-safe-snapshot.json");
  assert.equal(defaultTarget.marker_file, "baseline-registered.json");
});

test("protectedTargets lookups are exact by relative path and target id", () => {
  assert.equal(getTargetByRelPath(".env")?.target_id, "env_default");
  assert.equal(getTargetByRelPath(".env.local")?.target_id, "env_local");
  assert.equal(getTargetByRelPath("package.json")?.target_id, "package_json");
  assert.equal(getTargetByRelPath("tsconfig.json")?.target_id, "tsconfig_json");
  assert.equal(getTargetByRelPath("src/extension.ts")?.target_id, "source_extension_ts");

  assert.equal(getTargetByRelPath("src\\extension.ts"), undefined);
  assert.equal(getTargetByRelPath("missing.txt"), undefined);

  assert.equal(getTargetById("source_protectedTargets_ts")?.relative_path, "src/protectedTargets.ts");
  assert.equal(getTargetById("missing_target"), undefined);
});

test("protectedTargets registry metadata remains secret-safe and restore-enabled", () => {
  for (const target of getProtectedTargets()) {
    assert.equal(target.secret_safe, true, target.target_id);
    assert.equal(target.restore_enabled, true, target.target_id);
    assert.equal(target.receipt_visibility, "summary_only", target.target_id);
  }
});

test("protectedTargets registry classifies project and source targets", () => {
  assert.equal(getTargetById("package_json")?.target_type, "project_manifest");
  assert.equal(getTargetById("package_json")?.risk_level, "medium");

  assert.equal(getTargetById("tsconfig_json")?.target_type, "project_config");
  assert.equal(getTargetById("tsconfig_json")?.risk_level, "medium");

  assert.equal(getTargetById("source_extension_ts")?.target_type, "source_code");
  assert.equal(getTargetById("source_extension_ts")?.risk_level, "high");

  assert.equal(getTargetById("source_protectedTargets_ts")?.target_type, "source_code");
  assert.equal(getTargetById("source_protectedTargets_ts")?.risk_level, "high");

  assert.equal(getTargetById("source_pathUtils_ts")?.risk_level, "medium");
});

test("protectedTargets registry uses unique ids, paths, indexes, and markers", () => {
  const targets = getProtectedTargets();

  const ids = targets.map(target => target.target_id);
  const paths = targets.map(target => target.relative_path);
  const indexes = targets.map(target => target.snapshot_index_file);
  const markers = targets.map(target => target.marker_file);

  assert.equal(new Set(ids).size, ids.length);
  assert.equal(new Set(paths).size, paths.length);
  assert.equal(new Set(indexes).size, indexes.length);
  assert.equal(new Set(markers).size, markers.length);
});
test("protectedTargets registry is frozen",()=>{assert.equal(Object.isFrozen(getProtectedTargets()),true);});
