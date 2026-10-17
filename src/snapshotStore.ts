//
// SNAPSHOT CREATION INVARIANT
//   baseline.content = pre-save disk text (captured in onWillSaveTextDocument)
//   The post-save risky content is NEVER used as snapshot content
//   EXCEPT during the first meaningful .env baseline registration path
//   (createBaselineSnapshotFromContent), which is the only caller that
//   provides post-save content. That method is called only by the
//   Orchestrator (extension.ts) and only when no baseline marker exists.
//
//   Verification after write:
//     readBack = readFile(snapFile, "utf8")
//     MUST satisfy: readBack === baseline.content
//     MUST satisfy: sha256(readBack) === baseline.sha256
//
//
//   (engine.removeRestoring called by extension.ts after editor refresh)
//
// BLOCKER-01 change to Steps B, C, H:
//   Previously used index.snapshot_file and index.content_sha256 (rolling).
//   Now uses index.baseline_snapshot_file and index.baseline_content_sha256
//   (immutable). The rolling fields are audit-only and never used for restore.
//
// lockedAbsPath is included in EVERY RestoreResult returned after Step D
// so the caller can unconditionally call removeRestoring() in its finally.
//
// BLOCKER-01: INDEX FIELD SEPARATION
//
// The LatestSafeSnapshotIndex now carries two pointer/hash pairs:
//
//   Immutable (written at registration, never overwritten by createSnapshot):
//
//   Rolling (updated by createSnapshot on every protected-change save):
//
// createSnapshot reads the existing index before writing so that it can
// carry forward the immutable baseline fields. If the existing index is
// absent or missing the baseline fields, createSnapshot returns null and
// refuses to create an index without the immutable baseline anchors.
//
// Phase 5-P change (minimal):
//   Constructor now accepts an optional indexFileName parameter.
//   hardcoded value from Phase 1, so the .env store is unchanged.
//   The .env.local store passes "latest-safe-snapshot.env_local.json".

import * as fs       from "fs";
import * as nodePath from "path";

import {
  BaselineEntry,
  SnapshotManifest,
  LatestSafeSnapshotIndex,
  RestoreResult,
} from "../packages/aegis-core";
import { EnvCoreEngine }                                      from "./envCoreEngine";
import { sha256OfString, toSnapshotFilename, newSnapshotId, normalizePathForKey } from "./pathUtils";

const DEFAULT_INDEX_FILE = "latest-safe-snapshot.json";

function logSnapshotError(message: string, detail?: unknown): void {
  console.error(...(typeof detail === "undefined" ? [message] : [message, detail]));
}

function logSnapshotWarning(message: string, detail?: unknown): void {
  console.warn(...(typeof detail === "undefined" ? [message] : [message, detail]));
}

async function writeDurableUtf8File(targetPath: string, content: string): Promise<void> {
  // SNAPSHOT_CRASH_SAFE_DURABLE_WRITE_RUNTIME_GUARD_V1
  const targetDir = nodePath.dirname(targetPath);
  const tempPath = nodePath.join(
    targetDir,
    `.${nodePath.basename(targetPath)}.${process.pid}.${Date.now()}.tmp`
  );

  let keepTemp = true;
  try {
    const handle = await fs.promises.open(tempPath, "w");
    try {
      await handle.writeFile(content, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }

    await fs.promises.rename(tempPath, targetPath);
    keepTemp = false;
    await bestEffortSyncDirectory(targetDir);
  } finally {
    if (keepTemp) {
      try { await fs.promises.unlink(tempPath); } catch { /* best effort cleanup */ }
    }
  }
}

async function bestEffortSyncDirectory(targetDir: string): Promise<void> {
  // SNAPSHOT_DIRECTORY_SYNC_BEST_EFFORT_GUARD_V1
  try {
    const dirHandle = await fs.promises.open(targetDir, "r");
    try {
      await dirHandle.sync();
    } finally {
      await dirHandle.close();
    }
  } catch {
    // Directory fsync is best-effort across platforms.
  }
}

export class SnapshotStore {
  private readonly snapshotsDir: string;
  private readonly indexPath:    string;
  private _isRestoring           = false;

  /**
   * @param aegisDir      Absolute path to the .aegis directory.
   * @param indexFileName Optional index filename. Defaults to
   *                      "latest-safe-snapshot.json" (unchanged from Phase 1).
   *                      Pass a different name for additional protected targets.
   */
  constructor(
    private readonly aegisDir: string,
    indexFileName: string = DEFAULT_INDEX_FILE,
    private readonly expectedRestoreAbsPath?: string
  ) {
    this.snapshotsDir = nodePath.join(aegisDir, "snapshots");
    this.indexPath    = nodePath.join(aegisDir, indexFileName);
  }

  async ensureDirs(): Promise<void> {
    await fs.promises.mkdir(this.snapshotsDir, { recursive: true });
  }


  /**
   * Create a snapshot from baseline.content (pre-save disk text) and, after
   * full read-back verification, update the target's index file.
   *
   * BLOCKER-01: This method now reads the existing index before writing so
   * it can carry forward the immutable baseline_snapshot_file and
   * baseline_content_sha256 fields. If the existing index does not exist or
   * to create an index that lacks the immutable baseline anchors. This prevents
   * a contaminated rolling snapshot from silently replacing the baseline pointer.
   *
   * Returns snapshot_id on complete success (snapshot verified + index written).
   */
  async createSnapshot(
    baseline: BaselineEntry,
    relPath:  string
  ): Promise<string | null> {

    //
    // The existing index must be present and must contain the immutable
    // baseline_snapshot_file and baseline_content_sha256 fields. If either
    // is missing, refuse to proceed. The caller (handleDidSave) has already
    // confirmed the baseline marker exists, so the index should also exist.
    // If it does not, something is corrupted and we must not write a partial
    // index that lacks baseline fields.
    const existingIndex = await this.readIndex().catch(err => { logSnapshotWarning("[Aegis] createSnapshot index read threw:", err); return null; });

    if (!existingIndex) {
      logSnapshotError("[Aegis] createSnapshot: no existing index found. " +
        "Cannot create protected-change snapshot without immutable baseline fields. " +
        "Re-register baseline.");
      return null;
    }
    if (!existingIndex.baseline_snapshot_file || !existingIndex.baseline_content_sha256) {
      logSnapshotError("[Aegis] createSnapshot: existing index is missing baseline_snapshot_file " +
        "or baseline_content_sha256. Index was written before BLOCKER-01. " +
        "Re-register baseline to rebuild the index with immutable baseline fields.");
      return null;
    }

    // Preserve the immutable baseline fields from the existing index.
    // These must never be overwritten.
    const baselineSnapshotFile   = existingIndex.baseline_snapshot_file;
    const baselineContentSha256  = existingIndex.baseline_content_sha256;

    const snapshotId = newSnapshotId();
    const filesDir   = nodePath.join(this.snapshotsDir, snapshotId, "files");

    try { await fs.promises.mkdir(filesDir, { recursive: true }); }
    catch (err) { logSnapshotError("[Aegis] mkdir failed:", err); return null; }

    const snapFile    = nodePath.join(filesDir, toSnapshotFilename(relPath));
    const content     = baseline.content;   // pre-save text - never post-save
    const expectHash  = baseline.sha256;
    const byteLen     = Buffer.byteLength(content, "utf8");

    // Write snapshot content
    try { await writeDurableUtf8File(snapFile, content); }
    catch (err) { logSnapshotError("[Aegis] Snapshot write failed:", err); return null; }

    let readBack: string;
    try { readBack = await fs.promises.readFile(snapFile, "utf8"); }
    catch (err) { logSnapshotError("[Aegis] Snapshot read-back failed:", err); return null; }

    if (readBack !== content) {
      logSnapshotError("[Aegis] Snapshot content mismatch after write.");
      return null;
    }
    if (sha256OfString(readBack) !== expectHash) {
      logSnapshotError("[Aegis] Snapshot SHA-256 mismatch after write.");
      return null;
    }

    const manifest: SnapshotManifest = {
      snapshot_id:    snapshotId,
      created_at:     new Date().toISOString(),
      original_path:  baseline.originalAbsPath,
      normalized_key: baseline.normalizedKey,
      snapshot_file:  snapFile,
      source:         baseline.source,
      content_sha256: expectHash,
      byte_length:    byteLen,
      encoding:       "utf8",
    };
    const manifestPath = nodePath.join(this.snapshotsDir, snapshotId, "manifest.json");
    try { await writeDurableUtf8File(manifestPath, JSON.stringify(manifest, null, 2)); }
    catch (err) { logSnapshotError("[Aegis] Manifest write failed:", err); return null; }

    //
    // BLOCKER-01: baseline_snapshot_file and baseline_content_sha256 are copied
    // from the existing index read above. They are NOT replaced with the new
    // snapshot's path or hash. The new snapshot is a rolling audit entry only.
    const index: LatestSafeSnapshotIndex = {
      snapshot_id:             snapshotId,
      original_path:           baseline.originalAbsPath,
      normalized_key:          baseline.normalizedKey,
      source:                  baseline.source,
      created_at:              manifest.created_at,
      baseline_snapshot_file:  baselineSnapshotFile,
      baseline_content_sha256: baselineContentSha256,
      snapshot_file:           snapFile,
      content_sha256:          expectHash,
    };
    try {
      await writeDurableUtf8File(this.indexPath, JSON.stringify(index, null, 2));
    } catch (err) {
      logSnapshotError("[Aegis] Index write failed - not reporting safe restore point:", err);
      return null;
    }

    return snapshotId;
  }


  /**
   * Create a verified snapshot from explicitly provided post-save content.
   * Used ONLY during first meaningful baseline registration for a target.
   *
   * BLOCKER-01: This method now writes all four index fields, with the
   * immutable baseline fields equal to the registration values:
   *   baseline_snapshot_file   = the verified registration snapshot path
   *   baseline_content_sha256  = sha256(registration content)
   *   snapshot_file            = same as baseline_snapshot_file (no rolling yet)
   *   content_sha256           = same as baseline_content_sha256
   *
   * On subsequent protected-change saves, createSnapshot will update the
   * rolling fields (snapshot_file, content_sha256) but leave the baseline
   * fields untouched.
   *
   * CONTENT SAFETY:
   *   content is the raw protected file text. It is written to the snapshot
   *   file and to nothing else. It is NEVER logged, never written to the
   *   manifest (only hash), never written to the index (only hash), never
   *   exposed to UI or ledger.
   *
   * Returns snapshot_id on complete success.
   */
  async createBaselineSnapshotFromContent(
    content: string,
    absPath:  string,
    relPath:  string
  ): Promise<string | null> {

    //
    // Baseline registration is one-time. If an index already exists with
    // both baseline_snapshot_file and baseline_content_sha256, the baseline
    // was previously registered. Refuse to overwrite it.
    //
    // There is no explicit reset command in v0.1. Overwriting would silently
    // replace the immutable baseline with potentially contaminated content,
    // which is the exact failure mode this guard prevents.
    //
    // The caller (handleDidSave) is responsible for routing correctly via
    // the two-condition gate (marker + index check), but this guard is a
    // final backstop in case routing is incorrect for any reason.
    const existingIndex = await this.readIndex();
    if (existingIndex &&
        existingIndex.baseline_snapshot_file &&
        existingIndex.baseline_content_sha256) {
      logSnapshotError(
        "[Aegis] createBaselineSnapshotFromContent: REFUSED - an index with immutable " +
        "baseline fields already exists for this target. Baseline registration is one-time. " +
        "If a reset is needed, delete .aegis and re-register."
      );
      return null;
    }

    const snapshotId    = newSnapshotId();
    const filesDir      = nodePath.join(this.snapshotsDir, snapshotId, "files");
    const normalizedKey = normalizePathForKey(absPath);

    try { await fs.promises.mkdir(filesDir, { recursive: true }); }
    catch (err) { logSnapshotError("[Aegis] mkdir failed (baseline):", err); return null; }

    const snapFile   = nodePath.join(filesDir, toSnapshotFilename(relPath));
    const expectHash = sha256OfString(content);
    const byteLen    = Buffer.byteLength(content, "utf8");

    // Write snapshot content
    try { await writeDurableUtf8File(snapFile, content); }
    catch (err) { logSnapshotError("[Aegis] Baseline snapshot write failed:", err); return null; }

    // Read back and verify
    let readBack: string;
    try { readBack = await fs.promises.readFile(snapFile, "utf8"); }
    catch (err) { logSnapshotError("[Aegis] Baseline snapshot read-back failed:", err); return null; }

    if (readBack !== content) {
      logSnapshotError("[Aegis] Baseline snapshot content mismatch after write.");
      return null;
    }
    if (sha256OfString(readBack) !== expectHash) {
      logSnapshotError("[Aegis] Baseline snapshot SHA-256 mismatch after write.");
      return null;
    }

    const manifest: SnapshotManifest = {
      snapshot_id:    snapshotId,
      created_at:     new Date().toISOString(),
      original_path:  absPath,
      normalized_key: normalizedKey,
      snapshot_file:  snapFile,
      source:         "baseline_registration",
      content_sha256: expectHash,
      byte_length:    byteLen,
      encoding:       "utf8",
    };
    const manifestPath = nodePath.join(this.snapshotsDir, snapshotId, "manifest.json");
    try { await writeDurableUtf8File(manifestPath, JSON.stringify(manifest, null, 2)); }
    catch (err) { logSnapshotError("[Aegis] Baseline manifest write failed:", err); return null; }

    // Write index.
    //
    // BLOCKER-01: At registration time, all four fields point to the same
    // verified baseline snapshot. The immutable baseline_ fields are set here
    // and will never be overwritten by future createSnapshot calls.
    const index: LatestSafeSnapshotIndex = {
      snapshot_id:             snapshotId,
      original_path:           absPath,
      normalized_key:          normalizedKey,
      source:                  "baseline_registration",
      created_at:              manifest.created_at,
      baseline_snapshot_file:  snapFile,
      baseline_content_sha256: expectHash,
      snapshot_file:           snapFile,
      content_sha256:          expectHash,
    };
    try {
      await writeDurableUtf8File(this.indexPath, JSON.stringify(index, null, 2));
    } catch (err) {
      logSnapshotError("[Aegis] Baseline index write failed - not registering baseline:", err);
      return null;
    }

    return snapshotId;
  }

  async recreateBaselineSnapshotAfterMarkerLoss(
    content: string,
    absPath:  string,
    relPath:  string
  ): Promise<string | null> {

    //
    // Dedicated E-P0-2 marker-loss recovery path.
    // A valid immutable baseline index must already exist. This method is not
    // used for ordinary first registration and does not weaken the normal
    // createBaselineSnapshotFromContent overwrite guard.
    //
    const existingIndex = await this.readIndex();
    if (!existingIndex ||
        !existingIndex.baseline_snapshot_file ||
        !existingIndex.baseline_content_sha256) {
      logSnapshotError(
        "[Aegis] recreateBaselineSnapshotAfterMarkerLoss: REFUSED - " +
        "a valid immutable baseline index is required."
      );
      return null;
    }

    const expectedTargetKey = normalizePathForKey(nodePath.resolve(absPath));
    const indexedTargetKey = normalizePathForKey(
      nodePath.resolve(existingIndex.original_path)
    );

    if (
      indexedTargetKey !== expectedTargetKey ||
      existingIndex.normalized_key !== expectedTargetKey
    ) {
      logSnapshotError(
        "[Aegis] recreateBaselineSnapshotAfterMarkerLoss: REFUSED - " +
        "registered target binding does not match the requested protected path."
      );
      return null;
    }

    if (
      this.expectedRestoreAbsPath &&
      normalizePathForKey(nodePath.resolve(this.expectedRestoreAbsPath)) !==
        expectedTargetKey
    ) {
      logSnapshotError(
        "[Aegis] recreateBaselineSnapshotAfterMarkerLoss: REFUSED - " +
        "registry-derived protected target binding does not match."
      );
      return null;
    }

    let snapshotsRootRealPath: string;
    let existingBaselineRealPath: string;

    try {
      snapshotsRootRealPath = await fs.promises.realpath(this.snapshotsDir);
      existingBaselineRealPath = await fs.promises.realpath(
        existingIndex.baseline_snapshot_file
      );
    } catch (err) {
      logSnapshotError(
        "[Aegis] recreateBaselineSnapshotAfterMarkerLoss: REFUSED - " +
        "existing baseline snapshot could not be resolved.",
        err
      );
      return null;
    }

    const snapshotsRootKey = normalizePathForKey(
      nodePath.resolve(snapshotsRootRealPath)
    );
    const existingBaselineKey = normalizePathForKey(
      nodePath.resolve(existingBaselineRealPath)
    );

    if (!existingBaselineKey.startsWith(`${snapshotsRootKey}/`)) {
      logSnapshotError(
        "[Aegis] marker-loss recovery baseline snapshot is outside the snapshots directory."
      );
      return null;
    }

    let existingBaselineContent: string;

    try {
      existingBaselineContent = await fs.promises.readFile(
        existingBaselineRealPath,
        "utf8"
      );
    } catch (err) {
      logSnapshotError(
        "[Aegis] recreateBaselineSnapshotAfterMarkerLoss: REFUSED - " +
        "existing baseline snapshot could not be read.",
        err
      );
      return null;
    }

    if (
      sha256OfString(existingBaselineContent) !==
      existingIndex.baseline_content_sha256
    ) {
      logSnapshotError(
        "[Aegis] recreateBaselineSnapshotAfterMarkerLoss: REFUSED - " +
        "existing baseline snapshot SHA-256 does not match the immutable index."
      );
      return null;
    }

    const snapshotId    = newSnapshotId();
    const filesDir      = nodePath.join(this.snapshotsDir, snapshotId, "files");
    const normalizedKey = normalizePathForKey(absPath);

    try { await fs.promises.mkdir(filesDir, { recursive: true }); }
    catch (err) { logSnapshotError("[Aegis] mkdir failed (baseline):", err); return null; }

    const snapFile   = nodePath.join(filesDir, toSnapshotFilename(relPath));
    const expectHash = sha256OfString(content);
    const byteLen    = Buffer.byteLength(content, "utf8");

    // Write snapshot content
    try { await writeDurableUtf8File(snapFile, content); }
    catch (err) { logSnapshotError("[Aegis] Baseline snapshot write failed:", err); return null; }

    // Read back and verify
    let readBack: string;
    try { readBack = await fs.promises.readFile(snapFile, "utf8"); }
    catch (err) { logSnapshotError("[Aegis] Baseline snapshot read-back failed:", err); return null; }

    if (readBack !== content) {
      logSnapshotError("[Aegis] Baseline snapshot content mismatch after write.");
      return null;
    }
    if (sha256OfString(readBack) !== expectHash) {
      logSnapshotError("[Aegis] Baseline snapshot SHA-256 mismatch after write.");
      return null;
    }

    const manifest: SnapshotManifest = {
      snapshot_id:    snapshotId,
      created_at:     new Date().toISOString(),
      original_path:  absPath,
      normalized_key: normalizedKey,
      snapshot_file:  snapFile,
      source:         "baseline_registration",
      content_sha256: expectHash,
      byte_length:    byteLen,
      encoding:       "utf8",
    };
    const manifestPath = nodePath.join(this.snapshotsDir, snapshotId, "manifest.json");
    try { await writeDurableUtf8File(manifestPath, JSON.stringify(manifest, null, 2)); }
    catch (err) { logSnapshotError("[Aegis] Baseline manifest write failed:", err); return null; }

    // Write index.
    //
    // BLOCKER-01: At registration time, all four fields point to the same
    // verified baseline snapshot. The immutable baseline_ fields are set here
    // and will never be overwritten by future createSnapshot calls.
    const index: LatestSafeSnapshotIndex = {
      snapshot_id:             snapshotId,
      original_path:           absPath,
      normalized_key:          normalizedKey,
      source:                  "baseline_registration",
      created_at:              manifest.created_at,
      baseline_snapshot_file:  snapFile,
      baseline_content_sha256: expectHash,
      snapshot_file:           snapFile,
      content_sha256:          expectHash,
    };
    try {
      await writeDurableUtf8File(this.indexPath, JSON.stringify(index, null, 2));
    } catch (err) {
      logSnapshotError("[Aegis] Baseline index write failed - not registering baseline:", err);
      return null;
    }

    return snapshotId;
  }

  async recoverStartupArtifacts(): Promise<{ scanned: number; removed: number; failed: number }> {
    await this.ensureDirs();

    let scanned = 0;
    let removed = 0;
    let failed  = 0;

    const isDurableTempName = (name: string): boolean => {
      return /^\..+\.\d+\.\d+\.tmp$/.test(name);
    };

    const visitSnapshotDir = async (dir: string): Promise<void> => {
      let entries: fs.Dirent[];
      try {
        entries = await fs.promises.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        const fullPath = nodePath.join(dir, entry.name);

        if (entry.isDirectory()) {
          await visitSnapshotDir(fullPath);
          continue;
        }

        if (!entry.isFile() || !isDurableTempName(entry.name)) {
          continue;
        }

        scanned++;
        try {
          await fs.promises.unlink(fullPath);
          removed++;
        } catch {
          failed++;
        }
      }
    };

    let rootEntries: fs.Dirent[];
    try {
      rootEntries = await fs.promises.readdir(this.aegisDir, { withFileTypes: true });
    } catch {
      rootEntries = [];
    }

    for (const entry of rootEntries) {
      if (!entry.isFile() || !isDurableTempName(entry.name)) {
        continue;
      }

      const fullPath = nodePath.join(this.aegisDir, entry.name);
      scanned++;
      try {
        await fs.promises.unlink(fullPath);
        removed++;
      } catch {
        failed++;
      }
    }

    await visitSnapshotDir(this.snapshotsDir);

    return { scanned, removed, failed };
  }

  async readIndex(): Promise<LatestSafeSnapshotIndex | null> {
    try {
      return JSON.parse(
        await fs.promises.readFile(
          this.indexPath,
          "utf8"
        )
      ) as LatestSafeSnapshotIndex;
    } catch (error) {
      if (
        typeof error === "object" &&
        error !== null &&
        (
          error as {
            readonly code?: unknown;
          }
        ).code === "ENOENT"
      ) {
        return null;
      }

      throw error;
    }
  }

  hasIndex(): boolean {
    try { fs.accessSync(this.indexPath); return true; } catch { return false; }
  }


  /**
   * Restore the protected file from the immutable verified baseline snapshot.
   *
   * BLOCKER-01: Steps B, C, and H now use the baseline_ fields, not the
   * rolling fields:
   *
   *
   * This ensures that even if the rolling snapshot_file was contaminated by
   * an external file modification followed by a VS Code save event, the restore
   * source is always the original verified baseline snapshot.
   *
   * BACKWARD COMPATIBILITY:
   *   If the index exists but does not contain baseline_snapshot_file or
   *   baseline_content_sha256 (old index written before BLOCKER-01), restore
   *   refuses with a clear failure message. It does not fall back to the rolling
   *   snapshot_file. The user must re-register the baseline to rebuild the index.
   *
   *
   * CRITICAL: lockedAbsPath is populated on every RestoreResult returned
   * after Step D so that extension.ts can unconditionally call
   * engine.removeRestoring() in its finally block.
   */
  async restore(engine: EnvCoreEngine): Promise<RestoreResult> {
    if (this._isRestoring) {
      return { success: false, message: "Aegis restore is already running." };
    }
    this._isRestoring = true;

    try {
      let index: LatestSafeSnapshotIndex | null;
      try {
        index = await this.readIndex();
      } catch (err) {
        logSnapshotWarning("[Aegis] restore index read threw:", err);
        return {
          success: false,
          message: `Aegis: Could not read restore index: ${String(err)}`,
        };
      }
      if (!index) {
        return {
          success: false,
          message: "Aegis: No safe snapshot found. Save the protected file once to create one.",
        };
      }

      //
      // If either baseline field is absent, the index was written before
      // BLOCKER-01 and we cannot safely restore from it. The rolling
      // snapshot_file may contain contaminated content. Refuse and instruct
      // the user to re-register the baseline.
      if (!index.baseline_snapshot_file || !index.baseline_content_sha256) {
        return {
          success: false,
          message: "Aegis: Restore index is missing immutable baseline fields. " +
            "Re-register the baseline by deleting .aegis and saving the protected file again.",
        };
      }

      // NOT index.snapshot_file (rolling, may be contaminated).
      let snapContent: string;
      try { snapContent = await fs.promises.readFile(index.baseline_snapshot_file, "utf8"); }
      catch (err) {
        return {
          success: false,
          message: `Aegis: Could not read baseline snapshot file: ${String(err)}`,
        };
      }

      // NOT index.content_sha256 (rolling, may reflect contaminated content).
      if (sha256OfString(snapContent) !== index.baseline_content_sha256) {
        return {
          success: false,
          message: "Aegis: Baseline snapshot SHA-256 mismatch - restore cancelled.",
        };
      }

      const target = index.original_path;

      // RESTORE_TARGET_BINDING_SOURCE_OF_TRUTH_GUARD_V1
      // Restore may only write to the registry-derived protected target path.
      // A tampered .aegis index original_path must not redirect restore writes.
      if (this.expectedRestoreAbsPath) {
        const actualRestoreTargetKey   = normalizePathForKey(nodePath.resolve(target));
        const expectedRestoreTargetKey = normalizePathForKey(nodePath.resolve(this.expectedRestoreAbsPath));
        if (actualRestoreTargetKey !== expectedRestoreTargetKey) {
          return {
            success: false,
          message: "Aegis: Restore target binding mismatch - restore cancelled before disk write.",
          };
        }
      }

      engine.addRestoring(target);

      try {
        await fs.promises.mkdir(nodePath.dirname(target), { recursive: true });
        await writeDurableUtf8File(target, snapContent);

        let actual: string;
        try { actual = await fs.promises.readFile(target, "utf8"); }
        catch (err) {
          return {
            success: false,
            message: `Aegis: Could not read back restored file: ${String(err)}`,
            lockedAbsPath: target,
          };
        }

        if (actual !== snapContent) {
          return {
            success: false,
            message: "Aegis could not complete verified restore. Content mismatch.",
            lockedAbsPath: target,
          };
        }

        // NOT index.content_sha256. If the disk contains contaminated content
        // (e.g. the rolling snapshot wrote it), this check catches it.
        if (sha256OfString(actual) !== index.baseline_content_sha256) {
          return {
            success: false,
            message: "Aegis could not complete verified restore. SHA-256 mismatch against baseline.",
            lockedAbsPath: target,
          };
        }

        return {
          success:          true,
          message:          "Aegis restored file from verified baseline snapshot.",
          lockedAbsPath:    target,
          restoredAbsPath:  target,
        };

      } catch (err) {
        return {
          success: false,
          message: `Aegis could not complete verified restore: ${String(err)}`,
          lockedAbsPath: target,
        };
      }

    } finally {
      this._isRestoring = false;
    }
  }
}
