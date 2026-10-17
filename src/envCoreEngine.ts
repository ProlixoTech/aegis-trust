// src/envCoreEngine.ts - Pre-save baseline capture for Prolixo Aegis Phase 1
//
// WHY onWillSaveTextDocument matters:
//   onDidSaveTextDocument fires AFTER the OS has written the new content.
//   At that point the disk already holds the risky (post-save) content.
//   Reading the file there would give us the wrong content for the snapshot.
//
//   onWillSaveTextDocument fires BEFORE the write. We read the disk here -
//   still the pre-change content - and store it in pendingPreSaveBaselineByPath.
//   onDidSaveTextDocument then pulls that cached value and passes it to
//   snapshotStore.createSnapshot(). The snapshot file ends up containing
//   the SAFE content, not the risky content.
//
// NEW FILE SAFETY:
//   If .env does not exist yet (brand-new save), fs.existsSync returns false.
//   We store content="" with source="initial_creation" instead of calling
//   readFile and crashing with ENOENT.
//
// KEY RULE: content is NEVER written to console, UI messages, or any log.

import * as fs from "fs";
import { BaselineEntry, BaselineSource } from "../packages/aegis-core";
import { normalizePathForKey, sha256OfString } from "./pathUtils";

function logEnvCoreError(message: string, detail?: unknown): void {
  console.error(...(typeof detail === "undefined" ? [message] : [message, detail]));
}

export class EnvCoreEngine {

  /**
   * Populated ONLY by capturePreSave() inside onWillSaveTextDocument.
   * Consumed (and deleted) by consumePending() inside onDidSaveTextDocument.
   * Map key: normalizePathForKey(absolutePath)
   */
  private readonly pendingPreSaveBaselineByPath = new Map<string, BaselineEntry>();

  /**
   * Normalized absolute paths currently being written by Aegis restore.
   * Both onWillSaveTextDocument and onDidSaveTextDocument ignore these paths
   * to prevent false detections and infinite save loops during restore.
   */
  private readonly restoringKeys = new Set<string>();

// Pre-save baseline capture

  /**
   * Read the current on-disk content of .env BEFORE the save completes.
   *
   * Must be called via event.waitUntil() so the OS save waits for us:
   *   event.waitUntil(engine.capturePreSave(absPath))
   *
   * If fs.existsSync returns false (brand-new file), we store content=""
   * with source="initial_creation". No readFile call. No ENOENT crash.
   *
   * Content is NEVER logged.
   */
  async capturePreSave(originalAbsPath: string): Promise<void> {
    const key = normalizePathForKey(originalAbsPath);
    try {
      let content: string;
      let source: BaselineSource;

      if (fs.existsSync(originalAbsPath)) {
        content = fs.readFileSync(originalAbsPath, "utf8");  // sync: no event-loop yield, save cannot complete before read returns
        source  = "pre_save_disk";
      } else {
        content = "";
        source  = "initial_creation";
      }

      this.pendingPreSaveBaselineByPath.set(key, {
        originalAbsPath,
        normalizedKey: key,
      content,                          // in memory only - never logged
        sha256: sha256OfString(content),
        capturedAt: new Date().toISOString(),
        source,
      });
    } catch (err) {
      // Remove stale entry so onDidSave detects the failure cleanly
      this.pendingPreSaveBaselineByPath.delete(key);
      logEnvCoreError("[Aegis] Pre-save baseline capture failed:", err);
    }
  }

  /**
   * Retrieve and delete the pending pre-save baseline for this path.
 * "Consume once" - each baseline is used at most once per save event.
   */
  consumePending(originalAbsPath: string): BaselineEntry | undefined {
    const key   = normalizePathForKey(originalAbsPath);
    const entry = this.pendingPreSaveBaselineByPath.get(key);
    this.pendingPreSaveBaselineByPath.delete(key);
    return entry;
  }

// Restoring-paths lock

  isRestoring(originalAbsPath: string): boolean {
    return this.restoringKeys.has(normalizePathForKey(originalAbsPath));
  }

  addRestoring(originalAbsPath: string): void {
    this.restoringKeys.add(normalizePathForKey(originalAbsPath));
  }

  /**
   * Remove the restoring lock.
 * MUST be called in a finally block - never leave a path permanently locked.
   */
  removeRestoring(originalAbsPath: string): void {
    this.restoringKeys.delete(normalizePathForKey(originalAbsPath));
  }
}
