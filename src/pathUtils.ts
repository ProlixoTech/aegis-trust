// src/pathUtils.ts - Central path helpers for Prolixo Aegis Personal v0.1 Prototype
//
// RULE: normalizePathForKey() is for Map keys and comparisons ONLY.
//       Always use the original absolute path for fs.readFile / fs.writeFile.
//       Never write to disk with a lowercased path.
//
// Phase 5-P addition:
//   isProtectedTargetFile(absolutePath, targets) - detects any registered
//   protected target by its relative_path basename. Used by the Orchestrator's
//   save watchers in place of the single-target isEnvFile() check.
//   isEnvFile() is preserved unchanged for backward compatibility.

import * as nodePath from "path";
import * as nodeFs   from "fs";
import * as crypto   from "crypto";

/**
 * Normalize an absolute path for use as a Map key or comparison.
 * Converts backslashes to forward-slashes and lowercases.
 * Safe across Windows, macOS, and Linux.
 */
export function normalizePathForKey(inputPath: string): string {
  return inputPath.replace(/\\/g, "/").toLowerCase();
}

/** SHA-256 of a UTF-8 string. Used for integrity verification. */
export function sha256OfString(content: string): string {
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

/**
 * True when the file is exactly `.env` (Phase 1: only .env is protected).
 * Comparison is lowercase so it works on case-insensitive file systems.
 *
 * PRESERVED UNCHANGED from Phase 1 for backward compatibility.
 * New multi-target detection uses isProtectedTargetFile() instead.
 */
export function isEnvFile(absolutePath: string): boolean {
  return nodePath.basename(absolutePath).toLowerCase() === ".env";
}

/**
 * True when absolutePath is inside (or equal to) aegisDir.
 * Used to prevent Aegis from watching its own internal writes.
 */
export function isInsideAegisDir(absolutePath: string, aegisDir: string): boolean {
  const a = normalizePathForKey(absolutePath);
  const b = normalizePathForKey(aegisDir);
  return a === b || a.startsWith(b + "/");
}

/**
 * Convert a workspace-relative path into a flat safe filename.
 * ".env"          -> "_env.snapshot"
 * ".env.local"    -> "_env_local.snapshot"
 * "config/.env"   -> "config__env.snapshot"
 */
export function toSnapshotFilename(relPath: string): string {
  return relPath.replace(/[/\\]/g, "_").replace(/\./g, "_") + ".snapshot";
}

/** Generate a unique snapshot ID: snapshot_YYYYMMDD_HHMMSS_<4 random bytes>. */
export function newSnapshotId(): string {
  const d   = new Date();
  const z   = (n: number) => String(n).padStart(2, "0");
  const ts  = `${d.getFullYear()}${z(d.getMonth() + 1)}${z(d.getDate())}_${z(d.getHours())}${z(d.getMinutes())}${z(d.getSeconds())}`;
  return `snapshot_${ts}_${crypto.randomBytes(4).toString("hex")}`;
}

/**
 * Phase 5-P: Multi-target file detection.
 *
 * Returns true when the basename of absolutePath (lowercased) matches the
 * basename of any registered protected target's relative_path (lowercased).
 *
 * DESIGN NOTE:
 *   This function accepts the target list as a parameter rather than importing
 *   protectedTargets.ts directly. This avoids a circular dependency and keeps
 *   pathUtils.ts free of any registry import. The Orchestrator (extension.ts)
 *   passes getProtectedTargets() at the call site.
 *
 *   Comparison is basename-only and lowercased, matching the Phase 1 behaviour
 *   of isEnvFile(). Root-level targets are assumed (v0.1 scope).
 *
 * @param absolutePath  Absolute path of the file being saved.
 * @param relPaths      Array of relative_path values from the registry,
 *                      e.g. [".env", ".env.local"].
 */
export function isProtectedTargetFile(
  absolutePath: string,
  relPaths:     ReadonlyArray<string>,
  workspaceRoot?: string
): boolean {
  // PROTECTED_TARGET_WORKSPACE_BINDING_GUARD_V1
  // When workspaceRoot is supplied, bind detection to the exact registry-derived
  // workspace target path. Basename-only matching is retained only for legacy
  // callers that do not yet provide workspaceRoot.
  if (workspaceRoot) {
    const rootKey   = normalizePathForKey(nodePath.resolve(workspaceRoot));
    const actualKey = normalizePathForKey(nodePath.resolve(absolutePath));

    return relPaths.some(rp => {
      if (nodePath.isAbsolute(rp)) { return false; }

      const expectedPath = nodePath.resolve(workspaceRoot, rp);
      const expectedKey  = normalizePathForKey(expectedPath);

      if (expectedKey !== rootKey && !expectedKey.startsWith(rootKey + "/")) {
        return false;
      }

      return actualKey === expectedKey;
    });
  }

  const base = nodePath.posix.basename(normalizePathForKey(absolutePath));
  return relPaths.some(rp => nodePath.posix.basename(normalizePathForKey(rp)) === base);
}

/**
 * REALPATH_TARGET_BINDING_STANDARD_V1
 *
 * Final-product requirement anchor:
 * protected target checks must bind to resolved target identity, not only
 * string prefixes or display paths. This helper records the canonical
 * realpath plus lstat-derived native file identity hints so future policy
 * checks can detect symlink, junction, hardlink, alias, file-id/inode based
 * bypass attempts.
 *
 * This helper is side-effect free. It does not mark product pass.
 */
export interface RealpathTargetBindingInfo {
  originalPath: string;
  normalizedOriginalPathKey: string;
  realpath: string | null;
  normalizedRealpathKey: string | null;
  lstatFileId: string | null;
  mayBeSymlinkOrJunction: boolean;
  hardlinkCount: number | null;
  mayHaveHardlinkAlias: boolean;
  mayResolveThroughAlias: boolean;
  unresolvedReason: string | null;
}

export function describeRealpathTargetBinding(absolutePath: string, workspaceRoot?: string): RealpathTargetBindingInfo {
  const normalizedOriginalPathKey = normalizePathForKey(absolutePath);
  let resolvedRealpath: string | null = null;
  let normalizedRealpathKey: string | null = null;
  let lstatFileId: string | null = null;
  let mayBeSymlinkOrJunction = false;
  let hardlinkCount: number | null = null;
  let mayHaveHardlinkAlias = false;
  let mayResolveThroughAlias = false;
  let unresolvedReason: string | null = null;

  try {
    const stat = nodeFs.lstatSync(absolutePath);

    mayBeSymlinkOrJunction = stat.isSymbolicLink();
    hardlinkCount = typeof stat.nlink === "number" ? stat.nlink : null;
    mayHaveHardlinkAlias = hardlinkCount !== null && hardlinkCount > 1;

    const dev = typeof stat.dev === "number" ? String(stat.dev) : "unknown-dev";
    const ino = typeof stat.ino === "number" ? String(stat.ino) : "unknown-inode";
    lstatFileId = `dev:${dev}:inode:${ino}`;

    resolvedRealpath = nodeFs.realpathSync.native(absolutePath);
    normalizedRealpathKey = normalizePathForKey(resolvedRealpath);
    if (workspaceRoot !== undefined) {
      const rootPath = nodePath.resolve(workspaceRoot);
      const relativePath = nodePath.relative(rootPath, nodePath.resolve(absolutePath));
      const lexicalEscape = relativePath === ".." ||
        relativePath.startsWith(`..${nodePath.sep}`) || nodePath.isAbsolute(relativePath);
      const canonicalRoot = nodeFs.realpathSync.native(rootPath);
      const canonicalTarget = nodePath.resolve(canonicalRoot, relativePath);
      const realRelative = nodePath.relative(canonicalRoot, resolvedRealpath);
      const physicalEscape = realRelative === ".." ||
        realRelative.startsWith(`..${nodePath.sep}`) || nodePath.isAbsolute(realRelative);
      mayResolveThroughAlias = lexicalEscape || physicalEscape || resolvedRealpath !== canonicalTarget;
    } else {
      mayResolveThroughAlias = normalizedRealpathKey !== normalizedOriginalPathKey;
    }
  } catch (error) {
    unresolvedReason = error instanceof Error ? error.message : String(error);
  }

  return {
    originalPath: absolutePath,
    normalizedOriginalPathKey,
    realpath: resolvedRealpath,
    normalizedRealpathKey,
    lstatFileId,
    mayBeSymlinkOrJunction,
    hardlinkCount,
    mayHaveHardlinkAlias,
    mayResolveThroughAlias,
    unresolvedReason,
  };
}
