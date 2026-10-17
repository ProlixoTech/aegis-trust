// src/protectedTargets.ts - Protected Target Registry v0.4
//                           Prolixo Aegis Personal v0.1 Prototype
//
// =============================================================================
// PURPOSE
//
//   Single authoritative source of truth for which files Aegis protects.
//   Replaces scattered hard-coded file-name strings in the codebase.
//
//   The registry shape supports additional targets in future phases
//   without requiring schema changes beyond the target_type union.
//
// DESIGN RULES
//
//   - Static, in-code registry only. No disk file. No JSON config.
//   - No migration logic. No versioning file.
//   - This module MUST NOT import or call:
//       StateManager, SnapshotStore, LedgerWriter, ReceiptWriter,
//       AegisWebviewPanel, RiskScan, or any VS Code API.
//   - Pure data + helpers only.
//   - extension.ts (Orchestrator) is the only caller.
//
// Phase 5-M: env_default (.env). snapshot_index_file and marker_file introduced.
// Phase 5-P: env_local (.env.local) added. Per-target index and marker files.
// Phase 5-S: package_json (package.json) added. target_type "project_manifest".
// Phase 5-AF: tsconfig_json (tsconfig.json) added. target_type "project_config".
//             target_type union extended; all prior entries unchanged.
//
// =============================================================================

/**
 * A single protected target in the registry.
 *
 * target_id          - stable identifier. Never exposed to users or written
 *                      to ledger/receipt.
 * relative_path      - workspace-relative path, e.g. ".env".
 *                      Used to construct absolute paths and for display.
 * target_type        - classification for policy use.
 *                      "secret_config"    - holds secrets (.env, .env.local)
 *                      "project_manifest" - defines project structure (package.json)
 *                      "project_config"   - defines project tooling (tsconfig.json)
 * risk_level         - advisory severity classification.
 * secret_safe        - true: full file body is never logged, never in ledger/receipt.
 * restore_enabled    - true: participates in Restore Last Safe State.
 * receipt_visibility - "summary_only": path and event type only, no file content.
 * snapshot_index_file - per-target index filename under .aegis/ (unique per target).
 * marker_file         - per-target baseline marker filename under .aegis/ (unique).
 */
export interface ProtectedTarget {
  readonly target_id:            string;
  readonly relative_path:        string;
  readonly target_type:          "secret_config" | "project_manifest" | "project_config" | "source_code";
  readonly risk_level:           "high" | "medium" | "low";
  readonly secret_safe:          boolean;
  readonly restore_enabled:      boolean;
  readonly receipt_visibility:   "summary_only" | "hidden";
  readonly snapshot_index_file:  string;
  readonly marker_file:          string;
}

// Static registry

/**
 * The authoritative list of protected targets for v0.4.
 *
 * Four targets: .env, .env.local, package.json, tsconfig.json.
 *
 * env_default, env_local, and package_json entries are IDENTICAL to Phase 5-S -
 * full backward compatibility with all existing snapshot data on disk.
 *
 * DO NOT ADD without an explicit implementation phase instruction:
 *   - package-lock.json
 *   - pnpm-lock.yaml
 *   - yarn.lock
 *   - README.md
 *   - .env.example
 *   - .env.production
 *   - any document, folder, or binary file
 */
const PROTECTED_TARGETS: ReadonlyArray<ProtectedTarget> = Object.freeze([
  {
    target_id:           "env_default",
    relative_path:       ".env",
    target_type:         "secret_config",
    risk_level:          "high",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.json",
    marker_file:         "baseline-registered.json",
  },
  {
    target_id:           "env_local",
    relative_path:       ".env.local",
    target_type:         "secret_config",
    risk_level:          "high",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.env_local.json",
    marker_file:         "baseline-registered.env_local.json",
  },
  {
    target_id:           "package_json",
    relative_path:       "package.json",
    target_type:         "project_manifest",
    risk_level:          "medium",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.package_json.json",
    marker_file:         "baseline-registered.package_json.json",
  },
  {
    target_id:           "tsconfig_json",
    relative_path:       "tsconfig.json",
    target_type:         "project_config",
    risk_level:          "medium",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.tsconfig_json.json",
    marker_file:         "baseline-registered.tsconfig_json.json",
  },
  {
    target_id:           "source_extension_ts",
    relative_path:       "src/extension.ts",
    target_type:         "source_code",
    risk_level:          "high",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.source_extension_ts.json",
    marker_file:         "baseline-registered.source_extension_ts.json",
  },
  {
    target_id:           "source_snapshotStore_ts",
    relative_path:       "src/snapshotStore.ts",
    target_type:         "source_code",
    risk_level:          "high",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.source_snapshotStore_ts.json",
    marker_file:         "baseline-registered.source_snapshotStore_ts.json",
  },
  {
    target_id:           "source_ledgerWriter_ts",
    relative_path:       "src/ledgerWriter.ts",
    target_type:         "source_code",
    risk_level:          "medium",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.source_ledgerWriter_ts.json",
    marker_file:         "baseline-registered.source_ledgerWriter_ts.json",
  },
  {
    target_id:           "source_receiptWriter_ts",
    relative_path:       "src/receiptWriter.ts",
    target_type:         "source_code",
    risk_level:          "medium",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.source_receiptWriter_ts.json",
    marker_file:         "baseline-registered.source_receiptWriter_ts.json",
  },
  {
    target_id:           "source_aiComplianceGate_ts",
    relative_path:       "src/aiComplianceGate.ts",
    target_type:         "source_code",
    risk_level:          "medium",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.source_aiComplianceGate_ts.json",
    marker_file:         "baseline-registered.source_aiComplianceGate_ts.json",
  },
  {
    target_id:           "source_protectedTargets_ts",
    relative_path:       "src/protectedTargets.ts",
    target_type:         "source_code",
    risk_level:          "high",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.source_protectedTargets_ts.json",
    marker_file:         "baseline-registered.source_protectedTargets_ts.json",
  },
  {
    target_id:           "source_pathUtils_ts",
    relative_path:       "src/pathUtils.ts",
    target_type:         "source_code",
    risk_level:          "medium",
    secret_safe:         true,
    restore_enabled:     true,
    receipt_visibility:  "summary_only",
    snapshot_index_file: "latest-safe-snapshot.source_pathUtils_ts.json",
    marker_file:         "baseline-registered.source_pathUtils_ts.json",
  },
]);
// Helpers

/**
 * Return all registered protected targets.
 * Returns a frozen copy - callers must not mutate the registry.
 */
export function getProtectedTargets(): ReadonlyArray<ProtectedTarget> {
  return PROTECTED_TARGETS;
}

/**
 * Return the default `.env` protected target.
 */
export function getDefaultProtectedTarget(): ProtectedTarget {
  return PROTECTED_TARGETS[0];
}

/**
 * Convenience alias for getDefaultProtectedTarget().
 */
export function getEnvProtectedTarget(): ProtectedTarget {
  return getDefaultProtectedTarget();
}

/**
 * Return a target by its relative_path, or undefined if not found.
 * Used by the Orchestrator to look up a target when a save event fires.
 */
export function getTargetByRelPath(relPath: string): ProtectedTarget | undefined {
  return PROTECTED_TARGETS.find(t => t.relative_path === relPath);
}

/**
 * Return a target by its target_id, or undefined if not found.
 */
export function getTargetById(targetId: string): ProtectedTarget | undefined {
  return PROTECTED_TARGETS.find(t => t.target_id === targetId);
}
