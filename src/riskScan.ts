// src/riskScan.ts - First-run Risk Scan for Prolixo Aegis Personal v0.1 Prototype
//
// ROLE: Perform a lightweight, local, static scan of the project root and
//       return the Top 3 riskiest files that an AI coding agent should not
//       change carelessly.
//
// MUST NOT:
//   Read file contents (only filenames / existence).
//   Call network, Git, npm, or any external process.
//   Scan recursively beyond 1 level for specific known folders.
//   Import vscode, envCoreEngine, snapshotStore, stateManager,
//   webviewPanel, ledgerWriter, or receiptWriter.
//   Write files, ledger events, or receipts.
//   Change SAFE/BLOCKED/WARNING state.
//
// PERFORMANCE GUARANTEE:
//   Maximum 500 top-level entries processed (capped, noted in result).
//   At most 2-3 readdir calls total.
//   Sub-millisecond on any local disk.
//
// EXCLUDED DIRECTORIES:
//   node_modules, .git, .aegis, out, dist, build, coverage
//   (skipped during top-level iteration - never descended into)
//
// DISPLAY RULE:
//   Only relative paths are returned (never absolute user paths).
//   Reason strings are hardcoded static literals - never derived from file content.

import * as fs   from "fs";
import * as path from "path";

// Public types

export interface RiskItem {
  path:   string;   // relative path, e.g. ".env", ".vscode/settings.json"
  score:  number;   // static score - higher = review first
  reason: string;   // hardcoded static reason string - never from file content
}

export interface RiskScanResult {
  items:                  RiskItem[];   // Top 3, sorted descending by score
  capped:                 boolean;      // true if projectRoot had > 500 entries
  scannedTopLevelEntries: number;       // how many top-level entries were examined
}

// Constants

const MAX_TOP_LEVEL_ENTRIES = 500;
const TOP_N                 = 3;

/** Directories to skip entirely during top-level iteration. */
const EXCLUDED_DIRS = new Set([
  "node_modules", ".git", ".aegis",
  "out", "dist", "build", "coverage",
]);

/**
 * Static risk table for top-level files.
 * Key: exact basename (lowercase for matching).
 * Value: score + reason.
 *
 * Reason strings are static literals - they never contain file content.
 */
const TOP_LEVEL_RISK_TABLE: Record<string, { score: number; reason: string }> = {
  ".env":              { score: 100, reason: "Environment configuration file. Review before AI edits." },
  ".env.local":        { score:  95, reason: "Local environment override. Review before AI edits." },
  "package.json":      { score:  90, reason: "Project scripts and dependency entry point." },
  "package-lock.json": { score:  85, reason: "Dependency lockfile. AI edits can break installs." },
  "tsconfig.json":     { score:  80, reason: "TypeScript build configuration." },
  "vite.config.ts":    { score:  70, reason: "Build tool configuration." },
  "webpack.config.js": { score:  70, reason: "Bundler configuration." },
  "next.config.js":    { score:  70, reason: "Framework runtime/build configuration." },
  "docker-compose.yml":{ score:  65, reason: "Multi-service runtime configuration." },
  "dockerfile":        { score:  65, reason: "Build/runtime container configuration." },
  "readme.md":         { score:  30, reason: "Project documentation and AI context." },
};

// Main export

/**
 * Scan the project root for high-risk files and return the Top 3.
 *
 * Scan depth:
 *   - Top-level filenames from readdir(projectRoot)
 *   - .vscode/settings.json - one access() call
 *   - .github/workflows/*.yml/.yaml - one readdir() call
 *
 * Returns an empty result on any readdir failure - never throws.
 * All returned paths are relative to projectRoot.
 */
export async function runRiskScan(projectRoot: string): Promise<RiskScanResult> {
  const found:   RiskItem[] = [];
  let   capped              = false;
  let   scannedCount        = 0;

// 1. Read top-level entries
  let topEntries: string[] = [];
  try {
    topEntries = await fs.promises.readdir(projectRoot);
  } catch {
// Cannot read project root - return empty result silently
    return { items: [], capped: false, scannedTopLevelEntries: 0 };
  }

  if (topEntries.length > MAX_TOP_LEVEL_ENTRIES) {
    capped = true;
    topEntries = topEntries.slice(0, MAX_TOP_LEVEL_ENTRIES);
  }
  scannedCount = topEntries.length;

// 2. Check top-level filenames against the risk table
  for (const entry of topEntries) {
// Skip excluded directories - never descend into them
    if (EXCLUDED_DIRS.has(entry.toLowerCase())) { continue; }

    const lower = entry.toLowerCase();
    const hit   = TOP_LEVEL_RISK_TABLE[lower];
    if (hit) {
      found.push({ path: entry, score: hit.score, reason: hit.reason });
    }
  }

// 3. Check .vscode/settings.json (1 access call, no readdir)
  if (!found.some((f) => f.path === ".vscode/settings.json")) {
    try {
      await fs.promises.access(path.join(projectRoot, ".vscode", "settings.json"));
      found.push({
        path:   ".vscode/settings.json",
        score:  70,
        reason: "Workspace editor behavior configuration.",
      });
    } catch {
// File does not exist - skip silently
    }
  }

// 4. Check .github/workflows/*.yml/.yaml (1 readdir, no recursion)
  try {
    const workflowEntries = await fs.promises.readdir(
      path.join(projectRoot, ".github", "workflows")
    );
    const ymlFiles = workflowEntries.filter(
      (e) => e.toLowerCase().endsWith(".yml") || e.toLowerCase().endsWith(".yaml")
    );
    if (ymlFiles.length > 0) {
      // Add one representative entry for the workflows folder
      // (report the first found file, score applies to the whole folder)
      found.push({
        path:   `.github/workflows/${ymlFiles[0]}`,
        score:  75,
        reason: "CI workflow configuration.",
      });
    }
  } catch {
// .github/workflows does not exist - skip silently
  }

// 5. Sort: descending score, alphabetical tiebreaker
  found.sort((a, b) => {
    if (b.score !== a.score) { return b.score - a.score; }
    return a.path.localeCompare(b.path);
  });

// 6. Return Top 3
  return {
    items:                  found.slice(0, TOP_N),
    capped,
    scannedTopLevelEntries: scannedCount,
  };
}

/**
 * SECRET_EXFILTRATION_GUARD_STANDARD_V1
 *
 * Final-product requirement anchor:
 * AI-proposed commands that combine secret reads with exfiltration channels
 * such as clipboard writes, curl, Invoke-WebRequest, wget, Get-Content, cat,
 * or network upload/download verbs must be blocked or require review before
 * execution.
 *
 * This helper is side-effect free. It does not read file contents, does not
 * call network, does not call Git/npm/external processes, does not write
 * files, and does not mark product pass. It only classifies an already
 * provided command string.
 */
export interface SecretExfiltrationGuardAssessment {
  readsSecretLikeTarget: boolean;
  usesClipboardChannel: boolean;
  usesNetworkExfiltrationChannel: boolean;
  usesShellReadPrimitive: boolean;
  requiresReview: boolean;
  reason: string | null;
}

export function assessSecretExfiltrationCommand(commandText: string): SecretExfiltrationGuardAssessment {
  const normalized = commandText.toLowerCase();

  const readsSecretLikeTarget =
    /\b(secret|token|password|credential|api[_-]?key|private[_-]?key)\b/i.test(commandText) ||
    /(^|[\s"'` + "`" + `])\.env(\.local)?($|[\s"'` + "`" + `])/i.test(commandText) ||
    /\.(pem|p12|pfx|key)($|[\s"'` + "`" + `])/i.test(commandText);

  const usesClipboardChannel =
    /\b(set-clipboard|pbcopy|xclip|xsel|clipboard)\b/i.test(commandText);

  const usesNetworkExfiltrationChannel =
    /\b(curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm)\b/i.test(commandText) ||
    /\b(http|https):\/\//i.test(commandText);

  const usesShellReadPrimitive =
    /\b(get-content|cat|type)\b/i.test(commandText);

  const requiresReview =
    readsSecretLikeTarget &&
    (usesClipboardChannel || usesNetworkExfiltrationChannel || usesShellReadPrimitive);

  return {
    readsSecretLikeTarget,
    usesClipboardChannel,
    usesNetworkExfiltrationChannel,
    usesShellReadPrimitive,
    requiresReview,
    reason: requiresReview
      ? "SECRET_EXFILTRATION_GUARD_STANDARD_V1: command may read secret material and expose it through clipboard, shell read, or network exfiltration channel."
      : null,
  };
}
