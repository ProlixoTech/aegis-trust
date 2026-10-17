/**
 * actionQualityGateSafePatterns.ts
 *
 * Defines ALLOW-eligible patterns for the Action Quality Gate.
 * Two categories:
 *   1. Safe runner pattern  - Aegis runner + Set-Clipboard with EXPLICIT allowlisted action ID (RULE 1)
 *   2. Short read-only pattern - explicit short single-purpose read-only commands (RULE 9)
 *
 * FINAL_PRODUCT_REQUIREMENT_AI_CONNECTED_AEGIS=True
 * This module is caller-independent.
 */

// RULE 1: Safe Runner Pattern - EXPLICIT ALLOWLIST ONLY
//
// Allows exactly:
//   node .\scripts\<runner>.js <ACTION_ID> | Set-Clipboard; Write-Host "COPIED=<ACTION_ID>"
//
// CRITICAL: ACTION_ID must be in SAFE_RUNNER_ACTION_IDS.
// Any action ID not in this Set is NOT allowed by this rule and falls through to RULE 10 (REVIEW_NEEDED).
// Wildcard matching of action IDs is FORBIDDEN.
//
// Only READ_ONLY_*, RUN_* (check-only), VERIFY_*, COMPARE_*, AUDIT_* actions from the
// runner allowlist are included here. CREATE_*, REPAIR_*, RECORD_* are excluded
// because they mutate state and must not be auto-allowed.

const SAFE_RUNNER_ACTION_IDS = new Set<string>([
  "READ_ONLY_DISCOVER_REPO_ACTION_AUTHORITY_AND_IDENTITY_STATE",
  "READ_ONLY_VERIFY_ACTION_AUTHORITY_CONTENT",
  "RUN_HANDOFF_IDENTITY_INVARIANT_CHECK",
  "VERIFY_SUCCESSOR_HANDOFF_ZIP_AFTER_ACTION_AUTHORITY_BOOTSTRAP",
  "COMPARE_SUCCESSOR_HANDOFF_ZIP_ENTRIES_AFTER_ACTION_AUTHORITY_BOOTSTRAP",
  "AUDIT_HANDOFF_PACK_FOLDER_AND_ZIP_ENTRY_LENGTHS_AFTER_ACTION_AUTHORITY_BOOTSTRAP",
  // Add new read-only runner action IDs here explicitly. No wildcards.
]);

// Matches the structural shape of a safe runner command.
// Does NOT validate the action ID - that is done separately via SAFE_RUNNER_ACTION_IDS.
const SAFE_RUNNER_SHAPE_REGEX =
  /^node\s+[./\\]*scripts[/\\][\w.-]+\.js\s+([A-Z][A-Z0-9_]+)\s*\|\s*Set-Clipboard\s*;\s*Write-Host\s+["']?COPIED=\1["']?\s*$/i;

/**
 * Returns true if rawText:
 *   1. Matches the Aegis runner + Set-Clipboard structural pattern, AND
 *   2. The extracted ACTION_ID is explicitly in SAFE_RUNNER_ACTION_IDS.
 *
 * If the ACTION_ID is not in the allowlist, returns false.
 * the command falls through to RULE 10 (REVIEW_NEEDED), never auto-ALLOW.
 */
export function isSafeRunnerPattern(rawText: string): boolean {
  const trimmed = rawText.trim();
  if (trimmed.length === 0 || trimmed.length > 300) {
    return false;
  }

  const match = SAFE_RUNNER_SHAPE_REGEX.exec(trimmed);
  if (!match) {
    return false;
  }

  // Explicit allowlist check - this is the critical gate
  const actionId = match[1];
  return SAFE_RUNNER_ACTION_IDS.has(actionId);
}

/**
 * Returns the extracted action ID from a runner command, or null if no match.
 * Useful for diagnostics: to report which action ID was found and whether it was allowed.
 */
export function extractRunnerActionId(rawText: string): string | null {
  const match = SAFE_RUNNER_SHAPE_REGEX.exec(rawText.trim());
  return match ? match[1] : null;
}

// RULE 9: Short Read-Only Patterns
//
// Explicit whitelist of short, single-purpose, read-only command patterns.
// Conditions applied before each pattern check:
//   - Length < 200 characters
//   - No chaining operators (; && |)
//   - No mutation keywords

const SHORT_READONLY_PATTERNS: RegExp[] = [
  /^node\s+--check\s+\S+$/i,
  /^node\s+(--version|-v)\s*$/i,
  /^node\s+--help\s*$/i,
  /^Get-Content\s+\S+\s*$/i,
  /^Select-String\s+/i,
  /^git\s+status\s*$/i,
  /^git\s+diff\s+--\s+\S+\s*$/i,
  /^git\s+log\s+--oneline\s+-\d+\s*$/i,
  /^git\s+(--version|--help)\s*$/i,
  /^cat\s+\S+\s*$/i,
  /^type\s+\S+\s*$/i,
  /^echo\s+.{1,80}$/i,
];

const MUTATION_BLOCKLIST = [
  'build', 'test', 'pack', 'install', 'deploy', 'publish', 'release',
  'delete', 'remove', 'move', 'reset', 'restore', 'clean', 'purge',
  'write', 'create', 'mkdir', 'touch', 'format', 'overwrite',
];

// Pre-compiled word-boundary regexes for mutation blocklist.
// Using \b ensures we match whole words only, not substrings of filenames.
// Example: 'pack' does NOT match inside 'package.json', but DOES match 'npm pack'.
const MUTATION_BLOCKLIST_REGEXES: RegExp[] = MUTATION_BLOCKLIST.map(
  (k) => new RegExp(`\\b${k}\\b`, 'i')
);

/**
 * Returns true if rawText contains a mutation keyword as a whole word.
 * Uses word-boundary matching to avoid false positives on filenames
 * (e.g. 'pack' in 'package.json' does NOT trigger this).
 */
function hasMutationKeyword(text: string): boolean {
  return MUTATION_BLOCKLIST_REGEXES.some((re) => re.test(text));
}

/**
 * Returns true if rawText is an explicitly short, single-purpose, read-only command.
 */
export function isShortReadOnlyPattern(rawText: string): boolean {
  const trimmed = rawText.trim();
  if (trimmed.length === 0 || trimmed.length >= 200) {
    return false;
  }
  if (/[;&]|&&/.test(trimmed) || /\|/.test(trimmed)) {
    return false;
  }
  // Use word-boundary check to avoid false positives on filenames like 'package.json'
  if (hasMutationKeyword(trimmed)) {
    return false;
  }
  return SHORT_READONLY_PATTERNS.some((re) => re.test(trimmed));
}
