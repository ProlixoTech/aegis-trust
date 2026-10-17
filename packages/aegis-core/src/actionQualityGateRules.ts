/**
 * actionQualityGateRules.ts
 *
 * Individual rule functions for the Action Quality Gate.
 * Rules are evaluated in order by evaluateActionQuality(). First match wins.
 *
 * Rule ordering:
 *   RULE 1:  Safe runner + Set-Clipboard exact pattern -> ALLOW
 *   RULE 2:  Remote script execution -> BLOCK
 *   RULE 3:  Destructive file operation -> BLOCK
 *   RULE 4:  Destructive git command -> BLOCK
 *   RULE 5:  Build / package / install / deploy -> BLOCK
 *   RULE 6:  Product PASS / upload-ready / FINAL ZIP / release-state claim -> BLOCK
 *   RULE 7:  Command length > ~500 chars -> REVIEW_NEEDED
 *   RULE 8:  Mixed purpose / chained multi-operation -> SPLIT_REQUIRED
 *   RULE 9:  Explicit short read-only command -> ALLOW
 *   RULE 10: Default unknown command -> REVIEW_NEEDED
 *
 * FINAL_PRODUCT_REQUIREMENT_AI_CONNECTED_AEGIS=True
 * These rules are caller-independent - same logic for VS Code UI, Protected Terminal,
 * AI Connector, and external gateway callers.
 */

import { ActionGateStatus, ActionQualityResult, ActionQualityCallerSource, ActionQualityDetectedEffect, ActionQualityDetectedEffectKind } from './types';
import { isSafeRunnerPattern, isShortReadOnlyPattern } from './actionQualityGateSafePatterns';
import { RULE_MESSAGES } from './actionQualityGateMessages';

// Helper type

/** Partial result returned by a rule function. null means "not matched". */
type RuleMatch = Omit<ActionQualityResult, 'source'> | null;

function makeSyntacticLevel1Effect(
  ruleId: string,
  kind: ActionQualityDetectedEffectKind,
  description: string,
  confidence: ActionQualityDetectedEffect['confidence'] = 'HIGH'
): ActionQualityDetectedEffect {
  return {
    level: 'SYNTACTIC_LEVEL_1',
    kind,
    confidence,
    sourceRuleId: ruleId,
    description,
  };
}

function detectedEffectsForRule(ruleId: string): ActionQualityDetectedEffect[] {
  switch (ruleId) {
    case 'SAFE_RUNNER_PATTERN':
      return [
        makeSyntacticLevel1Effect(ruleId, 'READ_ONLY_INSPECTION', 'Recognized an Aegis safe runner pattern.'),
        makeSyntacticLevel1Effect(ruleId, 'CLIPBOARD_WRITE', 'Recognized deterministic Set-Clipboard evidence output.'),
      ];
    case 'REMOTE_SCRIPT_EXECUTION':
      return [
        makeSyntacticLevel1Effect(ruleId, 'REMOTE_SCRIPT_EXECUTION', 'Recognized inline remote script download/execution syntax.'),
      ];
    case 'DESTRUCTIVE_FILE_OP':
      return [
        makeSyntacticLevel1Effect(ruleId, 'DESTRUCTIVE_FILE_OPERATION', 'Recognized destructive or broad file operation syntax.'),
      ];
    case 'DESTRUCTIVE_GIT':
      return [
        makeSyntacticLevel1Effect(ruleId, 'DESTRUCTIVE_GIT_OPERATION', 'Recognized git operation syntax that can discard or rewrite work.'),
      ];
    case 'BUILD_PACKAGE_INSTALL':
      return [
        makeSyntacticLevel1Effect(ruleId, 'BUILD_PACKAGE_INSTALL_OR_DEPLOY', 'Recognized build, package, install, or deploy command syntax.'),
      ];
    case 'STATE_CLAIM_RISK':
      return [
        makeSyntacticLevel1Effect(ruleId, 'RELEASE_STATE_CLAIM', 'Recognized release-state, upload-ready, final zip, or Product PASS claim syntax.'),
      ];
    case 'COMMAND_LENGTH':
      return [
        makeSyntacticLevel1Effect(ruleId, 'LARGE_OR_COMPLEX_COMMAND', 'Recognized command text exceeding the configured length threshold.', 'MEDIUM'),
      ];
    case 'MIXED_PURPOSE':
      return [
        makeSyntacticLevel1Effect(ruleId, 'MIXED_OPERATION_CATEGORIES', 'Recognized multiple distinct operation categories in one command.'),
      ];
    case 'SHORT_READ_ONLY':
      return [
        makeSyntacticLevel1Effect(ruleId, 'READ_ONLY_INSPECTION', 'Recognized short single-purpose read-only command syntax.'),
      ];
    case 'DEFAULT_REVIEW_NEEDED':
    default:
      return [
        makeSyntacticLevel1Effect(ruleId, 'UNKNOWN_COMMAND_EFFECT', 'No specific safe or blocked effect pattern was recognized.', 'LOW'),
      ];
  }
}

function makeResult(
  status: ActionGateStatus,
  ruleId: string,
  reasons: string[],
  source: ActionQualityCallerSource
): ActionQualityResult {
  const msg = RULE_MESSAGES[ruleId];
  return {
    status,
    userMessage: msg?.userMessage ?? 'No message defined for this rule.',
    reasons,
    detectedEffects: detectedEffectsForRule(ruleId),
    nextSafeStep: msg?.nextSafeStep,
    internalRuleId: ruleId,
    source,
  };
}

// RULE 1: Safe runner + Set-Clipboard exact pattern -> ALLOW

export function rule1SafeRunner(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  if (!isSafeRunnerPattern(rawText)) {
    return null;
  }
  return makeResult('ALLOW', 'SAFE_RUNNER_PATTERN', ['Matches Aegis safe runner + Set-Clipboard pattern'], source);
}

// RULE 2: Remote script execution -> BLOCK

const REMOTE_SCRIPT_PATTERNS = [
  /\biex\s*\(/i,                         // iex (irm ...)
  /\biwr\b.*\|\s*iex\b/i,               // iwr ... | iex
  /\bInvoke-Expression\b/i,             // Invoke-Expression
  /\birm\b.+\|\s*iex\b/i,              // irm ... | iex
  /\bcurl\b.+\|\s*bash\b/i,            // curl ... | bash
  /\bcurl\b.+\|\s*sh\b/i,              // curl ... | sh
  /\bwget\b.+\|\s*bash\b/i,            // wget ... | bash
  /\bwget\b.+\|\s*sh\b/i,              // wget ... | sh
  /\bfetch\b.+\|\s*bash\b/i,           // fetch ... | bash
  /\bInvoke-WebRequest\b.*\|\s*iex\b/i, // Invoke-WebRequest ... | iex
];

export function rule2RemoteScript(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  const matched = REMOTE_SCRIPT_PATTERNS.find((re) => re.test(rawText));
  if (!matched) {
    return null;
  }
  return makeResult(
    'BLOCK',
    'REMOTE_SCRIPT_EXECUTION',
    ['Downloads and executes a remote script inline'],
    source
  );
}

// RULE 3: Destructive file operation -> BLOCK

const DESTRUCTIVE_FILE_PATTERNS: RegExp[] = [
  /\brm\s+-rf\b/i,                          // rm -rf
  /\brm\s+-r\s+-f\b/i,                      // rm -r -f
  /\bRemove-Item\b/i,                        // ANY Remove-Item is destructive (PowerShell delete cmdlet)
  /\bdel\s+\/[sq]\b/i,                       // del /s /q
  /\brmdir\s+\/[sq]\b/i,                     // rmdir /s
  /\brmdir\s+-p\b/i,                         // rmdir -p (recursive parent removal)
  /\brd\s+\/[sq]\b/i,                        // rd /s /q (Windows)
  /\bshred\b/i,                              // shred (Linux)
  /\bquarantine\b.{0,80}(all|folder|directory|src|source|root)/i,  // broad quarantine
];

export function rule3DestructiveFileOp(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  const matched = DESTRUCTIVE_FILE_PATTERNS.find((re) => re.test(rawText));
  if (!matched) {
    return null;
  }
  return makeResult(
    'BLOCK',
    'DESTRUCTIVE_FILE_OP',
    ['Contains a destructive file operation (delete, forced removal, or broad wipe)'],
    source
  );
}

// RULE 4: Destructive git command -> BLOCK

const DESTRUCTIVE_GIT_PATTERNS = [
  /\bgit\s+reset\s+--hard\b/i,         // git reset --hard
  /\bgit\s+clean\s+-f[d]?\b/i,         // git clean -f / -fd
  /\bgit\s+clean\s+-[d]?f\b/i,         // git clean -df
  /\bgit\s+restore\s+\.\s*$/i,         // git restore .  (broad restore)
  /\bgit\s+checkout\s+--\s+\.\s*$/i,   // git checkout -- .  (broad discard)
  /\bgit\s+stash\s+drop\b/i,           // git stash drop (destroys stash)
  /\bgit\s+branch\s+-[Dd]\b/i,         // git branch -d / -D
  /\bgit\s+push\s+.*--force\b/i,       // git push --force
  /\bgit\s+push\s+.*-f\b/i,            // git push -f
  /\bgit\s+rebase\s+/i,                // git rebase (rewrites history)
  /\bgit\s+filter-branch\b/i,          // git filter-branch
];

export function rule4DestructiveGit(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  const matched = DESTRUCTIVE_GIT_PATTERNS.find((re) => re.test(rawText));
  if (!matched) {
    return null;
  }
  return makeResult(
    'BLOCK',
    'DESTRUCTIVE_GIT',
    ['Contains a git command that discards or rewrites history/changes irreversibly'],
    source
  );
}

// RULE 5: Build / package / install / deploy -> BLOCK

const BUILD_PACKAGE_PATTERNS = [
  /\bnpm\s+run\s+build\b/i,
  /\bnpm\s+test\b/i,
  /\bnpm\s+t\b/i,
  /\bnpm\s+pack\b/i,
  /\bnpm\s+publish\b/i,
  /\bnpm\s+install\b/i,
  /\bnpm\s+i\b/i,
  /\bnpm\s+ci\b/i,
  /\bvsce\s+package\b/i,
  /\bvsce\s+publish\b/i,
  /\bcode\s+--install-extension\b/i,
  /\btsc\s+(?!--noEmit)/i,            // tsc without --noEmit (compile produces output)
  /\bwebpack\b/i,
  /\besbuild\b/i,
  /\brollup\b/i,
  /\byarn\s+build\b/i,
  /\byarn\s+test\b/i,
  /\byarn\s+add\b/i,
  /\bpnpm\s+build\b/i,
  /\bpnpm\s+test\b/i,
  /\bpnpm\s+add\b/i,
  /\bdeploy\b/i,
  /\bpublish\b/i,
  /\brelease\b/i,
  /\bmake\s+(all|build|install|deploy)\b/i,
  /\bpip\s+install\b/i,
  /\bpip3\s+install\b/i,
  /\bapt\s+(install|upgrade)\b/i,
  /\bbrew\s+install\b/i,
];

export function rule5BuildPackageInstall(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  const matched = BUILD_PACKAGE_PATTERNS.find((re) => re.test(rawText));
  if (!matched) {
    return null;
  }
  return makeResult(
    'BLOCK',
    'BUILD_PACKAGE_INSTALL',
    ['Contains a build, package, install, or deploy command'],
    source
  );
}

// RULE 6: Product PASS / upload-ready / FINAL ZIP / release-state claim -> BLOCK

const STATE_CLAIM_PATTERNS = [
// Product PASS variants - avoid matching "NO_PRODUCT_PASS" or "=False" markers
  /(?<!NO_)PRODUCT.?PASS(?!_MARKED\s*=\s*[Ff]alse)/i,
  // Upload-ready variants
  /upload.?ready(?!\s*=\s*[Ff]alse)/i,
  /uploadReady(?!\s*=\s*[Ff]alse)/i,
  // FINAL ZIP variants
  /FINAL.?ZIP(?!\s*=\s*[Ff]alse)/i,
  /finalZip(?!\s*=\s*[Ff]alse)/i,
  // Deployment/release-ready variants
  /deployment.?ready/i,
  /release.?ready/i,
  // Explicit key=value state claim forms (true only)
  /PRODUCT_PASS_MARKED\s*=\s*[Tt]rue/,
  /uploadReadyClaimed\s*=\s*[Tt]rue/,
  /finalZipCreated\s*=\s*[Tt]rue/,
];

export function rule6StateClaimRisk(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  const matched = STATE_CLAIM_PATTERNS.find((re) => re.test(rawText));
  if (!matched) {
    return null;
  }
  return makeResult(
    'BLOCK',
    'STATE_CLAIM_RISK',
    ['Contains a release-state, upload-ready, or Product PASS claim'],
    source
  );
}

// RULE 11: AI artifact channel authority claim -> BLOCK

const AI_ARTIFACT_CHANNEL_AUTHORITY_PATTERNS = [
  /sandbox:\/mnt\/data/i,
  /\/mnt\/data\/[^\s]+/i,
  /\bdownload\s+link\b/i,
  /\bgenerated\s+artifact\b/i,
  /\bpython_user_visible\b/i,
  /\bimage_gen\b/i,
  /\btool\s+invocation\b/i,
  /\bsidecar\s+file\b/i,
  /\bcreated\s+(?:a\s+)?file\b/i,
];

export function rule11AiArtifactChannelAuthority(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  const matched = AI_ARTIFACT_CHANNEL_AUTHORITY_PATTERNS.find((re) => re.test(rawText));
  if (!matched) {
    return null;
  }

  return makeResult(
    'BLOCK',
    'AI_ARTIFACT_CHANNEL_AUTHORITY',
    ['Contains an AI artifact channel, sandbox artifact, download link, or tool-created file authority claim'],
    source
  );
}

// RULE 7: Command length > ~500 chars -> REVIEW_NEEDED

const COMMAND_LENGTH_THRESHOLD = 500;

export function rule7CommandLength(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  if (rawText.trim().length <= COMMAND_LENGTH_THRESHOLD) {
    return null;
  }
  return makeResult(
    'REVIEW_NEEDED',
    'COMMAND_LENGTH',
    [`Command length (${rawText.trim().length} chars) exceeds the ~${COMMAND_LENGTH_THRESHOLD} character threshold`],
    source
  );
}

// RULE 8: Mixed purpose / chained multi-operation -> SPLIT_REQUIRED
//
// Detects when a command combines multiple distinct operation categories.
// The safe runner pattern (RULE 1) is already checked first, so we won't
// mis-flag "node runner | Set-Clipboard; Write-Host" here.

const OPERATION_CATEGORIES = [
  { name: 'read', pattern: /\b(cat|type|Get-Content|Select-String|git\s+log|git\s+diff|git\s+status|node\s+--check)\b/i },
  { name: 'write', pattern: /\b(Set-Content|Out-File|tee|echo\s+.+>|printf\s+.+>|>>|Write-Host\s+.+>\s*\S)\b/i },
  { name: 'build', pattern: /\b(tsc|webpack|esbuild|rollup|npm\s+run\s+build|yarn\s+build)\b/i },
  { name: 'test', pattern: /\b(jest|mocha|npm\s+test|yarn\s+test)\b/i },
  { name: 'git_mutation', pattern: /\b(git\s+(add|commit|push|pull|merge|rebase|stash|cherry-pick))\b/i },
  { name: 'network', pattern: /\b(curl|wget|iwr|Invoke-WebRequest|irm)\b/i },
];

/** Returns true if rawText appears to chain multiple unrelated operation categories */
function hasMixedPurpose(rawText: string): boolean {
  const trimmed = rawText.trim();

  // Must have at least one chaining operator to be "chained"
  const hasChaining = /[;]|\s&&\s/.test(trimmed);
  if (!hasChaining) {
    return false;
  }

  // Count how many distinct operation categories match
  const matchedCategories = OPERATION_CATEGORIES.filter(({ pattern }) => pattern.test(trimmed));
// Two or more distinct categories - mixed purpose
  return matchedCategories.length >= 2;
}

export function rule8MixedPurpose(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  if (!hasMixedPurpose(rawText)) {
    return null;
  }
  return {
    status: 'SPLIT_REQUIRED',
    userMessage: RULE_MESSAGES['MIXED_PURPOSE'].userMessage,
    reasons: ['Command combines multiple distinct operation categories in a single invocation'],
    detectedEffects: detectedEffectsForRule('MIXED_PURPOSE'),
    nextSafeStep: RULE_MESSAGES['MIXED_PURPOSE'].nextSafeStep,
    internalRuleId: 'MIXED_PURPOSE',
    source,
  };
}

// RULE 9: Explicit short read-only command -> ALLOW

export function rule9ShortReadOnly(rawText: string, source: ActionQualityCallerSource): ActionQualityResult | null {
  if (!isShortReadOnlyPattern(rawText)) {
    return null;
  }
  return makeResult(
    'ALLOW',
    'SHORT_READ_ONLY',
    ['Matches explicit short single-purpose read-only command pattern'],
    source
  );
}

// RULE 10: Default unknown command -> REVIEW_NEEDED

export function rule10DefaultReviewNeeded(rawText: string, source: ActionQualityCallerSource): ActionQualityResult {
  return makeResult(
    'REVIEW_NEEDED',
    'DEFAULT_REVIEW_NEEDED',
    ['Command could not be positively identified as safe - defaulting to review required'],
    source
  );
}

// Ordered rule list for evaluateActionQuality()

export type RuleFunction = (rawText: string, source: ActionQualityCallerSource) => ActionQualityResult | null;

/**
 * All rules in evaluation order (RULE 1 - RULE 9).
 * The caller (evaluateActionQuality) applies each in sequence and stops at first non-null.
 * rule10DefaultReviewNeeded is the unconditional fallback and not in this list.
 */
export const ORDERED_RULES: RuleFunction[] = [
  rule1SafeRunner,
  rule2RemoteScript,
  rule3DestructiveFileOp,
  rule4DestructiveGit,
  rule5BuildPackageInstall,
  rule6StateClaimRisk,
  rule11AiArtifactChannelAuthority,
  rule7CommandLength,
  rule8MixedPurpose,
  rule9ShortReadOnly,
];
