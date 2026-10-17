// ============================================================================
// Aegis AI Compliance Gate - Phase A (revised): pure checker module
// ----------------------------------------------------------------------------
// Per PHASE-5-CN-AI-COMPLIANCE-GATE-OPTION-B-IMPLEMENTATION-PLAN-LOCK.md and
// the Phase A revision adding the Repeat Violation Gate, Phase A scope is
// strictly:
//   - reviewAiComplianceText(input: string): ReviewResult
//   - additive types in src/types.ts (ReviewClassification, ReviewSubGate,
//     ReviewFinding, ReviewResult)
//   - focused tests
//
// This module is intentionally:
//   - Pure: no side effects, no file I/O, no network, no VS Code API usage.
//   - Local-only / offline: no external calls of any kind.
//   - Advisory: it never executes, blocks, or modifies anything. It only
//     classifies pasted text as SAFE_TO_RUN / WARNING / BLOCKED with
//     per-finding explanations.
//
// Phase A explicitly does NOT include: webview UI, command registration,
// package.json changes, or harness changes (see the implementation plan
// lock for Phases B-E).
//
// First-implementation level is regex/string-based, per
// PHASE-5-CN-AI-COMPLIANCE-GATE-MINIMUM-DESIGN-LOCK.md Section 8. This is a
// known limitation (false positives/negatives are possible) and is reflected
// in the "checkedSubGates" / isEmpty fields so a future UI can show a
// "what was/wasn't checked" note rather than implying a guarantee.
//
// ----------------------------------------------------------------------------
// Repeat Violation Gate (added in Phase A revision)
// ----------------------------------------------------------------------------
// A single missing contract item (e.g. one command block missing
// Set-Clipboard) remains WARNING, as before. If the SAME class of omission
// occurs 2 or more times within the reviewed text, an additional finding
// with severity BLOCK and a fixed ruleId/explanation is appended, and the
// overall classification escalates to BLOCKED. This reflects the principle
// that a single miss may be an oversight, but a repeated miss within the
// same AI output indicates the output as a whole is not reliable enough to
// execute as-is.
// ============================================================================

import {
  ReviewClassification,
  ReviewFinding,
  ReviewResult,
  ReviewSubGate,
} from "./types";

const ALL_SUB_GATES: ReviewSubGate[] = [
  "COMMAND_OUTPUT_CONTRACT",
  "MANUAL_ACTION_CONTRACT",
  "EVIDENCE_CLAIM",
  "STATE_PHASE_BOUNDARY",
  "RESTORE_RECOVERY_REPORTING",
];

const REPEAT_VIOLATION_EXPLANATION =
  "Repeated omission of the same required contract item indicates this AI output is not reliable enough to execute as-is.";

// Controlled "success" words from the Evidence Claim Gate.
const CONTROLLED_WORDS_PATTERN =
  /\b(PASS|Safe|restored|fixed|verified|complete|final|locked)\b/g;

// Evidence markers that justify use of a controlled word.
const EVIDENCE_MARKER_PATTERN =
  /(exit\s*(code\s*)?0\b|EXIT\s*=\s*0|check-state-evidence|verify-restored|verify-metadata|scan-safety|ledger|LOCKED?\s*\/|\bPASS\s*\/\s*LOCKED|lock\.md)/i;

// Phase / scope declarations (review-only, plan-only, etc).
const PHASE_DECLARATION_PATTERN =
  /(review-only|plan-only|planning only|do not implement|do not edit|audit-only|no file changes|not implemented)/i;

// Write/delete/implementation-indicating commands.
const WRITE_OR_DELETE_PATTERN =
  /(Remove-Item|^\s*rm\s|\bdel\s|Move-Item|New-Item\b.*-ItemType\s+File|git\s+commit|git\s+push|>>?\s*['"]?[\w./\\-]+\.(ts|js|json|md)\b)/gim;

// Restore success language (product term + historical shorthand).
const RESTORE_SUCCESS_PATTERN =
  /(restore last safe state|recovery restore)\b[^.\n]{0,80}\b(succeed(ed)?|success(ful)?|worked|passed|recovered)/i;

// Verification chain references.
const VERIFICATION_CHAIN_PATTERN =
  /(check-state-evidence|verify-restored|verify-metadata|scan-safety|ledger)/i;

// D-P0-6B / PASS_WITH_RECOVERY_NOTE references.
const DP06B_REFERENCE_PATTERN = /\b(D-P0-6B|PASS_WITH_RECOVERY_NOTE|PASS_WITH_LIMITATION)\b/i;

// D-P0-6B (or similar) asserted as plain PASS.
const DP06B_PLAIN_PASS_PATTERN =
  /\bD-P0-6B\b[^.\n]{0,60}\b(is|=|now)\b[^.\n]{0,20}\bPASS\b(?!\s*_)/i;

// Direct/manual controlled recovery language.
const DIRECT_CONTROLLED_RECOVERY_PATTERN =
  /(direct controlled recovery|manual recovery|manually recovered)/i;

// "Clean" PASS/restore language.
const CLEAN_PASS_PATTERN =
  /\b(clean\s+(pass|restore)|restore last safe state succeeded|recovery restore (worked|succeeded))\b/i;

// Fenced code block extraction: ```lang\n...\n```
const CODE_BLOCK_PATTERN = /```[^\r\n]*\r?\n([\s\S]*?)```/g;

// Heuristic: does a chunk of text "look like" a local command block even
// without fences (e.g. a raw PowerShell snippet pasted without markdown)?
const COMMAND_LIKE_PATTERN =
  /(\$result\b|Set-Clipboard|Get-Content|Remove-Item|node\s+scripts\/|npm\s+run|LASTEXITCODE)/i;

// Manual-action verb segments.
const ACTION_VERB_PATTERN =
  /\b(click|open|restart|reload|register|delete|save|corrupt|remove)\b[^.\n]{0,80}/gi;

// "Ask the user to choose a file/path/location" phrasing.
const ASK_USER_CHOOSE_LOCATION_PATTERN =
  /\b(choose|pick|select)\b[^.\n]{0,40}\b(location|folder|path|file|directory)\b|wherever you (like|prefer|want)|whichever (folder|location|path|directory)/gi;

// "Final product / runtime / user-facing" requirement framing.
const PRODUCT_RUNTIME_FRAMING_PATTERN =
  /\b(final product|product[- ]runtime|user[- ]facing|end user)\b/i;

// "Harness-only / dev-aid only / test-only" resolution framing.
const HARNESS_ONLY_FRAMING_PATTERN =
  /\b(harness[- ]only|harness[- ]side (development aid|only)|development aid only|test[- ]only|dev[- ]only)\b/i;

/**
 * Build a short, sanitized excerpt around a match. Long alphanumeric runs
 * that look like secret values (KEY=..., TOKEN=..., etc.) are masked before
 * the excerpt is returned, as a defense-in-depth measure in case pasted text
 * itself contains real secret-like values.
 */
function buildExcerpt(source: string, matchText: string, context = 30): string {
  const idx = source.indexOf(matchText);
  let raw: string;
  if (idx === -1) {
    raw = matchText;
  } else {
    const start = Math.max(0, idx - context);
    const end = Math.min(source.length, idx + matchText.length + context);
    raw = source.slice(start, end);
  }
  const collapsed = raw.replace(/\s+/g, " ").trim();
  // Mask secret-like patterns: KEY=value, TOKEN=value, SECRET=value, etc.
  const masked = collapsed.replace(
    /\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PWD)[A-Z0-9_]*\s*[:=]\s*)([^\s'"]+)/gi,
    "$1***"
  );
  return masked.length > 160 ? masked.slice(0, 157) + "..." : masked;
}

function pushFinding(
  findings: ReviewFinding[],
  subGate: ReviewSubGate,
  ruleId: string,
  severity: "BLOCK" | "WARNING",
  excerpt: string,
  explanation: string
): void {
  findings.push({ subGate, ruleId, severity, excerpt, explanation });
}

/** Extract fenced code blocks; if none exist, fall back to the whole text
 * if it "looks like" a command block. */
function extractCommandLikeBlocks(text: string): string[] {
  const blocks: string[] = [];
  let m: RegExpExecArray | null;
  const pattern = new RegExp(CODE_BLOCK_PATTERN);
  while ((m = pattern.exec(text)) !== null) {
    blocks.push(m[1]);
  }
  if (blocks.length === 0 && COMMAND_LIKE_PATTERN.test(text)) {
    blocks.push(text);
  }
  return blocks;
}

function hasActionEnvelopeOrDevelopmentActionContract(text: string): boolean {
  const hasJsonActionEnvelope =
    /"actionId"\s*:/i.test(text) &&
    /"capabilityId"\s*:/i.test(text) &&
    /"declaredEffects"\s*:/i.test(text);

  const hasDevelopmentActionContract =
    (/\bAEGIS_ACTION_ID\s*[:=]/i.test(text) || /\$ActionId\s*=/i.test(text)) &&
    /\bBOUNDARY\s*[:=]/i.test(text) &&
    /\bMUTATION_ALLOWED\s*[:=]/i.test(text);

  return hasJsonActionEnvelope || hasDevelopmentActionContract;
}

function checkExecutableAiOutputRequiresActionEnvelopeOrDevContract(
  text: string,
  commandLikeBlocks: string[],
  findings: ReviewFinding[]
): void {
  if (commandLikeBlocks.length === 0) {
    return;
  }

  if (hasActionEnvelopeOrDevelopmentActionContract(text)) {
    return;
  }

  pushFinding(
    findings,
    "COMMAND_OUTPUT_CONTRACT",
    "BLOCKED_AI_SYNTHESIZED_COMMAND_WITHOUT_ACTION_ENVELOPE_OR_DEV_CONTRACT",
    "BLOCK",
    buildExcerpt(text, commandLikeBlocks[0].slice(0, 80)),
    "Executable AI output was detected without a structured Action Envelope or the development-stage Action Contract markers. Aegis blocks copyable execution content that is not bound to an authorized action surface."
  );
}

/** Command Output Contract Gate checks, applied to each command-like block. */
function checkCommandOutputContract(
  block: string,
  findings: ReviewFinding[]
): void {
    // FINAL PRODUCT REQUIREMENT: Command Output Contract Gate / AI Command Contract Validator.
  // Every PowerShell command provided by the AI must carry an explicit command
  // contract and deterministic clipboard-backed evidence output. This is not
  // only an internal handoff rule; it is part of Aegis: Review AI Command / Action.
  if (!/\bCOMMAND\s+CONTRACT\s+REQUIRED\b/i.test(block)) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_COMMAND_CONTRACT_REQUIRED_HEADER",
      "WARNING",
      buildExcerpt(block, block.slice(0, 80)),
      "This command block does not include the required 'COMMAND CONTRACT REQUIRED' header. Aegis requires this header so the user can distinguish executable commands from prose or incomplete instructions."
    );
  }

  if (!/\$result\s*=\s*@\(\)/i.test(block)) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_RESULT_ARRAY_INITIALIZATION",
      "WARNING",
      buildExcerpt(block, block.slice(0, 80)),
      "This PowerShell command does not initialize '$result = @()'. Aegis requires result collection so command output is complete and machine-checkable."
    );
  }

  if (!/\$resultText\s*=\s*\$result\s*-join\b/i.test(block)) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_RESULTTEXT_JOIN",
      "WARNING",
      buildExcerpt(block, block.slice(0, 80)),
      "This PowerShell command does not create '$resultText = $result -join ...'. Aegis requires deterministic result text before copying or displaying evidence."
    );
  }

  if (!/\$resultText\s*\|\s*Set-Clipboard\b/i.test(block)) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_RESULTTEXT_SET_CLIPBOARD",
      "WARNING",
      buildExcerpt(block, block.slice(0, 80)),
      "This PowerShell command does not pipe '$resultText' to Set-Clipboard. Aegis requires clipboard capture so the user does not need to manually copy terminal output."
    );
  }

  const meaningfulLines = block
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  const lastMeaningfulLine =
    meaningfulLines.length > 0 ? meaningfulLines[meaningfulLines.length - 1] : "";
  if (lastMeaningfulLine !== "$resultText") {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_RESULTTEXT_FINAL_OUTPUT",
      "WARNING",
      buildExcerpt(block, block.slice(0, 80)),
      "This PowerShell command does not end by outputting '$resultText'. Aegis requires the same deterministic evidence text to be printed and copied."
    );
  }

  if (
    !/\$result\s*\+=\s*["'`][A-Z0-9_][A-Z0-9_]*=/i.test(block) &&
    !/Add-ResultLine\s+["'`][A-Z0-9_][A-Z0-9_]*=/i.test(block)
  ) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_MACHINE_CHECKABLE_KEY_VALUE_OUTPUT",
      "WARNING",
      buildExcerpt(block, block.slice(0, 80)),
      "This PowerShell command does not appear to output machine-checkable KEY=VALUE evidence lines. Aegis requires key=value output so results can be audited without screenshots or prose summaries."
    );
  }
// BLOCK: raw protected-content read.
  const readPattern =
    /(Get-Content|cat|type)\s+(['"]?)([^\s'";]*\.env(?:\.local)?)\2/i;
  const readMatch = block.match(readPattern);
  if (readMatch) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "RAW_PROTECTED_CONTENT_READ",
      "BLOCK",
      buildExcerpt(block, readMatch[0]),
      "This command appears to read the contents of a protected file (.env or .env.local). Commands must never print or display raw protected file content."
    );
  }

  // BLOCK: destructive/overwrite operations on protected targets.
  const destructivePattern = new RegExp(
    "(Remove-Item|rm|del|Move-Item)\\s+[^\\n\\r]*?" +
      "(\\.env(?:\\.local)?|package\\.json|tsconfig\\.json)" +
      "|>{1,2}\\s*['\"]?(\\.env(?:\\.local)?|package\\.json|tsconfig\\.json)",
    "i"
  );
  const destructiveMatch = block.match(destructivePattern);
  if (destructiveMatch) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "PROTECTED_TARGET_DESTRUCTIVE_OPERATION",
      "BLOCK",
      buildExcerpt(block, destructiveMatch[0]),
      "This command appears to delete, move, or overwrite a protected target (.env, .env.local, package.json, or tsconfig.json) without explicit, separately-approved scope for that exact action."
    );
  }

  // WARNING: missing window label.
  if (!/\bWINDOW\s*[:=]/i.test(block) && !/Extension Development Host|VS Code (window|terminal)/i.test(block)) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_WINDOW_LABEL",
      "WARNING",
      buildExcerpt(block, block.slice(0, 40)),
      "This command block does not state which VS Code window/terminal it should be run in. Running it in the wrong window could affect the wrong project or workspace."
    );
  }

  // WARNING: missing path/working-directory statement.
  if (!/\bPATH\s*[:=]/i.test(block) && !/[A-Za-z]:\\[^\s]+|\/[\w./-]+/.test(block)) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_PATH_STATEMENT",
      "WARNING",
      buildExcerpt(block, block.slice(0, 40)),
      "This command block does not state a working directory/path. If the command has file effects, running it from the wrong directory could affect the wrong files."
    );
  }

  // WARNING: missing boundary statement.
  if (!/\bBOUNDARY\s*[:=]/i.test(block) && !/boundary/i.test(block)) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_BOUNDARY_STATEMENT",
      "WARNING",
      buildExcerpt(block, block.slice(0, 40)),
      "This command block does not state what it is and is not allowed to touch. A boundary statement helps confirm the command's scope before running it."
    );
  }

  // WARNING: $result collected but no Set-Clipboard.
  if (/\$result\w*\b/i.test(block) && !/Set-Clipboard/i.test(block)) {
    const m = block.match(/\$result\w*\b/i)!;
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "MISSING_SET_CLIPBOARD",
      "WARNING",
      buildExcerpt(block, m[0]),
      "This command collects results into $result for the user to report back, but does not include '$result | Set-Clipboard'. Without clipboard capture, the user must manually copy output, which risks incomplete or inaccurate evidence."
    );
  }
}

/** Manual Action Contract Gate checks, applied to the full text (prose).
 * Processes ALL action-verb segments (not just the first) so the Repeat
 * Violation Gate can detect repeated omissions across multiple manual
 * action instructions. */
function checkManualActionContract(text: string, findings: ReviewFinding[]): void {
  const pattern = new RegExp(ACTION_VERB_PATTERN);
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    const segment = text.slice(Math.max(0, m.index - 600), Math.min(text.length, m.index + m[0].length + 600));
    const hasWindow = /window|Extension Development Host|VS Code|folder|workspace/i.test(segment);
    const hasExpectedResult = /(expect|should see|result:|you (should|will) see)/i.test(segment);
    const hasVerification = /(verification|verify|node scripts\/|check-state-evidence|run\b|report\b)/i.test(segment);

    if (!hasWindow) {
      pushFinding(
        findings,
        "MANUAL_ACTION_CONTRACT",
        "MISSING_WINDOW_OR_FOLDER",
        "WARNING",
        buildExcerpt(text, segment),
        "This manual action instruction does not specify which VS Code window/workspace it applies to. Ambiguous manual actions risk being performed in the wrong context."
      );
    }
    if (!hasExpectedResult) {
      pushFinding(
        findings,
        "MANUAL_ACTION_CONTRACT",
        "MISSING_EXPECTED_RESULT",
        "WARNING",
        buildExcerpt(text, segment),
        "This manual action instruction does not state what the user should expect to see afterward, making it hard to confirm it worked as intended."
      );
    }
    if (!hasVerification) {
      pushFinding(
        findings,
        "MANUAL_ACTION_CONTRACT",
        "MISSING_FOLLOW_UP_VERIFICATION",
        "WARNING",
        buildExcerpt(text, segment),
        "This manual action instruction does not specify a follow-up verification step to confirm the action succeeded."
      );
    }
  }

  // "Ask the user to choose a file/path/location manually" instances.
  const choicePattern = new RegExp(ASK_USER_CHOOSE_LOCATION_PATTERN);
  let cm: RegExpExecArray | null;
  while ((cm = choicePattern.exec(text)) !== null) {
    pushFinding(
      findings,
      "MANUAL_ACTION_CONTRACT",
      "AMBIGUOUS_USER_CHOICE_REQUIRED",
      "WARNING",
      buildExcerpt(text, cm[0]),
      "This text asks the user to choose a file, folder, or location themselves rather than the AI specifying a concrete path. This is an ambiguous local operation."
    );
  }
}

/** Evidence Claim Gate checks, applied to the full text. Reports one finding
 * per controlled-word occurrence when no evidence marker exists anywhere in
 * the text, so the Repeat Violation Gate can detect repeated unsupported
 * claims. */
function checkEvidenceClaim(text: string, findings: ReviewFinding[]): void {
  if (EVIDENCE_MARKER_PATTERN.test(text)) {
    return;
  }
  const pattern = new RegExp(CONTROLLED_WORDS_PATTERN);
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    pushFinding(
      findings,
      "EVIDENCE_CLAIM",
      "SUCCESS_CLAIM_WITHOUT_EVIDENCE",
      "BLOCK",
      buildExcerpt(text, m[0]),
      `This text uses a success/status word ("${m[0]}") without any accompanying evidence (exit codes, verification command results, ledger references, or lock-file references). Success claims must be backed by evidence, not stated alone.`
    );
  }
}

/** State / Phase Boundary Gate checks, applied to the full text. Reports one
 * finding per write/delete-type match when a phase declaration is present,
 * so the Repeat Violation Gate can detect repeated boundary drift. */
function checkStatePhaseBoundary(text: string, findings: ReviewFinding[]): void {
  const phaseMatch = text.match(PHASE_DECLARATION_PATTERN);
  if (!phaseMatch) {
    return;
  }
  const pattern = new RegExp(WRITE_OR_DELETE_PATTERN);
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    pushFinding(
      findings,
      "STATE_PHASE_BOUNDARY",
      "REVIEW_ONLY_WITH_WRITE_OR_DELETE",
      "BLOCK",
      buildExcerpt(text, m[0]),
      `This text declares a restricted phase ("${phaseMatch[0]}") but also contains a command that writes, deletes, or commits files ("${m[0].trim()}"). A review-only/plan-only step must not contain file-modifying commands.`
    );
  }
}

/** Restore / Recovery Reporting Gate checks, applied to the full text. */
function checkRestoreRecoveryReporting(text: string, findings: ReviewFinding[]): void {
  // Restore success claimed without verification chain.
  const restoreSuccessMatch = text.match(RESTORE_SUCCESS_PATTERN);
  if (restoreSuccessMatch && !VERIFICATION_CHAIN_PATTERN.test(text)) {
    pushFinding(
      findings,
      "RESTORE_RECOVERY_REPORTING",
      "RESTORE_SUCCESS_WITHOUT_VERIFICATION_CHAIN",
      "BLOCK",
      buildExcerpt(text, restoreSuccessMatch[0]),
      "This text claims a successful restore (Restore Last Safe State / Recovery Restore) but does not reference the required verification chain (workspace Safe state, metadata verification, scan-safety, and ledger evidence)."
    );
  }

  // D-P0-6B / PASS_WITH_RECOVERY_NOTE collapsed into plain PASS.
  if (DP06B_REFERENCE_PATTERN.test(text)) {
    const plainPassMatch = text.match(DP06B_PLAIN_PASS_PATTERN);
    const hasRecoveryNoteQualifier = /PASS_WITH_RECOVERY_NOTE|PASS_WITH_LIMITATION/i.test(text);
    if (plainPassMatch && !hasRecoveryNoteQualifier) {
      pushFinding(
        findings,
        "RESTORE_RECOVERY_REPORTING",
        "DP06B_COLLAPSED_TO_PLAIN_PASS",
        "BLOCK",
        buildExcerpt(text, plainPassMatch[0]),
        "This text refers to D-P0-6B (or a result historically recorded as PASS_WITH_RECOVERY_NOTE / PASS_WITH_LIMITATION) but states or implies it is now plain PASS, without referencing a re-classification lock."
      );
    }
  }

  // Direct controlled recovery described as clean PASS.
  const directRecoveryMatch = text.match(DIRECT_CONTROLLED_RECOVERY_PATTERN);
  const cleanPassMatch = text.match(CLEAN_PASS_PATTERN);
  if (directRecoveryMatch && cleanPassMatch) {
    pushFinding(
      findings,
      "RESTORE_RECOVERY_REPORTING",
      "DIRECT_RECOVERY_DESCRIBED_AS_CLEAN_PASS",
      "BLOCK",
      buildExcerpt(text, cleanPassMatch[0]),
      `This text describes a "${directRecoveryMatch[0]}" but also describes the outcome as a "${cleanPassMatch[0]}" without distinguishing the two. Direct/manual controlled recovery must not be reported as a clean Restore Last Safe State / PASS.`
    );
  }
}
/** Complex Command Contract checks, applied to each command-like block. */
function checkComplexCommandContract(block: string, findings: ReviewFinding[]): void {
  const nonCommentLines = block
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));

  const hasExplicitApproval =
    /\b(explicit(ly)?\s+approved|explicit\s+approval|user\s+approved|approved\s+by\s+user)\b/i.test(block);

  const hasRepair = /\b(repair|restore|recover|fix|patch)\b/i.test(block);
  const hasCleanup = /\b(cleanup|clean\s+up|Remove-Item|rm\b|del\b|delete)\b/i.test(block);
  const hasLock = /\b(lock|LOCK|result\s+lock|RESULT\s*=\s*PASS)\b/i.test(block);
  const hasZip = /\b(zip|Compress-Archive|handoff\s+pack|NEXT-CHAT-HANDOFF)\b/i.test(block);
  const hasBuildOrTest = /\b(npm\s+run|npm\s+test|tsc\b|vsce\b|check-state-evidence|verify-restored|verify-metadata|scan-safety)\b/i.test(block);

  const purposeCount = [hasRepair, hasCleanup, hasLock, hasZip, hasBuildOrTest].filter(Boolean).length;

  if ((block.length > 5000 || nonCommentLines.length > 90 || purposeCount >= 4) && !hasExplicitApproval) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "OVERLY_LONG_MULTI_PURPOSE_COMMAND",
      "WARNING",
      buildExcerpt(block, block.slice(0, 80)),
      "This command appears overly long or multi-purpose. Aegis requires short, purpose-specific commands when the user needs split commands and reliable copied output."
    );
  }

  if (hasRepair && hasCleanup && hasLock && hasZip && !hasExplicitApproval) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "COMBINED_REPAIR_CLEANUP_LOCK_ZIP_WITHOUT_EXPLICIT_APPROVAL",
      "BLOCK",
      buildExcerpt(block, block.slice(0, 120)),
      "This command appears to combine repair, cleanup, lock creation, and handoff zip work without explicit approval. Aegis requires these high-risk purposes to be split or separately approved."
    );
  }
}

/** Handoff zip claim checks, applied to the full AI text. */
function checkHandoffZipArtifactIdentityContract(text: string, findings: ReviewFinding[]): void {
  const hasHandoffZip =
    /\b(handoff|next-chat|pack|artifact)\b[\s\S]{0,120}\b(zip|\.zip)\b/i.test(text) ||
    /\b(zip|\.zip)\b[\s\S]{0,120}\b(handoff|next-chat|pack|artifact)\b/i.test(text);

  if (!hasHandoffZip) {
    return;
  }

  const hasZipSuccessClaim =
    /\b(created|generated|ready|complete|completed|final|verified|upload|exists|available)\b/i.test(text);
  const hasSha256 = /\bSHA256\b/i.test(text);
  const hasFingerprint = /\bfingerprint\b/i.test(text);
  const hasHashCommand = /\bGet-FileHash\b/i.test(text);
  const hasIdentityEvidence = hasSha256 && (hasFingerprint || hasHashCommand);

  if (hasZipSuccessClaim && !hasIdentityEvidence) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "HANDOFF_ZIP_CLAIM_WITHOUT_SHA256_FINGERPRINT_VERIFICATION",
      "BLOCK",
      buildExcerpt(text, "handoff zip"),
      "This text claims or implies a handoff zip is created, ready, final, or verified without SHA256 plus fingerprint or Get-FileHash evidence. Aegis requires artifact identity verification for every handoff zip claim."
    );
  }

  const mentionsPostZipChangeForward =
    /\b(created|updated|modified|changed|patched|added)\b[\s\S]{0,120}\b(lock|doc|protocol|handoff\s+entry|generator)\b/i.test(text);
  const mentionsPostZipChangeReverse =
    /\b(lock|doc|protocol|handoff\s+entry|generator)\b[\s\S]{0,120}\b(created|updated|modified|changed|patched|added)\b/i.test(text);
  const mentionsPostZipChange = mentionsPostZipChangeForward || mentionsPostZipChangeReverse;
  const marksOldZipStale =
    /\b(stale|superseded|successor\s+zip|old\s+zip\s+is\s+stale|previous\s+zip\s+is\s+stale)\b/i.test(text);

  if (mentionsPostZipChange && !marksOldZipStale) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "POST_ZIP_LOCK_DOC_CHANGE_WITHOUT_STALE_SUCCESSOR_NOTICE",
      "BLOCK",
      buildExcerpt(text, "handoff zip"),
      "This text mentions handoff zip work and later lock, doc, protocol, entry, or generator changes without marking the previous zip stale or requiring a successor zip. Aegis requires stale/successor handling after new handoff-relevant changes."
    );
  }
}
/**
 * Detects "final product / runtime / user-facing" requirement framing
 * combined with "harness-only / dev-aid-only / test-only" resolution
 * framing for the same requirement. A single occurrence is reported as a
 * WARNING (per "first occurrence may be WARNING"); 2+ occurrences are
 * additionally escalated by the Repeat Violation Gate
 * (REPEAT_PRODUCT_SCOPE_COLLAPSE).
 */
function checkProductScopeCollapse(text: string, findings: ReviewFinding[]): number {
  // Find paragraph-like windows (split on blank lines) and check each for
  // co-occurrence of both framings.
  const segments = text.split(/\n\s*\n/);
  let count = 0;
  for (const segment of segments) {
    if (
      PRODUCT_RUNTIME_FRAMING_PATTERN.test(segment) &&
      HARNESS_ONLY_FRAMING_PATTERN.test(segment)
    ) {
      count++;
      const m = segment.match(HARNESS_ONLY_FRAMING_PATTERN)!;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "PRODUCT_SCOPE_COLLAPSE_SUSPECTED",
        "WARNING",
        buildExcerpt(segment, m[0]),
        "This text frames a requirement as needing to be a final product / runtime / user-facing capability, but resolves it as harness-only, development-aid-only, or test-only. A product-runtime requirement should not be silently satisfied by development tooling alone."
      );
    }
  }
  return count;
}

/**
 * Safety Kernel v3.1 runtime authority constraint gate.
 *
 * SAFETY_KERNEL_V31_RUNTIME_AUTHORITY_CONSTRAINT_GATE_V1
 *
 * This gate prevents final-product safety-kernel requirements from being
 * collapsed into unsafe runtime behavior by AI-generated implementation text:
 * - server revocation may only cover metadata such as ruleset/policy/key/version/freshness;
 * - the server must never decide allow/block for a targeted user action;
 * - workspace-local trusted capabilities may only narrow or add allowed capabilities;
 * - workspace-local policy must not weaken non-overridable kernel invariants.
 */
function checkSafetyKernelV31RuntimeAuthorityConstraints(text: string, findings: ReviewFinding[]): number {
  const segments = text
    .split(/\n\s*\n/)
    .flatMap((segment) => segment.split(/(?<=[.;])\s+/))
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0);

  const serverAuthorityPattern =
    /\b(server|remote|cloud|ruleset service|policy service)\b[\s\S]{0,200}\b(allow|block|approve|deny|execute|proceed|override|decide|decision)\b[\s\S]{0,200}\b(user action|specific action|targeted action|command|operation|request)\b/i;

  const serverRevocationMentionPattern =
    /\b(server|remote|cloud|ruleset service|policy service)\b[\s\S]{0,160}\b(revocation|revoke|revoked)\b/i;

  const serverMetadataOnlySafePattern =
    /\b(metadata[- ]only|ruleset metadata|policy metadata|signing[- ]key metadata|version metadata|freshness metadata|server cannot|server must not|server never|local client remains|local[- ]first)\b/i;

  const workspaceTrustedCapabilityPattern =
    /\b(workspace[- ]local|workspace local|local workspace)\b[\s\S]{0,180}\b(trusted capability|trusted capabilities|capability policy|capability manifest)\b/i;

  const workspaceBypassPattern =
    /\b(silent auto[- ]?execute|auto[- ]?execute|system scope|receipt bypass|ledger bypass|nonce reuse|kernel bypass|no[- ]upload bypass|bypass no[- ]upload|weaken non[- ]overridable|weaken invariant|override kernel|skip receipt|skip ledger)\b/i;

  const workspaceConstraintSafePattern =
    /\b(cannot|must not|never|not allowed|prohibit|prohibited|may only narrow|may only add|cannot weaken|without weakening|non[- ]overridable)\b/i;

  let count = 0;

  for (const segment of segments) {
    if (serverAuthorityPattern.test(segment) && !serverMetadataOnlySafePattern.test(segment)) {
      count++;
      const m = segment.match(serverAuthorityPattern)!;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "SAFETY_KERNEL_V31_SERVER_TARGETED_ACTION_DECISION",
        "BLOCK",
        buildExcerpt(segment, m[0]),
        "This text gives a server or remote ruleset authority to allow/block/decide a targeted user action. Safety Kernel v3.1 requires the local client to remain the decision authority; server revocation is limited to metadata such as ruleset, policy, signing-key, version, or freshness metadata."
      );
    } else if (serverRevocationMentionPattern.test(segment) && !serverMetadataOnlySafePattern.test(segment)) {
      count++;
      const m = segment.match(serverRevocationMentionPattern)!;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "SAFETY_KERNEL_V31_SERVER_REVOCATION_SCOPE_UNCLEAR",
        "WARNING",
        buildExcerpt(segment, m[0]),
        "This text mentions server revocation without clearly limiting it to metadata-only revocation. Safety Kernel v3.1 requires server revocation to be scoped to ruleset/policy/signing-key/version/freshness metadata, not targeted user-action allow/block decisions."
      );
    }

    if (
      workspaceTrustedCapabilityPattern.test(segment) &&
      workspaceBypassPattern.test(segment) &&
      !workspaceConstraintSafePattern.test(segment)
    ) {
      count++;
      const m = segment.match(workspaceBypassPattern)!;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "SAFETY_KERNEL_V31_WORKSPACE_TRUSTED_CAPABILITY_BYPASS",
        "BLOCK",
        buildExcerpt(segment, m[0]),
        "This text allows a workspace-local trusted capability to bypass or weaken non-overridable kernel invariants. Workspace-local trusted capabilities may only narrow or add allowed capabilities and must not grant silent auto-execute, system scope, receipt/ledger bypass, nonce reuse, kernel bypass, or no-upload bypass."
      );
    }
  }

  return count;
}
/**
 * Repeat Violation Gate: counts occurrences of each tracked rule-class
 * among the per-occurrence findings already collected, and appends a
 * BLOCK-severity REPEAT_* finding for any class occurring 2+ times.
 */

/**
 * Self-describing handoff capsule ingestion compliance gate.
 *
 * SELF_DESCRIBING_HANDOFF_CAPSULE_INGESTION_GATE_V1
 *
 * Blocks AI-generated implementation text that would make handoff resume depend
 * on chat memory, a separate natural-language prompt, dynamic guessing of
 * read-only safety, or unsafe recovery/timeout behavior.
 */
function checkSelfDescribingHandoffCapsuleIngestionRules(text: string, findings: ReviewFinding[]): number {
  const segments = text
    .split(/\n\s*\n/)
    .flatMap((segment) => segment.split(/(?<=[.;])\s+/))
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0);

  const memoryResumePattern =
    /\b(chat memory|assistant memory|previous conversation|separate prompt|natural[- ]language instruction|user must say|paste instruction)\b[\s\S]{0,180}\b(resume|handoff|continue|capsule|zip)\b/i;
  const canonicalSafePattern =
    /\b(AEGIS-HANDOFF-CAPSULE\.json|self[- ]describing capsule|firstRequiredAction|READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE)\b/i;
  const readOnlyDynamicGuessPattern =
    /\b(dynamic|runtime|guess|infer)\b[\s\S]{0,160}\b(side[- ]effect[- ]free|read[- ]only|non[- ]exfiltrating|bounded)\b/i;
  const staticCapabilitySafePattern =
    /\b(static|statically|capability taxonomy|Capability Manifest|operation_class|requiredCapability)\b/i;
  const phaseOneWarnPattern =
    /\b(Fast Integrity|Phase 1)\b[\s\S]{0,120}\b(WARN|warning|pending confirmation)\b/i;
  const recoveryAutoPattern =
    /\b(AI|agent|connector)\b[\s\S]{0,160}\b(enter|switch to|auto[- ]?enter|automatically enter)\b[\s\S]{0,120}\b(recovery mode|RECOVERY_RESUME)\b/i;

  let count = 0;
  for (const segment of segments) {
    if (memoryResumePattern.test(segment) && !canonicalSafePattern.test(segment)) {
      count++;
      const m = segment.match(memoryResumePattern)!;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "SELF_DESCRIBING_HANDOFF_CAPSULE_REQUIRES_EXTERNAL_PROMPT",
        "BLOCK",
        buildExcerpt(segment, m[0]),
        "Final product handoff resume must be driven by a self-describing capsule descriptor, not chat memory, previous conversation context, or a separate natural-language instruction."
      );
    }

    if (readOnlyDynamicGuessPattern.test(segment) && !staticCapabilitySafePattern.test(segment)) {
      count++;
      const m = segment.match(readOnlyDynamicGuessPattern)!;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "READ_ONLY_VERIFY_DYNAMIC_SIDE_EFFECT_GUESS",
        "BLOCK",
        buildExcerpt(segment, m[0]),
        "READ_ONLY_VERIFY approval-nonce exemption must be based on static Capability Manifest taxonomy validation, not dynamic guessing that an arbitrary action is side-effect free."
      );
    }

    if (phaseOneWarnPattern.test(segment)) {
      count++;
      const m = segment.match(phaseOneWarnPattern)!;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "CAPSULE_FAST_INTEGRITY_WARN_FORBIDDEN",
        "BLOCK",
        buildExcerpt(segment, m[0]),
        "Capsule ingestion Phase 1 / Fast Integrity must produce PASS or FAIL/REVIEW_REQUIRED, not WARN. WARN is only allowed in bounded Phase 2 or Phase 3 conditions."
      );
    }

    if (recoveryAutoPattern.test(segment)) {
      count++;
      const m = segment.match(recoveryAutoPattern)!;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "AI_AUTO_RECOVERY_MODE_ENTRY_FORBIDDEN",
        "BLOCK",
        buildExcerpt(segment, m[0]),
        "Recovery mode cannot be entered automatically by an AI connector. It requires explicit user UI action, a signed RECOVERY_RESUME capsule, or managed admin approval."
      );
    }
  }

  return count;
}
function applyRepeatViolationGate(
  text: string,
  findings: ReviewFinding[],
  productScopeCollapseCount: number
): void {
  const countByRule = (ruleIds: string[]): number =>
    findings.filter((f) => ruleIds.includes(f.ruleId)).length;

  // REPEAT_MISSING_COMMAND_CONTRACT: same contract-item type (window, path,
  // or boundary) missing from 2+ command-like blocks.
  const windowMissing = countByRule(["MISSING_WINDOW_LABEL"]);
  const pathMissing = countByRule(["MISSING_PATH_STATEMENT"]);
  const boundaryMissing = countByRule(["MISSING_BOUNDARY_STATEMENT"]);
  if (windowMissing >= 2 || pathMissing >= 2 || boundaryMissing >= 2) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "REPEAT_MISSING_COMMAND_CONTRACT",
      "BLOCK",
      buildExcerpt(text, text.slice(0, 40)),
      REPEAT_VIOLATION_EXPLANATION
    );
  }


  // REPEAT_MISSING_COMMAND_CONTRACT_REQUIRED_HEADER: 2+ command blocks omit the
  // mandatory top-level command contract header.
  if (countByRule(["MISSING_COMMAND_CONTRACT_REQUIRED_HEADER"]) >= 2) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "REPEAT_MISSING_COMMAND_CONTRACT_REQUIRED_HEADER",
      "BLOCK",
      buildExcerpt(text, "COMMAND CONTRACT REQUIRED"),
      "Two or more command blocks omit the mandatory 'COMMAND CONTRACT REQUIRED' header. Repeated contract-header omission means the AI output is not reliable enough to execute as-is."
    );
  }

  // REPEAT_MISSING_RESULTTEXT_CONTRACT: the same resultText contract item is
  // missing from 2+ command blocks. A single command block that misses multiple
  // resultText details remains WARNING; repeated omission across blocks escalates.
  const resultTextJoinMissing = countByRule(["MISSING_RESULTTEXT_JOIN"]);
  const resultTextClipboardMissing = countByRule(["MISSING_RESULTTEXT_SET_CLIPBOARD"]);
  const resultTextFinalOutputMissing = countByRule(["MISSING_RESULTTEXT_FINAL_OUTPUT"]);
  if (
    resultTextJoinMissing >= 2 ||
    resultTextClipboardMissing >= 2 ||
    resultTextFinalOutputMissing >= 2
  ) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "REPEAT_MISSING_RESULTTEXT_CONTRACT",
      "BLOCK",
      buildExcerpt(text, "$resultText"),
      "The same '$resultText' evidence-handling contract item is missing from two or more command blocks. Repeated clipboard/output contract omission means the AI output is not reliable enough to execute as-is."
    );
  }
  // REPEAT_MISSING_CLIPBOARD_CAPTURE: 2+ command blocks missing Set-Clipboard.
  if (countByRule(["MISSING_SET_CLIPBOARD"]) >= 2) {
    pushFinding(
      findings,
      "COMMAND_OUTPUT_CONTRACT",
      "REPEAT_MISSING_CLIPBOARD_CAPTURE",
      "BLOCK",
      buildExcerpt(text, text.slice(0, 40)),
      REPEAT_VIOLATION_EXPLANATION
    );
  }

  // REPEAT_AMBIGUOUS_LOCAL_OPERATION: 2+ ambiguous manual-action instructions
  // and/or "ask user to choose location" instances, combined.
  const ambiguousCount = countByRule([
    "MISSING_WINDOW_OR_FOLDER",
    "MISSING_EXPECTED_RESULT",
    "MISSING_FOLLOW_UP_VERIFICATION",
    "AMBIGUOUS_USER_CHOICE_REQUIRED",
  ]);
  if (ambiguousCount >= 2) {
    pushFinding(
      findings,
      "MANUAL_ACTION_CONTRACT",
      "REPEAT_AMBIGUOUS_LOCAL_OPERATION",
      "BLOCK",
      buildExcerpt(text, text.slice(0, 40)),
      REPEAT_VIOLATION_EXPLANATION
    );
  }

  // REPEAT_PHASE_BOUNDARY_DRIFT: 2+ instances of declared boundary + write/
  // delete content.
  if (countByRule(["REVIEW_ONLY_WITH_WRITE_OR_DELETE"]) >= 2) {
    pushFinding(
      findings,
      "STATE_PHASE_BOUNDARY",
      "REPEAT_PHASE_BOUNDARY_DRIFT",
      "BLOCK",
      buildExcerpt(text, text.slice(0, 40)),
      REPEAT_VIOLATION_EXPLANATION
    );
  }

  // REPEAT_UNSUPPORTED_SUCCESS_CLAIM: 2+ controlled-success-words without
  // evidence anywhere in the text.
  if (countByRule(["SUCCESS_CLAIM_WITHOUT_EVIDENCE"]) >= 2) {
    pushFinding(
      findings,
      "EVIDENCE_CLAIM",
      "REPEAT_UNSUPPORTED_SUCCESS_CLAIM",
      "BLOCK",
      buildExcerpt(text, text.slice(0, 40)),
      REPEAT_VIOLATION_EXPLANATION
    );
  }

  // REPEAT_PRODUCT_SCOPE_COLLAPSE: 2+ instances of "final product/runtime"
  // requirement resolved as "harness-only".
  if (productScopeCollapseCount >= 2) {
    pushFinding(
      findings,
      "STATE_PHASE_BOUNDARY",
      "REPEAT_PRODUCT_SCOPE_COLLAPSE",
      "BLOCK",
      buildExcerpt(text, text.slice(0, 40)),
      REPEAT_VIOLATION_EXPLANATION
    );
  }
}

/**
 * Reviews AI-generated text (a command block, manual action instruction,
 * success/PASS claim, or any mix of these) and classifies it as
 * SAFE_TO_RUN, WARNING, or BLOCKED, with per-finding explanations.
 *
 * Pure function: same input always produces the same output. No side
 * effects, no file I/O, no network, no VS Code API usage.
 *
 * Includes the Repeat Violation Gate: if the same class of contract
 * omission occurs 2+ times in the input, an additional BLOCK-severity
 * REPEAT_* finding is appended and the overall classification escalates
 * to BLOCKED, even if each individual occurrence was only a WARNING.
 */

/**
 * FINAL_PRODUCT_KPL_DENIAL_GETRULESET_GATE_V1
 *
 * Blocks final-product requirement regressions:
 * - confirmed missing authorized path must not be rediscovered;
 * - recovery objective must not be reversed into STOP/BLOCKED solely because path is missing;
 * - denial labels are evidence, not schema or capability authority;
 * - getRuleset recovery requires an owner-approved recovery envelope.
 */
function checkKnownPreconditionLedgerAndDenialGetRulesetRequirements(text: string, findings: ReviewFinding[]): number {
  const segments = text
    .split(/\n\s*\n/)
    .flatMap((segment) => segment.split(/(?<=[.;])\s+/))
    .map((segment) => segment.trim())
    .filter(Boolean);

  let count = 0;

  const confirmedMissingPattern =
    /\b(AUTHORIZED_PATH_MISSING_DENIAL_GETRULESET(?:_CONFIRMED)?|authorized path missing|missing authorized path|confirmed missing)\b/i;
  const rediscoveryPattern =
    /\b(search|check|verify|discover|find|scan|look for)\b[\s\S]{0,120}\b(existing path|authorized path|runner path|getRuleset path|path exists)\b/i;
  const recoveryObjectivePattern =
    /\b(CREATE_AUTHORIZED_RECOVERY_PATH|recovery objective|create authorized recovery path|owner[- ]approved recovery)\b/i;
  const stopBecauseMissingPattern =
    /\b(stop|blocked|halt|cannot proceed|do not continue|terminal stop)\b[\s\S]{0,160}\b(missing|no path|path is missing|authorized path missing)\b/i;
  const denialAsSchemaPattern =
    /\b(denial label|denial labels)\b[\s\S]{0,160}\b(schema|capability authority|capability manifest|ruleset schema|derive schema|infer schema|authorized because)\b/i;
  const getRulesetRecoveryPattern =
    /\b(getRuleset|ruleset recovery|ruleset authority)\b[\s\S]{0,160}\b(recover|patch|create|route|authorize|authority path)\b/i;
  const ownerEnvelopeSafePattern =
    /\b(owner[- ]approved recovery envelope|OWNER_RECOVERY_ENVELOPE|authorized recovery envelope|envelope valid|owner authorized)\b/i;

  const documentHasConfirmedMissing = confirmedMissingPattern.test(text);
  const documentHasRecoveryObjective = recoveryObjectivePattern.test(text);

  for (const segment of segments) {
    const hasConfirmedMissing = confirmedMissingPattern.test(segment) || documentHasConfirmedMissing;
    const hasRecoveryObjective = recoveryObjectivePattern.test(segment) || documentHasRecoveryObjective;

    if (hasConfirmedMissing && rediscoveryPattern.test(segment)) {
      count += 1;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "KPL_REDISCOVERY_FORBIDDEN",
        "BLOCK",
        buildExcerpt(segment, segment.slice(0, 120)),
        "Known Precondition Ledger says the Denial/getRuleset authorized path is already confirmed missing. Rediscovering or checking whether that path exists is forbidden; the product must preserve the state as RECOVERY_REQUIRED."
      );
    }

    if (hasConfirmedMissing && hasRecoveryObjective && stopBecauseMissingPattern.test(segment)) {
      count += 1;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "KPL_OBJECTIVE_REVERSAL",
        "BLOCK",
        buildExcerpt(segment, segment.slice(0, 120)),
        "A confirmed missing authorized path with objective CREATE_AUTHORIZED_RECOVERY_PATH must be treated as RECOVERY_REQUIRED, not as a terminal stop or blocked objective."
      );
    }

    if (denialAsSchemaPattern.test(segment)) {
      count += 1;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "DENIAL_LABEL_USED_AS_SCHEMA_AUTHORITY",
        "BLOCK",
        buildExcerpt(segment, segment.slice(0, 120)),
        "Denial labels are evidence only. They must not be treated as schema, capability authority, or a source for deriving ruleset/getRuleset structure."
      );
    }

    if (getRulesetRecoveryPattern.test(segment) && !ownerEnvelopeSafePattern.test(segment)) {
      count += 1;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "GETRULESET_RECOVERY_WITHOUT_OWNER_ENVELOPE",
        "BLOCK",
        buildExcerpt(segment, segment.slice(0, 120)),
        "getRuleset authority recovery must be routed through an owner-approved recovery envelope; direct recovery without that envelope is not valid final-product behavior."
      );
    }
  }

  return count;
}
/**
 * FINAL_PRODUCT_NO_GUESSING_ALWAYS_VERIFY_GATE_V1
 *
 * Blocks assumption-based authority decisions:
 * - helper names and function signatures must be verified before mutation;
 * - required ZIP entries must come from compiler required surfaces;
 * - final product pass, upload-ready, and final ZIP status must come from explicit gate results;
 * - confirmed Known Precondition Ledger facts marked rediscoveryForbidden are preserved, not rechecked.
 */
/**
 * FINAL_PRODUCT_SOURCE_OF_TRUTH_DISCIPLINE_GATE_V1
 */
function checkSourceOfTruthDisciplineRequirements(text: string, findings: ReviewFinding[]): number {
  const segments = text.split(/\n\s*\n/).flatMap((s) => s.split(/(?<=[.;])\s+/)).map((s) => s.trim()).filter(Boolean);
  let count = 0;


  // SOURCE_OF_TRUTH_DOC_LEVEL_REDISCOVERY_V1
  if (
    /\b(?:ESTABLISHED_PRIOR_FACT|knownPrecondition|KNOWN_PRECONDITION|rediscoveryForbidden\s*=\s*true|rediscoveryForbidden=true)\b/i.test(text) &&
    /\b(?:re-verify|reverify|rediscover|re-discover|search\s+for|check\s+again|verify[\s\S]{0,60}existence)\b/i.test(text) &&
    !/\b(?:user\s+explicitly\s+(?:asked|requested)|explicit\s+user\s+request)\b/i.test(text)
  ) {
    count++;
    pushFinding(findings, "STATE_PHASE_BOUNDARY", "ESTABLISHED_PRIOR_FACT_REDISCOVERY_FORBIDDEN", "BLOCK", buildExcerpt(text, text.slice(0, 120)), "Established prior facts must be built on, not silently rediscovered.");
  }
  for (const segment of segments) {
    if (/\b(?:failure\s+label|denial\s+label|error\s+label|filename|displayed\s+hash|sandbox\s+artifact|assistant\s+claim)\b/i.test(segment) &&
        /\b(?:use|treat|derive|infer|accept)\b[\s\S]{0,120}\b(?:schema|source\s+of\s+truth|authority|provenance|contract|command)\b/i.test(segment) &&
        !/\b(?:read|verify|locate|verified|authoritative\s+source|primary\s+source|actual\s+(?:validator|compiler|contract))\b/i.test(segment)) {
      count++;
      pushFinding(findings, "EVIDENCE_CLAIM", "UNVERIFIED_APPEARANCE_USED_AS_SOURCE_OF_TRUTH", "BLOCK", buildExcerpt(segment, segment.slice(0, 120)), "Source-like appearances such as labels, filenames, hashes, sandbox artifacts, or assistant claims are pointers only, not source-of-truth authority.");
    }

    if (/\b(?:ESTABLISHED_PRIOR_FACT|knownPrecondition|KNOWN_PRECONDITION|rediscoveryForbidden\s*=\s*true|rediscoveryForbidden=true)\b/i.test(segment) &&
        /\b(?:re-verify|reverify|rediscover|re-discover|search\s+for|check\s+again|verify[\s\S]{0,60}existence)\b/i.test(segment) &&
        !/\b(?:user\s+explicitly\s+(?:asked|requested)|explicit\s+user\s+request)\b/i.test(segment)) {
      count++;
      pushFinding(findings, "STATE_PHASE_BOUNDARY", "ESTABLISHED_PRIOR_FACT_REDISCOVERY_FORBIDDEN", "BLOCK", buildExcerpt(segment, segment.slice(0, 120)), "Established prior facts must be built on, not silently rediscovered.");
    }

    if (/\breceipt\b/i.test(segment) && /\b(?:current|currently|now|live\s+state)\b/i.test(segment) && /\b(?:prove|proof|source\s+of\s+truth|authorized|safe)\b/i.test(segment)) {
      count++;
      pushFinding(findings, "EVIDENCE_CLAIM", "RECEIPT_PAST_DECISION_TREATED_AS_CURRENT_TRUTH", "BLOCK", buildExcerpt(segment, segment.slice(0, 120)), "A receipt is source-of-truth for a past decision, not proof of current state.");
    }
  }

  return count;
}

function checkNoGuessingAlwaysVerifyRequirements(text: string, findings: ReviewFinding[]): number {
  const segments = text
    .split(/\n\s*\n/)
    .flatMap((segment) => segment.split(/(?<=[.;])\s+/))
    .map((segment) => segment.trim())
    .filter(Boolean);

  let count = 0;
  const prohibitionPattern = /\b(?:NO_GUESSING_ALWAYS_VERIFY|ASSUMPTION_FORBIDDEN|VERIFY_BEFORE_DECISION|do not (?:infer|assume|guess)|must not (?:infer|assume|guess)|assumption is forbidden|verify before (?:decision|deciding|mutation|mutating))\b/i;
  const skipVerifyPattern = /\b(?:without (?:checking|verifying)|skip verification|no need to verify|do not verify)\b/i;
  const helperOrSignatureGuessPattern = /\b(?:assume|guess|infer|probably|likely|maybe|i think)\b[\s\S]{0,160}\b(?:helper|function signature|signature|addFinding|pushFinding)\b/i;
  const helperOrSignatureTargetFirstPattern = /\b(?:helper|function signature|signature|addFinding|pushFinding)\b[\s\S]{0,160}\b(?:assume|guess|infer|probably|likely|maybe|i think|without checking|without verifying)\b/i;
  const requiredZipEntryGuessPattern = /\b(?:assume|guess|infer|probably|likely|maybe|i think)\b[\s\S]{0,160}\b(?:required zip entry|zip entry|required entry|compiler required surface)\b/i;
  const requiredZipEntryTargetFirstPattern = /\b(?:required zip entry|zip entry|required entry|compiler required surface)\b[\s\S]{0,160}\b(?:assume|guess|infer|probably|likely|maybe|i think|without checking|without verifying|do not verify)\b/i;
  const finalStatusGuessPattern = /\b(?:final product pass|product pass|upload-ready|upload ready|final zip|final status)\b[\s\S]{0,180}\b(?:assume|guess|infer|probably|likely|maybe|looks complete|without checking|without verifying|no explicit gate|no gate result)\b/i;
  const authoritySurfaceGuessPattern = /\b(?:currentPhase|current phase|lock file|checker result|runner authority|compiler surface|script name|file name)\b[\s\S]{0,160}\b(?:assume|guess|infer|probably|likely|maybe|without checking|without verifying|do not verify)\b/i;

  for (const segment of segments) {
    const isNoGuessingContractStatement = prohibitionPattern.test(segment) && !skipVerifyPattern.test(segment);
    if (isNoGuessingContractStatement) {
      continue;
    }

    if (helperOrSignatureGuessPattern.test(segment) || helperOrSignatureTargetFirstPattern.test(segment)) {
      count += 1;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "HELPER_OR_SIGNATURE_GUESS_FORBIDDEN",
        "BLOCK",
        buildExcerpt(segment, segment.slice(0, 120)),
        "NO_GUESSING_ALWAYS_VERIFY requires helper names and function signatures to be verified before mutation; guessing addFinding/pushFinding or argument shape is forbidden."
      );
    }

    if (requiredZipEntryGuessPattern.test(segment) || requiredZipEntryTargetFirstPattern.test(segment)) {
      count += 1;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "REQUIRED_ZIP_ENTRY_GUESS_FORBIDDEN",
        "BLOCK",
        buildExcerpt(segment, segment.slice(0, 120)),
        "NO_GUESSING_ALWAYS_VERIFY requires required ZIP entries to be confirmed from the compiler required surface before declaring a ZIP defect."
      );
    }

    if (finalStatusGuessPattern.test(segment)) {
      count += 1;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "FINAL_STATUS_GUESS_FORBIDDEN",
        "BLOCK",
        buildExcerpt(segment, segment.slice(0, 120)),
        "NO_GUESSING_ALWAYS_VERIFY requires final product pass, upload-ready, and final ZIP status to come only from explicit gate results."
      );
    }

    if (authoritySurfaceGuessPattern.test(segment)) {
      count += 1;
      pushFinding(
        findings,
        "STATE_PHASE_BOUNDARY",
        "AUTHORITY_SURFACE_GUESS_FORBIDDEN",
        "BLOCK",
        buildExcerpt(segment, segment.slice(0, 120)),
        "NO_GUESSING_ALWAYS_VERIFY requires authority surfaces such as currentPhase, lock files, scripts, checkers, runner authority, and compiler surfaces to be verified before decision or mutation."
      );
    }
  }

  return count;
}

export function reviewAiComplianceText(input: string): ReviewResult {
  const text = input ?? "";
  const trimmed = text.trim();

  if (trimmed.length === 0) {
    return {
      classification: "SAFE_TO_RUN",
      findings: [],
      checkedSubGates: [],
      isEmpty: true,
    };
  }

  const findings: ReviewFinding[] = [];

  // Command Output Contract Gate
  const commandLikeBlocks = extractCommandLikeBlocks(text);
  checkExecutableAiOutputRequiresActionEnvelopeOrDevContract(text, commandLikeBlocks, findings);
  for (const block of commandLikeBlocks) {
    checkCommandOutputContract(block, findings);
    checkComplexCommandContract(block, findings);
  }

  // Manual Action Contract Gate
  checkManualActionContract(text, findings);

  // Evidence Claim Gate
  checkEvidenceClaim(text, findings);

  // State / Phase Boundary Gate
  checkStatePhaseBoundary(text, findings);

  // Restore / Recovery Reporting Gate
  checkRestoreRecoveryReporting(text, findings);

  checkHandoffZipArtifactIdentityContract(text, findings);

  checkSafetyKernelV31RuntimeAuthorityConstraints(text, findings);
  const knownPreconditionLedgerDenialGetRulesetCount = checkKnownPreconditionLedgerAndDenialGetRulesetRequirements(text, findings);
  checkSourceOfTruthDisciplineRequirements(text, findings);
  checkNoGuessingAlwaysVerifyRequirements(text, findings);

  // Product Scope Collapse detection (feeds Repeat Violation Gate)
  const productScopeCollapseCount = checkProductScopeCollapse(text, findings);
  const handoffCapsuleIngestionCount = checkSelfDescribingHandoffCapsuleIngestionRules(text, findings);

  // Repeat Violation Gate (post-pass over all findings collected above)
  applyRepeatViolationGate(text, findings, productScopeCollapseCount);

  // COMMAND_CONTRACT_REQUIRED compatibility normalizer.
  // Accepts the canonical underscore form used by the command contract.
  const hasCanonicalCommandContractRequiredHeader = /\bCOMMAND_CONTRACT_REQUIRED\s*[:=]\s*True\b/i.test(text);
  if (hasCanonicalCommandContractRequiredHeader) {
    for (let i = findings.length - 1; i >= 0; i -= 1) {
      const finding = findings[i];
      if (finding.ruleId === "MISSING_COMMAND_CONTRACT_REQUIRED_HEADER") {
        findings.splice(i, 1);
      }
    }
  }
  // Output Contract compatibility normalizer.
  // Accepts the clipboard-safe command style used by the project:
  // $lines/$result as a List<string>, Add-Line "KEY=VALUE", join to $out/$resultText,
  // Set-Clipboard, and short Write-Output markers telling the user to paste clipboard output.
  const hasListCollectorOutputContract =
    /\$(lines|result)\s*=\s*New-Object\s+System\.Collections\.Generic\.List\s*\[\s*string\s*\]/i.test(text) &&
    /function\s+Add-Line\s*\(/i.test(text) &&
    /Add-Line\s+["'][A-Z0-9_:-]+\s*=\s*[^"']+["']/i.test(text) &&
    /\$(out|resultText)\s*=\s*\$(lines|result)\s+-join\s+\[Environment\]::NewLine/i.test(text) &&
    /\$(out|resultText)\s*\|\s*Set-Clipboard/i.test(text) &&
    /Write-Output\s+["']CLIPBOARD_UPDATED=True["']/i.test(text) &&
    /Write-Output\s+["']PASTE_CLIPBOARD_OUTPUT_BACK_HERE=True["']/i.test(text);
  if (hasListCollectorOutputContract) {
    const outputCompatibilityRuleIds = new Set([
      "MISSING_RESULT_ARRAY_INITIALIZATION",
      "MISSING_RESULTTEXT_JOIN",
      "MISSING_RESULTTEXT_SET_CLIPBOARD",
      "MISSING_RESULTTEXT_FINAL_OUTPUT",
      "MISSING_MACHINE_CHECKABLE_KEY_VALUE_OUTPUT",
    ]);
    for (let i = findings.length - 1; i >= 0; i -= 1) {
      const finding = findings[i];
      if (outputCompatibilityRuleIds.has(finding.ruleId)) {
        findings.splice(i, 1);
      }
    }
  }
  let classification: ReviewClassification = "SAFE_TO_RUN";
  if (findings.some((f) => f.severity === "BLOCK")) {
    classification = "BLOCKED";
  } else if (findings.some((f) => f.severity === "WARNING")) {
    classification = "WARNING";
  }

  return {
    classification,
    findings,
    checkedSubGates: ALL_SUB_GATES,
    isEmpty: false,
  };
}





