/**
 * actionQualityGateMessages.ts
 *
 * User-facing messages and review output formatting for the Action Quality Gate.
 *
 * formatActionGateSection(result) produces a Markdown section that is included
 * in the review output for ALL statuses (ALLOW, REVIEW_NEEDED, SPLIT_REQUIRED, BLOCK).
 *
 * FINAL_PRODUCT_REQUIREMENT_AI_CONNECTED_AEGIS=True
 * This module is caller-independent. The same formatted output is used regardless
 * of which caller path (VS Code command, Protected Terminal, AI Connector, etc.)
 * invoked the gate.
 */

import { ActionQualityResult, ActionGateStatus } from './types';

// Status display labels

const STATUS_LABELS: Record<ActionGateStatus, string> = {
  ALLOW: 'ALLOW',
  REVIEW_NEEDED: 'REVIEW NEEDED',
  SPLIT_REQUIRED: 'SPLIT REQUIRED',
  BLOCK: 'BLOCK',
};

const STATUS_DESCRIPTIONS: Record<ActionGateStatus, string> = {
  ALLOW:
    'This command passed the pre-execution gate and is cleared for the next review stage.',
  REVIEW_NEEDED:
    'This command requires review before execution. It was not clearly identified as safe or unsafe.',
  SPLIT_REQUIRED:
    'This command combines multiple distinct operations. Split it into separate steps before proceeding.',
  BLOCK:
    'This command was blocked by the pre-execution gate. Do not run it until the issue is resolved.',
};

// Per-rule user messages

export const RULE_MESSAGES: Record<string, { userMessage: string; nextSafeStep?: string }> = {
  SAFE_RUNNER_PATTERN: {
    userMessage:
      'This matches the safe Aegis runner + Set-Clipboard pattern and is cleared for the next review stage.',
  },
  REMOTE_SCRIPT_EXECUTION: {
    userMessage:
      'This command downloads and executes a remote script. Aegis blocks remote script execution before it reaches the terminal.',
    nextSafeStep:
      'Download the script file separately, inspect its full contents, then run it locally after verification.',
  },
  DESTRUCTIVE_FILE_OP: {
    userMessage:
      'This command performs a destructive file operation (delete, forced removal, or broad wipe). Explicit authorization is required.',
    nextSafeStep:
      'Run a read-only check first to confirm exactly what will be affected, then request explicit authorization for each target.',
  },
  DESTRUCTIVE_GIT: {
    userMessage:
      'This git command discards uncommitted changes and cannot be undone. Aegis blocks it until the safe baseline is confirmed.',
    nextSafeStep:
      "Run 'git status' and 'git diff' to review what would be lost, then create a snapshot before proceeding.",
  },
  BUILD_PACKAGE_INSTALL: {
    userMessage:
      'This command triggers a build, package, install, or deploy step. A verified baseline and explicit phase authorization are required.',
    nextSafeStep:
      'Confirm the identity invariant and all required gate checks pass, then request a dedicated build/deploy phase.',
  },
  STATE_CLAIM_RISK: {
    userMessage:
      'This command appears to claim a release, upload-ready, or deployment-ready state. Aegis requires verified evidence before allowing any release-state claim.',
    nextSafeStep:
      'Run the identity invariant check and all required checkers. A dedicated release gate must pass before any release-state claim is allowed.',
  },
  AI_ARTIFACT_CHANNEL_AUTHORITY: {
    userMessage:
      'This text appears to claim or expose an AI-created artifact, sandbox path, download link, sidecar file, or tool-created file. Aegis requires authorized provenance before treating such material as valid.',
    nextSafeStep:
      'Do not treat the artifact or link as valid handoff material. First verify authorized provenance, receipt, and independent evidence, or label it invalid.',
  },

  COMMAND_LENGTH: {
    userMessage:
      'This command is unusually long (over ~500 characters). Review it carefully to ensure it does not combine unintended operations.',
    nextSafeStep:
      'Break the command into shorter, clearly scoped pieces and submit each one individually.',
  },
  MIXED_PURPOSE: {
    userMessage:
      'This command combines multiple distinct operations in a single invocation. Aegis requires single-purpose commands.',
    nextSafeStep:
      'Run only the first operation and review its output completely before submitting the next step.',
  },
  SHORT_READ_ONLY: {
    userMessage:
      'This is a short, single-purpose read-only command and is cleared for the next review stage.',
  },
  DEFAULT_REVIEW_NEEDED: {
    userMessage:
      'This command could not be positively identified as safe. Review it before execution.',
    nextSafeStep:
      'Confirm the command is read-only, single-purpose, and does not trigger any build, mutation, or release step.',
  },
};

// AI-connected gateway note (required in all outputs)

const AI_CONNECTED_NOTE = `
> **Action Quality Gate** is an AI-connected pre-execution gateway.
> Manual clipboard/selection review is only an MVP fallback and diagnostic path.
> Future callers include Aegis Protected Terminal, AI Connector, and external execution bridge.
`.trim();

// Main formatter

/**
 * Formats an ActionQualityResult into a Markdown section for inclusion
 * in the review output document or clipboard summary.
 *
 * Included for ALL statuses: ALLOW, REVIEW_NEEDED, SPLIT_REQUIRED, BLOCK.
 */
export function formatActionGateSection(result: ActionQualityResult): string {
  const statusLabel = STATUS_LABELS[result.status];
  const statusDesc = STATUS_DESCRIPTIONS[result.status];

  const lines: string[] = [
    '## Action Quality Gate',
    '',
    `**Status:** ${statusLabel}`,
    `**Rule:** \`${result.internalRuleId}\``,
    `**Source:** \`${result.source}\``,
    '',
    `**Assessment:** ${statusDesc}`,
    '',
  ];

  if (result.reasons.length > 0) {
    lines.push('**Reasons:**');
    for (const reason of result.reasons) {
      lines.push(`- ${reason}`);
    }
    lines.push('');
  }

  if (result.detectedEffects.length > 0) {
    lines.push('**Detected Effects:**');
    for (const effect of result.detectedEffects) {
      lines.push(`- \`${effect.level}\` / \`${effect.kind}\` / ${effect.confidence}: ${effect.description}`);
    }
    lines.push('');
  }

  lines.push(`**Message:** ${result.userMessage}`);
  lines.push('');

  if (result.nextSafeStep) {
    lines.push(`**Next Safe Step:** ${result.nextSafeStep}`);
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(AI_CONNECTED_NOTE);
  lines.push('');

  return lines.join('\n');
}

/**
 * Produces a short plain-text clipboard summary line for quick reference.
 * Used when a full Markdown panel is not available.
 */
export function formatClipboardSummary(result: ActionQualityResult): string {
  const parts = [
    `ACTION_QUALITY_GATE_STATUS=${result.status}`,
    `RULE=${result.internalRuleId}`,
    `SOURCE=${result.source}`,
    `MESSAGE=${result.userMessage}`,
  ];
  if (result.detectedEffects.length > 0) {
    parts.push('DETECTED_EFFECTS_LEVEL=SYNTACTIC_LEVEL_1');
    parts.push(`DETECTED_EFFECTS=${result.detectedEffects.map((effect) => `${effect.kind}:${effect.confidence}`).join(';')}`);
  }
  if (result.nextSafeStep) {
    parts.push(`NEXT_SAFE_STEP=${result.nextSafeStep}`);
  }
  parts.push('AI_CONNECTED_GATEWAY=True');
  return parts.join('\n');
}
