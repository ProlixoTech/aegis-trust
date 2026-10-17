import { evaluateActionQuality } from "../packages/aegis-core";
import { formatActionGateSection } from "../packages/aegis-core";
import type { ActionQualityResult } from "../packages/aegis-core";

export interface ProtectedTerminalMvp0Review {
  proposed: string;
  gateResult: ActionQualityResult;
  gateSection: string;
  sanitizedPreview: string;
  clipboardText: string;
  terminalHandoffBlocked: boolean;
  blockedMarkdown: string;
}

export interface ProtectedTerminalMvp0SnapshotPreflight {
  ok: boolean;
  snapshotCount: number;
  baselineRegistrationCount: number;
  skippedMissingCount: number;
  reasons: string[];
}

export function sanitizeProtectedTerminalMvp0Preview(proposed: string): string {
  return proposed.replace(/\s+/g, " ").replace(/(=)[^\s]+/g, "$1<redacted>").slice(0, 500);
}

export function buildProtectedTerminalMvp0ClipboardText(gateResult: ActionQualityResult): string {
  return [
    "=== AEGIS PROTECTED TERMINAL MVP-0 ===",
    "PROTECTED_TERMINAL_MVP0=True",
    "ACTION_QUALITY_GATE_STATUS=" + gateResult.status,
    "ACTION_QUALITY_GATE_RULE=" + gateResult.internalRuleId,
    "ACTION_QUALITY_GATE_SOURCE=" + gateResult.source,
    "ACTION_QUALITY_GATE_REASONS=" + gateResult.reasons.join("; "),
    "ACTION_QUALITY_GATE_NEXT_SAFE_STEP=" + (gateResult.nextSafeStep ?? ""),
    "COMMAND_NOT_EXECUTED_AUTOMATICALLY=True",
    "TERMINAL_HANDOFF_BLOCKED=" + String(gateResult.status !== "ALLOW"),
  ].join("\n");
}

export function buildProtectedTerminalMvp0BlockedMarkdown(
  gateResult: ActionQualityResult,
  gateSection: string,
  sanitizedPreview: string
): string {
  return [
    "# Aegis Protected Terminal MVP-0",
    "",
    gateSection,
    "",
    "## Sanitized command preview",
    "```",
    sanitizedPreview,
    "```",
    "",
    "## Decision",
    "- Terminal handoff: BLOCKED before insertion",
    "- Status: " + gateResult.status,
    "- Rule: " + gateResult.internalRuleId,
    "- Reasons: " + gateResult.reasons.join("; "),
    "- Next safe step: " + (gateResult.nextSafeStep ?? ""),
    "",
    "Command was blocked before terminal handoff.",
  ].join("\n");
}

export function evaluateProtectedTerminalMvp0Review(proposed: string): ProtectedTerminalMvp0Review {
  const gateResult = evaluateActionQuality(proposed, { source: "protected_terminal" });
  const gateSection = formatActionGateSection(gateResult);
  const sanitizedPreview = sanitizeProtectedTerminalMvp0Preview(proposed);
  const clipboardText = buildProtectedTerminalMvp0ClipboardText(gateResult);
  const terminalHandoffBlocked = gateResult.status !== "ALLOW";
  const blockedMarkdown = buildProtectedTerminalMvp0BlockedMarkdown(gateResult, gateSection, sanitizedPreview);

  return {
    proposed,
    gateResult,
    gateSection,
    sanitizedPreview,
    clipboardText,
    terminalHandoffBlocked,
    blockedMarkdown,
  };
}

export function buildProtectedTerminalMvp0AutosnapshotClipboardText(
  clipboardText: string,
  snapshotPreflight: ProtectedTerminalMvp0SnapshotPreflight
): string {
  return [
    clipboardText,
    "AUTOSNAPSHOT_PREFLIGHT_STATUS=" + (snapshotPreflight.ok ? "PASS" : "BLOCKED"),
    "AUTOSNAPSHOT_PREFLIGHT_SNAPSHOT_COUNT=" + String(snapshotPreflight.snapshotCount),
    "AUTOSNAPSHOT_PREFLIGHT_BASELINE_REGISTRATION_COUNT=" + String(snapshotPreflight.baselineRegistrationCount),
    "AUTOSNAPSHOT_PREFLIGHT_SKIPPED_MISSING_COUNT=" + String(snapshotPreflight.skippedMissingCount),
    "AUTOSNAPSHOT_PREFLIGHT_REASONS=" + snapshotPreflight.reasons.join("; "),
    "TERMINAL_HANDOFF_BLOCKED_BY_AUTOSNAPSHOT=" + String(!snapshotPreflight.ok),
  ].join("\n");
}

export function buildProtectedTerminalMvp0AutosnapshotBlockedMarkdown(
  snapshotPreflight: ProtectedTerminalMvp0SnapshotPreflight
): string {
  return [
    "# Aegis Protected Terminal AutoSnapshot",
    "",
    "## Decision",
    "- Terminal handoff: BLOCKED before insertion",
    "- Reason: " + snapshotPreflight.reasons.join("; "),
    "",
    "No command was inserted into the terminal.",
  ].join("\n");
}