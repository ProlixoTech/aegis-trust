/**
 * actionQualityGate.ts
 *
 * Action Quality Gate - AI-connected pre-execution gateway engine.
 *
 * Primary export:
 *   evaluateActionQuality(rawText, options?) -> ActionQualityResult
 *
 * This is a caller-independent core engine. The same function is called by:
 *   - VS Code command UI          (MVP-0, source: "vscode_command")
 *   - Manual review / fallback    (MVP-0, source: "manual_review")
 *   - Aegis Protected Terminal    (future, source: "protected_terminal")
 *   - AI agent connector          (future, source: "ai_connector")
 *   - External AI execution bridge (future, source: "external_gateway")
 *
 * Gate ordering (same for all callers):
 *   Action Quality Gate -> AI Compliance Gate -> Output Contract Gate -> diagnostic output.
 *
 * FINAL_PRODUCT_REQUIREMENT_AI_CONNECTED_AEGIS=True
 * Manual clipboard/selection review is only an MVP fallback and diagnostic path.
 * Future callers include Aegis Protected Terminal, AI Connector, and external execution bridge.
 */

import { ActionQualityResult, ActionQualityOptions, ActionQualityCallerSource } from './types';
import { ORDERED_RULES, rule10DefaultReviewNeeded } from './actionQualityGateRules';

// Safety guard

function logActionQualityWarning(message: string): void {
  console.warn(message);
}

/**
 * Warns if a BLOCK or SPLIT_REQUIRED result is missing nextSafeStep.
 * nextSafeStep is always present in RULE_MESSAGES for these statuses,
 * but this guard catches any future rule additions that miss it.
 */
function guardNextSafeStep(result: ActionQualityResult): void {
  if (
    (result.status === 'BLOCK' || result.status === 'SPLIT_REQUIRED') &&
    !result.nextSafeStep
  ) {
    logActionQualityWarning(
      `[ActionQualityGate] Rule "${result.internalRuleId}" returned ${result.status} without nextSafeStep. ` +
        'Add nextSafeStep to RULE_MESSAGES for this rule.'
    );
  }
}

// Core engine

/**
 * Evaluates a raw command/action string against the Action Quality Gate rule set.
 *
 * @param rawText  - The command or action text to evaluate (selected text, terminal command, AI suggestion, etc.)
 * @param options  - Optional caller context. Defaults: source = "manual_review".
 * @returns        ActionQualityResult with status, message, reasons, and optional nextSafeStep.
 *
 * Rule evaluation stops at the first match (first-match-wins).
 * Unknown commands default to REVIEW_NEEDED (never DEFAULT_ALLOW).
 */
export function evaluateActionQuality(
  rawText: string,
  options?: ActionQualityOptions
): ActionQualityResult {
  const source: ActionQualityCallerSource = options?.source ?? 'manual_review';

  // Empty input -> REVIEW_NEEDED
  if (!rawText || rawText.trim().length === 0) {
    const result = rule10DefaultReviewNeeded('', source);
    result.reasons = ['Empty or whitespace-only input'];
    return result;
  }

  // Evaluate rules in order, stop at first match
  for (const rule of ORDERED_RULES) {
    const result = rule(rawText, source);
    if (result !== null) {
      guardNextSafeStep(result);
      return result;
    }
  }

  // RULE 10: default -> unknown command -> REVIEW_NEEDED
  const defaultResult = rule10DefaultReviewNeeded(rawText, source);
  guardNextSafeStep(defaultResult);
  return defaultResult;
}
