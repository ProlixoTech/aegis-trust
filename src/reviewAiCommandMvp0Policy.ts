import { reviewAiComplianceText } from "../packages/aegis-core";
import type { ActionQualityResult } from "../packages/aegis-core";

export type ReviewAiCommandMvp0Classification = "SAFE_TO_RUN" | "WARNING" | "BLOCKED";
export type ReviewAiCommandMvp0InputSource = "selection" | "clipboard" | "input";

export interface ReviewAiCommandMvp0Finding {
  severity: "BLOCK" | "WARNING";
  code: string;
  explanation: string;
}

export interface ReviewAiCommandMvp0Result {
  classification: ReviewAiCommandMvp0Classification;
  findings: ReviewAiCommandMvp0Finding[];
  inputSource: ReviewAiCommandMvp0InputSource;
  sanitizedPreview: string;
  reviewedAtUtc: string;
}

export function sanitizeReviewAiCommandMvp0Text(raw: string): string {
  let sanitized = raw.replace(/\r\n/g, "\n");

  sanitized = sanitized.replace(
    /-----BEGIN [^-]+PRIVATE KEY-----[\s\S]*?-----END [^-]+PRIVATE KEY-----/gi,
    "[REDACTED PRIVATE KEY]"
  );

  sanitized = sanitized.replace(
    /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s`;&|]+)/gi,
    "$1=<redacted>"
  );

  sanitized = sanitized.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer <redacted>");
  sanitized = sanitized.replace(/\b[A-Za-z0-9_]{24,}\b/g, (match) => {
    const isAegisCommandContractToken =
      match === "COMMAND_CONTRACT_REQUIRED" ||
      match === "COMMAND_CONTRACT" ||
      match === "BOUNDARY" ||
      /^(READ_ONLY|SOURCE_EDIT_ONLY|CREATE_ONE|COMPILE_ONLY|NO_[A-Z0-9_]+|[A-Z0-9_]+_PASS|[A-Z0-9_]+_REGEN)[A-Z0-9_]*$/.test(match);

    return isAegisCommandContractToken ? match : "<redacted-token-like-value>";
  });

  if (sanitized.length > 3000) {
    sanitized = sanitized.substring(0, 3000) + "\n...[truncated for safe review display]";
  }

  return sanitized.replace(/```/g, "'''");
}

export function classifyReviewAiCommandMvp0Action(
  raw: string,
  inputSource: ReviewAiCommandMvp0InputSource,
  reviewedAtUtc = new Date().toISOString()
): ReviewAiCommandMvp0Result {
  const text = raw.replace(/\r\n/g, "\n");
  const pureResult = reviewAiComplianceText(text);

  return {
    classification: pureResult.classification as ReviewAiCommandMvp0Classification,
    findings: pureResult.findings.map((finding) => ({
      severity: finding.severity,
      code: finding.ruleId,
      explanation: `${finding.subGate}: ${finding.explanation}`,
    })),
    inputSource,
    sanitizedPreview: sanitizeReviewAiCommandMvp0Text(text),
    reviewedAtUtc,
  };
}

export function combineReviewAiCommandMvp0WithActionQuality(
  actionQuality: ActionQualityResult,
  review: ReviewAiCommandMvp0Result
): ActionQualityResult {
  if (actionQuality.status !== "ALLOW" || review.classification === "SAFE_TO_RUN") {
    return actionQuality;
  }

  const blocked = review.classification === "BLOCKED";
  const complianceReasons = review.findings.length > 0
    ? review.findings.map((finding) => `${finding.code}: ${finding.explanation}`)
    : [`AI Compliance Gate classification: ${review.classification}`];

  return {
    ...actionQuality,
    status: blocked ? "BLOCK" : "REVIEW_NEEDED",
    userMessage: blocked
      ? "AI Compliance Gate blocked this command or action."
      : "AI Compliance Gate requires human review for this command or action.",
    reasons: [...actionQuality.reasons, ...complianceReasons],
    nextSafeStep: blocked
      ? "Resolve the AI Compliance findings and submit a new review."
      : undefined,
    internalRuleId: blocked
      ? "AI_COMPLIANCE_BLOCKED"
      : "AI_COMPLIANCE_REVIEW_NEEDED",
  };
}

export function buildReviewAiCommandMvp0Markdown(result: ReviewAiCommandMvp0Result): string {
  const findingsText = result.findings.length === 0
    ? "- None detected by the MVP local rule set."
    : result.findings
      .map((finding) => `- ${finding.severity}: ${finding.code} - ${finding.explanation}`)
      .join("\n");

  return [
    "# Aegis AI Command / Action Review",
    "",
    `Classification: ${result.classification}`,
    `Input source: ${result.inputSource}`,
    `Reviewed at UTC: ${result.reviewedAtUtc}`,
    "",
    "## Findings",
    findingsText,
    "",
    "## Sanitized Preview",
    "",
    "```text",
    result.sanitizedPreview,
    "```",
    "",
    "## Reminder",
    "- This is a local MVP review, not a guarantee of safety.",
    "- Do not run BLOCKED commands.",
    "- For WARNING commands, correct the command contract before execution.",
  ].join("\n");
}

export function buildReviewAiCommandMvp0ClipboardText(result: ReviewAiCommandMvp0Result): string {
  const findingSummary = result.findings.length === 0
    ? "none"
    : result.findings.map((finding) => `${finding.severity}:${finding.code}`).join(", ");

  return [
    "=== AEGIS AI COMMAND REVIEW RESULT ===",
    `CLASSIFICATION=${result.classification}`,
    `INPUT_SOURCE=${result.inputSource}`,
    `FINDINGS=${findingSummary}`,
    `REVIEWED_AT_UTC=${result.reviewedAtUtc}`,
    "SANITIZED_PREVIEW_BEGIN",
    result.sanitizedPreview,
    "SANITIZED_PREVIEW_END",
  ].join("\n");
}