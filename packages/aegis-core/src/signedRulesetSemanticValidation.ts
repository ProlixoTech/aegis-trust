export interface SignedRulesetMetadata {
  rulesetVersion: number;
  notBefore?: string;
  notAfter?: string;
  monotonicCounter?: number;
}

export interface SignedRulesetSemanticAssessment {
  accepted: boolean;
  reason: string | null;
}

export function assessSignedRulesetSemanticCandidate(
  active: SignedRulesetMetadata | null,
  candidate: SignedRulesetMetadata,
  nowEpochMs: number
): SignedRulesetSemanticAssessment {
  if (!Number.isFinite(nowEpochMs)) {
    return { accepted: false, reason: "current time is invalid" };
  }

  if (!Number.isInteger(candidate.rulesetVersion) || candidate.rulesetVersion < 0) {
    return { accepted: false, reason: "rulesetVersion is missing or invalid" };
  }

  if (!Number.isInteger(candidate.monotonicCounter) || candidate.monotonicCounter! < 0) {
    return { accepted: false, reason: "monotonicCounter is missing or invalid" };
  }

  if (typeof candidate.notBefore !== "string" || candidate.notBefore.trim() === "") {
    return { accepted: false, reason: "notBefore is missing" };
  }

  if (typeof candidate.notAfter !== "string" || candidate.notAfter.trim() === "") {
    return { accepted: false, reason: "notAfter is missing" };
  }

  const notBeforeMs = Date.parse(candidate.notBefore);
  const notAfterMs = Date.parse(candidate.notAfter);

  if (!Number.isFinite(notBeforeMs)) {
    return { accepted: false, reason: "notBefore is invalid" };
  }

  if (!Number.isFinite(notAfterMs)) {
    return { accepted: false, reason: "notAfter is invalid" };
  }

  if (notBeforeMs > nowEpochMs) {
    return { accepted: false, reason: "ruleset is not yet valid" };
  }

  if (notAfterMs <= nowEpochMs) {
    return { accepted: false, reason: "ruleset is expired" };
  }

  if (notAfterMs <= notBeforeMs) {
    return { accepted: false, reason: "ruleset validity window is invalid" };
  }

  if (active && candidate.rulesetVersion < active.rulesetVersion) {
    return { accepted: false, reason: "candidate rulesetVersion is older than active rulesetVersion" };
  }

  if (
    active &&
    typeof active.monotonicCounter === "number" &&
    Number.isInteger(active.monotonicCounter) &&
    candidate.monotonicCounter! < active.monotonicCounter
  ) {
    return { accepted: false, reason: "candidate monotonicCounter is older than active monotonicCounter" };
  }

  return { accepted: true, reason: null };
}