export const AI_EXECUTION_AUTHORITY_MVP0_CAPABILITY_ID =
  "ai_gateway_explicit_execution" as const;

export const AI_EXECUTION_AUTHORITY_MVP0_ACTION_KIND =
  "ai_execution_gateway_execute" as const;

export type AiExecutionAuthorityMvp0ReasonCode =
  | "DENY_INVALID_INPUT"
  | "DENY_REVIEW_ONLY_CAPABILITY"
  | "DENY_CAPABILITY_ID_MISMATCH"
  | "DENY_ACTION_KIND_MISMATCH"
  | "DENY_USER_EXECUTION_CONFIRMATION_REQUIRED"
  | "DENY_AUTOMATIC_EXECUTION_REQUESTED"
  | "DENY_RUNTIME_REVIEW_NOT_ALLOW"
  | "DENY_APPROVAL_NONCE_SHA256_INVALID"
  | "DENY_CURRENT_AUTHORITY_BINDING_UNAVAILABLE"
  | "GRANT_EXPLICIT_EXECUTION_AUTHORITY";

export interface AiExecutionAuthorityMvp0EvaluationInput {
  readonly capabilityId: string;
  readonly actionKind: string;
  readonly userExecutionConfirmed: boolean;
  readonly automaticExecutionRequested: boolean;
  readonly runtimeReviewStatus: string;
  readonly approvalNonceSha256: string;
  readonly currentAuthorityBindingAvailable: boolean;
}

export interface AiExecutionAuthorityMvp0EvaluationResult {
  readonly execution_authority_granted: boolean;
  readonly reason_code: AiExecutionAuthorityMvp0ReasonCode;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function deny(
  reasonCode: Exclude<
    AiExecutionAuthorityMvp0ReasonCode,
    "GRANT_EXPLICIT_EXECUTION_AUTHORITY"
  >
): AiExecutionAuthorityMvp0EvaluationResult {
  return Object.freeze({
    execution_authority_granted: false,
    reason_code: reasonCode,
  });
}

export function evaluateAiExecutionAuthorityMvp0(
  input: unknown
): AiExecutionAuthorityMvp0EvaluationResult {
  if (!isRecord(input)) {
    return deny("DENY_INVALID_INPUT");
  }

  if (input.capabilityId === "ai_gateway_review_only") {
    return deny("DENY_REVIEW_ONLY_CAPABILITY");
  }

  if (
    input.capabilityId !==
    AI_EXECUTION_AUTHORITY_MVP0_CAPABILITY_ID
  ) {
    return deny("DENY_CAPABILITY_ID_MISMATCH");
  }

  if (
    input.actionKind !==
    AI_EXECUTION_AUTHORITY_MVP0_ACTION_KIND
  ) {
    return deny("DENY_ACTION_KIND_MISMATCH");
  }

  if (input.userExecutionConfirmed !== true) {
    return deny(
      "DENY_USER_EXECUTION_CONFIRMATION_REQUIRED"
    );
  }

  if (input.automaticExecutionRequested !== false) {
    return deny("DENY_AUTOMATIC_EXECUTION_REQUESTED");
  }

  if (input.runtimeReviewStatus !== "ALLOW") {
    return deny("DENY_RUNTIME_REVIEW_NOT_ALLOW");
  }

  if (
    typeof input.approvalNonceSha256 !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(
      input.approvalNonceSha256
    )
  ) {
    return deny("DENY_APPROVAL_NONCE_SHA256_INVALID");
  }

  if (input.currentAuthorityBindingAvailable !== true) {
    return deny(
      "DENY_CURRENT_AUTHORITY_BINDING_UNAVAILABLE"
    );
  }

  return Object.freeze({
    execution_authority_granted: true,
    reason_code: "GRANT_EXPLICIT_EXECUTION_AUTHORITY",
  });
}