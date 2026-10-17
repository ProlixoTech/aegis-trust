import {
  AiExecutionAuthorityMvp0ReasonCode,
  evaluateAiExecutionAuthorityMvp0,
} from "./aiExecutionAuthorityMvp0Policy";

export const AI_EXECUTION_GATEWAY_EXPLICIT_EXECUTION_MVP0_CAPABILITY_ID =
  "ai_gateway_explicit_execution" as const;

export const AI_EXECUTION_GATEWAY_EXPLICIT_EXECUTION_MVP0_ACTION_KIND =
  "ai_execution_gateway_execute" as const;

export type AiExecutionGatewayExplicitExecutionMvp0CapabilityReason =
  | "NOT_READY_FOR_PRODUCT_ENTRY_CONNECTION"
  | "READY_FOR_PRODUCT_ENTRY_CONNECTION";

export interface AiExecutionGatewayExplicitExecutionMvp0CapabilityResult {
  readonly product_entrypoint_capability_ready: boolean;
  readonly execution_authority_granted: boolean;
  readonly authority_reason_code: AiExecutionAuthorityMvp0ReasonCode;
  readonly capability_reason_code:
    AiExecutionGatewayExplicitExecutionMvp0CapabilityReason;
}

function makeResult(
  productEntrypointCapabilityReady: boolean,
  executionAuthorityGranted: boolean,
  authorityReasonCode: AiExecutionAuthorityMvp0ReasonCode,
  capabilityReasonCode:
    AiExecutionGatewayExplicitExecutionMvp0CapabilityReason
): AiExecutionGatewayExplicitExecutionMvp0CapabilityResult {
  return Object.freeze({
    product_entrypoint_capability_ready:
      productEntrypointCapabilityReady,
    execution_authority_granted:
      executionAuthorityGranted,
    authority_reason_code:
      authorityReasonCode,
    capability_reason_code:
      capabilityReasonCode,
  });
}

export function evaluateAiExecutionGatewayExplicitExecutionMvp0Capability(
  input: unknown
): AiExecutionGatewayExplicitExecutionMvp0CapabilityResult {
  const authorityDecision =
    evaluateAiExecutionAuthorityMvp0(
      input
    );

  if (!authorityDecision.execution_authority_granted) {
    return makeResult(
      false,
      authorityDecision.execution_authority_granted,
      authorityDecision.reason_code,
      "NOT_READY_FOR_PRODUCT_ENTRY_CONNECTION"
    );
  }

  return makeResult(
    true,
    authorityDecision.execution_authority_granted,
    authorityDecision.reason_code,
    "READY_FOR_PRODUCT_ENTRY_CONNECTION"
  );
}