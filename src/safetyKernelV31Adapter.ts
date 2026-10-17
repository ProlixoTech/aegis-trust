import {
  ActionQualityResult,
  SafetyKernelV31ActionEnvelope,
  SafetyKernelV31ApprovalNonce,
  SafetyKernelV31CapabilityRequested,
  SafetyKernelV31KernelDecisionResult,
  SafetyKernelV31MutationScope,
  SafetyKernelV31RiskClass,
  bridgeActionQualityResultToSafetyKernelV31Decision,
} from "./types";

/**
 * SAFETY_KERNEL_V3_1_SIDE_EFFECT_FREE_ADAPTER_V1
 *
 * This module is intentionally side-effect free.
 *
 * It does not:
 * - execute commands,
 * - issue or consume nonces,
 * - create WARN pending-confirmation state,
 * - write receipts or ledger entries,
 * - create restore points,
 * - call VS Code APIs,
 * - decide targeted user actions from a server response.
 */
export const SAFETY_KERNEL_V31_ADAPTER_INVARIANT = {
  SIDE_EFFECT_FREE: true,
  RUNTIME_ENFORCED: false,
  NONCE_LIFECYCLE_IMPLEMENTED: false,
  WARN_TIMEOUT_IMPLEMENTED: false,
  RECEIPT_LEDGER_WRITE_IMPLEMENTED: false,
  EXTENSION_CALLER_CONNECTED: false,
  SERVER_TARGETED_DECISION_ALLOWED: false,
} as const;

export interface SafetyKernelV31EnvelopeAdapterInput {
  action_id: string;
  target: string;
  intent: string;
  proposed_action: string;
  context_hash: string;
  timestamp: string;
  adapter_id: string;
  approval_nonce: SafetyKernelV31ApprovalNonce;
  policy_version: string;
  human_readable_summary: string;
  risk_class: SafetyKernelV31RiskClass;
  capability_requested: SafetyKernelV31CapabilityRequested;
  mutation_scope: SafetyKernelV31MutationScope;
}

/**
 * Build a Safety Kernel v3.1 action envelope from explicit caller-provided
 * values plus the existing ActionQualityResult source.
 *
 * This helper performs no execution and does not grant authority.
 */
export function buildSafetyKernelV31ActionEnvelopeFromActionQuality(
  input: SafetyKernelV31EnvelopeAdapterInput,
  actionQuality: ActionQualityResult
): SafetyKernelV31ActionEnvelope {
  return {
    action_id: input.action_id,
    source: actionQuality.source,
    target: input.target,
    intent: input.intent,
    proposed_action: input.proposed_action,
    risk_class: input.risk_class,
    context_hash: input.context_hash,
    timestamp: input.timestamp,
    adapter_id: input.adapter_id,
    human_readable_summary: input.human_readable_summary,
    capability_requested: input.capability_requested,
    mutation_scope: input.mutation_scope,
    approval_nonce: input.approval_nonce,
    policy_version: input.policy_version,
  };
}

/**
 * Build a Safety Kernel v3.1 decision-result record from an envelope and
 * ActionQualityResult using the bridge-only mapping.
 *
 * WARN is never created here. Existing REVIEW_NEEDED maps to REQUIRE_REVIEW.
 * This is not a kernel transaction and does not consume or reuse a nonce.
 */
export function buildSafetyKernelV31DecisionResultFromActionQuality(
  envelope: SafetyKernelV31ActionEnvelope,
  actionQuality: ActionQualityResult
): SafetyKernelV31KernelDecisionResult {
  const bridge = bridgeActionQualityResultToSafetyKernelV31Decision(actionQuality);

  return {
    action_id: envelope.action_id,
    decision: bridge.kernel_decision,
    approval_nonce: envelope.approval_nonce,
    policy_version: envelope.policy_version,
    reasons: actionQuality.reasons,
    detectedEffects: bridge.detectedEffects,
    human_readable_summary: envelope.human_readable_summary,
    receipt_required: true,
    ledger_required: true,
  };
}

/**
 * Convenience helper for diagnostic-only callers that need both structures.
 */
export function buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality(
  input: SafetyKernelV31EnvelopeAdapterInput,
  actionQuality: ActionQualityResult
): {
  envelope: SafetyKernelV31ActionEnvelope;
  decisionResult: SafetyKernelV31KernelDecisionResult;
  adapterInvariant: typeof SAFETY_KERNEL_V31_ADAPTER_INVARIANT;
} {
  const envelope = buildSafetyKernelV31ActionEnvelopeFromActionQuality(input, actionQuality);
  const decisionResult = buildSafetyKernelV31DecisionResultFromActionQuality(envelope, actionQuality);

  return {
    envelope,
    decisionResult,
    adapterInvariant: SAFETY_KERNEL_V31_ADAPTER_INVARIANT,
  };
}