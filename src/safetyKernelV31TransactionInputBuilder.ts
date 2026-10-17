import {
  ActionGateStatus,
  ActionQualityResult,
  SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH,
  SafetyKernelV31CapabilityRequested,
  SafetyKernelV31MutationScope,
  SafetyKernelV31RiskClass,
} from "./types";
import {
  SafetyKernelV31TransactionServiceInput,
} from "../packages/aegis-core";

/**
 * SAFETY_KERNEL_V3_1_TRANSACTION_INPUT_BUILDER_V1
 *
 * Builds validated input for the local transaction service.
 * It does not issue nonces, write evidence, execute commands, call VS Code APIs,
 * or grant execution authority.
 */
export const SAFETY_KERNEL_V31_TRANSACTION_INPUT_BUILDER_INVARIANT = {
  SIDE_EFFECT_FREE: true,
  LOCAL_INPUT_ONLY: true,
  DIAGNOSTIC_PLACEHOLDER_ALLOWED: false,
  NONCE_ISSUED_BY_TRANSACTION_SERVICE: true,
  AUTOMATIC_EXECUTION_ALLOWED: false,
  RUNTIME_CONNECTED: false,
  EXECUTION_AUTHORITY_GRANTED: false,
} as const;

export interface SafetyKernelV31TransactionCallerContext {
  action_id: string;
  target: string;
  intent: string;
  proposed_action: string;
  context_hash: string;
  timestamp: string;
  adapter_id: string;
  policy_version: string;
  human_readable_summary: string;
  risk_class?: SafetyKernelV31RiskClass;
  capability_requested?: SafetyKernelV31CapabilityRequested;
  mutation_scope?: SafetyKernelV31MutationScope;
}

export interface SafetyKernelV31TransactionInputBuilderResult {
  transactionInput: SafetyKernelV31TransactionServiceInput;
  invariant: typeof SAFETY_KERNEL_V31_TRANSACTION_INPUT_BUILDER_INVARIANT;
}

function requiredInline(value: string, code: string): string {
  const cleaned = value
    .replace(/`/g, "'")
    .replace(/\r/g, " ")
    .replace(/\n/g, " ")
    .replace(/\t/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (!cleaned) {
    throw new Error(code);
  }

  return cleaned;
}

function requiredIsoTimestamp(value: string): string {
  const cleaned = requiredInline(value, "INVALID_TIMESTAMP");
  const iso = /^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;
  const match = iso.exec(cleaned);
  if (!match || !Number.isFinite(Date.parse(cleaned))) {
    throw new Error("INVALID_TIMESTAMP");
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth =
    month === 2 ? (leapYear ? 29 : 28) : [4, 6, 9, 11].includes(month) ? 30 : 31;
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth) {
    throw new Error("INVALID_TIMESTAMP");
  }

  return cleaned;
}

function requiredProposedAction(value: string): string {
  if (!value.trim()) {
    throw new Error("INVALID_PROPOSED_ACTION");
  }

  return value;
}

export function mapActionGateStatusToTransactionRiskClass(
  status: ActionGateStatus
): SafetyKernelV31RiskClass {
  switch (status) {
    case "ALLOW":
      return "low";
    case "REVIEW_NEEDED":
      return "medium";
    case "SPLIT_REQUIRED":
      return "high";
    case "BLOCK":
      return "critical";
    default: {
      const exhaustive: never = status;
      return exhaustive;
    }
  }
}

export function buildDefaultSafetyKernelV31TransactionCapability(): SafetyKernelV31CapabilityRequested {
  return {
    operation_class: "execute",
    scope: "workspace",
    manner: "requires_review",
  };
}

export function resolveSafetyKernelV31TransactionCapabilityForSource(
  source: ActionQualityResult["source"]
): SafetyKernelV31CapabilityRequested {
  const manifestEntry =
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH.trusted_capabilities.find(
      (entry) => entry.allowed_sources.includes(source)
    );
  if (!manifestEntry) {
    throw new Error("UNTRUSTED_ACTION_QUALITY_SOURCE");
  }
  return {
    operation_class: manifestEntry.operation_class,
    scope: manifestEntry.scope,
    manner: manifestEntry.manner,
  };
}

function isSameSafetyKernelV31TransactionCapability(
  left: SafetyKernelV31CapabilityRequested,
  right: SafetyKernelV31CapabilityRequested
): boolean {
  return (
    left.operation_class === right.operation_class &&
    left.scope === right.scope &&
    left.manner === right.manner
  );
}

export function buildDefaultSafetyKernelV31TransactionMutationScope(
  target: string,
  capability: SafetyKernelV31CapabilityRequested
): SafetyKernelV31MutationScope {
  return {
    scope: capability.scope,
    target,
    protected_target: capability.scope === "protected_file",
  };
}

export function buildSafetyKernelV31TransactionServiceInputFromCallerContext(
  caller: SafetyKernelV31TransactionCallerContext,
  actionQuality: ActionQualityResult
): SafetyKernelV31TransactionServiceInput {
  const target = requiredInline(caller.target, "INVALID_TARGET");
  const manifestCapability =
    resolveSafetyKernelV31TransactionCapabilityForSource(actionQuality.source);
  const capability = caller.capability_requested ?? manifestCapability;
  if (
    caller.capability_requested &&
    !isSameSafetyKernelV31TransactionCapability(
      caller.capability_requested,
      manifestCapability
    )
  ) {
    throw new Error("CAPABILITY_SOURCE_MISMATCH");
  }

  const mutationScope = caller.mutation_scope
    ? {
        ...caller.mutation_scope,
        target: requiredInline(
          caller.mutation_scope.target,
          "INVALID_MUTATION_SCOPE_TARGET"
        ),
      }
    : buildDefaultSafetyKernelV31TransactionMutationScope(target, capability);
  if (
    mutationScope.scope !== capability.scope ||
    mutationScope.target !== target ||
    mutationScope.protected_target !== (capability.scope === "protected_file")
  ) {
    throw new Error("MUTATION_SCOPE_MISMATCH");
  }

  return {
    action_id: requiredInline(caller.action_id, "INVALID_ACTION_ID"),
    target,
    intent: requiredInline(caller.intent, "INVALID_INTENT"),
    proposed_action: requiredProposedAction(caller.proposed_action),
    context_hash: requiredInline(caller.context_hash, "INVALID_CONTEXT_HASH"),
    timestamp: requiredIsoTimestamp(caller.timestamp),
    adapter_id: requiredInline(caller.adapter_id, "INVALID_ADAPTER_ID"),
    policy_version: requiredInline(caller.policy_version, "INVALID_POLICY_VERSION"),
    human_readable_summary: requiredInline(
      caller.human_readable_summary,
      "INVALID_HUMAN_READABLE_SUMMARY"
    ),
    risk_class:
      caller.risk_class ?? mapActionGateStatusToTransactionRiskClass(actionQuality.status),
    capability_requested: capability,
    mutation_scope: mutationScope,
  };
}

export function buildSafetyKernelV31TransactionInputBuilderResult(
  caller: SafetyKernelV31TransactionCallerContext,
  actionQuality: ActionQualityResult
): SafetyKernelV31TransactionInputBuilderResult {
  return {
    transactionInput: buildSafetyKernelV31TransactionServiceInputFromCallerContext(
      caller,
      actionQuality
    ),
    invariant: SAFETY_KERNEL_V31_TRANSACTION_INPUT_BUILDER_INVARIANT,
  };
}
