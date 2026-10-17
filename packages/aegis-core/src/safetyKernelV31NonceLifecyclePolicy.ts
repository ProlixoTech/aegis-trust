import type {
  SafetyKernelV31AllowedExecutionAbortEvidence,
  SafetyKernelV31AllowedExecutionAbortReason,
} from "./types";

import type {
  SafetyKernelV31ApprovalNonce,
  SafetyKernelV31KernelDecision,
  SafetyKernelV31WarnTerminalEvidence,
  SafetyKernelV31WarnTerminalEvidenceReason,
} from "./types";

export type SafetyKernelV31NonceLifecyclePhase =
  | "ISSUED"
  | "ALLOW_PENDING_EXECUTION"
  | "WARN_PENDING"
  | "BLOCKED"
  | "REQUIRE_REVIEW"
  | "SPLIT_REQUIRED"
  | "CONSUMED";

interface SafetyKernelV31NonceLifecycleBase {
  actionId: string;
  approvalNonce: SafetyKernelV31ApprovalNonce;
  warnMustNeverAutoProceed: true;
  receiptRequired: true;
  ledgerRequired: true;
}

export type SafetyKernelV31NonceLifecycleRecord = SafetyKernelV31NonceLifecycleBase & (
  | { phase: "ISSUED"; decision: null; nonceConsumed: false; warnTimeoutSeconds?: never; parentEnvelopeInvalidated: false; childNoncesRequired: false }
  | { phase: "ALLOW_PENDING_EXECUTION"; decision: "ALLOW"; nonceConsumed: false; warnTimeoutSeconds?: never; parentEnvelopeInvalidated: false; childNoncesRequired: false }
  | { phase: "WARN_PENDING"; decision: "WARN"; nonceConsumed: false; warnTimeoutSeconds: number; parentEnvelopeInvalidated: false; childNoncesRequired: false }
  | { phase: "BLOCKED"; decision: "BLOCK"; nonceConsumed: true; warnTimeoutSeconds?: never; parentEnvelopeInvalidated: false; childNoncesRequired: false }
  | { phase: "REQUIRE_REVIEW"; decision: "REQUIRE_REVIEW"; nonceConsumed: true; warnTimeoutSeconds?: never; parentEnvelopeInvalidated: false; childNoncesRequired: false }
  | { phase: "SPLIT_REQUIRED"; decision: "SPLIT_REQUIRED"; nonceConsumed: true; warnTimeoutSeconds?: never; parentEnvelopeInvalidated: true; childNoncesRequired: true }
  | { phase: "CONSUMED"; decision: "ALLOW" | "WARN"; nonceConsumed: true; warnTimeoutSeconds?: never; parentEnvelopeInvalidated: false; childNoncesRequired: false }
);

type SafetyKernelV31IssuedLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ISSUED" }>;
type SafetyKernelV31DecisionCommittedLifecycle = Exclude<SafetyKernelV31NonceLifecycleRecord, { phase: "ISSUED" | "CONSUMED" }>;
type SafetyKernelV31AllowPendingLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }>;
type SafetyKernelV31WarnPendingLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "WARN_PENDING" }>;
type SafetyKernelV31ConsumedAllowLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "ALLOW" };
type SafetyKernelV31ConsumedWarnLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "WARN" };

export const SAFETY_KERNEL_V31_NONCE_LIFECYCLE_INVARIANT = {
  SIDE_EFFECT_FREE: true,
  RUNTIME_ENFORCED: false,
  NONCE_REUSE_ALLOWED: false,
  WARN_AUTO_PROCEED_ALLOWED: false,
  RECEIPT_REQUIRED: true,
  LEDGER_REQUIRED: true,
} as const;

function assertNonEmpty(value: string, error: string): void {
  if (!value.trim()) {
    throw new Error(error);
  }
}

function assertActiveIssued(
  record: SafetyKernelV31NonceLifecycleRecord
): asserts record is Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ISSUED" }> {
  if (record.phase !== "ISSUED" || record.nonceConsumed) {
    throw new Error("NONCE_NOT_ACTIVE");
  }
}

export function createSafetyKernelV31NonceLifecycle(
  actionId: string,
  approvalNonce: SafetyKernelV31ApprovalNonce
): SafetyKernelV31IssuedLifecycle {
  assertNonEmpty(actionId, "INVALID_ACTION_ID");
  assertNonEmpty(approvalNonce, "INVALID_APPROVAL_NONCE");

  return {
    actionId: actionId.trim(),
    approvalNonce: approvalNonce.trim(),
    phase: "ISSUED",
    decision: null,
    nonceConsumed: false,
    warnMustNeverAutoProceed: true,
    parentEnvelopeInvalidated: false,
    childNoncesRequired: false,
    receiptRequired: true,
    ledgerRequired: true,
  };
}

export function applySafetyKernelV31DecisionToNonce<D extends SafetyKernelV31KernelDecision>(
  record: SafetyKernelV31NonceLifecycleRecord,
  decision: D,
  warnTimeoutSeconds?: number
): Extract<SafetyKernelV31DecisionCommittedLifecycle, { decision: D }>;
export function applySafetyKernelV31DecisionToNonce(
  record: SafetyKernelV31NonceLifecycleRecord,
  decision: SafetyKernelV31KernelDecision,
  warnTimeoutSeconds = 60
): SafetyKernelV31DecisionCommittedLifecycle {
  assertActiveIssued(record);

  if (decision === "WARN") {
    if (!Number.isInteger(warnTimeoutSeconds) || warnTimeoutSeconds < 15 || warnTimeoutSeconds > 300) {
      throw new Error("INVALID_WARN_TIMEOUT");
    }

    return {
      ...record,
      phase: "WARN_PENDING",
      decision,
      warnTimeoutSeconds,
    };
  }

  if (decision === "ALLOW") {
    return {
      ...record,
      phase: "ALLOW_PENDING_EXECUTION",
      decision,
    };
  }

  if (decision === "BLOCK") {
    return {
      ...record,
      phase: "BLOCKED",
      decision,
      nonceConsumed: true,
    };
  }

  if (decision === "REQUIRE_REVIEW") {
    return {
      ...record,
      phase: "REQUIRE_REVIEW",
      decision,
      nonceConsumed: true,
    };
  }

  return {
    ...record,
    phase: "SPLIT_REQUIRED",
    decision,
    nonceConsumed: true,
    parentEnvelopeInvalidated: true,
    childNoncesRequired: true,
  };
}

export function confirmSafetyKernelV31Warn(
  record: SafetyKernelV31NonceLifecycleRecord
): SafetyKernelV31AllowPendingLifecycle {
  if (
    record.phase !== "WARN_PENDING" ||
    record.decision !== "WARN" ||
    record.nonceConsumed
  ) {
    throw new Error("WARN_NOT_PENDING");
  }

  const { warnTimeoutSeconds: _warnTimeoutSeconds, ...withoutTimeout } = record;

  return {
    ...withoutTimeout,
    phase: "ALLOW_PENDING_EXECUTION",
    decision: "ALLOW",
  };
}

export function completeSafetyKernelV31AllowedExecution(
  record: SafetyKernelV31NonceLifecycleRecord
): SafetyKernelV31ConsumedAllowLifecycle {
  if (
    record.phase !== "ALLOW_PENDING_EXECUTION" ||
    record.decision !== "ALLOW" ||
    record.nonceConsumed
  ) {
    throw new Error("ALLOW_EXECUTION_NOT_PENDING");
  }

  return {
    ...record,
    phase: "CONSUMED",
    nonceConsumed: true,
  };
}

export function abortSafetyKernelV31AllowedExecution(
  record: SafetyKernelV31NonceLifecycleRecord,
  reason: SafetyKernelV31AllowedExecutionAbortReason
): {
  lifecycle: SafetyKernelV31ConsumedAllowLifecycle;
  evidence: SafetyKernelV31AllowedExecutionAbortEvidence;
} {
  if (
    record.phase !== "ALLOW_PENDING_EXECUTION" ||
    record.decision !== "ALLOW" ||
    record.nonceConsumed
  ) {
    throw new Error("ALLOW_EXECUTION_NOT_PENDING");
  }

  if (
    reason !== "snapshot_failed" &&
    reason !== "authority_drift" &&
    reason !== "execution_failed" &&
    reason !== "cancel_by_user"
  ) {
    throw new Error("INVALID_ALLOWED_EXECUTION_ABORT_REASON");
  }

  return {
    lifecycle: {
      ...record,
      phase: "CONSUMED",
      nonceConsumed: true,
    },
    evidence: {
      action_id: record.actionId,
      approval_nonce: record.approvalNonce,
      reason,
      nonce_consumed: true,
      execution_completed: false,
      return_state: "IDLE",
      receipt_required: true,
      ledger_required: true,
    },
  };
}

export function terminateSafetyKernelV31Warn(
  record: SafetyKernelV31NonceLifecycleRecord,
  reason: SafetyKernelV31WarnTerminalEvidenceReason
): {
  lifecycle: SafetyKernelV31ConsumedWarnLifecycle;
  evidence: SafetyKernelV31WarnTerminalEvidence;
} {
  if (
    record.phase !== "WARN_PENDING" ||
    record.decision !== "WARN" ||
    record.nonceConsumed
  ) {
    throw new Error("WARN_NOT_PENDING");
  }

  const { warnTimeoutSeconds: _warnTimeoutSeconds, ...withoutTimeout } = record;

  return {
    lifecycle: {
      ...withoutTimeout,
      phase: "CONSUMED",
      nonceConsumed: true,
    },
    evidence: {
      action_id: record.actionId,
      approval_nonce: record.approvalNonce,
      reason,
      nonce_consumed: true,
      return_state: "IDLE",
      receipt_required: true,
      ledger_required: true,
      warn_must_never_auto_proceed: true,
    },
  };
}
