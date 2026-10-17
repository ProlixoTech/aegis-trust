import {
  SafetyKernelV31AllowedExecutionAbortEvidence,
  SafetyKernelV31AllowedExecutionAbortReason,
  SafetyKernelV31AllowedExecutionCompletionBinding,
  SafetyKernelV31AllowedExecutionCompletionEvidence,
  SafetyKernelV31KernelDecision,
  SafetyKernelV31KernelDecisionResult,
  SafetyKernelV31WarnConfirmationEvidence,
  SafetyKernelV31WarnTerminalEvidence,
  SafetyKernelV31WarnTerminalEvidenceReason,
} from "./types";
import {
  SafetyKernelV31EvidenceIntegrityReport,
  SafetyKernelV31EvidenceWriteResult,
  SafetyKernelV31EvidenceWriter,
} from "./safetyKernelV31EvidenceWriter";
import {
  SafetyKernelV31LocalNonceIssueResult,
  issueSafetyKernelV31LocalNonce,
} from "./safetyKernelV31LocalNonceIssuer";
import {
  SafetyKernelV31NonceLifecycleRecord,
  abortSafetyKernelV31AllowedExecution,
  applySafetyKernelV31DecisionToNonce,
  completeSafetyKernelV31AllowedExecution,
  confirmSafetyKernelV31Warn,
  terminateSafetyKernelV31Warn,
} from "./safetyKernelV31NonceLifecyclePolicy";

export interface SafetyKernelV31NonceEvidencePort {
  appendDecision(
    result: SafetyKernelV31KernelDecisionResult,
    timestamp?: string
  ): Promise<SafetyKernelV31EvidenceWriteResult>;
  appendAllowedExecutionCompletion(
    evidence: SafetyKernelV31AllowedExecutionCompletionEvidence,
    timestamp?: string
  ): Promise<SafetyKernelV31EvidenceWriteResult>;
  appendAllowedExecutionAbort?(
    evidence: SafetyKernelV31AllowedExecutionAbortEvidence,
    timestamp?: string
  ): Promise<SafetyKernelV31EvidenceWriteResult>;
  appendWarnConfirmation(
    evidence: SafetyKernelV31WarnConfirmationEvidence,
    timestamp?: string
  ): Promise<SafetyKernelV31EvidenceWriteResult>;
  appendWarnTerminal(
    evidence: SafetyKernelV31WarnTerminalEvidence,
    timestamp?: string
  ): Promise<SafetyKernelV31EvidenceWriteResult>;
  verifyIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport>;
}

type SafetyKernelV31IssuedLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ISSUED" }>;
type SafetyKernelV31DecisionCommittedLifecycle = Exclude<SafetyKernelV31NonceLifecycleRecord, { phase: "ISSUED" | "CONSUMED" }>;
type SafetyKernelV31DecisionCommittedLifecycleFor<D extends SafetyKernelV31KernelDecision> =
  Extract<SafetyKernelV31DecisionCommittedLifecycle, { decision: D }>;
type SafetyKernelV31WarnPendingLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "WARN_PENDING" }>;
type SafetyKernelV31AllowPendingLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }>;
type SafetyKernelV31ConsumedAllowLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "ALLOW" };
type SafetyKernelV31ConsumedWarnLifecycle = Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "WARN" };
type SafetyKernelV31CommittedEvidence = Extract<SafetyKernelV31EvidenceWriteResult, { ok: true }>;
type SafetyKernelV31RejectedEvidence = Extract<SafetyKernelV31EvidenceWriteResult, { ok: false }>;

export type SafetyKernelV31NonceDecisionCommitResult<D extends SafetyKernelV31KernelDecision = SafetyKernelV31KernelDecision> =
  | { committed: false; lifecycle: SafetyKernelV31IssuedLifecycle; evidence: SafetyKernelV31RejectedEvidence }
  | { committed: true; lifecycle: SafetyKernelV31DecisionCommittedLifecycleFor<D>; evidence: SafetyKernelV31CommittedEvidence };

export type SafetyKernelV31NonceWarnConfirmationCommitResult =
  | { committed: false; lifecycle: SafetyKernelV31WarnPendingLifecycle; evidence: SafetyKernelV31RejectedEvidence }
  | { committed: true; lifecycle: SafetyKernelV31AllowPendingLifecycle; evidence: SafetyKernelV31CommittedEvidence };

export type SafetyKernelV31NonceAllowedExecutionCompletionCommitResult =
  | { committed: false; lifecycle: SafetyKernelV31AllowPendingLifecycle; evidence: SafetyKernelV31RejectedEvidence }
  | { committed: true; lifecycle: SafetyKernelV31ConsumedAllowLifecycle; evidence: SafetyKernelV31CommittedEvidence };

export type SafetyKernelV31NonceAllowedExecutionAbortCommitResult =
  | { committed: false; lifecycle: SafetyKernelV31AllowPendingLifecycle; evidence: SafetyKernelV31RejectedEvidence }
  | { committed: true; lifecycle: SafetyKernelV31ConsumedAllowLifecycle; evidence: SafetyKernelV31CommittedEvidence };

export type SafetyKernelV31NonceWarnTerminalCommitResult =
  | { committed: false; lifecycle: SafetyKernelV31WarnPendingLifecycle; evidence: SafetyKernelV31RejectedEvidence }
  | { committed: true; lifecycle: SafetyKernelV31ConsumedWarnLifecycle; evidence: SafetyKernelV31CommittedEvidence };

export type SafetyKernelV31NonceCommitResult =
  | SafetyKernelV31NonceDecisionCommitResult
  | SafetyKernelV31NonceWarnConfirmationCommitResult
  | SafetyKernelV31NonceAllowedExecutionCompletionCommitResult
  | SafetyKernelV31NonceAllowedExecutionAbortCommitResult
  | SafetyKernelV31NonceWarnTerminalCommitResult;

export const SAFETY_KERNEL_V31_NONCE_TRANSACTION_COORDINATOR_INVARIANT = {
  LOCAL_NONCE_ONLY: true,
  RAW_NONCE_PERSISTED: false,
  RAW_NONCE_LOGGED: false,
  EVIDENCE_REQUIRED_BEFORE_STATE_COMMIT: true,
  RUNTIME_CONNECTED: false,
  EXECUTION_AUTHORITY_GRANTED: false,
} as const;

function assertDecisionMatchesLifecycle(
  lifecycle: SafetyKernelV31NonceLifecycleRecord,
  result: SafetyKernelV31KernelDecisionResult
): void {
  if (result.action_id !== lifecycle.actionId) {
    throw new Error("ACTION_ID_MISMATCH");
  }

  if (result.approval_nonce !== lifecycle.approvalNonce) {
    throw new Error("APPROVAL_NONCE_MISMATCH");
  }
}

function assertIssuedLifecycle(
  lifecycle: SafetyKernelV31NonceLifecycleRecord
): asserts lifecycle is SafetyKernelV31IssuedLifecycle {
  if (lifecycle.phase !== "ISSUED" || lifecycle.nonceConsumed) {
    throw new Error("NONCE_NOT_ACTIVE");
  }
}

function assertWarnPendingLifecycle(
  lifecycle: SafetyKernelV31NonceLifecycleRecord
): asserts lifecycle is SafetyKernelV31WarnPendingLifecycle {
  if (
    lifecycle.phase !== "WARN_PENDING" ||
    lifecycle.decision !== "WARN" ||
    lifecycle.nonceConsumed
  ) {
    throw new Error("WARN_NOT_PENDING");
  }
}

function assertAllowPendingLifecycle(
  lifecycle: SafetyKernelV31NonceLifecycleRecord
): asserts lifecycle is SafetyKernelV31AllowPendingLifecycle {
  if (
    lifecycle.phase !== "ALLOW_PENDING_EXECUTION" ||
    lifecycle.decision !== "ALLOW" ||
    lifecycle.nonceConsumed
  ) {
    throw new Error("ALLOW_EXECUTION_NOT_PENDING");
  }
}

export class SafetyKernelV31NonceTransactionCoordinator {
  constructor(private readonly evidence: SafetyKernelV31NonceEvidencePort) {}

  static createForAegisDir(aegisDir: string): SafetyKernelV31NonceTransactionCoordinator {
    return new SafetyKernelV31NonceTransactionCoordinator(
      new SafetyKernelV31EvidenceWriter(aegisDir)
    );
  }

  issue(
    actionId: string,
    randomByteLength?: number
  ): SafetyKernelV31LocalNonceIssueResult {
    return issueSafetyKernelV31LocalNonce(actionId, randomByteLength);
  }

  async applyDecision(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    result: SafetyKernelV31KernelDecisionResult & { decision: "ALLOW" },
    warnTimeoutSeconds?: number,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceDecisionCommitResult<"ALLOW">>;
  async applyDecision(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    result: SafetyKernelV31KernelDecisionResult & { decision: "WARN" },
    warnTimeoutSeconds?: number,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceDecisionCommitResult<"WARN">>;
  async applyDecision(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    result: SafetyKernelV31KernelDecisionResult & { decision: "BLOCK" },
    warnTimeoutSeconds?: number,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceDecisionCommitResult<"BLOCK">>;
  async applyDecision(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    result: SafetyKernelV31KernelDecisionResult & { decision: "REQUIRE_REVIEW" },
    warnTimeoutSeconds?: number,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceDecisionCommitResult<"REQUIRE_REVIEW">>;
  async applyDecision(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    result: SafetyKernelV31KernelDecisionResult & { decision: "SPLIT_REQUIRED" },
    warnTimeoutSeconds?: number,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceDecisionCommitResult<"SPLIT_REQUIRED">>;
  async applyDecision(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    result: SafetyKernelV31KernelDecisionResult,
    warnTimeoutSeconds?: number,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceDecisionCommitResult>;
  async applyDecision(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    result: SafetyKernelV31KernelDecisionResult,
    warnTimeoutSeconds = 60,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceDecisionCommitResult> {
    assertDecisionMatchesLifecycle(lifecycle, result);
    assertIssuedLifecycle(lifecycle);

    const nextLifecycle = applySafetyKernelV31DecisionToNonce(
      lifecycle,
      result.decision,
      warnTimeoutSeconds
    );
    const evidence = await this.evidence.appendDecision(result, timestamp);
    if (!evidence.ok) return { committed: false, lifecycle, evidence };
    return { committed: true, lifecycle: nextLifecycle, evidence };
  }

  async confirmWarn(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceWarnConfirmationCommitResult> {
    assertWarnPendingLifecycle(lifecycle);
    const nextLifecycle = confirmSafetyKernelV31Warn(lifecycle);
    const evidence = await this.evidence.appendWarnConfirmation(
      {
        action_id: lifecycle.actionId,
        approval_nonce: lifecycle.approvalNonce,
        nonce_consumed: false,
        next_state: "ALLOW_PENDING_EXECUTION",
        receipt_required: true,
        ledger_required: true,
        execution_authority_granted: false,
      },
      timestamp
    );

    if (!evidence.ok) return { committed: false, lifecycle, evidence };
    return { committed: true, lifecycle: nextLifecycle, evidence };
  }

  async completeAllowedExecution(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    timestamp?: string,
    executionBinding?: SafetyKernelV31AllowedExecutionCompletionBinding
  ): Promise<SafetyKernelV31NonceAllowedExecutionCompletionCommitResult> {
    assertAllowPendingLifecycle(lifecycle);
    const nextLifecycle = completeSafetyKernelV31AllowedExecution(lifecycle);
    const evidence = await this.evidence.appendAllowedExecutionCompletion(
      {
        action_id: lifecycle.actionId,
        approval_nonce: lifecycle.approvalNonce,
        nonce_consumed: true,
        receipt_required: true,
        ledger_required: true,
        ...(executionBinding
          ? { execution_binding: executionBinding }
          : {}),
      },
      timestamp
    );

    if (!evidence.ok) return { committed: false, lifecycle, evidence };
    return { committed: true, lifecycle: nextLifecycle, evidence };
  }

  async abortAllowedExecution(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    reason: SafetyKernelV31AllowedExecutionAbortReason,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceAllowedExecutionAbortCommitResult> {
    assertAllowPendingLifecycle(lifecycle);

    if (!this.evidence.appendAllowedExecutionAbort) {
      throw new Error("ALLOWED_EXECUTION_ABORT_EVIDENCE_PORT_UNAVAILABLE");
    }

    const aborted =
      abortSafetyKernelV31AllowedExecution(lifecycle, reason);
    const evidence =
      await this.evidence.appendAllowedExecutionAbort(
        aborted.evidence,
        timestamp
      );

    if (!evidence.ok) {
      return { committed: false, lifecycle, evidence };
    }

    return {
      committed: true,
      lifecycle: aborted.lifecycle,
      evidence,
    };
  }

  async terminateWarn(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    reason: SafetyKernelV31WarnTerminalEvidenceReason,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceWarnTerminalCommitResult> {
    assertWarnPendingLifecycle(lifecycle);
    const terminal = terminateSafetyKernelV31Warn(lifecycle, reason);
    const evidence = await this.evidence.appendWarnTerminal(
      terminal.evidence,
      timestamp
    );

    if (!evidence.ok) return { committed: false, lifecycle, evidence };
    return { committed: true, lifecycle: terminal.lifecycle, evidence };
  }

  verifyEvidenceIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport> {
    return this.evidence.verifyIntegrity();
  }
}
