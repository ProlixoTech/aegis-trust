import type {
  SafetyKernelV31AllowedExecutionAbortReason,
  SafetyKernelV31AllowedExecutionCompletionBinding,
} from "./types";

import {
  ActionQualityResult,
  SafetyKernelV31ActionEnvelope,
  SafetyKernelV31CapabilityRequested,
  SafetyKernelV31KernelDecision,
  SafetyKernelV31KernelDecisionResult,
  SafetyKernelV31MutationScope,
  SafetyKernelV31RiskClass,
  SafetyKernelV31WarnTerminalEvidenceReason,
} from "./types";
import {
  buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality,
} from "../packages/aegis-core";
import {
  SafetyKernelV31LocalNonceIssueResult,
} from "./safetyKernelV31LocalNonceIssuer";
import {
  SafetyKernelV31NonceDecisionCommitResult,
  SafetyKernelV31NonceWarnTerminalCommitResult,
  SafetyKernelV31NonceTransactionCoordinator,
} from "../packages/aegis-core";
import { SafetyKernelV31NonceLifecycleRecord } from "./safetyKernelV31NonceLifecyclePolicy";

export interface SafetyKernelV31TransactionServiceInput {
  action_id: string;
  target: string;
  intent: string;
  proposed_action: string;
  context_hash: string;
  timestamp: string;
  adapter_id: string;
  policy_version: string;
  human_readable_summary: string;
  risk_class: SafetyKernelV31RiskClass;
  capability_requested: SafetyKernelV31CapabilityRequested;
  mutation_scope: SafetyKernelV31MutationScope;
}

interface SafetyKernelV31TransactionServiceResultBase {
  issued: SafetyKernelV31LocalNonceIssueResult;
  envelope: SafetyKernelV31ActionEnvelope;
}

type SafetyKernelV31TransactionDecisionResult<D extends SafetyKernelV31KernelDecision> =
  Omit<SafetyKernelV31KernelDecisionResult, "decision"> & { decision: D };

type SafetyKernelV31TransactionDecisionCommitFailure =
  Extract<SafetyKernelV31NonceDecisionCommitResult, { committed: false }>;

type SafetyKernelV31TransactionDecisionCommitSuccess<P extends SafetyKernelV31NonceLifecycleRecord["phase"]> =
  Extract<SafetyKernelV31NonceDecisionCommitResult, { committed: true }> & {
    lifecycle: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: P }>;
  };

export type SafetyKernelV31TransactionServiceResult =
  SafetyKernelV31TransactionServiceResultBase &
    (
      | { decisionResult: SafetyKernelV31TransactionDecisionResult<"ALLOW">; commit: SafetyKernelV31TransactionDecisionCommitFailure | SafetyKernelV31TransactionDecisionCommitSuccess<"ALLOW_PENDING_EXECUTION"> }
      | { decisionResult: SafetyKernelV31TransactionDecisionResult<"WARN">; commit: SafetyKernelV31TransactionDecisionCommitFailure | SafetyKernelV31TransactionDecisionCommitSuccess<"WARN_PENDING"> }
      | { decisionResult: SafetyKernelV31TransactionDecisionResult<"BLOCK">; commit: SafetyKernelV31TransactionDecisionCommitFailure | SafetyKernelV31TransactionDecisionCommitSuccess<"BLOCKED"> }
      | { decisionResult: SafetyKernelV31TransactionDecisionResult<"REQUIRE_REVIEW">; commit: SafetyKernelV31TransactionDecisionCommitFailure | SafetyKernelV31TransactionDecisionCommitSuccess<"REQUIRE_REVIEW"> }
      | { decisionResult: SafetyKernelV31TransactionDecisionResult<"SPLIT_REQUIRED">; commit: SafetyKernelV31TransactionDecisionCommitFailure | SafetyKernelV31TransactionDecisionCommitSuccess<"SPLIT_REQUIRED"> }
    );

export const SAFETY_KERNEL_V31_TRANSACTION_SERVICE_INVARIANT = {
  LOCAL_NONCE_ONLY: true,
  ACTION_QUALITY_MAPPING_PRESERVED: true,
  LOCAL_WARN_POLICY_ALLOWED: true,
  WARN_MUST_NEVER_AUTO_PROCEED: true,
  EVIDENCE_REQUIRED_BEFORE_STATE_COMMIT: true,
  AUTOMATIC_EXECUTION_ALLOWED: false,
  RUNTIME_CONNECTED: false,
  EXECUTION_AUTHORITY_GRANTED: false,
} as const;

const SAFETY_KERNEL_V31_LOCAL_WARN_POLICY_REASON =
  "LOCAL_AI_CONNECTOR_LOW_RISK_EXECUTION_REQUIRES_USER_CONFIRMATION";

function shouldApplySafetyKernelV31WarnPolicy(
  envelope: SafetyKernelV31ActionEnvelope,
  actionQuality: ActionQualityResult,
  decisionResult: SafetyKernelV31KernelDecisionResult
): boolean {
  return (
    actionQuality.status === "ALLOW" &&
    decisionResult.decision === "ALLOW" &&
    envelope.source === "ai_connector" &&
    envelope.risk_class === "low" &&
    envelope.capability_requested.operation_class === "execute" &&
    envelope.capability_requested.scope === "workspace" &&
    envelope.capability_requested.manner === "requires_review" &&
    envelope.mutation_scope.scope === "workspace" &&
    envelope.mutation_scope.target === envelope.target &&
    envelope.mutation_scope.protected_target === false
  );
}

export class SafetyKernelV31TransactionService {
  constructor(
    private readonly coordinator: SafetyKernelV31NonceTransactionCoordinator
  ) {}

  static createForAegisDir(aegisDir: string): SafetyKernelV31TransactionService {
    return new SafetyKernelV31TransactionService(
      SafetyKernelV31NonceTransactionCoordinator.createForAegisDir(aegisDir)
    );
  }

  async reviewAndCommit(
    input: SafetyKernelV31TransactionServiceInput,
    actionQuality: ActionQualityResult
  ): Promise<SafetyKernelV31TransactionServiceResult> {
    const issued = this.coordinator.issue(input.action_id);
    const built = buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality(
      {
        ...input,
        approval_nonce: issued.approvalNonce,
      },
      actionQuality
    );
    const decisionResult: SafetyKernelV31KernelDecisionResult =
      shouldApplySafetyKernelV31WarnPolicy(
        built.envelope,
        actionQuality,
        built.decisionResult
      )
        ? {
            ...built.decisionResult,
            decision: "WARN",
            reasons: [
              ...built.decisionResult.reasons,
              SAFETY_KERNEL_V31_LOCAL_WARN_POLICY_REASON,
            ],
          }
        : built.decisionResult;
    if (decisionResult.decision === "ALLOW") {
      const narrowedDecisionResult: SafetyKernelV31TransactionDecisionResult<"ALLOW"> = { ...decisionResult, decision: "ALLOW" };
      const commit = await this.coordinator.applyDecision(issued.lifecycle, narrowedDecisionResult, undefined, input.timestamp);
      if (commit.committed && commit.lifecycle.phase !== "ALLOW_PENDING_EXECUTION") throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
      return { issued, envelope: built.envelope, decisionResult: narrowedDecisionResult, commit };
    }
    if (decisionResult.decision === "WARN") {
      const narrowedDecisionResult: SafetyKernelV31TransactionDecisionResult<"WARN"> = { ...decisionResult, decision: "WARN" };
      const commit = await this.coordinator.applyDecision(issued.lifecycle, narrowedDecisionResult, undefined, input.timestamp);
      if (commit.committed && commit.lifecycle.phase !== "WARN_PENDING") throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
      return { issued, envelope: built.envelope, decisionResult: narrowedDecisionResult, commit };
    }
    if (decisionResult.decision === "BLOCK") {
      const narrowedDecisionResult: SafetyKernelV31TransactionDecisionResult<"BLOCK"> = { ...decisionResult, decision: "BLOCK" };
      const commit = await this.coordinator.applyDecision(issued.lifecycle, narrowedDecisionResult, undefined, input.timestamp);
      if (commit.committed && commit.lifecycle.phase !== "BLOCKED") throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
      return { issued, envelope: built.envelope, decisionResult: narrowedDecisionResult, commit };
    }
    if (decisionResult.decision === "REQUIRE_REVIEW") {
      const narrowedDecisionResult: SafetyKernelV31TransactionDecisionResult<"REQUIRE_REVIEW"> = { ...decisionResult, decision: "REQUIRE_REVIEW" };
      const commit = await this.coordinator.applyDecision(issued.lifecycle, narrowedDecisionResult, undefined, input.timestamp);
      if (commit.committed && commit.lifecycle.phase !== "REQUIRE_REVIEW") throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
      return { issued, envelope: built.envelope, decisionResult: narrowedDecisionResult, commit };
    }
    if (decisionResult.decision !== "SPLIT_REQUIRED") {
      throw new Error("UNSUPPORTED_TRANSACTION_DECISION");
    }
    const narrowedDecisionResult: SafetyKernelV31TransactionDecisionResult<"SPLIT_REQUIRED"> = { ...decisionResult, decision: "SPLIT_REQUIRED" };
    const commit = await this.coordinator.applyDecision(issued.lifecycle, narrowedDecisionResult, undefined, input.timestamp);
    if (commit.committed && commit.lifecycle.phase !== "SPLIT_REQUIRED") throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
    return { issued, envelope: built.envelope, decisionResult: narrowedDecisionResult, commit };
  }

  async confirmWarn(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    timestamp?: string
  ) {
    return this.coordinator.confirmWarn(lifecycle, timestamp);
  }

  async completeAllowedExecution(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    timestamp?: string,
    executionBinding?: SafetyKernelV31AllowedExecutionCompletionBinding
  ) {
    return this.coordinator.completeAllowedExecution(
      lifecycle,
      timestamp,
      executionBinding
    );
  }

  abortAllowedExecution(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    reason: SafetyKernelV31AllowedExecutionAbortReason,
    timestamp?: string
  ) {
    return this.coordinator.abortAllowedExecution(
      lifecycle,
      reason,
      timestamp
    );
  }

  terminateWarn(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    reason: SafetyKernelV31WarnTerminalEvidenceReason,
    timestamp?: string
  ): Promise<SafetyKernelV31NonceWarnTerminalCommitResult> {
    return this.coordinator.terminateWarn(lifecycle, reason, timestamp);
  }
}
