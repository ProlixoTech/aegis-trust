import {
  ActionQualityResult,
  SafetyKernelV31AllowedExecutionAbortReason,
  SafetyKernelV31AllowedExecutionCompletionBinding,
  SafetyKernelV31WarnTerminalEvidenceReason,
} from "./types";
import {
  SafetyKernelV31TransactionCallerContext,
  SafetyKernelV31TransactionInputBuilderResult,
  buildSafetyKernelV31TransactionInputBuilderResult,
} from "./safetyKernelV31TransactionInputBuilder";
import {
  SafetyKernelV31TransactionService,
  SafetyKernelV31TransactionServiceInput,
} from "../packages/aegis-core";
import {
  SafetyKernelV31TransactionOutputResult,
  formatSafetyKernelV31TransactionOutput,
} from "./safetyKernelV31TransactionOutput";
import type { SafetyKernelV31TransactionPublicRecord } from "./safetyKernelV31TransactionOutput";
import type { SafetyKernelV31NonceLifecycleRecord } from "./safetyKernelV31NonceLifecyclePolicy";
import {
  SafetyKernelV31PostReviewLifecycleOutputResultForEvent,
  formatSafetyKernelV31PostReviewLifecycleOutput,
} from "./safetyKernelV31PostReviewLifecycleOutput";
import {
  SafetyKernelV31TransactionSessionPublicRecord,
  SafetyKernelV31TransactionSessionStore,
} from "../packages/aegis-core";
import {
  SafetyKernelV31AllowedExecutionSessionBindingStore,
} from "../packages/aegis-core";
import type {
  SafetyKernelV31AllowedExecutionAuthorityBindingInput,
  SafetyKernelV31AllowedExecutionSessionBoundBinding,
} from "../packages/aegis-core";

/**
 * SAFETY_KERNEL_V3_1_TRANSACTION_REVIEW_PIPELINE_V1
 *
 * Combines validated transaction input, local nonce transaction review,
 * evidence-first lifecycle commit, and nonce-safe public output.
 *
 * Default construction does not execute commands, call VS Code APIs, expose
 * raw approval nonces, connect itself to extension runtime paths, or grant
 * execution authority. Coordinated execution is available only through
 * explicitly injected detached dependencies.
 */
export const SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT = {
  INPUT_BUILDER_REQUIRED: true,
  LOCAL_NONCE_TRANSACTION_REQUIRED: true,
  EVIDENCE_FIRST_COMMIT_REQUIRED: true,
  POST_REVIEW_LIFECYCLE_OUTPUT_REQUIRED: true,
  TRANSACTION_SESSION_STORE_REQUIRED: true,
  DETACHED_ALLOWED_EXECUTION_COORDINATOR_INJECTION_REQUIRED: true,
  SESSION_BINDING_STORE_REQUIRED_FOR_COORDINATED_EXECUTION: true,
  LEGACY_COMPLETION_PATH_REPLACED: false,
  RAW_APPROVAL_NONCE_EXPOSED: false,
  AUTOMATIC_EXECUTION_ALLOWED: false,
  RUNTIME_CONNECTED: false,
  EXECUTION_AUTHORITY_GRANTED: false,
} as const;

interface SafetyKernelV31TransactionReviewPipelineResultBase {
  transactionInput: SafetyKernelV31TransactionServiceInput;
  invariant: typeof SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT;
}

type SafetyKernelV31TransactionReviewOutput<D extends SafetyKernelV31TransactionPublicRecord["decision"]> =
  Omit<SafetyKernelV31TransactionOutputResult, "record"> & {
    record: Extract<SafetyKernelV31TransactionPublicRecord, { decision: D }>;
  };

type SafetyKernelV31TransactionReviewSession<P extends SafetyKernelV31TransactionSessionPublicRecord["lifecyclePhase"]> =
  Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: P }>;

type SafetyKernelV31TransactionReviewServiceResult = Awaited<
  ReturnType<SafetyKernelV31TransactionService["reviewAndCommit"]>
>;

function isSafetyKernelV31TransactionReviewDecision<
  D extends SafetyKernelV31TransactionPublicRecord["decision"]
>(
  result: SafetyKernelV31TransactionReviewServiceResult,
  decision: D
): result is Extract<
  SafetyKernelV31TransactionReviewServiceResult,
  { decisionResult: { decision: D } }
> {
  return result.decisionResult.decision === decision;
}

export type SafetyKernelV31TransactionReviewPipelineResult =
  SafetyKernelV31TransactionReviewPipelineResultBase &
    (
      | { output: SafetyKernelV31TransactionReviewOutput<"ALLOW">; session: SafetyKernelV31TransactionReviewSession<"ALLOW_PENDING_EXECUTION"> }
      | { output: SafetyKernelV31TransactionReviewOutput<"WARN">; session: SafetyKernelV31TransactionReviewSession<"WARN_PENDING"> }
      | { output: SafetyKernelV31TransactionReviewOutput<"BLOCK">; session: null }
      | { output: SafetyKernelV31TransactionReviewOutput<"REQUIRE_REVIEW">; session: null }
      | { output: SafetyKernelV31TransactionReviewOutput<"SPLIT_REQUIRED">; session: null }
    );

export type SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult = {
  session: SafetyKernelV31TransactionReviewSession<"ALLOW_PENDING_EXECUTION">;
  output: SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"WARN_CONFIRMED">;
};

export type SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult = {
  session: SafetyKernelV31TransactionReviewSession<"CONSUMED">;
  output: SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"ALLOWED_EXECUTION_COMPLETED">;
};

export type SafetyKernelV31TransactionReviewPipelineAllowedAbortSessionResult = {
  session: SafetyKernelV31TransactionReviewSession<"CONSUMED">;
  reason: SafetyKernelV31AllowedExecutionAbortReason;
  evidenceCommitted: true;
};

export type SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult = {
  session: SafetyKernelV31TransactionReviewSession<"CONSUMED">;
  output: SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"WARN_TERMINATED">;
};

export type SafetyKernelV31TransactionReviewPipelinePostReviewSessionResult =
  | SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult
  | SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult
  | SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult;

interface SafetyKernelV31TransactionReviewPipelineExecutionOutputSummary {
  readonly stdoutSha256: string;
  readonly stderrSha256: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
}

type SafetyKernelV31TransactionReviewPipelineCoordinationResult =
  | {
      readonly status: "completion_candidate";
      readonly sessionId: string;
      readonly actionId: string;
      readonly commandSha256: string;
      readonly snapshotBindingSha256: string;
      readonly authorityRevision: number;
      readonly exitCode: 0;
      readonly output:
        SafetyKernelV31TransactionReviewPipelineExecutionOutputSummary;
    }
  | {
      readonly status: "abort_candidate";
      readonly sessionId: string;
      readonly actionId: string;
      readonly reason:
        SafetyKernelV31AllowedExecutionAbortReason;
      readonly executionErrorCode?:
        | "EXECUTION_START_FAILED"
        | "EXECUTION_OBSERVATION_FAILED";
      readonly exitCode?: number;
      readonly output?:
        SafetyKernelV31TransactionReviewPipelineExecutionOutputSummary;
    }
  | {
      readonly status: "rejected";
      readonly sessionId: string;
      readonly code:
        "EXECUTION_SESSION_ALREADY_CLAIMED";
    };

export interface SafetyKernelV31TransactionReviewPipelineAllowedExecutionCoordinationPort {
  executeAllowed(
    request: ReturnType<
      SafetyKernelV31AllowedExecutionSessionBindingStore["getExecutionRequest"]
    >
  ): Promise<
    SafetyKernelV31TransactionReviewPipelineCoordinationResult
  >;
}

export type SafetyKernelV31TransactionReviewPipelineCoordinatedExecutionSessionResult =
  | {
      status: "completed";
      session:
        SafetyKernelV31TransactionReviewSession<"CONSUMED">;
      output:
        SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"ALLOWED_EXECUTION_COMPLETED">;
    }
  | {
      status: "aborted";
      session:
        SafetyKernelV31TransactionReviewSession<"CONSUMED">;
      reason:
        SafetyKernelV31AllowedExecutionAbortReason;
      evidenceCommitted: true;
    }
  | {
      status: "rejected";
      sessionId: string;
      code:
        "EXECUTION_SESSION_ALREADY_CLAIMED";
    };

export class SafetyKernelV31TransactionReviewPipeline {
  constructor(
    private readonly transactionService: SafetyKernelV31TransactionService,
    private readonly transactionSessionStore: SafetyKernelV31TransactionSessionStore,
    private readonly allowedExecutionBindingStore:
      SafetyKernelV31AllowedExecutionSessionBindingStore | null = null,
    private readonly allowedExecutionCoordinator:
      SafetyKernelV31TransactionReviewPipelineAllowedExecutionCoordinationPort | null = null
  ) {
    if (
      this.allowedExecutionCoordinator !== null &&
      this.allowedExecutionBindingStore === null
    ) {
      throw new Error(
        "ALLOWED_EXECUTION_BINDING_STORE_REQUIRED"
      );
    }
  }

  static createForAegisDir(
    aegisDir: string
  ): SafetyKernelV31TransactionReviewPipeline {
    return new SafetyKernelV31TransactionReviewPipeline(
      SafetyKernelV31TransactionService.createForAegisDir(aegisDir),
      new SafetyKernelV31TransactionSessionStore()
    );
  }

  async review(
    caller: SafetyKernelV31TransactionCallerContext,
    actionQuality: ActionQualityResult
  ): Promise<SafetyKernelV31TransactionReviewPipelineResult> {
    const built: SafetyKernelV31TransactionInputBuilderResult =
      buildSafetyKernelV31TransactionInputBuilderResult(caller, actionQuality);
    const transactionResult = await this.transactionService.reviewAndCommit(
      built.transactionInput,
      actionQuality
    );
    if (!transactionResult.commit.committed) throw new Error("DECISION_EVIDENCE_NOT_COMMITTED");
    if (isSafetyKernelV31TransactionReviewDecision(transactionResult, "ALLOW")) {
      const output = formatSafetyKernelV31TransactionOutput(transactionResult);
      const session = this.transactionSessionStore.create(transactionResult.commit.lifecycle);
      this.registerReviewedCommandForSession(
        session,
        transactionResult.commit.lifecycle,
        built.transactionInput.proposed_action
      );
      return { transactionInput: built.transactionInput, output, session, invariant: SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT };
    }
    if (isSafetyKernelV31TransactionReviewDecision(transactionResult, "WARN")) {
      const output = formatSafetyKernelV31TransactionOutput(transactionResult);
      const session = this.transactionSessionStore.create(transactionResult.commit.lifecycle);
      this.registerReviewedCommandForSession(
        session,
        transactionResult.commit.lifecycle,
        built.transactionInput.proposed_action
      );
      return { transactionInput: built.transactionInput, output, session, invariant: SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT };
    }
    if (isSafetyKernelV31TransactionReviewDecision(transactionResult, "BLOCK")) {
      const output = formatSafetyKernelV31TransactionOutput(transactionResult);
      return { transactionInput: built.transactionInput, output, session: null, invariant: SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT };
    }
    if (isSafetyKernelV31TransactionReviewDecision(transactionResult, "REQUIRE_REVIEW")) {
      const output = formatSafetyKernelV31TransactionOutput(transactionResult);
      return { transactionInput: built.transactionInput, output, session: null, invariant: SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT };
    }
    if (isSafetyKernelV31TransactionReviewDecision(transactionResult, "SPLIT_REQUIRED")) {
      const output = formatSafetyKernelV31TransactionOutput(transactionResult);
      return { transactionInput: built.transactionInput, output, session: null, invariant: SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT };
    }
    throw new Error("UNREACHABLE_TRANSACTION_DECISION");
  }

  private registerReviewedCommandForSession(
    session: SafetyKernelV31TransactionSessionPublicRecord,
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    commandText: string
  ): void {
    if (!this.allowedExecutionBindingStore) {
      return;
    }

    try {
      this.allowedExecutionBindingStore.registerReviewedCommand({
        sessionId: session.sessionId,
        actionId: lifecycle.actionId,
        approvalNonceSha256:
          "sha256:" + session.approvalNonceSha256,
        commandText,
      });
    } catch (error) {
      this.transactionSessionStore.delete(session.sessionId);
      throw error;
    }
  }

  private requireAllowedExecutionCoordinationDependencies(): {
    bindingStore:
      SafetyKernelV31AllowedExecutionSessionBindingStore;
    coordinator:
      SafetyKernelV31TransactionReviewPipelineAllowedExecutionCoordinationPort;
  } {
    if (
      !this.allowedExecutionBindingStore ||
      !this.allowedExecutionCoordinator
    ) {
      throw new Error(
        "ALLOWED_EXECUTION_COORDINATION_NOT_CONNECTED"
      );
    }

    return {
      bindingStore: this.allowedExecutionBindingStore,
      coordinator: this.allowedExecutionCoordinator,
    };
  }

  bindAllowedExecutionSessionAuthority(
    sessionId: string,
    input:
      SafetyKernelV31AllowedExecutionAuthorityBindingInput
  ): SafetyKernelV31AllowedExecutionSessionBoundBinding {
    const dependencies =
      this.requireAllowedExecutionCoordinationDependencies();

    const publicSession =
      this.transactionSessionStore.read(sessionId);

    if (!publicSession) {
      throw new Error("SESSION_NOT_FOUND");
    }

    if (
      publicSession.lifecyclePhase !==
      "ALLOW_PENDING_EXECUTION"
    ) {
      throw new Error(
        "ALLOWED_EXECUTION_SESSION_NOT_PENDING"
      );
    }

    const lifecycle =
      this.transactionSessionStore.getLifecycleForInternalUse(
        sessionId
      );

    if (
      lifecycle.phase !==
      "ALLOW_PENDING_EXECUTION"
    ) {
      throw new Error(
        "ALLOWED_EXECUTION_SESSION_NOT_PENDING"
      );
    }

    const reviewedBinding =
      dependencies.bindingStore.read(sessionId);

    if (!reviewedBinding) {
      throw new Error(
        "EXECUTION_SESSION_BINDING_NOT_FOUND"
      );
    }

    if (
      reviewedBinding.sessionId !== sessionId ||
      reviewedBinding.actionId !== lifecycle.actionId ||
      reviewedBinding.approvalNonceSha256 !==
        "sha256:" +
          publicSession.approvalNonceSha256
    ) {
      throw new Error(
        "EXECUTION_SESSION_BINDING_MISMATCH"
      );
    }

    return dependencies.bindingStore.bindAuthority(
      sessionId,
      input
    );
  }

  async coordinateAllowedExecutionSession(
    sessionId: string,
    timestamp?: string
  ): Promise<
    SafetyKernelV31TransactionReviewPipelineCoordinatedExecutionSessionResult
  > {
    const dependencies =
      this.requireAllowedExecutionCoordinationDependencies();

    const publicSession =
      this.transactionSessionStore.read(sessionId);

    if (!publicSession) {
      throw new Error("SESSION_NOT_FOUND");
    }

    if (
      publicSession.lifecyclePhase !==
      "ALLOW_PENDING_EXECUTION"
    ) {
      throw new Error(
        "ALLOWED_EXECUTION_SESSION_NOT_PENDING"
      );
    }

    const lifecycle =
      this.transactionSessionStore.getLifecycleForInternalUse(
        sessionId
      );

    if (
      lifecycle.phase !==
      "ALLOW_PENDING_EXECUTION"
    ) {
      throw new Error(
        "ALLOWED_EXECUTION_SESSION_NOT_PENDING"
      );
    }

    const request =
      dependencies.bindingStore.getExecutionRequest(
        sessionId
      );

    if (
      request.binding.sessionId !== sessionId ||
      request.binding.actionId !== lifecycle.actionId ||
      request.binding.approvalNonceSha256 !==
        "sha256:" +
          publicSession.approvalNonceSha256
    ) {
      throw new Error(
        "EXECUTION_SESSION_BINDING_MISMATCH"
      );
    }

    const coordinated =
      await dependencies.coordinator.executeAllowed(
        request
      );

    if (coordinated.sessionId !== sessionId) {
      throw new Error(
        "COORDINATED_EXECUTION_RESULT_BINDING_MISMATCH"
      );
    }

    if (coordinated.status === "rejected") {
      return {
        status: "rejected",
        sessionId: coordinated.sessionId,
        code: coordinated.code,
      };
    }

    if (
      coordinated.actionId !== lifecycle.actionId
    ) {
      throw new Error(
        "COORDINATED_EXECUTION_RESULT_BINDING_MISMATCH"
      );
    }

    if (
      coordinated.status === "abort_candidate"
    ) {
      const aborted =
        await this.transactionService.abortAllowedExecution(
          lifecycle,
          coordinated.reason,
          timestamp
        );

      if (!aborted.committed) {
        throw new Error(
          "ALLOWED_EXECUTION_ABORT_EVIDENCE_NOT_COMMITTED"
        );
      }

      const session =
        this.transactionSessionStore.replace(
          sessionId,
          aborted.lifecycle
        );

      dependencies.bindingStore.delete(sessionId);

      return {
        status: "aborted",
        session,
        reason: coordinated.reason,
        evidenceCommitted: true,
      };
    }

    const executionBinding:
      SafetyKernelV31AllowedExecutionCompletionBinding = {
        authority_revision:
          coordinated.authorityRevision,
        command_sha256:
          coordinated.commandSha256,
        snapshot_binding_sha256:
          coordinated.snapshotBindingSha256,
        exit_code: coordinated.exitCode,
        stdout_sha256:
          coordinated.output.stdoutSha256,
        stderr_sha256:
          coordinated.output.stderrSha256,
        stdout_bytes:
          coordinated.output.stdoutBytes,
        stderr_bytes:
          coordinated.output.stderrBytes,
      };

    const completion =
      await this.transactionService.completeAllowedExecution(
        lifecycle,
        timestamp,
        executionBinding
      );

    if (!completion.committed) {
      throw new Error(
        "ALLOWED_EXECUTION_COMPLETION_EVIDENCE_NOT_COMMITTED"
      );
    }

    const output =
      formatSafetyKernelV31PostReviewLifecycleOutput(
        "ALLOWED_EXECUTION_COMPLETED",
        completion.lifecycle,
        completion.evidence
      );

    const session =
      this.transactionSessionStore.replace(
        sessionId,
        completion.lifecycle
      );

    dependencies.bindingStore.delete(sessionId);

    return {
      status: "completed",
      session,
      output,
    };
  }

  readSession(
    sessionId: string
  ): SafetyKernelV31TransactionSessionPublicRecord | null {
    return this.transactionSessionStore.read(sessionId);
  }

  async confirmWarnSession(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult> {
    const lifecycle = this.transactionSessionStore.getLifecycleForInternalUse(sessionId);
    const confirmation = await this.transactionService.confirmWarn(lifecycle, timestamp);
    if (!confirmation.committed) throw new Error("WARN_CONFIRMATION_EVIDENCE_NOT_COMMITTED");
    const output = formatSafetyKernelV31PostReviewLifecycleOutput(
      "WARN_CONFIRMED",
      confirmation.lifecycle,
      confirmation.evidence
    );
    const session = this.transactionSessionStore.replace(sessionId, confirmation.lifecycle);
    return { session, output };
  }

  async completeAllowedExecutionSession(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult> {
    if (this.allowedExecutionCoordinator) {
      throw new Error(
        "COORDINATED_ALLOWED_EXECUTION_SESSION_REQUIRED"
      );
    }

    const lifecycle = this.transactionSessionStore.getLifecycleForInternalUse(sessionId);
    const completion = await this.transactionService.completeAllowedExecution(lifecycle, timestamp);
    if (!completion.committed) throw new Error("ALLOWED_EXECUTION_COMPLETION_EVIDENCE_NOT_COMMITTED");
    const output = formatSafetyKernelV31PostReviewLifecycleOutput(
      "ALLOWED_EXECUTION_COMPLETED",
      completion.lifecycle,
      completion.evidence
    );
    const session = this.transactionSessionStore.replace(sessionId, completion.lifecycle);
    this.allowedExecutionBindingStore?.delete(sessionId);
    return { session, output };
  }

  async abortAllowedExecutionSession(
    sessionId: string,
    reason: SafetyKernelV31AllowedExecutionAbortReason,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineAllowedAbortSessionResult> {
    const lifecycle =
      this.transactionSessionStore.getLifecycleForInternalUse(sessionId);
    const aborted =
      await this.transactionService.abortAllowedExecution(
        lifecycle,
        reason,
        timestamp
      );

    if (!aborted.committed) {
      throw new Error(
        "ALLOWED_EXECUTION_ABORT_EVIDENCE_NOT_COMMITTED"
      );
    }

    const session = this.transactionSessionStore.replace(
      sessionId,
      aborted.lifecycle
    );

    this.allowedExecutionBindingStore?.delete(sessionId);

    return {
      session,
      reason,
      evidenceCommitted: true,
    };
  }

  async terminateWarnSession(
    sessionId: string,
    reason: SafetyKernelV31WarnTerminalEvidenceReason,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult> {
    const lifecycle = this.transactionSessionStore.getLifecycleForInternalUse(sessionId);
    const terminal = await this.transactionService.terminateWarn(
      lifecycle,
      reason,
      timestamp
    );
    if (!terminal.committed) throw new Error("WARN_TERMINATION_EVIDENCE_NOT_COMMITTED");
    const output = formatSafetyKernelV31PostReviewLifecycleOutput(
      "WARN_TERMINATED",
      terminal.lifecycle,
      terminal.evidence
    );
    const session = this.transactionSessionStore.replace(
      sessionId,
      terminal.lifecycle
    );
    this.allowedExecutionBindingStore?.delete(sessionId);
    return { session, output };
  }

  async confirmWarn(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    timestamp?: string
  ): Promise<SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"WARN_CONFIRMED">> {
    const confirmation = await this.transactionService.confirmWarn(lifecycle, timestamp);
    if (!confirmation.committed) throw new Error("WARN_CONFIRMATION_EVIDENCE_NOT_COMMITTED");
    return formatSafetyKernelV31PostReviewLifecycleOutput(
      "WARN_CONFIRMED",
      confirmation.lifecycle,
      confirmation.evidence
    );
  }

  async completeAllowedExecution(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    timestamp?: string
  ): Promise<SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"ALLOWED_EXECUTION_COMPLETED">> {
    if (this.allowedExecutionCoordinator) {
      throw new Error(
        "COORDINATED_ALLOWED_EXECUTION_SESSION_REQUIRED"
      );
    }

    const completion = await this.transactionService.completeAllowedExecution(lifecycle, timestamp);
    if (!completion.committed) throw new Error("ALLOWED_EXECUTION_COMPLETION_EVIDENCE_NOT_COMMITTED");
    return formatSafetyKernelV31PostReviewLifecycleOutput(
      "ALLOWED_EXECUTION_COMPLETED",
      completion.lifecycle,
      completion.evidence
    );
  }

  async terminateWarn(
    lifecycle: SafetyKernelV31NonceLifecycleRecord,
    reason: SafetyKernelV31WarnTerminalEvidenceReason,
    timestamp?: string
  ): Promise<SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"WARN_TERMINATED">> {
    const terminal = await this.transactionService.terminateWarn(
      lifecycle,
      reason,
      timestamp
    );
    if (!terminal.committed) throw new Error("WARN_TERMINATION_EVIDENCE_NOT_COMMITTED");
    return formatSafetyKernelV31PostReviewLifecycleOutput(
      "WARN_TERMINATED",
      terminal.lifecycle,
      terminal.evidence
    );
  }
}
