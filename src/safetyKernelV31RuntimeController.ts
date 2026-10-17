import type {
  ActionQualityResult,
  SafetyKernelV31AllowedExecutionAbortReason,
  SafetyKernelV31WarnTerminalEvidenceReason,
} from "../packages/aegis-core";
import type { SafetyKernelV31TransactionCallerContext } from "../packages/aegis-core";
import {
  SafetyKernelV31TransactionReviewPipeline,
  SafetyKernelV31TransactionReviewPipelineAllowedAbortSessionResult,
  SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult,
  SafetyKernelV31TransactionReviewPipelineCoordinatedExecutionSessionResult,
  SafetyKernelV31TransactionReviewPipelineResult,
  SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult,
  SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult,
} from "../packages/aegis-core";
import type { SafetyKernelV31TransactionSessionPublicRecord } from "../packages/aegis-core";
import type {
  SafetyKernelV31AllowedExecutionAuthorityBindingInput,
  SafetyKernelV31AllowedExecutionSessionBoundBinding,
} from "../packages/aegis-core";

/**
 * SAFETY_KERNEL_V3_1_RUNTIME_CONTROLLER_V1
 *
 * Owns one transaction review pipeline instance and exposes only the
 * session-based review lifecycle surface intended for a future extension
 * runtime connection.
 *
 * Default construction does not execute commands, expose raw lifecycle
 * records or approval nonces, connect itself to extension runtime paths, or
 * grant execution authority. Detached authority-binding and coordinated
 * execution forwarding are available only through an explicitly injected
 * Pipeline Port.
 */
export const SAFETY_KERNEL_V31_RUNTIME_CONTROLLER_INVARIANT = {
  SINGLE_PIPELINE_INSTANCE_REQUIRED: true,
  SESSION_BASED_PUBLIC_API_ONLY: true,
  RAW_LIFECYCLE_API_EXPOSED: false,
  RAW_APPROVAL_NONCE_EXPOSED: false,
  AUTOMATIC_EXECUTION_ALLOWED: false,
  RUNTIME_CONNECTED: false,
  EXECUTION_AUTHORITY_GRANTED: false,
} as const;

export interface SafetyKernelV31RuntimeControllerPipelinePort {
  review(
    caller: SafetyKernelV31TransactionCallerContext,
    actionQuality: ActionQualityResult
  ): Promise<SafetyKernelV31TransactionReviewPipelineResult>;
  readSession(sessionId: string): SafetyKernelV31TransactionSessionPublicRecord | null;
  confirmWarnSession(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult>;
  completeAllowedExecutionSession(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult>;
  bindAllowedExecutionSessionAuthority?(
    sessionId: string,
    input: SafetyKernelV31AllowedExecutionAuthorityBindingInput
  ): SafetyKernelV31AllowedExecutionSessionBoundBinding;
  coordinateAllowedExecutionSession?(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineCoordinatedExecutionSessionResult>;
  abortAllowedExecutionSession?(
    sessionId: string,
    reason: SafetyKernelV31AllowedExecutionAbortReason,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineAllowedAbortSessionResult>;
  terminateWarnSession(
    sessionId: string,
    reason: SafetyKernelV31WarnTerminalEvidenceReason,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult>;
}

export class SafetyKernelV31RuntimeController {
  constructor(
    private readonly pipeline: SafetyKernelV31RuntimeControllerPipelinePort
  ) {}

  static createForAegisDir(aegisDir: string): SafetyKernelV31RuntimeController {
    const normalizedAegisDir = aegisDir.trim();
    if (!normalizedAegisDir) throw new Error("INVALID_AEGIS_DIR");
    return new SafetyKernelV31RuntimeController(
      SafetyKernelV31TransactionReviewPipeline.createForAegisDir(
        normalizedAegisDir
      )
    );
  }

  review(
    caller: SafetyKernelV31TransactionCallerContext,
    actionQuality: ActionQualityResult
  ): Promise<SafetyKernelV31TransactionReviewPipelineResult> {
    return this.pipeline.review(caller, actionQuality);
  }

  readSession(
    sessionId: string
  ): SafetyKernelV31TransactionSessionPublicRecord | null {
    return this.pipeline.readSession(sessionId);
  }

  confirmWarnSession(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult> {
    return this.pipeline.confirmWarnSession(sessionId, timestamp);
  }

  bindAllowedExecutionSessionAuthority(
    sessionId: string,
    input: SafetyKernelV31AllowedExecutionAuthorityBindingInput
  ): SafetyKernelV31AllowedExecutionSessionBoundBinding {
    const bindAuthority =
      this.pipeline.bindAllowedExecutionSessionAuthority;

    if (!bindAuthority) {
      throw new Error(
        "ALLOWED_EXECUTION_AUTHORITY_BINDING_PIPELINE_UNAVAILABLE"
      );
    }

    return bindAuthority.call(
      this.pipeline,
      sessionId,
      input
    );
  }

  coordinateAllowedExecutionSession(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineCoordinatedExecutionSessionResult> {
    const coordinate =
      this.pipeline.coordinateAllowedExecutionSession;

    if (!coordinate) {
      return Promise.reject(
        new Error(
          "ALLOWED_EXECUTION_COORDINATION_PIPELINE_UNAVAILABLE"
        )
      );
    }

    return coordinate.call(
      this.pipeline,
      sessionId,
      timestamp
    );
  }

  completeAllowedExecutionSession(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult> {
    return this.pipeline.completeAllowedExecutionSession(sessionId, timestamp);
  }

  abortAllowedExecutionSession(
    sessionId: string,
    reason: SafetyKernelV31AllowedExecutionAbortReason,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineAllowedAbortSessionResult> {
    if (!this.pipeline.abortAllowedExecutionSession) {
      return Promise.reject(
        new Error("ALLOWED_EXECUTION_ABORT_PIPELINE_UNAVAILABLE")
      );
    }

    return this.pipeline.abortAllowedExecutionSession(
      sessionId,
      reason,
      timestamp
    );
  }

  terminateWarnSession(
    sessionId: string,
    reason: SafetyKernelV31WarnTerminalEvidenceReason,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult> {
    return this.pipeline.terminateWarnSession(sessionId, reason, timestamp);
  }
}
