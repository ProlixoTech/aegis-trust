import * as crypto from "crypto";

import type {
  AegisExecutionPort,
  AegisExecutionResult,
} from "./platformPorts";
import type {
  SafetyKernelV31AllowedExecutionAbortReason,
} from "./types";

export type SafetyKernelV31CoordinatedExecutionAbortReason = Extract<
  SafetyKernelV31AllowedExecutionAbortReason,
  "snapshot_failed" | "authority_drift" | "execution_failed"
>;

export interface SafetyKernelV31AllowedExecutionBinding {
  readonly authorityRevision: number;
  readonly workspaceId: string;
  readonly actionId: string;
  readonly sessionId: string;
  readonly approvalNonceSha256: string;
  readonly commandSha256: string;
  readonly snapshotBindingSha256: string;
}

export interface SafetyKernelV31AllowedExecutionBindingVerifier {
  verify(
    binding: SafetyKernelV31AllowedExecutionBinding
  ): Promise<"verified" | "authority_drift" | "snapshot_failed">;
}

export interface SafetyKernelV31AllowedExecutionRequest {
  readonly binding: SafetyKernelV31AllowedExecutionBinding;
  readonly commandText: string;
  readonly cwd: string;
}

export interface SafetyKernelV31ExecutionOutputSummary {
  readonly stdoutSha256: string;
  readonly stderrSha256: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
}

export type SafetyKernelV31AllowedExecutionCoordinationResult =
  | {
      readonly status: "completion_candidate";
      readonly sessionId: string;
      readonly actionId: string;
      readonly commandSha256: string;
      readonly snapshotBindingSha256: string;
      readonly authorityRevision: number;
      readonly exitCode: 0;
      readonly output: SafetyKernelV31ExecutionOutputSummary;
    }
  | {
      readonly status: "abort_candidate";
      readonly sessionId: string;
      readonly actionId: string;
      readonly reason: SafetyKernelV31CoordinatedExecutionAbortReason;
      readonly executionErrorCode?:
        | "EXECUTION_START_FAILED"
        | "EXECUTION_OBSERVATION_FAILED";
      readonly exitCode?: number;
      readonly output?: SafetyKernelV31ExecutionOutputSummary;
    }
  | {
      readonly status: "rejected";
      readonly sessionId: string;
      readonly code: "EXECUTION_SESSION_ALREADY_CLAIMED";
    };

export const SAFETY_KERNEL_V31_ALLOWED_EXECUTION_COORDINATOR_INVARIANT = {
  SESSION_EXECUTION_CLAIM_EXACTLY_ONCE: true,
  COMMAND_SHA256_RECHECK_REQUIRED: true,
  AUTHORITY_AND_SNAPSHOT_BINDING_VERIFICATION_REQUIRED: true,
  EXIT_CODE_ZERO_REQUIRED_FOR_COMPLETION: true,
  RAW_STDOUT_STORED_IN_RESULT: false,
  RAW_STDERR_STORED_IN_RESULT: false,
  PIPELINE_CONNECTED: false,
  RUNTIME_CONTROLLER_CONNECTED: false,
  EXTENSION_RUNTIME_CONNECTED: false,
  REAL_PROCESS_REQUIRED_BY_TESTS: false,
} as const;

function sha256(value: string): string {
  return (
    "sha256:" +
    crypto.createHash("sha256").update(value, "utf8").digest("hex")
  );
}

function requireInline(value: string, errorCode: string): string {
  const normalized = value.trim();

  if (
    !normalized ||
    normalized.length > 500 ||
    /[\r\n]/.test(normalized)
  ) {
    throw new Error(errorCode);
  }

  return normalized;
}

function requireSha256(value: string, errorCode: string): string {
  const normalized = value.trim().toLowerCase();

  if (!/^sha256:[a-f0-9]{64}$/.test(normalized)) {
    throw new Error(errorCode);
  }

  return normalized;
}

function validateBinding(
  binding: SafetyKernelV31AllowedExecutionBinding
): SafetyKernelV31AllowedExecutionBinding {
  if (
    !Number.isSafeInteger(binding.authorityRevision) ||
    binding.authorityRevision < 0
  ) {
    throw new Error("INVALID_AUTHORITY_REVISION");
  }

  return {
    authorityRevision: binding.authorityRevision,
    workspaceId: requireInline(binding.workspaceId, "INVALID_WORKSPACE_ID"),
    actionId: requireInline(binding.actionId, "INVALID_ACTION_ID"),
    sessionId: requireInline(binding.sessionId, "INVALID_SESSION_ID"),
    approvalNonceSha256: requireSha256(
      binding.approvalNonceSha256,
      "INVALID_APPROVAL_NONCE_SHA256"
    ),
    commandSha256: requireSha256(
      binding.commandSha256,
      "INVALID_COMMAND_SHA256"
    ),
    snapshotBindingSha256: requireSha256(
      binding.snapshotBindingSha256,
      "INVALID_SNAPSHOT_BINDING_SHA256"
    ),
  };
}

function summarizeOutput(
  result: Pick<AegisExecutionResult, "stdout" | "stderr">
): SafetyKernelV31ExecutionOutputSummary {
  return {
    stdoutSha256: sha256(result.stdout),
    stderrSha256: sha256(result.stderr),
    stdoutBytes: Buffer.byteLength(result.stdout, "utf8"),
    stderrBytes: Buffer.byteLength(result.stderr, "utf8"),
  };
}

export class SafetyKernelV31AllowedExecutionCoordinator {
  private readonly claimedSessions = new Set<string>();

  constructor(
    private readonly execution: AegisExecutionPort,
    private readonly bindingVerifier:
      SafetyKernelV31AllowedExecutionBindingVerifier
  ) {}

  async executeAllowed(
    request: SafetyKernelV31AllowedExecutionRequest
  ): Promise<SafetyKernelV31AllowedExecutionCoordinationResult> {
    const binding = validateBinding(request.binding);
    const commandText = request.commandText;
    const cwd = requireInline(request.cwd, "INVALID_EXECUTION_CWD");

    if (!commandText.trim()) {
      throw new Error("INVALID_EXECUTION_COMMAND");
    }

    if (this.claimedSessions.has(binding.sessionId)) {
      return {
        status: "rejected",
        sessionId: binding.sessionId,
        code: "EXECUTION_SESSION_ALREADY_CLAIMED",
      };
    }

    this.claimedSessions.add(binding.sessionId);

    if (sha256(commandText) !== binding.commandSha256) {
      return {
        status: "abort_candidate",
        sessionId: binding.sessionId,
        actionId: binding.actionId,
        reason: "authority_drift",
      };
    }

    let verification:
      | "verified"
      | "authority_drift"
      | "snapshot_failed";

    try {
      verification = await this.bindingVerifier.verify(binding);
    } catch {
      verification = "authority_drift";
    }

    if (verification !== "verified") {
      return {
        status: "abort_candidate",
        sessionId: binding.sessionId,
        actionId: binding.actionId,
        reason: verification,
      };
    }

    let executionResult: AegisExecutionResult;

    try {
      executionResult = await this.execution.execute({
        commandText,
        cwd,
      });
    } catch {
      return {
        status: "abort_candidate",
        sessionId: binding.sessionId,
        actionId: binding.actionId,
        reason: "execution_failed",
      };
    }

    const output = summarizeOutput(executionResult);

    if (executionResult.status === "failed") {
      return {
        status: "abort_candidate",
        sessionId: binding.sessionId,
        actionId: binding.actionId,
        reason: "execution_failed",
        executionErrorCode: executionResult.errorCode,
        ...(typeof executionResult.exitCode === "number"
          ? { exitCode: executionResult.exitCode }
          : {}),
        output,
      };
    }

    if (executionResult.exitCode !== 0) {
      return {
        status: "abort_candidate",
        sessionId: binding.sessionId,
        actionId: binding.actionId,
        reason: "execution_failed",
        exitCode: executionResult.exitCode,
        output,
      };
    }

    return {
      status: "completion_candidate",
      sessionId: binding.sessionId,
      actionId: binding.actionId,
      commandSha256: binding.commandSha256,
      snapshotBindingSha256: binding.snapshotBindingSha256,
      authorityRevision: binding.authorityRevision,
      exitCode: 0,
      output,
    };
  }
}