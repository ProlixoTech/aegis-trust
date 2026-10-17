import * as crypto from "crypto";

import type {
  SafetyKernelV31AllowedExecutionBinding,
  SafetyKernelV31AllowedExecutionRequest,
} from "./safetyKernelV31AllowedExecutionCoordinator";

export interface SafetyKernelV31AllowedExecutionSessionReviewBindingInput {
  readonly sessionId: string;
  readonly actionId: string;
  readonly approvalNonceSha256: string;
  readonly commandText: string;
}

export interface SafetyKernelV31AllowedExecutionAuthorityBindingInput {
  readonly authorityRevision: number;
  readonly workspaceId: string;
  readonly snapshotBindingSha256: string;
  readonly cwd: string;
}

export interface SafetyKernelV31AllowedExecutionSessionReviewedBinding {
  readonly sessionId: string;
  readonly actionId: string;
  readonly approvalNonceSha256: string;
  readonly commandText: string;
  readonly commandSha256: string;
  readonly authorityBound: false;
}

export interface SafetyKernelV31AllowedExecutionSessionBoundBinding {
  readonly sessionId: string;
  readonly actionId: string;
  readonly approvalNonceSha256: string;
  readonly commandText: string;
  readonly commandSha256: string;
  readonly authorityBound: true;
  readonly authorityRevision: number;
  readonly workspaceId: string;
  readonly snapshotBindingSha256: string;
  readonly cwd: string;
}

export type SafetyKernelV31AllowedExecutionSessionBinding =
  | SafetyKernelV31AllowedExecutionSessionReviewedBinding
  | SafetyKernelV31AllowedExecutionSessionBoundBinding;

interface SafetyKernelV31AllowedExecutionSessionStoredBinding {
  readonly sessionId: string;
  readonly actionId: string;
  readonly approvalNonceSha256: string;
  readonly commandText: string;
  readonly commandSha256: string;
  readonly authority:
    | {
        readonly authorityRevision: number;
        readonly workspaceId: string;
        readonly snapshotBindingSha256: string;
        readonly cwd: string;
      }
    | null;
}

export const SAFETY_KERNEL_V31_ALLOWED_EXECUTION_SESSION_BINDING_STORE_INVARIANT = {
  MEMORY_ONLY: true,
  RAW_APPROVAL_NONCE_ACCEPTED: false,
  RAW_APPROVAL_NONCE_PERSISTED: false,
  REVIEWED_COMMAND_IMMUTABLE: true,
  COMMAND_SHA256_COMPUTED_FROM_REVIEWED_COMMAND: true,
  AUTHORITY_BINDING_EXACTLY_ONCE: true,
  DEFENSIVE_COPY_REQUIRED: true,
  PIPELINE_CONNECTED: false,
  RUNTIME_CONNECTED: false,
  REAL_PROCESS_EXECUTION_ALLOWED: false,
} as const;

function sha256(value: string): string {
  return (
    "sha256:" +
    crypto.createHash("sha256").update(value, "utf8").digest("hex")
  );
}

function requireInline(
  value: string,
  errorCode: string,
  maximumLength = 500
): string {
  if (typeof value !== "string") {
    throw new Error(errorCode);
  }

  const normalized = value.trim();

  if (
    !normalized ||
    normalized.length > maximumLength ||
    /[\r\n]/.test(normalized)
  ) {
    throw new Error(errorCode);
  }

  return normalized;
}

function requireSessionId(value: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-f0-9]{48}$/.test(value)
  ) {
    throw new Error("INVALID_SESSION_ID");
  }

  return value;
}

function requireSha256(
  value: string,
  errorCode: string
): string {
  if (
    typeof value !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(value)
  ) {
    throw new Error(errorCode);
  }

  return value;
}

function requireCommandText(value: string): string {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > 100000
  ) {
    throw new Error("INVALID_REVIEWED_COMMAND_TEXT");
  }

  return value;
}

function assertNoRawApprovalNonceInput(
  input: SafetyKernelV31AllowedExecutionSessionReviewBindingInput
): void {
  const candidate = input as unknown as Record<string, unknown>;

  if (
    Object.prototype.hasOwnProperty.call(
      candidate,
      "approvalNonce"
    ) ||
    Object.prototype.hasOwnProperty.call(
      candidate,
      "rawApprovalNonce"
    )
  ) {
    throw new Error("RAW_APPROVAL_NONCE_INPUT_FORBIDDEN");
  }
}

function cloneBinding(
  stored: SafetyKernelV31AllowedExecutionSessionStoredBinding
): SafetyKernelV31AllowedExecutionSessionBinding {
  const base = {
    sessionId: stored.sessionId,
    actionId: stored.actionId,
    approvalNonceSha256: stored.approvalNonceSha256,
    commandText: stored.commandText,
    commandSha256: stored.commandSha256,
  } as const;

  if (stored.authority === null) {
    return {
      ...base,
      authorityBound: false,
    };
  }

  return {
    ...base,
    authorityBound: true,
    authorityRevision: stored.authority.authorityRevision,
    workspaceId: stored.authority.workspaceId,
    snapshotBindingSha256:
      stored.authority.snapshotBindingSha256,
    cwd: stored.authority.cwd,
  };
}

export class SafetyKernelV31AllowedExecutionSessionBindingStore {
  private readonly bindings =
    new Map<
      string,
      SafetyKernelV31AllowedExecutionSessionStoredBinding
    >();

  get size(): number {
    return this.bindings.size;
  }

  registerReviewedCommand(
    input: SafetyKernelV31AllowedExecutionSessionReviewBindingInput
  ): SafetyKernelV31AllowedExecutionSessionReviewedBinding {
    assertNoRawApprovalNonceInput(input);

    const sessionId = requireSessionId(input.sessionId);

    if (this.bindings.has(sessionId)) {
      throw new Error(
        "EXECUTION_SESSION_BINDING_ALREADY_REGISTERED"
      );
    }

    const actionId = requireInline(
      input.actionId,
      "INVALID_ACTION_ID"
    );

    const approvalNonceSha256 = requireSha256(
      input.approvalNonceSha256,
      "INVALID_APPROVAL_NONCE_SHA256"
    );

    const commandText = requireCommandText(input.commandText);

    const stored: SafetyKernelV31AllowedExecutionSessionStoredBinding = {
      sessionId,
      actionId,
      approvalNonceSha256,
      commandText,
      commandSha256: sha256(commandText),
      authority: null,
    };

    this.bindings.set(sessionId, stored);

    return cloneBinding(
      stored
    ) as SafetyKernelV31AllowedExecutionSessionReviewedBinding;
  }

  bindAuthority(
    sessionIdValue: string,
    input: SafetyKernelV31AllowedExecutionAuthorityBindingInput
  ): SafetyKernelV31AllowedExecutionSessionBoundBinding {
    const sessionId = requireSessionId(sessionIdValue);
    const current = this.bindings.get(sessionId);

    if (!current) {
      throw new Error("EXECUTION_SESSION_BINDING_NOT_FOUND");
    }

    if (current.authority !== null) {
      throw new Error(
        "EXECUTION_SESSION_AUTHORITY_ALREADY_BOUND"
      );
    }

    if (
      !Number.isSafeInteger(input.authorityRevision) ||
      input.authorityRevision < 0
    ) {
      throw new Error("INVALID_AUTHORITY_REVISION");
    }

    const authority = {
      authorityRevision: input.authorityRevision,
      workspaceId: requireInline(
        input.workspaceId,
        "INVALID_WORKSPACE_ID"
      ),
      snapshotBindingSha256: requireSha256(
        input.snapshotBindingSha256,
        "INVALID_SNAPSHOT_BINDING_SHA256"
      ),
      cwd: requireInline(
        input.cwd,
        "INVALID_EXECUTION_CWD",
        2000
      ),
    } as const;

    const bound: SafetyKernelV31AllowedExecutionSessionStoredBinding = {
      ...current,
      authority,
    };

    this.bindings.set(sessionId, bound);

    return cloneBinding(
      bound
    ) as SafetyKernelV31AllowedExecutionSessionBoundBinding;
  }

  read(
    sessionIdValue: string
  ): SafetyKernelV31AllowedExecutionSessionBinding | null {
    const sessionId = requireSessionId(sessionIdValue);
    const stored = this.bindings.get(sessionId);
    return stored ? cloneBinding(stored) : null;
  }

  getExecutionRequest(
    sessionIdValue: string
  ): SafetyKernelV31AllowedExecutionRequest {
    const sessionId = requireSessionId(sessionIdValue);
    const stored = this.bindings.get(sessionId);

    if (!stored) {
      throw new Error("EXECUTION_SESSION_BINDING_NOT_FOUND");
    }

    if (stored.authority === null) {
      throw new Error(
        "EXECUTION_SESSION_AUTHORITY_NOT_BOUND"
      );
    }

    const binding: SafetyKernelV31AllowedExecutionBinding = {
      authorityRevision:
        stored.authority.authorityRevision,
      workspaceId: stored.authority.workspaceId,
      actionId: stored.actionId,
      sessionId: stored.sessionId,
      approvalNonceSha256:
        stored.approvalNonceSha256,
      commandSha256: stored.commandSha256,
      snapshotBindingSha256:
        stored.authority.snapshotBindingSha256,
    };

    return {
      binding: { ...binding },
      commandText: stored.commandText,
      cwd: stored.authority.cwd,
    };
  }

  delete(sessionIdValue: string): boolean {
    const sessionId = requireSessionId(sessionIdValue);
    return this.bindings.delete(sessionId);
  }

  clear(): void {
    this.bindings.clear();
  }
}