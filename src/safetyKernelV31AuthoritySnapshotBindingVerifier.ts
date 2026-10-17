import type {
  SafetyKernelV31AllowedExecutionBinding,
  SafetyKernelV31AllowedExecutionBindingVerifier,
} from "./safetyKernelV31AllowedExecutionCoordinator";

export type SafetyKernelV31AuthoritySnapshotBindingVerificationResult =
  | "verified"
  | "authority_drift"
  | "snapshot_failed";

export interface SafetyKernelV31AuthoritySnapshotBindingReadback {
  readonly authorityRevision: number;
  readonly workspaceId: string;
  readonly snapshotBindingSha256: string;
}

export interface SafetyKernelV31AuthoritySnapshotBindingReadPort {
  readCurrentBinding(): Promise<unknown>;
}

export const SAFETY_KERNEL_V31_AUTHORITY_SNAPSHOT_BINDING_VERIFIER_INVARIANT =
  Object.freeze({
    READ_PORT_CALLED_ON_EVERY_VERIFY: true,
    STATE_CACHE_ALLOWED: false,
    READ_FAILURE_FAILS_CLOSED: true,
    MALFORMED_READBACK_MAPS_TO_AUTHORITY_DRIFT: true,
    AUTHORITY_REVISION_MISMATCH_MAPS_TO_AUTHORITY_DRIFT: true,
    WORKSPACE_ID_MISMATCH_MAPS_TO_AUTHORITY_DRIFT: true,
    SNAPSHOT_BINDING_MISMATCH_MAPS_TO_SNAPSHOT_FAILED: true,
    CANONICAL_AUTHORITY_IMPORTED: false,
    SNAPSHOT_STORE_IMPORTED: false,
    EXTENSION_CONNECTED: false,
    NODE_PROCESS_ADAPTER_CONNECTED: false,
    REAL_PROCESS_REQUIRED_BY_TESTS: false,
    RAW_APPROVAL_NONCE_EXPOSED: false,
    RAW_STDOUT_EXPOSED: false,
    RAW_STDERR_EXPOSED: false,
  } as const);

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isAuthorityRevision(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isWorkspaceId(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }

  const normalized = value.trim();

  return (
    normalized.length > 0 &&
    normalized.length <= 200 &&
    normalized === value &&
    !/[\r\n]/.test(value)
  );
}

function isSha256(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^sha256:[a-f0-9]{64}$/.test(value)
  );
}

export class SafetyKernelV31AuthoritySnapshotBindingVerifier
  implements SafetyKernelV31AllowedExecutionBindingVerifier {
  constructor(
    private readonly readPort:
      SafetyKernelV31AuthoritySnapshotBindingReadPort
  ) {}

  async verify(
    binding: SafetyKernelV31AllowedExecutionBinding
  ): Promise<SafetyKernelV31AuthoritySnapshotBindingVerificationResult> {
    try {
      if (!isRecord(binding)) {
        return "authority_drift";
      }

      if (
        !isAuthorityRevision(binding.authorityRevision) ||
        !isWorkspaceId(binding.workspaceId)
      ) {
        return "authority_drift";
      }

      if (!isSha256(binding.snapshotBindingSha256)) {
        return "snapshot_failed";
      }

      const current = await this.readPort.readCurrentBinding();

      if (!isRecord(current)) {
        return "authority_drift";
      }

      if (
        !isAuthorityRevision(current.authorityRevision) ||
        !isWorkspaceId(current.workspaceId) ||
        !isSha256(current.snapshotBindingSha256)
      ) {
        return "authority_drift";
      }

      if (
        current.authorityRevision !== binding.authorityRevision ||
        current.workspaceId !== binding.workspaceId
      ) {
        return "authority_drift";
      }

      if (
        current.snapshotBindingSha256 !==
        binding.snapshotBindingSha256
      ) {
        return "snapshot_failed";
      }

      return "verified";
    } catch {
      return "authority_drift";
    }
  }
}