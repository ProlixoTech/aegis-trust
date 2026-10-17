import * as crypto from "crypto";

import type {
  SafetyKernelV31NonceLifecycleRecord,
} from "./safetyKernelV31NonceLifecyclePolicy";

interface SafetyKernelV31TransactionSessionPublicRecordBase {
  sessionId: string;
  actionId: string;
  approvalNonceSha256: string;
  createdAt: string;
  memoryOnly: true;
  rawApprovalNonceExposed: false;
  runtimeConnected: false;
  executionAuthorityGranted: false;
}

export type SafetyKernelV31TransactionSessionPublicRecord =
  SafetyKernelV31TransactionSessionPublicRecordBase &
    (
      | { lifecyclePhase: "WARN_PENDING"; nonceConsumed: false; expiresAt: string }
      | { lifecyclePhase: "ALLOW_PENDING_EXECUTION"; nonceConsumed: false; expiresAt: null }
      | { lifecyclePhase: "CONSUMED"; nonceConsumed: true; expiresAt: null }
    );

type SafetyKernelV31TransactionSessionPendingLifecycleRecord = Extract<
  SafetyKernelV31NonceLifecycleRecord,
  { phase: "WARN_PENDING" | "ALLOW_PENDING_EXECUTION" }
>;

type SafetyKernelV31TransactionSessionStorableLifecycleRecord = Extract<
  SafetyKernelV31NonceLifecycleRecord,
  { phase: "WARN_PENDING" | "ALLOW_PENDING_EXECUTION" | "CONSUMED" }
>;

export type SafetyKernelV31TransactionSessionPublicRecordForPhase<
  P extends SafetyKernelV31TransactionSessionPublicRecord["lifecyclePhase"]
> = Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: P }>;

export const SAFETY_KERNEL_V31_TRANSACTION_SESSION_STORE_INVARIANT = {
  MEMORY_ONLY: true,
  RAW_APPROVAL_NONCE_PERSISTED: false,
  RAW_APPROVAL_NONCE_LOGGED: false,
  OPAQUE_SESSION_ID_REQUIRED: true,
  SESSION_ID_DERIVED_FROM_NONCE: false,
  AUTOMATIC_EXECUTION_ALLOWED: false,
  RUNTIME_CONNECTED: false,
  EXECUTION_AUTHORITY_GRANTED: false,
} as const;

interface SafetyKernelV31TransactionSessionStoredRecord {
  lifecycle: SafetyKernelV31NonceLifecycleRecord;
  createdAt: string;
  expiresAt: string | null;
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function cloneLifecycle(
  lifecycle: SafetyKernelV31NonceLifecycleRecord
): SafetyKernelV31NonceLifecycleRecord {
  return { ...lifecycle };
}

function assertSessionId(sessionId: string): void {
  if (!/^[a-f0-9]{48}$/.test(sessionId)) throw new Error("INVALID_SESSION_ID");
}

function assertPendingLifecycle(
  lifecycle: SafetyKernelV31NonceLifecycleRecord
): void {
  if (
    lifecycle.nonceConsumed ||
    (lifecycle.phase !== "WARN_PENDING" &&
      lifecycle.phase !== "ALLOW_PENDING_EXECUTION") ||
    (lifecycle.phase === "WARN_PENDING" && lifecycle.decision !== "WARN") ||
    (lifecycle.phase === "ALLOW_PENDING_EXECUTION" &&
      lifecycle.decision !== "ALLOW")
  ) {
    throw new Error("SESSION_LIFECYCLE_NOT_PENDING");
  }
}

function publicRecord(
  sessionId: string,
  stored: SafetyKernelV31TransactionSessionStoredRecord
): SafetyKernelV31TransactionSessionPublicRecord {
  const lifecycle = stored.lifecycle;
  const nonce = lifecycle.approvalNonce;
  const actionId = lifecycle.actionId
    .split(nonce)
    .join("<redacted-nonce>")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 320);
  const base = {
    sessionId,
    actionId,
    approvalNonceSha256: sha256(nonce),
    createdAt: stored.createdAt,
    memoryOnly: true,
    rawApprovalNonceExposed: false,
    runtimeConnected: false,
    executionAuthorityGranted: false,
  } as const;
  if (lifecycle.phase === "WARN_PENDING") {
    if (
      lifecycle.nonceConsumed ||
      lifecycle.decision !== "WARN" ||
      stored.expiresAt === null
    ) {
      throw new Error("INVALID_WARN_SESSION_RECORD");
    }
    return { ...base, lifecyclePhase: "WARN_PENDING", nonceConsumed: false, expiresAt: stored.expiresAt };
  }
  if (lifecycle.phase === "ALLOW_PENDING_EXECUTION") {
    if (
      lifecycle.nonceConsumed ||
      lifecycle.decision !== "ALLOW" ||
      stored.expiresAt !== null
    ) {
      throw new Error("INVALID_ALLOW_SESSION_RECORD");
    }
    return { ...base, lifecyclePhase: "ALLOW_PENDING_EXECUTION", nonceConsumed: false, expiresAt: null };
  }
  if (lifecycle.phase === "CONSUMED") {
    if (!lifecycle.nonceConsumed || stored.expiresAt !== null) throw new Error("INVALID_CONSUMED_SESSION_RECORD");
    return { ...base, lifecyclePhase: "CONSUMED", nonceConsumed: true, expiresAt: null };
  }
  throw new Error("SESSION_LIFECYCLE_NOT_PUBLIC");
}

export class SafetyKernelV31TransactionSessionStore {
  private readonly sessions =
    new Map<string, SafetyKernelV31TransactionSessionStoredRecord>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  get size(): number {
    return this.sessions.size;
  }

  create<L extends SafetyKernelV31TransactionSessionPendingLifecycleRecord>(
    lifecycle: L
  ): SafetyKernelV31TransactionSessionPublicRecordForPhase<L["phase"]>;
  create(
    lifecycle: SafetyKernelV31NonceLifecycleRecord
  ): SafetyKernelV31TransactionSessionPublicRecord;
  create(
    lifecycle: SafetyKernelV31NonceLifecycleRecord
  ): SafetyKernelV31TransactionSessionPublicRecord {
    assertPendingLifecycle(lifecycle);
    let sessionId: string;
    do {
      sessionId = crypto.randomBytes(24).toString("hex");
    } while (this.sessions.has(sessionId));
    const createdAtDate = this.now();
    const createdAt = createdAtDate.toISOString();
    const expiresAt =
      lifecycle.phase === "WARN_PENDING"
        ? new Date(
            createdAtDate.getTime() + (lifecycle.warnTimeoutSeconds ?? 60) * 1000
          ).toISOString()
        : null;
    const stored: SafetyKernelV31TransactionSessionStoredRecord = {
      lifecycle: cloneLifecycle(lifecycle),
      createdAt,
      expiresAt,
    };
    this.sessions.set(sessionId, stored);
    return publicRecord(sessionId, stored);
  }

  read(
    sessionId: string
  ): SafetyKernelV31TransactionSessionPublicRecord | null {
    assertSessionId(sessionId);
    const stored = this.sessions.get(sessionId);
    return stored ? publicRecord(sessionId, stored) : null;
  }

  getLifecycleForInternalUse(
    sessionId: string
  ): SafetyKernelV31NonceLifecycleRecord {
    assertSessionId(sessionId);
    const stored = this.sessions.get(sessionId);
    if (!stored) throw new Error("SESSION_NOT_FOUND");
    return cloneLifecycle(stored.lifecycle);
  }

  replace<L extends SafetyKernelV31TransactionSessionStorableLifecycleRecord>(
    sessionId: string,
    lifecycle: L
  ): SafetyKernelV31TransactionSessionPublicRecordForPhase<L["phase"]>;
  replace(
    sessionId: string,
    lifecycle: SafetyKernelV31NonceLifecycleRecord
  ): SafetyKernelV31TransactionSessionPublicRecord;
  replace(
    sessionId: string,
    lifecycle: SafetyKernelV31NonceLifecycleRecord
  ): SafetyKernelV31TransactionSessionPublicRecord {
    assertSessionId(sessionId);
    const current = this.sessions.get(sessionId);
    if (!current) throw new Error("SESSION_NOT_FOUND");
    if (
      current.lifecycle.actionId !== lifecycle.actionId ||
      current.lifecycle.approvalNonce !== lifecycle.approvalNonce
    ) {
      throw new Error("SESSION_BINDING_MISMATCH");
    }
    if (
      current.lifecycle.phase === "ALLOW_PENDING_EXECUTION" &&
      lifecycle.phase === "WARN_PENDING"
    ) {
      throw new Error("SESSION_LIFECYCLE_REGRESSION");
    }
    if (lifecycle.nonceConsumed) {
      if (lifecycle.phase !== "CONSUMED") {
        throw new Error("INVALID_CONSUMED_SESSION_PHASE");
      }
    } else {
      assertPendingLifecycle(lifecycle);
    }
    const next: SafetyKernelV31TransactionSessionStoredRecord = {
      lifecycle: cloneLifecycle(lifecycle),
      createdAt: current.createdAt,
      expiresAt:
        lifecycle.phase === "WARN_PENDING" ? current.expiresAt : null,
    };
    const record = publicRecord(sessionId, next);
    if (lifecycle.nonceConsumed) this.sessions.delete(sessionId);
    else this.sessions.set(sessionId, next);
    return record;
  }

  delete(sessionId: string): boolean {
    assertSessionId(sessionId);
    return this.sessions.delete(sessionId);
  }

  clear(): void {
    this.sessions.clear();
  }
}
