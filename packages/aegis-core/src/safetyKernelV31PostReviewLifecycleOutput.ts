import * as crypto from "crypto";

import type { SafetyKernelV31EvidenceWriteResult } from "./safetyKernelV31EvidenceWriter";
import type { SafetyKernelV31NonceLifecycleRecord } from "./safetyKernelV31NonceLifecyclePolicy";

export type SafetyKernelV31PostReviewLifecycleEvent =
  | "WARN_CONFIRMED"
  | "ALLOWED_EXECUTION_COMPLETED"
  | "WARN_TERMINATED";

interface SafetyKernelV31PostReviewLifecyclePublicRecordBase {
  actionId: string;
  approvalNonceSha256: string;
  evidenceCommitted: true;
  evidenceReason: "success";
  ledgerPath: string;
  receiptPath: string;
  warnMustNeverAutoProceed: true;
  automaticExecutionAllowed: false;
  runtimeConnected: false;
  executionAuthorityGranted: false;
}

export type SafetyKernelV31PostReviewLifecyclePublicRecord =
  SafetyKernelV31PostReviewLifecyclePublicRecordBase &
    (
      | { event: "WARN_CONFIRMED"; lifecyclePhase: "ALLOW_PENDING_EXECUTION"; nonceConsumed: false }
      | { event: "ALLOWED_EXECUTION_COMPLETED"; lifecyclePhase: "CONSUMED"; nonceConsumed: true }
      | { event: "WARN_TERMINATED"; lifecyclePhase: "CONSUMED"; nonceConsumed: true }
    );

export type SafetyKernelV31PostReviewLifecyclePublicRecordForEvent<
  E extends SafetyKernelV31PostReviewLifecycleEvent
> = Extract<SafetyKernelV31PostReviewLifecyclePublicRecord, { event: E }>;

export interface SafetyKernelV31PostReviewLifecycleOutputResult {
  record: SafetyKernelV31PostReviewLifecyclePublicRecord;
  markdown: string;
  clipboardSummary: string;
  invariant: typeof SAFETY_KERNEL_V31_POST_REVIEW_LIFECYCLE_OUTPUT_INVARIANT;
}

export type SafetyKernelV31PostReviewLifecycleOutputResultForEvent<
  E extends SafetyKernelV31PostReviewLifecycleEvent
> = Omit<SafetyKernelV31PostReviewLifecycleOutputResult, "record"> & {
  record: SafetyKernelV31PostReviewLifecyclePublicRecordForEvent<E>;
};

export const SAFETY_KERNEL_V31_POST_REVIEW_LIFECYCLE_OUTPUT_INVARIANT = {
  RAW_APPROVAL_NONCE_EXPOSED: false,
  APPROVAL_NONCE_SHA256_ONLY: true,
  EVIDENCE_FIRST_ALLOWED_COMPLETION_REQUIRED: true,
  EVIDENCE_FIRST_TERMINATION_REQUIRED: true,
  AUTOMATIC_EXECUTION_ALLOWED: false,
  RUNTIME_CONNECTED: false,
  EXECUTION_AUTHORITY_GRANTED: false,
} as const;

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function clean(value: string | null, nonce: string): string | null {
  if (value === null) return null;
  return value.split(nonce).join("<redacted-nonce>").replace(/\s+/g, " ").trim().slice(0, 320);
}

function receiptBoolean(value: boolean | null): "True" | "False" | "NotApplicable" {
  return value === null ? "NotApplicable" : value ? "True" : "False";
}

export function buildSafetyKernelV31PostReviewLifecyclePublicRecord<
  E extends SafetyKernelV31PostReviewLifecycleEvent
>(
  event: E,
  lifecycle: SafetyKernelV31NonceLifecycleRecord,
  evidence?: SafetyKernelV31EvidenceWriteResult
): SafetyKernelV31PostReviewLifecyclePublicRecordForEvent<E>;
export function buildSafetyKernelV31PostReviewLifecyclePublicRecord(
  event: SafetyKernelV31PostReviewLifecycleEvent,
  lifecycle: SafetyKernelV31NonceLifecycleRecord,
  evidence?: SafetyKernelV31EvidenceWriteResult
): SafetyKernelV31PostReviewLifecyclePublicRecord {
  const actionId = lifecycle.actionId;
  const nonce = lifecycle.approvalNonce;

  if (!actionId.trim()) throw new Error("INVALID_ACTION_ID");
  if (!nonce.trim()) throw new Error("INVALID_APPROVAL_NONCE");
  if (
    event === "WARN_CONFIRMED" &&
    (lifecycle.phase !== "ALLOW_PENDING_EXECUTION" ||
      lifecycle.decision !== "ALLOW" ||
      lifecycle.nonceConsumed)
  ) throw new Error("INVALID_WARN_CONFIRMED_PHASE");
  if (
    event === "ALLOWED_EXECUTION_COMPLETED" &&
    (lifecycle.phase !== "CONSUMED" ||
      lifecycle.decision !== "ALLOW" ||
      !lifecycle.nonceConsumed)
  ) throw new Error("INVALID_ALLOWED_EXECUTION_COMPLETION_PHASE");
  if (
    event === "WARN_TERMINATED" &&
    (lifecycle.phase !== "CONSUMED" ||
      lifecycle.decision !== "WARN" ||
      !lifecycle.nonceConsumed)
  ) throw new Error("INVALID_WARN_TERMINATED_PHASE");
  if (!evidence) {
    if (event === "WARN_CONFIRMED") throw new Error("WARN_CONFIRMATION_EVIDENCE_REQUIRED");
    if (event === "ALLOWED_EXECUTION_COMPLETED") throw new Error("ALLOWED_EXECUTION_COMPLETION_EVIDENCE_REQUIRED");
    throw new Error("WARN_TERMINATION_EVIDENCE_REQUIRED");
  }
  if (!evidence.ok) throw new Error("POST_REVIEW_LIFECYCLE_EVIDENCE_NOT_COMMITTED");
  if (
    evidence.reason !== "success" ||
    typeof evidence.ledgerPath !== "string" ||
    !evidence.ledgerPath.trim() ||
    typeof evidence.receiptPath !== "string" ||
    !evidence.receiptPath.trim()
  ) {
    throw new Error("POST_REVIEW_LIFECYCLE_EVIDENCE_INCOMPLETE");
  }
  const committedEvidence = evidence;
  const base = {
    actionId: clean(actionId, nonce) ?? "",
    approvalNonceSha256: sha256(nonce),
    evidenceCommitted: true,
    evidenceReason: "success",
    ledgerPath: clean(committedEvidence.ledgerPath, nonce) ?? "",
    receiptPath: clean(committedEvidence.receiptPath, nonce) ?? "",
    warnMustNeverAutoProceed: true,
    automaticExecutionAllowed: false,
    runtimeConnected: false,
    executionAuthorityGranted: false,
  } as const;
  if (event === "WARN_CONFIRMED") {
    return { ...base, event, lifecyclePhase: "ALLOW_PENDING_EXECUTION", nonceConsumed: false };
  }
  if (event === "ALLOWED_EXECUTION_COMPLETED") {
    return { ...base, event, lifecyclePhase: "CONSUMED", nonceConsumed: true };
  }
  if (event !== "WARN_TERMINATED") {
    throw new Error("UNSUPPORTED_POST_REVIEW_LIFECYCLE_EVENT");
  }
  return { ...base, event: "WARN_TERMINATED", lifecyclePhase: "CONSUMED", nonceConsumed: true };
}

export function formatSafetyKernelV31PostReviewLifecycleOutput<
  E extends SafetyKernelV31PostReviewLifecycleEvent
>(
  event: E,
  lifecycle: SafetyKernelV31NonceLifecycleRecord,
  evidence?: SafetyKernelV31EvidenceWriteResult
): SafetyKernelV31PostReviewLifecycleOutputResultForEvent<E>;
export function formatSafetyKernelV31PostReviewLifecycleOutput(
  event: SafetyKernelV31PostReviewLifecycleEvent,
  lifecycle: SafetyKernelV31NonceLifecycleRecord,
  evidence?: SafetyKernelV31EvidenceWriteResult
): SafetyKernelV31PostReviewLifecycleOutputResult {
  const record = buildSafetyKernelV31PostReviewLifecyclePublicRecord(event, lifecycle, evidence);
  const markdown = [
    "## Safety Kernel v3.1 Post-Review Lifecycle",
    "",
    `- Event: ${record.event}`,
    `- Action ID: ${record.actionId}`,
    `- Approval nonce SHA-256: ${record.approvalNonceSha256}`,
    `- Lifecycle phase: ${record.lifecyclePhase}`,
    `- Nonce consumed: ${receiptBoolean(record.nonceConsumed)}`,
    `- Evidence committed: ${receiptBoolean(record.evidenceCommitted)}`,
    "- Automatic execution allowed: False",
    "- Runtime connected: False",
    "- Execution authority granted: False",
  ].join("\n");
  const clipboardSummary = [
    "SAFETY_KERNEL_V31_POST_REVIEW_LIFECYCLE_OUTPUT=True",
    `EVENT=${record.event}`,
    `ACTION_ID=${record.actionId}`,
    `APPROVAL_NONCE_SHA256=${record.approvalNonceSha256}`,
    `LIFECYCLE_PHASE=${record.lifecyclePhase}`,
    `NONCE_CONSUMED=${receiptBoolean(record.nonceConsumed)}`,
    `EVIDENCE_COMMITTED=${receiptBoolean(record.evidenceCommitted)}`,
    "RAW_APPROVAL_NONCE_EXPOSED=False",
    "AUTOMATIC_EXECUTION_ALLOWED=False",
    "RUNTIME_CONNECTED=False",
    "EXECUTION_AUTHORITY_GRANTED=False",
  ].join("\n");
  return { record, markdown, clipboardSummary, invariant: SAFETY_KERNEL_V31_POST_REVIEW_LIFECYCLE_OUTPUT_INVARIANT };
}
