import * as crypto from "crypto";

import type { SafetyKernelV31TransactionServiceResult } from "./safetyKernelV31TransactionService";

interface SafetyKernelV31TransactionPublicRecordBase {
  actionId: string;
  approvalNonceSha256: string;
  evidenceCommitted: true;
  evidenceReason: "success";
  ledgerPath: string;
  receiptPath: string;
  humanReadableSummary: string;
  automaticExecutionAllowed: false;
  runtimeConnected: false;
  executionAuthorityGranted: false;
}

export type SafetyKernelV31TransactionPublicRecord =
  SafetyKernelV31TransactionPublicRecordBase &
    (
      | { decision: "ALLOW"; lifecyclePhase: "ALLOW_PENDING_EXECUTION"; nonceConsumed: false; parentEnvelopeInvalidated: false; childNoncesRequired: false }
      | { decision: "WARN"; lifecyclePhase: "WARN_PENDING"; nonceConsumed: false; parentEnvelopeInvalidated: false; childNoncesRequired: false }
      | { decision: "BLOCK"; lifecyclePhase: "BLOCKED"; nonceConsumed: true; parentEnvelopeInvalidated: false; childNoncesRequired: false }
      | { decision: "REQUIRE_REVIEW"; lifecyclePhase: "REQUIRE_REVIEW"; nonceConsumed: true; parentEnvelopeInvalidated: false; childNoncesRequired: false }
      | { decision: "SPLIT_REQUIRED"; lifecyclePhase: "SPLIT_REQUIRED"; nonceConsumed: true; parentEnvelopeInvalidated: true; childNoncesRequired: true }
    );

export type SafetyKernelV31TransactionPublicRecordForDecision<
  D extends SafetyKernelV31TransactionPublicRecord["decision"]
> = Extract<SafetyKernelV31TransactionPublicRecord, { decision: D }>;

export interface SafetyKernelV31TransactionOutputResult {
  record: SafetyKernelV31TransactionPublicRecord;
  markdown: string;
  clipboardSummary: string;
  invariant: typeof SAFETY_KERNEL_V31_TRANSACTION_OUTPUT_INVARIANT;
}

export type SafetyKernelV31TransactionOutputResultForDecision<
  D extends SafetyKernelV31TransactionPublicRecord["decision"]
> = Omit<SafetyKernelV31TransactionOutputResult, "record"> & {
  record: SafetyKernelV31TransactionPublicRecordForDecision<D>;
};

export const SAFETY_KERNEL_V31_TRANSACTION_OUTPUT_INVARIANT = {
  RAW_APPROVAL_NONCE_EXPOSED: false,
  APPROVAL_NONCE_SHA256_ONLY: true,
  AUTOMATIC_EXECUTION_ALLOWED: false,
  RUNTIME_CONNECTED: false,
  EXECUTION_AUTHORITY_GRANTED: false,
} as const;

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function clean(value: string | null, nonce: string): string | null {
  if (value === null) {
    return null;
  }

  return value
    .split(nonce)
    .join("<redacted-nonce>")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 320);
}

function receiptBoolean(value: boolean): "True" | "False" {
  return value ? "True" : "False";
}

export function buildSafetyKernelV31TransactionPublicRecord<
  R extends SafetyKernelV31TransactionServiceResult
>(
  result: R
): SafetyKernelV31TransactionPublicRecordForDecision<R["decisionResult"]["decision"]>;
export function buildSafetyKernelV31TransactionPublicRecord(
  result: SafetyKernelV31TransactionServiceResult
): SafetyKernelV31TransactionPublicRecord {
  const actionId = result.issued.lifecycle.actionId;
  const nonce = result.issued.approvalNonce;

  if (!actionId.trim()) {
    throw new Error("INVALID_ACTION_ID");
  }

  if (!nonce.trim()) {
    throw new Error("INVALID_APPROVAL_NONCE");
  }

  const issuedLifecycle = result.issued.lifecycle;
  if (issuedLifecycle.phase !== "ISSUED" || issuedLifecycle.decision !== null || issuedLifecycle.nonceConsumed || issuedLifecycle.parentEnvelopeInvalidated || issuedLifecycle.childNoncesRequired || issuedLifecycle.warnMustNeverAutoProceed !== true || issuedLifecycle.receiptRequired !== true || issuedLifecycle.ledgerRequired !== true) {
    throw new Error("INVALID_ISSUED_LIFECYCLE");
  }

  if (
    result.envelope.action_id !== actionId ||
    result.decisionResult.action_id !== actionId ||
    result.commit.lifecycle.actionId !== actionId
  ) {
    throw new Error("ACTION_ID_MISMATCH");
  }

  if (
    result.issued.lifecycle.approvalNonce !== nonce ||
    result.envelope.approval_nonce !== nonce ||
    result.decisionResult.approval_nonce !== nonce ||
    result.commit.lifecycle.approvalNonce !== nonce
  ) {
    throw new Error("APPROVAL_NONCE_MISMATCH");
  }

  const commit = result.commit;
  if (!commit.committed || !commit.evidence.ok) throw new Error("TRANSACTION_EVIDENCE_NOT_COMMITTED");
  if (
    commit.evidence.reason !== "success" ||
    !commit.evidence.ledgerPath?.trim() ||
    !commit.evidence.receiptPath?.trim()
  ) throw new Error("TRANSACTION_EVIDENCE_INCOMPLETE");
  const lifecycle = commit.lifecycle;
  const base = {
    actionId: clean(actionId, nonce) ?? "",
    approvalNonceSha256: sha256(nonce),
    evidenceCommitted: true,
    evidenceReason: "success",
    ledgerPath: clean(commit.evidence.ledgerPath, nonce) ?? "",
    receiptPath: clean(commit.evidence.receiptPath, nonce) ?? "",
    humanReadableSummary: clean(result.decisionResult.human_readable_summary, nonce) ?? "",
    automaticExecutionAllowed: false,
    runtimeConnected: false,
    executionAuthorityGranted: false,
  } as const;
  const decision = result.decisionResult.decision;
  if (decision === "ALLOW") {
    if (lifecycle.phase !== "ALLOW_PENDING_EXECUTION" || lifecycle.decision !== "ALLOW" || lifecycle.nonceConsumed || lifecycle.parentEnvelopeInvalidated || lifecycle.childNoncesRequired) throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
    return { ...base, decision, lifecyclePhase: "ALLOW_PENDING_EXECUTION", nonceConsumed: false, parentEnvelopeInvalidated: false, childNoncesRequired: false };
  }
  if (decision === "WARN") {
    if (lifecycle.phase !== "WARN_PENDING" || lifecycle.decision !== "WARN" || lifecycle.nonceConsumed || lifecycle.parentEnvelopeInvalidated || lifecycle.childNoncesRequired) throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
    return { ...base, decision, lifecyclePhase: "WARN_PENDING", nonceConsumed: false, parentEnvelopeInvalidated: false, childNoncesRequired: false };
  }
  if (decision === "BLOCK") {
    if (lifecycle.phase !== "BLOCKED" || lifecycle.decision !== "BLOCK" || !lifecycle.nonceConsumed || lifecycle.parentEnvelopeInvalidated || lifecycle.childNoncesRequired) throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
    return { ...base, decision, lifecyclePhase: "BLOCKED", nonceConsumed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false };
  }
  if (decision === "REQUIRE_REVIEW") {
    if (lifecycle.phase !== "REQUIRE_REVIEW" || lifecycle.decision !== "REQUIRE_REVIEW" || !lifecycle.nonceConsumed || lifecycle.parentEnvelopeInvalidated || lifecycle.childNoncesRequired) throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
    return { ...base, decision, lifecyclePhase: "REQUIRE_REVIEW", nonceConsumed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false };
  }
  if (decision !== "SPLIT_REQUIRED") throw new Error("UNSUPPORTED_TRANSACTION_DECISION");
  if (lifecycle.phase !== "SPLIT_REQUIRED" || lifecycle.decision !== "SPLIT_REQUIRED" || !lifecycle.nonceConsumed || !lifecycle.parentEnvelopeInvalidated || !lifecycle.childNoncesRequired) throw new Error("TRANSACTION_DECISION_LIFECYCLE_MISMATCH");
  return { ...base, decision: "SPLIT_REQUIRED", lifecyclePhase: "SPLIT_REQUIRED", nonceConsumed: true, parentEnvelopeInvalidated: true, childNoncesRequired: true };
}

export function formatSafetyKernelV31TransactionOutput<
  R extends SafetyKernelV31TransactionServiceResult
>(
  result: R
): SafetyKernelV31TransactionOutputResultForDecision<R["decisionResult"]["decision"]>;
export function formatSafetyKernelV31TransactionOutput(
  result: SafetyKernelV31TransactionServiceResult
): SafetyKernelV31TransactionOutputResult {
  const record = buildSafetyKernelV31TransactionPublicRecord(result);
  const markdown = [
    "## Safety Kernel v3.1 Transaction",
    "",
    `- Action ID: ${record.actionId}`,
    `- Decision: ${record.decision}`,
    `- Approval nonce SHA-256: ${record.approvalNonceSha256}`,
    `- Lifecycle phase: ${record.lifecyclePhase}`,
    `- Nonce consumed: ${receiptBoolean(record.nonceConsumed)}`,
    `- Evidence committed: ${receiptBoolean(record.evidenceCommitted)}`,
    `- Evidence reason: ${record.evidenceReason}`,
    "- Automatic execution allowed: False",
    "- Runtime connected: False",
    "- Execution authority granted: False",
    "",
    record.humanReadableSummary,
  ].join("\n");
  const clipboardSummary = [
    "SAFETY_KERNEL_V31_TRANSACTION_OUTPUT=True",
    `ACTION_ID=${record.actionId}`,
    `DECISION=${record.decision}`,
    `APPROVAL_NONCE_SHA256=${record.approvalNonceSha256}`,
    `LIFECYCLE_PHASE=${record.lifecyclePhase}`,
    `NONCE_CONSUMED=${receiptBoolean(record.nonceConsumed)}`,
    `EVIDENCE_COMMITTED=${receiptBoolean(record.evidenceCommitted)}`,
    `EVIDENCE_REASON=${record.evidenceReason}`,
    `PARENT_ENVELOPE_INVALIDATED=${receiptBoolean(record.parentEnvelopeInvalidated)}`,
    `CHILD_NONCES_REQUIRED=${receiptBoolean(record.childNoncesRequired)}`,
    "RAW_APPROVAL_NONCE_EXPOSED=False",
    "AUTOMATIC_EXECUTION_ALLOWED=False",
    "RUNTIME_CONNECTED=False",
    "EXECUTION_AUTHORITY_GRANTED=False",
  ].join("\n");

  return {
    record,
    markdown,
    clipboardSummary,
    invariant: SAFETY_KERNEL_V31_TRANSACTION_OUTPUT_INVARIANT,
  };
}
