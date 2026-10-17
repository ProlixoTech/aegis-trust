import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";

import type { SafetyKernelV31EvidenceWriteResult } from "./safetyKernelV31EvidenceWriter";
import type { SafetyKernelV31NonceLifecycleRecord } from "./safetyKernelV31NonceLifecyclePolicy";
import {
  SAFETY_KERNEL_V31_POST_REVIEW_LIFECYCLE_OUTPUT_INVARIANT,
  buildSafetyKernelV31PostReviewLifecyclePublicRecord,
  formatSafetyKernelV31PostReviewLifecycleOutput,
} from "./safetyKernelV31PostReviewLifecycleOutput";
import type {
  SafetyKernelV31PostReviewLifecycleOutputResultForEvent,
  SafetyKernelV31PostReviewLifecyclePublicRecord,
  SafetyKernelV31PostReviewLifecyclePublicRecordForEvent,
} from "./safetyKernelV31PostReviewLifecycleOutput";

const postReviewRecordTypeBase = { actionId: "post-review-type-sentinel", approvalNonceSha256: "d".repeat(64), evidenceCommitted: true, evidenceReason: "success", ledgerPath: "/tmp/post-review-type-evidence.jsonl", receiptPath: "/tmp/post-review-type-receipt.md", warnMustNeverAutoProceed: true, automaticExecutionAllowed: false, runtimeConnected: false, executionAuthorityGranted: false } as const;
// @ts-expect-error WARN confirmation must remain pending with an unconsumed nonce
const invalidWarnConfirmedPublicRecord: SafetyKernelV31PostReviewLifecyclePublicRecord = { ...postReviewRecordTypeBase, event: "WARN_CONFIRMED", lifecyclePhase: "CONSUMED", nonceConsumed: true };
// @ts-expect-error allowed execution completion must report a consumed lifecycle
const invalidAllowedCompletionPublicRecord: SafetyKernelV31PostReviewLifecyclePublicRecord = { ...postReviewRecordTypeBase, event: "ALLOWED_EXECUTION_COMPLETED", lifecyclePhase: "ALLOW_PENDING_EXECUTION", nonceConsumed: false };
// @ts-expect-error WARN termination must report a consumed lifecycle
const invalidWarnTerminationPublicRecord: SafetyKernelV31PostReviewLifecyclePublicRecord = { ...postReviewRecordTypeBase, event: "WARN_TERMINATED", lifecyclePhase: "WARN_PENDING", nonceConsumed: false };
// @ts-expect-error successful public lifecycle evidence requires durable paths
const invalidPostReviewEvidencePublicRecord: SafetyKernelV31PostReviewLifecyclePublicRecord = { ...postReviewRecordTypeBase, event: "WARN_CONFIRMED", lifecyclePhase: "ALLOW_PENDING_EXECUTION", nonceConsumed: false, ledgerPath: null };
void invalidWarnConfirmedPublicRecord;
void invalidAllowedCompletionPublicRecord;
void invalidWarnTerminationPublicRecord;
void invalidPostReviewEvidencePublicRecord;

if (false) {
  const committedEvidenceType = {} as Extract<SafetyKernelV31EvidenceWriteResult, { ok: true }>;
  const allowPendingLifecycleType = {} as Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }>;
  const allowConsumedLifecycleType = {} as Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED"; decision: "ALLOW" }>;
  const warnConsumedLifecycleType = {} as Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED"; decision: "WARN" }>;
  const warnRecordType = buildSafetyKernelV31PostReviewLifecyclePublicRecord("WARN_CONFIRMED", allowPendingLifecycleType, committedEvidenceType);
  const expectedWarnRecordType: SafetyKernelV31PostReviewLifecyclePublicRecordForEvent<"WARN_CONFIRMED"> = warnRecordType;
  // @ts-expect-error WARN-confirmed builder result cannot expose allowed-completion event
  const invalidWarnRecordEventType: SafetyKernelV31PostReviewLifecyclePublicRecordForEvent<"ALLOWED_EXECUTION_COMPLETED"> = warnRecordType;
  const allowedOutputType = formatSafetyKernelV31PostReviewLifecycleOutput("ALLOWED_EXECUTION_COMPLETED", allowConsumedLifecycleType, committedEvidenceType);
  const expectedAllowedOutputType: SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"ALLOWED_EXECUTION_COMPLETED"> = allowedOutputType;
  // @ts-expect-error allowed-completion formatter result cannot expose WARN-termination event
  const invalidAllowedOutputEventType: SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"WARN_TERMINATED"> = allowedOutputType;
  const terminatedOutputType = formatSafetyKernelV31PostReviewLifecycleOutput("WARN_TERMINATED", warnConsumedLifecycleType, committedEvidenceType);
  const expectedTerminatedOutputType: SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"WARN_TERMINATED"> = terminatedOutputType;
  // @ts-expect-error WARN-termination formatter result cannot expose WARN-confirmation event
  const invalidTerminatedOutputEventType: SafetyKernelV31PostReviewLifecycleOutputResultForEvent<"WARN_CONFIRMED"> = terminatedOutputType;
  void expectedWarnRecordType;
  void invalidWarnRecordEventType;
  void expectedAllowedOutputType;
  void invalidAllowedOutputEventType;
  void expectedTerminatedOutputType;
  void invalidTerminatedOutputEventType;
}

const NONCE = "c".repeat(64);

function lifecycle(
  phase: "ALLOW_PENDING_EXECUTION",
  decision: "ALLOW",
  nonceConsumed: false,
  actionId?: string
): Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }>;
function lifecycle(
  phase: "WARN_PENDING",
  decision: "WARN",
  nonceConsumed: false,
  actionId?: string
): Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "WARN_PENDING" }>;
function lifecycle(
  phase: "CONSUMED",
  decision: "ALLOW" | "WARN",
  nonceConsumed: true,
  actionId?: string
): Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }>;
function lifecycle(
  phase: "ALLOW_PENDING_EXECUTION" | "WARN_PENDING" | "CONSUMED",
  decision: "ALLOW" | "WARN",
  nonceConsumed: boolean,
  actionId = "post-review-action"
): SafetyKernelV31NonceLifecycleRecord {
  const base = { actionId, approvalNonce: NONCE, warnMustNeverAutoProceed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false, receiptRequired: true, ledgerRequired: true } as const;
  if (phase === "WARN_PENDING") {
    if (decision !== "WARN" || nonceConsumed) throw new Error("INVALID_WARN_FIXTURE");
    return { ...base, phase, decision, nonceConsumed: false, warnTimeoutSeconds: 60 };
  }
  if (phase === "ALLOW_PENDING_EXECUTION") {
    if (decision !== "ALLOW" || nonceConsumed) throw new Error("INVALID_ALLOW_FIXTURE");
    return { ...base, phase, decision, nonceConsumed: false };
  }
  if (!nonceConsumed) throw new Error("INVALID_CONSUMED_FIXTURE");
  return { ...base, phase, decision, nonceConsumed: true };
}

const evidence: SafetyKernelV31EvidenceWriteResult = {
  ok: true,
  ledgerPath: "/tmp/post-review-evidence.jsonl",
  receiptPath: "/tmp/post-review-receipt.md",
  reason: "success",
};

// @ts-expect-error successful evidence requires both durable paths
const invalidSuccessEvidenceTypeCheck: SafetyKernelV31EvidenceWriteResult = { ok: true, ledgerPath: null, receiptPath: "/tmp/receipt.md", reason: "success" };
// @ts-expect-error failed evidence cannot claim success or retain a durable path
const invalidFailureEvidenceTypeCheck: SafetyKernelV31EvidenceWriteResult = { ok: false, ledgerPath: "/tmp/evidence.jsonl", receiptPath: null, reason: "success" };
void invalidSuccessEvidenceTypeCheck;
void invalidFailureEvidenceTypeCheck;

test("post-review lifecycle output invariant remains nonce-safe, evidence-first, disconnected, and non-executing", () => {
  assert.deepEqual(SAFETY_KERNEL_V31_POST_REVIEW_LIFECYCLE_OUTPUT_INVARIANT, {
    RAW_APPROVAL_NONCE_EXPOSED: false,
    APPROVAL_NONCE_SHA256_ONLY: true,
    EVIDENCE_FIRST_ALLOWED_COMPLETION_REQUIRED: true,
    EVIDENCE_FIRST_TERMINATION_REQUIRED: true,
    AUTOMATIC_EXECUTION_ALLOWED: false,
    RUNTIME_CONNECTED: false,
    EXECUTION_AUTHORITY_GRANTED: false,
  });
});

test("post-review lifecycle output formats WARN confirmation with evidence without exposing the raw nonce", () => {
  const record = buildSafetyKernelV31PostReviewLifecyclePublicRecord(
    "WARN_CONFIRMED",
    lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false),
    evidence
  );
  const expected = crypto.createHash("sha256").update(NONCE, "utf8").digest("hex");
  assert.equal(record.approvalNonceSha256, expected);
  assert.equal(record.lifecyclePhase, "ALLOW_PENDING_EXECUTION");
  assert.equal(record.evidenceCommitted, true);
  assert.equal(record.evidenceReason, "success");
  assert.equal(JSON.stringify(record).includes(NONCE), false);
  assert.equal(Object.prototype.hasOwnProperty.call(record, "approvalNonce"), false);
});

test("post-review lifecycle output rejects an empty approval nonce", () => {
  const invalidLifecycle = {
    ...lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false),
    approvalNonce: "",
  };

  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_CONFIRMED",
      invalidLifecycle,
      evidence
    ),
    /INVALID_APPROVAL_NONCE/
  );
});

test("post-review lifecycle output rejects WARN confirmation without evidence", () => {
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_CONFIRMED",
      lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false)
    ),
    /WARN_CONFIRMATION_EVIDENCE_REQUIRED/
  );
});

test("post-review lifecycle output rejects unsuccessful evidence for every lifecycle event", () => {
  const failedEvidence = {
    ...evidence,
    ok: false as const,
    reason: "write_failed" as const,
    ledgerPath: null,
    receiptPath: null,
  };
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_CONFIRMED",
      lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false),
      failedEvidence
    ),
    /POST_REVIEW_LIFECYCLE_EVIDENCE_NOT_COMMITTED/
  );
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "ALLOWED_EXECUTION_COMPLETED",
      lifecycle("CONSUMED", "ALLOW", true),
      failedEvidence
    ),
    /POST_REVIEW_LIFECYCLE_EVIDENCE_NOT_COMMITTED/
  );
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_TERMINATED",
      lifecycle("CONSUMED", "WARN", true),
      failedEvidence
    ),
    /POST_REVIEW_LIFECYCLE_EVIDENCE_NOT_COMMITTED/
  );
});

test("post-review lifecycle output rejects incomplete successful evidence", () => {
  const missingLedger = { ...evidence, ledgerPath: null } as unknown as SafetyKernelV31EvidenceWriteResult;
  const missingReceipt = { ...evidence, receiptPath: null } as unknown as SafetyKernelV31EvidenceWriteResult;
  const inconsistentReason = { ...evidence, reason: "write_failed" } as unknown as SafetyKernelV31EvidenceWriteResult;

  for (const incompleteEvidence of [missingLedger, missingReceipt, inconsistentReason]) {
    assert.throws(
      () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
        "WARN_CONFIRMED",
        lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false),
        incompleteEvidence
      ),
      /POST_REVIEW_LIFECYCLE_EVIDENCE_INCOMPLETE/
    );
  }
});

test("post-review lifecycle output formats allowed execution completion as consumed and non-authoritative", () => {
  const output = formatSafetyKernelV31PostReviewLifecycleOutput(
    "ALLOWED_EXECUTION_COMPLETED",
    lifecycle("CONSUMED", "ALLOW", true),
    evidence
  );
  assert.equal(output.record.nonceConsumed, true);
  assert.equal(output.clipboardSummary.includes("NONCE_CONSUMED=True"), true);
  assert.equal(output.clipboardSummary.includes("EVIDENCE_COMMITTED=True"), true);
  assert.equal(output.clipboardSummary.includes("RAW_APPROVAL_NONCE_EXPOSED=False"), true);
  assert.equal(output.clipboardSummary.includes("EXECUTION_AUTHORITY_GRANTED=False"), true);
  assert.equal(output.clipboardSummary.includes(NONCE), false);
});

test("post-review lifecycle output requires and sanitizes WARN termination evidence", () => {
  const sensitiveEvidence: SafetyKernelV31EvidenceWriteResult = {
    ...evidence,
    ledgerPath: `/tmp/${NONCE}/evidence.jsonl`,
    receiptPath: `/tmp/${NONCE}/receipt.md`,
  };
  const output = formatSafetyKernelV31PostReviewLifecycleOutput(
    "WARN_TERMINATED",
    lifecycle("CONSUMED", "WARN", true, `action-${NONCE}`),
    sensitiveEvidence
  );
  assert.equal(output.record.evidenceCommitted, true);
  assert.equal(output.record.evidenceReason, "success");
  assert.equal(JSON.stringify(output).includes(NONCE), false);
  assert.equal(output.record.actionId.includes("<redacted-nonce>"), true);
  assert.equal(output.record.ledgerPath?.includes("<redacted-nonce>"), true);
  assert.equal(output.record.receiptPath?.includes("<redacted-nonce>"), true);
});

test("post-review lifecycle output rejects missing evidence and invalid lifecycle phases", () => {
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_TERMINATED",
      lifecycle("CONSUMED", "WARN", true)
    ),
    /WARN_TERMINATION_EVIDENCE_REQUIRED/
  );
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "ALLOWED_EXECUTION_COMPLETED",
      lifecycle("CONSUMED", "ALLOW", true)
    ),
    /ALLOWED_EXECUTION_COMPLETION_EVIDENCE_REQUIRED/
  );
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_CONFIRMED",
      lifecycle("WARN_PENDING", "WARN", false)
    ),
    /INVALID_WARN_CONFIRMED_PHASE/
  );
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "ALLOWED_EXECUTION_COMPLETED",
      lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false)
    ),
    /INVALID_ALLOWED_EXECUTION_COMPLETION_PHASE/
  );
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "ALLOWED_EXECUTION_COMPLETED",
      lifecycle("CONSUMED", "WARN", true),
      evidence
    ),
    /INVALID_ALLOWED_EXECUTION_COMPLETION_PHASE/
  );
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_TERMINATED",
      lifecycle("CONSUMED", "ALLOW", true),
      evidence
    ),
    /INVALID_WARN_TERMINATED_PHASE/
  );
});

test("post-review lifecycle output rejects blank action ids and blank evidence paths", () => {
  const blankActionLifecycle = {
    ...lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false),
    actionId: "   ",
  };
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_CONFIRMED",
      blankActionLifecycle,
      evidence
    ),
    /INVALID_ACTION_ID/
  );

  const blankLedger = { ...evidence, ledgerPath: "   " } as SafetyKernelV31EvidenceWriteResult;
  const blankReceipt = { ...evidence, receiptPath: "\t\n" } as SafetyKernelV31EvidenceWriteResult;
  for (const incompleteEvidence of [blankLedger, blankReceipt]) {
    assert.throws(
      () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
        "WARN_CONFIRMED",
        lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false),
        incompleteEvidence
      ),
      /POST_REVIEW_LIFECYCLE_EVIDENCE_INCOMPLETE/
    );
  }
});

test("post-review lifecycle output normalizes bounded public fields without mutating inputs", () => {
  const lifecycleInput = {
    ...lifecycle("CONSUMED", "WARN", true),
    actionId: `  action\t${NONCE}\n${"x".repeat(400)}  `,
  };
  const evidenceInput: SafetyKernelV31EvidenceWriteResult = {
    ok: true,
    ledgerPath: `  /tmp/${NONCE}/\t${"l".repeat(400)}.jsonl  `,
    receiptPath: `\n/tmp/${NONCE}/  ${"r".repeat(400)}.md  `,
    reason: "success",
  };
  const lifecycleBefore = JSON.stringify(lifecycleInput);
  const evidenceBefore = JSON.stringify(evidenceInput);

  const output = formatSafetyKernelV31PostReviewLifecycleOutput(
    "WARN_TERMINATED",
    lifecycleInput,
    evidenceInput
  );
  const expectedHash = crypto.createHash("sha256").update(NONCE, "utf8").digest("hex");
  assert.equal(output.record.approvalNonceSha256, expectedHash);

  for (const value of [
    output.record.actionId,
    output.record.ledgerPath,
    output.record.receiptPath,
  ]) {
    assert.equal(value.length, 320);
    assert.equal(value.includes("<redacted-nonce>"), true);
    assert.equal(value.includes(NONCE), false);
    assert.equal(/[\t\r\n]/.test(value), false);
    assert.equal(/\s{2,}/.test(value), false);
  }

  assert.equal(JSON.stringify(output).includes(NONCE), false);
  assert.equal(output.markdown.includes(NONCE), false);
  assert.equal(output.clipboardSummary.includes(NONCE), false);
  assert.equal(JSON.stringify(lifecycleInput), lifecycleBefore);
  assert.equal(JSON.stringify(evidenceInput), evidenceBefore);
  assert.equal(
    output.invariant,
    SAFETY_KERNEL_V31_POST_REVIEW_LIFECYCLE_OUTPUT_INVARIANT
  );
});

test("post-review lifecycle output rejects an unsupported event before WARN_TERMINATED fallback", () => {
  const unsupportedEvent = "UNSUPPORTED_EVENT" as unknown as Parameters<
    typeof buildSafetyKernelV31PostReviewLifecyclePublicRecord
  >[0];

  assert.throws(
    () =>
      buildSafetyKernelV31PostReviewLifecyclePublicRecord(
        unsupportedEvent,
        lifecycle("CONSUMED", "WARN", true),
        evidence
      ),
    /UNSUPPORTED_POST_REVIEW_LIFECYCLE_EVENT/
  );
});

test("post-review lifecycle output rejects a WARN confirmation with only the phase mismatched", () => {
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_CONFIRMED",
      { ...lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false), phase: "WARN_PENDING" } as unknown as SafetyKernelV31NonceLifecycleRecord,
      evidence
    ),
    /INVALID_WARN_CONFIRMED_PHASE/
  );
});

test("post-review lifecycle output rejects a WARN confirmation with only the decision mismatched", () => {
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_CONFIRMED",
      { ...lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false), decision: "WARN" } as unknown as SafetyKernelV31NonceLifecycleRecord,
      evidence
    ),
    /INVALID_WARN_CONFIRMED_PHASE/
  );
});

test("post-review lifecycle output rejects a WARN confirmation with only nonce consumption mismatched", () => {
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_CONFIRMED",
      { ...lifecycle("ALLOW_PENDING_EXECUTION", "ALLOW", false), nonceConsumed: true } as unknown as SafetyKernelV31NonceLifecycleRecord,
      evidence
    ),
    /INVALID_WARN_CONFIRMED_PHASE/
  );
});

test("post-review lifecycle output rejects an allowed execution completion with only the phase mismatched", () => {
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "ALLOWED_EXECUTION_COMPLETED",
      { ...lifecycle("CONSUMED", "ALLOW", true), phase: "ALLOW_PENDING_EXECUTION" } as unknown as SafetyKernelV31NonceLifecycleRecord,
      evidence
    ),
    /INVALID_ALLOWED_EXECUTION_COMPLETION_PHASE/
  );
});

test("post-review lifecycle output rejects an allowed execution completion with only nonce consumption mismatched", () => {
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "ALLOWED_EXECUTION_COMPLETED",
      { ...lifecycle("CONSUMED", "ALLOW", true), nonceConsumed: false } as unknown as SafetyKernelV31NonceLifecycleRecord,
      evidence
    ),
    /INVALID_ALLOWED_EXECUTION_COMPLETION_PHASE/
  );
});

test("post-review lifecycle output rejects a WARN termination with only the phase mismatched", () => {
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_TERMINATED",
      { ...lifecycle("CONSUMED", "WARN", true), phase: "WARN_PENDING" } as unknown as SafetyKernelV31NonceLifecycleRecord,
      evidence
    ),
    /INVALID_WARN_TERMINATED_PHASE/
  );
});

test("post-review lifecycle output rejects a WARN termination with only nonce consumption mismatched", () => {
  assert.throws(
    () => buildSafetyKernelV31PostReviewLifecyclePublicRecord(
      "WARN_TERMINATED",
      { ...lifecycle("CONSUMED", "WARN", true), nonceConsumed: false } as unknown as SafetyKernelV31NonceLifecycleRecord,
      evidence
    ),
    /INVALID_WARN_TERMINATED_PHASE/
  );
});
