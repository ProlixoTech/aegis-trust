import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";

import type { SafetyKernelV31TransactionServiceResult } from "./safetyKernelV31TransactionService";
import type { SafetyKernelV31NonceLifecycleRecord } from "./safetyKernelV31NonceLifecyclePolicy";
import {
  SAFETY_KERNEL_V31_TRANSACTION_OUTPUT_INVARIANT,
  buildSafetyKernelV31TransactionPublicRecord,
  formatSafetyKernelV31TransactionOutput,
} from "./safetyKernelV31TransactionOutput";
import type {
  SafetyKernelV31TransactionOutputResultForDecision,
  SafetyKernelV31TransactionPublicRecord,
  SafetyKernelV31TransactionPublicRecordForDecision,
} from "./safetyKernelV31TransactionOutput";

const transactionRecordTypeBase = { actionId: "transaction-type-sentinel", approvalNonceSha256: "e".repeat(64), evidenceCommitted: true, evidenceReason: "success", ledgerPath: "/tmp/transaction-type-evidence.jsonl", receiptPath: "/tmp/transaction-type-receipt.md", humanReadableSummary: "type sentinel", automaticExecutionAllowed: false, runtimeConnected: false, executionAuthorityGranted: false } as const;
// @ts-expect-error ALLOW must remain pending with an unconsumed nonce
const invalidAllowTransactionRecord: SafetyKernelV31TransactionPublicRecord = { ...transactionRecordTypeBase, decision: "ALLOW", lifecyclePhase: "BLOCKED", nonceConsumed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false };
// @ts-expect-error WARN must map to WARN_PENDING
const invalidWarnTransactionRecord: SafetyKernelV31TransactionPublicRecord = { ...transactionRecordTypeBase, decision: "WARN", lifecyclePhase: "CONSUMED", nonceConsumed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false };
// @ts-expect-error SPLIT_REQUIRED requires parent invalidation and child nonces
const invalidSplitTransactionRecord: SafetyKernelV31TransactionPublicRecord = { ...transactionRecordTypeBase, decision: "SPLIT_REQUIRED", lifecyclePhase: "SPLIT_REQUIRED", nonceConsumed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false };
// @ts-expect-error successful transaction evidence requires durable paths
const invalidTransactionEvidenceRecord: SafetyKernelV31TransactionPublicRecord = { ...transactionRecordTypeBase, decision: "REQUIRE_REVIEW", lifecyclePhase: "REQUIRE_REVIEW", nonceConsumed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false, ledgerPath: null };
void invalidAllowTransactionRecord;
void invalidWarnTransactionRecord;
void invalidSplitTransactionRecord;
void invalidTransactionEvidenceRecord;

if (false) {
  const allowServiceResultType = {} as Extract<SafetyKernelV31TransactionServiceResult, { decisionResult: { decision: "ALLOW" } }>;
  const warnServiceResultType = {} as Extract<SafetyKernelV31TransactionServiceResult, { decisionResult: { decision: "WARN" } }>;
  const blockServiceResultType = {} as Extract<SafetyKernelV31TransactionServiceResult, { decisionResult: { decision: "BLOCK" } }>;
  const allowRecordType = buildSafetyKernelV31TransactionPublicRecord(allowServiceResultType);
  const expectedAllowRecordType: SafetyKernelV31TransactionPublicRecordForDecision<"ALLOW"> = allowRecordType;
  // @ts-expect-error ALLOW builder result cannot expose WARN decision
  const invalidAllowRecordDecisionType: SafetyKernelV31TransactionPublicRecordForDecision<"WARN"> = allowRecordType;
  const warnOutputType = formatSafetyKernelV31TransactionOutput(warnServiceResultType);
  const expectedWarnOutputType: SafetyKernelV31TransactionOutputResultForDecision<"WARN"> = warnOutputType;
  // @ts-expect-error WARN formatter result cannot expose BLOCK decision
  const invalidWarnOutputDecisionType: SafetyKernelV31TransactionOutputResultForDecision<"BLOCK"> = warnOutputType;
  const blockOutputType = formatSafetyKernelV31TransactionOutput(blockServiceResultType);
  const expectedBlockOutputType: SafetyKernelV31TransactionOutputResultForDecision<"BLOCK"> = blockOutputType;
  // @ts-expect-error BLOCK formatter result cannot expose ALLOW decision
  const invalidBlockOutputDecisionType: SafetyKernelV31TransactionOutputResultForDecision<"ALLOW"> = blockOutputType;
  void expectedAllowRecordType;
  void invalidAllowRecordDecisionType;
  void expectedWarnOutputType;
  void invalidWarnOutputDecisionType;
  void expectedBlockOutputType;
  void invalidBlockOutputDecisionType;
}

const NONCE = "a".repeat(64);

function makeResult(): SafetyKernelV31TransactionServiceResult {
  const issuedLifecycle: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ISSUED" }> = { actionId: "action-output", approvalNonce: NONCE, phase: "ISSUED", decision: null, nonceConsumed: false, warnMustNeverAutoProceed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false, receiptRequired: true, ledgerRequired: true };
  const lifecycle: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "REQUIRE_REVIEW" }> = {
    actionId: "action-output",
    approvalNonce: NONCE,
    phase: "REQUIRE_REVIEW" as const,
    decision: "REQUIRE_REVIEW" as const,
    nonceConsumed: true,
    warnMustNeverAutoProceed: true as const,
    parentEnvelopeInvalidated: false,
    childNoncesRequired: false,
    receiptRequired: true as const,
    ledgerRequired: true as const,
  };

  return {
    issued: {
      approvalNonce: NONCE,
      lifecycle: issuedLifecycle,
      randomByteLength: 32,
      randomSource: "crypto.randomBytes",
    },
    envelope: {
      action_id: "action-output",
      source: "manual_review",
      target: "src/example.ts",
      intent: "format transaction output",
      proposed_action: "read-only diagnostic",
      risk_class: "low",
      context_hash: "sha256:abc",
      timestamp: "2026-01-01T00:00:00.000Z",
      adapter_id: "safetyKernelV31TransactionOutput.test",
      human_readable_summary: "Transaction output test",
      capability_requested: {
        operation_class: "read",
        scope: "specific_file",
        manner: "preview_only",
      },
      mutation_scope: {
        scope: "specific_file",
        target: "src/example.ts",
        protected_target: false,
      },
      approval_nonce: NONCE,
      policy_version: "policy-test",
    },
    decisionResult: {
      action_id: "action-output",
      decision: "REQUIRE_REVIEW",
      approval_nonce: NONCE,
      policy_version: "policy-test",
      reasons: ["review required"],
      detectedEffects: [],
      human_readable_summary: "Transaction output test",
      receipt_required: true,
      ledger_required: true,
    },
    commit: {
      committed: true,
      lifecycle,
      evidence: {
        ok: true,
        ledgerPath: "/tmp/evidence.jsonl",
        receiptPath: "/tmp/receipt.md",
        reason: "success",
      },
    },
  };
}

test("transaction output invariant exposes only nonce SHA-256 and remains disconnected and non-executing", () => {
  assert.deepEqual(SAFETY_KERNEL_V31_TRANSACTION_OUTPUT_INVARIANT, {
    RAW_APPROVAL_NONCE_EXPOSED: false,
    APPROVAL_NONCE_SHA256_ONLY: true,
    AUTOMATIC_EXECUTION_ALLOWED: false,
    RUNTIME_CONNECTED: false,
    EXECUTION_AUTHORITY_GRANTED: false,
  });
});

test("transaction public record hashes the nonce and does not expose the raw nonce", () => {
  const record = buildSafetyKernelV31TransactionPublicRecord(makeResult());
  const expected = crypto.createHash("sha256").update(NONCE, "utf8").digest("hex");

  assert.equal(record.approvalNonceSha256, expected);
  assert.equal(record.actionId, "action-output");
  assert.equal(record.decision, "REQUIRE_REVIEW");
  assert.equal(record.lifecyclePhase, "REQUIRE_REVIEW");
  assert.equal(record.nonceConsumed, true);
  assert.equal(record.evidenceCommitted, true);
  assert.equal(JSON.stringify(record).includes(NONCE), false);
  assert.equal(Object.prototype.hasOwnProperty.call(record, "approvalNonce"), false);
});

test("transaction output markdown and clipboard contain the hash but never the raw nonce", () => {
  const output = formatSafetyKernelV31TransactionOutput(makeResult());

  assert.equal(output.markdown.includes(NONCE), false);
  assert.equal(output.clipboardSummary.includes(NONCE), false);
  assert.equal(output.markdown.includes(output.record.approvalNonceSha256), true);
  assert.equal(output.clipboardSummary.includes(output.record.approvalNonceSha256), true);
  assert.equal(output.clipboardSummary.includes("RAW_APPROVAL_NONCE_EXPOSED=False"), true);
  assert.equal(output.clipboardSummary.includes("AUTOMATIC_EXECUTION_ALLOWED=False"), true);
  assert.equal(output.clipboardSummary.includes("RUNTIME_CONNECTED=False"), true);
  assert.equal(output.clipboardSummary.includes("EXECUTION_AUTHORITY_GRANTED=False"), true);
});

test("transaction output redacts nonce occurrences from public text fields", () => {
  const result = makeResult();
  result.issued.lifecycle = {
    ...result.issued.lifecycle,
    actionId: `action-${NONCE}`,
  };
  result.envelope = {
    ...result.envelope,
    action_id: `action-${NONCE}`,
  };
  result.decisionResult = {
    ...result.decisionResult,
    action_id: `action-${NONCE}`,
    human_readable_summary: `summary ${NONCE}`,
  };
  result.commit = {
    committed: true,
    lifecycle: {
      ...result.commit.lifecycle,
      actionId: `action-${NONCE}`,
    },
    evidence: {
      ok: true,
      reason: "success",
      ledgerPath: `/imp/${NONCE}/evidence.jsonl`,
      receiptPath: `/imp/${NONCE}/receipt.md`,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];

  const output = formatSafetyKernelV31TransactionOutput(result);

  assert.equal(JSON.stringify(output).includes(NONCE), false);
  assert.equal(output.record.actionId.includes("<redacted-nonce>"), true);
  assert.equal(output.record.humanReadableSummary.includes("<redacted-nonce>"), true);
  assert.equal(output.record.ledgerPath?.includes("<redacted-nonce>"), true);
  assert.equal(output.record.receiptPath?.includes("<redacted-nonce>"), true);
});

test("transaction output rejects an empty approval nonce", () => {
  const result = makeResult();
  result.issued = { ...result.issued, approvalNonce: "" };

  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_APPROVAL_NONCE/
  );
});

test("transaction output rejects mismatched action ids before formatting", () => {
  const result = makeResult();
  result.envelope = { ...result.envelope, action_id: "other-action" };

  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /ACTION_ID_MISMATCH/
  );
});

test("transaction output rejects mismatched nonce bindings before formatting", () => {
  const result = makeResult();
  result.decisionResult = {
    ...result.decisionResult,
    approval_nonce: "b".repeat(64),
  };

  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /APPROVAL_NONCE_MISMATCH/
  );
});

test("transaction output rejects uncommitted or incomplete evidence", () => {
  const uncommitted = makeResult();
  uncommitted.commit = {
    committed: false,
    lifecycle: uncommitted.commit.lifecycle,
    evidence: { ok: false, ledgerPath: null, receiptPath: null, reason: "write_failed" },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(() => buildSafetyKernelV31TransactionPublicRecord(uncommitted), /TRANSACTION_EVIDENCE_NOT_COMMITTED/);

  const incomplete = makeResult();
  incomplete.commit = {
    ...incomplete.commit,
    evidence: { ok: true, ledgerPath: null, receiptPath: "/tmp/receipt.md", reason: "success" },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(() => buildSafetyKernelV31TransactionPublicRecord(incomplete), /TRANSACTION_EVIDENCE_INCOMPLETE/);
});

test("transaction output rejects decision and lifecycle mismatches", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "ALLOW" };
  assert.throws(() => buildSafetyKernelV31TransactionPublicRecord(result), /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/);
});


test("valid transaction outputs are produced for all remaining decisions", () => {
  const cases = [
    { decision: "ALLOW", phase: "ALLOW_PENDING_EXECUTION", nonceConsumed: false, parentEnvelopeInvalidated: false, childNoncesRequired: false },
    { decision: "WARN", phase: "WARN_PENDING", nonceConsumed: false, parentEnvelopeInvalidated: false, childNoncesRequired: false },
    { decision: "BLOCK", phase: "BLOCKED", nonceConsumed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false },
    { decision: "SPLIT_REQUIRED", phase: "SPLIT_REQUIRED", nonceConsumed: true, parentEnvelopeInvalidated: true, childNoncesRequired: true },
  ] as const;

  for (const expected of cases) {
    const result = makeResult();
    const lifecycle = {
      ...result.commit.lifecycle,
      phase: expected.phase,
      decision: expected.decision,
      nonceConsumed: expected.nonceConsumed,
      parentEnvelopeInvalidated: expected.parentEnvelopeInvalidated,
      childNoncesRequired: expected.childNoncesRequired,
    } as SafetyKernelV31NonceLifecycleRecord;
    result.decisionResult = { ...result.decisionResult, decision: expected.decision };
    result.commit = { ...result.commit, lifecycle } as unknown as SafetyKernelV31TransactionServiceResult["commit"];

    const output = formatSafetyKernelV31TransactionOutput(result);
    assert.equal(output.record.decision, expected.decision);
    assert.equal(output.record.lifecyclePhase, expected.phase);
    assert.equal(output.record.nonceConsumed, expected.nonceConsumed);
    assert.equal(output.record.parentEnvelopeInvalidated, expected.parentEnvelopeInvalidated);
    assert.equal(output.record.childNoncesRequired, expected.childNoncesRequired);
    assert.equal(output.markdown.includes(`- Decision: ${expected.decision}`), true);
    assert.equal(output.clipboardSummary.includes(`DECISION=${expected.decision}`), true);
    assert.equal(output.clipboardSummary.includes(`LIFECYCLE_PHASE=${expected.phase}`), true);
  }
});


test("transaction output rejects an empty action id", () => {
  const result = {
    issued: {
      approvalNonce: "nonce-empty-action",
      lifecycle: { actionId: "   ", approvalNonce: "nonce-empty-action" },
    },
  } as unknown as SafetyKernelV31TransactionServiceResult;
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ACTION_ID/
  );
});


test("transaction output normalizes a null human-readable summary to an empty string", () => {
  const result = makeResult();
  result.decisionResult = {
    ...result.decisionResult,
    human_readable_summary: null as unknown as string,
  };
  const record = buildSafetyKernelV31TransactionPublicRecord(result);
  assert.equal(record.humanReadableSummary, "");
});

test("transaction output rejects blank evidence paths and inconsistent success reason", () => {
  const blankLedger = makeResult();
  blankLedger.commit = {
    ...blankLedger.commit,
    evidence: {
      ok: true,
      ledgerPath: "   ",
      receiptPath: "/tmp/receipt.md",
      reason: "success",
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];

  const blankReceipt = makeResult();
  blankReceipt.commit = {
    ...blankReceipt.commit,
    evidence: {
      ok: true,
      ledgerPath: "/tmp/evidence.jsonl",
      receiptPath: "\t\n",
      reason: "success",
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];

  const inconsistentReason = makeResult();
  inconsistentReason.commit = {
    ...inconsistentReason.commit,
    evidence: {
      ok: true,
      ledgerPath: "/tmp/evidence.jsonl",
      receiptPath: "/tmp/receipt.md",
      reason: "write_failed",
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];

  for (const result of [blankLedger, blankReceipt, inconsistentReason]) {
    assert.throws(
      () => buildSafetyKernelV31TransactionPublicRecord(result),
      /TRANSACTION_EVIDENCE_INCOMPLETE/
    );
  }
});

test("transaction output normalizes bounded public fields, preserves raw nonce hashing, bindings, and input immutability", () => {
  const rawNonce = "raw-transaction-output-nonce";
  const longTail = "x".repeat(400);
  const rawActionId = `  action ${rawNonce}\n${longTail}  `;
  const rawSummary = `  summary\t${rawNonce}\n${longTail}  `;
  const rawLedgerPath = `  /tmp/${rawNonce}/ledger\n${longTail}.jsonl  `;
  const rawReceiptPath = `  /tmp/${rawNonce}/receipt\t${longTail}.md  `;
  const result = makeResult();
  const lifecycle = {
    ...result.commit.lifecycle,
    actionId: rawActionId,
    approvalNonce: rawNonce,
  } as SafetyKernelV31NonceLifecycleRecord;
  result.issued = {
    ...result.issued,
    approvalNonce: rawNonce,
    lifecycle: {
      ...result.issued.lifecycle,
      actionId: rawActionId,
      approvalNonce: rawNonce,
    },
  };
  result.envelope = {
    ...result.envelope,
    action_id: rawActionId,
    approval_nonce: rawNonce,
  };
  result.decisionResult = {
    ...result.decisionResult,
    action_id: rawActionId,
    approval_nonce: rawNonce,
    human_readable_summary: rawSummary,
  };
  result.commit = {
    committed: true,
    lifecycle,
    evidence: {
      ok: true,
      reason: "success",
      ledgerPath: rawLedgerPath,
      receiptPath: rawReceiptPath,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  const inputBefore = JSON.stringify(result);

  const output = formatSafetyKernelV31TransactionOutput(result);
  const expectedHash = crypto.createHash("sha256").update(rawNonce, "utf8").digest("hex");
  assert.equal(output.record.approvalNonceSha256, expectedHash);
  for (const value of [
    output.record.actionId,
    output.record.humanReadableSummary,
    output.record.ledgerPath,
    output.record.receiptPath,
  ]) {
    assert.equal(value.length, 320);
    assert.equal(value.includes("<redacted-nonce>"), true);
    assert.equal(value.includes(rawNonce), false);
    assert.equal(/[\t\r\n]/.test(value), false);
    assert.equal(/\s{2,}/.test(value), false);
  }
  assert.equal(JSON.stringify(output.record).includes(rawNonce), false);
  assert.equal(output.markdown.includes(rawNonce), false);
  assert.equal(output.clipboardSummary.includes(rawNonce), false);
  assert.equal(output.invariant, SAFETY_KERNEL_V31_TRANSACTION_OUTPUT_INVARIANT);
  assert.equal(JSON.stringify(result), inputBefore);

  const actionMismatchCases: Array<
    (value: SafetyKernelV31TransactionServiceResult) => void
  > = [
    (value) => {
      value.envelope = { ...value.envelope, action_id: "other-action" };
    },
    (value) => {
      value.decisionResult = { ...value.decisionResult, action_id: "other-action" };
    },
    (value) => {
      value.commit = {
        ...value.commit,
        lifecycle: { ...value.commit.lifecycle, actionId: "other-action" },
      } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
    },
  ];
  for (const mutate of actionMismatchCases) {
    const mismatched = makeResult();
    mutate(mismatched);
    assert.throws(
      () => buildSafetyKernelV31TransactionPublicRecord(mismatched),
      /ACTION_ID_MISMATCH/
    );
  }

  const nonceMismatchCases: Array<
    (value: SafetyKernelV31TransactionServiceResult) => void
  > = [
    (value) => {
      value.issued = {
        ...value.issued,
        lifecycle: { ...value.issued.lifecycle, approvalNonce: "other-nonce" },
      };
    },
    (value) => {
      value.envelope = { ...value.envelope, approval_nonce: "other-nonce" };
    },
    (value) => {
      value.decisionResult = {
        ...value.decisionResult,
        approval_nonce: "other-nonce",
      };
    },
    (value) => {
      value.commit = {
        ...value.commit,
        lifecycle: { ...value.commit.lifecycle, approvalNonce: "other-nonce" },
      } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
    },
  ];
  for (const mutate of nonceMismatchCases) {
    const mismatched = makeResult();
    mutate(mismatched);
    assert.throws(
      () => buildSafetyKernelV31TransactionPublicRecord(mismatched),
      /APPROVAL_NONCE_MISMATCH/
    );
  }
});

test("transaction output rejects an unsupported decision before SPLIT_REQUIRED fallback formatting", () => {
  const result = makeResult();
  const lifecycle = {
    ...result.commit.lifecycle,
    phase: "SPLIT_REQUIRED",
    decision: "SPLIT_REQUIRED",
    nonceConsumed: true,
    parentEnvelopeInvalidated: true,
    childNoncesRequired: true,
  } as SafetyKernelV31NonceLifecycleRecord;

  result.commit = { ...result.commit, lifecycle } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  result.decisionResult = {
    ...result.decisionResult,
    decision: "UNKNOWN_DECISION" as never,
  };

  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /UNSUPPORTED_TRANSACTION_DECISION/
  );
});

test("transaction output rejects a non-issued issuance lifecycle", () => {
  const result = makeResult();
  result.issued = {
    ...result.issued,
    lifecycle: { ...result.commit.lifecycle },
  };
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ISSUED_LIFECYCLE/
  );
});


test("transaction output rejects an issued lifecycle with a non-null decision", () => {
  const result = makeResult();
  (result.issued.lifecycle as unknown as { decision: string }).decision = "ALLOW";
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ISSUED_LIFECYCLE/
  );
});

test("transaction output rejects an issued lifecycle with a consumed nonce", () => {
  const result = makeResult();
  (result.issued.lifecycle as unknown as { nonceConsumed: boolean }).nonceConsumed = true;
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ISSUED_LIFECYCLE/
  );
});

test("transaction output rejects an issued lifecycle with an invalidated parent envelope", () => {
  const result = makeResult();
  (result.issued.lifecycle as unknown as { parentEnvelopeInvalidated: boolean }).parentEnvelopeInvalidated = true;
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ISSUED_LIFECYCLE/
  );
});

test("transaction output rejects an issued lifecycle that requires child nonces", () => {
  const result = makeResult();
  (result.issued.lifecycle as unknown as { childNoncesRequired: boolean }).childNoncesRequired = true;
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ISSUED_LIFECYCLE/
  );
});

test("transaction output rejects an issued lifecycle that permits WARN auto-proceed", () => {
  const result = makeResult();
  (result.issued.lifecycle as unknown as { warnMustNeverAutoProceed: boolean }).warnMustNeverAutoProceed = false;
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ISSUED_LIFECYCLE/
  );
});

test("transaction output rejects an issued lifecycle that does not require a receipt", () => {
  const result = makeResult();
  (result.issued.lifecycle as unknown as { receiptRequired: boolean }).receiptRequired = false;
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ISSUED_LIFECYCLE/
  );
});

test("transaction output rejects an issued lifecycle that does not require ledger evidence", () => {
  const result = makeResult();
  (result.issued.lifecycle as unknown as { ledgerRequired: boolean }).ledgerRequired = false;
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ISSUED_LIFECYCLE/
  );
});

test("transaction output rejects an issued lifecycle with a non-issued phase", () => {
  const result = makeResult();
  (result.issued.lifecycle as unknown as { phase: string }).phase = "REQUIRE_REVIEW";
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /INVALID_ISSUED_LIFECYCLE/
  );
});

test("transaction output rejects failed evidence when commit is marked committed", () => {
  const result = makeResult();
  result.commit = {
    ...result.commit,
    committed: true,
    evidence: { ok: false, ledgerPath: null, receiptPath: null, reason: "write_failed" },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_EVIDENCE_NOT_COMMITTED/
  );
});

test("transaction output rejects an ALLOW lifecycle with only the phase mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "ALLOW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "REQUIRE_REVIEW",
      decision: "ALLOW",
      nonceConsumed: false,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects an ALLOW lifecycle with only the decision mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "ALLOW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "ALLOW_PENDING_EXECUTION",
      decision: "WARN",
      nonceConsumed: false,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects an ALLOW lifecycle with only nonce consumption mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "ALLOW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "ALLOW_PENDING_EXECUTION",
      decision: "ALLOW",
      nonceConsumed: true,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects an ALLOW lifecycle with only parent invalidation mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "ALLOW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "ALLOW_PENDING_EXECUTION",
      decision: "ALLOW",
      nonceConsumed: false,
      parentEnvelopeInvalidated: true,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects an ALLOW lifecycle with only child nonce requirement mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "ALLOW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "ALLOW_PENDING_EXECUTION",
      decision: "ALLOW",
      nonceConsumed: false,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: true,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a WARN lifecycle with only the phase mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "WARN" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "ALLOW_PENDING_EXECUTION",
      decision: "WARN",
      nonceConsumed: false,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a WARN lifecycle with only the decision mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "WARN" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "WARN_PENDING",
      decision: "ALLOW",
      nonceConsumed: false,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a WARN lifecycle with only nonce consumption mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "WARN" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "WARN_PENDING",
      decision: "WARN",
      nonceConsumed: true,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a WARN lifecycle with only parent invalidation mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "WARN" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "WARN_PENDING",
      decision: "WARN",
      nonceConsumed: false,
      parentEnvelopeInvalidated: true,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a WARN lifecycle with only child nonce requirement mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "WARN" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "WARN_PENDING",
      decision: "WARN",
      nonceConsumed: false,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: true,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a BLOCK lifecycle with only the phase mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "BLOCK" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "WARN_PENDING",
      decision: "BLOCK",
      nonceConsumed: true,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a BLOCK lifecycle with only the decision mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "BLOCK" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "BLOCKED",
      decision: "ALLOW",
      nonceConsumed: true,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a BLOCK lifecycle with only nonce consumption mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "BLOCK" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "BLOCKED",
      decision: "BLOCK",
      nonceConsumed: false,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a BLOCK lifecycle with only parent invalidation mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "BLOCK" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "BLOCKED",
      decision: "BLOCK",
      nonceConsumed: true,
      parentEnvelopeInvalidated: true,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a BLOCK lifecycle with only child nonce requirement mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "BLOCK" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "BLOCKED",
      decision: "BLOCK",
      nonceConsumed: true,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: true,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a REQUIRE_REVIEW lifecycle with only the phase mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "REQUIRE_REVIEW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "BLOCKED",
      decision: "REQUIRE_REVIEW",
      nonceConsumed: true,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a REQUIRE_REVIEW lifecycle with only the decision mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "REQUIRE_REVIEW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "REQUIRE_REVIEW",
      decision: "BLOCK",
      nonceConsumed: true,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a REQUIRE_REVIEW lifecycle with only nonce consumption mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "REQUIRE_REVIEW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "REQUIRE_REVIEW",
      decision: "REQUIRE_REVIEW",
      nonceConsumed: false,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a REQUIRE_REVIEW lifecycle with only parent invalidation mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "REQUIRE_REVIEW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "REQUIRE_REVIEW",
      decision: "REQUIRE_REVIEW",
      nonceConsumed: true,
      parentEnvelopeInvalidated: true,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a REQUIRE_REVIEW lifecycle with only child nonce requirement mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "REQUIRE_REVIEW" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "REQUIRE_REVIEW",
      decision: "REQUIRE_REVIEW",
      nonceConsumed: true,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: true,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a SPLIT_REQUIRED lifecycle with only the phase mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "SPLIT_REQUIRED" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "BLOCKED",
      decision: "SPLIT_REQUIRED",
      nonceConsumed: true,
      parentEnvelopeInvalidated: true,
      childNoncesRequired: true,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a SPLIT_REQUIRED lifecycle with only the decision mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "SPLIT_REQUIRED" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "SPLIT_REQUIRED",
      decision: "BLOCK",
      nonceConsumed: true,
      parentEnvelopeInvalidated: true,
      childNoncesRequired: true,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a SPLIT_REQUIRED lifecycle with only nonce consumption mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "SPLIT_REQUIRED" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "SPLIT_REQUIRED",
      decision: "SPLIT_REQUIRED",
      nonceConsumed: false,
      parentEnvelopeInvalidated: true,
      childNoncesRequired: true,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a SPLIT_REQUIRED lifecycle with only parent invalidation mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "SPLIT_REQUIRED" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "SPLIT_REQUIRED",
      decision: "SPLIT_REQUIRED",
      nonceConsumed: true,
      parentEnvelopeInvalidated: false,
      childNoncesRequired: true,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects a SPLIT_REQUIRED lifecycle with only child nonce requirement mismatched", () => {
  const result = makeResult();
  result.decisionResult = { ...result.decisionResult, decision: "SPLIT_REQUIRED" };
  result.commit = {
    ...result.commit,
    lifecycle: {
      ...result.commit.lifecycle,
      phase: "SPLIT_REQUIRED",
      decision: "SPLIT_REQUIRED",
      nonceConsumed: true,
      parentEnvelopeInvalidated: true,
      childNoncesRequired: false,
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/
  );
});

test("transaction output rejects an uncommitted commit with otherwise successful evidence", () => {
  const result = makeResult();
  result.commit = {
    ...result.commit,
    committed: false,
    evidence: {
      ok: true,
      ledgerPath: "/tmp/evidence.jsonl",
      receiptPath: "/tmp/receipt.md",
      reason: "success",
    },
  } as unknown as SafetyKernelV31TransactionServiceResult["commit"];
  assert.throws(
    () => buildSafetyKernelV31TransactionPublicRecord(result),
    /TRANSACTION_EVIDENCE_NOT_COMMITTED/
  );
});
