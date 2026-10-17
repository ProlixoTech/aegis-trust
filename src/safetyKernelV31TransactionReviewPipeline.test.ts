import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";

import type {
  SafetyKernelV31AllowedExecutionAbortEvidence,
  SafetyKernelV31AllowedExecutionCompletionEvidence,
} from "../packages/aegis-core";
import type { ActionQualityResult } from "../packages/aegis-core";
import type { SafetyKernelV31NonceLifecycleRecord } from "./safetyKernelV31NonceLifecyclePolicy";
import type { SafetyKernelV31EvidenceIntegrityReport, SafetyKernelV31EvidenceWriteResult } from "./safetyKernelV31EvidenceWriter";
import { SafetyKernelV31NonceTransactionCoordinator } from "../packages/aegis-core";
import type { SafetyKernelV31NonceEvidencePort } from "../packages/aegis-core";
import { SafetyKernelV31TransactionService } from "../packages/aegis-core";
import {
  SafetyKernelV31AllowedExecutionSessionBindingStore,
} from "../packages/aegis-core";
import type {
  AegisExecutionPort,
  AegisExecutionRequest,
  AegisExecutionResult,
} from "../packages/aegis-core";
import {
  SafetyKernelV31AllowedExecutionCoordinator,
} from "./safetyKernelV31AllowedExecutionCoordinator";
import type {
  SafetyKernelV31AllowedExecutionBindingVerifier,
} from "./safetyKernelV31AllowedExecutionCoordinator";
import type { SafetyKernelV31PostReviewLifecycleOutputResult } from "./safetyKernelV31PostReviewLifecycleOutput";
import type { SafetyKernelV31TransactionOutputResult, SafetyKernelV31TransactionPublicRecord } from "./safetyKernelV31TransactionOutput";
import { SafetyKernelV31TransactionSessionStore } from "../packages/aegis-core";
import type { SafetyKernelV31TransactionSessionPublicRecord } from "../packages/aegis-core";
import {
  SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT,
  SafetyKernelV31TransactionReviewPipeline,
} from "./safetyKernelV31TransactionReviewPipeline";
import type {
  SafetyKernelV31TransactionReviewPipelinePostReviewSessionResult,
  SafetyKernelV31TransactionReviewPipelineResult,
} from "./safetyKernelV31TransactionReviewPipeline";

const pipelineResultTypeBase = { transactionInput: {} as never, invariant: SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT } as const;
const allowPipelineOutputType = {} as SafetyKernelV31TransactionOutputResult & { record: Extract<SafetyKernelV31TransactionPublicRecord, { decision: "ALLOW" }> };
const warnPipelineOutputType = {} as SafetyKernelV31TransactionOutputResult & { record: Extract<SafetyKernelV31TransactionPublicRecord, { decision: "WARN" }> };
const blockPipelineOutputType = {} as SafetyKernelV31TransactionOutputResult & { record: Extract<SafetyKernelV31TransactionPublicRecord, { decision: "BLOCK" }> };
const allowPipelineSessionType = {} as Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: "ALLOW_PENDING_EXECUTION" }>;
const warnPipelineSessionType = {} as Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: "WARN_PENDING" }>;
// @ts-expect-error ALLOW review result requires an ALLOW_PENDING_EXECUTION session
const invalidAllowWarnSession: SafetyKernelV31TransactionReviewPipelineResult = { ...pipelineResultTypeBase, output: allowPipelineOutputType, session: warnPipelineSessionType };
// @ts-expect-error WARN review result cannot omit its WARN_PENDING session
const invalidWarnMissingSession: SafetyKernelV31TransactionReviewPipelineResult = { ...pipelineResultTypeBase, output: warnPipelineOutputType, session: null };
// @ts-expect-error terminal BLOCK review result cannot expose a pending session
const invalidBlockPendingSession: SafetyKernelV31TransactionReviewPipelineResult = { ...pipelineResultTypeBase, output: blockPipelineOutputType, session: allowPipelineSessionType };
void invalidAllowWarnSession;
void invalidWarnMissingSession;
void invalidBlockPendingSession;

const warnConfirmedPostReviewOutputType = {} as Omit<SafetyKernelV31PostReviewLifecycleOutputResult, "record"> & { record: Extract<SafetyKernelV31PostReviewLifecycleOutputResult["record"], { event: "WARN_CONFIRMED" }> };
const allowedCompletedPostReviewOutputType = {} as Omit<SafetyKernelV31PostReviewLifecycleOutputResult, "record"> & { record: Extract<SafetyKernelV31PostReviewLifecycleOutputResult["record"], { event: "ALLOWED_EXECUTION_COMPLETED" }> };
const warnTerminatedPostReviewOutputType = {} as Omit<SafetyKernelV31PostReviewLifecycleOutputResult, "record"> & { record: Extract<SafetyKernelV31PostReviewLifecycleOutputResult["record"], { event: "WARN_TERMINATED" }> };
const consumedPipelineSessionType = {} as Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: "CONSUMED" }>;
// @ts-expect-error WARN confirmation must return an ALLOW_PENDING_EXECUTION session
const invalidWarnConfirmationConsumedSession: SafetyKernelV31TransactionReviewPipelinePostReviewSessionResult = { output: warnConfirmedPostReviewOutputType, session: consumedPipelineSessionType };
// @ts-expect-error allowed completion must return a CONSUMED session
const invalidAllowedCompletionPendingSession: SafetyKernelV31TransactionReviewPipelinePostReviewSessionResult = { output: allowedCompletedPostReviewOutputType, session: allowPipelineSessionType };
// @ts-expect-error WARN termination must return a CONSUMED session
const invalidWarnTerminationPendingSession: SafetyKernelV31TransactionReviewPipelinePostReviewSessionResult = { output: warnTerminatedPostReviewOutputType, session: warnPipelineSessionType };
void invalidWarnConfirmationConsumedSession;
void invalidAllowedCompletionPendingSession;
void invalidWarnTerminationPendingSession;

function gate(status: ActionQualityResult["status"]): ActionQualityResult {
  return {
    status,
    userMessage: "pipeline test message",
    internalRuleId: "PIPELINE_TEST_RULE",
    source: "vscode_command",
    reasons: ["pipeline test"],
    detectedEffects: [],
  } as ActionQualityResult;
}

function caller(actionId: string) {
  return {
    action_id: actionId,
    target: "src/example.ts",
    intent: "review transaction without execution",
    proposed_action: "Get-Content src/example.ts",
    context_hash: "sha256:pipeline-test",
    timestamp: "2026-01-01T00:00:00.000Z",
    adapter_id: "transaction-review-pipeline-test",
    policy_version: "policy-test",
    human_readable_summary: "Transaction review pipeline test",
  };
}

function warnPending(actionId: string, approvalNonce: string): SafetyKernelV31NonceLifecycleRecord {
  return { actionId, approvalNonce, phase: "WARN_PENDING", decision: "WARN", nonceConsumed: false, warnTimeoutSeconds: 60, warnMustNeverAutoProceed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false, receiptRequired: true, ledgerRequired: true };
}

function allowPending(actionId: string, approvalNonce: string): SafetyKernelV31NonceLifecycleRecord {
  return { actionId, approvalNonce, phase: "ALLOW_PENDING_EXECUTION", decision: "ALLOW", nonceConsumed: false, warnMustNeverAutoProceed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false, receiptRequired: true, ledgerRequired: true };
}

async function withPipeline(
  run: (pipeline: SafetyKernelV31TransactionReviewPipeline) => Promise<void>
): Promise<void> {
  const aegisDir = await fs.mkdtemp(
    path.join(os.tmpdir(), "aegis-sk-v31-pipeline-")
  );
  try {
    await run(SafetyKernelV31TransactionReviewPipeline.createForAegisDir(aegisDir));
  } finally {
    await fs.rm(aegisDir, { recursive: true, force: true });
  }
}

test("transaction review pipeline invariant remains input-validated, evidence-first, nonce-safe, disconnected, and non-executing", () => {
  assert.deepEqual(SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT, {
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
  });
});

test("transaction review pipeline builds input, commits evidence, and returns nonce-safe output", async () => {
  await withPipeline(async (pipeline) => {
    const result = await pipeline.review(
      caller("pipeline-review"),
      gate("REVIEW_NEEDED")
    );

    assert.equal(result.transactionInput.action_id, "pipeline-review");
    assert.equal(result.output.record.actionId, "pipeline-review");
    assert.equal(result.output.record.decision, "REQUIRE_REVIEW");
    assert.equal(result.output.record.evidenceCommitted, true);
    assert.equal(result.output.record.nonceConsumed, true);
    assert.equal(result.session, null);
    assert.match(result.output.record.approvalNonceSha256, /^[a-f0-9]{64}$/);
    assert.equal(
      Object.prototype.hasOwnProperty.call(result.transactionInput, "approval_nonce"),
      false
    );
    assert.equal(Object.prototype.hasOwnProperty.call(result, "transactionResult"), false);
    assert.equal(
      result.output.clipboardSummary.includes("RAW_APPROVAL_NONCE_EXPOSED=False"),
      true
    );
  });
});

test("transaction review pipeline rejects uncommitted decision evidence without creating a session", async () => {
  const sessions = new SafetyKernelV31TransactionSessionStore();
  const evidence: SafetyKernelV31NonceEvidencePort = {
    async appendDecision(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: false, ledgerPath: null, receiptPath: null, reason: "write_failed" };
    },
    async appendWarnConfirmation(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async appendAllowedExecutionCompletion(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async appendWarnTerminal(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async verifyIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport> {
      return { ok: true, ledgerExists: true, ledgerPath: "/evidence.jsonl", eventCount: 0, headHash: "head" };
    },
  };
  const pipeline = new SafetyKernelV31TransactionReviewPipeline(
    new SafetyKernelV31TransactionService(new SafetyKernelV31NonceTransactionCoordinator(evidence)),
    sessions
  );
  try {
    await assert.rejects(
      () => pipeline.review(caller("pipeline-decision-evidence-failure"), gate("ALLOW")),
      /DECISION_EVIDENCE_NOT_COMMITTED/
    );
    assert.equal(sessions.size, 0);
  } finally {
    sessions.clear();
  }
});

test("transaction review pipeline rejects invalid caller input before transaction review", async () => {
  await withPipeline(async (pipeline) => {
    await assert.rejects(
      () => pipeline.review({ ...caller("valid"), action_id: " " }, gate("ALLOW")),
      /INVALID_ACTION_ID/
    );
  });
});

test("transaction review pipeline issues unique local nonce hashes for separate reviews", async () => {
  await withPipeline(async (pipeline) => {
    const first = await pipeline.review(caller("pipeline-first"), gate("BLOCK"));
    const second = await pipeline.review(caller("pipeline-second"), gate("BLOCK"));

    assert.notEqual(
      first.output.record.approvalNonceSha256,
      second.output.record.approvalNonceSha256
    );
    assert.equal(first.output.record.evidenceCommitted, true);
    assert.equal(second.output.record.evidenceCommitted, true);
    assert.equal(first.output.record.nonceConsumed, true);
    assert.equal(second.output.record.nonceConsumed, true);
  });
});

test("transaction review pipeline formats WARN confirmation as nonce-safe post-review output", async () => {
  await withPipeline(async (pipeline) => {
    const nonce = "pipeline-warn-confirm-nonce";
    const result = await pipeline.confirmWarn(warnPending("pipeline-warn-confirm", nonce));
    assert.equal(result.record.event, "WARN_CONFIRMED");
    assert.equal(result.record.lifecyclePhase, "ALLOW_PENDING_EXECUTION");
    assert.equal(result.record.nonceConsumed, false);
    assert.equal(result.record.evidenceCommitted, true);
    assert.match(result.record.approvalNonceSha256, /^[a-f0-9]{64}$/);
    assert.equal(result.clipboardSummary.includes(nonce), false);
    assert.equal(result.record.executionAuthorityGranted, false);
  });
});

test("transaction review pipeline formats allowed execution completion without granting authority", async () => {
  await withPipeline(async (pipeline) => {
    const nonce = "pipeline-allowed-completion-nonce";
    const result = await pipeline.completeAllowedExecution(allowPending("pipeline-allowed-completion", nonce));
    assert.equal(result.record.event, "ALLOWED_EXECUTION_COMPLETED");
    assert.equal(result.record.lifecyclePhase, "CONSUMED");
    assert.equal(result.record.nonceConsumed, true);
    assert.equal(result.record.evidenceCommitted, true);
    assert.equal(result.clipboardSummary.includes(nonce), false);
    assert.equal(result.record.automaticExecutionAllowed, false);
  });
});

test("transaction review pipeline terminates WARN only with committed nonce-safe evidence output", async () => {
  await withPipeline(async (pipeline) => {
    const nonce = "pipeline-warn-terminal-nonce";
    const result = await pipeline.terminateWarn(warnPending("pipeline-warn-terminal", nonce), "cancel_by_user");
    assert.equal(result.record.event, "WARN_TERMINATED");
    assert.equal(result.record.lifecyclePhase, "CONSUMED");
    assert.equal(result.record.nonceConsumed, true);
    assert.equal(result.record.evidenceCommitted, true);
    assert.equal(result.clipboardSummary.includes(nonce), false);
    assert.equal(result.record.runtimeConnected, false);
  });
});

async function withPipelineAndSessionStore(
  run: (
    pipeline: SafetyKernelV31TransactionReviewPipeline,
    sessions: SafetyKernelV31TransactionSessionStore
  ) => Promise<void>
): Promise<void> {
  const aegisDir = await fs.mkdtemp(
    path.join(os.tmpdir(), "aegis-sk-AEGIS3_SYNTHETIC_TEST")
  );
  const sessions = new SafetyKernelV31TransactionSessionStore();
  try {
    await run(
      new SafetyKernelV31TransactionReviewPipeline(
        SafetyKernelV31TransactionService.createForAegisDir(aegisDir),
        sessions
      ),
      sessions
    );
  } finally {
    sessions.clear();
    await fs.rm(aegisDir, { recursive: true, force: true });
  }
}

test("transaction review pipeline returns an opaque session only for a pending lifecycle", async () => {
  await withPipeline(async (pipeline) => {
    const result = await pipeline.review(
      caller("pipeline-session-allow"),
      gate("ALLOW")
    );
    assert.ok(result.session);
    assert.match(result.session.sessionId, /^[a-f0-9]{48}$/);
    assert.equal(result.session.lifecyclePhase, "ALLOW_PENDING_EXECUTION");
    assert.equal(
      result.session.approvalNonceSha256,
      result.output.record.approvalNonceSha256
    );
    assert.equal(result.session.rawApprovalNonceExposed, false);
    assert.equal(result.session.runtimeConnected, false);
    assert.equal(result.session.executionAuthorityGranted, false);
  });
});

test("transaction review pipeline completes an allowed session and removes it", async () => {
  await withPipeline(async (pipeline) => {
    const reviewed = await pipeline.review(
      caller("pipeline-session-complete"),
      gate("ALLOW")
    );
    assert.ok(reviewed.session);
    const sessionId = reviewed.session.sessionId;
    const completed = await pipeline.completeAllowedExecutionSession(sessionId);
    assert.equal(completed.output.record.event, "ALLOWED_EXECUTION_COMPLETED");
    assert.equal(completed.session.lifecyclePhase, "CONSUMED");
    assert.equal(completed.session.nonceConsumed, true);
    await assert.rejects(
      () => pipeline.completeAllowedExecutionSession(sessionId),
      /SESSION_NOT_FOUND/
    );
  });
});

test("transaction review pipeline preserves an allowed session when completion evidence fails", async () => {
  const sessions = new SafetyKernelV31TransactionSessionStore();
  const evidence: SafetyKernelV31NonceEvidencePort = {
    async appendDecision(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async appendWarnConfirmation(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async appendAllowedExecutionCompletion(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: false, ledgerPath: null, receiptPath: null, reason: "write_failed" };
    },
    async appendWarnTerminal(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async verifyIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport> {
      return { ok: true, ledgerExists: true, ledgerPath: "/evidence.jsonl", eventCount: 0, headHash: "head" };
    },
  };
  const pipeline = new SafetyKernelV31TransactionReviewPipeline(
    new SafetyKernelV31TransactionService(new SafetyKernelV31NonceTransactionCoordinator(evidence)),
    sessions
  );
  const pending = allowPending("pipeline-session-evidence-failure", "pipeline-session-evidence-failure-nonce");
  const created = sessions.create(pending);
  try {
    await assert.rejects(
      () => pipeline.completeAllowedExecutionSession(created.sessionId),
      /ALLOWED_EXECUTION_COMPLETION_EVIDENCE_NOT_COMMITTED/
    );
    assert.deepEqual(sessions.getLifecycleForInternalUse(created.sessionId), pending);
    const preserved = sessions.read(created.sessionId);
    assert.equal(preserved?.lifecyclePhase, "ALLOW_PENDING_EXECUTION");
    assert.equal(preserved?.nonceConsumed, false);
  } finally {
    sessions.clear();
  }
});

test("transaction review pipeline preserves WARN state when terminal evidence fails", async () => {
  const sessions = new SafetyKernelV31TransactionSessionStore();
  const evidence: SafetyKernelV31NonceEvidencePort = {
    async appendDecision(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async appendWarnConfirmation(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async appendAllowedExecutionCompletion(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async appendWarnTerminal(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: false, ledgerPath: null, receiptPath: null, reason: "write_failed" };
    },
    async verifyIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport> {
      return { ok: true, ledgerExists: true, ledgerPath: "/evidence.jsonl", eventCount: 0, headHash: "head" };
    },
  };
  const pipeline = new SafetyKernelV31TransactionReviewPipeline(
    new SafetyKernelV31TransactionService(new SafetyKernelV31NonceTransactionCoordinator(evidence)),
    sessions
  );
  const pending = warnPending("pipeline-warn-evidence-failure", "pipeline-warn-evidence-failure-nonce");
  const created = sessions.create(pending);
  try {
    await assert.rejects(
      () => pipeline.terminateWarnSession(created.sessionId, "cancel_by_user"),
      /WARN_TERMINATION_EVIDENCE_NOT_COMMITTED/
    );
    assert.deepEqual(sessions.getLifecycleForInternalUse(created.sessionId), pending);
    const preserved = sessions.read(created.sessionId);
    assert.equal(preserved?.lifecyclePhase, "WARN_PENDING");
    assert.equal(preserved?.nonceConsumed, false);
    await assert.rejects(
      () => pipeline.terminateWarn(pending, "timeout_expired"),
      /WARN_TERMINATION_EVIDENCE_NOT_COMMITTED/
    );
    assert.equal(pending.phase, "WARN_PENDING");
    assert.equal(pending.nonceConsumed, false);
  } finally {
    sessions.clear();
  }
});

test("transaction review pipeline preserves WARN state when confirmation evidence fails", async () => {
  const sessions = new SafetyKernelV31TransactionSessionStore();
  const evidence: SafetyKernelV31NonceEvidencePort = {
    async appendDecision(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async appendWarnConfirmation(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: false, ledgerPath: null, receiptPath: null, reason: "write_failed" };
    },
    async appendAllowedExecutionCompletion(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async appendWarnTerminal(): Promise<SafetyKernelV31EvidenceWriteResult> {
      return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" };
    },
    async verifyIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport> {
      return { ok: true, ledgerExists: true, ledgerPath: "/evidence.jsonl", eventCount: 0, headHash: "head" };
    },
  };
  const pipeline = new SafetyKernelV31TransactionReviewPipeline(
    new SafetyKernelV31TransactionService(new SafetyKernelV31NonceTransactionCoordinator(evidence)),
    sessions
  );
  const pending = warnPending("pipeline-confirm-evidence-failure", "pipeline-confirm-evidence-failure-nonce");
  const created = sessions.create(pending);
  try {
    await assert.rejects(
      () => pipeline.confirmWarnSession(created.sessionId),
      /WARN_CONFIRMATION_EVIDENCE_NOT_COMMITTED/
    );
    assert.deepEqual(sessions.getLifecycleForInternalUse(created.sessionId), pending);
    assert.equal(sessions.read(created.sessionId)?.lifecyclePhase, "WARN_PENDING");
    await assert.rejects(
      () => pipeline.confirmWarn(pending),
      /WARN_CONFIRMATION_EVIDENCE_NOT_COMMITTED/
    );
    assert.equal(pending.phase, "WARN_PENDING");
    assert.equal(pending.nonceConsumed, false);
  } finally {
    sessions.clear();
  }
});

test("transaction review pipeline confirms WARN through an opaque session", async () => {
  await withPipelineAndSessionStore(async (pipeline, sessions) => {
    const created = sessions.create(
      warnPending("pipeline-session-confirm", "pipeline-session-confirm-nonce")
    );
    const confirmed = await pipeline.confirmWarnSession(created.sessionId);
    assert.equal(confirmed.output.record.event, "WARN_CONFIRMED");
    assert.equal(confirmed.session.lifecyclePhase, "ALLOW_PENDING_EXECUTION");
    assert.equal(confirmed.session.nonceConsumed, false);
    assert.equal(confirmed.output.record.evidenceCommitted, true);
    assert.equal(confirmed.output.clipboardSummary.includes("pipeline-session-confirm-nonce"), false);
  });
});

test("transaction review pipeline terminates WARN through an opaque session with evidence", async () => {
  await withPipelineAndSessionStore(async (pipeline, sessions) => {
    const created = sessions.create(
      warnPending("pipeline-session-terminate", "pipeline-session-terminate-nonce")
    );
    const terminated = await pipeline.terminateWarnSession(
      created.sessionId,
      "cancel_by_user"
    );
    assert.equal(terminated.output.record.event, "WARN_TERMINATED");
    assert.equal(terminated.session.lifecyclePhase, "CONSUMED");
    assert.equal(terminated.session.nonceConsumed, true);
    assert.equal(terminated.output.record.evidenceCommitted, true);
    assert.equal(sessions.read(created.sessionId), null);
    assert.equal(terminated.output.record.executionAuthorityGranted, false);
  });
});


test("transaction review pipeline reads a nonce-safe session and returns null after consumption", async () => {
  await withPipeline(async (pipeline) => {
    const reviewed = await pipeline.review(
      caller("pipeline-session-read"),
      gate("ALLOW")
    );
    assert.ok(reviewed.session);
    const sessionId = reviewed.session.sessionId;
    const read = pipeline.readSession(sessionId);
    assert.deepEqual(read, reviewed.session);
    assert.equal(read?.rawApprovalNonceExposed, false);
    await pipeline.completeAllowedExecutionSession(sessionId);
    assert.equal(pipeline.readSession(sessionId), null);
  });
});


test("unsupported committed decision is rejected directly", async () => {
  const service = {
    async reviewAndCommit() {
      return { decisionResult: { decision: "UNSUPPORTED_DECISION" }, commit: { committed: true } };
    },
  } as unknown as SafetyKernelV31TransactionService;
  const pipeline = new SafetyKernelV31TransactionReviewPipeline(service, new SafetyKernelV31TransactionSessionStore());
  await assert.rejects(() => pipeline.review(caller("pipeline-unreachable-decision"), gate("ALLOW")), /UNREACHABLE_TRANSACTION_DECISION/);
});

test("transaction review pipeline returns WARN with an opaque pending session", async () => {
  await withPipeline(async (pipeline) => {
    const result = await pipeline.review(
      caller("pipeline-review-warn"),
      { ...gate("ALLOW"), source: "ai_connector" }
    );
    assert.equal(result.output.record.decision, "WARN");
    assert.ok(result.session);
    assert.equal(result.session.lifecyclePhase, "WARN_PENDING");
    assert.equal(result.session.nonceConsumed, false);
  });
});

test("transaction review pipeline returns SPLIT_REQUIRED without a session", async () => {
  await withPipeline(async (pipeline) => {
    const result = await pipeline.review(
      caller("pipeline-review-split-required"),
      gate("SPLIT_REQUIRED")
    );
    assert.equal(result.output.record.decision, "SPLIT_REQUIRED");
    assert.equal(result.output.record.evidenceCommitted, true);
    assert.equal(result.output.record.nonceConsumed, true);
    assert.equal(result.session, null);
  });
});


test("transaction review pipeline direct allowed completion rejects uncommitted evidence", async () => {
  const evidence: SafetyKernelV31NonceEvidencePort = {
    async appendDecision(): Promise<SafetyKernelV31EvidenceWriteResult> { return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" }; },
    async appendWarnConfirmation(): Promise<SafetyKernelV31EvidenceWriteResult> { return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" }; },
    async appendAllowedExecutionCompletion(): Promise<SafetyKernelV31EvidenceWriteResult> { return { ok: false, ledgerPath: null, receiptPath: null, reason: "write_failed" }; },
    async appendWarnTerminal(): Promise<SafetyKernelV31EvidenceWriteResult> { return { ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success" }; },
    async verifyIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport> { return { ok: true, ledgerExists: true, ledgerPath: "/evidence.jsonl", eventCount: 0, headHash: "head" }; },
  };
  const pipeline = new SafetyKernelV31TransactionReviewPipeline(
    new SafetyKernelV31TransactionService(new SafetyKernelV31NonceTransactionCoordinator(evidence)),
    new SafetyKernelV31TransactionSessionStore()
  );
  const pending = allowPending("pipeline-direct-completion-evidence-failure", "pipeline-direct-completion-evidence-failure-nonce");
  await assert.rejects(
    () => pipeline.completeAllowedExecution(pending),
    /ALLOWED_EXECUTION_COMPLETION_EVIDENCE_NOT_COMMITTED/
  );
  assert.equal(pending.phase, "ALLOW_PENDING_EXECUTION");
  assert.equal(pending.nonceConsumed, false);
});

test("transaction review pipeline preserves inputs, forwards timestamps and reasons, and contains service failures without session mutation", async () => {
  await withPipeline(async (pipeline) => {
    const callerInput = {
      ...caller("pipeline-input-immutability"),
      action_id: "  pipeline-input-immutability\n",
      intent: "  review\n without mutation  ",
    };
    const actionQualityInput = gate("BLOCK");
    const callerBefore = JSON.stringify(callerInput);
    const actionQualityBefore = JSON.stringify(actionQualityInput);

    const reviewed = await pipeline.review(callerInput, actionQualityInput);

    assert.equal(reviewed.transactionInput.action_id, "pipeline-input-immutability");
    assert.equal(reviewed.transactionInput.intent, "review without mutation");
    assert.equal(
      reviewed.invariant,
      SAFETY_KERNEL_V31_TRANSACTION_REVIEW_PIPELINE_INVARIANT
    );
    assert.equal(JSON.stringify(callerInput), callerBefore);
    assert.equal(JSON.stringify(actionQualityInput), actionQualityBefore);
  });

  const calls: Array<{
    method: string;
    actionId: string;
    timestamp: string | undefined;
    reason?: string;
  }> = [];
  const successEvidence: SafetyKernelV31EvidenceWriteResult = {
    ok: true,
    ledgerPath: "/evidence.jsonl",
    receiptPath: "/receipt.md",
    reason: "success",
  };
  const serviceError = new Error("simulated pipeline service failure");
  const service = {
    async reviewAndCommit(): Promise<never> {
      throw new Error("UNEXPECTED_REVIEW_CALL");
    },
    async confirmWarn(
      lifecycle: SafetyKernelV31NonceLifecycleRecord,
      timestamp?: string
    ) {
      calls.push({
        method: "confirmWarn",
        actionId: lifecycle.actionId,
        timestamp,
      });
      if (lifecycle.actionId === "pipeline-service-error") {
        throw serviceError;
      }
      return {
        committed: true,
        lifecycle: {
          ...lifecycle,
          phase: "ALLOW_PENDING_EXECUTION",
          decision: "ALLOW",
          nonceConsumed: false,
          parentEnvelopeInvalidated: false,
          childNoncesRequired: false,
        } as SafetyKernelV31NonceLifecycleRecord,
        evidence: successEvidence,
      };
    },
    async completeAllowedExecution(
      lifecycle: SafetyKernelV31NonceLifecycleRecord,
      timestamp?: string
    ) {
      calls.push({
        method: "completeAllowedExecution",
        actionId: lifecycle.actionId,
        timestamp,
      });
      return {
        committed: true,
        lifecycle: {
          ...lifecycle,
          phase: "CONSUMED",
          decision: "ALLOW",
          nonceConsumed: true,
          parentEnvelopeInvalidated: false,
          childNoncesRequired: false,
        } as SafetyKernelV31NonceLifecycleRecord,
        evidence: successEvidence,
      };
    },
    async terminateWarn(
      lifecycle: SafetyKernelV31NonceLifecycleRecord,
      reason: string,
      timestamp?: string
    ) {
      calls.push({
        method: "terminateWarn",
        actionId: lifecycle.actionId,
        reason,
        timestamp,
      });
      return {
        committed: true,
        lifecycle: {
          ...lifecycle,
          phase: "CONSUMED",
          decision: "WARN",
          nonceConsumed: true,
          parentEnvelopeInvalidated: false,
          childNoncesRequired: false,
        } as SafetyKernelV31NonceLifecycleRecord,
        evidence: successEvidence,
      };
    },
  } as unknown as SafetyKernelV31TransactionService;
  const sessions = new SafetyKernelV31TransactionSessionStore();
  const pipeline = new SafetyKernelV31TransactionReviewPipeline(service, sessions);

  try {
    const directWarn = warnPending(
      "pipeline-direct-confirm-forwarding",
      "pipeline-direct-confirm-forwarding-nonce"
    );
    const directWarnBefore = JSON.stringify(directWarn);
    await pipeline.confirmWarn(directWarn, "2026-07-16T23:50:01.001Z");
    assert.equal(JSON.stringify(directWarn), directWarnBefore);

    const directAllow = allowPending(
      "pipeline-direct-complete-forwarding",
      "pipeline-direct-complete-forwarding-nonce"
    );
    const directAllowBefore = JSON.stringify(directAllow);
    await pipeline.completeAllowedExecution(
      directAllow,
      "2026-07-16T23:50:02.002Z"
    );
    assert.equal(JSON.stringify(directAllow), directAllowBefore);

    const directTerminate = warnPending(
      "pipeline-direct-terminate-forwarding",
      "pipeline-direct-terminate-forwarding-nonce"
    );
    const directTerminateBefore = JSON.stringify(directTerminate);
    await pipeline.terminateWarn(
      directTerminate,
      "timeout_expired",
      "2026-07-16T23:50:03.003Z"
    );
    assert.equal(JSON.stringify(directTerminate), directTerminateBefore);

    const confirmSession = sessions.create(
      warnPending(
        "pipeline-session-confirm-forwarding",
        "pipeline-session-confirm-forwarding-nonce"
      )
    );
    await pipeline.confirmWarnSession(
      confirmSession.sessionId,
      "2026-07-16T23:50:04.004Z"
    );

    const completeSession = sessions.create(
      allowPending(
        "pipeline-session-complete-forwarding",
        "pipeline-session-complete-forwarding-nonce"
      )
    );
    await pipeline.completeAllowedExecutionSession(
      completeSession.sessionId,
      "2026-07-16T23:50:05.005Z"
    );

    const terminateSession = sessions.create(
      warnPending(
        "pipeline-session-terminate-forwarding",
        "pipeline-session-terminate-forwarding-nonce"
      )
    );
    await pipeline.terminateWarnSession(
      terminateSession.sessionId,
      "cancel_by_user",
      "2026-07-16T23:50:06.006Z"
    );

    const errorPending = warnPending(
      "pipeline-service-error",
      "pipeline-service-error-nonce"
    );
    const errorSession = sessions.create(errorPending);
    const errorSessionBefore = sessions.read(errorSession.sessionId);
    let caught: unknown;
    try {
      await pipeline.confirmWarnSession(
        errorSession.sessionId,
        "2026-07-16T23:50:07.007Z"
      );
    } catch (error) {
      caught = error;
    }
    assert.equal(caught, serviceError);
    assert.deepEqual(sessions.read(errorSession.sessionId), errorSessionBefore);
    assert.deepEqual(
      sessions.getLifecycleForInternalUse(errorSession.sessionId),
      errorPending
    );

    assert.deepEqual(calls, [
      {
        method: "confirmWarn",
        actionId: "pipeline-direct-confirm-forwarding",
        timestamp: "2026-07-16T23:50:01.001Z",
      },
      {
        method: "completeAllowedExecution",
        actionId: "pipeline-direct-complete-forwarding",
        timestamp: "2026-07-16T23:50:02.002Z",
      },
      {
        method: "terminateWarn",
        actionId: "pipeline-direct-terminate-forwarding",
        reason: "timeout_expired",
        timestamp: "2026-07-16T23:50:03.003Z",
      },
      {
        method: "confirmWarn",
        actionId: "pipeline-session-confirm-forwarding",
        timestamp: "2026-07-16T23:50:04.004Z",
      },
      {
        method: "completeAllowedExecution",
        actionId: "pipeline-session-complete-forwarding",
        timestamp: "2026-07-16T23:50:05.005Z",
      },
      {
        method: "terminateWarn",
        actionId: "pipeline-session-terminate-forwarding",
        reason: "cancel_by_user",
        timestamp: "2026-07-16T23:50:06.006Z",
      },
      {
        method: "confirmWarn",
        actionId: "pipeline-service-error",
        timestamp: "2026-07-16T23:50:07.007Z",
      },
    ]);
  } finally {
    sessions.clear();
  }
});

test("transaction review pipeline mutates sessions only after post-review output formatting succeeds", async () => {
  const malformedEvidence = {
    ok: true,
    ledgerPath: null,
    receiptPath: "/receipt.md",
    reason: "success",
  } as unknown as SafetyKernelV31EvidenceWriteResult;
  const service = {
    async reviewAndCommit(): Promise<never> {
      throw new Error("UNEXPECTED_REVIEW_CALL");
    },
    async confirmWarn(lifecycle: SafetyKernelV31NonceLifecycleRecord) {
      return {
        committed: true,
        lifecycle: {
          ...lifecycle,
          phase: "ALLOW_PENDING_EXECUTION",
          decision: "ALLOW",
          nonceConsumed: false,
          parentEnvelopeInvalidated: false,
          childNoncesRequired: false,
        } as SafetyKernelV31NonceLifecycleRecord,
        evidence: malformedEvidence,
      };
    },
    async completeAllowedExecution(lifecycle: SafetyKernelV31NonceLifecycleRecord) {
      return {
        committed: true,
        lifecycle: {
          ...lifecycle,
          phase: "CONSUMED",
          decision: "ALLOW",
          nonceConsumed: true,
          parentEnvelopeInvalidated: false,
          childNoncesRequired: false,
        } as SafetyKernelV31NonceLifecycleRecord,
        evidence: malformedEvidence,
      };
    },
    async terminateWarn(lifecycle: SafetyKernelV31NonceLifecycleRecord) {
      return {
        committed: true,
        lifecycle: {
          ...lifecycle,
          phase: "CONSUMED",
          decision: "WARN",
          nonceConsumed: true,
          parentEnvelopeInvalidated: false,
          childNoncesRequired: false,
        } as SafetyKernelV31NonceLifecycleRecord,
        evidence: malformedEvidence,
      };
    },
  } as unknown as SafetyKernelV31TransactionService;
  const sessions = new SafetyKernelV31TransactionSessionStore();
  const pipeline = new SafetyKernelV31TransactionReviewPipeline(service, sessions);

  const cases = [
    {
      created: sessions.create(
        warnPending("pipeline-format-failure-confirm", "pipeline-format-failure-confirm-nonce")
      ),
      run: (sessionId: string) => pipeline.confirmWarnSession(sessionId),
    },
    {
      created: sessions.create(
        allowPending("pipeline-format-failure-complete", "pipeline-format-failure-complete-nonce")
      ),
      run: (sessionId: string) => pipeline.completeAllowedExecutionSession(sessionId),
    },
    {
      created: sessions.create(
        warnPending("pipeline-format-failure-terminate", "pipeline-format-failure-terminate-nonce")
      ),
      run: (sessionId: string) =>
        pipeline.terminateWarnSession(sessionId, "cancel_by_user"),
    },
  ];

  try {
    for (const current of cases) {
      const publicBefore = sessions.read(current.created.sessionId);
      const lifecycleBefore = sessions.getLifecycleForInternalUse(
        current.created.sessionId
      );
      await assert.rejects(() => current.run(current.created.sessionId), /EVIDENCE/);
      assert.deepEqual(sessions.read(current.created.sessionId), publicBefore);
      assert.deepEqual(
        sessions.getLifecycleForInternalUse(current.created.sessionId),
        lifecycleBefore
      );
    }
  } finally {
    sessions.clear();
  }
});

async function withAllowedExecutionBindingPipeline(
  run: (
    pipeline: SafetyKernelV31TransactionReviewPipeline,
    sessions: SafetyKernelV31TransactionSessionStore,
    bindingStore: SafetyKernelV31AllowedExecutionSessionBindingStore
  ) => Promise<void>
): Promise<void> {
  const aegisDir = await fs.mkdtemp(
    path.join(
      os.tmpdir(),
      "aegis-sk-AEGIS1_SYNTHETIC_TEST"
    )
  );

  const sessions =
    new SafetyKernelV31TransactionSessionStore();

  const bindingStore =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  try {
    await run(
      new SafetyKernelV31TransactionReviewPipeline(
        SafetyKernelV31TransactionService.createForAegisDir(
          aegisDir
        ),
        sessions,
        bindingStore
      ),
      sessions,
      bindingStore
    );
  } finally {
    bindingStore.clear();
    sessions.clear();

    await fs.rm(
      aegisDir,
      {
        recursive: true,
        force: true,
      }
    );
  }
}

test("injected pipeline registers the exact reviewed command for an ALLOW session", async () => {
  await withAllowedExecutionBindingPipeline(
    async (pipeline, _sessions, bindingStore) => {
      const reviewed = await pipeline.review(
        caller("pipeline-binding-allow"),
        gate("ALLOW")
      );

      assert.ok(reviewed.session);

      const binding = bindingStore.read(
        reviewed.session.sessionId
      );

      assert.ok(binding);
      assert.equal(binding.authorityBound, false);
      assert.equal(
        binding.sessionId,
        reviewed.session.sessionId
      );
      assert.equal(
        binding.actionId,
        reviewed.session.actionId
      );
      assert.equal(
        binding.approvalNonceSha256,
        "sha256:" +
          reviewed.session.approvalNonceSha256
      );
      assert.equal(
        binding.commandText,
        reviewed.transactionInput.proposed_action
      );
      assert.match(
        binding.commandSha256,
        /^sha256:[a-f0-9]{64}$/
      );
    }
  );
});

test("WARN confirmation preserves its binding and a separate WARN terminal transition removes its binding", async () => {
  await withAllowedExecutionBindingPipeline(
    async (pipeline, _sessions, bindingStore) => {
      const confirmedReview = await pipeline.review(
        caller("pipeline-binding-warn-confirm"),
        {
          ...gate("ALLOW"),
          source: "ai_connector",
        }
      );

      assert.equal(
        confirmedReview.output.record.decision,
        "WARN"
      );
      assert.ok(confirmedReview.session);

      const confirmedSessionId =
        confirmedReview.session.sessionId;

      const bindingBeforeConfirmation =
        bindingStore.read(confirmedSessionId);

      assert.ok(bindingBeforeConfirmation);

      const confirmed =
        await pipeline.confirmWarnSession(
          confirmedSessionId
        );

      assert.equal(
        confirmed.session.lifecyclePhase,
        "ALLOW_PENDING_EXECUTION"
      );

      assert.deepEqual(
        bindingStore.read(confirmedSessionId),
        bindingBeforeConfirmation
      );

      await pipeline.abortAllowedExecutionSession(
        confirmedSessionId,
        "cancel_by_user"
      );

      assert.equal(
        bindingStore.read(confirmedSessionId),
        null
      );

      const terminalReview = await pipeline.review(
        caller("pipeline-binding-warn-terminal"),
        {
          ...gate("ALLOW"),
          source: "ai_connector",
        }
      );

      assert.equal(
        terminalReview.output.record.decision,
        "WARN"
      );
      assert.ok(terminalReview.session);

      const terminalSessionId =
        terminalReview.session.sessionId;

      assert.ok(
        bindingStore.read(terminalSessionId)
      );

      const terminated =
        await pipeline.terminateWarnSession(
          terminalSessionId,
          "cancel_by_user"
        );

      assert.equal(
        terminated.session.lifecyclePhase,
        "CONSUMED"
      );

      assert.equal(
        bindingStore.read(terminalSessionId),
        null
      );
    }
  );
});

test("successful ALLOW abort and legacy completion remove reviewed command bindings", async () => {
  await withAllowedExecutionBindingPipeline(
    async (pipeline, _sessions, bindingStore) => {
      const abortReviewed = await pipeline.review(
        caller("pipeline-binding-abort"),
        gate("ALLOW")
      );

      assert.ok(abortReviewed.session);

      const abortSessionId =
        abortReviewed.session.sessionId;

      assert.ok(bindingStore.read(abortSessionId));

      await pipeline.abortAllowedExecutionSession(
        abortSessionId,
        "cancel_by_user"
      );

      assert.equal(
        bindingStore.read(abortSessionId),
        null
      );

      const completionReviewed =
        await pipeline.review(
          caller("pipeline-binding-completion"),
          gate("ALLOW")
        );

      assert.ok(completionReviewed.session);

      const completionSessionId =
        completionReviewed.session.sessionId;

      assert.ok(
        bindingStore.read(completionSessionId)
      );

      await pipeline.completeAllowedExecutionSession(
        completionSessionId
      );

      assert.equal(
        bindingStore.read(completionSessionId),
        null
      );
    }
  );
});

test("binding registration failure removes the newly created transaction session", async () => {
  const aegisDir = await fs.mkdtemp(
    path.join(
      os.tmpdir(),
      "aegis-sk-AEGIS2_SYNTHETIC_TEST_XXXXXXX"
    )
  );

  const sessions =
    new SafetyKernelV31TransactionSessionStore();

  const bindingStore =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  let createdSessionId: string | null = null;

  const originalCreate = sessions.create.bind(sessions);

  sessions.create = ((
    lifecycle: SafetyKernelV31NonceLifecycleRecord
  ) => {
    const created = originalCreate(lifecycle);
    createdSessionId = created.sessionId;
    return created;
  }) as typeof sessions.create;

  bindingStore.registerReviewedCommand = (() => {
    throw new Error(
      "TEST_BINDING_REGISTRATION_FAILED"
    );
  }) as typeof bindingStore.registerReviewedCommand;

  const pipeline =
    new SafetyKernelV31TransactionReviewPipeline(
      SafetyKernelV31TransactionService.createForAegisDir(
        aegisDir
      ),
      sessions,
      bindingStore
    );

  try {
    await assert.rejects(
      () =>
        pipeline.review(
          caller("pipeline-binding-registration-failure"),
          gate("ALLOW")
        ),
      /TEST_BINDING_REGISTRATION_FAILED/
    );

    if (createdSessionId === null) {
      throw new Error(
        "EXPECTED_CREATED_SESSION_ID"
      );
    }

    assert.equal(
      sessions.read(createdSessionId),
      null
    );

    assert.equal(bindingStore.size, 0);
  } finally {
    bindingStore.clear();
    sessions.clear();

    await fs.rm(
      aegisDir,
      {
        recursive: true,
        force: true,
      }
    );
  }
});
type CoordinatedVerificationResult =
  | "verified"
  | "authority_drift"
  | "snapshot_failed";

interface CoordinatedPipelineHarnessOptions {
  readonly execute: (
    request: AegisExecutionRequest
  ) =>
    | Promise<AegisExecutionResult>
    | AegisExecutionResult;
  readonly verify?: CoordinatedVerificationResult;
}

function coordinatedDigest(value: string): string {
  return (
    "sha256:" +
    crypto
      .createHash("sha256")
      .update(value, "utf8")
      .digest("hex")
  );
}

function createCoordinatedPipelineHarness(
  options: CoordinatedPipelineHarnessOptions
) {
  const sessions =
    new SafetyKernelV31TransactionSessionStore();

  const bindingStore =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  const success: SafetyKernelV31EvidenceWriteResult = {
    ok: true,
    ledgerPath: "/coordinated-evidence.jsonl",
    receiptPath: "/coordinated-receipt.md",
    reason: "success",
  };

  let executionCalls = 0;

  const executionRequests:
    AegisExecutionRequest[] = [];

  let allowedEvidence:
    SafetyKernelV31AllowedExecutionCompletionEvidence |
    null = null;

  let abortEvidence:
    SafetyKernelV31AllowedExecutionAbortEvidence |
    null = null;

  const evidence: SafetyKernelV31NonceEvidencePort = {
    async appendDecision() {
      return success;
    },

    async appendAllowedExecutionCompletion(value) {
      allowedEvidence = value;
      return success;
    },

    async appendAllowedExecutionAbort(value) {
      abortEvidence = value;
      return success;
    },

    async appendWarnConfirmation() {
      return success;
    },

    async appendWarnTerminal() {
      return success;
    },

    async verifyIntegrity() {
      return {
        ok: true,
        ledgerExists: true,
        ledgerPath:
          "/coordinated-evidence.jsonl",
        eventCount: 0,
        headHash: "head",
      };
    },
  };

  const execution: AegisExecutionPort = {
    async execute(request) {
      executionCalls += 1;
      executionRequests.push({ ...request });
      return options.execute(request);
    },
  };

  const verifier:
    SafetyKernelV31AllowedExecutionBindingVerifier = {
      async verify() {
        return options.verify ?? "verified";
      },
    };

  const pipeline =
    new SafetyKernelV31TransactionReviewPipeline(
      new SafetyKernelV31TransactionService(
        new SafetyKernelV31NonceTransactionCoordinator(
          evidence
        )
      ),
      sessions,
      bindingStore,
      new SafetyKernelV31AllowedExecutionCoordinator(
        execution,
        verifier
      )
    );

  return {
    pipeline,
    sessions,
    bindingStore,
    executionRequests,

    get executionCalls(): number {
      return executionCalls;
    },

    get allowedEvidence() {
      return allowedEvidence;
    },

    get abortEvidence() {
      return abortEvidence;
    },
  };
}

test("default pipeline construction keeps coordinated execution disconnected", async () => {
  await withPipeline(async (pipeline) => {
    const reviewed = await pipeline.review(
      caller("pipeline-coordination-disconnected"),
      gate("ALLOW")
    );

    assert.ok(reviewed.session);

    assert.throws(
      () =>
        pipeline.bindAllowedExecutionSessionAuthority(
          reviewed.session.sessionId,
          {
            authorityRevision: 1,
            workspaceId:
              "workspace-disconnected",
            snapshotBindingSha256:
              "sha256:" + "1".repeat(64),
            cwd: "/workspace/disconnected",
          }
        ),
      /ALLOWED_EXECUTION_COORDINATION_NOT_CONNECTED/
    );

    await assert.rejects(
      () =>
        pipeline.coordinateAllowedExecutionSession(
          reviewed.session.sessionId
        ),
      /ALLOWED_EXECUTION_COORDINATION_NOT_CONNECTED/
    );
  });
});

test("coordinated completion executes the exact reviewed command once and commits bounded evidence", async () => {
  const rawStdout =
    "coordinated-raw-stdout-secret";

  const rawStderr =
    "coordinated-raw-stderr-secret";

  const harness =
    createCoordinatedPipelineHarness({
      execute: async () => ({
        status: "completed",
        exitCode: 0,
        stdout: rawStdout,
        stderr: rawStderr,
      }),
    });

  const reviewed = await harness.pipeline.review(
    caller("pipeline-coordinated-completion"),
    gate("ALLOW")
  );

  assert.ok(reviewed.session);

  const sessionId =
    reviewed.session.sessionId;

  const lifecycle =
    harness.sessions.getLifecycleForInternalUse(
      sessionId
    );

  await assert.rejects(
    () =>
      harness.pipeline.completeAllowedExecutionSession(
        sessionId
      ),
    /COORDINATED_ALLOWED_EXECUTION_SESSION_REQUIRED/
  );

  await assert.rejects(
    () =>
      harness.pipeline.completeAllowedExecution(
        lifecycle
      ),
    /COORDINATED_ALLOWED_EXECUTION_SESSION_REQUIRED/
  );

  harness.pipeline.bindAllowedExecutionSessionAuthority(
    sessionId,
    {
      authorityRevision: 72,
      workspaceId: "workspace-completion",
      snapshotBindingSha256:
        "sha256:" + "2".repeat(64),
      cwd: "/workspace/project",
    }
  );

  const completed =
    await harness.pipeline.coordinateAllowedExecutionSession(
      sessionId,
      "2026-07-20T12:00:00.000Z"
    );

  assert.equal(completed.status, "completed");

  if (completed.status !== "completed") {
    throw new Error(
      "EXPECTED_COORDINATED_COMPLETION"
    );
  }

  assert.equal(
    completed.session.lifecyclePhase,
    "CONSUMED"
  );

  assert.equal(
    completed.session.nonceConsumed,
    true
  );

  assert.equal(harness.executionCalls, 1);

  assert.deepEqual(
    harness.executionRequests,
    [
      {
        commandText:
          reviewed.transactionInput.proposed_action,
        cwd: "/workspace/project",
      },
    ]
  );

  const capturedEvidence =
    harness.allowedEvidence;

  assert.ok(capturedEvidence);

  assert.deepEqual(
    capturedEvidence.execution_binding,
    {
      authority_revision: 72,
      command_sha256:
        coordinatedDigest(
          reviewed.transactionInput.proposed_action
        ),
      snapshot_binding_sha256:
        "sha256:" + "2".repeat(64),
      exit_code: 0,
      stdout_sha256:
        coordinatedDigest(rawStdout),
      stderr_sha256:
        coordinatedDigest(rawStderr),
      stdout_bytes:
        Buffer.byteLength(rawStdout, "utf8"),
      stderr_bytes:
        Buffer.byteLength(rawStderr, "utf8"),
    }
  );

  const publicResult =
    JSON.stringify(completed);

  assert.equal(
    publicResult.includes(rawStdout),
    false
  );

  assert.equal(
    publicResult.includes(rawStderr),
    false
  );

  assert.equal(
    harness.sessions.read(sessionId),
    null
  );

  assert.equal(
    harness.bindingStore.read(sessionId),
    null
  );
});

test("coordinated nonzero exit commits execution_failed abort evidence before consuming the session", async () => {
  const harness =
    createCoordinatedPipelineHarness({
      execute: async () => ({
        status: "completed",
        exitCode: 9,
        stdout: "partial-output",
        stderr: "nonzero-exit",
      }),
    });

  const reviewed = await harness.pipeline.review(
    caller("pipeline-coordinated-abort"),
    gate("ALLOW")
  );

  assert.ok(reviewed.session);

  const sessionId =
    reviewed.session.sessionId;

  harness.pipeline.bindAllowedExecutionSessionAuthority(
    sessionId,
    {
      authorityRevision: 73,
      workspaceId: "workspace-abort",
      snapshotBindingSha256:
        "sha256:" + "3".repeat(64),
      cwd: "/workspace/abort",
    }
  );

  const aborted =
    await harness.pipeline.coordinateAllowedExecutionSession(
      sessionId
    );

  assert.equal(aborted.status, "aborted");

  if (aborted.status !== "aborted") {
    throw new Error(
      "EXPECTED_COORDINATED_ABORT"
    );
  }

  assert.equal(
    aborted.reason,
    "execution_failed"
  );

  assert.equal(
    aborted.evidenceCommitted,
    true
  );

  assert.equal(
    aborted.session.lifecyclePhase,
    "CONSUMED"
  );

  assert.equal(harness.executionCalls, 1);
  assert.equal(harness.allowedEvidence, null);

  assert.equal(
    harness.abortEvidence?.reason,
    "execution_failed"
  );

  assert.equal(
    harness.sessions.read(sessionId),
    null
  );

  assert.equal(
    harness.bindingStore.read(sessionId),
    null
  );
});

test("concurrent coordinated calls claim one session synchronously and never execute twice", async () => {
  let resolveExecution!:
    (result: AegisExecutionResult) => void;

  const executionPromise =
    new Promise<AegisExecutionResult>(
      (resolve) => {
        resolveExecution = resolve;
      }
    );

  const harness =
    createCoordinatedPipelineHarness({
      execute: async () => executionPromise,
    });

  const reviewed = await harness.pipeline.review(
    caller("pipeline-coordinated-single-claim"),
    gate("ALLOW")
  );

  assert.ok(reviewed.session);

  const sessionId =
    reviewed.session.sessionId;

  harness.pipeline.bindAllowedExecutionSessionAuthority(
    sessionId,
    {
      authorityRevision: 74,
      workspaceId: "workspace-single-claim",
      snapshotBindingSha256:
        "sha256:" + "4".repeat(64),
      cwd: "/workspace/single-claim",
    }
  );

  const first =
    harness.pipeline.coordinateAllowedExecutionSession(
      sessionId
    );

  await Promise.resolve();
  await Promise.resolve();

  const second =
    await harness.pipeline.coordinateAllowedExecutionSession(
      sessionId
    );

  assert.deepEqual(second, {
    status: "rejected",
    sessionId,
    code:
      "EXECUTION_SESSION_ALREADY_CLAIMED",
  });

  assert.equal(harness.executionCalls, 1);

  assert.ok(
    harness.sessions.read(sessionId)
  );

  assert.ok(
    harness.bindingStore.read(sessionId)
  );

  resolveExecution({
    status: "completed",
    exitCode: 0,
    stdout: "single-result",
    stderr: "",
  });

  const firstResult = await first;

  assert.equal(
    firstResult.status,
    "completed"
  );

  assert.equal(harness.executionCalls, 1);

  assert.equal(
    harness.sessions.read(sessionId),
    null
  );

  assert.equal(
    harness.bindingStore.read(sessionId),
    null
  );
});