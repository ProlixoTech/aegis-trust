import test from "node:test";
import assert from "node:assert/strict";
import { SafetyKernelV31AllowedExecutionCompletionBinding, SafetyKernelV31AllowedExecutionCompletionEvidence, SafetyKernelV31KernelDecisionResult, SafetyKernelV31WarnConfirmationEvidence, SafetyKernelV31WarnTerminalEvidence } from "../packages/aegis-core";
import { SafetyKernelV31EvidenceIntegrityReport, SafetyKernelV31EvidenceWriteResult } from "./safetyKernelV31EvidenceWriter";
import {
  SAFETY_KERNEL_V31_NONCE_TRANSACTION_COORDINATOR_INVARIANT,
  SafetyKernelV31NonceAllowedExecutionCompletionCommitResult,
  SafetyKernelV31NonceCommitResult,
  SafetyKernelV31NonceDecisionCommitResult,
  SafetyKernelV31NonceEvidencePort,
  SafetyKernelV31NonceTransactionCoordinator,
  SafetyKernelV31NonceWarnConfirmationCommitResult,
  SafetyKernelV31NonceWarnTerminalCommitResult,
} from "./safetyKernelV31NonceTransactionCoordinator";

const ok: SafetyKernelV31EvidenceWriteResult = {
  ok: true, ledgerPath: "/evidence.jsonl", receiptPath: "/receipt.md", reason: "success",
};
const fail: SafetyKernelV31EvidenceWriteResult = {
  ok: false, ledgerPath: null, receiptPath: null, reason: "write_failed",
};

// @ts-expect-error committed success cannot carry failed evidence
const invalidCommittedSuccess: SafetyKernelV31NonceCommitResult = { committed: true, lifecycle: {} as never, evidence: fail };
// @ts-expect-error rejected commit cannot carry successful evidence
const invalidRejectedCommit: SafetyKernelV31NonceCommitResult = { committed: false, lifecycle: {} as never, evidence: ok };
void invalidCommittedSuccess;
void invalidRejectedCommit;

const issuedLifecycleType = {} as Extract<import("./safetyKernelV31NonceLifecyclePolicy").SafetyKernelV31NonceLifecycleRecord, { phase: "ISSUED" }>;
const warnPendingLifecycleType = {} as Extract<import("./safetyKernelV31NonceLifecyclePolicy").SafetyKernelV31NonceLifecycleRecord, { phase: "WARN_PENDING" }>;
const allowPendingLifecycleType = {} as Extract<import("./safetyKernelV31NonceLifecyclePolicy").SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }>;
const consumedAllowLifecycleType = {} as Extract<import("./safetyKernelV31NonceLifecyclePolicy").SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "ALLOW" };
const consumedWarnLifecycleType = {} as Extract<import("./safetyKernelV31NonceLifecyclePolicy").SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "WARN" };
// @ts-expect-error rejected decision commit must preserve ISSUED lifecycle
const invalidDecisionFailureLifecycle: SafetyKernelV31NonceDecisionCommitResult = { committed: false, lifecycle: warnPendingLifecycleType, evidence: fail };
// @ts-expect-error successful WARN confirmation must become ALLOW_PENDING_EXECUTION
const invalidWarnConfirmationSuccess: SafetyKernelV31NonceWarnConfirmationCommitResult = { committed: true, lifecycle: consumedAllowLifecycleType, evidence: ok };
// @ts-expect-error rejected allowed completion must preserve ALLOW_PENDING_EXECUTION
const invalidAllowedCompletionFailure: SafetyKernelV31NonceAllowedExecutionCompletionCommitResult = { committed: false, lifecycle: warnPendingLifecycleType, evidence: fail };
// @ts-expect-error successful allowed completion must consume an ALLOW lifecycle
const invalidAllowedCompletionDecision: SafetyKernelV31NonceAllowedExecutionCompletionCommitResult = { committed: true, lifecycle: consumedWarnLifecycleType, evidence: ok };
// @ts-expect-error successful WARN termination must consume a WARN lifecycle
const invalidWarnTerminalDecision: SafetyKernelV31NonceWarnTerminalCommitResult = { committed: true, lifecycle: consumedAllowLifecycleType, evidence: ok };
void issuedLifecycleType;
void allowPendingLifecycleType;
void invalidDecisionFailureLifecycle;
void invalidWarnConfirmationSuccess;
void invalidAllowedCompletionFailure;
void invalidAllowedCompletionDecision;
void invalidWarnTerminalDecision;

class EvidenceStub implements SafetyKernelV31NonceEvidencePort {
  decisionWrite = ok;
  warnWrite = ok;
  allowedWrite = ok;
  confirmWrite = ok;
  decisionCalls = 0;
  allowedEvidence: SafetyKernelV31AllowedExecutionCompletionEvidence | null = null;
  confirmEvidence: SafetyKernelV31WarnConfirmationEvidence | null = null;
  confirmTimestamp: string | undefined = undefined;
  warnEvidence: SafetyKernelV31WarnTerminalEvidence | null = null;

  async appendDecision(): Promise<SafetyKernelV31EvidenceWriteResult> {
    this.decisionCalls += 1;
    return this.decisionWrite;
  }

  async appendWarnConfirmation(evidence: SafetyKernelV31WarnConfirmationEvidence, timestamp?: string): Promise<SafetyKernelV31EvidenceWriteResult> {
    this.confirmEvidence = evidence;
    this.confirmTimestamp = timestamp;
    return this.confirmWrite;
  }

  async appendAllowedExecutionCompletion(evidence: SafetyKernelV31AllowedExecutionCompletionEvidence): Promise<SafetyKernelV31EvidenceWriteResult> {
    this.allowedEvidence = evidence;
    return this.allowedWrite;
  }

  async appendWarnTerminal(evidence: SafetyKernelV31WarnTerminalEvidence): Promise<SafetyKernelV31EvidenceWriteResult> {
    this.warnEvidence = evidence;
    return this.warnWrite;
  }

  async verifyIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport> {
    return { ok: true, ledgerExists: true, ledgerPath: "/evidence.jsonl", eventCount: 0, headHash: "head" };
  }
}

function decision(actionId: string, nonce: string, value: SafetyKernelV31KernelDecisionResult["decision"]): SafetyKernelV31KernelDecisionResult {
  return {
    action_id: actionId,
    decision: value,
    approval_nonce: nonce,
    policy_version: "3.1-test",
    reasons: ["test"],
    human_readable_summary: "test",
    receipt_required: true,
    ledger_required: true,
  };
}

test("nonce transaction coordinator invariant remains local, evidence-first, disconnected, and non-executing", () => {
  assert.deepEqual(SAFETY_KERNEL_V31_NONCE_TRANSACTION_COORDINATOR_INVARIANT, {
    LOCAL_NONCE_ONLY: true,
    RAW_NONCE_PERSISTED: false,
    RAW_NONCE_LOGGED: false,
    EVIDENCE_REQUIRED_BEFORE_STATE_COMMIT: true,
    RUNTIME_CONNECTED: false,
    EXECUTION_AUTHORITY_GRANTED: false,
  });
});

test("coordinator issues a local cryptographic nonce with ISSUED lifecycle", () => {
  const issued = new SafetyKernelV31NonceTransactionCoordinator(new EvidenceStub()).issue("action-1");
  assert.equal(issued.lifecycle.actionId, "action-1");
  assert.equal(issued.lifecycle.approvalNonce, issued.approvalNonce);
  assert.equal(issued.lifecycle.phase, "ISSUED");
  assert.equal(issued.randomSource, "crypto.randomBytes");
});

test("decision state commits only after successful evidence write", async () => {
  const evidence = new EvidenceStub();
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(evidence);
  const issued = coordinator.issue("action-allow");
  const committed = await coordinator.applyDecision(
    issued.lifecycle,
    decision("action-allow", issued.approvalNonce, "ALLOW")
  );
  assert.equal(committed.committed, true);
  assert.equal(committed.lifecycle.phase, "ALLOW_PENDING_EXECUTION");

  evidence.decisionWrite = fail;
  const blocked = coordinator.issue("action-block");
  const rejected = await coordinator.applyDecision(
    blocked.lifecycle,
    decision("action-block", blocked.approvalNonce, "BLOCK")
  );
  assert.equal(rejected.committed, false);
  assert.deepEqual(rejected.lifecycle, blocked.lifecycle);
});

test("action and nonce mismatches are rejected before evidence append",  async () => {
  const evidence = new EvidenceStub();
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(evidence);
  const issued = coordinator.issue("action-match");

  await assert.rejects(
    coordinator.applyDecision(issued.lifecycle, decision("other", issued.approvalNonce, "ALLOW")),
    /ACTION_ID_MISMATCH/
  );
  await assert.rejects(
    coordinator.applyDecision(issued.lifecycle, decision("action-match", "other", "ALLOW")),
    /APPROVAL_NONCE_MISMATCH/
  );
  assert.equal(evidence.decisionCalls, 0);
});

test("WARN confirmation and allowed execution completion commit only after evidence succeeds", async () => {
  const evidence = new EvidenceStub();
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(evidence);
  const issued = coordinator.issue("action-warn");
  const pending = await coordinator.applyDecision(
    issued.lifecycle,
    decision("action-warn", issued.approvalNonce, "WARN"),
    45
  );
  assert.equal(pending.lifecycle.phase, "WARN_PENDING");
  assert.equal(pending.lifecycle.warnTimeoutSeconds, 45);

  const timestamp = "2026-01-01T00:03:00.000Z";
  const confirmation = await coordinator.confirmWarn(pending.lifecycle, timestamp);
  assert.equal(confirmation.committed, true);
  assert.equal(confirmation.lifecycle.phase, "ALLOW_PENDING_EXECUTION");
  assert.equal(evidence.confirmEvidence?.action_id, "action-warn");
  assert.equal(evidence.confirmEvidence?.nonce_consumed, false);
  assert.equal(evidence.confirmEvidence?.next_state, "ALLOW_PENDING_EXECUTION");
  assert.equal(evidence.confirmEvidence?.execution_authority_granted, false);
  assert.equal(evidence.confirmTimestamp, timestamp);
  const confirmed = confirmation.lifecycle;
  const completed = await coordinator.completeAllowedExecution(confirmed);
  assert.equal(completed.committed, true);
  assert.equal(completed.lifecycle.phase, "CONSUMED");
  assert.equal(completed.lifecycle.nonceConsumed, true);
  assert.equal(evidence.allowedEvidence?.action_id, "action-warn");
  assert.equal(evidence.allowedEvidence?.nonce_consumed, true);
  assert.equal(evidence.allowedEvidence?.receipt_required, true);
  assert.equal(evidence.allowedEvidence?.ledger_required, true);

  evidence.confirmWrite = fail;
  const confirmationRejected = await coordinator.confirmWarn(pending.lifecycle, timestamp);
  assert.equal(confirmationRejected.committed, false);
  assert.deepEqual(confirmationRejected.lifecycle, pending.lifecycle);
  evidence.confirmWrite = ok;

  evidence.allowedWrite = fail;
  const rejected = await coordinator.completeAllowedExecution(confirmed);
  assert.equal(rejected.committed, false);
  assert.deepEqual(rejected.lifecycle, confirmed);
});

test("WARN terminal state commits only when terminal evidence succeeds", async () => {
  const evidence = new EvidenceStub();
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(evidence);
  const first = coordinator.issue("action-cancel");
  const pending = await coordinator.applyDecision(
    first.lifecycle,
    decision("action-cancel", first.approvalNonce, "WARN")
  );
  const cancelled = await coordinator.terminateWarn(pending.lifecycle, "cancel_by_user");
  assert.equal(cancelled.committed, true);
  assert.equal(cancelled.lifecycle.phase, "CONSUMED");
  assert.equal(evidence.warnEvidence?.reason, "cancel_by_user");

  evidence.warnWrite = fail;
  const second = coordinator.issue("action-timeout");
  const pending2 = await coordinator.applyDecision(
    second.lifecycle,
    decision("action-timeout", second.approvalNonce, "WARN")
  );
  const timedOut = await coordinator.terminateWarn(pending2.lifecycle, "timeout_expired");
  assert.equal(timedOut.committed, false);
  assert.deepEqual(timedOut.lifecycle, pending2.lifecycle);
});


test("coordinator rejects invalid lifecycle phases before evidence append", async () => {
  const evidence = new EvidenceStub();
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(evidence);
  const issued = coordinator.issue("action-invalid-lifecycle");
  const blocked = await coordinator.applyDecision(
    issued.lifecycle,
    decision("action-invalid-lifecycle", issued.approvalNonce, "BLOCK")
  );
  if (!blocked.committed) throw new Error("EXPECTED_BLOCK_COMMIT");
  await assert.rejects(
    coordinator.applyDecision(
      blocked.lifecycle,
      decision("action-invalid-lifecycle", issued.approvalNonce, "ALLOW")
    ),
    /NONCE_NOT_ACTIVE/
  );
  await assert.rejects(coordinator.confirmWarn(issued.lifecycle), /WARN_NOT_PENDING/);
  await assert.rejects(
    coordinator.completeAllowedExecution(issued.lifecycle),
    /ALLOW_EXECUTION_NOT_PENDING/
  );
  assert.equal(evidence.decisionCalls, 1);
});

test("coordinator delegates evidence integrity verification", async () => {
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(new EvidenceStub());
  assert.deepEqual(await coordinator.verifyEvidenceIntegrity(), {
    ok: true,
    ledgerExists: true,
    ledgerPath: "/evidence.jsonl",
    eventCount: 0,
    headHash: "head",
  });
});

test("coordinator preserves evidence arguments, bindings, timestamps, and port errors", async () => {
  const seen: {
    decision?: SafetyKernelV31KernelDecisionResult;
    decisionTimestamp?: string;
    confirmation?: SafetyKernelV31WarnConfirmationEvidence;
    confirmationTimestamp?: string;
    completion?: SafetyKernelV31AllowedExecutionCompletionEvidence;
    completionTimestamp?: string;
    terminal?: SafetyKernelV31WarnTerminalEvidence;
    terminalTimestamp?: string;
  } = {};

  const port: SafetyKernelV31NonceEvidencePort = {
    async appendDecision(result, timestamp) {
      seen.decision = result;
      seen.decisionTimestamp = timestamp;
      return ok;
    },
    async appendWarnConfirmation(evidence, timestamp) {
      seen.confirmation = evidence;
      seen.confirmationTimestamp = timestamp;
      return ok;
    },
    async appendAllowedExecutionCompletion(evidence, timestamp) {
      seen.completion = evidence;
      seen.completionTimestamp = timestamp;
      return ok;
    },
    async appendWarnTerminal(evidence, timestamp) {
      seen.terminal = evidence;
      seen.terminalTimestamp = timestamp;
      return ok;
    },
    async verifyIntegrity() {
      return {
        ok: true,
        ledgerExists: true,
        ledgerPath: "/evidence.jsonl",
        eventCount: 0,
        headHash: "head",
      };
    },
  };

  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(port);
  const decisionTimestamp = "2026-07-16T23:30:00.000Z";
  const issuedAllow = coordinator.issue("action-decision-arguments");
  const allowDecision = decision(
    "action-decision-arguments",
    issuedAllow.approvalNonce,
    "ALLOW"
  );
  const allowed = await coordinator.applyDecision(
    issuedAllow.lifecycle,
    allowDecision,
    undefined,
    decisionTimestamp
  );
  assert.equal(seen.decision, allowDecision);
  assert.equal(seen.decisionTimestamp, decisionTimestamp);
  if (!allowed.committed) throw new Error("EXPECTED_ALLOW_COMMIT");

  const completionTimestamp = "2026-07-16T23:31:00.000Z";
  await coordinator.completeAllowedExecution(
    allowed.lifecycle,
    completionTimestamp
  );
  assert.deepEqual(seen.completion, {
    action_id: "action-decision-arguments",
    approval_nonce: issuedAllow.approvalNonce,
    nonce_consumed: true,
    receipt_required: true,
    ledger_required: true,
  });
  assert.equal(seen.completionTimestamp, completionTimestamp);

  const issuedWarn = coordinator.issue("action-warn-arguments");
  const warned = await coordinator.applyDecision(
    issuedWarn.lifecycle,
    decision("action-warn-arguments", issuedWarn.approvalNonce, "WARN"),
    45
  );
  if (!warned.committed) throw new Error("EXPECTED_WARN_COMMIT");

  const confirmationTimestamp = "2026-07-16T23:32:00.000Z";
  await coordinator.confirmWarn(warned.lifecycle, confirmationTimestamp);
  assert.deepEqual(seen.confirmation, {
    action_id: "action-warn-arguments",
    approval_nonce: issuedWarn.approvalNonce,
    nonce_consumed: false,
    next_state: "ALLOW_PENDING_EXECUTION",
    receipt_required: true,
    ledger_required: true,
    execution_authority_granted: false,
  });
  assert.equal(seen.confirmationTimestamp, confirmationTimestamp);

  const issuedTerminal = coordinator.issue("action-terminal-arguments");
  const terminalPending = await coordinator.applyDecision(
    issuedTerminal.lifecycle,
    decision(
      "action-terminal-arguments",
      issuedTerminal.approvalNonce,
      "WARN"
    ),
    60
  );
  if (!terminalPending.committed) throw new Error("EXPECTED_TERMINAL_WARN_COMMIT");

  const terminalTimestamp = "2026-07-16T23:33:00.000Z";
  await coordinator.terminateWarn(
    terminalPending.lifecycle,
    "timeout_expired",
    terminalTimestamp
  );
  assert.deepEqual(seen.terminal, {
    action_id: "action-terminal-arguments",
    approval_nonce: issuedTerminal.approvalNonce,
    reason: "timeout_expired",
    nonce_consumed: true,
    return_state: "IDLE",
    receipt_required: true,
    ledger_required: true,
    warn_must_never_auto_proceed: true,
  });
  assert.equal(seen.terminalTimestamp, terminalTimestamp);

  const failure = new Error("EVIDENCE_PORT_FAILURE");
  const throwingPort: SafetyKernelV31NonceEvidencePort = {
    async appendDecision() {
      throw failure;
    },
    async appendWarnConfirmation() {
      throw failure;
    },
    async appendAllowedExecutionCompletion() {
      throw failure;
    },
    async appendWarnTerminal() {
      throw failure;
    },
    async verifyIntegrity() {
      throw failure;
    },
  };
  const throwingCoordinator = new SafetyKernelV31NonceTransactionCoordinator(
    throwingPort
  );

  await assert.rejects(
    () =>
      throwingCoordinator.applyDecision(
        issuedAllow.lifecycle,
        allowDecision,
        undefined,
        decisionTimestamp
      ),
    (error) => error === failure
  );
  await assert.rejects(
    () => throwingCoordinator.confirmWarn(warned.lifecycle),
    (error) => error === failure
  );
  await assert.rejects(
    () => throwingCoordinator.completeAllowedExecution(allowed.lifecycle),
    (error) => error === failure
  );
  await assert.rejects(
    () =>
      throwingCoordinator.terminateWarn(
        terminalPending.lifecycle,
        "cancel_by_user"
      ),
    (error) => error === failure
  );
  await assert.rejects(
    () => throwingCoordinator.verifyEvidenceIntegrity(),
    (error) => error === failure
  );
});

test("coordinator rejects pending phase and decision mismatches before evidence append", async () => {
  const evidence = new EvidenceStub();
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(evidence);

  const issuedWarn = coordinator.issue("action-warn-decision-mismatch");
  const warned = await coordinator.applyDecision(
    issuedWarn.lifecycle,
    decision(
      "action-warn-decision-mismatch",
      issuedWarn.approvalNonce,
      "WARN"
    )
  );
  if (!warned.committed) throw new Error("EXPECTED_WARN_COMMIT");
  const warnDecisionMismatch = {
    ...warned.lifecycle,
    decision: "ALLOW",
  } as unknown as Parameters<
    SafetyKernelV31NonceTransactionCoordinator["confirmWarn"]
  >[0];

  await assert.rejects(
    () => coordinator.confirmWarn(warnDecisionMismatch),
    /WARN_NOT_PENDING/
  );
  await assert.rejects(
    () => coordinator.terminateWarn(warnDecisionMismatch, "cancel_by_user"),
    /WARN_NOT_PENDING/
  );

  const issuedAllow = coordinator.issue("action-allow-decision-mismatch");
  const allowed = await coordinator.applyDecision(
    issuedAllow.lifecycle,
    decision(
      "action-allow-decision-mismatch",
      issuedAllow.approvalNonce,
      "ALLOW"
    )
  );
  if (!allowed.committed) throw new Error("EXPECTED_ALLOW_COMMIT");
  const allowDecisionMismatch = {
    ...allowed.lifecycle,
    decision: "WARN",
  } as unknown as Parameters<
    SafetyKernelV31NonceTransactionCoordinator["completeAllowedExecution"]
  >[0];

  await assert.rejects(
    () => coordinator.completeAllowedExecution(allowDecisionMismatch),
    /ALLOW_EXECUTION_NOT_PENDING/
  );
  assert.equal(evidence.confirmEvidence, null);
  assert.equal(evidence.warnEvidence, null);
  assert.equal(evidence.allowedEvidence, null);
});

test("coordinator forwards execution binding to completion evidence", async () => {
  const evidence = new EvidenceStub();
  const coordinator =
    new SafetyKernelV31NonceTransactionCoordinator(evidence);
  const issued = coordinator.issue(
    "action-coordinated-completion-binding"
  );

  const allowed = await coordinator.applyDecision(
    issued.lifecycle,
    decision(
      "action-coordinated-completion-binding",
      issued.approvalNonce,
      "ALLOW"
    )
  );

  if (!allowed.committed) {
    throw new Error("EXPECTED_ALLOW_COMMIT");
  }

  const executionBinding:
    SafetyKernelV31AllowedExecutionCompletionBinding = {
      authority_revision: 29,
      command_sha256: "sha256:" + "a".repeat(64),
      snapshot_binding_sha256:
        "sha256:" + "b".repeat(64),
      exit_code: 0,
      stdout_sha256: "sha256:" + "c".repeat(64),
      stderr_sha256: "sha256:" + "d".repeat(64),
      stdout_bytes: 21,
      stderr_bytes: 22,
    };

  const timestamp = "2026-07-19T11:00:00.000Z";

  const completed =
    await coordinator.completeAllowedExecution(
      allowed.lifecycle,
      timestamp,
      executionBinding
    );

  assert.equal(completed.committed, true);
  assert.deepEqual(evidence.allowedEvidence, {
    action_id: "action-coordinated-completion-binding",
    approval_nonce: issued.approvalNonce,
    nonce_consumed: true,
    receipt_required: true,
    ledger_required: true,
    execution_binding: executionBinding,
  });
});