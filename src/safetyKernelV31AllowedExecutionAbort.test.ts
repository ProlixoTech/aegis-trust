import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import type {
  SafetyKernelV31AllowedExecutionAbortReason,
} from "../packages/aegis-core";
import {
  abortSafetyKernelV31AllowedExecution,
  type SafetyKernelV31NonceLifecycleRecord,
} from "./safetyKernelV31NonceLifecyclePolicy";
import {
  SafetyKernelV31EvidenceWriter,
} from "./safetyKernelV31EvidenceWriter";
import {
  SafetyKernelV31NonceTransactionCoordinator,
} from "./safetyKernelV31NonceTransactionCoordinator";
import {
  SafetyKernelV31TransactionReviewPipeline,
} from "./safetyKernelV31TransactionReviewPipeline";
import {
  SafetyKernelV31RuntimeController,
} from "./safetyKernelV31RuntimeController";

function allowPending(): SafetyKernelV31NonceLifecycleRecord {
  return {
    actionId: "allowed-execution-abort-test-action",
    approvalNonce: "allowed-execution-abort-test-nonce" as never,
    warnMustNeverAutoProceed: true,
    receiptRequired: true,
    ledgerRequired: true,
    phase: "ALLOW_PENDING_EXECUTION",
    decision: "ALLOW",
    nonceConsumed: false,
    parentEnvelopeInvalidated: false,
    childNoncesRequired: false,
  };
}

test("allowed execution abort consumes the pending nonce and records a bounded reason", () => {
  const result = abortSafetyKernelV31AllowedExecution(
    allowPending(),
    "snapshot_failed"
  );

  assert.equal(result.lifecycle.phase, "CONSUMED");
  assert.equal(result.lifecycle.nonceConsumed, true);
  assert.equal(result.evidence.reason, "snapshot_failed");
  assert.equal(result.evidence.execution_completed, false);
  assert.equal(result.evidence.return_state, "IDLE");
  assert.equal(result.evidence.nonce_consumed, true);
});

test("allowed execution abort rejects non-pending lifecycle and invalid runtime reason", () => {
  const consumed = {
    ...allowPending(),
    phase: "CONSUMED" as const,
    nonceConsumed: true as const,
  } as SafetyKernelV31NonceLifecycleRecord;

  assert.throws(
    () => abortSafetyKernelV31AllowedExecution(consumed, "execution_failed"),
    /ALLOW_EXECUTION_NOT_PENDING/
  );
  assert.throws(
    () => abortSafetyKernelV31AllowedExecution(
      allowPending(),
      "invalid_reason" as SafetyKernelV31AllowedExecutionAbortReason
    ),
    /INVALID_ALLOWED_EXECUTION_ABORT_REASON/
  );
});

test("allowed execution abort evidence is durably written with no execution success claim", async () => {
  const root = await fs.promises.mkdtemp(
    path.join(os.tmpdir(), "aegis-allowed-abort-")
  );

  try {
    const writer = new SafetyKernelV31EvidenceWriter(
      path.join(root, ".aegis")
    );
    const result = await writer.appendAllowedExecutionAbort({
      action_id: "allowed-abort-evidence-test",
      approval_nonce: "allowed-abort-evidence-nonce" as never,
      reason: "authority_drift",
      nonce_consumed: true,
      execution_completed: false,
      return_state: "IDLE",
      receipt_required: true,
      ledger_required: true,
    }, "2026-07-19T00:00:00.000Z");

    assert.equal(result.ok, true);
    if (!result.ok) return;

    const receipt = await fs.promises.readFile(
      result.receiptPath,
      "utf8"
    );
    const ledger = await fs.promises.readFile(
      result.ledgerPath,
      "utf8"
    );

    assert.match(receipt, /Allowed execution abort reason: authority_drift/);
    assert.match(receipt, /Execution completed: false/);
    assert.match(ledger, /"eventType":"allowed_execution_aborted"/);
    assert.equal(ledger.includes("allowed-abort-evidence-nonce"), false);
  } finally {
    await fs.promises.rm(root, {
      recursive: true,
      force: true,
    });
  }
});

test("coordinator commits allowed abort only after evidence succeeds", async () => {
  let capturedReason = "";
  const successPort = {
    appendAllowedExecutionAbort: async (evidence: { reason: string }) => {
      capturedReason = evidence.reason;
      return {
        ok: true as const,
        ledgerPath: "ledger",
        receiptPath: "receipt",
        reason: "success" as const,
      };
    },
  } as never;

  const successCoordinator =
    new SafetyKernelV31NonceTransactionCoordinator(successPort);
  const success = await successCoordinator.abortAllowedExecution(
    allowPending(),
    "execution_failed",
    "2026-07-19T00:00:00.000Z"
  );

  assert.equal(success.committed, true);
  assert.equal(success.lifecycle.phase, "CONSUMED");
  assert.equal(capturedReason, "execution_failed");

  const failurePort = {
    appendAllowedExecutionAbort: async () => ({
      ok: false as const,
      ledgerPath: null,
      receiptPath: null,
      reason: "write_failed" as const,
    }),
  } as never;

  const failureCoordinator =
    new SafetyKernelV31NonceTransactionCoordinator(failurePort);
  const failure = await failureCoordinator.abortAllowedExecution(
    allowPending(),
    "cancel_by_user"
  );

  assert.equal(failure.committed, false);
  assert.equal(failure.lifecycle.phase, "ALLOW_PENDING_EXECUTION");
  assert.equal(failure.lifecycle.nonceConsumed, false);
});

test("pipeline and runtime controller expose only evidence-first session abort", async () => {
  const publicSession = {
    sessionId: "s".repeat(48),
    actionId: "allowed-execution-abort-test-action",
    approvalNonceSha256: "f".repeat(64),
    lifecyclePhase: "CONSUMED",
    nonceConsumed: true,
    createdAt: "2026-07-19T00:00:00.000Z",
    expiresAt: null,
  };

  let replaced = false;
  const service = {
    abortAllowedExecution: async (
      _lifecycle: unknown,
      reason: SafetyKernelV31AllowedExecutionAbortReason
    ) => ({
      committed: true,
      lifecycle: {
        ...allowPending(),
        phase: "CONSUMED",
        nonceConsumed: true,
      },
      evidence: {
        ok: true,
        ledgerPath: "ledger",
        receiptPath: "receipt",
        reason: "success",
      },
      abortReason: reason,
    }),
  } as never;
  const store = {
    getLifecycleForInternalUse: () => allowPending(),
    replace: () => {
      replaced = true;
      return publicSession;
    },
  } as never;

  const pipeline =
    new SafetyKernelV31TransactionReviewPipeline(service, store);
  const pipelineResult =
    await pipeline.abortAllowedExecutionSession(
      publicSession.sessionId,
      "snapshot_failed"
    );

  assert.equal(replaced, true);
  assert.equal(pipelineResult.reason, "snapshot_failed");
  assert.equal(pipelineResult.evidenceCommitted, true);
  assert.equal(pipelineResult.session.lifecyclePhase, "CONSUMED");

  let delegatedReason = "";
  const controllerPort = {
    abortAllowedExecutionSession: async (
      _sessionId: string,
      reason: SafetyKernelV31AllowedExecutionAbortReason
    ) => {
      delegatedReason = reason;
      return pipelineResult;
    },
  } as never;
  const controller =
    new SafetyKernelV31RuntimeController(controllerPort);
  const controllerResult =
    await controller.abortAllowedExecutionSession(
      publicSession.sessionId,
      "authority_drift"
    );

  assert.equal(delegatedReason, "authority_drift");
  assert.equal(controllerResult.evidenceCommitted, true);
});
