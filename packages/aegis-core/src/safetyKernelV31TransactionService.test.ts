import test from "node:test";
import assert from "node:assert/strict";

import type {
  ActionQualityResult,
  SafetyKernelV31AllowedExecutionCompletionBinding,
  SafetyKernelV31AllowedExecutionCompletionEvidence,
  SafetyKernelV31KernelDecisionResult,
  SafetyKernelV31WarnConfirmationEvidence,
  SafetyKernelV31WarnTerminalEvidence,
} from "./types";
import type {
  SafetyKernelV31EvidenceIntegrityReport,
  SafetyKernelV31EvidenceWriteResult,
} from "./safetyKernelV31EvidenceWriter";
import {
  SafetyKernelV31NonceTransactionCoordinator,
} from "./safetyKernelV31NonceTransactionCoordinator";
import type {
  SafetyKernelV31NonceEvidencePort,
} from "./safetyKernelV31NonceTransactionCoordinator";
import type { SafetyKernelV31NonceLifecycleRecord } from "./safetyKernelV31NonceLifecyclePolicy";
import {
  SAFETY_KERNEL_V31_TRANSACTION_SERVICE_INVARIANT,
  SafetyKernelV31TransactionService,
} from "./safetyKernelV31TransactionService";
import type {
  SafetyKernelV31TransactionServiceInput,
  SafetyKernelV31TransactionServiceResult,
} from "./safetyKernelV31TransactionService";

const success: SafetyKernelV31EvidenceWriteResult = {
  ok: true,
  ledgerPath: "/evidence.jsonl",
  receiptPath: "/receipt.md",
  reason: "success",
};

const failure: SafetyKernelV31EvidenceWriteResult = {
  ok: false,
  ledgerPath: null,
  receiptPath: null,
  reason: "write_failed",
};

const serviceResultTypeBase = { issued: {} as never, envelope: {} as never } as const;
const allowDecisionType = { decision: "ALLOW" } as SafetyKernelV31KernelDecisionResult & { decision: "ALLOW" };
const warnDecisionType = { decision: "WARN" } as SafetyKernelV31KernelDecisionResult & { decision: "WARN" };
const blockDecisionType = { decision: "BLOCK" } as SafetyKernelV31KernelDecisionResult & { decision: "BLOCK" };
const allowPendingLifecycleType = {} as Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }>;
const warnPendingLifecycleType = {} as Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "WARN_PENDING" }>;
const blockedLifecycleType = {} as Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "BLOCKED" }>;
// @ts-expect-error successful ALLOW result cannot carry a BLOCKED lifecycle
const invalidAllowServiceSuccess: SafetyKernelV31TransactionServiceResult = { ...serviceResultTypeBase, decisionResult: allowDecisionType, commit: { committed: true, lifecycle: blockedLifecycleType, evidence: success } };
// @ts-expect-error successful WARN result must carry WARN_PENDING lifecycle
const invalidWarnServiceSuccess: SafetyKernelV31TransactionServiceResult = { ...serviceResultTypeBase, decisionResult: warnDecisionType, commit: { committed: true, lifecycle: allowPendingLifecycleType, evidence: success } };
// @ts-expect-error failed decision commit must preserve the ISSUED lifecycle
const invalidBlockServiceFailure: SafetyKernelV31TransactionServiceResult = { ...serviceResultTypeBase, decisionResult: blockDecisionType, commit: { committed: false, lifecycle: blockedLifecycleType, evidence: failure } };
void warnPendingLifecycleType;
void invalidAllowServiceSuccess;
void invalidWarnServiceSuccess;
void invalidBlockServiceFailure;

class EvidenceStub implements SafetyKernelV31NonceEvidencePort {
  decisionWrite: SafetyKernelV31EvidenceWriteResult = success;
  decisionCalls = 0;
  lastDecision: SafetyKernelV31KernelDecisionResult | null = null;
  lastDecisionTimestamp: string | undefined = undefined;
  allowedWrite: SafetyKernelV31EvidenceWriteResult = success;
  confirmWrite: SafetyKernelV31EvidenceWriteResult = success;
  lastConfirmEvidence: SafetyKernelV31WarnConfirmationEvidence | null = null;
  lastConfirmTimestamp: string | undefined = undefined;
  lastAllowedEvidence: SafetyKernelV31AllowedExecutionCompletionEvidence | null = null;
  lastAllowedTimestamp: string | undefined = undefined;
  warnWrite: SafetyKernelV31EvidenceWriteResult = success;
  lastWarnEvidence: SafetyKernelV31WarnTerminalEvidence | null = null;

  async appendDecision(
    result: SafetyKernelV31KernelDecisionResult,
    timestamp?: string
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    this.decisionCalls += 1;
    this.lastDecision = result;
    this.lastDecisionTimestamp = timestamp;
    return this.decisionWrite;
  }

  async appendWarnConfirmation(
    evidence: SafetyKernelV31WarnConfirmationEvidence,
    timestamp?: string
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    this.lastConfirmEvidence = evidence;
    this.lastConfirmTimestamp = timestamp;
    return this.confirmWrite;
  }

  async appendAllowedExecutionCompletion(
    evidence: SafetyKernelV31AllowedExecutionCompletionEvidence,
    timestamp?: string
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    this.lastAllowedEvidence = evidence;
    this.lastAllowedTimestamp = timestamp;
    return this.allowedWrite;
  }

  async appendWarnTerminal(
    evidence: SafetyKernelV31WarnTerminalEvidence
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    this.lastWarnEvidence = evidence;
    return this.warnWrite;
  }

  async verifyIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport> {
    return {
      ok: true,
      ledgerExists: true,
      ledgerPath: "/evidence.jsonl",
      eventCount: this.decisionCalls,
      headHash: "head",
    };
  }
}

function makeActionQuality(
  status: ActionQualityResult["status"]
): ActionQualityResult {
  return {
    status,
    userMessage: "review message",
    reasons: ["reason-one"],
    detectedEffects: [],
    internalRuleId: "TEST_RULE",
    source: "manual_review",
  };
}

function makeInput(actionId: string): SafetyKernelV31TransactionServiceInput {
  return {
    action_id: actionId,
    target: "src/example.ts",
    intent: "review transaction service",
    proposed_action: "read-only diagnostic",
    context_hash: "sha256:abc",
    timestamp: "2026-01-01T00:00:00.000Z",
    adapter_id: "safetyKernelV31TransactionService.test",
    policy_version: "policy-test",
    human_readable_summary: "Transaction service direct test",
    risk_class: "low",
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
  };
}

function createHarness(): {
  evidence: EvidenceStub;
  service: SafetyKernelV31TransactionService;
} {
  const evidence = new EvidenceStub();
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(evidence);
  return {
    evidence,
    service: new SafetyKernelV31TransactionService(coordinator),
  };
}

async function makeWarnPending(
  evidence: EvidenceStub,
  actionId: string
) {
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(evidence);
  const issued = coordinator.issue(actionId);
  const decision: SafetyKernelV31KernelDecisionResult = {
    action_id: actionId,
    decision: "WARN",
    approval_nonce: issued.approvalNonce,
    policy_version: "policy-test",
    reasons: ["warn lifecycle test"],
    human_readable_summary: "WARN lifecycle test",
    receipt_required: true,
    ledger_required: true,
  };
  return coordinator.applyDecision(issued.lifecycle, decision);
}

test("transaction service invariant preserves Action Quality mapping and allows only local pending-confirmation WARN policy", () => {
  assert.deepEqual(SAFETY_KERNEL_V31_TRANSACTION_SERVICE_INVARIANT, {
    LOCAL_NONCE_ONLY: true,
    ACTION_QUALITY_MAPPING_PRESERVED: true,
    LOCAL_WARN_POLICY_ALLOWED: true,
    WARN_MUST_NEVER_AUTO_PROCEED: true,
    EVIDENCE_REQUIRED_BEFORE_STATE_COMMIT: true,
    AUTOMATIC_EXECUTION_ALLOWED: false,
    RUNTIME_CONNECTED: false,
    EXECUTION_AUTHORITY_GRANTED: false,
  });
});

test("transaction service issues one local nonce and binds it to envelope, decision, and evidence", async () => {
  const { evidence, service } = createHarness();
  const result = await service.reviewAndCommit(
    makeInput("action-allow"),
    makeActionQuality("ALLOW")
  );

  assert.match(result.issued.approvalNonce, /^[0-9a-f]{64}$/);
  assert.equal(result.envelope.approval_nonce, result.issued.approvalNonce);
  assert.equal(result.decisionResult.approval_nonce, result.issued.approvalNonce);
  assert.equal(evidence.lastDecision?.approval_nonce, result.issued.approvalNonce);
  assert.equal(result.envelope.source, "manual_review");
  assert.equal(result.decisionResult.decision, "ALLOW");
  assert.equal(result.commit.committed, true);
  assert.equal(result.commit.lifecycle.phase, "ALLOW_PENDING_EXECUTION");
});

test("transaction service forwards input timestamp to decision evidence", async () => {
  const { evidence, service } = createHarness();
  const input = makeInput("action-timestamp");
  await service.reviewAndCommit(input, makeActionQuality("ALLOW"));
  assert.equal(evidence.lastDecisionTimestamp, input.timestamp);
});
test("transaction service maps REVIEW_NEEDED to REQUIRE_REVIEW and consumes only after evidence success", async () => {
  const { service } = createHarness();
  const result = await service.reviewAndCommit(
    makeInput("action-review"),
    makeActionQuality("REVIEW_NEEDED")
  );

  assert.equal(result.decisionResult.decision, "REQUIRE_REVIEW");
  assert.equal(result.commit.committed, true);
  assert.equal(result.commit.lifecycle.phase, "REQUIRE_REVIEW");
  assert.equal(result.commit.lifecycle.nonceConsumed, true);
});

test("transaction service preserves ISSUED lifecycle when evidence append fails", async () => {
  const { evidence, service } = createHarness();
  evidence.decisionWrite = failure;

  const result = await service.reviewAndCommit(
    makeInput("action-failure"),
    makeActionQuality("BLOCK")
  );

  assert.equal(result.decisionResult.decision, "BLOCK");
  assert.equal(result.commit.committed, false);
  assert.deepEqual(result.commit.lifecycle, result.issued.lifecycle);
  assert.equal(result.commit.lifecycle.phase, "ISSUED");
  assert.equal(result.commit.lifecycle.nonceConsumed, false);
});

test("transaction service preserves SPLIT_REQUIRED parent invalidation and child nonce requirement", async () => {
  const { service } = createHarness();
  const result = await service.reviewAndCommit(
    makeInput("action-split"),
    makeActionQuality("SPLIT_REQUIRED")
  );

  assert.equal(result.decisionResult.decision, "SPLIT_REQUIRED");
  assert.equal(result.commit.committed, true);
  assert.equal(result.commit.lifecycle.phase, "SPLIT_REQUIRED");
  assert.equal(result.commit.lifecycle.nonceConsumed, true);
  assert.equal(result.commit.lifecycle.parentEnvelopeInvalidated, true);
  assert.equal(result.commit.lifecycle.childNoncesRequired, true);
});

test("transaction service creates unique local nonces for separate transactions", async () => {
  const { service } = createHarness();
  const first = await service.reviewAndCommit(
    makeInput("action-one"),
    makeActionQuality("ALLOW")
  );
  const second = await service.reviewAndCommit(
    makeInput("action-two"),
    makeActionQuality("ALLOW")
  );

  assert.notEqual(first.issued.approvalNonce, second.issued.approvalNonce);
  assert.equal(first.issued.randomSource, "crypto.randomBytes");
  assert.equal(second.issued.randomSource, "crypto.randomBytes");
});

test("transaction service commits allowed execution completion only after evidence succeeds", async () => {
  const { evidence, service } = createHarness();
  const reviewed = await makeWarnPending(evidence, "action-warn-confirm");

  assert.equal(reviewed.lifecycle.phase, "WARN_PENDING");
  const timestamp = "2026-01-01T00:03:00.000Z";
  const confirmation = await service.confirmWarn(reviewed.lifecycle, timestamp);
  assert.equal(confirmation.committed, true);
  assert.equal(confirmation.lifecycle.phase, "ALLOW_PENDING_EXECUTION");
  assert.equal(evidence.lastConfirmEvidence?.action_id, "action-warn-confirm");
  assert.equal(evidence.lastConfirmEvidence?.nonce_consumed, false);
  assert.equal(evidence.lastConfirmEvidence?.execution_authority_granted, false);
  assert.equal(evidence.lastConfirmTimestamp, timestamp);
  const confirmed = confirmation.lifecycle;
  const completed = await service.completeAllowedExecution(confirmed, timestamp);
  assert.equal(completed.committed, true);
  assert.equal(completed.lifecycle.phase, "CONSUMED");
  assert.equal(completed.lifecycle.nonceConsumed, true);
  assert.equal(evidence.lastAllowedEvidence?.action_id, "action-warn-confirm");
  assert.equal(evidence.lastAllowedEvidence?.nonce_consumed, true);
  assert.equal(evidence.lastAllowedEvidence?.receipt_required, true);
  assert.equal(evidence.lastAllowedEvidence?.ledger_required, true);
  assert.equal(evidence.lastAllowedTimestamp, timestamp);

  evidence.confirmWrite = failure;
  const confirmationRejected = await service.confirmWarn(reviewed.lifecycle, timestamp);
  assert.equal(confirmationRejected.committed, false);
  assert.deepEqual(confirmationRejected.lifecycle, reviewed.lifecycle);
  evidence.confirmWrite = success;

  evidence.allowedWrite = failure;
  const rejected = await service.completeAllowedExecution(confirmed, timestamp);
  assert.equal(rejected.committed, false);
  assert.deepEqual(rejected.lifecycle, confirmed);
});

test("transaction service commits WARN terminal state only after terminal evidence succeeds", async () => {
  const { evidence, service } = createHarness();
  const first = await makeWarnPending(evidence, "action-warn-cancel");
  const cancelled = await service.terminateWarn(
    first.lifecycle,
    "cancel_by_user"
  );
  assert.equal(cancelled.committed, true);
  assert.equal(cancelled.lifecycle.phase, "CONSUMED");
  assert.equal(evidence.lastWarnEvidence?.reason, "cancel_by_user");

  evidence.warnWrite = failure;
  const second = await makeWarnPending(evidence, "action-warn-timeout");
  const timedOut = await service.terminateWarn(
    second.lifecycle,
    "timeout_expired"
  );
  assert.equal(timedOut.committed, false);
  assert.deepEqual(timedOut.lifecycle, second.lifecycle);
});

test("transaction service Action Quality review path never creates WARN lifecycle", async () => {
  const cases = [
    ["ALLOW", "ALLOW", "ALLOW_PENDING_EXECUTION"],
    ["REVIEW_NEEDED", "REQUIRE_REVIEW", "REQUIRE_REVIEW"],
    ["SPLIT_REQUIRED", "SPLIT_REQUIRED", "SPLIT_REQUIRED"],
    ["BLOCK", "BLOCK", "BLOCKED"],
  ] as const;
  for (const [status, decision, phase] of cases) {
    const { service } = createHarness();
    const result = await service.reviewAndCommit(makeInput("action-no-warn-" + status.toLowerCase()), makeActionQuality(status));
    assert.equal(result.decisionResult.decision, decision);
    assert.equal(result.commit.lifecycle.phase, phase);
    assert.notEqual(result.decisionResult.decision, "WARN");
    assert.notEqual(result.commit.lifecycle.phase, "WARN_PENDING");
  }
});

test("transaction service creates WARN only for low-risk AI connector reviewed execution", async () => {
  const { service } = createHarness();
  const result = await service.reviewAndCommit(
    {
      ...makeInput("action-ai-warn"),
      risk_class: "low",
      capability_requested: {
        operation_class: "execute",
        scope: "workspace",
        manner: "requires_review",
      },
      mutation_scope: {
        scope: "workspace",
        target: "src/example.ts",
        protected_target: false,
      },
    },
    {
      ...makeActionQuality("ALLOW"),
      source: "ai_connector",
    }
  );

  assert.equal(result.decisionResult.decision, "WARN");
  assert.equal(result.commit.lifecycle.phase, "WARN_PENDING");
  assert.equal(result.commit.lifecycle.nonceConsumed, false);
  assert.ok(
    result.decisionResult.reasons.includes(
      "LOCAL_AI_CONNECTOR_LOW_RISK_EXECUTION_REQUIRES_USER_CONFIRMATION"
    )
  );
});

test("transaction service WARN policy preserves existing decisions when any policy condition differs", async () => {
  const assertNotWarn = async (
    actionId: string,
    inputPatch: Partial<SafetyKernelV31TransactionServiceInput>,
    actionQuality: ActionQualityResult,
    expectedDecision: SafetyKernelV31KernelDecisionResult["decision"],
    expectedPhase: string
  ) => {
    const { service } = createHarness();
    const result = await service.reviewAndCommit(
      {
        ...makeInput(actionId),
        capability_requested: {
          operation_class: "execute",
          scope: "workspace",
          manner: "requires_review",
        },
        mutation_scope: {
          scope: "workspace",
          target: "src/example.ts",
          protected_target: false,
        },
        ...inputPatch,
      },
      actionQuality
    );
    assert.equal(result.decisionResult.decision, expectedDecision, actionId);
    assert.equal(result.commit.lifecycle.phase, expectedPhase, actionId);
    assert.notEqual(result.decisionResult.decision, "WARN", actionId);
  };

  await assertNotWarn(
    "action-warn-source-mismatch",
    {},
    { ...makeActionQuality("ALLOW"), source: "manual_review" },
    "ALLOW",
    "ALLOW_PENDING_EXECUTION"
  );
  await assertNotWarn(
    "action-warn-status-mismatch",
    {},
    { ...makeActionQuality("REVIEW_NEEDED"), source: "ai_connector" },
    "REQUIRE_REVIEW",
    "REQUIRE_REVIEW"
  );
  await assertNotWarn(
    "action-warn-risk-mismatch",
    { risk_class: "medium" },
    { ...makeActionQuality("ALLOW"), source: "ai_connector" },
    "ALLOW",
    "ALLOW_PENDING_EXECUTION"
  );
  await assertNotWarn(
    "action-warn-operation-mismatch",
    {
      capability_requested: {
        operation_class: "read",
        scope: "workspace",
        manner: "requires_review",
      },
    },
    { ...makeActionQuality("ALLOW"), source: "ai_connector" },
    "ALLOW",
    "ALLOW_PENDING_EXECUTION"
  );
  await assertNotWarn(
    "action-warn-scope-mismatch",
    {
      capability_requested: {
        operation_class: "execute",
        scope: "specific_file",
        manner: "requires_review",
      },
      mutation_scope: {
        scope: "specific_file",
        target: "src/example.ts",
        protected_target: false,
      },
    },
    { ...makeActionQuality("ALLOW"), source: "ai_connector" },
    "ALLOW",
    "ALLOW_PENDING_EXECUTION"
  );
  await assertNotWarn(
    "action-warn-manner-mismatch",
    {
      capability_requested: {
        operation_class: "execute",
        scope: "workspace",
        manner: "preview_only",
      },
    },
    { ...makeActionQuality("ALLOW"), source: "ai_connector" },
    "ALLOW",
    "ALLOW_PENDING_EXECUTION"
  );
  await assertNotWarn(
    "action-warn-protected-target-mismatch",
    {
      mutation_scope: {
        scope: "workspace",
        target: "src/example.ts",
        protected_target: true,
      },
    },
    { ...makeActionQuality("ALLOW"), source: "ai_connector" },
    "ALLOW",
    "ALLOW_PENDING_EXECUTION"
  );
});


test("transaction service WARN policy requires matching workspace mutation scope and target", async () => {
  const cases: Array<{ actionId: string; mutationScope: SafetyKernelV31TransactionServiceInput["mutation_scope"] }> = [
    { actionId: "action-warn-mutation-scope-mismatch", mutationScope: { scope: "specific_file", target: "src/example.ts", protected_target: false } },
    { actionId: "action-warn-mutation-target-mismatch", mutationScope: { scope: "workspace", target: "src/other.ts", protected_target: false } },
  ];
  for (const { actionId, mutationScope } of cases) {
    const { service } = createHarness();
    const result = await service.reviewAndCommit(
      {
        ...makeInput(actionId),
        risk_class: "low",
        capability_requested: { operation_class: "execute", scope: "workspace", manner: "requires_review" },
        mutation_scope: mutationScope,
      },
      { ...makeActionQuality("ALLOW"), source: "ai_connector" }
    );
    assert.equal(result.decisionResult.decision, "ALLOW", actionId);
    assert.equal(result.commit.lifecycle.phase, "ALLOW_PENDING_EXECUTION", actionId);
    assert.notEqual(result.decisionResult.decision, "WARN", actionId);
  }
});


test("transaction service rejects committed lifecycle mismatches for every decision", async () => {
  const evidence = new EvidenceStub();
  const coordinator = new SafetyKernelV31NonceTransactionCoordinator(evidence);
  coordinator.applyDecision = (async (lifecycle: SafetyKernelV31NonceLifecycleRecord) => ({
    committed: true,
    lifecycle: { ...lifecycle, phase: "ISSUED" },
    evidence: success,
  })) as typeof coordinator.applyDecision;
  const service = new SafetyKernelV31TransactionService(coordinator);
  const cases: Array<{ actionId: string; input: SafetyKernelV31TransactionServiceInput; actionQuality: ActionQualityResult }> = [
    { actionId: "allow", input: makeInput("action-lifecycle-mismatch-allow"), actionQuality: makeActionQuality("ALLOW") },
    { actionId: "warn", input: { ...makeInput("action-lifecycle-mismatch-warn"), capability_requested: { operation_class: "execute", scope: "workspace", manner: "requires_review" }, mutation_scope: { scope: "workspace", target: "src/example.ts", protected_target: false } }, actionQuality: { ...makeActionQuality("ALLOW"), source: "ai_connector" } },
    { actionId: "block", input: makeInput("action-lifecycle-mismatch-block"), actionQuality: makeActionQuality("BLOCK") },
    { actionId: "require-review", input: makeInput("action-lifecycle-mismatch-review"), actionQuality: makeActionQuality("REVIEW_NEEDED") },
    { actionId: "split-required", input: makeInput("action-lifecycle-mismatch-split"), actionQuality: makeActionQuality("SPLIT_REQUIRED") },
  ];
  for (const { actionId, input, actionQuality } of cases) {
    await assert.rejects(
      () => service.reviewAndCommit(input, actionQuality),
      /TRANSACTION_DECISION_LIFECYCLE_MISMATCH/,
      actionId
    );
  }
});

test("transaction service preserves inputs, forwards every decision and lifecycle argument, and propagates coordinator errors unchanged", async () => {
  const reviewCases: Array<{
    input: SafetyKernelV31TransactionServiceInput;
    actionQuality: ActionQualityResult;
    expectedDecision: SafetyKernelV31KernelDecisionResult["decision"];
  }> = [
    {
      input: makeInput("action-boundary-allow"),
      actionQuality: makeActionQuality("ALLOW"),
      expectedDecision: "ALLOW",
    },
    {
      input: makeInput("action-boundary-review"),
      actionQuality: makeActionQuality("REVIEW_NEEDED"),
      expectedDecision: "REQUIRE_REVIEW",
    },
    {
      input: makeInput("action-boundary-block"),
      actionQuality: makeActionQuality("BLOCK"),
      expectedDecision: "BLOCK",
    },
    {
      input: makeInput("action-boundary-split"),
      actionQuality: makeActionQuality("SPLIT_REQUIRED"),
      expectedDecision: "SPLIT_REQUIRED",
    },
    {
      input: {
        ...makeInput("action-boundary-warn"),
        risk_class: "low",
        capability_requested: {
          operation_class: "execute",
          scope: "workspace",
          manner: "requires_review",
        },
        mutation_scope: {
          scope: "workspace",
          target: "src/example.ts",
          protected_target: false,
        },
      },
      actionQuality: {
        ...makeActionQuality("ALLOW"),
        source: "ai_connector",
      },
      expectedDecision: "WARN",
    },
  ];

  for (const { input, actionQuality, expectedDecision } of reviewCases) {
    const { evidence, service } = createHarness();
    const inputBefore = JSON.stringify(input);
    const actionQualityBefore = JSON.stringify(actionQuality);
    const result = await service.reviewAndCommit(input, actionQuality);

    assert.equal(result.decisionResult.decision, expectedDecision);
    assert.equal(evidence.lastDecisionTimestamp, input.timestamp);
    assert.equal(JSON.stringify(input), inputBefore);
    assert.equal(JSON.stringify(actionQuality), actionQualityBefore);
  }

  const calls: Array<{
    method: string;
    lifecycle: SafetyKernelV31NonceLifecycleRecord;
    timestamp: string | undefined;
    reason?: string;
  }> = [];
  const forwardingCoordinator = {
    async confirmWarn(
      lifecycle: SafetyKernelV31NonceLifecycleRecord,
      timestamp?: string
    ) {
      calls.push({ method: "confirmWarn", lifecycle, timestamp });
      return { committed: false, lifecycle, evidence: failure };
    },
    async completeAllowedExecution(
      lifecycle: SafetyKernelV31NonceLifecycleRecord,
      timestamp?: string
    ) {
      calls.push({ method: "completeAllowedExecution", lifecycle, timestamp });
      return { committed: false, lifecycle, evidence: failure };
    },
    async terminateWarn(
      lifecycle: SafetyKernelV31NonceLifecycleRecord,
      reason: string,
      timestamp?: string
    ) {
      calls.push({ method: "terminateWarn", lifecycle, reason, timestamp });
      return { committed: false, lifecycle, evidence: failure };
    },
  } as unknown as SafetyKernelV31NonceTransactionCoordinator;
  const forwardingService = new SafetyKernelV31TransactionService(
    forwardingCoordinator
  );
  const warnLifecycle: SafetyKernelV31NonceLifecycleRecord = {
    actionId: "action-boundary-warn-lifecycle",
    approvalNonce: "boundary-warn-nonce",
    phase: "WARN_PENDING",
    decision: "WARN",
    nonceConsumed: false,
    warnTimeoutSeconds: 60,
    warnMustNeverAutoProceed: true,
    parentEnvelopeInvalidated: false,
    childNoncesRequired: false,
    receiptRequired: true,
    ledgerRequired: true,
  };
  const allowLifecycle: SafetyKernelV31NonceLifecycleRecord = {
    actionId: "action-boundary-allow-lifecycle",
    approvalNonce: "boundary-allow-nonce",
    phase: "ALLOW_PENDING_EXECUTION",
    decision: "ALLOW",
    nonceConsumed: false,
    warnMustNeverAutoProceed: true,
    parentEnvelopeInvalidated: false,
    childNoncesRequired: false,
    receiptRequired: true,
    ledgerRequired: true,
  };
  const warnBefore = JSON.stringify(warnLifecycle);
  const allowBefore = JSON.stringify(allowLifecycle);

  const confirmResult = await forwardingService.confirmWarn(
    warnLifecycle,
    "2026-07-17T00:10:01.001Z"
  );
  const completionResult = await forwardingService.completeAllowedExecution(
    allowLifecycle,
    "2026-07-17T00:10:02.002Z"
  );
  const terminalResult = await forwardingService.terminateWarn(
    warnLifecycle,
    "timeout_expired",
    "2026-07-17T00:10:03.003Z"
  );

  assert.equal(confirmResult.lifecycle, warnLifecycle);
  assert.equal(completionResult.lifecycle, allowLifecycle);
  assert.equal(terminalResult.lifecycle, warnLifecycle);
  assert.deepEqual(calls, [
    {
      method: "confirmWarn",
      lifecycle: warnLifecycle,
      timestamp: "2026-07-17T00:10:01.001Z",
    },
    {
      method: "completeAllowedExecution",
      lifecycle: allowLifecycle,
      timestamp: "2026-07-17T00:10:02.002Z",
    },
    {
      method: "terminateWarn",
      lifecycle: warnLifecycle,
      reason: "timeout_expired",
      timestamp: "2026-07-17T00:10:03.003Z",
    },
  ]);
  assert.equal(JSON.stringify(warnLifecycle), warnBefore);
  assert.equal(JSON.stringify(allowLifecycle), allowBefore);

  const coordinatorError = new Error("simulated transaction service coordinator failure");
  const failingCoordinator = {
    issue(actionId: string): never {
      assert.equal(actionId, "action-boundary-error");
      throw coordinatorError;
    },
  } as unknown as SafetyKernelV31NonceTransactionCoordinator;
  const failingService = new SafetyKernelV31TransactionService(
    failingCoordinator
  );
  const failingInput = makeInput("action-boundary-error");
  const failingActionQuality = makeActionQuality("ALLOW");
  const failingInputBefore = JSON.stringify(failingInput);
  const failingActionQualityBefore = JSON.stringify(failingActionQuality);
  let caught: unknown;
  try {
    await failingService.reviewAndCommit(failingInput, failingActionQuality);
  } catch (error) {
    caught = error;
  }

  assert.equal(caught, coordinatorError);
  assert.equal(JSON.stringify(failingInput), failingInputBefore);
  assert.equal(JSON.stringify(failingActionQuality), failingActionQualityBefore);
});

test("transaction service rejects an unsupported adapter decision before SPLIT_REQUIRED fallback", async () => {
  const adapterModule = require("./safetyKernelV31Adapter") as {
    buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality:
      typeof import("./safetyKernelV31Adapter").buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality;
  };
  const originalBuilder =
    adapterModule.buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality;
  adapterModule.buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality = ((
    input,
    actionQuality
  ) => {
    const built = originalBuilder(input, actionQuality);
    return {
      ...built,
      decisionResult: {
        ...built.decisionResult,
        decision: "UNSUPPORTED_DECISION" as never,
      },
    };
  }) as typeof originalBuilder;

  try {
    const { service } = createHarness();
    await assert.rejects(
      () =>
        service.reviewAndCommit(
          makeInput("action-unsupported-decision"),
          makeActionQuality("ALLOW")
        ),
      /UNSUPPORTED_TRANSACTION_DECISION/
    );
  } finally {
    adapterModule.buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality =
      originalBuilder;
  }
});

test("transaction service forwards execution binding unchanged", async () => {
  const { evidence, service } = createHarness();
  const reviewed = await makeWarnPending(
    evidence,
    "action-service-execution-binding"
  );

  const confirmation = await service.confirmWarn(
    reviewed.lifecycle,
    "2026-07-19T11:01:00.000Z"
  );

  if (!confirmation.committed) {
    throw new Error("EXPECTED_WARN_CONFIRMATION_COMMIT");
  }

  const executionBinding:
    SafetyKernelV31AllowedExecutionCompletionBinding = {
      authority_revision: 31,
      command_sha256: "sha256:" + "1".repeat(64),
      snapshot_binding_sha256:
        "sha256:" + "2".repeat(64),
      exit_code: 0,
      stdout_sha256: "sha256:" + "3".repeat(64),
      stderr_sha256: "sha256:" + "4".repeat(64),
      stdout_bytes: 33,
      stderr_bytes: 34,
    };

  const timestamp = "2026-07-19T11:02:00.000Z";

  const completed =
    await service.completeAllowedExecution(
      confirmation.lifecycle,
      timestamp,
      executionBinding
    );

  assert.equal(completed.committed, true);
  assert.equal(
    evidence.lastAllowedTimestamp,
    timestamp
  );
  assert.deepEqual(
    evidence.lastAllowedEvidence?.execution_binding,
    executionBinding
  );
});