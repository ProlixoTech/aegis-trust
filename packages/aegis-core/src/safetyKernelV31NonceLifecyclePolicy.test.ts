import test from "node:test";
import assert from "node:assert/strict";

import {
  SAFETY_KERNEL_V31_NONCE_LIFECYCLE_INVARIANT,
  applySafetyKernelV31DecisionToNonce,
  completeSafetyKernelV31AllowedExecution,
  confirmSafetyKernelV31Warn,
  createSafetyKernelV31NonceLifecycle,
  terminateSafetyKernelV31Warn,
} from "./safetyKernelV31NonceLifecyclePolicy";

import type { SafetyKernelV31NonceLifecycleRecord } from "./safetyKernelV31NonceLifecyclePolicy";

const lifecycleTypeBase = { actionId: "action-type-sentinel", approvalNonce: "nonce-type-sentinel", warnMustNeverAutoProceed: true, receiptRequired: true, ledgerRequired: true } as const;
// @ts-expect-error ISSUED lifecycle cannot carry an ALLOW decision
const invalidIssuedDecision: SafetyKernelV31NonceLifecycleRecord = { ...lifecycleTypeBase, phase: "ISSUED", decision: "ALLOW", nonceConsumed: false, parentEnvelopeInvalidated: false, childNoncesRequired: false };
// @ts-expect-error WARN_PENDING lifecycle requires a bounded timeout field
const invalidWarnWithoutTimeout: SafetyKernelV31NonceLifecycleRecord = { ...lifecycleTypeBase, phase: "WARN_PENDING", decision: "WARN", nonceConsumed: false, parentEnvelopeInvalidated: false, childNoncesRequired: false };
// @ts-expect-error SPLIT_REQUIRED lifecycle requires both split flags
const invalidSplitFlags: SafetyKernelV31NonceLifecycleRecord = { ...lifecycleTypeBase, phase: "SPLIT_REQUIRED", decision: "SPLIT_REQUIRED", nonceConsumed: true, parentEnvelopeInvalidated: false, childNoncesRequired: false };
// @ts-expect-error CONSUMED lifecycle cannot retain an active nonce
const invalidConsumedNonce: SafetyKernelV31NonceLifecycleRecord = { ...lifecycleTypeBase, phase: "CONSUMED", decision: "ALLOW", nonceConsumed: false, parentEnvelopeInvalidated: false, childNoncesRequired: false };
void invalidIssuedDecision;
void invalidWarnWithoutTimeout;
void invalidSplitFlags;
void invalidConsumedNonce;

const issuedReturnType = createSafetyKernelV31NonceLifecycle("ACTION_RETURN_TYPE_ISSUED", "nonce-return-issued");
const issuedExpectedType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ISSUED" }> = issuedReturnType;
// @ts-expect-error created lifecycle cannot be ALLOW pending
const invalidCreatedAllowType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }> = issuedReturnType;
const allowReturnType = applySafetyKernelV31DecisionToNonce(issuedReturnType, "ALLOW");
const allowExpectedType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }> = allowReturnType;
// @ts-expect-error ALLOW decision cannot return WARN_PENDING
const invalidAllowWarnReturnType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "WARN_PENDING" }> = allowReturnType;
const warnReturnType = applySafetyKernelV31DecisionToNonce(createSafetyKernelV31NonceLifecycle("ACTION_RETURN_TYPE_WARN", "nonce-return-warn"), "WARN");
const warnExpectedType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "WARN_PENDING" }> = warnReturnType;
const confirmedReturnType = confirmSafetyKernelV31Warn(warnReturnType);
const confirmedExpectedType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }> = confirmedReturnType;
const consumedAllowReturnType = completeSafetyKernelV31AllowedExecution(allowReturnType);
const consumedAllowExpectedType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "ALLOW" } = consumedAllowReturnType;
// @ts-expect-error completed ALLOW lifecycle cannot carry WARN decision
const invalidConsumedAllowWarnType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "WARN" } = consumedAllowReturnType;
const consumedWarnReturnType = terminateSafetyKernelV31Warn(warnReturnType, "cancel_by_user").lifecycle;
const consumedWarnExpectedType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "WARN" } = consumedWarnReturnType;
// @ts-expect-error terminated WARN lifecycle cannot carry ALLOW decision
const invalidConsumedWarnAllowType: Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }> & { decision: "ALLOW" } = consumedWarnReturnType;
void issuedExpectedType;
void invalidCreatedAllowType;
void allowExpectedType;
void invalidAllowWarnReturnType;
void warnExpectedType;
void confirmedExpectedType;
void consumedAllowExpectedType;
void invalidConsumedAllowWarnType;
void consumedWarnExpectedType;
void invalidConsumedWarnAllowType;

test("nonce lifecycle invariant remains side-effect free and not runtime enforced", () => {
  assert.equal(SAFETY_KERNEL_V31_NONCE_LIFECYCLE_INVARIANT.SIDE_EFFECT_FREE, true);
  assert.equal(SAFETY_KERNEL_V31_NONCE_LIFECYCLE_INVARIANT.RUNTIME_ENFORCED, false);
  assert.equal(SAFETY_KERNEL_V31_NONCE_LIFECYCLE_INVARIANT.NONCE_REUSE_ALLOWED, false);
  assert.equal(SAFETY_KERNEL_V31_NONCE_LIFECYCLE_INVARIANT.WARN_AUTO_PROCEED_ALLOWED, false);
});

test("ALLOW keeps nonce active until verified execution completion", () => {
  const issued = createSafetyKernelV31NonceLifecycle("ACTION_ALLOW", "nonce-allow");
  const allowed = applySafetyKernelV31DecisionToNonce(issued, "ALLOW");

  assert.equal(allowed.phase, "ALLOW_PENDING_EXECUTION");
  assert.equal(allowed.nonceConsumed, false);
  assert.equal(allowed.approvalNonce, "nonce-allow");

  const completed = completeSafetyKernelV31AllowedExecution(allowed);
  assert.equal(completed.phase, "CONSUMED");
  assert.equal(completed.nonceConsumed, true);
});

test("WARN preserves the same nonce and never auto-proceeds", () => {
  const issued = createSafetyKernelV31NonceLifecycle("ACTION_WARN", "nonce-warn");
  const pending = applySafetyKernelV31DecisionToNonce(issued, "WARN");

  assert.equal(pending.phase, "WARN_PENDING");
  assert.equal(pending.approvalNonce, "nonce-warn");
  assert.equal(pending.warnTimeoutSeconds, 60);
  assert.equal(pending.nonceConsumed, false);
  assert.equal(pending.warnMustNeverAutoProceed, true);

  const confirmed = confirmSafetyKernelV31Warn(pending);
  assert.equal(confirmed.phase, "ALLOW_PENDING_EXECUTION");
  assert.equal(confirmed.approvalNonce, "nonce-warn");
  assert.equal(confirmed.nonceConsumed, false);
});

test("WARN cancel and timeout consume nonce and require receipt and ledger evidence", () => {
  for (const reason of ["cancel_by_user", "timeout_expired"] as const) {
    const issued = createSafetyKernelV31NonceLifecycle("ACTION_WARN_END", "nonce-" + reason);
    const pending = applySafetyKernelV31DecisionToNonce(issued, "WARN", 30);
    const ended = terminateSafetyKernelV31Warn(pending, reason);

    assert.equal(ended.lifecycle.phase, "CONSUMED");
    assert.equal(ended.lifecycle.nonceConsumed, true);
    assert.equal(ended.evidence.reason, reason);
    assert.equal(ended.evidence.return_state, "IDLE");
    assert.equal(ended.evidence.receipt_required, true);
    assert.equal(ended.evidence.ledger_required, true);
    assert.equal(ended.evidence.warn_must_never_auto_proceed, true);
  }
});

test("BLOCK and REQUIRE_REVIEW consume the old nonce", () => {
  for (const decision of ["BLOCK", "REQUIRE_REVIEW"] as const) {
    const issued = createSafetyKernelV31NonceLifecycle("ACTION_" + decision, "nonce-" + decision);
    const result = applySafetyKernelV31DecisionToNonce(issued, decision);

    assert.equal(result.phase, decision === "BLOCK" ? "BLOCKED" : "REQUIRE_REVIEW");
    assert.equal(result.nonceConsumed, true);
  }
});

test("SPLIT_REQUIRED invalidates the parent and requires child nonces", () => {
  const issued = createSafetyKernelV31NonceLifecycle("ACTION_SPLIT", "nonce-split");
  const split = applySafetyKernelV31DecisionToNonce(issued, "SPLIT_REQUIRED");

  assert.equal(split.phase, "SPLIT_REQUIRED");
  assert.equal(split.nonceConsumed, true);
  assert.equal(split.parentEnvelopeInvalidated, true);
  assert.equal(split.childNoncesRequired, true);
});

test("consumed or non-issued nonces cannot be reused", () => {
  const issued = createSafetyKernelV31NonceLifecycle("ACTION_REUSE", "nonce-reuse");
  const blocked = applySafetyKernelV31DecisionToNonce(issued, "BLOCK");

  assert.throws(
    () => applySafetyKernelV31DecisionToNonce(blocked, "ALLOW"),
    /NONCE_NOT_ACTIVE/
  );
});

test("WARN timeout must remain within the contract bounds", () => {
  const issued = createSafetyKernelV31NonceLifecycle("ACTION_TIMEOUT", "nonce-timeout");

  assert.throws(
    () => applySafetyKernelV31DecisionToNonce(issued, "WARN", 14),
    /INVALID_WARN_TIMEOUT/
  );
  assert.throws(
    () => applySafetyKernelV31DecisionToNonce(issued, "WARN", 301),
    /INVALID_WARN_TIMEOUT/
  );
});


test("invalid pending lifecycle transitions are rejected directly", () => {
  const issued = createSafetyKernelV31NonceLifecycle("ACTION_INVALID_PENDING", "nonce-invalid-pending");
  assert.throws(() => confirmSafetyKernelV31Warn(issued), /WARN_NOT_PENDING/);
  assert.throws(() => terminateSafetyKernelV31Warn(issued, "cancel_by_user"), /WARN_NOT_PENDING/);
  assert.throws(() => completeSafetyKernelV31AllowedExecution(issued), /ALLOW_EXECUTION_NOT_PENDING/);
});


test("nonce lifecycle rejects an empty action id", () => {
  assert.throws(
    () => createSafetyKernelV31NonceLifecycle("   ", "nonce-valid-action-id-test"),
    /INVALID_ACTION_ID/
  );
});

test("nonce lifecycle rejects an empty approval nonce", () => {
  assert.throws(
    () => createSafetyKernelV31NonceLifecycle("ACTION_VALID_NONCE_TEST", "   "),
    /INVALID_APPROVAL_NONCE/
  );
});

test("nonce lifecycle normalizes bindings and enforces WARN timeout boundary and cleanup contracts", () => {
  const normalized = createSafetyKernelV31NonceLifecycle(
    "  ACTION_BOUNDARY  ",
    "  nonce-boundary  "
  );
  assert.equal(normalized.actionId, "ACTION_BOUNDARY");
  assert.equal(normalized.approvalNonce, "nonce-boundary");

  for (const timeout of [15, 300]) {
    const pending = applySafetyKernelV31DecisionToNonce(
      createSafetyKernelV31NonceLifecycle(
        "  ACTION_WARN_BOUNDARY  ",
        "  nonce-warn-boundary  "
      ),
      "WARN",
      timeout
    );
    assert.equal(pending.warnTimeoutSeconds, timeout);

    const confirmed = confirmSafetyKernelV31Warn(pending);
    assert.equal("warnTimeoutSeconds" in confirmed, false);

    const ended = terminateSafetyKernelV31Warn(pending, "timeout_expired");
    assert.equal("warnTimeoutSeconds" in ended.lifecycle, false);
    assert.equal(ended.evidence.action_id, "ACTION_WARN_BOUNDARY");
    assert.equal(ended.evidence.approval_nonce, "nonce-warn-boundary");
  }

  assert.throws(
    () =>
      applySafetyKernelV31DecisionToNonce(
        createSafetyKernelV31NonceLifecycle("ACTION_WARN_FRACTION", "nonce-warn-fraction"),
        "WARN",
        15.5
      ),
    /INVALID_WARN_TIMEOUT/
  );

  const completed = completeSafetyKernelV31AllowedExecution(
    applySafetyKernelV31DecisionToNonce(
      createSafetyKernelV31NonceLifecycle("ACTION_ALLOW_COMPLETE", "nonce-allow-complete"),
      "ALLOW"
    )
  );
  assert.equal(completed.phase, "CONSUMED");
  assert.equal(completed.decision, "ALLOW");
  assert.equal(completed.nonceConsumed, true);
});

test("nonce lifecycle rejects pending phase and decision mismatches directly", () => {
  const warnPending = applySafetyKernelV31DecisionToNonce(
    createSafetyKernelV31NonceLifecycle(
      "ACTION_WARN_DECISION_MISMATCH",
      "nonce-warn-decision-mismatch"
    ),
    "WARN"
  );
  const warnDecisionMismatch = {
    ...warnPending,
    decision: "ALLOW",
  } as unknown as Parameters<typeof confirmSafetyKernelV31Warn>[0];

  assert.throws(
    () => confirmSafetyKernelV31Warn(warnDecisionMismatch),
    /WARN_NOT_PENDING/
  );
  assert.throws(
    () => terminateSafetyKernelV31Warn(warnDecisionMismatch, "cancel_by_user"),
    /WARN_NOT_PENDING/
  );

  const allowPending = applySafetyKernelV31DecisionToNonce(
    createSafetyKernelV31NonceLifecycle(
      "ACTION_ALLOW_DECISION_MISMATCH",
      "nonce-allow-decision-mismatch"
    ),
    "ALLOW"
  );
  const allowDecisionMismatch = {
    ...allowPending,
    decision: "WARN",
  } as unknown as Parameters<
    typeof completeSafetyKernelV31AllowedExecution
  >[0];

  assert.throws(
    () => completeSafetyKernelV31AllowedExecution(allowDecisionMismatch),
    /ALLOW_EXECUTION_NOT_PENDING/
  );
});
