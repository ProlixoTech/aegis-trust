import test from "node:test";
import assert from "node:assert/strict";

import {
  SAFETY_KERNEL_V31_ADAPTER_INVARIANT,
  buildSafetyKernelV31ActionEnvelopeFromActionQuality,
  buildSafetyKernelV31DecisionResultFromActionQuality,
  buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality,
} from "./safetyKernelV31Adapter";

import type { SafetyKernelV31EnvelopeAdapterInput } from "./safetyKernelV31Adapter";

import type {
  ActionQualityResult,
} from "./types";

function makeActionQuality(status: ActionQualityResult["status"]): ActionQualityResult {
  return {
    status,
    userMessage: "review message",
    reasons: ["reason-one", "reason-two"],
    detectedEffects: [],
    internalRuleId: "TEST_RULE",
    source: "manual_review",
  };
}

function makeInput(): SafetyKernelV31EnvelopeAdapterInput {
  return {
    action_id: "ACTION_TEST",
    target: "src/example.ts",
    intent: "verify adapter mapping",
    proposed_action: "read-only diagnostic",
    context_hash: "sha256:abc",
    timestamp: "2026-01-01T00:00:00.000Z",
    adapter_id: "safetyKernelV31Adapter.test",
    approval_nonce: "nonce-test",
    policy_version: "policy-test",
    human_readable_summary: "Adapter direct test",
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

test("safetyKernelV31Adapter invariant declares bridge-only side-effect-free status", () => {
  assert.equal(SAFETY_KERNEL_V31_ADAPTER_INVARIANT.SIDE_EFFECT_FREE, true);
  assert.equal(SAFETY_KERNEL_V31_ADAPTER_INVARIANT.RUNTIME_ENFORCED, false);
  assert.equal(SAFETY_KERNEL_V31_ADAPTER_INVARIANT.NONCE_LIFECYCLE_IMPLEMENTED, false);
  assert.equal(SAFETY_KERNEL_V31_ADAPTER_INVARIANT.WARN_TIMEOUT_IMPLEMENTED, false);
  assert.equal(SAFETY_KERNEL_V31_ADAPTER_INVARIANT.RECEIPT_LEDGER_WRITE_IMPLEMENTED, false);
  assert.equal(SAFETY_KERNEL_V31_ADAPTER_INVARIANT.EXTENSION_CALLER_CONNECTED, false);
  assert.equal(SAFETY_KERNEL_V31_ADAPTER_INVARIANT.SERVER_TARGETED_DECISION_ALLOWED, false);
});

test("safetyKernelV31Adapter builds envelope from explicit input and action-quality source", () => {
  const input = makeInput();
  const actionQuality = makeActionQuality("ALLOW");

  const envelope = buildSafetyKernelV31ActionEnvelopeFromActionQuality(input, actionQuality);

  assert.equal(envelope.action_id, input.action_id);
  assert.equal(envelope.source, "manual_review");
  assert.equal(envelope.target, input.target);
  assert.equal(envelope.intent, input.intent);
  assert.equal(envelope.proposed_action, input.proposed_action);
  assert.equal(envelope.risk_class, input.risk_class);
  assert.equal(envelope.context_hash, input.context_hash);
  assert.equal(envelope.timestamp, input.timestamp);
  assert.equal(envelope.adapter_id, input.adapter_id);
  assert.equal(envelope.human_readable_summary, input.human_readable_summary);
  assert.deepEqual(envelope.capability_requested, input.capability_requested);
  assert.deepEqual(envelope.mutation_scope, input.mutation_scope);
  assert.equal(envelope.approval_nonce, input.approval_nonce);
  assert.equal(envelope.policy_version, input.policy_version);
});

test("safetyKernelV31Adapter maps ALLOW decision result without consuming nonce or changing reasons", () => {
  const input = makeInput();
  const actionQuality = makeActionQuality("ALLOW");
  const envelope = buildSafetyKernelV31ActionEnvelopeFromActionQuality(input, actionQuality);

  const result = buildSafetyKernelV31DecisionResultFromActionQuality(envelope, actionQuality);

  assert.equal(result.action_id, input.action_id);
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.approval_nonce, input.approval_nonce);
  assert.equal(result.policy_version, input.policy_version);
  assert.deepEqual(result.reasons, actionQuality.reasons);
  assert.deepEqual(result.detectedEffects, []);
  assert.equal(result.human_readable_summary, input.human_readable_summary);
  assert.equal(result.receipt_required, true);
  assert.equal(result.ledger_required, true);
});

test("safetyKernelV31Adapter maps REVIEW_NEEDED to REQUIRE_REVIEW and returns both records", () => {
  const input = makeInput();
  const actionQuality = makeActionQuality("REVIEW_NEEDED");

  const combined = buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality(input, actionQuality);

  assert.equal(combined.envelope.action_id, input.action_id);
  assert.equal(combined.decisionResult.action_id, input.action_id);
  assert.equal(combined.decisionResult.decision, "REQUIRE_REVIEW");
  assert.equal(combined.decisionResult.approval_nonce, input.approval_nonce);
  assert.equal(combined.decisionResult.receipt_required, true);
  assert.equal(combined.decisionResult.ledger_required, true);
  assert.equal(combined.adapterInvariant, SAFETY_KERNEL_V31_ADAPTER_INVARIANT);
});
test("safetyKernelV31Adapter preserves BLOCK and SPLIT_REQUIRED mappings, detected effects, and combined equivalence", () => {
  const input = makeInput();
  const detectedEffects = ["filesystem_write", "terminal_handoff"] as unknown as ActionQualityResult["detectedEffects"];
  const blockActionQuality = makeActionQuality("BLOCK");
  blockActionQuality.detectedEffects = detectedEffects;

  const blockEnvelope = buildSafetyKernelV31ActionEnvelopeFromActionQuality(
    input,
    blockActionQuality
  );
  const blockResult = buildSafetyKernelV31DecisionResultFromActionQuality(
    blockEnvelope,
    blockActionQuality
  );

  assert.equal(blockResult.decision, "BLOCK");
  assert.deepEqual(blockResult.detectedEffects, detectedEffects);
  assert.deepEqual(blockResult.reasons, blockActionQuality.reasons);

  const splitActionQuality = makeActionQuality("SPLIT_REQUIRED");
  const splitEnvelope = buildSafetyKernelV31ActionEnvelopeFromActionQuality(
    input,
    splitActionQuality
  );
  const splitResult = buildSafetyKernelV31DecisionResultFromActionQuality(
    splitEnvelope,
    splitActionQuality
  );

  assert.equal(splitResult.decision, "SPLIT_REQUIRED");

  const combined = buildSafetyKernelV31EnvelopeAndDecisionFromActionQuality(
    input,
    blockActionQuality
  );
  assert.deepEqual(combined.envelope, blockEnvelope);
  assert.deepEqual(combined.decisionResult, blockResult);
  assert.equal(combined.adapterInvariant, SAFETY_KERNEL_V31_ADAPTER_INVARIANT);
});
