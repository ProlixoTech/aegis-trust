import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  AI_EXECUTION_GATEWAY_EXPLICIT_EXECUTION_MVP0_ACTION_KIND,
  AI_EXECUTION_GATEWAY_EXPLICIT_EXECUTION_MVP0_CAPABILITY_ID,
  evaluateAiExecutionGatewayExplicitExecutionMvp0Capability,
} from "./aiExecutionGatewayExplicitExecutionMvp0Capability";

function allowInput() {
  return {
    capabilityId:
      AI_EXECUTION_GATEWAY_EXPLICIT_EXECUTION_MVP0_CAPABILITY_ID,
    actionKind:
      AI_EXECUTION_GATEWAY_EXPLICIT_EXECUTION_MVP0_ACTION_KIND,
    userExecutionConfirmed: true,
    automaticExecutionRequested: false,
    runtimeReviewStatus: "ALLOW",
    approvalNonceSha256:
      "sha256:" + "a".repeat(64),
    currentAuthorityBindingAvailable: true,
  };
}

test("explicit execution capability denies the review-only capability", () => {
  const result =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability({
      ...allowInput(),
      capabilityId: "ai_gateway_review_only",
    });

  assert.equal(
    result.product_entrypoint_capability_ready,
    false
  );
  assert.equal(
    result.execution_authority_granted,
    false
  );
  assert.equal(
    result.authority_reason_code,
    "DENY_REVIEW_ONLY_CAPABILITY"
  );
  assert.equal(
    result.capability_reason_code,
    "NOT_READY_FOR_PRODUCT_ENTRY_CONNECTION"
  );
});

test("explicit execution capability denies a wrong action kind", () => {
  const result =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability({
      ...allowInput(),
      actionKind: "ai_execution_gateway_review",
    });

  assert.equal(
    result.product_entrypoint_capability_ready,
    false
  );
  assert.equal(
    result.authority_reason_code,
    "DENY_ACTION_KIND_MISMATCH"
  );
});

test("explicit execution capability denies without explicit user confirmation", () => {
  const result =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability({
      ...allowInput(),
      userExecutionConfirmed: false,
    });

  assert.equal(
    result.product_entrypoint_capability_ready,
    false
  );
  assert.equal(
    result.authority_reason_code,
    "DENY_USER_EXECUTION_CONFIRMATION_REQUIRED"
  );
});

test("explicit execution capability denies an automatic execution request", () => {
  const result =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability({
      ...allowInput(),
      automaticExecutionRequested: true,
    });

  assert.equal(
    result.product_entrypoint_capability_ready,
    false
  );
  assert.equal(
    result.authority_reason_code,
    "DENY_AUTOMATIC_EXECUTION_REQUESTED"
  );
});

test("explicit execution capability denies a non-ALLOW runtime review", () => {
  const result =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability({
      ...allowInput(),
      runtimeReviewStatus: "BLOCK",
    });

  assert.equal(
    result.product_entrypoint_capability_ready,
    false
  );
  assert.equal(
    result.authority_reason_code,
    "DENY_RUNTIME_REVIEW_NOT_ALLOW"
  );
});

test("explicit execution capability denies an invalid nonce or missing authority binding", () => {
  const invalidNonce =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability({
      ...allowInput(),
      approvalNonceSha256:
        "sha256:" + "g".repeat(64),
    });

  const missingBinding =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability({
      ...allowInput(),
      currentAuthorityBindingAvailable: false,
    });

  assert.equal(
    invalidNonce.product_entrypoint_capability_ready,
    false
  );
  assert.equal(
    invalidNonce.authority_reason_code,
    "DENY_APPROVAL_NONCE_SHA256_INVALID"
  );
  assert.equal(
    missingBinding.product_entrypoint_capability_ready,
    false
  );
  assert.equal(
    missingBinding.authority_reason_code,
    "DENY_CURRENT_AUTHORITY_BINDING_UNAVAILABLE"
  );
});

test("explicit execution capability is ready only when the authority policy grants", () => {
  const result =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability(
      allowInput()
    );

  assert.equal(
    result.product_entrypoint_capability_ready,
    true
  );
  assert.equal(
    result.execution_authority_granted,
    true
  );
  assert.equal(
    result.authority_reason_code,
    "GRANT_EXPLICIT_EXECUTION_AUTHORITY"
  );
  assert.equal(
    result.capability_reason_code,
    "READY_FOR_PRODUCT_ENTRY_CONNECTION"
  );
});

test("explicit execution capability is deterministic frozen and has no forbidden runtime dependency", () => {
  const input =
    allowInput();

  const first =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability(
      input
    );

  const second =
    evaluateAiExecutionGatewayExplicitExecutionMvp0Capability(
      input
    );

  assert.deepEqual(
    second,
    first
  );
  assert.notEqual(
    second,
    first
  );
  assert.equal(
    Object.isFrozen(first),
    true
  );
  assert.equal(
    Object.isFrozen(second),
    true
  );

  const source =
    readFileSync(
      join(
        process.cwd(),
        "src",
        "aiExecutionGatewayExplicitExecutionMvp0Capability.ts"
      ),
      "utf8"
    );

  assert.match(
    source,
    /from\s+"\.\/aiExecutionAuthorityMvp0Policy"/
  );

  assert.doesNotMatch(
    source,
    /\b(?:node:|vscode|child_process)\b/
  );

  assert.doesNotMatch(
    source,
    /\b(?:readFile|writeFile|appendFile|unlink|rm|mkdir|spawn|exec|executeCommand|sendText)\s*\(/
  );

  assert.doesNotMatch(
    source,
    /from\s+"\.\/(?:nodeProcessExecutionAdapter|safetyKernelV31RuntimeController|safetyKernelV31AllowedExecutionCoordinator|safetyKernelV31NonceLifecyclePolicy|receiptWriter|ledgerWriter)"/
  );
});