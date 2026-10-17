import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  AI_EXECUTION_AUTHORITY_MVP0_ACTION_KIND,
  AI_EXECUTION_AUTHORITY_MVP0_CAPABILITY_ID,
  AiExecutionAuthorityMvp0EvaluationInput,
  evaluateAiExecutionAuthorityMvp0,
} from "./aiExecutionAuthorityMvp0Policy";

function allowInput(): AiExecutionAuthorityMvp0EvaluationInput {
  return {
    capabilityId:
      AI_EXECUTION_AUTHORITY_MVP0_CAPABILITY_ID,
    actionKind:
      AI_EXECUTION_AUTHORITY_MVP0_ACTION_KIND,
    userExecutionConfirmed: true,
    automaticExecutionRequested: false,
    runtimeReviewStatus: "ALLOW",
    approvalNonceSha256:
      "sha256:" + "a".repeat(64),
    currentAuthorityBindingAvailable: true,
  };
}

test("detached execution authority denies the review-only capability", () => {
  const result =
    evaluateAiExecutionAuthorityMvp0({
      ...allowInput(),
      capabilityId: "ai_gateway_review_only",
    });

  assert.equal(
    result.execution_authority_granted,
    false
  );
  assert.equal(
    result.reason_code,
    "DENY_REVIEW_ONLY_CAPABILITY"
  );
});

test("detached execution authority denies a wrong action kind", () => {
  const result =
    evaluateAiExecutionAuthorityMvp0({
      ...allowInput(),
      actionKind: "ai_execution_gateway_review",
    });

  assert.equal(
    result.execution_authority_granted,
    false
  );
  assert.equal(
    result.reason_code,
    "DENY_ACTION_KIND_MISMATCH"
  );
});

test("detached execution authority denies without explicit user confirmation", () => {
  const result =
    evaluateAiExecutionAuthorityMvp0({
      ...allowInput(),
      userExecutionConfirmed: false,
    });

  assert.equal(
    result.execution_authority_granted,
    false
  );
  assert.equal(
    result.reason_code,
    "DENY_USER_EXECUTION_CONFIRMATION_REQUIRED"
  );
});

test("detached execution authority denies an automatic execution request", () => {
  const result =
    evaluateAiExecutionAuthorityMvp0({
      ...allowInput(),
      automaticExecutionRequested: true,
    });

  assert.equal(
    result.execution_authority_granted,
    false
  );
  assert.equal(
    result.reason_code,
    "DENY_AUTOMATIC_EXECUTION_REQUESTED"
  );
});

test("detached execution authority denies a non-ALLOW runtime review", () => {
  const result =
    evaluateAiExecutionAuthorityMvp0({
      ...allowInput(),
      runtimeReviewStatus: "BLOCK",
    });

  assert.equal(
    result.execution_authority_granted,
    false
  );
  assert.equal(
    result.reason_code,
    "DENY_RUNTIME_REVIEW_NOT_ALLOW"
  );
});

test("detached execution authority denies missing or invalid approval nonce SHA-256", () => {
  const missing =
    evaluateAiExecutionAuthorityMvp0({
      ...allowInput(),
      approvalNonceSha256: "",
    });

  const invalid =
    evaluateAiExecutionAuthorityMvp0({
      ...allowInput(),
      approvalNonceSha256:
        "sha256:" + "g".repeat(64),
    });

  assert.equal(
    missing.execution_authority_granted,
    false
  );
  assert.equal(
    missing.reason_code,
    "DENY_APPROVAL_NONCE_SHA256_INVALID"
  );
  assert.deepEqual(
    invalid,
    missing
  );
});

test("detached execution authority denies without a current authority binding", () => {
  const result =
    evaluateAiExecutionAuthorityMvp0({
      ...allowInput(),
      currentAuthorityBindingAvailable: false,
    });

  assert.equal(
    result.execution_authority_granted,
    false
  );
  assert.equal(
    result.reason_code,
    "DENY_CURRENT_AUTHORITY_BINDING_UNAVAILABLE"
  );
});

test("detached execution authority grants only when every exact prerequisite passes", () => {
  const result =
    evaluateAiExecutionAuthorityMvp0(
      allowInput()
    );

  assert.equal(
    result.execution_authority_granted,
    true
  );
  assert.equal(
    result.reason_code,
    "GRANT_EXPLICIT_EXECUTION_AUTHORITY"
  );
  assert.equal(
    Object.isFrozen(result),
    true
  );
});

test("detached execution authority returns a deterministic result for identical input", () => {
  const input =
    allowInput();

  const first =
    evaluateAiExecutionAuthorityMvp0(
      input
    );

  const second =
    evaluateAiExecutionAuthorityMvp0(
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
});

test("detached execution authority source has no Node VS Code filesystem or process execution dependency", () => {
  const source =
    readFileSync(
      join(
        process.cwd(),
        "src",
        "aiExecutionAuthorityMvp0Policy.ts"
      ),
      "utf8"
    );

  assert.doesNotMatch(
    source,
    /^\s*import\s/m
  );

  assert.doesNotMatch(
    source,
    /\brequire\s*\(/
  );

  assert.doesNotMatch(
    source,
    /\b(?:vscode|node:|child_process)\b/
  );

  assert.doesNotMatch(
    source,
    /\b(?:readFile|writeFile|appendFile|unlink|rm|mkdir|spawn|exec|executeCommand|sendText)\s*\(/
  );
});