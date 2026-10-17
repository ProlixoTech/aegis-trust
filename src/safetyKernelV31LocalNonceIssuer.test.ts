import test from "node:test";
import assert from "node:assert/strict";

import {
  SAFETY_KERNEL_V31_LOCAL_NONCE_DEFAULT_BYTES,
  SAFETY_KERNEL_V31_LOCAL_NONCE_ISSUER_INVARIANT,
  SAFETY_KERNEL_V31_LOCAL_NONCE_MAX_BYTES,
  SAFETY_KERNEL_V31_LOCAL_NONCE_MIN_BYTES,
  issueSafetyKernelV31LocalNonce,
} from "./safetyKernelV31LocalNonceIssuer";

test("local nonce issuer invariant remains local, non-persistent, disconnected, and non-executing", () => {
  assert.equal(SAFETY_KERNEL_V31_LOCAL_NONCE_ISSUER_INVARIANT.LOCAL_ONLY, true);
  assert.equal(SAFETY_KERNEL_V31_LOCAL_NONCE_ISSUER_INVARIANT.CRYPTOGRAPHIC_RANDOM_SOURCE, true);
  assert.equal(SAFETY_KERNEL_V31_LOCAL_NONCE_ISSUER_INVARIANT.GATEWAY_SUPPLIED_NONCE_ALLOWED, false);
  assert.equal(SAFETY_KERNEL_V31_LOCAL_NONCE_ISSUER_INVARIANT.RAW_NONCE_PERSISTED, false);
  assert.equal(SAFETY_KERNEL_V31_LOCAL_NONCE_ISSUER_INVARIANT.RAW_NONCE_LOGGED, false);
  assert.equal(SAFETY_KERNEL_V31_LOCAL_NONCE_ISSUER_INVARIANT.RUNTIME_CONNECTED, false);
  assert.equal(SAFETY_KERNEL_V31_LOCAL_NONCE_ISSUER_INVARIANT.EXECUTION_AUTHORITY_GRANTED, false);
});

test("local nonce issuer creates a default 32-byte hexadecimal nonce and ISSUED lifecycle", () => {
  const result = issueSafetyKernelV31LocalNonce("ACTION_LOCAL_NONCE");

  assert.equal(result.randomByteLength, SAFETY_KERNEL_V31_LOCAL_NONCE_DEFAULT_BYTES);
  assert.equal(result.randomSource, "crypto.randomBytes");
  assert.match(result.approvalNonce, /^[0-9a-f]{64}$/);
  assert.equal(result.lifecycle.actionId, "ACTION_LOCAL_NONCE");
  assert.equal(result.lifecycle.approvalNonce, result.approvalNonce);
  assert.equal(result.lifecycle.phase, "ISSUED");
  assert.equal(result.lifecycle.decision, null);
  assert.equal(result.lifecycle.nonceConsumed, false);
  assert.equal(result.lifecycle.receiptRequired, true);
  assert.equal(result.lifecycle.ledgerRequired, true);
});

test("local nonce issuer returns unique nonce values for the same action", () => {
  const first = issueSafetyKernelV31LocalNonce("ACTION_UNIQUE");
  const second = issueSafetyKernelV31LocalNonce("ACTION_UNIQUE");

  assert.notEqual(first.approvalNonce, second.approvalNonce);
});

test("local nonce issuer accepts only bounded integer byte lengths", () => {
  const minimum = issueSafetyKernelV31LocalNonce("ACTION_MIN", SAFETY_KERNEL_V31_LOCAL_NONCE_MIN_BYTES);
  const maximum = issueSafetyKernelV31LocalNonce("ACTION_MAX", SAFETY_KERNEL_V31_LOCAL_NONCE_MAX_BYTES);

  assert.equal(minimum.approvalNonce.length, SAFETY_KERNEL_V31_LOCAL_NONCE_MIN_BYTES * 2);
  assert.equal(maximum.approvalNonce.length, SAFETY_KERNEL_V31_LOCAL_NONCE_MAX_BYTES * 2);

  for (const invalid of [
    SAFETY_KERNEL_V31_LOCAL_NONCE_MIN_BYTES - 1,
    SAFETY_KERNEL_V31_LOCAL_NONCE_MAX_BYTES + 1,
    16.5,
  ]) {
    assert.throws(
      () => issueSafetyKernelV31LocalNonce("ACTION_INVALID_LENGTH", invalid),
      /INVALID_NONCE_BYTE_LENGTH/
    );
  }
});

test("local nonce issuer rejects an empty action id", () => {
  assert.throws(
    () => issueSafetyKernelV31LocalNonce("   "),
    /INVALID_ACTION_ID/
  );
});
