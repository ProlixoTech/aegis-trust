import * as assert from "node:assert/strict";
import { test } from "node:test";
import {
  assessSignedRulesetSemanticCandidate,
  SignedRulesetMetadata,
} from "./signedRulesetSemanticValidation";

const now = Date.parse("2026-07-23T12:00:00.000Z");

const active: SignedRulesetMetadata = {
  rulesetVersion: 5,
  monotonicCounter: 10,
  notBefore: "2026-07-20T00:00:00.000Z",
  notAfter: "2026-07-30T00:00:00.000Z",
};

function validCandidate(): SignedRulesetMetadata {
  return {
    rulesetVersion: 6,
    monotonicCounter: 11,
    notBefore: "2026-07-22T00:00:00.000Z",
    notAfter: "2026-07-29T00:00:00.000Z",
  };
}

test("accepts a semantically valid signed ruleset", () => {
  assert.deepEqual(
    assessSignedRulesetSemanticCandidate(active, validCandidate(), now),
    { accepted: true, reason: null }
  );
});

test("rejects an invalid rulesetVersion", () => {
  const candidate = { ...validCandidate(), rulesetVersion: Number.NaN };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects rulesetVersion rollback", () => {
  const candidate = { ...validCandidate(), rulesetVersion: 4 };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects a missing monotonicCounter", () => {
  const candidate: SignedRulesetMetadata = {
    rulesetVersion: 6,
    notBefore: "2026-07-22T00:00:00.000Z",
    notAfter: "2026-07-29T00:00:00.000Z",
  };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects monotonicCounter rollback", () => {
  const candidate = { ...validCandidate(), monotonicCounter: 9 };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects a missing notBefore", () => {
  const candidate: SignedRulesetMetadata = {
    rulesetVersion: 6,
    monotonicCounter: 11,
    notAfter: "2026-07-29T00:00:00.000Z",
  };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects a future notBefore", () => {
  const candidate = { ...validCandidate(), notBefore: "2026-07-24T00:00:00.000Z" };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects a missing notAfter", () => {
  const candidate: SignedRulesetMetadata = {
    rulesetVersion: 6,
    monotonicCounter: 11,
    notBefore: "2026-07-22T00:00:00.000Z",
  };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects an expired notAfter", () => {
  const candidate = { ...validCandidate(), notAfter: "2026-07-23T11:59:59.000Z" };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects an invalid notBefore", () => {
  const candidate = { ...validCandidate(), notBefore: "invalid" };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects an invalid notAfter", () => {
  const candidate = { ...validCandidate(), notAfter: "invalid" };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});

test("rejects a non-increasing validity window", () => {
  const candidate = {
    ...validCandidate(),
    notBefore: "2026-07-25T00:00:00.000Z",
    notAfter: "2026-07-24T00:00:00.000Z",
  };
  assert.equal(assessSignedRulesetSemanticCandidate(active, candidate, now).accepted, false);
});