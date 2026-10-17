import * as assert from "node:assert/strict";
import { test } from "node:test";
import { assessReleaseGate, ReleaseGateInput } from "./releaseGate";

function passingInput(): ReleaseGateInput {
  return {
    identityInvariantPassed: true,
    requiredCheckerIds: ["identity", "policy", "tests"],
    checkerResults: [
      { checkerId: "identity", passed: true },
      { checkerId: "policy", passed: true },
      { checkerId: "tests", passed: true },
    ],
    releaseStateClaim: "ready",
  };
}

test("passes when the identity invariant and all required checkers pass", () => {
  assert.deepEqual(assessReleaseGate(passingInput()), { passed: true, reason: null });
});

test("rejects a failed identity invariant", () => {
  const input = { ...passingInput(), identityInvariantPassed: false };
  assert.equal(assessReleaseGate(input).passed, false);
});

test("rejects an empty required checker list", () => {
  const input = { ...passingInput(), requiredCheckerIds: [] };
  assert.equal(assessReleaseGate(input).passed, false);
});

test("rejects duplicate required checker ids", () => {
  const input = { ...passingInput(), requiredCheckerIds: ["identity", "identity"] };
  assert.equal(assessReleaseGate(input).passed, false);
});

test("rejects a missing required checker result", () => {
  const input = {
    ...passingInput(),
    checkerResults: [{ checkerId: "identity", passed: true }],
  };
  assert.equal(assessReleaseGate(input).passed, false);
});

test("rejects a required checker without a result value", () => {
  const input = {
    ...passingInput(),
    checkerResults: [
      { checkerId: "identity", passed: true },
      { checkerId: "policy" },
      { checkerId: "tests", passed: true },
    ],
  };
  assert.equal(assessReleaseGate(input).passed, false);
});

test("rejects a failed required checker", () => {
  const input = {
    ...passingInput(),
    checkerResults: [
      { checkerId: "identity", passed: true },
      { checkerId: "policy", passed: false },
      { checkerId: "tests", passed: true },
    ],
  };
  assert.equal(assessReleaseGate(input).passed, false);
});

test("rejects a release-state claim that disagrees with the gate result", () => {
  const input: ReleaseGateInput = {
    ...passingInput(),
    releaseStateClaim: "not-ready",
  };
  assert.equal(assessReleaseGate(input).passed, false);
});