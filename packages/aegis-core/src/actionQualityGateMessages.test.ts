import test from "node:test";
import assert from "node:assert/strict";

import {
  RULE_MESSAGES,
  formatActionGateSection,
  formatClipboardSummary,
} from "./actionQualityGateMessages";

import type { ActionQualityResult } from "./types";

function makeResult(overrides: Partial<ActionQualityResult> = {}): ActionQualityResult {
  return {
    status: "BLOCK",
    userMessage: "Blocked for test",
    reasons: ["reason one", "reason two"],
    detectedEffects: [],
    nextSafeStep: "Run a read-only check first.",
    internalRuleId: "DESTRUCTIVE_FILE_OP",
    source: "manual_review",
    ...overrides,
  };
}

test("actionQualityGateMessages exposes stable per-rule message entries", () => {
  assert.equal(RULE_MESSAGES.SAFE_RUNNER_PATTERN.userMessage.includes("safe Aegis runner"), true);
  assert.equal(RULE_MESSAGES.SHORT_READ_ONLY.userMessage.includes("short, single-purpose read-only"), true);
  assert.equal(RULE_MESSAGES.DEFAULT_REVIEW_NEEDED.nextSafeStep?.includes("read-only"), true);
  assert.equal(RULE_MESSAGES.AI_ARTIFACT_CHANNEL_AUTHORITY.nextSafeStep?.includes("authorized provenance"), true);
});

test("actionQualityGateMessages formats markdown section with status, rule, reasons, and next step", () => {
  const section = formatActionGateSection(makeResult());

  assert.match(section, /^## Action Quality Gate/);
  assert.match(section, /\*\*Status:\*\* .*BLOCK/);
  assert.match(section, /\*\*Rule:\*\* `DESTRUCTIVE_FILE_OP`/);
  assert.match(section, /\*\*Source:\*\* `manual_review`/);
  assert.match(section, /This command was blocked by the pre-execution gate/);
  assert.match(section, /\*\*Reasons:\*\*/);
  assert.match(section, /- reason one/);
  assert.match(section, /\*\*Message:\*\* Blocked for test/);
  assert.match(section, /\*\*Next Safe Step:\*\* Run a read-only check first\./);
  assert.match(section, /Action Quality Gate\*\* is an AI-connected pre-execution gateway/);
});

test("actionQualityGateMessages omits optional reasons and next step when absent", () => {
  const section = formatActionGateSection(makeResult({
    status: "ALLOW",
    userMessage: "Allowed for test",
    reasons: [],
    nextSafeStep: undefined,
    internalRuleId: "SHORT_READ_ONLY",
    source: "vscode_command",
  }));

  assert.match(section, /\*\*Status:\*\* .*ALLOW/);
  assert.match(section, /\*\*Rule:\*\* `SHORT_READ_ONLY`/);
  assert.match(section, /\*\*Source:\*\* `vscode_command`/);
  assert.match(section, /cleared for the next review stage/);
  assert.doesNotMatch(section, /\*\*Reasons:\*\*/);
  assert.doesNotMatch(section, /\*\*Next Safe Step:\*\*/);
  assert.match(section, /AI Connector/);
});

test("actionQualityGateMessages formats clipboard summary with required gateway fields", () => {
  const summary = formatClipboardSummary(makeResult());

  assert.match(summary, /^ACTION_QUALITY_GATE_STATUS=BLOCK/m);
  assert.match(summary, /^RULE=DESTRUCTIVE_FILE_OP/m);
  assert.match(summary, /^SOURCE=manual_review/m);
  assert.match(summary, /^MESSAGE=Blocked for test/m);
  assert.match(summary, /^NEXT_SAFE_STEP=Run a read-only check first\./m);
  assert.match(summary, /^AI_CONNECTED_GATEWAY=True/m);
});

test("actionQualityGateMessages includes detected effect summary when effects are present", () => {
  const summary = formatClipboardSummary(makeResult({
    detectedEffects: [
      {
        level: "SYNTACTIC_LEVEL_1",
        kind: "DESTRUCTIVE_FILE_OPERATION",
        confidence: "HIGH",
        description: "delete-like operation",
        sourceRuleId: "TEST_RULE",
      } as ActionQualityResult["detectedEffects"][number],
    ],
  }));

  assert.match(summary, /^DETECTED_EFFECTS_LEVEL=SYNTACTIC_LEVEL_1/m);
  assert.match(summary, /^DETECTED_EFFECTS=DESTRUCTIVE_FILE_OPERATION:HIGH/m);
});
test("actionQualityGateMessages markdown includes detected effects", () => {
  const section = formatActionGateSection(makeResult({
    detectedEffects: [
      {
        level: "SYNTACTIC_LEVEL_1",
        kind: "DESTRUCTIVE_FILE_OPERATION",
        confidence: "HIGH",
        description: "delete-like operation",
        sourceRuleId: "TEST_RULE",
      } as ActionQualityResult["detectedEffects"][number],
    ],
  }));

  assert.match(section, /\*\*Detected Effects:\*\*/);
  assert.match(section, /`SYNTACTIC_LEVEL_1` \/ `DESTRUCTIVE_FILE_OPERATION` \/ HIGH: delete-like operation/);
});
