import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  buildReviewAiCommandMvp0ClipboardText,
  buildReviewAiCommandMvp0Markdown,
  classifyReviewAiCommandMvp0Action,
  combineReviewAiCommandMvp0WithActionQuality,
  sanitizeReviewAiCommandMvp0Text,
} from "./reviewAiCommandMvp0Policy";

test("Review AI Command MVP-0 command registration is exposed through package and extension exactly once", () => {
  const packageJson = readFileSync(resolve(process.cwd(), "package.json"), "utf8");
  const extensionSource = readFileSync(resolve(process.cwd(), "src", "extension.ts"), "utf8");

  const countInPackage = (needle: string) => packageJson.split(needle).length - 1;
  const countInExtension = (needle: string) => extensionSource.split(needle).length - 1;

  assert.equal(countInPackage('"onCommand:aegis.reviewAiCommandOrAction"'), 1);
  assert.equal(countInPackage('"command":  "aegis.reviewAiCommandOrAction"'), 1);
  assert.equal(countInPackage('"title":  "Aegis: Review AI Command / Action"'), 1);
  assert.equal(countInExtension('registerCommand("aegis.reviewAiCommandOrAction"'), 1);
  assert.equal(countInExtension("await handleReviewAiCommandOrAction();"), 1);
});
test("Review AI Command MVP-0 sanitizes secrets, bearer tokens, fences, and long token-like values", () => {
  const raw = [
    "password=super-secret",
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
    "opaque_token_123456789012345678901234567890",
    "```powershell",
    "Get-Content package.json",
    "```",
  ].join("\n");

  const sanitized = sanitizeReviewAiCommandMvp0Text(raw);

  assert.match(sanitized, /password=<redacted>/);
  assert.match(sanitized, /Bearer <redacted>/);
  assert.match(sanitized, /<redacted-token-like-value>/);
  assert.doesNotMatch(sanitized, /```/);
  assert.match(sanitized, /'''powershell/);
});

test("Review AI Command MVP-0 covers sanitizer edge cases and empty findings", () => {
  const raw = "-----BEGIN RSA PRIVATE KEY-----\r\nAEGIS_SYNTHETIC_INVALID_PRIVATE_KEY_TEST_DATA\r\n-----END RSA PRIVATE KEY-----\r\npassword=\"quoted secret\"\r\n" + "x ".repeat(1600);
  const sanitized = sanitizeReviewAiCommandMvp0Text(raw);
  assert.match(sanitized, /\[REDACTED PRIVATE KEY\]/);
  assert.match(sanitized, /password=<redacted>/);
  assert.doesNotMatch(sanitized, /\r\n/);
  assert.match(sanitized, /truncated for safe review display/);
  const markdown = buildReviewAiCommandMvp0Markdown({ classification: "SAFE_TO_RUN", findings: [], inputSource: "input", sanitizedPreview: sanitized, reviewedAtUtc: "2026-07-13T00:00:00.000Z" });
  assert.match(markdown, /None detected by the MVP local rule set\./);
});

test("Review AI Command MVP-0 sanitizer preserves Aegis command contract tokens", () => {
  const sanitized = sanitizeReviewAiCommandMvp0Text(
    "COMMAND_CONTRACT_REQUIRED READ_ONLY_VERIFY_SAMPLE_PASS BOUNDARY"
  );

  assert.match(sanitized, /COMMAND_CONTRACT_REQUIRED/);
  assert.match(sanitized, /READ_ONLY_VERIFY_SAMPLE_PASS/);
  assert.match(sanitized, /BOUNDARY/);
});

test("Review AI Command MVP-0 classification preserves source, timestamp, and sanitized preview", () => {
  const result = classifyReviewAiCommandMvp0Action(
    "Get-Content package.json",
    "input",
    "2026-07-03T00:00:00.000Z"
  );

  assert.equal(result.inputSource, "input");
  assert.equal(result.reviewedAtUtc, "2026-07-03T00:00:00.000Z");
  assert.equal(result.sanitizedPreview, "Get-Content package.json");
  assert.ok(["SAFE_TO_RUN", "WARNING", "BLOCKED"].includes(result.classification));
  assert.ok(Array.isArray(result.findings));
});

test("Review AI Command MVP-0 classification maps unsafe findings into review findings", () => {
  const result = classifyReviewAiCommandMvp0Action(
    "Remove-Item -Recurse -Force C:\\important",
    "selection",
    "2026-07-03T00:00:00.000Z"
  );

  assert.equal(result.inputSource, "selection");
  assert.ok(result.findings.length >= 1);
  assert.ok(result.findings.every((finding) => finding.code.length > 0));
  assert.ok(result.findings.every((finding) => finding.explanation.length > 0));
});

test("Review AI Command MVP-0 markdown builder includes findings and sanitized preview", () => {
  const result = classifyReviewAiCommandMvp0Action(
    "token=abcdefghijklmnopqrstuvwxyz1234567890",
    "clipboard",
    "2026-07-03T00:00:00.000Z"
  );

  const markdown = buildReviewAiCommandMvp0Markdown(result);

  assert.match(markdown, /# Aegis AI Command \/ Action Review/);
  assert.match(markdown, /Input source: clipboard/);
  assert.match(markdown, /Reviewed at UTC: 2026-07-03T00:00:00.000Z/);
  assert.match(markdown, /## Sanitized Preview/);
  assert.match(markdown, /token=<redacted>/);
});

test("Review AI Command MVP-0 clipboard builder preserves classification metadata and preview bounds", () => {
  const result = classifyReviewAiCommandMvp0Action(
    "Get-Content package.json",
    "input",
    "2026-07-03T00:00:00.000Z"
  );

  const clipboard = buildReviewAiCommandMvp0ClipboardText(result);

  assert.match(clipboard, /=== AEGIS AI COMMAND REVIEW RESULT ===/);
  assert.match(clipboard, /CLASSIFICATION=/);
  assert.match(clipboard, /INPUT_SOURCE=input/);
  assert.match(clipboard, /FINDINGS=/);
  assert.match(clipboard, /REVIEWED_AT_UTC=2026-07-03T00:00:00.000Z/);
  assert.match(clipboard, /SANITIZED_PREVIEW_BEGIN/);
  assert.match(clipboard, /Get-Content package\.json/);
  assert.match(clipboard, /SANITIZED_PREVIEW_END/);
});

test("Review AI Command merges compliance into the final Action Quality verdict", () => {
  const action: import("../packages/aegis-core").ActionQualityResult = {
    status: "ALLOW",
    userMessage: "allowed",
    reasons: ["action quality allowed"],
    detectedEffects: [],
    internalRuleId: "SHORT_READ_ONLY",
    source: "vscode_command",
  };

  const safeReview = {
    classification: "SAFE_TO_RUN" as const,
    findings: [],
    inputSource: "input" as const,
    sanitizedPreview: "safe",
    reviewedAtUtc: "2026-07-19T00:00:00.000Z",
  };
  assert.equal(
    combineReviewAiCommandMvp0WithActionQuality(action, safeReview),
    action
  );

  const existingBlock = {
    ...action,
    status: "BLOCK" as const,
    internalRuleId: "REMOTE_SCRIPT_EXECUTION",
  };
  assert.equal(
    combineReviewAiCommandMvp0WithActionQuality(existingBlock, safeReview),
    existingBlock
  );

  const blocked = combineReviewAiCommandMvp0WithActionQuality(action, {
    classification: "BLOCKED",
    findings: [{
      severity: "BLOCK",
      code: "SECRET_EXFILTRATION",
      explanation: "blocked",
    }],
    inputSource: "input",
    sanitizedPreview: "redacted",
    reviewedAtUtc: "2026-07-19T00:00:00.000Z",
  });
  assert.equal(blocked.status, "BLOCK");
  assert.equal(blocked.internalRuleId, "AI_COMPLIANCE_BLOCKED");
  assert.match(blocked.reasons.join(" "), /SECRET_EXFILTRATION/);
  assert.ok(blocked.nextSafeStep);
  assert.equal(blocked.source, "vscode_command");

  const warning = combineReviewAiCommandMvp0WithActionQuality(action, {
    classification: "WARNING",
    findings: [{
      severity: "WARNING",
      code: "PRODUCT_SCOPE_COLLAPSE_SUSPECTED",
      explanation: "review",
    }],
    inputSource: "input",
    sanitizedPreview: "review",
    reviewedAtUtc: "2026-07-19T00:00:00.000Z",
  });
  assert.equal(warning.status, "REVIEW_NEEDED");
  assert.equal(warning.internalRuleId, "AI_COMPLIANCE_REVIEW_NEEDED");
  assert.match(warning.reasons.join(" "), /PRODUCT_SCOPE_COLLAPSE_SUSPECTED/);
});
