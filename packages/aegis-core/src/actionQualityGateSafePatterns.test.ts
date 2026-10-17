import test from "node:test";
import assert from "node:assert/strict";

import {
  extractRunnerActionId,
  isSafeRunnerPattern,
  isShortReadOnlyPattern,
} from "./actionQualityGateSafePatterns";

test("actionQualityGateSafePatterns allows only explicit safe runner action ids with copied marker", () => {
  const allowed = String.raw`node .\scripts\verify.js READ_ONLY_VERIFY_ACTION_AUTHORITY_CONTENT | Set-Clipboard; Write-Host "COPIED=READ_ONLY_VERIFY_ACTION_AUTHORITY_CONTENT"`;

  assert.equal(isSafeRunnerPattern(allowed), true);
  assert.equal(extractRunnerActionId(allowed), "READ_ONLY_VERIFY_ACTION_AUTHORITY_CONTENT");
});

test("actionQualityGateSafePatterns extracts but does not allow unknown runner action ids", () => {
  const unknown = String.raw`node .\scripts\verify.js READ_ONLY_NOT_IN_ALLOWLIST | Set-Clipboard; Write-Host "COPIED=READ_ONLY_NOT_IN_ALLOWLIST"`;

  assert.equal(extractRunnerActionId(unknown), "READ_ONLY_NOT_IN_ALLOWLIST");
  assert.equal(isSafeRunnerPattern(unknown), false);
});

test("actionQualityGateSafePatterns rejects runner commands when copied marker does not match action id", () => {
  const mismatch = String.raw`node .\scripts\verify.js READ_ONLY_VERIFY_ACTION_AUTHORITY_CONTENT | Set-Clipboard; Write-Host "COPIED=RUN_HANDOFF_IDENTITY_INVARIANT_CHECK"`;

  assert.equal(extractRunnerActionId(mismatch), null);
  assert.equal(isSafeRunnerPattern(mismatch), false);
});

test("actionQualityGateSafePatterns accepts short single-purpose read-only commands", () => {
  assert.equal(isShortReadOnlyPattern("node --check src/example.ts"), true);
  assert.equal(isShortReadOnlyPattern("node --version"), true);
  assert.equal(isShortReadOnlyPattern("Get-Content src\\types.ts"), true);
  assert.equal(isShortReadOnlyPattern("Select-String -LiteralPath src\\types.ts -Pattern ActionGateStatus"), true);
  assert.equal(isShortReadOnlyPattern("git status"), true);
  assert.equal(isShortReadOnlyPattern("git diff -- src\\types.ts"), true);
  assert.equal(isShortReadOnlyPattern("git log --oneline -5"), true);
  assert.equal(isShortReadOnlyPattern("cat src/types.ts"), true);
  assert.equal(isShortReadOnlyPattern("type src\\types.ts"), true);
  assert.equal(isShortReadOnlyPattern("echo readonly diagnostic"), true);
});

test("actionQualityGateSafePatterns rejects empty, chained, piped, long, and mutating commands", () => {
  assert.equal(isShortReadOnlyPattern(""), false);
  assert.equal(isShortReadOnlyPattern("git status; git diff"), false);
  assert.equal(isShortReadOnlyPattern("git status && git diff"), false);
  assert.equal(isShortReadOnlyPattern("Get-Content src\\types.ts | Set-Clipboard"), false);
  assert.equal(isShortReadOnlyPattern("npm test"), false);
  assert.equal(isShortReadOnlyPattern("npm install"), false);
  assert.equal(isShortReadOnlyPattern("Remove-Item src\\types.ts"), false);
  assert.equal(isShortReadOnlyPattern(`echo ${"x".repeat(201)}`), false);
});

test("actionQualityGateSafePatterns mutation word boundaries do not block package.json filename", () => {
  assert.equal(isShortReadOnlyPattern("Get-Content package.json"), true);
  assert.equal(isShortReadOnlyPattern("git diff -- package.json"), true);
});

test("actionQualityGateSafePatterns rejects case-variant allowlisted action ids", () => {
  const lower = "node .\\scripts\\verify.js read_only_verify_action_authority_content | Set-Clipboard; Write-Host \"COPIED=read_only_verify_action_authority_content\"";

  assert.equal(extractRunnerActionId(lower), "read_only_verify_action_authority_content");
  assert.equal(isSafeRunnerPattern(lower), false);
});
