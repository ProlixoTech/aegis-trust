import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  buildProtectedTerminalMvp0AutosnapshotBlockedMarkdown,
  buildProtectedTerminalMvp0AutosnapshotClipboardText,
  buildProtectedTerminalMvp0ClipboardText,
  evaluateProtectedTerminalMvp0Review,
  sanitizeProtectedTerminalMvp0Preview,
} from "./protectedTerminalMvp0Policy";

test("Protected Terminal MVP-0 command registration is exposed through package and extension exactly once", () => {
  const packageJson = readFileSync(resolve(process.cwd(), "package.json"), "utf8");
  const extensionSource = readFileSync(resolve(process.cwd(), "src", "extension.ts"), "utf8");

  const countInPackage = (needle: string) => packageJson.split(needle).length - 1;
  const countInExtension = (needle: string) => extensionSource.split(needle).length - 1;

  assert.equal(countInPackage('"onCommand:aegis.protectedTerminal"'), 1);
  assert.equal(countInPackage('"command":  "aegis.protectedTerminal"'), 1);
  assert.equal(countInPackage('"title":  "Aegis: Protected Terminal (MVP-0)"'), 1);
  assert.equal(countInExtension('registerCommand("aegis.protectedTerminal"'), 1);
  assert.equal(countInExtension("await handleProtectedTerminalMvp0();"), 1);
});
test("Protected Terminal MVP-0 sanitizes preview redactions and length", () => {
  const sanitized = sanitizeProtectedTerminalMvp0Preview("Write-Output   token=secret value=visible " + "x".repeat(600));

  assert.match(sanitized, /token=<redacted>/);
  assert.match(sanitized, /value=<redacted>/);
  assert.equal(sanitized.length, 500);
});

test("Protected Terminal MVP-0 review blocks destructive command before handoff", () => {
  const review = evaluateProtectedTerminalMvp0Review("Remove-Item .\\old-snapshot.json");

  assert.equal(review.gateResult.status, "BLOCK");
  assert.equal(review.gateResult.source, "protected_terminal");
  assert.equal(review.terminalHandoffBlocked, true);
  assert.match(review.clipboardText, /TERMINAL_HANDOFF_BLOCKED=true/);
  assert.match(review.blockedMarkdown, /Terminal handoff: BLOCKED before insertion/);
});

test("Protected Terminal MVP-0 artifact authority claim -> BLOCK before handoff", () => {
  const review = evaluateProtectedTerminalMvp0Review("sandbox:/mnt/data/generated-report.pdf");

  assert.equal(review.gateResult.status, "BLOCK");
  assert.equal(review.gateResult.internalRuleId, "AI_ARTIFACT_CHANNEL_AUTHORITY");
  assert.equal(review.gateResult.source, "protected_terminal");
  assert.equal(review.terminalHandoffBlocked, true);
  assert.match(review.clipboardText, /ACTION_QUALITY_GATE_RULE=AI_ARTIFACT_CHANNEL_AUTHORITY/);
  assert.match(review.clipboardText, /TERMINAL_HANDOFF_BLOCKED=true/);
  assert.match(review.blockedMarkdown, /Terminal handoff: BLOCKED before insertion/);
});

test("Protected Terminal MVP-0 review allows short read-only command without automatic execution", () => {
  const review = evaluateProtectedTerminalMvp0Review("Get-Content package.json");

  assert.equal(review.gateResult.status, "ALLOW");
  assert.equal(review.gateResult.source, "protected_terminal");
  assert.equal(review.terminalHandoffBlocked, false);
  assert.match(review.clipboardText, /COMMAND_NOT_EXECUTED_AUTOMATICALLY=True/);
  assert.match(review.clipboardText, /TERMINAL_HANDOFF_BLOCKED=false/);
});

test("Protected Terminal MVP-0 allow decision is review-only and never execution authority", () => {
  const review = evaluateProtectedTerminalMvp0Review("Get-Content package.json");

  assert.equal(review.gateResult.status, "ALLOW");
  assert.equal(review.gateResult.source, "protected_terminal");
  assert.equal(review.terminalHandoffBlocked, false);
  assert.match(review.clipboardText, /PROTECTED_TERMINAL_MVP0=True/);
  assert.match(review.clipboardText, /COMMAND_NOT_EXECUTED_AUTOMATICALLY=True/);
  assert.match(review.clipboardText, /TERMINAL_HANDOFF_BLOCKED=false/);

  for (const forbiddenAuthorityMarker of [
    "NONCE_CONSUMED=True",
    "EXECUTION_AUTHORITY_GRANTED=True"
  ]) {
    assert.equal(review.clipboardText.includes(forbiddenAuthorityMarker), false, forbiddenAuthorityMarker);
  }
});

test("Protected Terminal MVP-0 clipboard builder preserves gate metadata", () => {
  const review = evaluateProtectedTerminalMvp0Review("Get-Content package.json");
  const clipboardText = buildProtectedTerminalMvp0ClipboardText(review.gateResult);

  assert.match(clipboardText, /PROTECTED_TERMINAL_MVP0=True/);
  assert.match(clipboardText, /ACTION_QUALITY_GATE_STATUS=ALLOW/);
  assert.match(clipboardText, /ACTION_QUALITY_GATE_SOURCE=protected_terminal/);
});

test("Protected Terminal MVP-0 autosnapshot clipboard reports pass and blocked states", () => {
  const baseClipboard = evaluateProtectedTerminalMvp0Review("Get-Content package.json").clipboardText;

  const passText = buildProtectedTerminalMvp0AutosnapshotClipboardText(baseClipboard, {
    ok: true,
    snapshotCount: 2,
    baselineRegistrationCount: 1,
    skippedMissingCount: 0,
    reasons: [],
  });

  const blockedText = buildProtectedTerminalMvp0AutosnapshotClipboardText(baseClipboard, {
    ok: false,
    snapshotCount: 0,
    baselineRegistrationCount: 0,
    skippedMissingCount: 1,
    reasons: ["missing baseline"],
  });

  assert.match(passText, /AUTOSNAPSHOT_PREFLIGHT_STATUS=PASS/);
  assert.match(passText, /TERMINAL_HANDOFF_BLOCKED_BY_AUTOSNAPSHOT=false/);
  assert.match(blockedText, /AUTOSNAPSHOT_PREFLIGHT_STATUS=BLOCKED/);
  assert.match(blockedText, /AUTOSNAPSHOT_PREFLIGHT_REASONS=missing baseline/);
  assert.match(blockedText, /TERMINAL_HANDOFF_BLOCKED_BY_AUTOSNAPSHOT=true/);
});

test("Protected Terminal MVP-0 autosnapshot blocked markdown forbids terminal insertion", () => {
  const markdown = buildProtectedTerminalMvp0AutosnapshotBlockedMarkdown({
    ok: false,
    snapshotCount: 0,
    baselineRegistrationCount: 0,
    skippedMissingCount: 1,
    reasons: ["missing snapshot"],
  });

  assert.match(markdown, /Aegis Protected Terminal AutoSnapshot/);
  assert.match(markdown, /Terminal handoff: BLOCKED before insertion/);
  assert.match(markdown, /No command was inserted into the terminal/);
});
test("Protected Terminal MVP-0 review-needed decision blocks terminal handoff",()=>{const r=evaluateProtectedTerminalMvp0Review("");assert.equal(r.gateResult.status,"REVIEW_NEEDED");assert.equal(r.terminalHandoffBlocked,true);assert.match(r.clipboardText,/TERMINAL_HANDOFF_BLOCKED=true/);});
