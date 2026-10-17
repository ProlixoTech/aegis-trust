// ============================================================================
// Aegis AI Compliance Gate - Phase A focused tests.
// Violation Gate)
// ----------------------------------------------------------------------------
// Covers the Phase A required-check scenarios from
// PHASE-5-CN-AI-COMPLIANCE-GATE-OPTION-B-IMPLEMENTATION-PLAN-LOCK.md
// (Section 8, items 1-9 and 11; items 10/12 are deferred to Phase B/D since
// they involve mixed-input UI behavior and persistence, which Phase A's
// pure module does not implement), plus the Repeat Violation Gate added in
// the Phase A revision.
//
// Uses Node's built-in test runner (node:test) and assert/strict, so no
// additional dependencies are required. Run via:
//   node --test <compiled-output-dir>/aiComplianceGate.test.js
// (path depends on this project's tsconfig outDir; see implementation
// plan lock Section 9 for the build/check plan.)
//
// NOTE: This assumes Node's built-in test runner (Node 18+) is acceptable
// for this project. If the project already uses a different test runner
// (e.g. Jest/Mocha), this file's `import { test } from "node:test"` and
// ssert calls may need adaptation for other test runners; behavior remains the same.
// underlying assertions and scenario inputs would not need to change.
// ============================================================================

import test from "node:test";
import assert from "node:assert/strict";
import { reviewAiComplianceText } from "./aiComplianceGate";

// ----------------------------------------------------------------------------
// Original Phase A rules
// ----------------------------------------------------------------------------

test("missing Set-Clipboard -> WARNING (single occurrence)", () => {
  const input = `
AEGIS_ACTION_ID=AI_GATE_LEGACY_TEST_INPUT_DEV_CONTRACT_V1
BOUNDARY=unit-test-input-only
MUTATION_ALLOWED=False
\`\`\`powershell
# WINDOW: Code folder VS Code terminal
# PATH:   C:\\Users\\admin\\Desktop\\prolixo-aegis-phase1-clean-2
# BOUNDARY: read-only checks only
$result = @()
node scripts/internal-regression-test.js verify-restored
$result += "VERIFY_RESTORED_EXIT=$LASTEXITCODE"
$result
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "WARNING");
  assert.ok(
    result.findings.some(
      (f) => f.ruleId === "MISSING_SET_CLIPBOARD" && f.severity === "WARNING"
    )
  );
  assert.ok(!result.findings.some((f) => f.ruleId === "REPEAT_MISSING_CLIPBOARD_CAPTURE"));
});

test("missing window/path/boundary -> WARNING (single occurrence)", () => {
  const input = `
AEGIS_ACTION_ID=AI_GATE_LEGACY_TEST_INPUT_DEV_CONTRACT_V1
BOUNDARY=unit-test-input-only
MUTATION_ALLOWED=False
\`\`\`powershell
$result = @()
node scripts/internal-regression-test.js verify-restored
$result += "VERIFY_RESTORED_EXIT=$LASTEXITCODE"
$result | Set-Clipboard
$result
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "WARNING");
  const ruleIds = result.findings.map((f) => f.ruleId);
  assert.ok(ruleIds.includes("MISSING_WINDOW_LABEL"));
  assert.ok(ruleIds.includes("MISSING_BOUNDARY_STATEMENT"));
  assert.ok(!ruleIds.includes("REPEAT_MISSING_COMMAND_CONTRACT"));
});

test("Get-Content .env -> BLOCKED", () => {
  const input = `
\`\`\`powershell
# WINDOW: Code folder VS Code terminal
# PATH: C:\\project
# BOUNDARY: read .env for debugging
Get-Content .env
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some((f) => f.ruleId === "RAW_PROTECTED_CONTENT_READ" && f.severity === "BLOCK")
  );
});

test("review-only + Remove-Item -> BLOCKED (single occurrence)", () => {
  const input = `
This is a review-only step. Do not edit files.

\`\`\`powershell
Remove-Item .\\old-snapshot.json
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some(
      (f) => f.ruleId === "REVIEW_ONLY_WITH_WRITE_OR_DELETE" && f.severity === "BLOCK"
    )
  );
  assert.ok(!result.findings.some((f) => f.ruleId === "REPEAT_PHASE_BOUNDARY_DRIFT"));
});

test("PASS without evidence -> BLOCKED (single occurrence)", () => {
  const input = `Everything is done. The result is PASS.`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some(
      (f) => f.ruleId === "SUCCESS_CLAIM_WITHOUT_EVIDENCE" && f.severity === "BLOCK"
    )
  );
  assert.ok(!result.findings.some((f) => f.ruleId === "REPEAT_UNSUPPORTED_SUCCESS_CLAIM"));
});

test("PASS with evidence -> not blocked by Evidence Claim Gate", () => {
  const input = `
The result is PASS.
check-state-evidence --expect safe exit 0
verify-restored exit 0
`;
  const result = reviewAiComplianceText(input);
  assert.ok(
    !result.findings.some((f) => f.ruleId === "SUCCESS_CLAIM_WITHOUT_EVIDENCE")
  );
});

test("Evidence Claim Gate blocks unsupported success claims across input surfaces", () => {
  const inputs = [
    "Chat summary: Everything is done. The result is PASS.",
    "Terminal note: The operation is complete.",
    "Review panel text: This is fully verified.",
    "Handoff note: The handoff is complete.",
    "Agent response: The fix is complete."
  ];

  for (const input of inputs) {
    const result = reviewAiComplianceText(input);

    assert.equal(result.classification, "BLOCKED", input);
    assert.ok(
      result.findings.some(
        (f) => f.ruleId === "SUCCESS_CLAIM_WITHOUT_EVIDENCE" && f.severity === "BLOCK"
      ),
      input
    );
  }
});

test("Restore success without verification chain -> BLOCKED", () => {
  const input = `Restore Last Safe State succeeded. The workspace is fine now.`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some(
      (f) =>
        f.ruleId === "RESTORE_SUCCESS_WITHOUT_VERIFICATION_CHAIN" &&
        f.severity === "BLOCK"
    )
  );
});

test("D-P0-6B plain PASS misuse -> BLOCKED", () => {
  const input = `Good news: D-P0-6B is PASS now, fully resolved.`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some(
      (f) => f.ruleId === "DP06B_COLLAPSED_TO_PLAIN_PASS" && f.severity === "BLOCK"
    )
  );
});

test("D-P0-6B with PASS_WITH_RECOVERY_NOTE qualifier -> not flagged by DP06B rule", () => {
  const input = `D-P0-6B = PASS_WITH_RECOVERY_NOTE / LOCKED / SAFE.`;
  const result = reviewAiComplianceText(input);
  assert.ok(
    !result.findings.some((f) => f.ruleId === "DP06B_COLLAPSED_TO_PLAIN_PASS")
  );
});

test("direct controlled recovery described as clean PASS -> BLOCKED", () => {
  const input = `We performed a direct controlled recovery, and the restore last safe state succeeded, so this is a clean PASS.`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some(
      (f) =>
        f.ruleId === "DIRECT_RECOVERY_DESCRIBED_AS_CLEAN_PASS" &&
        f.severity === "BLOCK"
    )
  );
});

test("well-formed safe command -> SAFE_TO_RUN", () => {
  const input = `
AEGIS_ACTION_ID=AI_GATE_LEGACY_TEST_INPUT_DEV_CONTRACT_V1
BOUNDARY=unit-test-input-only
MUTATION_ALLOWED=False
\`\`\`powershell id="safe-reviewed-command"
# COMMAND CONTRACT REQUIRED
# WINDOW: Code folder VS Code terminal
# PATH: C:\\Users\\admin\\Desktop\\prolixo-aegis-phase1-clean-2
# BOUNDARY: read-only verification only, no protected target changes

$result = @()
node scripts/internal-regression-test.js verify-restored
$result += "VERIFY_RESTORED_EXIT=$LASTEXITCODE"
$resultText = $result -join "\`r\`n"
$resultText | Set-Clipboard
$resultText
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "SAFE_TO_RUN");
  assert.deepEqual(result.findings, []);
  assert.equal(result.isEmpty, false);
});

test("empty input -> neutral, non-false-safe handling", () => {
  const result = reviewAiComplianceText("");
  assert.equal(result.classification, "SAFE_TO_RUN");
  assert.equal(result.isEmpty, true);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.checkedSubGates, []);
});

test("whitespace-only input -> treated as empty", () => {
  const result = reviewAiComplianceText("   \n\t  ");
  assert.equal(result.isEmpty, true);
  assert.equal(result.classification, "SAFE_TO_RUN");
});

// ----------------------------------------------------------------------------
// Repeat Violation Gate (Phase A revision)
// ----------------------------------------------------------------------------

test("REPEAT_MISSING_COMMAND_CONTRACT: 2 blocks both missing window -> BLOCKED", () => {
  const input = `
\`\`\`powershell
$result = @()
$result | Set-Clipboard
$result
\`\`\`

\`\`\`powershell
$result2 = @()
$result2 | Set-Clipboard
$result2
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some(
      (f) => f.ruleId === "REPEAT_MISSING_COMMAND_CONTRACT" && f.severity === "BLOCK"
    )
  );
  const repeatFinding = result.findings.find((f) => f.ruleId === "REPEAT_MISSING_COMMAND_CONTRACT")!;
  assert.equal(
    repeatFinding.explanation,
    "Repeated omission of the same required contract item indicates this AI output is not reliable enough to execute as-is."
  );
});

test("REPEAT_MISSING_CLIPBOARD_CAPTURE: 2 blocks both missing Set-Clipboard -> BLOCKED", () => {
  const input = `
\`\`\`powershell
# WINDOW: Code folder VS Code terminal
# PATH: C:\\project
# BOUNDARY: read-only
$result = @()
node scripts/internal-regression-test.js verify-restored
$result += "VERIFY_RESTORED_EXIT=$LASTEXITCODE"
$result
\`\`\`

\`\`\`powershell
# WINDOW: Code folder VS Code terminal
# PATH: C:\\project
# BOUNDARY: read-only
$result2 = @()
node scripts/internal-regression-test.js verify-metadata
$result2 += "VERIFY_METADATA_EXIT=$LASTEXITCODE"
$result2
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some(
      (f) => f.ruleId === "REPEAT_MISSING_CLIPBOARD_CAPTURE" && f.severity === "BLOCK"
    )
  );
});

test("REPEAT_AMBIGUOUS_LOCAL_OPERATION: 2 'choose a location' instances -> BLOCKED", () => {
  const input = `
First, choose a folder to save the backup file.
Then, save the second file wherever you like.
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  const ruleIds = result.findings.map((f) => f.ruleId);
  assert.ok(ruleIds.includes("AMBIGUOUS_USER_CHOICE_REQUIRED"));
  assert.ok(ruleIds.includes("REPEAT_AMBIGUOUS_LOCAL_OPERATION"));
  const repeatFinding = result.findings.find((f) => f.ruleId === "REPEAT_AMBIGUOUS_LOCAL_OPERATION")!;
  assert.equal(repeatFinding.severity, "BLOCK");
});

test("REPEAT_PHASE_BOUNDARY_DRIFT: review-only text with 2 write/delete commands -> BLOCKED", () => {
  const input = `
This step is review-only. Do not edit files.

\`\`\`powershell
Remove-Item .\\old-snapshot.json
git commit -m "remove old snapshot"
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  const repeatFindings = result.findings.filter((f) => f.ruleId === "REPEAT_PHASE_BOUNDARY_DRIFT");
  assert.equal(repeatFindings.length, 1);
  assert.equal(repeatFindings[0].severity, "BLOCK");
});

test("REPEAT_UNSUPPORTED_SUCCESS_CLAIM: multiple controlled words without evidence -> BLOCKED", () => {
  const input = `The build is complete and the result is PASS, fully verified and final.`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  const successClaims = result.findings.filter((f) => f.ruleId === "SUCCESS_CLAIM_WITHOUT_EVIDENCE");
  assert.ok(successClaims.length >= 2);
  assert.ok(
    result.findings.some(
      (f) => f.ruleId === "REPEAT_UNSUPPORTED_SUCCESS_CLAIM" && f.severity === "BLOCK"
    )
  );
});

test("REPEAT_PRODUCT_SCOPE_COLLAPSE: 2 paragraphs collapsing product-runtime requirement to harness-only -> BLOCKED", () => {
  const input = `
This feature must be a final product runtime capability for the end user.
However, a harness-only checker is sufficient for now.

This is also a user-facing requirement.
A development aid only implementation covers this requirement.
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  const suspectedFindings = result.findings.filter((f) => f.ruleId === "PRODUCT_SCOPE_COLLAPSE_SUSPECTED");
  assert.ok(suspectedFindings.length >= 2);
  assert.ok(
    result.findings.some(
      (f) => f.ruleId === "REPEAT_PRODUCT_SCOPE_COLLAPSE" && f.severity === "BLOCK"
    )
  );
});

test("single product-scope-collapse paragraph -> WARNING only, no repeat escalation", () => {
  const input = `
This must be a product-runtime capability for the end user.
However, a harness-only checker is sufficient for now.
`;
  const result = reviewAiComplianceText(input);
  assert.ok(
    result.findings.some(
      (f) => f.ruleId === "PRODUCT_SCOPE_COLLAPSE_SUSPECTED" && f.severity === "WARNING"
    )
  );
  assert.ok(!result.findings.some((f) => f.ruleId === "REPEAT_PRODUCT_SCOPE_COLLAPSE"));
  assert.equal(result.classification, "WARNING");
});

test("missing COMMAND CONTRACT REQUIRED header -> WARNING", () => {
  const input = `
AEGIS_ACTION_ID=AI_GATE_LEGACY_TEST_INPUT_DEV_CONTRACT_V1
BOUNDARY=unit-test-input-only
MUTATION_ALLOWED=False
\`\`\`powershell id="missing-contract-header"
# WINDOW: Code folder VS Code terminal
# PATH: C:\\Users\\admin\\Desktop\\prolixo-aegis-phase1-clean-2
# BOUNDARY: read-only verification only

$result = @()
$result += "CHECK_ONLY=True"
$resultText = $result -join "\`r\`n"
$resultText | Set-Clipboard
$resultText
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "WARNING");
  assert.ok(
    result.findings.some(
      (f) =>
        f.ruleId === "MISSING_COMMAND_CONTRACT_REQUIRED_HEADER" &&
        f.severity === "WARNING"
    )
  );
});

test("missing resultText output contract -> WARNING", () => {
  const input = `
AEGIS_ACTION_ID=AI_GATE_LEGACY_TEST_INPUT_DEV_CONTRACT_V1
BOUNDARY=unit-test-input-only
MUTATION_ALLOWED=False
\`\`\`powershell id="missing-resulttext-contract"
# COMMAND CONTRACT REQUIRED
# WINDOW: Code folder VS Code terminal
# PATH: C:\\Users\\admin\\Desktop\\prolixo-aegis-phase1-clean-2
# BOUNDARY: read-only verification only

$result = @()
$result += "CHECK_ONLY=True"
$result | Set-Clipboard
$result
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "WARNING");
  const ruleIds = result.findings.map((f) => f.ruleId);
  assert.ok(ruleIds.includes("MISSING_RESULTTEXT_JOIN"));
  assert.ok(ruleIds.includes("MISSING_RESULTTEXT_SET_CLIPBOARD"));
  assert.ok(ruleIds.includes("MISSING_RESULTTEXT_FINAL_OUTPUT"));
});

test("REPEAT_MISSING_COMMAND_CONTRACT_REQUIRED_HEADER: 2 blocks missing header -> BLOCKED", () => {
  const input = `
\`\`\`powershell id="first-missing-header"
# WINDOW: Code folder VS Code terminal
# PATH: C:\\project
# BOUNDARY: read-only

$result = @()
$result += "FIRST_CHECK=True"
$resultText = $result -join "\`r\`n"
$resultText | Set-Clipboard
$resultText
\`\`\`

\`\`\`powershell id="second-missing-header"
# WINDOW: Code folder VS Code terminal
# PATH: C:\\project
# BOUNDARY: read-only

$result = @()
$result += "SECOND_CHECK=True"
$resultText = $result -join "\`r\`n"
$resultText | Set-Clipboard
$resultText
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some(
      (f) =>
        f.ruleId === "REPEAT_MISSING_COMMAND_CONTRACT_REQUIRED_HEADER" &&
        f.severity === "BLOCK"
    )
  );
});

test("REPEAT_MISSING_RESULTTEXT_CONTRACT: 2 legacy clipboard blocks -> BLOCKED", () => {
  const input = `
\`\`\`powershell id="first-legacy-clipboard"
# COMMAND CONTRACT REQUIRED
# WINDOW: Code folder VS Code terminal
# PATH: C:\\project
# BOUNDARY: read-only

$result = @()
$result += "FIRST_CHECK=True"
$result | Set-Clipboard
$result
\`\`\`

\`\`\`powershell id="second-legacy-clipboard"
# COMMAND CONTRACT REQUIRED
# WINDOW: Code folder VS Code terminal
# PATH: C:\\project
# BOUNDARY: read-only

$result = @()
$result += "SECOND_CHECK=True"
$result | Set-Clipboard
$result
\`\`\`
`;
  const result = reviewAiComplianceText(input);
  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some(
      (f) =>
        f.ruleId === "REPEAT_MISSING_RESULTTEXT_CONTRACT" &&
        f.severity === "BLOCK"
    )
  );
});

test("KPL confirmed missing path rediscovery attempt -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "KNOWN_PRECONDITION=AUTHORIZED_PATH_MISSING_DENIAL_GETRULESET_CONFIRMED. Search the runner for the existing authorized path before creating recovery."
  );

  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some((f) => f.ruleId === "KPL_REDISCOVERY_FORBIDDEN" && f.severity === "BLOCK")
  );
});

test("KPL recovery objective reversed to stop because path missing -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "AUTHORIZED_PATH_MISSING_DENIAL_GETRULESET is confirmed. OBJECTIVE=CREATE_AUTHORIZED_RECOVERY_PATH. Stop because the authorized path is missing."
  );

  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some((f) => f.ruleId === "KPL_OBJECTIVE_REVERSAL" && f.severity === "BLOCK")
  );
});

test("denial label treated as schema authority -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "Use the denial label as the ruleset schema and derive schema fields from the denial label."
  );

  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some((f) => f.ruleId === "DENIAL_LABEL_USED_AS_SCHEMA_AUTHORITY" && f.severity === "BLOCK")
  );
});

test("getRuleset recovery without owner envelope -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "Patch getRuleset recovery directly and create the ruleset authority path without an owner recovery envelope."
  );

  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some((f) => f.ruleId === "GETRULESET_RECOVERY_WITHOUT_OWNER_ENVELOPE" && f.severity === "BLOCK")
  );
});

test("getRuleset recovery with owner-approved recovery envelope -> not blocked by getRuleset envelope rule", () => {
  const result = reviewAiComplianceText(
    "Route getRuleset recovery through an OWNER_RECOVERY_ENVELOPE. The owner-approved recovery envelope is valid before creating the authorized recovery path."
  );

  assert.ok(
    !result.findings.some((f) => f.ruleId === "GETRULESET_RECOVERY_WITHOUT_OWNER_ENVELOPE")
  );
});

test("helper/function signature guess -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "Assume addFinding exists and patch aiComplianceGate without checking the actual helper signature."
  );

  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some((f) => f.ruleId === "HELPER_OR_SIGNATURE_GUESS_FORBIDDEN" && f.severity === "BLOCK")
  );
});

test("required ZIP entry guessed without compiler surface -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "Treat src__aiComplianceGate.test.ts as a required ZIP entry because it is probably required; do not verify the compiler required surface."
  );

  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some((f) => f.ruleId === "REQUIRED_ZIP_ENTRY_GUESS_FORBIDDEN" && f.severity === "BLOCK")
  );
});

test("final status guessed without explicit gate result -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "Claim upload-ready and final product pass because the checkpoint looks complete, without checking explicit gate results."
  );

  assert.equal(result.classification, "BLOCKED");
  assert.ok(
    result.findings.some((f) => f.ruleId === "FINAL_STATUS_GUESS_FORBIDDEN" && f.severity === "BLOCK")
  );
});

test("SOURCE_OF_TRUTH failure label used as retry schema -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "Use failure label missing_command_contract_required as the source of truth for the retry command schema."
  );
  assert.equal(result.classification, "BLOCKED");
  assert.ok(result.findings.some((f) => f.ruleId === "UNVERIFIED_APPEARANCE_USED_AS_SOURCE_OF_TRUTH"));
});

test("SOURCE_OF_TRUTH established prior fact rediscovery -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "knownPrecondition AUTHORIZED_PATH_MISSING with rediscoveryForbidden=true was established. Re-verify path existence before building recovery."
  );
  assert.equal(result.classification, "BLOCKED");
  assert.ok(result.findings.some((f) => f.ruleId === "ESTABLISHED_PRIOR_FACT_REDISCOVERY_FORBIDDEN"));
});

test("SOURCE_OF_TRUTH receipt treated as current truth -> BLOCKED", () => {
  const result = reviewAiComplianceText(
    "Use the prior receipt as proof that the file is currently safe now."
  );
  assert.equal(result.classification, "BLOCKED");
  assert.ok(result.findings.some((f) => f.ruleId === "RECEIPT_PAST_DECISION_TREATED_AS_CURRENT_TRUTH"));
});

test("NO_GUESSING_ALWAYS_VERIFY contract statement -> not blocked by no-guessing gate", () => {
  const result = reviewAiComplianceText(
    "NO_GUESSING_ALWAYS_VERIFY=True. Do not assume helper names; verify the actual helper signature before mutation."
  );

  assert.ok(
    !result.findings.some((f) => f.ruleId === "HELPER_OR_SIGNATURE_GUESS_FORBIDDEN")
  );
});
test("command-like AI output without Action Envelope or development Action Contract is blocked", () => {
  const input = [
    "```powershell",
    "npm run compile",
    "```",
  ].join("\n");

  const result = reviewAiComplianceText(input);

  const findings = result.findings.filter(
    (finding) =>
      finding.ruleId ===
      "BLOCKED_AI_SYNTHESIZED_COMMAND_WITHOUT_ACTION_ENVELOPE_OR_DEV_CONTRACT"
  );

  assert.equal(result.classification, "BLOCKED");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.severity, "BLOCK");
});
