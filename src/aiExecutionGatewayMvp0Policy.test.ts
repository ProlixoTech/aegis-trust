import type {
  ResolveServerRulesetFallbackResult,
} from "./serverRulesetFallbackResolution";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";

import {
  detectAiExecutionGatewayMvp0WorkflowDrift,
  evaluateAiExecutionGatewayMvp0UserDefinedRules,
  validateAiExecutionGatewayMvp0BootstrapCapsule,
  validateAiExecutionGatewayMvp0UserDefinedRuleSet,
  evaluateAiExecutionGatewayMvp0ActionQuality,
  enforceAiExecutionGatewayMvp0EffectPreflight,
  hasAuthorizedAiExecutionGatewayMvp0Surface,
  buildAiExecutionGatewayMvp0CanonicalProposal,
  parseAiExecutionGatewayMvp0Envelope,
  buildAiExecutionGatewayMvp0FinalReviewedOnlyReceiptLines,
  buildAiExecutionGatewayMvp0InvalidBootstrapCapsuleReceiptLines,
  buildAiExecutionGatewayMvp0InvalidEnvelopeReceiptLines,
  buildAiExecutionGatewayMvp0NoAuthorizedSurfaceReceiptLines,
  buildAiExecutionGatewayMvp0WorkflowDriftBlockedReceiptLines,
  buildAiExecutionGatewayMvp0UserDefinedRuleBlockedReceiptLines,
  evaluateAiExecutionGatewayMvp0ServerRuleset,
  buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines,
} from "./aiExecutionGatewayMvp0Policy";
import { SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH } from "../packages/aegis-core";

test("Gateway MVP-0 envelope parse rejects invalid JSON", () => {
  const result = parseAiExecutionGatewayMvp0Envelope("{not json");

  assert.equal(result.envelopeValid, false);
  assert.equal(result.envelopeError, "INVALID_JSON_ENVELOPE");
  assert.equal(result.proposed, "");
});

test("Gateway MVP-0 envelope parse requires ai_connector source", () => {
  const result = parseAiExecutionGatewayMvp0Envelope(JSON.stringify({
    source: "manual_review",
    proposedCommand: "Get-Content package.json",
  }));

  assert.equal(result.envelopeValid, false);
  assert.equal(result.envelopeError, "INVALID_OR_MISSING_SOURCE");
});

test("Gateway MVP-0 capability manifest excludes external_gateway until bridge is implemented", () => {
  const capability = SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH.trusted_capabilities.find(
    (entry) => entry.capability_id === "ai_gateway_review_only"
  );

  assert.ok(capability);
  assert.deepEqual(capability.allowed_sources, ["ai_connector"]);
});
test("Gateway MVP-0 envelope parse requires proposed command", () => {
  const result = parseAiExecutionGatewayMvp0Envelope(JSON.stringify({
    source: "ai_connector",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
  }));

  assert.equal(result.envelopeValid, false);
  assert.equal(result.envelopeError, "MISSING_PROPOSED_COMMAND");
});

test("Gateway MVP-0 envelope parse accepts proposedCommand and trims it", () => {
  const result = parseAiExecutionGatewayMvp0Envelope(JSON.stringify({
    source: "ai_connector",
    intent: "propose_terminal_command",
    actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
    capabilityId: "ai_gateway_review_only",
    targetPath: "package.json",
    proposedCommand: "  Get-Content package.json  ",
  }));

  assert.equal(result.envelopeValid, true);
  assert.equal(result.envelopeError, "");
  assert.equal(result.envelopeSource, "ai_connector");
  assert.equal(result.envelopeIntent, "propose_terminal_command");
  assert.equal(result.envelopeActionId, "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY");
  assert.equal(result.envelopeCapabilityId, "ai_gateway_review_only");
  assert.equal(result.envelopeTargetPath, "package.json");
  assert.equal(result.proposed, "Get-Content package.json");
});

test("Gateway MVP-0 authorized surface requires exact action and capability", () => {
  assert.equal(
    hasAuthorizedAiExecutionGatewayMvp0Surface(
      "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
      "ai_gateway_review_only"
    ),
    true
  );

  assert.equal(
    hasAuthorizedAiExecutionGatewayMvp0Surface(
      "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
      "WRONG_CAPABILITY"
    ),
    false
  );
});

test("Gateway MVP-0 workflow drift blocks release and packaging commands", () => {
  assert.equal(detectAiExecutionGatewayMvp0WorkflowDrift("vsce package").blocked, true);
  assert.equal(detectAiExecutionGatewayMvp0WorkflowDrift("Compress-Archive . out.zip").blocked, true);
  assert.equal(detectAiExecutionGatewayMvp0WorkflowDrift("The final ZIP is upload-ready.").blocked, true);
});

test("Gateway MVP-0 workflow drift blocks AI artifact channel commands and claims", () => {
  const blockedExamples = [
    "sandbox:/mnt/data/generated.zip",
    "Here is the download link for the generated artifact.",
    "python_user_visible created a file.",
    "image_gen generated an image artifact.",
    "tool invocation creates a sidecar file.",
    "created file: /mnt/data/report.pdf",
  ];

  for (const proposed of blockedExamples) {
    assert.equal(detectAiExecutionGatewayMvp0WorkflowDrift(proposed).blocked, true);
  }
});
test("Gateway MVP-0 workflow drift allows short read-only inspection text", () => {
  const result = detectAiExecutionGatewayMvp0WorkflowDrift("Get-Content package.json");

  assert.equal(result.blocked, false);
  assert.equal(result.pattern, "");
});

test("Gateway MVP-0 action quality uses ai_connector source", () => {
  const result = evaluateAiExecutionGatewayMvp0ActionQuality("Get-Content package.json");

  assert.equal(result.status, "ALLOW");
  assert.equal(result.source, "ai_connector");
});

test("Gateway MVP-0 validates and enforces user-defined additional block rules", () => {
  const validation = validateAiExecutionGatewayMvp0UserDefinedRuleSet({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: ["  Remove-Item  ", "publish-secret"],
  });

  assert.equal(validation.valid, true);
  assert.equal(validation.error, "");
  assert.ok(validation.ruleSet);
  assert.deepEqual(validation.ruleSet.blockedCommandSubstrings, ["Remove-Item", "publish-secret"]);

  const blocked = evaluateAiExecutionGatewayMvp0UserDefinedRules(
    "Remove-Item ./protected-file",
    validation.ruleSet
  );
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.matchedRule, "Remove-Item");
  assert.equal(blocked.ruleSetId, "owner-rules");

  const allowed = evaluateAiExecutionGatewayMvp0UserDefinedRules(
    "Get-Content package.json",
    validation.ruleSet
  );
  assert.equal(allowed.blocked, false);
  assert.equal(allowed.matchedRule, "");
});

test("Gateway MVP-0 rejects malformed user-defined rule sets", () => {
  assert.equal(
    validateAiExecutionGatewayMvp0UserDefinedRuleSet({
      schemaVersion: 2,
      ruleSetId: "owner-rules",
      blockedCommandSubstrings: [],
    }).error,
    "UNSUPPORTED_SCHEMA_VERSION"
  );

  assert.equal(
    validateAiExecutionGatewayMvp0UserDefinedRuleSet({
      schemaVersion: 1,
      ruleSetId: "owner-rules",
      blockedCommandSubstrings: [""],
    }).error,
    "INVALID_BLOCKED_RULE"
  );
});

test("Gateway MVP-0 user-defined rules cannot weaken built-in workflow drift", () => {
  const validation = validateAiExecutionGatewayMvp0UserDefinedRuleSet({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: [],
  });

  assert.ok(validation.ruleSet);
  assert.equal(
    evaluateAiExecutionGatewayMvp0UserDefinedRules("Get-Content package.json", validation.ruleSet).blocked,
    false
  );
  assert.equal(detectAiExecutionGatewayMvp0WorkflowDrift("vsce package").blocked, true);
});

test("Gateway MVP-0 helper builds user-defined rule blocked receipt", () => {
  const lines = buildAiExecutionGatewayMvp0UserDefinedRuleBlockedReceiptLines({
    envelopeSource: "ai_connector",
    envelopeIntent: "propose_terminal_command",
    ruleSetId: "owner-rules",
    matchedRule: "Remove-Item",
    sanitizedCommandPreview: "Remove-Item ./protected-file",
  });

  assert.deepEqual(lines, [
    "=== AEGIS AI EXECUTION GATEWAY MVP-0 ===",
    "AI_ACTION_ENVELOPE_CONTRACT_MVP0=True",
    "AI_GATEWAY_DECISION_RECEIPT_MVP0=True",
    "ENVELOPE_VALID=True",
    "ENVELOPE_SOURCE=ai_connector",
    "ENVELOPE_INTENT=propose_terminal_command",
    "USER_DEFINED_RULE_GATE_ENFORCED=True",
    "USER_DEFINED_RULE_BLOCKED=True",
    "USER_DEFINED_RULE_SET_ID=owner-rules",
    "USER_DEFINED_RULE_MATCH=Remove-Item",
    "EXECUTION_NOT_PERFORMED=True",
    "AUTO_EXECUTE_DISABLED=True",
    "GATEWAY_HANDOFF_BLOCKED=True",
    "SANITIZED_COMMAND_PREVIEW=Remove-Item ./protected-file",
  ]);
});

test("Gateway MVP-0 command registration is exposed through package and extension exactly once", () => {
  const packageJson = readFileSync(resolve(process.cwd(), "package.json"), "utf8");
  const extensionSource = readFileSync(resolve(process.cwd(), "src", "extension.ts"), "utf8");

  const countInPackage = (needle: string) => packageJson.split(needle).length - 1;
  const countInExtension = (needle: string) => extensionSource.split(needle).length - 1;

  assert.equal(countInPackage('"onCommand:aegis.aegisExecutionGatewayMvp0"'), 1);
  assert.equal(countInPackage('"command":  "aegis.aegisExecutionGatewayMvp0"'), 1);
  assert.equal(countInPackage('"title":  "Aegis: AI Execution Gateway MVP-0"'), 1);
  assert.equal(countInExtension('registerCommand("aegis.aegisExecutionGatewayMvp0"'), 1);
  assert.equal(countInExtension("await handleAegisExecutionGatewayMvp0("), 1);
});
test("Gateway MVP-0 extension delegates final reviewed-only receipt to helper", () => {
  const extensionSource = readFileSync(resolve(process.cwd(), "src", "extension.ts"), "utf8");
  const start = extensionSource.indexOf("const out = buildAiExecutionGatewayMvp0FinalReviewedOnlyReceiptLines({");
  const end = extensionSource.indexOf("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed.");
  assert.notEqual(start, -1);
  assert.ok(end > start);
  const block = extensionSource.slice(start, end);

  for (const marker of [
    "envelopeSource,",
    "envelopeIntent,",
    "envelopeActionId,",
    "envelopeCapabilityId,",
    "gateResult,",
    "sanitizedCommandPreview:",
    "gatewayHandoffBlocked:",
    "runtimeControllerReviewConnected:",
    "runtimeControllerAvailable:",
    "runtimeControllerClipboardSummary:",
    "runtimeSessionId:",
    "runtimeSessionPhase:",
  ]) {
    assert.ok(block.includes(marker), marker);
  }

  for (const removed of [
    "skV31DiagnosticClipboardSummary",
    "diagnosticInputBuilderSideEffectFree",
    "diagnosticInputBuilderRuntimeEnforced",
    "diagnosticNoncePlaceholderOnly",
    "realKernelTransaction",
    "diagnosticOutputHelperSideEffectFree",
    "diagnosticOutputHelperRuntimeEnforced",
  ]) {
    assert.ok(!block.includes(removed), removed);
  }
});

test("Gateway MVP-0 helper builds final reviewed-only receipt key contract", () => {
  const gateResult = evaluateAiExecutionGatewayMvp0ActionQuality("Get-Content package.json");
  const receipt = buildAiExecutionGatewayMvp0FinalReviewedOnlyReceiptLines({
    envelopeSource: "ai_connector",
    envelopeIntent: "propose_terminal_command",
    envelopeActionId: "ACTION_ID",
    envelopeCapabilityId: "CAPABILITY_ID",
    gateResult,
    sanitizedCommandPreview: "Get-Content package.json",
    gatewayHandoffBlocked: false,
  });

  for (const requiredLine of [
    "AI_GATEWAY_DECISION_RECEIPT_MVP0=True",
    "ENVELOPE_VALID=True",
    "SURFACE_DECISION=REVIEWED_ONLY_NO_EXECUTION",
    "AI_WORKFLOW_DRIFT_BLOCKED=False",
    "GIT_DEPENDENT_WORKFLOW_BLOCKED=False",
    "ACTION_QUALITY_GATE_NEXT_SAFE_STEP=",
    "EXECUTION_NOT_PERFORMED=True",
    "AUTO_EXECUTE_DISABLED=True",
    "REVIEW_RUNTIME_CONNECTED=False",
    "EXECUTION_RUNTIME_CONNECTED=False",
    "RAW_PROPOSED_ACTION_FULL_OUTPUT_DISABLED=True",
    "GATEWAY_HANDOFF_BLOCKED=False",
  ]) {
    assert.ok(receipt.includes(requiredLine), requiredLine);
  }
});

test("AI Gateway MVP-0 production receipt ignores deprecated diagnostic inputs", () => {
  const gateResult = evaluateAiExecutionGatewayMvp0ActionQuality("Get-Content package.json");
  const receipt = buildAiExecutionGatewayMvp0FinalReviewedOnlyReceiptLines({
    envelopeSource: "ai_connector",
    envelopeIntent: "propose_terminal_command",
    envelopeActionId: "ACTION_ID",
    envelopeCapabilityId: "CAPABILITY_ID",
    gateResult,
    skV31DiagnosticClipboardSummary: "FORBIDDEN_DIAGNOSTIC_SENTINEL",
    diagnosticInputBuilderSideEffectFree: true,
    diagnosticInputBuilderRuntimeEnforced: true,
    diagnosticNoncePlaceholderOnly: true,
    realKernelTransaction: false,
    diagnosticOutputHelperSideEffectFree: true,
    diagnosticOutputHelperRuntimeEnforced: true,
    sanitizedCommandPreview: "Get-Content package.json",
    gatewayHandoffBlocked: false,
  });

  const text = receipt.join("\n");
  assert.doesNotMatch(text, /FORBIDDEN_DIAGNOSTIC_SENTINEL/);
  assert.doesNotMatch(text, /DIAGNOSTIC_OUTPUT_ONLY/);
  assert.match(text, /REVIEW_RUNTIME_CONNECTED=False/);
  assert.match(text, /EXECUTION_RUNTIME_CONNECTED=False/);
});

test("Gateway MVP-0 helper builds blocked receipt key contracts", () => {
  const invalidEnvelopeReceipt = buildAiExecutionGatewayMvp0InvalidEnvelopeReceiptLines({
    envelopeError: "ENVELOPE_PARSE_FAILED"
  });

  for (const requiredLine of [
    "AI_GATEWAY_DECISION_RECEIPT_MVP0=True",
    "ENVELOPE_VALID=False",
    "ENVELOPE_ERROR=ENVELOPE_PARSE_FAILED",
    "WORKFLOW_DRIFT_BLOCKED=False",
    "GIT_DEPENDENT_WORKFLOW_BLOCKED=False",
    "GATEWAY_HANDOFF_BLOCKED=True"
  ]) {
    assert.equal(invalidEnvelopeReceipt.includes(requiredLine), true, requiredLine);
  }

  const invalidBootstrapReceipt = buildAiExecutionGatewayMvp0InvalidBootstrapCapsuleReceiptLines({
    bootstrapCapsuleError: "BOOTSTRAP_CAPSULE_INVALID_JSON",
    envelopeSource: "ai_connector",
    envelopeIntent: "propose_terminal_command"
  });

  for (const requiredLine of [
    "BOOTSTRAP_CAPSULE_ENFORCED=True",
    "BOOTSTRAP_CAPSULE_VALID=False",
    "BOOTSTRAP_CAPSULE_ERROR=BOOTSTRAP_CAPSULE_INVALID_JSON",
    "ENVELOPE_SOURCE=ai_connector",
    "ENVELOPE_INTENT=propose_terminal_command",
    "GATEWAY_HANDOFF_BLOCKED=True"
  ]) {
    assert.equal(invalidBootstrapReceipt.includes(requiredLine), true, requiredLine);
  }

  const noSurfaceReceipt = buildAiExecutionGatewayMvp0NoAuthorizedSurfaceReceiptLines({
    envelopeSource: "ai_connector",
    envelopeIntent: "propose_terminal_command",
    envelopeActionId: "ACTION_ID",
    envelopeCapabilityId: "CAPABILITY_ID"
  });

  for (const requiredLine of [
    "AUTHORIZED_SURFACE_GATE_ENFORCED=True",
    "AUTHORIZED_SURFACE_EXISTS=False",
    "SURFACE_DECISION=BLOCKED_NO_AUTHORIZED_SURFACE",
    "USER_APPROVAL_OVERRIDES=False",
    "ENVELOPE_ACTION_ID=ACTION_ID",
    "ENVELOPE_CAPABILITY_ID=CAPABILITY_ID",
    "GATEWAY_HANDOFF_BLOCKED=True"
  ]) {
    assert.equal(noSurfaceReceipt.includes(requiredLine), true, requiredLine);
  }

  const driftReceipt = buildAiExecutionGatewayMvp0WorkflowDriftBlockedReceiptLines({
    envelopeSource: "ai_connector",
    envelopeIntent: "propose_terminal_command",
    workflowDriftPattern: "FINAL_OR_PACKAGE_COMMAND",
    sanitizedCommandPreview: "npm run package"
  });

  for (const requiredLine of [
    "AI_WORKFLOW_DRIFT_BLOCKED=True",
    "GIT_DEPENDENT_WORKFLOW_BLOCKED=True",
    "WORKFLOW_DRIFT_PATTERN=FINAL_OR_PACKAGE_COMMAND",
    "SANITIZED_COMMAND_PREVIEW=npm run package",
    "GATEWAY_HANDOFF_BLOCKED=True"
  ]) {
    assert.equal(driftReceipt.includes(requiredLine), true, requiredLine);
  }
});

test("Gateway MVP-0 extension delegates blocked receipt outputs to helpers", () => {
  const extensionSource = readFileSync(resolve(process.cwd(), "src", "extension.ts"), "utf8");

  for (const helperName of [
    "buildAiExecutionGatewayMvp0InvalidEnvelopeReceiptLines",
    "buildAiExecutionGatewayMvp0InvalidBootstrapCapsuleReceiptLines",
    "buildAiExecutionGatewayMvp0NoAuthorizedSurfaceReceiptLines",
    "buildAiExecutionGatewayMvp0WorkflowDriftBlockedReceiptLines",
    "buildAiExecutionGatewayMvp0InvalidUserDefinedRuleSetReceiptLines",
    "buildAiExecutionGatewayMvp0UserDefinedRuleBlockedReceiptLines"
  ]) {
    assert.equal(extensionSource.includes(helperName + ","), true, helperName + " import");
    assert.equal(extensionSource.includes("const out = " + helperName + "({"), true, helperName + " call");
  }

  assert.equal(extensionSource.includes("const out = ["), false);
  const clipboardWriteCount = extensionSource.match(/clipboard\.writeText\(out\)/g)?.length ?? 0;
  assert.equal(clipboardWriteCount, 7);
});

test("Gateway MVP-0 policy keeps receipt header literals deduplicated", () => {
  const policySource = readFileSync(resolve(process.cwd(), "src", "aiExecutionGatewayMvp0Policy.ts"), "utf8");

  const count = (needle: string): number => policySource.split(needle).length - 1;

  assert.equal(count("function buildAiExecutionGatewayMvp0ReceiptHeaderLines"), 1);
  assert.equal(count("=== AEGIS AI EXECUTION GATEWAY MVP-0 ==="), 1);
  assert.equal(count("AI_ACTION_ENVELOPE_CONTRACT_MVP0=True"), 1);
  assert.equal(count("AI_GATEWAY_DECISION_RECEIPT_MVP0=True"), 1);
  assert.equal(count("AI_CONNECTED_EXECUTION_INTERCEPTION_MVP0=True"), 1);
  assert.equal(count("...buildAiExecutionGatewayMvp0ReceiptHeaderLines({ connectedExecutionInterception: true }),"), 1);
  assert.equal(count("...buildAiExecutionGatewayMvp0ReceiptHeaderLines(),"), 6);
});

test("Gateway MVP-0 policy keeps receipt footer literals deduplicated", () => {
  const policySource = readFileSync(resolve(process.cwd(), "src", "aiExecutionGatewayMvp0Policy.ts"), "utf8");

  const count = (needle: string): number => policySource.split(needle).length - 1;

  assert.equal(count("function buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines"), 1);
  assert.equal(count("EXECUTION_NOT_PERFORMED=True"), 1);
  assert.equal(count("AUTO_EXECUTE_DISABLED=True"), 1);
  assert.equal(count("GATEWAY_HANDOFF_BLOCKED=True"), 1);
  assert.equal(count("...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines(),"), 1);
  assert.equal(count("...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines({ gatewayHandoffBlocked: true })"), 6);
});

test("Gateway MVP-0 policy keeps receipt key literals deduplicated", () => {
  const policySource = readFileSync(resolve(process.cwd(), "src", "aiExecutionGatewayMvp0Policy.ts"), "utf8");

  const count = (needle: string): number => policySource.split(needle).length - 1;

  assert.equal(count("function formatAiExecutionGatewayMvp0ReceiptBoolean"), 1);
  assert.equal(count("function buildAiExecutionGatewayMvp0EnvelopeSourceIntentReceiptLines"), 1);
  assert.equal(count("function buildAiExecutionGatewayMvp0EnvelopeActionCapabilityReceiptLines"), 1);
  assert.equal(count("function buildAiExecutionGatewayMvp0WorkflowBlockStatusReceiptLines"), 1);
  assert.equal(count("function buildAiExecutionGatewayMvp0SanitizedCommandPreviewReceiptLines"), 1);

  assert.equal(count("...buildAiExecutionGatewayMvp0EnvelopeSourceIntentReceiptLines(input),"), 6);
  assert.equal(count("...buildAiExecutionGatewayMvp0EnvelopeActionCapabilityReceiptLines(input),"), 2);
  assert.equal(count("...buildAiExecutionGatewayMvp0WorkflowBlockStatusReceiptLines("), 3);
  assert.equal(count("...buildAiExecutionGatewayMvp0SanitizedCommandPreviewReceiptLines("), 4);

  assert.equal(count("ENVELOPE_SOURCE="), 1);
  assert.equal(count("ENVELOPE_INTENT="), 1);
  assert.equal(count("ENVELOPE_ACTION_ID="), 1);
  assert.equal(count("ENVELOPE_CAPABILITY_ID="), 1);
  assert.equal(count("AI_WORKFLOW_DRIFT_BLOCKED="), 1);
  assert.equal(count("GIT_DEPENDENT_WORKFLOW_BLOCKED="), 1);
  assert.equal(count("SANITIZED_COMMAND_PREVIEW="), 1);
});

test("Gateway MVP-0 helper exposes runtime controller review receipt without execution authority", () => {
  const gateResult = evaluateAiExecutionGatewayMvp0ActionQuality("Get-Content package.json");
  const receipt = buildAiExecutionGatewayMvp0FinalReviewedOnlyReceiptLines({
    envelopeSource: "ai_connector",
    envelopeIntent: "propose_terminal_command",
    envelopeActionId: "ACTION_ID",
    envelopeCapabilityId: "CAPABILITY_ID",
    gateResult,
    sanitizedCommandPreview: "Get-Content package.json",
    gatewayHandoffBlocked: false,
    runtimeControllerReviewConnected: true,
    runtimeControllerAvailable: true,
    runtimeControllerClipboardSummary: "RUNTIME_REVIEW_SENTINEL=True",
    runtimeSessionId: "SESSION_ID",
    runtimeSessionPhase: "WARN_PENDING",
  });

  const text = receipt.join("\n");
  for (const marker of [
    "COMMAND_DELEGATION_CONNECTED=True",
    "RUNTIME_CONTROLLER_AVAILABLE=True",
    "RUNTIME_REVIEW_SENTINEL=True",
    "SESSION_ID=SESSION_ID",
    "SESSION_PHASE=WARN_PENDING",
    "REVIEW_RUNTIME_CONNECTED=True",
    "EXECUTION_RUNTIME_CONNECTED=False",
    "AUTOMATIC_EXECUTION_ALLOWED=False",
    "EXECUTION_AUTHORITY_GRANTED=False",
  ]) {
    assert.match(text,new RegExp(marker));
  }
  assert.doesNotMatch(text,/SAFETY_KERNEL_V31_DIAGNOSTIC/);
});

test("Gateway MVP-0 rejects handoff fields in permanent user rules", () => {
  const result = validateAiExecutionGatewayMvp0UserDefinedRuleSet({
    schemaVersion: 1,
    ruleSetId: "owner-rules",
    blockedCommandSubstrings: [],
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
  });
  assert.equal(result.valid, false);
  assert.equal(result.error, "UNKNOWN_RULE_SET_FIELD");
});

test("Gateway MVP-0 rejects permanent rule fields in a handoff capsule", () => {
  const result = validateAiExecutionGatewayMvp0BootstrapCapsule({
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    firstCommandHash: "test-command-hash",
    knownPreconditions: [],
    forbiddenFirstActions: [],
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    approvalNonceRequired: true,
    receiptRequired: true,
    blockedCommandSubstrings: ["git reset"],
  });
  assert.equal(result.valid, false);
  assert.equal(result.error, "BOOTSTRAP_CAPSULE_UNKNOWN_FIELD");
});


test("Gateway MVP-0 rejects externally supplied authority fields", () => {
  for (const field of [
    "approvalNonce",
    "policyVersion",
    "rulesetVersion",
    "capabilityManifestVersion",
    "workspaceId",
    "sessionId",
    "commandTemplateHash",
  ]) {
    const result = parseAiExecutionGatewayMvp0Envelope(
      JSON.stringify({
        source: "ai_connector",
        intent: "propose_terminal_command",
        actionId:
          "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
        capabilityId: "ai_gateway_review_only",
        proposedCommand: "Get-Content package.json",
        [field]: "external-authority-must-not-be-trusted",
      })
    );
    assert.equal(result.envelopeValid, false);
    assert.equal(
      result.envelopeError,
      "EXTERNAL_AUTHORITY_FIELD_FORBIDDEN"
    );
  }
});

test("Gateway MVP-0 binds canonical proposal authority locally without a nonce", () => {
  const parsed = parseAiExecutionGatewayMvp0Envelope(
    JSON.stringify({
      source: "ai_connector",
      intent: "propose_terminal_command",
      actionId:
        "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
      capabilityId: "ai_gateway_review_only",
      targetPath: "package.json",
      proposedCommand: "Get-Content package.json",
    })
  );

  const proposal =
    buildAiExecutionGatewayMvp0CanonicalProposal(
      parsed,
      {
        localActionId: "aegis-action-" + "c".repeat(64),
        workspaceId: "sha256:" + "a".repeat(64),
        policyVersion:
          SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
            .policy_version,
        rulesetVersion: "bundled-local-ruleset-v1",
        capabilityManifestVersion:
          SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
            .manifest_version,
        sessionId: null,
      },
      "sha256:" + "b".repeat(64)
    );

  assert.equal(
    proposal.action_id,
    "aegis-action-" + "c".repeat(64)
  );
  assert.equal(
    proposal.external_action_id,
    "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY"
  );

  assert.equal(
    proposal.capability_id,
    "ai_gateway_review_only"
  );
  assert.deepEqual(
    proposal.declared_effects,
    ["review_output_only"]
  );
  assert.deepEqual(proposal.target_paths, ["package.json"]);
  assert.equal(proposal.approval_nonce_supplied, false);
  assert.equal(proposal.execution_authority_granted, false);
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      proposal,
      "approval_nonce"
    ),
    false
  );
});
test("Gateway MVP-0 effect preflight preserves canonical review-only ALLOW", () => {
  const gateResult =
    evaluateAiExecutionGatewayMvp0ActionQuality(
      "Get-Content package.json"
    );
  const result =
    enforceAiExecutionGatewayMvp0EffectPreflight(
      {
        source: "ai_connector",
        declared_effects: ["review_output_only"],
      },
      gateResult
    );

  assert.equal(result, gateResult);
  assert.equal(result.status, "ALLOW");
});

test("Gateway MVP-0 effect preflight blocks ALLOW regression on declaration or detected-effect mismatch", () => {
  const gateResult =
    evaluateAiExecutionGatewayMvp0ActionQuality(
      "Get-Content package.json"
    );

  const declarationMismatch =
    enforceAiExecutionGatewayMvp0EffectPreflight(
      {
        source: "ai_connector",
        declared_effects: ["unexpected_effect"],
      },
      gateResult
    );

  const detectedEffectMismatch =
    enforceAiExecutionGatewayMvp0EffectPreflight(
      {
        source: "ai_connector",
        declared_effects: ["review_output_only"],
      },
      {
        ...gateResult,
        detectedEffects: [{
          level: "SYNTACTIC_LEVEL_1",
          kind: "REMOTE_SCRIPT_EXECUTION",
          confidence: "HIGH",
          sourceRuleId: "TEST_REGRESSION",
          description: "Synthetic unsafe ALLOW regression.",
        }],
      }
    );

  for (const result of [
    declarationMismatch,
    detectedEffectMismatch,
  ]) {
    assert.equal(result.status, "BLOCK");
    assert.equal(
      result.internalRuleId,
      "DECLARED_DETECTED_EFFECT_MISMATCH"
    );
    assert.ok(result.nextSafeStep);
  }
});

function serverRulesetResolution(
  overrides: Partial<ResolveServerRulesetFallbackResult> = {}
): ResolveServerRulesetFallbackResult {
  return {
    accepted: true,
    source: "CURRENT",
    reason: "fixture",
    freshUntilEpochMs: null,
    hardUntilEpochMs: null,
    rules: [
      {
        ruleId: "server-rule",
        category: "catastrophic",
        pattern: "blocked-command",
      },
    ],
    currentDiagnostic: "CURRENT_FRESH",
    lkgDiagnostic: "LKG_ABSENT",
    ...overrides,
  };
}

test("Gateway MVP-0 server ruleset blocks a matching rule", () => {
  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "prefix blocked-command suffix",
      serverRulesetResolution()
    );

  assert.equal(result.blocked, true);
  assert.equal(result.accepted, true);
  assert.equal(result.source, "CURRENT");
  assert.equal(result.matchedRuleId, "server-rule");
  assert.equal(result.matchedCategory, "catastrophic");
  assert.equal(result.reason, "SERVER_RULESET_MATCHED");
});

test("Gateway MVP-0 server ruleset allows only when no rule matches", () => {
  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "Get-Content package.json",
      serverRulesetResolution()
    );

  assert.equal(result.blocked, false);
  assert.equal(result.accepted, true);
  assert.equal(result.matchedRuleId, "");
  assert.equal(result.matchedCategory, null);
  assert.equal(result.reason, "SERVER_RULESET_NO_MATCH");
});

test("Gateway MVP-0 server ruleset rejects an unaccepted resolution", () => {
  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "Get-Content package.json",
      serverRulesetResolution({
        accepted: false,
        source: null,
        rules: [],
      })
    );

  assert.equal(result.blocked, true);
  assert.equal(result.accepted, false);
  assert.equal(
    result.reason,
    "SERVER_RULESET_RESOLUTION_REJECTED"
  );
});

test("Gateway MVP-0 server ruleset rejects a null resolution source", () => {
  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "Get-Content package.json",
      serverRulesetResolution({
        source: null,
      })
    );

  assert.equal(result.blocked, true);
  assert.equal(result.accepted, false);
  assert.equal(
    result.reason,
    "SERVER_RULESET_SOURCE_MISSING"
  );
});

test("Gateway MVP-0 server ruleset rejects accepted empty rules", () => {
  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "Get-Content package.json",
      serverRulesetResolution({
        rules: [],
      })
    );

  assert.equal(result.blocked, true);
  assert.equal(result.accepted, false);
  assert.equal(
    result.reason,
    "SERVER_RULESET_RULES_EMPTY"
  );
});

test("Gateway MVP-0 server ruleset rejects oversized UTF-8 input", () => {
  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "a".repeat(16385),
      serverRulesetResolution()
    );

  assert.equal(result.blocked, true);
  assert.equal(result.accepted, false);
  assert.equal(
    result.reason,
    "SERVER_RULESET_INPUT_TOO_LARGE"
  );
});

test("Gateway MVP-0 server ruleset rejects an unsafe pattern", () => {
  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "secret",
      serverRulesetResolution({
        rules: [
          {
            ruleId: "unsafe-rule",
            category: "catastrophic",
            pattern: ".*secret",
          },
        ],
      })
    );

  assert.equal(result.blocked, true);
  assert.equal(result.accepted, false);
  assert.equal(result.matchedRuleId, "unsafe-rule");
  assert.equal(
    result.reason,
    "SERVER_RULESET_PATTERN_REJECTED"
  );
});

test("Gateway MVP-0 server ruleset fails closed on match operation budget exhaustion", () => {
  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "zzzzzzzzzzblocked-command",
      serverRulesetResolution(),
      {
        perRuleOperationBudget: 0,
      }
    );

  assert.equal(result.blocked, true);
  assert.equal(result.accepted, false);
  assert.equal(
    result.reason,
    "SERVER_RULESET_MATCH_FAILED"
  );
});

test("Gateway MVP-0 server ruleset enforces the 250ms action fuse", () => {
  const times = [
    1000,
    1250,
  ];

  let index = 0;

  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "blocked-command",
      serverRulesetResolution(),
      {
        nowEpochMs: () => {
          const selected =
            times[
              Math.min(
                index,
                times.length - 1
              )
            ];

          index += 1;
          return selected;
        },
      }
    );

  assert.equal(result.blocked, true);
  assert.equal(result.accepted, false);
  assert.equal(
    result.reason,
    "SERVER_RULESET_ACTION_FUSE_EXCEEDED"
  );
});

test("Gateway MVP-0 server ruleset selects the deterministic first matching rule", () => {
  const result =
    evaluateAiExecutionGatewayMvp0ServerRuleset(
      "danger",
      serverRulesetResolution({
        rules: [
          {
            ruleId: "z-rule",
            category: "catastrophic",
            pattern: "danger",
          },
          {
            ruleId: "a-rule",
            category: "destructive",
            pattern: "danger",
          },
        ],
      })
    );

  assert.equal(result.blocked, true);
  assert.equal(result.matchedRuleId, "a-rule");
  assert.equal(result.matchedCategory, "destructive");
});

test("Gateway MVP-0 server ruleset does not mutate the resolution or rule array", () => {
  const rules = Object.freeze([
    Object.freeze({
      ruleId: "z-rule",
      category: "catastrophic" as const,
      pattern: "z-pattern",
    }),
    Object.freeze({
      ruleId: "a-rule",
      category: "catastrophic" as const,
      pattern: "a-pattern",
    }),
  ]);

  const resolution =
    Object.freeze(
      serverRulesetResolution({
        rules,
      })
    );

  const before =
    JSON.stringify(resolution);

  evaluateAiExecutionGatewayMvp0ServerRuleset(
    "no-match",
    resolution
  );

  assert.equal(
    JSON.stringify(resolution),
    before
  );

  assert.deepEqual(
    rules.map(rule => rule.ruleId),
    [
      "z-rule",
      "a-rule",
    ]
  );
});

test("Gateway MVP-0 server ruleset receipt omits raw command and pattern and uses shared footer", () => {
  const rawCommand =
    "super-secret-command";

  const rawPattern =
    "super-secret-pattern";

  const lines =
    buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines({
      resolutionAccepted: true,
      resolutionSource: "CURRENT",
      matchedRuleId: "rule-a",
      matchedCategory: "catastrophic",
      reason: "SERVER_RULESET_MATCHED",
    });

  const joined =
    lines.join("\n");

  assert.equal(
    joined.includes(rawCommand),
    false
  );

  assert.equal(
    joined.includes(rawPattern),
    false
  );

  assert.deepEqual(
    lines,
    [
      "SERVER_RULESET_GATE_ENFORCED=True",
      "SERVER_RULESET_RESOLUTION_ACCEPTED=True",
      "SERVER_RULESET_RESOLUTION_SOURCE=CURRENT",
      "SERVER_RULESET_MATCHED_RULE_ID=rule-a",
      "SERVER_RULESET_MATCHED_CATEGORY=catastrophic",
      "SERVER_RULESET_REASON=SERVER_RULESET_MATCHED",
      "EXECUTION_NOT_PERFORMED=True",
      "AUTO_EXECUTE_DISABLED=True",
      "GATEWAY_HANDOFF_BLOCKED=True",
    ]
  );

  const implementationText =
    evaluateAiExecutionGatewayMvp0ServerRuleset.toString();

  assert.equal(
    implementationText.includes("RegExp"),
    false
  );

  assert.equal(
    implementationText.includes("eval("),
    false
  );
});

// G00B_COMMAND_INTERPRETATION_NORMALIZATION_TESTS_BEGIN
const g00bWrapperCases = Object.freeze([
  { caseId: "WRAP-001", input: "sh -c 'rm -rf /*'", expectedRuleIdIncludes: ".rm." },
  { caseId: "WRAP-002", input: 'bash -c "rm -rf /*"', expectedRuleIdIncludes: ".rm." },
  { caseId: "WRAP-003", input: "zsh -c 'sudo rm -rf /*'", expectedRuleIdIncludes: ".sudo-rm." },
  { caseId: "WRAP-004", input: "/bin/sh -c 'find / -delete'", expectedRuleIdIncludes: ".find." },
  { caseId: "WRAP-005", input: "env sh -c 'rm -rf ${HOME}'", expectedRuleIdIncludes: ".rm." },
  { caseId: "WRAP-006", input: "sudo sh -c 'dd if=/dev/zero of=/dev/disk0'", expectedRuleIdIncludes: ".dd." },
  { caseId: "WRAP-007", input: 'pwsh -NoProfile -Command "Remove-Item C:\\* -Recurse -Force"', expectedRuleIdIncludes: ".powershell." },
  { caseId: "WRAP-008", input: 'powershell.exe -NoProfile -Command "Clear-Disk -Number 0 -RemoveData"', expectedRuleIdIncludes: ".powershell." },
  { caseId: "WRAP-009", input: "cmd.exe /c rd /s /q C:\\", expectedRuleIdIncludes: ".cmd." },
  { caseId: "WRAP-010", input: "cmd /c del /f /s /q C:\\*", expectedRuleIdIncludes: ".cmd." },
  { caseId: "WRAP-011", input: "C:\\Windows\\System32\\cmd.exe /c format C: /y", expectedRuleIdIncludes: ".cmd." },
  { caseId: "WRAP-012", input: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command Remove-Item C:\\* -Recurse -Force", expectedRuleIdIncludes: ".powershell." },
  { caseId: "WRAP-013", input: "/usr/bin/find / -delete", expectedRuleIdIncludes: ".find." },
  { caseId: "WRAP-014", input: "/bin/dd if=/dev/zero of=/dev/disk0", expectedRuleIdIncludes: ".dd." },
  { caseId: "WRAP-015", input: "/usr/sbin/diskutil zeroDisk /dev/disk0", expectedRuleIdIncludes: ".diskutil." },
] as const);

const g00bNegativeCases = Object.freeze([
  "rm -rf ./build",
  "/bin/rm -rf /tmp/aegis-g00a",
  "sudo rm -rf /var/tmp/aegis-g00a",
  "find ./workspace -delete",
  "dd if=/dev/zero of=./disk.img",
  "diskutil list",
  "Remove-Item .\\dist -Recurse -Force",
  "Clear-Disk -Number 1 -RemoveData",
  "rd /s /q C:\\temp",
  "del /f /s /q C:\\temp\\*",
  "format D: /y",
  "Get-Content package.json",
  "echo rm -rf /*",
  'Write-Output "Remove-Item C:\\* -Recurse -Force"',
  "sh -c 'echo aegis-safe'",
] as const);

function g00bBundledFallbackResolution(): ResolveServerRulesetFallbackResult {
  const parsed = JSON.parse(
    readFileSync(
      join(
        process.cwd(),
        "resources",
        "server-ruleset",
        "bundled-catastrophic-fallback.json"
      ),
      "utf8"
    )
  ) as {
    readonly rules: ReadonlyArray<{
      readonly ruleId: string;
      readonly category: "catastrophic";
      readonly pattern: string;
    }>;
  };

  assert.equal(parsed.rules.length, 114);
  return serverRulesetResolution({ rules: parsed.rules });
}

test("Gateway MVP-0 server ruleset blocks all 15 frozen wrapper and absolute-path cases", () => {
  const resolution = g00bBundledFallbackResolution();

  for (const entry of g00bWrapperCases) {
    const result = evaluateAiExecutionGatewayMvp0ServerRuleset(
      entry.input,
      resolution
    );

    assert.equal(result.blocked, true, entry.caseId);
    assert.equal(result.accepted, true, entry.caseId);
    assert.equal(result.reason, "SERVER_RULESET_MATCHED", entry.caseId);
    assert.equal(result.matchedCategory, "catastrophic", entry.caseId);
    assert.equal(
      result.matchedRuleId.includes(entry.expectedRuleIdIncludes),
      true,
      entry.caseId + ":" + result.matchedRuleId
    );
  }
});

test("Gateway MVP-0 server ruleset keeps all 15 frozen negative controls unmatched", () => {
  const resolution = g00bBundledFallbackResolution();

  for (const input of g00bNegativeCases) {
    const result = evaluateAiExecutionGatewayMvp0ServerRuleset(
      input,
      resolution
    );

    assert.equal(result.blocked, false, input);
    assert.equal(result.accepted, true, input);
    assert.equal(result.reason, "SERVER_RULESET_NO_MATCH", input);
    assert.equal(result.matchedRuleId, "", input);
    assert.equal(result.matchedCategory, null, input);
  }
});

test("Gateway MVP-0 server ruleset fails closed on malformed recognized wrappers", () => {
  const resolution = g00bBundledFallbackResolution();

  for (const input of [
    "sh -c rm -rf /*",
    "bash -c 'unterminated",
    "pwsh -NoProfile -Command",
    "cmd.exe /c",
    "/usr/bin/find",
  ]) {
    const result = evaluateAiExecutionGatewayMvp0ServerRuleset(
      input,
      resolution
    );

    assert.equal(result.blocked, true, input);
    assert.equal(result.accepted, false, input);
    assert.equal(result.reason, "SERVER_RULESET_INPUT_INVALID", input);
  }
});
// G00B_COMMAND_INTERPRETATION_NORMALIZATION_TESTS_END
