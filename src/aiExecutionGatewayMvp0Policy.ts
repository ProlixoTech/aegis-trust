import type {
  ResolveServerRulesetFallbackResult,
  ServerRulesetResolutionSource,
} from "./serverRulesetFallbackResolution";

import type {
  ServerRulesetRuleCategory,
} from "./serverRulesetTrustProvider";

import {
  MAX_SERVER_RULESET_INPUT_BYTES,
  MAX_SERVER_RULESET_RULE_OPERATIONS,
  MAX_SERVER_RULESET_RULE_WALL_CLOCK_MS,
  compileServerRulesetSafeRegex,
  matchServerRulesetSafeRegex,
} from "./serverRulesetSafeRegex";
import { deriveServerRulesetCommandCandidates } from "./serverRulesetCommandNormalization";
import {
  ActionQualityResult,
  SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH,
  SafetyKernelV31ActionProposal,
} from "../packages/aegis-core";
import { evaluateActionQuality } from "../packages/aegis-core";

export interface AiExecutionGatewayMvp0Envelope {
  source?: unknown;
  intent?: unknown;
  actionId?: unknown;
  capabilityId?: unknown;
  proposedCommand?: unknown;
  command?: unknown;
  action?: unknown;
  targetPath?: unknown;
  riskContext?: unknown;
}

export interface AiExecutionGatewayMvp0EnvelopeParseResult {
  envelopeValid: boolean;
  envelopeError: string;
  envelopeSource: string;
  envelopeIntent: string;
  envelopeActionId: string;
  envelopeCapabilityId: string;
  envelopeTargetPath: string;
  proposed: string;
}

export interface AiExecutionGatewayMvp0WorkflowDriftResult {
  blocked: boolean;
  pattern: string;
}

export function parseAiExecutionGatewayMvp0Envelope(raw: string): AiExecutionGatewayMvp0EnvelopeParseResult {
  let envelopeSource = "";
  let envelopeIntent = "";
  let envelopeActionId = "";
  let envelopeCapabilityId = "";
  let envelopeTargetPath = "";

  try {
    const env = JSON.parse(raw) as AiExecutionGatewayMvp0Envelope;
    envelopeSource = typeof env.source === "string" ? env.source : "";
    envelopeIntent = typeof env.intent === "string" ? env.intent : "";
    envelopeActionId = typeof env.actionId === "string" ? env.actionId : "";
    envelopeCapabilityId = typeof env.capabilityId === "string" ? env.capabilityId : "";
    envelopeTargetPath = typeof env.targetPath === "string" ? env.targetPath : "";

    const forbiddenAuthorityFields = [
      "approvalNonce",
      "approval_nonce",
      "policyVersion",
      "policy_version",
      "rulesetVersion",
      "ruleset_version",
      "capabilityManifestVersion",
      "capability_manifest_version",
      "workspaceId",
      "workspace_id",
      "sessionId",
      "session_id",
      "commandTemplateHash",
      "command_template_hash",
    ];

    if (
      forbiddenAuthorityFields.some(field =>
        Object.prototype.hasOwnProperty.call(env, field)
      )
    ) {
      return {
        envelopeValid: false,
        envelopeError: "EXTERNAL_AUTHORITY_FIELD_FORBIDDEN",
        envelopeSource,
        envelopeIntent,
        envelopeActionId,
        envelopeCapabilityId,
        envelopeTargetPath,
        proposed: "",
      };
    }

    const candidate =
      typeof env.proposedCommand === "string" ? env.proposedCommand :
      typeof env.command === "string" ? env.command :
      typeof env.action === "string" ? env.action :
      "";

    if (envelopeSource !== "ai_connector") {
      return {
        envelopeValid: false,
        envelopeError: "INVALID_OR_MISSING_SOURCE",
        envelopeSource,
        envelopeIntent,
        envelopeActionId,
        envelopeCapabilityId,
        envelopeTargetPath,
        proposed: "",
      };
    }

    if (!candidate.trim()) {
      return {
        envelopeValid: false,
        envelopeError: "MISSING_PROPOSED_COMMAND",
        envelopeSource,
        envelopeIntent,
        envelopeActionId,
        envelopeCapabilityId,
        envelopeTargetPath,
        proposed: "",
      };
    }

    return {
      envelopeValid: true,
      envelopeError: "",
      envelopeSource,
      envelopeIntent,
      envelopeActionId,
      envelopeCapabilityId,
      envelopeTargetPath,
      proposed: candidate.trim(),
    };
  } catch {
    return {
      envelopeValid: false,
      envelopeError: "INVALID_JSON_ENVELOPE",
      envelopeSource,
      envelopeIntent,
      envelopeActionId,
      envelopeCapabilityId,
      envelopeTargetPath,
      proposed: "",
    };
  }
}

export interface AiExecutionGatewayMvp0BootstrapCapsuleValidationResult {
  readonly valid: boolean;
  readonly error: string;
}

export function validateAiExecutionGatewayMvp0BootstrapCapsule(
  value: unknown
): AiExecutionGatewayMvp0BootstrapCapsuleValidationResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { valid: false, error: "BOOTSTRAP_CAPSULE_NOT_OBJECT" };
  }

  const allowedKeys = new Set([
    "capsuleSchemaVersion",
    "capsuleKind",
    "firstRequiredAction",
    "firstCommandHash",
    "knownPreconditions",
    "forbiddenFirstActions",
    "capabilityManifestVersion",
    "policyVersion",
    "approvalNonceRequired",
    "receiptRequired",
  ]);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    return { valid: false, error: "BOOTSTRAP_CAPSULE_UNKNOWN_FIELD" };
  }

  const candidate = value as {
    capsuleSchemaVersion?: unknown; capsuleKind?: unknown; firstRequiredAction?: unknown;
    firstCommandHash?: unknown; knownPreconditions?: unknown; forbiddenFirstActions?: unknown;
    capabilityManifestVersion?: unknown; policyVersion?: unknown;
    approvalNonceRequired?: unknown; receiptRequired?: unknown;
  };
  const structurallyValid =
    candidate.capsuleSchemaVersion === "1.0.0" &&
    candidate.capsuleKind === "HANDOFF_RESUME" &&
    candidate.firstRequiredAction === "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1" &&
    typeof candidate.firstCommandHash === "string" &&
    candidate.firstCommandHash.trim().length > 0 &&
    Array.isArray(candidate.knownPreconditions) &&
    Array.isArray(candidate.forbiddenFirstActions) &&
    typeof candidate.capabilityManifestVersion === "string" &&
    candidate.capabilityManifestVersion.trim().length > 0 &&
    typeof candidate.policyVersion === "string" &&
    candidate.policyVersion.trim().length > 0 &&
    candidate.approvalNonceRequired === true &&
    candidate.receiptRequired === true;

  if (!structurallyValid) {
    return {
      valid: false,
      error: "BOOTSTRAP_CAPSULE_INCOMPLETE",
    };
  }

  if (
    candidate.capabilityManifestVersion !==
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
      .manifest_version
  ) {
    return {
      valid: false,
      error: "CAPABILITY_MANIFEST_VERSION_MISMATCH",
    };
  }

  if (
    candidate.policyVersion !==
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
      .policy_version
  ) {
    return {
      valid: false,
      error: "POLICY_VERSION_MISMATCH",
    };
  }

  return { valid: true, error: "" };
}

export interface AiExecutionGatewayMvp0UserDefinedRuleSet {
  schemaVersion: 1;
  ruleSetId: string;
  blockedCommandSubstrings: string[];
}

export interface AiExecutionGatewayMvp0UserDefinedRuleValidationResult {
  valid: boolean;
  error: string;
  ruleSet: AiExecutionGatewayMvp0UserDefinedRuleSet | null;
}

export interface AiExecutionGatewayMvp0UserDefinedRuleEvaluationResult {
  blocked: boolean;
  matchedRule: string;
  ruleSetId: string;
}

export function validateAiExecutionGatewayMvp0UserDefinedRuleSet(
  value: unknown
): AiExecutionGatewayMvp0UserDefinedRuleValidationResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { valid: false, error: "RULE_SET_NOT_OBJECT", ruleSet: null };
  }

  const allowedKeys = new Set(["schemaVersion", "ruleSetId", "blockedCommandSubstrings"]);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    return { valid: false, error: "UNKNOWN_RULE_SET_FIELD", ruleSet: null };
  }

  const candidate = value as {
    schemaVersion?: unknown;
    ruleSetId?: unknown;
    blockedCommandSubstrings?: unknown;
  };

  if (candidate.schemaVersion !== 1) {
    return { valid: false, error: "UNSUPPORTED_SCHEMA_VERSION", ruleSet: null };
  }

  if (typeof candidate.ruleSetId !== "string" || !candidate.ruleSetId.trim()) {
    return { valid: false, error: "INVALID_RULE_SET_ID", ruleSet: null };
  }

  if (!Array.isArray(candidate.blockedCommandSubstrings)) {
    return { valid: false, error: "BLOCKED_RULES_NOT_ARRAY", ruleSet: null };
  }

  if (candidate.blockedCommandSubstrings.length > 100) {
    return { valid: false, error: "TOO_MANY_BLOCKED_RULES", ruleSet: null };
  }

  const normalizedRules: string[] = [];
  for (const entry of candidate.blockedCommandSubstrings) {
    if (typeof entry !== "string") {
      return { valid: false, error: "BLOCKED_RULE_NOT_STRING", ruleSet: null };
    }

    const normalized = entry.trim();
    if (!normalized || normalized.length > 200) {
      return { valid: false, error: "INVALID_BLOCKED_RULE", ruleSet: null };
    }

    normalizedRules.push(normalized);
  }

  return {
    valid: true,
    error: "",
    ruleSet: {
      schemaVersion: 1,
      ruleSetId: candidate.ruleSetId.trim(),
      blockedCommandSubstrings: normalizedRules,
    },
  };
}

export function evaluateAiExecutionGatewayMvp0UserDefinedRules(
  proposed: string,
  ruleSet: AiExecutionGatewayMvp0UserDefinedRuleSet
): AiExecutionGatewayMvp0UserDefinedRuleEvaluationResult {
  const normalizedProposed = proposed.toLowerCase();
  const matchedRule = ruleSet.blockedCommandSubstrings.find(
    (rule) => normalizedProposed.includes(rule.toLowerCase())
  ) ?? "";

  return {
    blocked: matchedRule.length > 0,
    matchedRule,
    ruleSetId: ruleSet.ruleSetId,
  };
}

export interface AiExecutionGatewayMvp0LocalAuthorityBinding {
  localActionId: string;
  workspaceId: string;
  policyVersion: string;
  rulesetVersion: string;
  capabilityManifestVersion: string;
  sessionId: string | null;
}

export function buildAiExecutionGatewayMvp0CanonicalProposal(
  parsed: AiExecutionGatewayMvp0EnvelopeParseResult,
  authority: AiExecutionGatewayMvp0LocalAuthorityBinding,
  commandTemplateHash: string
): SafetyKernelV31ActionProposal {
  if (!parsed.envelopeValid) {
    throw new Error("INVALID_GATEWAY_PROPOSAL_SOURCE");
  }

  const manifestEntry =
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
      .trusted_capabilities
      .find(entry =>
        entry.capability_id === parsed.envelopeCapabilityId &&
        entry.action_kind === "ai_execution_gateway_review" &&
        entry.allowed_sources.includes("ai_connector") &&
        entry.handler_id === "aegis.aegisExecutionGatewayMvp0"
      );

  if (!manifestEntry) {
    throw new Error("CAPABILITY_MANIFEST_MISMATCH");
  }

  if (
    authority.capabilityManifestVersion !==
      SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
        .manifest_version ||
    authority.policyVersion !==
      SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
        .policy_version
  ) {
    throw new Error("LOCAL_AUTHORITY_VERSION_MISMATCH");
  }

  if (
    !/^aegis-action-[a-f0-9]{64}$/.test(authority.localActionId) ||
    !/^sha256:[a-f0-9]{64}$/.test(authority.workspaceId) ||
    !/^sha256:[a-f0-9]{64}$/.test(commandTemplateHash) ||
    !authority.rulesetVersion.trim()
  ) {
    throw new Error("INVALID_LOCAL_AUTHORITY_BINDING");
  }

  const target =
    parsed.envelopeTargetPath.trim() ||
    "unspecified-ai-gateway-mvp0-target";

  return {
    action_id: authority.localActionId,
    external_action_id: parsed.envelopeActionId.trim(),
    source: "ai_connector",
    capability_id: manifestEntry.capability_id,
    intent:
      parsed.envelopeIntent.trim() ||
      "ai_gateway_mvp0_runtime_controller_review",
    proposed_action: parsed.proposed,
    declared_effects: [manifestEntry.effect_scope],
    target_paths: [target],
    command_template_hash: commandTemplateHash,
    mutation_scope: {
      scope: manifestEntry.scope,
      target,
      protected_target:
        manifestEntry.scope === "protected_file",
    },
    policy_version: authority.policyVersion,
    ruleset_version: authority.rulesetVersion,
    capability_manifest_version:
      authority.capabilityManifestVersion,
    workspace_id: authority.workspaceId,
    session_id: authority.sessionId,
    approval_nonce_supplied: false,
    execution_authority_granted: false,
  };
}

export function resolveAiExecutionGatewayMvp0CapabilityId(): string {
  const matches =
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
      .trusted_capabilities
      .filter(entry =>
        entry.action_kind === "ai_execution_gateway_review" &&
        entry.allowed_sources.includes("ai_connector") &&
        entry.handler_id === "aegis.aegisExecutionGatewayMvp0"
      );

  return matches.length === 1
    ? matches[0].capability_id
    : "";
}

export function hasAuthorizedAiExecutionGatewayMvp0Surface(
  actionId: string,
  capabilityId: string
): boolean {
  const manifestCapabilityId =
    resolveAiExecutionGatewayMvp0CapabilityId();

  return (
    actionId ===
      "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY" &&
    manifestCapabilityId.length > 0 &&
    capabilityId === manifestCapabilityId
  );
}

const workflowDriftPatterns = [
  /\bgit\s+(apply|restore|checkout|reset|clean|commit|push|pull|merge|rebase)\b/i,
  /\b(Invoke-WebRequest|curl|wget)\b/i,
  /powershell\s+-ExecutionPolicy\b/i,
  /\.ps1\b/i,
  /\bvsce\s+package\b/i,
  /\b(code\s+--install-extension|npm\s+install|npm\s+i)\b/i,
  /\b(Product PASS|FINAL ZIP|upload-ready)\b/i,
  /\b(Compress-Archive|Expand-Archive)\b/i,
  /sandbox:\/mnt\/data/i,
  /\/mnt\/data\/[^\s]+/i,
  /\bdownload\s+link\b/i,
  /\bgenerated\s+artifact\b/i,
  /\bpython_user_visible\b/i,
  /\bimage_gen\b/i,
  /\btool\s+invocation\b/i,
  /\bsidecar\s+file\b/i,
  /\bcreated\s+(?:a\s+)?file\b/i,
];

export function detectAiExecutionGatewayMvp0WorkflowDrift(proposed: string): AiExecutionGatewayMvp0WorkflowDriftResult {
  const match = workflowDriftPatterns.find((pattern) => pattern.test(proposed));

  return {
    blocked: Boolean(match),
    pattern: match ? String(match) : "",
  };
}

export function evaluateAiExecutionGatewayMvp0ActionQuality(proposed: string): ActionQualityResult {
  return evaluateActionQuality(proposed, { source: "ai_connector" });
}

export const AI_EXECUTION_GATEWAY_MVP0_EFFECT_PREFLIGHT_INVARIANT = {
  REUSES_ACTION_QUALITY_SYNTAX_CLASSIFICATION: true,
  SECOND_RULE_ENGINE_CREATED: false,
  ALLOW_REQUIRES_RECOGNIZED_SYNTACTIC_EFFECTS: true,
  DECLARED_DETECTED_EFFECT_MATCH_REQUIRED: true,
  FAIL_CLOSED_ON_MISMATCH: true,
} as const;

const AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY_EFFECTS = new Set([
  "READ_ONLY_INSPECTION",
  "CLIPBOARD_WRITE",
]);

export function enforceAiExecutionGatewayMvp0EffectPreflight(
  proposal: Pick<
    SafetyKernelV31ActionProposal,
    "source" | "declared_effects"
  >,
  gateResult: ActionQualityResult
): ActionQualityResult {
  if (gateResult.status !== "ALLOW") {
    return gateResult;
  }

  const declarationMatches =
    proposal.source === "ai_connector" &&
    gateResult.source === "ai_connector" &&
    proposal.declared_effects.length === 1 &&
    proposal.declared_effects[0] === "review_output_only";

  const detectedEffectsMatch =
    gateResult.detectedEffects.length > 0 &&
    gateResult.detectedEffects.every(
      effect =>
        effect.level === "SYNTACTIC_LEVEL_1" &&
        AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY_EFFECTS.has(effect.kind)
    );

  if (declarationMatches && detectedEffectsMatch) {
    return gateResult;
  }

  return {
    ...gateResult,
    status: "BLOCK",
    userMessage:
      "Aegis blocked this action because its declared review-only boundary does not match the detected command effects.",
    reasons: [
      ...gateResult.reasons,
      "Canonical declared effects and syntactically detected effects do not match",
    ],
    nextSafeStep:
      "Use one recognized read-only review command whose detected effects remain inside review_output_only.",
    internalRuleId: "DECLARED_DETECTED_EFFECT_MISMATCH",
  };
}

function buildAiExecutionGatewayMvp0ReceiptHeaderLines(input: { readonly connectedExecutionInterception?: boolean } = {}): string[] {
  const lines = ["=== AEGIS AI EXECUTION GATEWAY MVP-0 ==="];

  if (input.connectedExecutionInterception) {
    lines.push("AI_CONNECTED_EXECUTION_INTERCEPTION_MVP0=True");
  }

  lines.push(
    "AI_ACTION_ENVELOPE_CONTRACT_MVP0=True",
    "AI_GATEWAY_DECISION_RECEIPT_MVP0=True"
  );

  return lines;
}
function buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines(input: { readonly gatewayHandoffBlocked?: boolean } = {}): string[] {
  const lines = [
    "EXECUTION_NOT_PERFORMED=True",
    "AUTO_EXECUTE_DISABLED=True"
  ];

  if (input.gatewayHandoffBlocked) {
    lines.push("GATEWAY_HANDOFF_BLOCKED=True");
  }

  return lines;
}
function formatAiExecutionGatewayMvp0ReceiptBoolean(value: boolean): string {
  return value ? "True" : "False";
}

function buildAiExecutionGatewayMvp0EnvelopeSourceIntentReceiptLines(input: { readonly envelopeSource: string; readonly envelopeIntent: string }): string[] {
  return [
    "ENVELOPE_SOURCE=" + input.envelopeSource,
    "ENVELOPE_INTENT=" + input.envelopeIntent
  ];
}

function buildAiExecutionGatewayMvp0EnvelopeActionCapabilityReceiptLines(input: { readonly envelopeActionId: string; readonly envelopeCapabilityId: string }): string[] {
  return [
    "ENVELOPE_ACTION_ID=" + input.envelopeActionId,
    "ENVELOPE_CAPABILITY_ID=" + input.envelopeCapabilityId
  ];
}

function buildAiExecutionGatewayMvp0WorkflowBlockStatusReceiptLines(input: { readonly aiWorkflowDriftBlocked?: boolean; readonly gitDependentWorkflowBlocked: boolean }): string[] {
  const lines: string[] = [];

  if (input.aiWorkflowDriftBlocked !== undefined) {
    lines.push("AI_WORKFLOW_DRIFT_BLOCKED=" + formatAiExecutionGatewayMvp0ReceiptBoolean(input.aiWorkflowDriftBlocked));
  }

  lines.push("GIT_DEPENDENT_WORKFLOW_BLOCKED=" + formatAiExecutionGatewayMvp0ReceiptBoolean(input.gitDependentWorkflowBlocked));

  return lines;
}

function buildAiExecutionGatewayMvp0SanitizedCommandPreviewReceiptLines(input: { readonly sanitizedCommandPreview?: string } = {}): string[] {
  return [
    "SANITIZED_COMMAND_PREVIEW=" + (input.sanitizedCommandPreview ?? "")
  ];
}
export interface AiExecutionGatewayMvp0FinalReviewedOnlyReceiptInput {
  envelopeSource: string;
  envelopeIntent: string;
  envelopeActionId: string;
  envelopeCapabilityId: string;
  gateResult: ActionQualityResult;
  /** @deprecated Diagnostic-only runtime wiring is disconnected. */
  skV31DiagnosticClipboardSummary?: string;
  /** @deprecated Diagnostic-only runtime wiring is disconnected. */
  diagnosticInputBuilderSideEffectFree?: boolean;
  /** @deprecated Diagnostic-only runtime wiring is disconnected. */
  diagnosticInputBuilderRuntimeEnforced?: boolean;
  /** @deprecated Diagnostic-only runtime wiring is disconnected. */
  diagnosticNoncePlaceholderOnly?: boolean;
  /** @deprecated Diagnostic-only runtime wiring is disconnected. */
  realKernelTransaction?: boolean;
  /** @deprecated Diagnostic-only runtime wiring is disconnected. */
  diagnosticOutputHelperSideEffectFree?: boolean;
  /** @deprecated Diagnostic-only runtime wiring is disconnected. */
  diagnosticOutputHelperRuntimeEnforced?: boolean;
  sanitizedCommandPreview: string;
  gatewayHandoffBlocked: boolean;
  runtimeControllerReviewConnected?: boolean;
  runtimeControllerAvailable?: boolean;
  runtimeControllerClipboardSummary?: string;
  runtimeSessionId?: string;
  runtimeSessionPhase?: string;
}

function toReceiptBoolean(value: boolean): "True" | "False" {
  return value ? "True" : "False";
}

export function buildAiExecutionGatewayMvp0FinalReviewedOnlyReceiptLines(
  input: AiExecutionGatewayMvp0FinalReviewedOnlyReceiptInput
): string[] {
  const gateResult = input.gateResult;

  return [
    ...buildAiExecutionGatewayMvp0ReceiptHeaderLines({ connectedExecutionInterception: true }),
    "ENVELOPE_VALID=True",
    ...buildAiExecutionGatewayMvp0EnvelopeSourceIntentReceiptLines(input),
    ...buildAiExecutionGatewayMvp0EnvelopeActionCapabilityReceiptLines(input),
    "BOOTSTRAP_CAPSULE_ENFORCED=True",
    "BOOTSTRAP_CAPSULE_VALID=True",
    "AUTHORIZED_SURFACE_GATE_ENFORCED=True",
    "AUTHORIZED_SURFACE_EXISTS=True",
    "SURFACE_DECISION=REVIEWED_ONLY_NO_EXECUTION",
    "WORKFLOW_DRIFT_BLOCKED=False",
    ...buildAiExecutionGatewayMvp0WorkflowBlockStatusReceiptLines({ aiWorkflowDriftBlocked: false, gitDependentWorkflowBlocked: false }),
    "ACTION_QUALITY_GATE_SOURCE=" + gateResult.source,
    "ACTION_QUALITY_GATE_STATUS=" + gateResult.status,
    "ACTION_QUALITY_GATE_RULE=" + gateResult.internalRuleId,
    "ACTION_QUALITY_GATE_REASONS=" + gateResult.reasons.join("; "),
    "ACTION_QUALITY_GATE_NEXT_SAFE_STEP=" + (gateResult.nextSafeStep ?? ""),
    ...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines(),
    "=== SAFETY KERNEL V3.1 RUNTIME CONTROLLER REVIEW ===",
    "COMMAND_DELEGATION_CONNECTED=" + toReceiptBoolean(input.runtimeControllerReviewConnected === true),
    "REVIEW_RUNTIME_CONNECTED=" + toReceiptBoolean(input.runtimeControllerReviewConnected === true),
    "RUNTIME_CONTROLLER_AVAILABLE=" + toReceiptBoolean(input.runtimeControllerAvailable === true),
    input.runtimeControllerClipboardSummary ?? "",
    "SESSION_ID=" + (input.runtimeSessionId ?? ""),
    "SESSION_PHASE=" + (input.runtimeSessionPhase ?? ""),
    "RAW_APPROVAL_NONCE_EXPOSED=False",
    "EXECUTION_RUNTIME_CONNECTED=False",
    "AUTOMATIC_EXECUTION_ALLOWED=False",
    "EXECUTION_AUTHORITY_GRANTED=False",
    "RAW_PROPOSED_ACTION_FULL_OUTPUT_DISABLED=True",
    ...buildAiExecutionGatewayMvp0SanitizedCommandPreviewReceiptLines(input),
    "GATEWAY_HANDOFF_BLOCKED=" + toReceiptBoolean(input.gatewayHandoffBlocked)
  ];
}

export interface AiExecutionGatewayMvp0InvalidEnvelopeReceiptInput {
  envelopeError: string;
}

export function buildAiExecutionGatewayMvp0InvalidEnvelopeReceiptLines(
  input: AiExecutionGatewayMvp0InvalidEnvelopeReceiptInput
): string[] {
  return [
    ...buildAiExecutionGatewayMvp0ReceiptHeaderLines(),
    "ENVELOPE_VALID=False",
    "ENVELOPE_ERROR=" + input.envelopeError,
    "WORKFLOW_DRIFT_BLOCKED=False",
    ...buildAiExecutionGatewayMvp0WorkflowBlockStatusReceiptLines({ gitDependentWorkflowBlocked: false }),
    ...buildAiExecutionGatewayMvp0SanitizedCommandPreviewReceiptLines(),
    ...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines({ gatewayHandoffBlocked: true })
  ];
}

export interface AiExecutionGatewayMvp0InvalidBootstrapCapsuleReceiptInput {
  bootstrapCapsuleError: string;
  envelopeSource: string;
  envelopeIntent: string;
}

export function buildAiExecutionGatewayMvp0InvalidBootstrapCapsuleReceiptLines(
  input: AiExecutionGatewayMvp0InvalidBootstrapCapsuleReceiptInput
): string[] {
  return [
    ...buildAiExecutionGatewayMvp0ReceiptHeaderLines(),
    "BOOTSTRAP_CAPSULE_ENFORCED=True",
    "BOOTSTRAP_CAPSULE_VALID=False",
    "BOOTSTRAP_CAPSULE_ERROR=" + input.bootstrapCapsuleError,
    "ENVELOPE_VALID=True",
    ...buildAiExecutionGatewayMvp0EnvelopeSourceIntentReceiptLines(input),
    ...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines({ gatewayHandoffBlocked: true })
  ];
}

export interface AiExecutionGatewayMvp0NoAuthorizedSurfaceReceiptInput {
  envelopeSource: string;
  envelopeIntent: string;
  envelopeActionId: string;
  envelopeCapabilityId: string;
}

export function buildAiExecutionGatewayMvp0NoAuthorizedSurfaceReceiptLines(
  input: AiExecutionGatewayMvp0NoAuthorizedSurfaceReceiptInput
): string[] {
  return [
    ...buildAiExecutionGatewayMvp0ReceiptHeaderLines(),
    "BOOTSTRAP_CAPSULE_ENFORCED=True",
    "BOOTSTRAP_CAPSULE_VALID=True",
    "AUTHORIZED_SURFACE_GATE_ENFORCED=True",
    "AUTHORIZED_SURFACE_EXISTS=False",
    "SURFACE_DECISION=BLOCKED_NO_AUTHORIZED_SURFACE",
    "USER_APPROVAL_OVERRIDES=False",
    "ENVELOPE_VALID=True",
    ...buildAiExecutionGatewayMvp0EnvelopeSourceIntentReceiptLines(input),
    ...buildAiExecutionGatewayMvp0EnvelopeActionCapabilityReceiptLines(input),
    ...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines({ gatewayHandoffBlocked: true })
  ];
}

export interface AiExecutionGatewayMvp0InvalidUserDefinedRuleSetReceiptInput {
  envelopeSource: string;
  envelopeIntent: string;
  userRuleError: string;
}

export function buildAiExecutionGatewayMvp0InvalidUserDefinedRuleSetReceiptLines(
  input: AiExecutionGatewayMvp0InvalidUserDefinedRuleSetReceiptInput
): string[] {
  return [
    ...buildAiExecutionGatewayMvp0ReceiptHeaderLines(),
    "ENVELOPE_VALID=True",
    ...buildAiExecutionGatewayMvp0EnvelopeSourceIntentReceiptLines(input),
    "USER_DEFINED_RULE_GATE_ENFORCED=True",
    "USER_DEFINED_RULE_SET_VALID=False",
    "USER_DEFINED_RULE_ERROR=" + input.userRuleError,
    ...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines({ gatewayHandoffBlocked: true })
  ];
}

export interface AiExecutionGatewayMvp0UserDefinedRuleBlockedReceiptInput {
  envelopeSource: string;
  envelopeIntent: string;
  ruleSetId: string;
  matchedRule: string;
  sanitizedCommandPreview: string;
}

export function buildAiExecutionGatewayMvp0UserDefinedRuleBlockedReceiptLines(
  input: AiExecutionGatewayMvp0UserDefinedRuleBlockedReceiptInput
): string[] {
  return [
    ...buildAiExecutionGatewayMvp0ReceiptHeaderLines(),
    "ENVELOPE_VALID=True",
    ...buildAiExecutionGatewayMvp0EnvelopeSourceIntentReceiptLines(input),
    "USER_DEFINED_RULE_GATE_ENFORCED=True",
    "USER_DEFINED_RULE_BLOCKED=True",
    "USER_DEFINED_RULE_SET_ID=" + input.ruleSetId,
    "USER_DEFINED_RULE_MATCH=" + input.matchedRule,
    ...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines({ gatewayHandoffBlocked: true }),
    ...buildAiExecutionGatewayMvp0SanitizedCommandPreviewReceiptLines(input)
  ];
}

export interface AiExecutionGatewayMvp0WorkflowDriftBlockedReceiptInput {
  envelopeSource: string;
  envelopeIntent: string;
  workflowDriftPattern: string;
  sanitizedCommandPreview: string;
}

export function buildAiExecutionGatewayMvp0WorkflowDriftBlockedReceiptLines(
  input: AiExecutionGatewayMvp0WorkflowDriftBlockedReceiptInput
): string[] {
  return [
    ...buildAiExecutionGatewayMvp0ReceiptHeaderLines(),
    "ENVELOPE_VALID=True",
    ...buildAiExecutionGatewayMvp0EnvelopeSourceIntentReceiptLines(input),
    ...buildAiExecutionGatewayMvp0WorkflowBlockStatusReceiptLines({ aiWorkflowDriftBlocked: true, gitDependentWorkflowBlocked: true }),
    ...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines({ gatewayHandoffBlocked: true }),
    "WORKFLOW_DRIFT_PATTERN=" + input.workflowDriftPattern,
    ...buildAiExecutionGatewayMvp0SanitizedCommandPreviewReceiptLines(input)
  ];
}

export const AI_EXECUTION_GATEWAY_MVP0_SERVER_RULESET_ACTION_FUSE_MS =
  250;

export type AiExecutionGatewayMvp0ServerRulesetReason =
  | "SERVER_RULESET_RESOLUTION_REJECTED"
  | "SERVER_RULESET_SOURCE_MISSING"
  | "SERVER_RULESET_RULES_EMPTY"
  | "SERVER_RULESET_INPUT_INVALID"
  | "SERVER_RULESET_INPUT_TOO_LARGE"
  | "SERVER_RULESET_ACTION_FUSE_EXCEEDED"
  | "SERVER_RULESET_PATTERN_REJECTED"
  | "SERVER_RULESET_MATCH_FAILED"
  | "SERVER_RULESET_MATCHED"
  | "SERVER_RULESET_NO_MATCH";

export interface AiExecutionGatewayMvp0ServerRulesetEvaluationOptions {
  readonly perRuleOperationBudget?: number;
  readonly perRuleWallClockMs?: number;
  readonly nowEpochMs?: () => number;
}

export interface AiExecutionGatewayMvp0ServerRulesetEvaluationResult {
  readonly blocked: boolean;
  readonly accepted: boolean;
  readonly source: ServerRulesetResolutionSource | null;
  readonly matchedRuleId: string;
  readonly matchedCategory: ServerRulesetRuleCategory | null;
  readonly reason: AiExecutionGatewayMvp0ServerRulesetReason;
}

interface AiExecutionGatewayMvp0ServerRulesetLimits {
  readonly perRuleOperationBudget: number;
  readonly perRuleWallClockMs: number;
}

function makeAiExecutionGatewayMvp0ServerRulesetResult(
  blocked: boolean,
  accepted: boolean,
  source: ServerRulesetResolutionSource | null,
  matchedRuleId: string,
  matchedCategory: ServerRulesetRuleCategory | null,
  reason: AiExecutionGatewayMvp0ServerRulesetReason
): AiExecutionGatewayMvp0ServerRulesetEvaluationResult {
  return Object.freeze({
    blocked,
    accepted,
    source,
    matchedRuleId,
    matchedCategory,
    reason,
  });
}

function compareAiExecutionGatewayMvp0ServerRuleText(
  left: string,
  right: string
): number {
  if (left < right) {
    return -1;
  }

  if (left > right) {
    return 1;
  }

  return 0;
}

function resolveAiExecutionGatewayMvp0ServerRulesetLimits(
  options: AiExecutionGatewayMvp0ServerRulesetEvaluationOptions
): AiExecutionGatewayMvp0ServerRulesetLimits | null {
  const operationBudget =
    options.perRuleOperationBudget ??
    MAX_SERVER_RULESET_RULE_OPERATIONS;

  const wallClockMs =
    options.perRuleWallClockMs ??
    MAX_SERVER_RULESET_RULE_WALL_CLOCK_MS;

  if (
    !Number.isSafeInteger(operationBudget) ||
    operationBudget < 0 ||
    !Number.isFinite(wallClockMs) ||
    wallClockMs < 0
  ) {
    return null;
  }

  return Object.freeze({
    perRuleOperationBudget:
      operationBudget,
    perRuleWallClockMs:
      wallClockMs,
  });
}

function isAiExecutionGatewayMvp0ServerRulesetActionFuseExceeded(
  nowEpochMs: () => number,
  startedAtEpochMs: number
): boolean {
  const currentEpochMs =
    nowEpochMs();

  return (
    !Number.isFinite(currentEpochMs) ||
    currentEpochMs - startedAtEpochMs >=
      AI_EXECUTION_GATEWAY_MVP0_SERVER_RULESET_ACTION_FUSE_MS
  );
}

export function evaluateAiExecutionGatewayMvp0ServerRuleset(
  proposed: string,
  resolution: ResolveServerRulesetFallbackResult,
  options: AiExecutionGatewayMvp0ServerRulesetEvaluationOptions = {}
): AiExecutionGatewayMvp0ServerRulesetEvaluationResult {
  if (
    typeof proposed !== "string" ||
    !resolution ||
    typeof resolution !== "object"
  ) {
    return makeAiExecutionGatewayMvp0ServerRulesetResult(
      true,
      false,
      null,
      "",
      null,
      "SERVER_RULESET_INPUT_INVALID"
    );
  }

  if (!resolution.accepted) {
    return makeAiExecutionGatewayMvp0ServerRulesetResult(
      true,
      false,
      resolution.source,
      "",
      null,
      "SERVER_RULESET_RESOLUTION_REJECTED"
    );
  }

  if (resolution.source === null) {
    return makeAiExecutionGatewayMvp0ServerRulesetResult(
      true,
      false,
      null,
      "",
      null,
      "SERVER_RULESET_SOURCE_MISSING"
    );
  }

  if (
    !Array.isArray(resolution.rules) ||
    resolution.rules.length === 0
  ) {
    return makeAiExecutionGatewayMvp0ServerRulesetResult(
      true,
      false,
      resolution.source,
      "",
      null,
      "SERVER_RULESET_RULES_EMPTY"
    );
  }

  if (
    Buffer.byteLength(
      proposed,
      "utf8"
    ) >
    MAX_SERVER_RULESET_INPUT_BYTES
  ) {
    return makeAiExecutionGatewayMvp0ServerRulesetResult(
      true,
      false,
      resolution.source,
      "",
      null,
      "SERVER_RULESET_INPUT_TOO_LARGE"
    );
  }

  const limits =
    resolveAiExecutionGatewayMvp0ServerRulesetLimits(
      options
    );

  if (limits === null) {
    return makeAiExecutionGatewayMvp0ServerRulesetResult(
      true,
      false,
      resolution.source,
      "",
      null,
      "SERVER_RULESET_INPUT_INVALID"
    );
  }

  const commandCandidates =
    deriveServerRulesetCommandCandidates(proposed);

  if (!commandCandidates.accepted) {
    return makeAiExecutionGatewayMvp0ServerRulesetResult(
      true,
      false,
      resolution.source,
      "",
      null,
      "SERVER_RULESET_INPUT_INVALID"
    );
  }
  const nowEpochMs =
    options.nowEpochMs ??
    Date.now;

  let startedAtEpochMs: number;

  try {
    startedAtEpochMs =
      nowEpochMs();
  } catch {
    return makeAiExecutionGatewayMvp0ServerRulesetResult(
      true,
      false,
      resolution.source,
      "",
      null,
      "SERVER_RULESET_ACTION_FUSE_EXCEEDED"
    );
  }

  if (!Number.isFinite(startedAtEpochMs)) {
    return makeAiExecutionGatewayMvp0ServerRulesetResult(
      true,
      false,
      resolution.source,
      "",
      null,
      "SERVER_RULESET_ACTION_FUSE_EXCEEDED"
    );
  }

  const rules =
    [...resolution.rules].sort(
      (left, right) =>
        compareAiExecutionGatewayMvp0ServerRuleText(
          left.ruleId,
          right.ruleId
        ) ||
        compareAiExecutionGatewayMvp0ServerRuleText(
          left.category,
          right.category
        ) ||
        compareAiExecutionGatewayMvp0ServerRuleText(
          left.pattern,
          right.pattern
        )
    );

  for (const rule of rules) {
    if (
      isAiExecutionGatewayMvp0ServerRulesetActionFuseExceeded(
        nowEpochMs,
        startedAtEpochMs
      )
    ) {
      return makeAiExecutionGatewayMvp0ServerRulesetResult(
        true,
        false,
        resolution.source,
        "",
        null,
        "SERVER_RULESET_ACTION_FUSE_EXCEEDED"
      );
    }

    if (
      typeof rule.ruleId !== "string" ||
      typeof rule.category !== "string" ||
      typeof rule.pattern !== "string"
    ) {
      return makeAiExecutionGatewayMvp0ServerRulesetResult(
        true,
        false,
        resolution.source,
        "",
        null,
        "SERVER_RULESET_PATTERN_REJECTED"
      );
    }

    const compiled =
      compileServerRulesetSafeRegex(
        rule.pattern
      );

    if (!compiled.accepted) {
      return makeAiExecutionGatewayMvp0ServerRulesetResult(
        true,
        false,
        resolution.source,
        rule.ruleId,
        rule.category,
        "SERVER_RULESET_PATTERN_REJECTED"
      );
    }

    for (const commandCandidate of commandCandidates.candidates) {
      if (
        isAiExecutionGatewayMvp0ServerRulesetActionFuseExceeded(
          nowEpochMs,
          startedAtEpochMs
        )
      ) {
        return makeAiExecutionGatewayMvp0ServerRulesetResult(
          true,
          false,
          resolution.source,
          "",
          null,
          "SERVER_RULESET_ACTION_FUSE_EXCEEDED"
        );
      }

      let matchResult;

      try {
        matchResult =
          matchServerRulesetSafeRegex(
            rule.pattern,
            commandCandidate,
            {
              operationBudget:
                limits.perRuleOperationBudget,
              wallClockFuseMs:
                limits.perRuleWallClockMs,
            }
          );
      } catch {
        return makeAiExecutionGatewayMvp0ServerRulesetResult(
          true,
          false,
          resolution.source,
          rule.ruleId,
          rule.category,
          "SERVER_RULESET_MATCH_FAILED"
        );
      }

      if (!matchResult.accepted) {
        return makeAiExecutionGatewayMvp0ServerRulesetResult(
          true,
          false,
          resolution.source,
          rule.ruleId,
          rule.category,
          "SERVER_RULESET_MATCH_FAILED"
        );
      }

      if (
        isAiExecutionGatewayMvp0ServerRulesetActionFuseExceeded(
          nowEpochMs,
          startedAtEpochMs
        )
      ) {
        return makeAiExecutionGatewayMvp0ServerRulesetResult(
          true,
          false,
          resolution.source,
          "",
          null,
          "SERVER_RULESET_ACTION_FUSE_EXCEEDED"
        );
      }

      if (matchResult.matched) {
        return makeAiExecutionGatewayMvp0ServerRulesetResult(
          true,
          true,
          resolution.source,
          rule.ruleId,
          rule.category,
          "SERVER_RULESET_MATCHED"
        );
      }
    }
  }

  return makeAiExecutionGatewayMvp0ServerRulesetResult(
    false,
    true,
    resolution.source,
    "",
    null,
    "SERVER_RULESET_NO_MATCH"
  );
}

export interface AiExecutionGatewayMvp0ServerRulesetBlockedReceiptInput {
  readonly resolutionAccepted: boolean;
  readonly resolutionSource: ServerRulesetResolutionSource | null;
  readonly matchedRuleId: string;
  readonly matchedCategory: ServerRulesetRuleCategory | null;
  readonly reason: AiExecutionGatewayMvp0ServerRulesetReason;
}

export function buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines(
  input: AiExecutionGatewayMvp0ServerRulesetBlockedReceiptInput
): string[] {
  return [
    "SERVER_RULESET_GATE_ENFORCED=True",
    "SERVER_RULESET_RESOLUTION_ACCEPTED=" +
      (
        input.resolutionAccepted
          ? "True"
          : "False"
      ),
    "SERVER_RULESET_RESOLUTION_SOURCE=" +
      (
        input.resolutionSource ??
        "NONE"
      ),
    "SERVER_RULESET_MATCHED_RULE_ID=" +
      (
        input.matchedRuleId ||
        "NONE"
      ),
    "SERVER_RULESET_MATCHED_CATEGORY=" +
      (
        input.matchedCategory ??
        "NONE"
      ),
    "SERVER_RULESET_REASON=" +
      input.reason,
    ...buildAiExecutionGatewayMvp0ReceiptExecutionFooterLines({
      gatewayHandoffBlocked: true,
    }),
  ];
}
