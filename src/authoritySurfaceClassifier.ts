import { createHash } from "node:crypto";
import type {
  ArtifactIntentEnvelope,
  ArtifactIntentProvenance,
} from "./artifactIntentPreflight";

export const AUTHORITY_SURFACE_CLASSIFIER_SCHEMA_VERSION =
  "1.0.0";

export type ArtifactAuthoritySurface =
  | "policy_surface"
  | "generated_artifact"
  | "ledger"
  | "receipt";

export interface AuthoritySurfaceRule {
  readonly ruleId: string;
  readonly artifactKind: string;
  readonly provenance: ArtifactIntentProvenance;
  readonly targetPrefix: string;
  readonly authoritySurface: ArtifactAuthoritySurface;
}

export interface AuthoritySurfaceClassificationInput {
  readonly intent: ArtifactIntentEnvelope;
  readonly rules?: readonly AuthoritySurfaceRule[];
}

export interface AuthoritySurfaceClassificationResult {
  readonly accepted: true;
  readonly classificationId: string;
  readonly authoritySurface: ArtifactAuthoritySurface;
  readonly matchedRuleId: string;
  readonly normalizedTargetPath: string;
}

export const DEFAULT_ARTIFACT_AUTHORITY_SURFACE_RULES:
  readonly AuthoritySurfaceRule[] = Object.freeze([
    Object.freeze({
      ruleId: "work-receipt-receipt-surface-v1",
      artifactKind: "work_receipt",
      provenance: "local_user_command",
      targetPrefix: ".aegis/receipts",
      authoritySurface: "receipt",
    }),
  ]);

function requireInlineIdentifier(
  value: string,
  errorCode: string
): string {
  const normalized = value.trim();

  if (
    !normalized ||
    normalized.length > 200 ||
    /[\r\n\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new Error(errorCode);
  }

  return normalized;
}

function normalizeRelativePath(
  value: string,
  errorCode: string
): string {
  const normalized = value.trim();

  if (
    !normalized ||
    normalized.startsWith("/") ||
    /^[a-zA-Z]:[\\/]/.test(normalized) ||
    normalized.includes("\\") ||
    /[\r\n\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new Error(errorCode);
  }

  const segments = normalized.split("/");

  if (
    segments.some(
      segment =>
        !segment ||
        segment === "." ||
        segment === ".."
    )
  ) {
    throw new Error(errorCode);
  }

  return normalized;
}

function canonicalize(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("NON_FINITE_CANONICAL_NUMBER");
    }

    return value;
  }

  if (Array.isArray(value)) {
    return value.map(item => canonicalize(item));
  }

  if (typeof value === "object") {
    const source = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};

    for (const key of Object.keys(source).sort()) {
      if (source[key] === undefined) {
        throw new Error("UNDEFINED_CANONICAL_VALUE");
      }

      output[key] = canonicalize(source[key]);
    }

    return output;
  }

  throw new Error("UNSUPPORTED_CANONICAL_VALUE");
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256")
    .update(value, "utf8")
    .digest("hex")}`;
}

function pathMatchesPrefix(
  targetPath: string,
  targetPrefix: string
): boolean {
  return (
    targetPath === targetPrefix ||
    targetPath.startsWith(targetPrefix + "/")
  );
}

function normalizeRules(
  rules: readonly AuthoritySurfaceRule[]
): readonly AuthoritySurfaceRule[] {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw new Error("EMPTY_AUTHORITY_SURFACE_RULES");
  }

  const normalized = rules.map(rule => {
    const provenance = rule.provenance;

    if (
      provenance !== "local_user_command" &&
      provenance !== "aegis_runtime"
    ) {
      throw new Error(
        "INVALID_AUTHORITY_SURFACE_RULE_PROVENANCE"
      );
    }

    if (
      rule.authoritySurface !== "policy_surface" &&
      rule.authoritySurface !== "generated_artifact" &&
      rule.authoritySurface !== "ledger" &&
      rule.authoritySurface !== "receipt"
    ) {
      throw new Error(
        "INVALID_AUTHORITY_SURFACE_RULE_SURFACE"
      );
    }

    return {
      ruleId: requireInlineIdentifier(
        rule.ruleId,
        "INVALID_AUTHORITY_SURFACE_RULE_ID"
      ),
      artifactKind: requireInlineIdentifier(
        rule.artifactKind,
        "INVALID_AUTHORITY_SURFACE_RULE_ARTIFACT_KIND"
      ),
      provenance,
      targetPrefix: normalizeRelativePath(
        rule.targetPrefix,
        "INVALID_AUTHORITY_SURFACE_RULE_TARGET_PREFIX"
      ),
      authoritySurface: rule.authoritySurface,
    } satisfies AuthoritySurfaceRule;
  });

  const ruleIds = normalized.map(rule => rule.ruleId);

  if (new Set(ruleIds).size !== ruleIds.length) {
    throw new Error("DUPLICATE_AUTHORITY_SURFACE_RULE_ID");
  }

  const semanticKeys = normalized.map(rule =>
    canonicalJson({
      artifactKind: rule.artifactKind,
      provenance: rule.provenance,
      targetPrefix: rule.targetPrefix,
      authoritySurface: rule.authoritySurface,
    })
  );

  if (new Set(semanticKeys).size !== semanticKeys.length) {
    throw new Error("DUPLICATE_AUTHORITY_SURFACE_RULE");
  }

  return [...normalized].sort((left, right) =>
    left.ruleId.localeCompare(right.ruleId)
  );
}

export function classifyArtifactAuthoritySurface(
  input: AuthoritySurfaceClassificationInput
): AuthoritySurfaceClassificationResult {
  if (input.intent.schemaVersion !== "1.0.0") {
    throw new Error(
      "INVALID_AUTHORITY_SURFACE_INTENT_SCHEMA_VERSION"
    );
  }

  const intentId = requireInlineIdentifier(
    input.intent.intentId,
    "INVALID_AUTHORITY_SURFACE_INTENT_ID"
  );

  const artifactKind = requireInlineIdentifier(
    input.intent.artifactKind,
    "INVALID_AUTHORITY_SURFACE_ARTIFACT_KIND"
  );

  const provenance = input.intent.provenance;

  if (
    provenance !== "local_user_command" &&
    provenance !== "aegis_runtime"
  ) {
    throw new Error(
      "INVALID_AUTHORITY_SURFACE_PROVENANCE"
    );
  }

  const normalizedTargetPath = normalizeRelativePath(
    input.intent.targetPath,
    "INVALID_AUTHORITY_SURFACE_TARGET_PATH"
  );

  const rules = normalizeRules(
    input.rules ??
      DEFAULT_ARTIFACT_AUTHORITY_SURFACE_RULES
  );

  const matches = rules.filter(
    rule =>
      rule.artifactKind === artifactKind &&
      rule.provenance === provenance &&
      pathMatchesPrefix(
        normalizedTargetPath,
        rule.targetPrefix
      )
  );

  if (matches.length === 0) {
    throw new Error(
      "NO_MATCHING_AUTHORITY_SURFACE_RULE"
    );
  }

  if (matches.length !== 1) {
    throw new Error(
      "AMBIGUOUS_AUTHORITY_SURFACE_RULE"
    );
  }

  const matchedRule = matches[0];

  if (!matchedRule) {
    throw new Error(
      "AUTHORITY_SURFACE_RULE_RESOLUTION_FAILED"
    );
  }

  const classificationId = sha256(
    canonicalJson({
      schemaVersion:
        AUTHORITY_SURFACE_CLASSIFIER_SCHEMA_VERSION,
      intentId,
      artifactKind,
      provenance,
      normalizedTargetPath,
      matchedRuleId: matchedRule.ruleId,
      authoritySurface: matchedRule.authoritySurface,
    })
  );

  return {
    accepted: true,
    classificationId,
    authoritySurface: matchedRule.authoritySurface,
    matchedRuleId: matchedRule.ruleId,
    normalizedTargetPath,
  };
}