import { createHash } from "node:crypto";
import type {
  CanonicalAuthorityState,
} from "./canonicalAuthorityState";

export const ARTIFACT_INTENT_PREFLIGHT_SCHEMA_VERSION =
  "1.0.0";

export type ArtifactIntentProvenance =
  | "local_user_command"
  | "aegis_runtime";

export interface ArtifactIntentAuthorityBinding {
  readonly revision: number;
  readonly workspaceId: string;
  readonly policyVersion: string;
  readonly rulesetVersion: string;
  readonly capabilityManifestVersion: string;
  readonly actionId: string | null;
  readonly sessionId: string | null;
  readonly approvalNonceSha256: string | null;
}

export interface ArtifactIntentEnvelope {
  readonly schemaVersion:
    typeof ARTIFACT_INTENT_PREFLIGHT_SCHEMA_VERSION;
  readonly intentId: string;
  readonly artifactKind: string;
  readonly provenance: ArtifactIntentProvenance;
  readonly targetPath: string;
  readonly entryPaths: readonly string[];
  readonly authorityBinding: ArtifactIntentAuthorityBinding;
}

export interface ArtifactIntentPreflightInput {
  readonly intent: ArtifactIntentEnvelope;
  readonly authorityState: CanonicalAuthorityState;
  readonly allowedArtifactKinds: readonly string[];
  readonly allowedTargetPrefixes: readonly string[];
}

export interface ArtifactIntentPreflightResult {
  readonly accepted: true;
  readonly preflightId: string;
  readonly authorityStateSha256: string;
  readonly normalizedIntent: ArtifactIntentEnvelope;
}

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

function requireNullableIdentifier(
  value: string | null,
  errorCode: string
): string | null {
  return value === null
    ? null
    : requireInlineIdentifier(value, errorCode);
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

function normalizeUniqueIdentifiers(
  values: readonly string[],
  emptyError: string,
  invalidError: string,
  duplicateError: string
): readonly string[] {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error(emptyError);
  }

  const normalized = values.map(value =>
    requireInlineIdentifier(value, invalidError)
  );

  if (new Set(normalized).size !== normalized.length) {
    throw new Error(duplicateError);
  }

  return [...normalized].sort();
}

function normalizeUniquePaths(
  values: readonly string[],
  emptyError: string,
  invalidError: string,
  duplicateError: string
): readonly string[] {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error(emptyError);
  }

  const normalized = values.map(value =>
    normalizeRelativePath(value, invalidError)
  );

  if (new Set(normalized).size !== normalized.length) {
    throw new Error(duplicateError);
  }

  return [...normalized].sort();
}

function pathMatchesAllowedPrefix(
  targetPath: string,
  allowedPrefix: string
): boolean {
  return (
    targetPath === allowedPrefix ||
    targetPath.startsWith(allowedPrefix + "/")
  );
}

function verifyAuthorityBinding(
  binding: ArtifactIntentAuthorityBinding,
  authorityState: CanonicalAuthorityState
): ArtifactIntentAuthorityBinding {
  if (
    !Number.isSafeInteger(binding.revision) ||
    binding.revision < 0
  ) {
    throw new Error("INVALID_ARTIFACT_AUTHORITY_REVISION");
  }

  const normalized: ArtifactIntentAuthorityBinding = {
    revision: binding.revision,
    workspaceId: requireInlineIdentifier(
      binding.workspaceId,
      "INVALID_ARTIFACT_WORKSPACE_ID"
    ),
    policyVersion: requireInlineIdentifier(
      binding.policyVersion,
      "INVALID_ARTIFACT_POLICY_VERSION"
    ),
    rulesetVersion: requireInlineIdentifier(
      binding.rulesetVersion,
      "INVALID_ARTIFACT_RULESET_VERSION"
    ),
    capabilityManifestVersion: requireInlineIdentifier(
      binding.capabilityManifestVersion,
      "INVALID_ARTIFACT_CAPABILITY_MANIFEST_VERSION"
    ),
    actionId: requireNullableIdentifier(
      binding.actionId,
      "INVALID_ARTIFACT_ACTION_ID"
    ),
    sessionId: requireNullableIdentifier(
      binding.sessionId,
      "INVALID_ARTIFACT_SESSION_ID"
    ),
    approvalNonceSha256: binding.approvalNonceSha256,
  };

  if (
    normalized.approvalNonceSha256 !== null &&
    !/^sha256:[a-f0-9]{64}$/.test(
      normalized.approvalNonceSha256
    )
  ) {
    throw new Error("INVALID_ARTIFACT_APPROVAL_NONCE_SHA256");
  }

  if (
    normalized.revision !== authorityState.revision ||
    normalized.workspaceId !== authorityState.workspaceId ||
    normalized.policyVersion !== authorityState.policyVersion ||
    normalized.rulesetVersion !== authorityState.rulesetVersion ||
    normalized.capabilityManifestVersion !==
      authorityState.capabilityManifestVersion ||
    normalized.actionId !== authorityState.actionId ||
    normalized.sessionId !== authorityState.sessionId ||
    normalized.approvalNonceSha256 !==
      authorityState.approvalNonceSha256
  ) {
    throw new Error("ARTIFACT_AUTHORITY_BINDING_MISMATCH");
  }

  return normalized;
}

export function preflightArtifactIntent(
  input: ArtifactIntentPreflightInput
): ArtifactIntentPreflightResult {
  if (
    input.authorityState.productPass !== false ||
    input.authorityState.releaseReady !== false ||
    input.authorityState.uploadReady !== false ||
    input.authorityState.finalArtifactCreated !== false
  ) {
    throw new Error("UNAUTHORIZED_FINAL_STATE_CLAIM");
  }

  if (
    input.intent.schemaVersion !==
    ARTIFACT_INTENT_PREFLIGHT_SCHEMA_VERSION
  ) {
    throw new Error("INVALID_ARTIFACT_INTENT_SCHEMA_VERSION");
  }

  const intentId = requireInlineIdentifier(
    input.intent.intentId,
    "INVALID_ARTIFACT_INTENT_ID"
  );

  const artifactKind = requireInlineIdentifier(
    input.intent.artifactKind,
    "INVALID_ARTIFACT_KIND"
  );

  if (
    input.intent.provenance !== "local_user_command" &&
    input.intent.provenance !== "aegis_runtime"
  ) {
    throw new Error("INVALID_ARTIFACT_PROVENANCE");
  }

  const targetPath = normalizeRelativePath(
    input.intent.targetPath,
    "INVALID_ARTIFACT_TARGET_PATH"
  );

  const entryPaths = normalizeUniquePaths(
    input.intent.entryPaths,
    "EMPTY_ARTIFACT_INTENT_ENTRIES",
    "INVALID_ARTIFACT_INTENT_ENTRY_PATH",
    "DUPLICATE_ARTIFACT_INTENT_ENTRY_PATH"
  );

  const allowedArtifactKinds = normalizeUniqueIdentifiers(
    input.allowedArtifactKinds,
    "EMPTY_ALLOWED_ARTIFACT_KINDS",
    "INVALID_ALLOWED_ARTIFACT_KIND",
    "DUPLICATE_ALLOWED_ARTIFACT_KIND"
  );

  const allowedTargetPrefixes = normalizeUniquePaths(
    input.allowedTargetPrefixes,
    "EMPTY_ALLOWED_ARTIFACT_TARGET_PREFIXES",
    "INVALID_ALLOWED_ARTIFACT_TARGET_PREFIX",
    "DUPLICATE_ALLOWED_ARTIFACT_TARGET_PREFIX"
  );

  if (!allowedArtifactKinds.includes(artifactKind)) {
    throw new Error("ARTIFACT_KIND_NOT_ALLOWED");
  }

  if (
    !allowedTargetPrefixes.some(prefix =>
      pathMatchesAllowedPrefix(targetPath, prefix)
    )
  ) {
    throw new Error("ARTIFACT_TARGET_NOT_ALLOWED");
  }

  const authorityBinding = verifyAuthorityBinding(
    input.intent.authorityBinding,
    input.authorityState
  );

  const normalizedIntent: ArtifactIntentEnvelope = {
    schemaVersion: ARTIFACT_INTENT_PREFLIGHT_SCHEMA_VERSION,
    intentId,
    artifactKind,
    provenance: input.intent.provenance,
    targetPath,
    entryPaths,
    authorityBinding,
  };

  const authorityStateSha256 = sha256(
    canonicalJson(input.authorityState)
  );

  const preflightId = sha256(
    canonicalJson({
      authorityStateSha256,
      normalizedIntent,
    })
  );

  return {
    accepted: true,
    preflightId,
    authorityStateSha256,
    normalizedIntent,
  };
}