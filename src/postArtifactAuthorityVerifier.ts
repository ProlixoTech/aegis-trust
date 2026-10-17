import { createHash } from "node:crypto";
import type {
  CanonicalAuthorityState,
} from "./canonicalAuthorityState";
import type {
  CompiledArtifactManifest,
} from "./artifactCompiler";
import {
  preflightArtifactIntent,
  type ArtifactIntentEnvelope,
} from "./artifactIntentPreflight";
import {
  classifyArtifactAuthoritySurface,
  type ArtifactAuthoritySurface,
  type AuthoritySurfaceRule,
} from "./authoritySurfaceClassifier";

export const POST_ARTIFACT_AUTHORITY_VERIFIER_SCHEMA_VERSION =
  "1.0.0";

export interface PersistedArtifactAuthorityRecord {
  readonly preflightId: string;
  readonly preflightAuthorityStateSha256: string;
  readonly intent: ArtifactIntentEnvelope;
  readonly authoritySurfaceClassificationId: string;
  readonly authoritySurface: ArtifactAuthoritySurface;
  readonly authoritySurfaceRuleId: string;
  readonly artifactId: string;
  readonly manifest: CompiledArtifactManifest;
}

export interface PostArtifactAuthorityVerificationInput {
  readonly artifact: PersistedArtifactAuthorityRecord;
  readonly preArtifactAuthorityState: CanonicalAuthorityState;
  readonly postArtifactAuthorityState: CanonicalAuthorityState;
  readonly allowedArtifactKinds: readonly string[];
  readonly allowedTargetPrefixes: readonly string[];
  readonly authoritySurfaceRules?:
    readonly AuthoritySurfaceRule[];
  readonly expectedAuthoritySurface:
    ArtifactAuthoritySurface;
  readonly expectedAuthoritySurfaceRuleId: string;
}

export interface PostArtifactAuthorityVerificationResult {
  readonly accepted: true;
  readonly verificationId: string;
  readonly artifactId: string;
  readonly preArtifactAuthorityStateSha256: string;
  readonly postArtifactAuthorityStateSha256: string;
  readonly postArtifactAuthorityRevision: number;
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

function requireSha256(
  value: string,
  errorCode: string
): string {
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) {
    throw new Error(errorCode);
  }

  return value;
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

function requireAuthoritySurface(
  value: ArtifactAuthoritySurface
): ArtifactAuthoritySurface {
  if (
    value !== "policy_surface" &&
    value !== "generated_artifact" &&
    value !== "ledger" &&
    value !== "receipt"
  ) {
    throw new Error(
      "INVALID_EXPECTED_ARTIFACT_AUTHORITY_SURFACE"
    );
  }

  return value;
}

function requireTimestamp(
  value: string,
  errorCode: string
): string {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new Error(errorCode);
  }

  return value;
}

function verifyManifestEntryScope(
  manifest: CompiledArtifactManifest,
  intent: ArtifactIntentEnvelope
): void {
  if (
    !Array.isArray(manifest.entries) ||
    manifest.entries.length === 0
  ) {
    throw new Error(
      "EMPTY_POST_ARTIFACT_MANIFEST_ENTRIES"
    );
  }

  const manifestPaths = manifest.entries.map(entry => {
    if (
      !entry.path ||
      !/^sha256:[a-f0-9]{64}$/.test(
        entry.contentSha256
      ) ||
      !Number.isSafeInteger(entry.byteLength) ||
      entry.byteLength < 0
    ) {
      throw new Error(
        "INVALID_POST_ARTIFACT_MANIFEST_ENTRY"
      );
    }

    return entry.path;
  });

  if (
    canonicalJson(manifestPaths) !==
    canonicalJson(intent.entryPaths)
  ) {
    throw new Error(
      "POST_ARTIFACT_MANIFEST_ENTRY_SCOPE_MISMATCH"
    );
  }
}

export function verifyPostArtifactInternalAuthority(
  input: PostArtifactAuthorityVerificationInput
): PostArtifactAuthorityVerificationResult {
  const artifact = input.artifact;

  const artifactId = requireSha256(
    artifact.artifactId,
    "INVALID_POST_ARTIFACT_ID"
  );

  const persistedPreflightId = requireSha256(
    artifact.preflightId,
    "INVALID_POST_ARTIFACT_PREFLIGHT_ID"
  );

  const persistedClassificationId = requireSha256(
    artifact.authoritySurfaceClassificationId,
    "INVALID_POST_ARTIFACT_CLASSIFICATION_ID"
  );

  const persistedPreflightAuthorityStateSha256 =
    requireSha256(
      artifact.preflightAuthorityStateSha256,
      "INVALID_POST_ARTIFACT_PREFLIGHT_AUTHORITY_SHA256"
    );

  const expectedAuthoritySurface =
    requireAuthoritySurface(
      input.expectedAuthoritySurface
    );

  const expectedAuthoritySurfaceRuleId =
    requireInlineIdentifier(
      input.expectedAuthoritySurfaceRuleId,
      "INVALID_EXPECTED_AUTHORITY_SURFACE_RULE_ID"
    );

  const preflight = preflightArtifactIntent({
    intent: artifact.intent,
    authorityState: input.preArtifactAuthorityState,
    allowedArtifactKinds: input.allowedArtifactKinds,
    allowedTargetPrefixes:
      input.allowedTargetPrefixes,
  });

  if (
    canonicalJson(artifact.intent) !==
    canonicalJson(preflight.normalizedIntent)
  ) {
    throw new Error(
      "POST_ARTIFACT_INTENT_NOT_NORMALIZED"
    );
  }

  if (persistedPreflightId !== preflight.preflightId) {
    throw new Error(
      "POST_ARTIFACT_PREFLIGHT_ID_MISMATCH"
    );
  }

  const classification =
    input.authoritySurfaceRules === undefined
      ? classifyArtifactAuthoritySurface({
          intent: preflight.normalizedIntent,
        })
      : classifyArtifactAuthoritySurface({
          intent: preflight.normalizedIntent,
          rules: input.authoritySurfaceRules,
        });

  if (
    classification.authoritySurface !==
    expectedAuthoritySurface
  ) {
    throw new Error(
      "POST_ARTIFACT_AUTHORITY_SURFACE_MISMATCH"
    );
  }

  if (
    classification.matchedRuleId !==
    expectedAuthoritySurfaceRuleId
  ) {
    throw new Error(
      "POST_ARTIFACT_AUTHORITY_SURFACE_RULE_MISMATCH"
    );
  }

  if (
    artifact.authoritySurface !==
    classification.authoritySurface
  ) {
    throw new Error(
      "PERSISTED_AUTHORITY_SURFACE_MISMATCH"
    );
  }

  if (
    artifact.authoritySurfaceRuleId !==
    classification.matchedRuleId
  ) {
    throw new Error(
      "PERSISTED_AUTHORITY_SURFACE_RULE_MISMATCH"
    );
  }

  if (
    persistedClassificationId !==
    classification.classificationId
  ) {
    throw new Error(
      "POST_ARTIFACT_CLASSIFICATION_ID_MISMATCH"
    );
  }

  const manifest = artifact.manifest;

  if (manifest.schemaVersion !== "1.0.0") {
    throw new Error(
      "INVALID_POST_ARTIFACT_MANIFEST_SCHEMA_VERSION"
    );
  }

  const recomputedArtifactId = sha256(
    canonicalJson(manifest)
  );

  if (artifactId !== recomputedArtifactId) {
    throw new Error("POST_ARTIFACT_ID_MISMATCH");
  }

  const preArtifactAuthorityStateSha256 = sha256(
    canonicalJson(input.preArtifactAuthorityState)
  );

  if (
    manifest.authorityStateSha256 !==
      preArtifactAuthorityStateSha256 ||
    persistedPreflightAuthorityStateSha256 !==
      preArtifactAuthorityStateSha256 ||
    preflight.authorityStateSha256 !==
      preArtifactAuthorityStateSha256
  ) {
    throw new Error(
      "POST_ARTIFACT_AUTHORITY_HASH_MISMATCH"
    );
  }

  if (
    manifest.authorityRevision !==
    input.preArtifactAuthorityState.revision
  ) {
    throw new Error(
      "POST_ARTIFACT_MANIFEST_AUTHORITY_REVISION_MISMATCH"
    );
  }

  if (
    manifest.projectIdentity !==
    input.preArtifactAuthorityState.projectIdentity
  ) {
    throw new Error(
      "POST_ARTIFACT_PROJECT_IDENTITY_MISMATCH"
    );
  }

  if (
    manifest.workspaceId !==
    input.preArtifactAuthorityState.workspaceId
  ) {
    throw new Error(
      "POST_ARTIFACT_WORKSPACE_ID_MISMATCH"
    );
  }

  if (
    manifest.artifactKind !==
    preflight.normalizedIntent.artifactKind
  ) {
    throw new Error(
      "POST_ARTIFACT_KIND_MISMATCH"
    );
  }

  verifyManifestEntryScope(
    manifest,
    preflight.normalizedIntent
  );

  const expectedPostRevision =
    input.preArtifactAuthorityState.revision + 1;

  if (
    input.postArtifactAuthorityState.revision !==
    expectedPostRevision
  ) {
    throw new Error(
      "POST_ARTIFACT_AUTHORITY_REVISION_MISMATCH"
    );
  }

  if (
    input.postArtifactAuthorityState.currentArtifactId !==
    artifactId
  ) {
    throw new Error(
      "POST_ARTIFACT_CURRENT_ARTIFACT_ID_MISMATCH"
    );
  }

  const postTimestamp = requireTimestamp(
    input.postArtifactAuthorityState.decisionScope
      .timestamp,
    "INVALID_POST_ARTIFACT_AUTHORITY_TIMESTAMP"
  );

  const expectedPostArtifactAuthorityState:
    CanonicalAuthorityState = {
      ...input.preArtifactAuthorityState,
      revision: expectedPostRevision,
      currentArtifactId: artifactId,
      decisionScope: {
        ...input.preArtifactAuthorityState.decisionScope,
        timestamp: postTimestamp,
      },
      productPass: false,
      releaseReady: false,
      uploadReady: false,
      finalArtifactCreated: false,
    };

  if (
    canonicalJson(
      input.postArtifactAuthorityState
    ) !==
    canonicalJson(
      expectedPostArtifactAuthorityState
    )
  ) {
    throw new Error(
      "POST_ARTIFACT_AUTHORITY_STATE_DRIFT"
    );
  }

  const postArtifactAuthorityStateSha256 = sha256(
    canonicalJson(input.postArtifactAuthorityState)
  );

  const verificationId = sha256(
    canonicalJson({
      schemaVersion:
        POST_ARTIFACT_AUTHORITY_VERIFIER_SCHEMA_VERSION,
      artifactId,
      preflightId: persistedPreflightId,
      authoritySurfaceClassificationId:
        persistedClassificationId,
      preArtifactAuthorityStateSha256,
      postArtifactAuthorityStateSha256,
      postArtifactAuthorityRevision:
        input.postArtifactAuthorityState.revision,
    })
  );

  return {
    accepted: true,
    verificationId,
    artifactId,
    preArtifactAuthorityStateSha256,
    postArtifactAuthorityStateSha256,
    postArtifactAuthorityRevision:
      input.postArtifactAuthorityState.revision,
  };
}