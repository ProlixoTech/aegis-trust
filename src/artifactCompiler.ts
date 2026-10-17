import { createHash } from "node:crypto";
import type { CanonicalAuthorityState } from "./canonicalAuthorityState";

export const ARTIFACT_MANIFEST_SCHEMA_VERSION = "1.0.0";

export interface ArtifactCompilerEntryInput {
  readonly path: string;
  readonly contentSha256: string;
  readonly byteLength: number;
}

export interface ArtifactCompilerInput {
  readonly artifactKind: string;
  readonly authorityState: CanonicalAuthorityState;
  readonly entries: readonly ArtifactCompilerEntryInput[];
}

export interface CompiledArtifactManifestEntry {
  readonly path: string;
  readonly contentSha256: string;
  readonly byteLength: number;
}

export interface CompiledArtifactManifest {
  readonly schemaVersion: typeof ARTIFACT_MANIFEST_SCHEMA_VERSION;
  readonly artifactKind: string;
  readonly projectIdentity: string;
  readonly workspaceId: string;
  readonly authorityRevision: number;
  readonly authorityStateSha256: string;
  readonly entries: readonly CompiledArtifactManifestEntry[];
}

export interface CompiledArtifact {
  readonly artifactId: string;
  readonly canonicalManifestJson: string;
  readonly manifest: CompiledArtifactManifest;
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

function normalizeSha256(
  value: string,
  errorCode: string
): string {
  const normalized = value.trim().toLowerCase();
  const prefixed = /^[a-f0-9]{64}$/.test(normalized)
    ? `sha256:${normalized}`
    : normalized;

  if (!/^sha256:[a-f0-9]{64}$/.test(prefixed)) {
    throw new Error(errorCode);
  }

  return prefixed;
}

function normalizeArtifactPath(value: string): string {
  const normalized = value.trim();

  if (
    !normalized ||
    normalized.startsWith("/") ||
    /^[a-zA-Z]:[\\/]/.test(normalized) ||
    normalized.includes("\\") ||
    /[\r\n\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new Error("INVALID_ARTIFACT_ENTRY_PATH");
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
    throw new Error("INVALID_ARTIFACT_ENTRY_PATH");
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

function validateAuthorityState(
  state: CanonicalAuthorityState
): void {
  requireInlineIdentifier(
    state.schemaVersion,
    "INVALID_AUTHORITY_SCHEMA_VERSION"
  );
  requireInlineIdentifier(
    state.projectIdentity,
    "INVALID_AUTHORITY_PROJECT_IDENTITY"
  );
  requireInlineIdentifier(
    state.workspaceId,
    "INVALID_AUTHORITY_WORKSPACE_ID"
  );

  if (
    !Number.isSafeInteger(state.revision) ||
    state.revision < 0
  ) {
    throw new Error("INVALID_AUTHORITY_REVISION");
  }

  if (
    state.productPass !== false ||
    state.releaseReady !== false ||
    state.uploadReady !== false ||
    state.finalArtifactCreated !== false
  ) {
    throw new Error("UNAUTHORIZED_FINAL_STATE_CLAIM");
  }

  if (
    !Array.isArray(state.protectedTargets) ||
    state.protectedTargets.length === 0
  ) {
    throw new Error("INVALID_AUTHORITY_PROTECTED_TARGETS");
  }
}

export function compileArtifact(
  input: ArtifactCompilerInput
): CompiledArtifact {
  const artifactKind = requireInlineIdentifier(
    input.artifactKind,
    "INVALID_ARTIFACT_KIND"
  );

  validateAuthorityState(input.authorityState);

  if (!Array.isArray(input.entries) || input.entries.length === 0) {
    throw new Error("EMPTY_ARTIFACT_ENTRIES");
  }

  const seenPaths = new Set<string>();

  const entries = input.entries
    .map(entry => {
      const path = normalizeArtifactPath(entry.path);

      if (seenPaths.has(path)) {
        throw new Error("DUPLICATE_ARTIFACT_ENTRY_PATH");
      }
      seenPaths.add(path);

      if (
        !Number.isSafeInteger(entry.byteLength) ||
        entry.byteLength < 0
      ) {
        throw new Error("INVALID_ARTIFACT_ENTRY_BYTE_LENGTH");
      }

      return {
        path,
        contentSha256: normalizeSha256(
          entry.contentSha256,
          "INVALID_ARTIFACT_ENTRY_SHA256"
        ),
        byteLength: entry.byteLength,
      };
    })
    .sort((left, right) =>
      left.path < right.path
        ? -1
        : left.path > right.path
          ? 1
          : 0
    );

  const authorityStateSha256 = sha256(
    canonicalJson(input.authorityState)
  );

  const manifest: CompiledArtifactManifest = {
    schemaVersion: ARTIFACT_MANIFEST_SCHEMA_VERSION,
    artifactKind,
    projectIdentity: input.authorityState.projectIdentity,
    workspaceId: input.authorityState.workspaceId,
    authorityRevision: input.authorityState.revision,
    authorityStateSha256,
    entries,
  };

  const canonicalManifestJson = canonicalJson(manifest);

  return {
    artifactId: sha256(canonicalManifestJson),
    canonicalManifestJson,
    manifest,
  };
}