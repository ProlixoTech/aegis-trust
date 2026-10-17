import { createHash } from "crypto";

import type {
  AegisUiState,
  SafetyKernelV31CapabilityManifest,
} from "../packages/aegis-core";
import {
  SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH,
} from "../packages/aegis-core";
import type { ProtectedTarget } from "../packages/aegis-core";

export const CANONICAL_AUTHORITY_SCHEMA_VERSION = "1.0.0";
export const CANONICAL_AUTHORITY_DECISION_SCHEMA_VERSION = "1.0.0";
export const CANONICAL_AUTHORITY_RULESET_VERSION = "bundled-local-ruleset-v1";
export const CANONICAL_PROJECT_IDENTITY = "prolixo-aegis-personal";
export const CANONICAL_AUTHORITY_SNAPSHOT_ENVELOPE_SCHEMA_VERSION = "1.0.0";

export type CanonicalAuthorityVerificationResult =
  | "UNVERIFIED"
  | "VERIFIED"
  | "FAILED";

export type CanonicalAuthorityNonceState =
  | "NONE"
  | "ISSUED"
  | "WARN_PENDING"
  | "CONSUMED"
  | "CANCELLED"
  | "TIMED_OUT";

export interface CanonicalAuthorityDecisionScope {
  readonly decisionSchemaVersion: string;
  readonly rulesetVersion: string;
  readonly policyVersion: string;
  readonly checkerVersions: Readonly<Record<string, string>>;
  readonly capabilityManifestVersion: string;
  readonly coveredScope: readonly string[];
  readonly timestamp: string;
}

export interface CanonicalAuthorityState {
  readonly schemaVersion: string;
  readonly revision: number;
  readonly projectIdentity: string;
  readonly workspaceId: string;
  readonly safeBaselineId: string | null;
  readonly protectedTargets: readonly string[];
  readonly capabilityManifestId: string;
  readonly capabilityManifestVersion: string;
  readonly policyVersion: string;
  readonly rulesetVersion: string;
  readonly actionId: string | null;
  readonly sessionId: string | null;
  readonly approvalNonceSha256: string | null;
  readonly approvalNonceState: CanonicalAuthorityNonceState;
  readonly currentArtifactId: string | null;
  readonly recoveryPackageId: string | null;
  readonly receiptId: string | null;
  readonly ledgerHeadHash: string | null;
  readonly verificationResult: CanonicalAuthorityVerificationResult;
  readonly userVisibleState: AegisUiState["status"];
  readonly decisionScope: CanonicalAuthorityDecisionScope;
  readonly productPass: false;
  readonly releaseReady: false;
  readonly uploadReady: false;
  readonly finalArtifactCreated: false;
}

export interface CanonicalAuthorityStateSnapshotEnvelope {
  readonly envelopeSchemaVersion: string;
  readonly stateSchemaVersion: string;
  readonly projectIdentity: string;
  readonly payloadSha256: string;
  readonly state: CanonicalAuthorityState;
}

export interface CanonicalAuthorityStateCreateInput {
  readonly workspaceId: string;
  readonly protectedTargets: ReadonlyArray<ProtectedTarget>;
  readonly initialUserVisibleState: AegisUiState["status"];
  readonly capabilityManifest?: SafetyKernelV31CapabilityManifest;
  readonly timestamp?: string;
}

export interface CanonicalAuthorityStatePatch {
  readonly safeBaselineId?: string | null;
  readonly actionId?: string | null;
  readonly sessionId?: string | null;
  readonly approvalNonceSha256?: string | null;
  readonly approvalNonceState?: CanonicalAuthorityNonceState;
  readonly currentArtifactId?: string | null;
  readonly recoveryPackageId?: string | null;
  readonly receiptId?: string | null;
  readonly ledgerHeadHash?: string | null;
  readonly verificationResult?: CanonicalAuthorityVerificationResult;
  readonly userVisibleState?: AegisUiState["status"];
}

export type CanonicalAuthorityKernelLifecyclePhase =
  | "ALLOW_PENDING_EXECUTION"
  | "WARN_PENDING"
  | "BLOCKED"
  | "REQUIRE_REVIEW"
  | "SPLIT_REQUIRED"
  | "CONSUMED";

export type CanonicalAuthorityKernelTerminalReason =
  | "cancel_by_user"
  | "timeout_expired"
  | null;

export interface CanonicalAuthorityKernelSyncInput {
  readonly actionId: string;
  readonly sessionId: string | null;
  readonly approvalNonceSha256: string;
  readonly lifecyclePhase: CanonicalAuthorityKernelLifecyclePhase;
  readonly terminalReason?: CanonicalAuthorityKernelTerminalReason;
}

function requireInlineIdentifier(value: string, errorCode: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 200 || /[\r\n]/.test(normalized)) {
    throw new Error(errorCode);
  }
  return normalized;
}

function requireNullableIdentifier(
  value: string | null,
  errorCode: string
): string | null {
  return value === null ? null : requireInlineIdentifier(value, errorCode);
}

function requireTimestamp(value: string): string {
  if (!value || Number.isNaN(Date.parse(value))) {
    throw new Error("INVALID_AUTHORITY_TIMESTAMP");
  }
  return value;
}

function validateCapabilityManifest(
  manifest: SafetyKernelV31CapabilityManifest
): void {
  requireInlineIdentifier(manifest.manifest_id, "INVALID_CAPABILITY_MANIFEST_ID");
  requireInlineIdentifier(
    manifest.manifest_version,
    "INVALID_CAPABILITY_MANIFEST_VERSION"
  );
  requireInlineIdentifier(
    manifest.policy_version,
    "INVALID_CAPABILITY_POLICY_VERSION"
  );

  if (
    manifest.source_of_truth !== "local_client_capability_manifest" ||
    manifest.server_may_only_narrow_or_add_allowed_capabilities !== true ||
    manifest.server_cannot_grant_bypass !== true ||
    !manifest.non_overridable_invariants.includes("deny_by_default")
  ) {
    throw new Error("INVALID_CAPABILITY_MANIFEST_AUTHORITY");
  }

  if (manifest.trusted_capabilities.length === 0) {
    throw new Error("INVALID_CAPABILITY_MANIFEST_EMPTY");
  }

  const ids = new Set<string>();
  for (const entry of manifest.trusted_capabilities) {
    const id = requireInlineIdentifier(
      entry.capability_id,
      "INVALID_CAPABILITY_ID"
    );
    if (ids.has(id)) throw new Error("DUPLICATE_CAPABILITY_ID");
    ids.add(id);

    requireInlineIdentifier(
      entry.action_kind,
      "INVALID_CAPABILITY_ACTION_KIND"
    );
    requireInlineIdentifier(
      entry.handler_id,
      "INVALID_CAPABILITY_HANDLER_ID"
    );
    if (
      !Array.isArray(entry.artifact_kinds) ||
      !Array.isArray(entry.command_template_hashes)
    ) {
      throw new Error(
        "INVALID_CAPABILITY_TEMPLATE_OR_ARTIFACT_BOUNDARY"
      );
    }
    for (const value of [
      ...entry.artifact_kinds,
      ...entry.command_template_hashes,
    ]) {
      requireInlineIdentifier(
        value,
        "INVALID_CAPABILITY_DECLARATION"
      );
    }
    if (
      entry.allowed_sources.length === 0 ||
      !entry.non_overridable_invariants.includes("deny_by_default") ||
      ![
        "review_output_only",
        "terminal_text_insert_only",
      ].includes(entry.effect_scope) ||
      entry.target_scope !== "workspace_only" ||
      entry.approval_requirement !==
        "safety_kernel_review_required"
    ) {
      throw new Error("INVALID_CAPABILITY_BOUNDARY");
    }
  }
}

function normalizeProtectedTargets(
  targets: ReadonlyArray<ProtectedTarget>
): readonly string[] {
  if (targets.length === 0) {
    throw new Error("EMPTY_PROTECTED_TARGET_REGISTRY");
  }

  const ids = targets.map(target =>
    requireInlineIdentifier(
      target.target_id,
      "INVALID_PROTECTED_TARGET_ID"
    )
  );

  if (new Set(ids).size !== ids.length) {
    throw new Error("DUPLICATE_PROTECTED_TARGET_ID");
  }

  return Object.freeze([...ids].sort());
}

function cloneState(
  state: CanonicalAuthorityState
): CanonicalAuthorityState {
  return {
    ...state,
    protectedTargets: [...state.protectedTargets],
    decisionScope: {
      ...state.decisionScope,
      checkerVersions: { ...state.decisionScope.checkerVersions },
      coveredScope: [...state.decisionScope.coveredScope],
    },
  };
}

function freezeState(
  state: CanonicalAuthorityState
): CanonicalAuthorityState {
  const decisionScope = Object.freeze({
    ...state.decisionScope,
    checkerVersions: Object.freeze({
      ...state.decisionScope.checkerVersions,
    }),
    coveredScope: Object.freeze([
      ...state.decisionScope.coveredScope,
    ]),
  });

  return Object.freeze({
    ...state,
    protectedTargets: Object.freeze([...state.protectedTargets]),
    decisionScope,
  });
}

function validateReferenceState(
  state: CanonicalAuthorityState
): void {
  requireNullableIdentifier(
    state.safeBaselineId,
    "INVALID_SAFE_BASELINE_ID"
  );
  requireNullableIdentifier(state.actionId, "INVALID_ACTION_ID");
  requireNullableIdentifier(state.sessionId, "INVALID_SESSION_ID");
  requireNullableIdentifier(
    state.currentArtifactId,
    "INVALID_CURRENT_ARTIFACT_ID"
  );
  requireNullableIdentifier(
    state.recoveryPackageId,
    "INVALID_RECOVERY_PACKAGE_ID"
  );
  requireNullableIdentifier(state.receiptId, "INVALID_RECEIPT_ID");
  requireNullableIdentifier(
    state.ledgerHeadHash,
    "INVALID_LEDGER_HEAD_HASH"
  );

  if (
    state.approvalNonceSha256 !== null &&
    !/^sha256:[a-f0-9]{64}$/.test(state.approvalNonceSha256)
  ) {
    throw new Error("INVALID_APPROVAL_NONCE_SHA256");
  }

  if (
    (state.approvalNonceState === "NONE") !==
    (state.approvalNonceSha256 === null)
  ) {
    throw new Error("NONCE_STATE_HASH_MISMATCH");
  }
}

const CANONICAL_AUTHORITY_STATE_KEYS = Object.freeze([
  "schemaVersion",
  "revision",
  "projectIdentity",
  "workspaceId",
  "safeBaselineId",
  "protectedTargets",
  "capabilityManifestId",
  "capabilityManifestVersion",
  "policyVersion",
  "rulesetVersion",
  "actionId",
  "sessionId",
  "approvalNonceSha256",
  "approvalNonceState",
  "currentArtifactId",
  "recoveryPackageId",
  "receiptId",
  "ledgerHeadHash",
  "verificationResult",
  "userVisibleState",
  "decisionScope",
  "productPass",
  "releaseReady",
  "uploadReady",
  "finalArtifactCreated",
]);

const CANONICAL_AUTHORITY_DECISION_SCOPE_KEYS = Object.freeze([
  "decisionSchemaVersion",
  "rulesetVersion",
  "policyVersion",
  "checkerVersions",
  "capabilityManifestVersion",
  "coveredScope",
  "timestamp",
]);

const CANONICAL_AUTHORITY_SNAPSHOT_ENVELOPE_KEYS = Object.freeze([
  "envelopeSchemaVersion",
  "stateSchemaVersion",
  "projectIdentity",
  "payloadSha256",
  "state",
]);

const CANONICAL_AUTHORITY_VERIFICATION_RESULTS =
  new Set<string>([
    "UNVERIFIED",
    "VERIFIED",
    "FAILED",
  ]);

const CANONICAL_AUTHORITY_NONCE_STATES =
  new Set<string>([
    "NONE",
    "ISSUED",
    "WARN_PENDING",
    "CONSUMED",
    "CANCELLED",
    "TIMED_OUT",
  ]);

const CANONICAL_AUTHORITY_UI_STATES =
  new Set<string>([
    "SAFE",
    "WARNING",
    "BLOCKED",
    "RESTORING",
  ]);

function requireSnapshotRecord(
  value: unknown,
  errorCode: string
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new Error(errorCode);
  }

  return value as Record<string, unknown>;
}

function requireSnapshotExactKeys(
  value: Record<string, unknown>,
  expectedKeys: readonly string[],
  errorCode: string
): void {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();

  if (
    actual.length !== expected.length ||
    actual.some(
      (key, index) =>
        key !== expected[index]
    )
  ) {
    throw new Error(errorCode);
  }
}

function requireSnapshotInlineIdentifier(
  value: unknown,
  errorCode: string
): string {
  if (typeof value !== "string") {
    throw new Error(errorCode);
  }

  return requireInlineIdentifier(
    value,
    errorCode
  );
}

function requireSnapshotNullableIdentifier(
  value: unknown,
  errorCode: string
): string | null {
  if (value === null) {
    return null;
  }

  return requireSnapshotInlineIdentifier(
    value,
    errorCode
  );
}

function requireSnapshotRevision(
  value: unknown
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new Error(
      "INVALID_CANONICAL_AUTHORITY_REVISION"
    );
  }

  return value;
}

function requireSnapshotIdentifierArray(
  value: unknown,
  errorCode: string,
  requireSorted: boolean
): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.length === 0
  ) {
    throw new Error(errorCode);
  }

  const normalized =
    value.map(entry =>
      requireSnapshotInlineIdentifier(
        entry,
        errorCode
      )
    );

  if (
    new Set(normalized).size !==
    normalized.length
  ) {
    throw new Error(
      errorCode + "_DUPLICATE"
    );
  }

  if (requireSorted) {
    const sorted = [...normalized].sort();

    if (
      normalized.some(
        (entry, index) =>
          entry !== sorted[index]
      )
    ) {
      throw new Error(
        "CANONICAL_AUTHORITY_PROTECTED_TARGETS_NOT_SORTED"
      );
    }
  }

  return Object.freeze([
    ...normalized,
  ]);
}

function requireSnapshotCheckerVersions(
  value: unknown
): Readonly<Record<string, string>> {
  const record =
    requireSnapshotRecord(
      value,
      "INVALID_CANONICAL_AUTHORITY_CHECKER_VERSIONS"
    );

  const normalized:
    Record<string, string> = {};

  for (
    const rawKey of
    Object.keys(record).sort()
  ) {
    const key =
      requireInlineIdentifier(
        rawKey,
        "INVALID_CANONICAL_AUTHORITY_CHECKER_ID"
      );

    if (
      key === "__proto__" ||
      key === "prototype" ||
      key === "constructor" ||
      Object.prototype.hasOwnProperty.call(
        normalized,
        key
      )
    ) {
      throw new Error(
        "INVALID_CANONICAL_AUTHORITY_CHECKER_ID"
      );
    }

    normalized[key] =
      requireSnapshotInlineIdentifier(
        record[rawKey],
        "INVALID_CANONICAL_AUTHORITY_CHECKER_VERSION"
      );
  }

  return Object.freeze({
    ...normalized,
  });
}

function stableSnapshotStringify(
  value: unknown
): string {
  if (value === null) {
    return "null";
  }

  if (
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(
        "INVALID_CANONICAL_AUTHORITY_SNAPSHOT_NUMBER"
      );
    }

    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return (
      "[" +
      value
        .map(entry =>
          stableSnapshotStringify(entry)
        )
        .join(",") +
      "]"
    );
  }

  if (
    typeof value === "object" &&
    value !== null
  ) {
    const record =
      value as Record<string, unknown>;

    return (
      "{" +
      Object.keys(record)
        .sort()
        .map(
          key =>
            JSON.stringify(key) +
            ":" +
            stableSnapshotStringify(
              record[key]
            )
        )
        .join(",") +
      "}"
    );
  }

  throw new Error(
    "UNSUPPORTED_CANONICAL_AUTHORITY_SNAPSHOT_VALUE"
  );
}

function validateCanonicalAuthoritySnapshotState(
  value: unknown
): CanonicalAuthorityState {
  const record =
    requireSnapshotRecord(
      value,
      "MALFORMED_CANONICAL_AUTHORITY_STATE"
    );

  requireSnapshotExactKeys(
    record,
    CANONICAL_AUTHORITY_STATE_KEYS,
    "INVALID_CANONICAL_AUTHORITY_STATE_KEYS"
  );

  if (
    record.schemaVersion !==
    CANONICAL_AUTHORITY_SCHEMA_VERSION
  ) {
    throw new Error(
      "UNSUPPORTED_CANONICAL_AUTHORITY_SCHEMA_VERSION"
    );
  }

  if (
    record.projectIdentity !==
    CANONICAL_PROJECT_IDENTITY
  ) {
    throw new Error(
      "INVALID_CANONICAL_AUTHORITY_PROJECT_IDENTITY"
    );
  }

  const workspaceId =
    requireSnapshotInlineIdentifier(
      record.workspaceId,
      "INVALID_WORKSPACE_ID"
    );

  if (
    !/^sha256:[a-f0-9]{64}$/.test(
      workspaceId
    )
  ) {
    throw new Error(
      "INVALID_WORKSPACE_ID"
    );
  }

  const protectedTargets =
    requireSnapshotIdentifierArray(
      record.protectedTargets,
      "INVALID_CANONICAL_AUTHORITY_PROTECTED_TARGETS",
      true
    );

  const capabilityManifestId =
    requireSnapshotInlineIdentifier(
      record.capabilityManifestId,
      "INVALID_CAPABILITY_MANIFEST_ID"
    );

  const capabilityManifestVersion =
    requireSnapshotInlineIdentifier(
      record.capabilityManifestVersion,
      "INVALID_CAPABILITY_MANIFEST_VERSION"
    );

  const policyVersion =
    requireSnapshotInlineIdentifier(
      record.policyVersion,
      "INVALID_CAPABILITY_POLICY_VERSION"
    );

  if (
    capabilityManifestId !==
      SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH.manifest_id ||
    capabilityManifestVersion !==
      SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH.manifest_version ||
    policyVersion !==
      SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH.policy_version
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_CAPABILITY_BINDING_MISMATCH"
    );
  }

  const rulesetVersion =
    requireSnapshotInlineIdentifier(
      record.rulesetVersion,
      "INVALID_CANONICAL_AUTHORITY_RULESET_VERSION"
    );

  if (
    rulesetVersion !==
    CANONICAL_AUTHORITY_RULESET_VERSION
  ) {
    throw new Error(
      "UNSUPPORTED_CANONICAL_AUTHORITY_RULESET_VERSION"
    );
  }

  const approvalNonceState =
    requireSnapshotInlineIdentifier(
      record.approvalNonceState,
      "INVALID_CANONICAL_AUTHORITY_NONCE_STATE"
    );

  if (
    !CANONICAL_AUTHORITY_NONCE_STATES.has(
      approvalNonceState
    )
  ) {
    throw new Error(
      "INVALID_CANONICAL_AUTHORITY_NONCE_STATE"
    );
  }

  const verificationResult =
    requireSnapshotInlineIdentifier(
      record.verificationResult,
      "INVALID_CANONICAL_AUTHORITY_VERIFICATION_RESULT"
    );

  if (
    !CANONICAL_AUTHORITY_VERIFICATION_RESULTS.has(
      verificationResult
    )
  ) {
    throw new Error(
      "INVALID_CANONICAL_AUTHORITY_VERIFICATION_RESULT"
    );
  }

  const userVisibleState =
    requireSnapshotInlineIdentifier(
      record.userVisibleState,
      "INVALID_CANONICAL_AUTHORITY_USER_VISIBLE_STATE"
    );

  if (
    !CANONICAL_AUTHORITY_UI_STATES.has(
      userVisibleState
    )
  ) {
    throw new Error(
      "INVALID_CANONICAL_AUTHORITY_USER_VISIBLE_STATE"
    );
  }

  if (
    record.productPass !== false ||
    record.releaseReady !== false ||
    record.uploadReady !== false ||
    record.finalArtifactCreated !== false
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_RELEASE_CLAIM_FORBIDDEN"
    );
  }

  const decisionRecord =
    requireSnapshotRecord(
      record.decisionScope,
      "MALFORMED_CANONICAL_AUTHORITY_DECISION_SCOPE"
    );

  requireSnapshotExactKeys(
    decisionRecord,
    CANONICAL_AUTHORITY_DECISION_SCOPE_KEYS,
    "INVALID_CANONICAL_AUTHORITY_DECISION_SCOPE_KEYS"
  );

  if (
    decisionRecord.decisionSchemaVersion !==
    CANONICAL_AUTHORITY_DECISION_SCHEMA_VERSION
  ) {
    throw new Error(
      "UNSUPPORTED_CANONICAL_AUTHORITY_DECISION_SCHEMA_VERSION"
    );
  }

  if (
    decisionRecord.rulesetVersion !==
    rulesetVersion
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_DECISION_RULESET_MISMATCH"
    );
  }

  if (
    decisionRecord.policyVersion !==
    policyVersion
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_DECISION_POLICY_MISMATCH"
    );
  }

  if (
    decisionRecord.capabilityManifestVersion !==
    capabilityManifestVersion
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_DECISION_MANIFEST_MISMATCH"
    );
  }

  const coveredScope =
    requireSnapshotIdentifierArray(
      decisionRecord.coveredScope,
      "INVALID_CANONICAL_AUTHORITY_COVERED_SCOPE",
      false
    );

  if (
    !coveredScope.includes(
      "L2_CANONICAL_AUTHORITY_STATE"
    )
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_SCOPE_MISSING"
    );
  }

  const state: CanonicalAuthorityState = {
    schemaVersion:
      CANONICAL_AUTHORITY_SCHEMA_VERSION,

    revision:
      requireSnapshotRevision(
        record.revision
      ),

    projectIdentity:
      CANONICAL_PROJECT_IDENTITY,

    workspaceId,

    safeBaselineId:
      requireSnapshotNullableIdentifier(
        record.safeBaselineId,
        "INVALID_SAFE_BASELINE_ID"
      ),

    protectedTargets,
    capabilityManifestId,
    capabilityManifestVersion,
    policyVersion,
    rulesetVersion,

    actionId:
      requireSnapshotNullableIdentifier(
        record.actionId,
        "INVALID_ACTION_ID"
      ),

    sessionId:
      requireSnapshotNullableIdentifier(
        record.sessionId,
        "INVALID_SESSION_ID"
      ),

    approvalNonceSha256:
      requireSnapshotNullableIdentifier(
        record.approvalNonceSha256,
        "INVALID_APPROVAL_NONCE_SHA256"
      ),

    approvalNonceState: approvalNonceState as CanonicalAuthorityNonceState,

    currentArtifactId:
      requireSnapshotNullableIdentifier(
        record.currentArtifactId,
        "INVALID_CURRENT_ARTIFACT_ID"
      ),

    recoveryPackageId:
      requireSnapshotNullableIdentifier(
        record.recoveryPackageId,
        "INVALID_RECOVERY_PACKAGE_ID"
      ),

    receiptId:
      requireSnapshotNullableIdentifier(
        record.receiptId,
        "INVALID_RECEIPT_ID"
      ),

    ledgerHeadHash:
      requireSnapshotNullableIdentifier(
        record.ledgerHeadHash,
        "INVALID_LEDGER_HEAD_HASH"
      ),

    verificationResult: verificationResult as CanonicalAuthorityVerificationResult,

    userVisibleState: userVisibleState as AegisUiState["status"],

    decisionScope: {
      decisionSchemaVersion:
        CANONICAL_AUTHORITY_DECISION_SCHEMA_VERSION,

      rulesetVersion,
      policyVersion,

      checkerVersions:
        requireSnapshotCheckerVersions(
          decisionRecord.checkerVersions
        ),

      capabilityManifestVersion,
      coveredScope,

      timestamp:
        requireTimestamp(
          requireSnapshotInlineIdentifier(
            decisionRecord.timestamp,
            "INVALID_AUTHORITY_TIMESTAMP"
          )
        ),
    },

    productPass: false,
    releaseReady: false,
    uploadReady: false,
    finalArtifactCreated: false,
  };

  validateReferenceState(state);

  return freezeState(state);
}

function canonicalAuthoritySnapshotPayloadSha256(
  state: CanonicalAuthorityState
): string {
  return (
    "sha256:" +
    createHash("sha256")
      .update(
        stableSnapshotStringify(state),
        "utf8"
      )
      .digest("hex")
  );
}

function validateCanonicalAuthoritySnapshotEnvelope(
  value: unknown
): CanonicalAuthorityState {
  const envelope =
    requireSnapshotRecord(
      value,
      "MALFORMED_CANONICAL_AUTHORITY_SNAPSHOT_ENVELOPE"
    );

  requireSnapshotExactKeys(
    envelope,
    CANONICAL_AUTHORITY_SNAPSHOT_ENVELOPE_KEYS,
    "INVALID_CANONICAL_AUTHORITY_SNAPSHOT_ENVELOPE_KEYS"
  );

  if (
    envelope.envelopeSchemaVersion !==
    CANONICAL_AUTHORITY_SNAPSHOT_ENVELOPE_SCHEMA_VERSION
  ) {
    throw new Error(
      "UNSUPPORTED_CANONICAL_AUTHORITY_SNAPSHOT_ENVELOPE_SCHEMA_VERSION"
    );
  }

  const state =
    validateCanonicalAuthoritySnapshotState(
      envelope.state
    );

  if (
    envelope.stateSchemaVersion !==
    state.schemaVersion
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_SNAPSHOT_STATE_SCHEMA_MISMATCH"
    );
  }

  if (
    envelope.projectIdentity !==
    state.projectIdentity
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_SNAPSHOT_PROJECT_IDENTITY_MISMATCH"
    );
  }

  if (
    typeof envelope.payloadSha256 !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(
      envelope.payloadSha256
    )
  ) {
    throw new Error(
      "INVALID_CANONICAL_AUTHORITY_SNAPSHOT_HASH"
    );
  }

  const expectedHash =
    canonicalAuthoritySnapshotPayloadSha256(
      state
    );

  if (
    envelope.payloadSha256 !==
    expectedHash
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_SNAPSHOT_HASH_MISMATCH"
    );
  }

  return state;
}

export class CanonicalAuthorityStateStore {
  private state: CanonicalAuthorityState;

  private constructor(state: CanonicalAuthorityState) {
    this.state = freezeState(state);
  }

  static create(
    input: CanonicalAuthorityStateCreateInput
  ): CanonicalAuthorityStateStore {
    const manifest =
      input.capabilityManifest ??
      SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH;

    validateCapabilityManifest(manifest);

    const workspaceId = requireInlineIdentifier(
      input.workspaceId,
      "INVALID_WORKSPACE_ID"
    );
    if (!/^sha256:[a-f0-9]{64}$/.test(workspaceId)) {
      throw new Error("INVALID_WORKSPACE_ID");
    }

    const timestamp = requireTimestamp(
      input.timestamp ?? new Date().toISOString()
    );

    return new CanonicalAuthorityStateStore({
      schemaVersion: CANONICAL_AUTHORITY_SCHEMA_VERSION,
      revision: 0,
      projectIdentity: CANONICAL_PROJECT_IDENTITY,
      workspaceId,
      safeBaselineId: null,
      protectedTargets: normalizeProtectedTargets(
        input.protectedTargets
      ),
      capabilityManifestId: manifest.manifest_id,
      capabilityManifestVersion: manifest.manifest_version,
      policyVersion: manifest.policy_version,
      rulesetVersion: CANONICAL_AUTHORITY_RULESET_VERSION,
      actionId: null,
      sessionId: null,
      approvalNonceSha256: null,
      approvalNonceState: "NONE",
      currentArtifactId: null,
      recoveryPackageId: null,
      receiptId: null,
      ledgerHeadHash: null,
      verificationResult: "UNVERIFIED",
      userVisibleState: input.initialUserVisibleState,
      decisionScope: {
        decisionSchemaVersion:
          CANONICAL_AUTHORITY_DECISION_SCHEMA_VERSION,
        rulesetVersion: CANONICAL_AUTHORITY_RULESET_VERSION,
        policyVersion: manifest.policy_version,
        checkerVersions: {},
        capabilityManifestVersion: manifest.manifest_version,
        coveredScope: ["L2_CANONICAL_AUTHORITY_STATE"],
        timestamp,
      },
      productPass: false,
      releaseReady: false,
      uploadReady: false,
      finalArtifactCreated: false,
    });
  }

  getState(): CanonicalAuthorityState {
    return cloneState(this.state);
  }

  static hydrateSnapshot(
    envelope: unknown
  ): CanonicalAuthorityStateStore {
    return new CanonicalAuthorityStateStore(
      validateCanonicalAuthoritySnapshotEnvelope(
        envelope
      )
    );
  }

  static hydrateSnapshotJson(
    serializedEnvelope: string
  ): CanonicalAuthorityStateStore {
    if (
      typeof serializedEnvelope !== "string" ||
      serializedEnvelope.trim().length === 0
    ) {
      throw new Error(
        "INVALID_CANONICAL_AUTHORITY_SNAPSHOT_JSON"
      );
    }

    let parsed: unknown;

    try {
      parsed = JSON.parse(
        serializedEnvelope
      );
    } catch {
      throw new Error(
        "INVALID_CANONICAL_AUTHORITY_SNAPSHOT_JSON"
      );
    }

    return CanonicalAuthorityStateStore
      .hydrateSnapshot(parsed);
  }

  exportSnapshotEnvelope():
    CanonicalAuthorityStateSnapshotEnvelope {
    const state =
      validateCanonicalAuthoritySnapshotState(
        cloneState(this.state)
      );

    return Object.freeze({
      envelopeSchemaVersion:
        CANONICAL_AUTHORITY_SNAPSHOT_ENVELOPE_SCHEMA_VERSION,

      stateSchemaVersion:
        state.schemaVersion,

      projectIdentity:
        state.projectIdentity,

      payloadSha256:
        canonicalAuthoritySnapshotPayloadSha256(
          state
        ),

      state,
    });
  }

  serializeSnapshotEnvelope(): string {
    return stableSnapshotStringify(
      this.exportSnapshotEnvelope()
    );
  }

  update(
    expectedRevision: number,
    patch: CanonicalAuthorityStatePatch,
    timestamp = new Date().toISOString()
  ): CanonicalAuthorityState {
    if (expectedRevision !== this.state.revision) {
      throw new Error("STALE_CANONICAL_AUTHORITY_REVISION");
    }
    if (Object.keys(patch).length === 0) {
      throw new Error("EMPTY_CANONICAL_AUTHORITY_PATCH");
    }

    const next: CanonicalAuthorityState = {
      ...this.state,
      ...patch,
      revision: this.state.revision + 1,
      decisionScope: {
        ...this.state.decisionScope,
        timestamp: requireTimestamp(timestamp),
      },
      productPass: false,
      releaseReady: false,
      uploadReady: false,
      finalArtifactCreated: false,
    };

    this.state =
      validateCanonicalAuthoritySnapshotState(
        next
      );

    return this.getState();
  }

  synchronizeSafetyKernelState(
    input: CanonicalAuthorityKernelSyncInput,
    timestamp = new Date().toISOString()
  ): CanonicalAuthorityState {
    const actionId = requireInlineIdentifier(
      input.actionId,
      "INVALID_ACTION_ID"
    );
    const rawHash = input.approvalNonceSha256.trim();
    const approvalNonceSha256 =
      /^[a-f0-9]{64}$/.test(rawHash)
        ? "sha256:" + rawHash
        : rawHash;

    if (!/^sha256:[a-f0-9]{64}$/.test(approvalNonceSha256)) {
      throw new Error("INVALID_APPROVAL_NONCE_SHA256");
    }

    const pending =
      input.lifecyclePhase === "ALLOW_PENDING_EXECUTION" ||
      input.lifecyclePhase === "WARN_PENDING";
    let sessionId: string | null = null;

    if (pending) {
      sessionId = requireNullableIdentifier(
        input.sessionId,
        "INVALID_SESSION_ID"
      );
      if (sessionId === null) {
        throw new Error("PENDING_KERNEL_SESSION_REQUIRED");
      }
    } else if (input.sessionId !== null) {
      throw new Error("TERMINAL_KERNEL_SESSION_FORBIDDEN");
    }

    const terminalReason = input.terminalReason ?? null;
    if (
      terminalReason !== null &&
      input.lifecyclePhase !== "CONSUMED"
    ) {
      throw new Error("INVALID_KERNEL_TERMINAL_REASON");
    }

    let approvalNonceState: CanonicalAuthorityNonceState;
    if (input.lifecyclePhase === "WARN_PENDING") {
      approvalNonceState = "WARN_PENDING";
    } else if (
      input.lifecyclePhase === "ALLOW_PENDING_EXECUTION"
    ) {
      approvalNonceState = "ISSUED";
    } else if (terminalReason === "cancel_by_user") {
      approvalNonceState = "CANCELLED";
    } else if (terminalReason === "timeout_expired") {
      approvalNonceState = "TIMED_OUT";
    } else {
      approvalNonceState = "CONSUMED";
    }

    return this.update(
      this.state.revision,
      {
        actionId,
        sessionId,
        approvalNonceSha256,
        approvalNonceState,
      },
      timestamp
    );
  }

  synchronizeUserVisibleState(
    userVisibleState: AegisUiState["status"],
    timestamp = new Date().toISOString()
  ): CanonicalAuthorityState {
    return this.update(
      this.state.revision,
      { userVisibleState },
      timestamp
    );
  }
}
