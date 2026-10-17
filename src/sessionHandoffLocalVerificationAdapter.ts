import * as crypto from "node:crypto";

import {
  SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION,
  evaluateSessionHandoffRuntimeGate,
  type SessionHandoffOperationClass,
  type SessionHandoffRuntimeGateResult,
  type SessionHandoffVerificationInput,
} from "./sessionHandoffRuntimeGate";

import {
  verifyReceiptLedgerBinding,
} from "../packages/aegis-core";

export const SESSION_HANDOFF_LOCAL_VERIFICATION_ADAPTER_VERSION =
  1 as const;

export type SessionHandoffLocalVerificationAdapterIssueCode =
  | "CAPSULE_INVALID"
  | "CAPSULE_DESCRIPTOR_HASH_MISMATCH"
  | "CAPSULE_PROJECT_IDENTITY_MISMATCH"
  | "CAPSULE_WORKSPACE_IDENTITY_MISMATCH"
  | "CAPSULE_SESSION_ID_MISMATCH"
  | "CAPSULE_NONCE_HASH_MISMATCH"
  | "SIGNER_IDENTITY_MISMATCH"
  | "SIGNATURE_PROVIDER_UNAVAILABLE"
  | "SIGNATURE_VERIFICATION_FAILED"
  | "CAPSULE_FRESHNESS_FAILED"
  | "SESSION_FRESHNESS_FAILED"
  | "CANONICAL_AUTHORITY_STATE_INVALID"
  | "CANONICAL_AUTHORITY_NOT_VERIFIED"
  | "CANONICAL_STATE_READ_FAILED"
  | "CANONICAL_STATE_HASH_MISMATCH"
  | "CHECKER_READ_FAILED"
  | "CHECKER_HASH_MISMATCH"
  | "AUTHORITY_READ_FAILED"
  | "AUTHORITY_HASH_MISMATCH"
  | "CURRENT_STATE_POINTER_READ_FAILED"
  | "CURRENT_STATE_POINTER_HASH_MISMATCH"
  | "SESSION_RECORD_INVALID"
  | "SESSION_NOT_PENDING"
  | "AUTHORITY_BINDING_READ_FAILED"
  | "AUTHORITY_BINDING_INVALID"
  | "AUTHORITY_BINDING_MISMATCH"
  | "AUTHORITY_BINDING_VERIFICATION_FAILED"
  | "REQUIRED_ENTRY_MISSING"
  | "REQUIRED_ENTRY_HASH_MISMATCH"
  | "RECEIPT_READ_FAILED"
  | "LEDGER_READ_FAILED"
  | "RECEIPT_LEDGER_INTEGRITY_FAILED"
  | "SEQUENCE_STORE_UNAVAILABLE"
  | "HANDOFF_SEQUENCE_REPLAY_OR_ROLLBACK"
  | "SEQUENCE_STORE_FAILURE"
  | "CURRENT_STATE_POINTER_FIELD_CLOSURE_FAILED"
  | "UNKNOWN_OPERATION_CLASS"
  | "PROVIDER_FAILURE";

export type SessionHandoffLocalVerificationBytes =
  | string
  | Buffer;

export interface SessionHandoffCurrentStatePointerClosureV1 {
  readonly currentPolicyPointer: string;
  readonly currentRulesetPointer: string;
  readonly currentActionPointer: string;
  readonly currentLockPointer: string;
  readonly currentReceiptPointer: string;
  readonly currentPhase: string;
  readonly currentLock: string;
  readonly currentResultLock: string;
  readonly currentResultLockFile: string;
  readonly policyVersion: string;
  readonly rulesetVersion: string;
  readonly capabilityManifest: string;
}

export interface SessionHandoffVerificationCapsuleUnsignedV1 {
  readonly capsuleSchemaVersion: "1.0.0";
  readonly capsuleKind: "HANDOFF_RESUME";
  readonly firstRequiredAction:
    typeof SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION;
  readonly projectId: string;
  readonly workspaceId: string;
  readonly sessionId: string;
  readonly approvalNonceSha256: string;
  readonly signerId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly handoffSequence: number;
  readonly authorityRevision: number;
  readonly snapshotBindingSha256: string;
  readonly canonicalStateSha256: string;
  readonly checkerSha256: string;
  readonly authoritySha256: string;
  readonly currentStatePointerSha256: string;
  readonly currentStatePointerClosure:
    SessionHandoffCurrentStatePointerClosureV1;
  readonly requiredEntryHashes:
    Readonly<Record<string, string>>;
}

export interface SessionHandoffVerificationCapsuleV1
  extends SessionHandoffVerificationCapsuleUnsignedV1 {
  readonly descriptorHash: string;
  readonly signature: string;
}

export interface SessionHandoffCanonicalAuthorityReader {
  getState(): unknown;
}

export interface SessionHandoffRuntimeSessionReader {
  readSession(sessionId: string): unknown;
}

export interface SessionHandoffAuthorityBindingReadPort {
  readCurrentBinding(): Promise<unknown>;
}

export interface SessionHandoffAuthorityBindingVerificationInput {
  readonly authorityRevision: number;
  readonly workspaceId: string;
  readonly snapshotBindingSha256: string;
  readonly actionId: string;
  readonly sessionId: string;
  readonly approvalNonceSha256: string;
  readonly commandSha256: string;
}

export interface SessionHandoffAuthorityBindingVerifier {
  verify(
    input:
      SessionHandoffAuthorityBindingVerificationInput
  ): Promise<
    | "verified"
    | "authority_drift"
    | "snapshot_failed"
  >;
}

export interface SessionHandoffTrustedSignatureVerifier {
  verify(input: {
    readonly signerId: string;
    readonly descriptorHash: string;
    readonly canonicalPayload: string;
    readonly signature: string;
  }): Promise<boolean>;
}

export interface SessionHandoffPersistentSequenceStore {
  readHighestAcceptedSequence(input: {
    readonly projectId: string;
    readonly signerId: string;
  }): Promise<number | null>;

  claimSequence(input: {
    readonly projectId: string;
    readonly signerId: string;
    readonly sequence: number;
    readonly descriptorHash: string;
  }): Promise<boolean>;
}

export interface SessionHandoffLocalVerificationProviders {
  readonly canonicalAuthorityReader:
    SessionHandoffCanonicalAuthorityReader;

  readonly runtimeSessionReader:
    SessionHandoffRuntimeSessionReader;

  readonly authorityBindingReadPort:
    SessionHandoffAuthorityBindingReadPort;

  readonly authorityBindingVerifier:
    SessionHandoffAuthorityBindingVerifier;

  readonly readCanonicalStateBytes:
    () => Promise<SessionHandoffLocalVerificationBytes>;

  readonly readCheckerBytes:
    () => Promise<SessionHandoffLocalVerificationBytes>;

  readonly readAuthorityBytes:
    () => Promise<SessionHandoffLocalVerificationBytes>;

  readonly readCurrentStatePointerBytes:
    () => Promise<SessionHandoffLocalVerificationBytes>;

  readonly readRequiredEntryBytes:
    (
      entryName: string
    ) => Promise<
      SessionHandoffLocalVerificationBytes | null
    >;

  readonly readReceiptText:
    () => Promise<string>;

  readonly readLedgerText:
    () => Promise<string>;

  readonly now:
    () => Date;

  readonly signatureVerifier?:
    SessionHandoffTrustedSignatureVerifier;

  readonly sequenceStore?:
    SessionHandoffPersistentSequenceStore;
}

export interface SessionHandoffLocalVerificationPolicy {
  readonly expectedProjectId: string;
  readonly expectedSignerIds:
    readonly string[];
  readonly maximumCapsuleAgeMilliseconds: number;
}

export interface SessionHandoffLocalVerificationAdapterInput {
  readonly operationClass: unknown;
  readonly capsuleText: string;
  readonly presentedSessionId: string;
  readonly presentedApprovalNonceSha256: string;
}

export interface SessionHandoffLocalVerificationAdapterResult {
  readonly authorized: boolean;
  readonly bootstrapReadOnlyAllowed: boolean;
  readonly descriptorHash: string | null;
  readonly sequenceClaimed: boolean;
  readonly adapterIssueCodes:
    readonly SessionHandoffLocalVerificationAdapterIssueCode[];
  readonly gateResult:
    SessionHandoffRuntimeGateResult;
  readonly callerVerificationBooleanAccepted: false;
  readonly productPassClaimed: false;
  readonly finalClaimed: false;
  readonly releaseReadyClaimed: false;
  readonly uploadReadyClaimed: false;
}

interface CanonicalAuthorityEvidence {
  readonly projectIdentity: string;
  readonly workspaceId: string;
  readonly revision: number;
  readonly sessionId: string;
  readonly approvalNonceSha256: string;
  readonly approvalNonceState:
    | "NONE"
    | "ISSUED"
    | "WARN_PENDING"
    | "CONSUMED"
    | "CANCELLED"
    | "TIMED_OUT";
  readonly verificationResult:
    | "UNVERIFIED"
    | "VERIFIED"
    | "FAILED";
}

interface RuntimeSessionEvidence {
  readonly sessionId: string;
  readonly approvalNonceSha256: string;
  readonly createdAt: string;
  readonly lifecyclePhase:
    | "WARN_PENDING"
    | "ALLOW_PENDING_EXECUTION"
    | "CONSUMED";
  readonly nonceConsumed: boolean;
  readonly expiresAt: string | null;
}

interface AuthorityBindingEvidence {
  readonly authorityRevision: number;
  readonly workspaceId: string;
  readonly snapshotBindingSha256: string;
}

const KNOWN_OPERATION_CLASSES =
  new Set<SessionHandoffOperationClass>([
    "READ_ONLY",
    "MUTATION",
    "EXECUTE",
    "NETWORK",
    "DELETE",
    "PACKAGE",
    "EXPORT",
  ]);

const EFFECT_OPERATION_CLASSES =
  new Set<SessionHandoffOperationClass>([
    "MUTATION",
    "EXECUTE",
    "NETWORK",
    "DELETE",
    "PACKAGE",
    "EXPORT",
  ]);

const CAPSULE_KEYS =
  new Set([
    "capsuleSchemaVersion",
    "capsuleKind",
    "firstRequiredAction",
    "projectId",
    "workspaceId",
    "sessionId",
    "approvalNonceSha256",
    "signerId",
    "issuedAt",
    "expiresAt",
    "handoffSequence",
    "authorityRevision",
    "snapshotBindingSha256",
    "canonicalStateSha256",
    "checkerSha256",
    "authoritySha256",
    "currentStatePointerSha256",
    "currentStatePointerClosure",
    "requiredEntryHashes",
    "descriptorHash",
    "signature",
  ]);

function isRecord(
  value: unknown
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isNonEmptyInlineString(
  value: unknown
): value is string {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    !/[\r\n\0]/.test(value)
  );
}

function normalizeSha256(
  value: unknown
): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed =
    value.trim().toLowerCase();

  const candidate =
    trimmed.startsWith("sha256:")
      ? trimmed.slice("sha256:".length)
      : trimmed;

  return /^[a-f0-9]{64}$/.test(candidate)
    ? candidate
    : null;
}

function prefixedSha256(
  value: unknown
): string | null {
  const normalized =
    normalizeSha256(value);

  return normalized === null
    ? null
    : "sha256:" + normalized;
}

function asBytes(
  value: unknown
): Buffer | null {
  if (typeof value === "string") {
    return Buffer.from(value, "utf8");
  }

  if (Buffer.isBuffer(value)) {
    return value;
  }

  return null;
}

export function sha256SessionHandoffBytes(
  value: SessionHandoffLocalVerificationBytes
): string {
  const bytes =
    asBytes(value);

  if (bytes === null) {
    throw new Error(
      "INVALID_SESSION_HANDOFF_HASH_INPUT"
    );
  }

  return crypto
    .createHash("sha256")
    .update(bytes)
    .digest("hex");
}

function canonicalizeJson(
  value: unknown
): string {
  if (value === null) {
    return "null";
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (typeof value === "boolean") {
    return value
      ? "true"
      : "false";
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(
        "NON_FINITE_CANONICAL_NUMBER"
      );
    }

    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return (
      "[" +
      value
        .map(item =>
          canonicalizeJson(item)
        )
        .join(",") +
      "]"
    );
  }

  if (isRecord(value)) {
    const keys =
      Object.keys(value).sort();

    return (
      "{" +
      keys
        .map(key =>
          JSON.stringify(key) +
          ":" +
          canonicalizeJson(value[key])
        )
        .join(",") +
      "}"
    );
  }

  throw new Error(
    "UNSUPPORTED_CANONICAL_JSON_VALUE"
  );
}

// NT19_A2_FIELD_LEVEL_CURRENT_STATE_POINTER_CLOSURE

const SESSION_HANDOFF_CURRENT_STATE_POINTER_CLOSURE_KEYS = [
  "currentPolicyPointer",
  "currentRulesetPointer",
  "currentActionPointer",
  "currentLockPointer",
  "currentReceiptPointer",
  "currentPhase",
  "currentLock",
  "currentResultLock",
  "currentResultLockFile",
  "policyVersion",
  "rulesetVersion",
  "capabilityManifest",
] as const;

type SessionHandoffCurrentStatePointerClosureKey =
  typeof SESSION_HANDOFF_CURRENT_STATE_POINTER_CLOSURE_KEYS[number];

const SESSION_HANDOFF_CURRENT_STATE_DOCUMENT_KEY_BY_CLOSURE_KEY:
  Readonly<
    Record<
      SessionHandoffCurrentStatePointerClosureKey,
      string
    >
  > = Object.freeze({
    currentPolicyPointer: "CURRENT_POLICY_POINTER",
    currentRulesetPointer: "CURRENT_RULESET_POINTER",
    currentActionPointer: "CURRENT_ACTION_POINTER",
    currentLockPointer: "CURRENT_LOCK_POINTER",
    currentReceiptPointer: "CURRENT_RECEIPT_POINTER",
    currentPhase: "CURRENT_PHASE",
    currentLock: "CURRENT_LOCK",
    currentResultLock: "CURRENT_RESULT_LOCK",
    currentResultLockFile: "CURRENT_RESULT_LOCK_FILE",
    policyVersion: "POLICY_VERSION",
    rulesetVersion: "RULESET_VERSION",
    capabilityManifest: "CAPABILITY_MANIFEST",
  });

function parseSessionHandoffCurrentStatePointerClosure(
  value: unknown
): SessionHandoffCurrentStatePointerClosureV1 | null {
  if (!isRecord(value)) {
    return null;
  }

  const actualKeys = Object.keys(value).sort();
  const expectedKeys = [
    ...SESSION_HANDOFF_CURRENT_STATE_POINTER_CLOSURE_KEYS,
  ].sort();

  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some(
      (key, index) => key !== expectedKeys[index]
    )
  ) {
    return null;
  }

  const readValue = (
    key: SessionHandoffCurrentStatePointerClosureKey
  ): string | null => {
    const candidate = value[key];

    return (
      isNonEmptyInlineString(candidate) &&
      candidate === candidate.trim()
    )
      ? candidate
      : null;
  };

  const currentPolicyPointer =
    readValue("currentPolicyPointer");
  const currentRulesetPointer =
    readValue("currentRulesetPointer");
  const currentActionPointer =
    readValue("currentActionPointer");
  const currentLockPointer =
    readValue("currentLockPointer");
  const currentReceiptPointer =
    readValue("currentReceiptPointer");
  const currentPhase =
    readValue("currentPhase");
  const currentLock =
    readValue("currentLock");
  const currentResultLock =
    readValue("currentResultLock");
  const currentResultLockFile =
    readValue("currentResultLockFile");
  const policyVersion =
    readValue("policyVersion");
  const rulesetVersion =
    readValue("rulesetVersion");
  const capabilityManifest =
    readValue("capabilityManifest");

  if (
    currentPolicyPointer === null ||
    currentRulesetPointer === null ||
    currentActionPointer === null ||
    currentLockPointer === null ||
    currentReceiptPointer === null ||
    currentPhase === null ||
    currentLock === null ||
    currentResultLock === null ||
    currentResultLockFile === null ||
    policyVersion === null ||
    rulesetVersion === null ||
    capabilityManifest === null
  ) {
    return null;
  }

  return Object.freeze({
    currentPolicyPointer,
    currentRulesetPointer,
    currentActionPointer,
    currentLockPointer,
    currentReceiptPointer,
    currentPhase,
    currentLock,
    currentResultLock,
    currentResultLockFile,
    policyVersion,
    rulesetVersion,
    capabilityManifest,
  });
}

function parseSessionHandoffCurrentStatePointerDocument(
  bytes: SessionHandoffLocalVerificationBytes
): SessionHandoffCurrentStatePointerClosureV1 | null {
  const text = Buffer.isBuffer(bytes)
    ? bytes.toString("utf8")
    : bytes;

  if (text.includes("\u0000")) {
    return null;
  }

  const lines = text
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .split("\n");

  let sectionStart = -1;

  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].trim() === "CURRENT_TASK=C-10") {
      sectionStart = index;
    }
  }

  if (sectionStart < 0) {
    return null;
  }

  let sectionEnd = lines.length;

  for (
    let index = sectionStart + 1;
    index < lines.length;
    index += 1
  ) {
    if (
      lines[index]
        .trim()
        .startsWith("CURRENT_TASK=")
    ) {
      sectionEnd = index;
      break;
    }
  }

  const valuesByDocumentKey =
    new Map<string, string[]>();

  for (
    const documentKey of
      Object.values(
        SESSION_HANDOFF_CURRENT_STATE_DOCUMENT_KEY_BY_CLOSURE_KEY
      )
  ) {
    valuesByDocumentKey.set(documentKey, []);
  }

  for (
    let index = sectionStart + 1;
    index < sectionEnd;
    index += 1
  ) {
    const line = lines[index];
    const separator = line.indexOf("=");

    if (separator < 1) {
      continue;
    }

    const rawKey = line.slice(0, separator);
    const rawValue = line.slice(separator + 1);

    if (rawKey !== rawKey.trim()) {
      continue;
    }

    const matches =
      valuesByDocumentKey.get(rawKey);

    if (matches !== undefined) {
      matches.push(rawValue);
    }
  }

  const candidate:
    Record<string, unknown> = {};

  for (
    const closureKey of
      SESSION_HANDOFF_CURRENT_STATE_POINTER_CLOSURE_KEYS
  ) {
    const documentKey =
      SESSION_HANDOFF_CURRENT_STATE_DOCUMENT_KEY_BY_CLOSURE_KEY[
        closureKey
      ];

    const matches =
      valuesByDocumentKey.get(documentKey) ?? [];

    if (matches.length !== 1) {
      return null;
    }

    candidate[closureKey] = matches[0];
  }

  return parseSessionHandoffCurrentStatePointerClosure(
    candidate
  );
}

function sessionHandoffCurrentStatePointerClosuresEqual(
  expected:
    SessionHandoffCurrentStatePointerClosureV1,
  actual:
    SessionHandoffCurrentStatePointerClosureV1
): boolean {
  return SESSION_HANDOFF_CURRENT_STATE_POINTER_CLOSURE_KEYS
    .every(
      key => expected[key] === actual[key]
    );
}


export function canonicalizeSessionHandoffUnsignedCapsule(
  capsule:
    SessionHandoffVerificationCapsuleUnsignedV1
): string {
  return canonicalizeJson(capsule);
}

export function computeSessionHandoffDescriptorHash(
  capsule:
    SessionHandoffVerificationCapsuleUnsignedV1
): string {
  return sha256SessionHandoffBytes(
    canonicalizeSessionHandoffUnsignedCapsule(
      capsule
    )
  );
}

function toUnsignedCapsule(
  capsule:
    SessionHandoffVerificationCapsuleV1
): SessionHandoffVerificationCapsuleUnsignedV1 {
  return {
    capsuleSchemaVersion:
      capsule.capsuleSchemaVersion,
    capsuleKind:
      capsule.capsuleKind,
    firstRequiredAction:
      capsule.firstRequiredAction,
    projectId:
      capsule.projectId,
    workspaceId:
      capsule.workspaceId,
    sessionId:
      capsule.sessionId,
    approvalNonceSha256:
      capsule.approvalNonceSha256,
    signerId:
      capsule.signerId,
    issuedAt:
      capsule.issuedAt,
    expiresAt:
      capsule.expiresAt,
    handoffSequence:
      capsule.handoffSequence,
    authorityRevision:
      capsule.authorityRevision,
    snapshotBindingSha256:
      capsule.snapshotBindingSha256,
    canonicalStateSha256:
      capsule.canonicalStateSha256,
    checkerSha256:
      capsule.checkerSha256,
    authoritySha256:
      capsule.authoritySha256,
    currentStatePointerSha256:
      capsule.currentStatePointerSha256,
    currentStatePointerClosure:
      capsule.currentStatePointerClosure,
    requiredEntryHashes:
      capsule.requiredEntryHashes,
  };
}

function parseCapsule(
  capsuleText: string
): SessionHandoffVerificationCapsuleV1 | null {
  let parsed: unknown;

  try {
    parsed = JSON.parse(capsuleText);
  } catch {
    return null;
  }

  if (!isRecord(parsed)) {
    return null;
  }

  if (
    Object.keys(parsed).some(
      key => !CAPSULE_KEYS.has(key)
    )
  ) {
    return null;
  }

  if (
    parsed.capsuleSchemaVersion !== "1.0.0" ||
    parsed.capsuleKind !== "HANDOFF_RESUME" ||
    parsed.firstRequiredAction !==
      SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION ||
    !isNonEmptyInlineString(
      parsed.projectId
    ) ||
    !isNonEmptyInlineString(
      parsed.workspaceId
    ) ||
    !isNonEmptyInlineString(
      parsed.sessionId
    ) ||
    !/^[a-f0-9]{48}$/.test(
      parsed.sessionId
    ) ||
    normalizeSha256(
      parsed.approvalNonceSha256
    ) === null ||
    !isNonEmptyInlineString(
      parsed.signerId
    ) ||
    !isNonEmptyInlineString(
      parsed.issuedAt
    ) ||
    !isNonEmptyInlineString(
      parsed.expiresAt
    ) ||
    typeof parsed.handoffSequence !==
      "number" ||
    !Number.isSafeInteger(
      parsed.handoffSequence
    ) ||
    parsed.handoffSequence < 1 ||
    typeof parsed.authorityRevision !==
      "number" ||
    !Number.isSafeInteger(
      parsed.authorityRevision
    ) ||
    parsed.authorityRevision < 0 ||
    normalizeSha256(
      parsed.snapshotBindingSha256
    ) === null ||
    normalizeSha256(
      parsed.canonicalStateSha256
    ) === null ||
    normalizeSha256(
      parsed.checkerSha256
    ) === null ||
    normalizeSha256(
      parsed.authoritySha256
    ) === null ||
    normalizeSha256(
      parsed.currentStatePointerSha256
    ) === null ||
    parseSessionHandoffCurrentStatePointerClosure(
      parsed.currentStatePointerClosure
    ) === null ||
    normalizeSha256(
      parsed.descriptorHash
    ) === null ||
    !isNonEmptyInlineString(
      parsed.signature
    ) ||
    !isRecord(
      parsed.requiredEntryHashes
    )
  ) {
    return null;
  }

  const entryNames =
    Object.keys(
      parsed.requiredEntryHashes
    ).sort();

  if (entryNames.length === 0) {
    return null;
  }

  const requiredEntryHashes:
    Record<string, string> = {};

  for (const entryName of entryNames) {
    if (
      !isNonEmptyInlineString(
        entryName
      ) ||
      entryName.startsWith("/") ||
      entryName.includes("..") ||
      entryName.includes("\\")
    ) {
      return null;
    }

    const entryHash =
      normalizeSha256(
        parsed.requiredEntryHashes[
          entryName
        ]
      );

    if (entryHash === null) {
      return null;
    }

    requiredEntryHashes[entryName] =
      entryHash;
  }

  return {
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction:
      SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION,
    projectId:
      parsed.projectId,
    workspaceId:
      parsed.workspaceId,
    sessionId:
      parsed.sessionId,
    approvalNonceSha256:
      parsed.approvalNonceSha256 as string,
    signerId:
      parsed.signerId,
    issuedAt:
      parsed.issuedAt,
    expiresAt:
      parsed.expiresAt,
    handoffSequence:
      parsed.handoffSequence,
    authorityRevision:
      parsed.authorityRevision,
    snapshotBindingSha256:
      parsed.snapshotBindingSha256 as string,
    canonicalStateSha256:
      parsed.canonicalStateSha256 as string,
    checkerSha256:
      parsed.checkerSha256 as string,
    authoritySha256:
      parsed.authoritySha256 as string,
    currentStatePointerSha256:
      parsed.currentStatePointerSha256 as string,
    currentStatePointerClosure:
      parseSessionHandoffCurrentStatePointerClosure(
        parsed.currentStatePointerClosure
      ) as SessionHandoffCurrentStatePointerClosureV1,
    requiredEntryHashes:
      Object.freeze({
        ...requiredEntryHashes,
      }),
    descriptorHash:
      parsed.descriptorHash as string,
    signature:
      parsed.signature,
  };
}

function parseCanonicalAuthorityEvidence(
  value: unknown
): CanonicalAuthorityEvidence | null {
  if (!isRecord(value)) {
    return null;
  }

  const nonceStates =
    new Set([
      "NONE",
      "ISSUED",
      "WARN_PENDING",
      "CONSUMED",
      "CANCELLED",
      "TIMED_OUT",
    ]);

  const verificationResults =
    new Set([
      "UNVERIFIED",
      "VERIFIED",
      "FAILED",
    ]);

  if (
    !isNonEmptyInlineString(
      value.projectIdentity
    ) ||
    !isNonEmptyInlineString(
      value.workspaceId
    ) ||
    typeof value.revision !== "number" ||
    !Number.isSafeInteger(
      value.revision
    ) ||
    value.revision < 0 ||
    !isNonEmptyInlineString(
      value.sessionId
    ) ||
    normalizeSha256(
      value.approvalNonceSha256
    ) === null ||
    typeof value.approvalNonceState !==
      "string" ||
    !nonceStates.has(
      value.approvalNonceState
    ) ||
    typeof value.verificationResult !==
      "string" ||
    !verificationResults.has(
      value.verificationResult
    )
  ) {
    return null;
  }

  return {
    projectIdentity:
      value.projectIdentity,
    workspaceId:
      value.workspaceId,
    revision:
      value.revision,
    sessionId:
      value.sessionId,
    approvalNonceSha256:
      value.approvalNonceSha256 as string,
    approvalNonceState:
      value.approvalNonceState as
        CanonicalAuthorityEvidence[
          "approvalNonceState"
        ],
    verificationResult:
      value.verificationResult as
        CanonicalAuthorityEvidence[
          "verificationResult"
        ],
  };
}

function parseRuntimeSessionEvidence(
  value: unknown
): RuntimeSessionEvidence | null {
  if (!isRecord(value)) {
    return null;
  }

  const phases =
    new Set([
      "WARN_PENDING",
      "ALLOW_PENDING_EXECUTION",
      "CONSUMED",
    ]);

  if (
    !isNonEmptyInlineString(
      value.sessionId
    ) ||
    normalizeSha256(
      value.approvalNonceSha256
    ) === null ||
    !isNonEmptyInlineString(
      value.createdAt
    ) ||
    typeof value.lifecyclePhase !==
      "string" ||
    !phases.has(
      value.lifecyclePhase
    ) ||
    typeof value.nonceConsumed !==
      "boolean" ||
    !(
      value.expiresAt === null ||
      isNonEmptyInlineString(
        value.expiresAt
      )
    )
  ) {
    return null;
  }

  return {
    sessionId:
      value.sessionId,
    approvalNonceSha256:
      value.approvalNonceSha256 as string,
    createdAt:
      value.createdAt,
    lifecyclePhase:
      value.lifecyclePhase as
        RuntimeSessionEvidence[
          "lifecyclePhase"
        ],
    nonceConsumed:
      value.nonceConsumed,
    expiresAt:
      value.expiresAt as
        string | null,
  };
}

function parseAuthorityBindingEvidence(
  value: unknown
): AuthorityBindingEvidence | null {
  if (!isRecord(value)) {
    return null;
  }

  if (
    typeof value.authorityRevision !==
      "number" ||
    !Number.isSafeInteger(
      value.authorityRevision
    ) ||
    value.authorityRevision < 0 ||
    !isNonEmptyInlineString(
      value.workspaceId
    ) ||
    prefixedSha256(
      value.snapshotBindingSha256
    ) === null
  ) {
    return null;
  }

  return {
    authorityRevision:
      value.authorityRevision,
    workspaceId:
      value.workspaceId,
    snapshotBindingSha256:
      value.snapshotBindingSha256 as string,
  };
}

function validDateMilliseconds(
  value: string
): number | null {
  const parsed =
    Date.parse(value);

  return Number.isFinite(parsed)
    ? parsed
    : null;
}

function frozenIssues(
  issues:
    SessionHandoffLocalVerificationAdapterIssueCode[]
): readonly SessionHandoffLocalVerificationAdapterIssueCode[] {
  return Object.freeze([
    ...issues,
  ]);
}

export class SessionHandoffLocalVerificationAdapter {
  constructor(
    private readonly policy:
      SessionHandoffLocalVerificationPolicy,
    private readonly providers:
      SessionHandoffLocalVerificationProviders
  ) {
    if (
      !isNonEmptyInlineString(
        policy.expectedProjectId
      ) ||
      !Array.isArray(
        policy.expectedSignerIds
      ) ||
      policy.expectedSignerIds.length === 0 ||
      policy.expectedSignerIds.some(
        signerId =>
          !isNonEmptyInlineString(
            signerId
          )
      ) ||
      new Set(
        policy.expectedSignerIds
      ).size !==
        policy.expectedSignerIds.length ||
      !Number.isSafeInteger(
        policy.maximumCapsuleAgeMilliseconds
      ) ||
      policy.maximumCapsuleAgeMilliseconds < 1
    ) {
      throw new Error(
        "INVALID_SESSION_HANDOFF_LOCAL_VERIFICATION_POLICY"
      );
    }
  }

  async evaluate(
    input:
      SessionHandoffLocalVerificationAdapterInput
  ): Promise<
    SessionHandoffLocalVerificationAdapterResult
  > {
    const issues:
      SessionHandoffLocalVerificationAdapterIssueCode[] = [];

    const issueSet =
      new Set<
        SessionHandoffLocalVerificationAdapterIssueCode
      >();

    const addIssue = (
      issue:
        SessionHandoffLocalVerificationAdapterIssueCode
    ): void => {
      if (issueSet.add(issue)) {
        issues.push(issue);
      }
    };

    const operationClass =
      typeof input.operationClass === "string" &&
      KNOWN_OPERATION_CLASSES.has(
        input.operationClass as
          SessionHandoffOperationClass
      )
        ? input.operationClass as
            SessionHandoffOperationClass
        : null;

    if (operationClass === null) {
      addIssue(
        "UNKNOWN_OPERATION_CLASS"
      );
    }

    const capsule =
      parseCapsule(
        input.capsuleText
      );

    if (capsule === null) {
      addIssue("CAPSULE_INVALID");
    }

    const expectedCanonicalStateHash =
      capsule === null
        ? ""
        : normalizeSha256(
            capsule.canonicalStateSha256
          ) ?? "";

    const expectedCheckerHash =
      capsule === null
        ? ""
        : normalizeSha256(
            capsule.checkerSha256
          ) ?? "";

    const expectedAuthorityHash =
      capsule === null
        ? ""
        : normalizeSha256(
            capsule.authoritySha256
          ) ?? "";

    let actualCanonicalStateHash = "";
    let actualCheckerHash = "";
    let actualAuthorityHash = "";
    let actualCurrentStatePointerHash = "";
    let actualCurrentStatePointerBytes:
      SessionHandoffLocalVerificationBytes | null =
        null;

    try {
      actualCanonicalStateHash =
        sha256SessionHandoffBytes(
          await this.providers
            .readCanonicalStateBytes()
        );
    } catch {
      addIssue(
        "CANONICAL_STATE_READ_FAILED"
      );
    }

    try {
      actualCheckerHash =
        sha256SessionHandoffBytes(
          await this.providers
            .readCheckerBytes()
        );
    } catch {
      addIssue(
        "CHECKER_READ_FAILED"
      );
    }

    try {
      actualAuthorityHash =
        sha256SessionHandoffBytes(
          await this.providers
            .readAuthorityBytes()
        );
    } catch {
      addIssue(
        "AUTHORITY_READ_FAILED"
      );
    }

    try {
      actualCurrentStatePointerBytes =
        await this.providers
          .readCurrentStatePointerBytes();

      actualCurrentStatePointerHash =
        sha256SessionHandoffBytes(
          actualCurrentStatePointerBytes
        );
    } catch {
      addIssue(
        "CURRENT_STATE_POINTER_READ_FAILED"
      );
    }

    const canonicalStateHashMatched =
      capsule !== null &&
      expectedCanonicalStateHash.length === 64 &&
      actualCanonicalStateHash ===
        expectedCanonicalStateHash;

    if (
      capsule !== null &&
      !canonicalStateHashMatched
    ) {
      addIssue(
        "CANONICAL_STATE_HASH_MISMATCH"
      );
    }

    const checkerHashMatched =
      capsule !== null &&
      expectedCheckerHash.length === 64 &&
      actualCheckerHash ===
        expectedCheckerHash;

    if (
      capsule !== null &&
      !checkerHashMatched
    ) {
      addIssue(
        "CHECKER_HASH_MISMATCH"
      );
    }

    const authorityHashMatched =
      capsule !== null &&
      expectedAuthorityHash.length === 64 &&
      actualAuthorityHash ===
        expectedAuthorityHash;

    if (
      capsule !== null &&
      !authorityHashMatched
    ) {
      addIssue(
        "AUTHORITY_HASH_MISMATCH"
      );
    }

    const expectedCurrentStatePointerHash =
      capsule === null
        ? ""
        : normalizeSha256(
            capsule.currentStatePointerSha256
          ) ?? "";

    const currentStatePointerHashVerified =
      capsule !== null &&
      expectedCurrentStatePointerHash.length ===
        64 &&
      actualCurrentStatePointerHash ===
        expectedCurrentStatePointerHash;

    const localCurrentStatePointerClosure =
      actualCurrentStatePointerBytes === null
        ? null
        : parseSessionHandoffCurrentStatePointerDocument(
            actualCurrentStatePointerBytes
          );

    const currentStatePointerFieldClosureVerified =
      capsule !== null &&
      localCurrentStatePointerClosure !== null &&
      sessionHandoffCurrentStatePointerClosuresEqual(
        capsule.currentStatePointerClosure,
        localCurrentStatePointerClosure
      );

    if (
      capsule !== null &&
      !currentStatePointerHashVerified
    ) {
      addIssue(
        "CURRENT_STATE_POINTER_HASH_MISMATCH"
      );
    }

    if (
      capsule !== null &&
      !currentStatePointerFieldClosureVerified
    ) {
      addIssue(
        "CURRENT_STATE_POINTER_FIELD_CLOSURE_FAILED"
      );
    }

    const currentStatePointerClosureVerified =
      currentStatePointerHashVerified &&
      currentStatePointerFieldClosureVerified;

    let descriptorHashVerified = false;
    let computedDescriptorHash:
      string | null = null;
    let canonicalPayload = "";

    if (capsule !== null) {
      try {
        const unsignedCapsule =
          toUnsignedCapsule(
            capsule
          );

        canonicalPayload =
          canonicalizeSessionHandoffUnsignedCapsule(
            unsignedCapsule
          );

        computedDescriptorHash =
          computeSessionHandoffDescriptorHash(
            unsignedCapsule
          );

        descriptorHashVerified =
          computedDescriptorHash ===
          normalizeSha256(
            capsule.descriptorHash
          );

        if (!descriptorHashVerified) {
          addIssue(
            "CAPSULE_DESCRIPTOR_HASH_MISMATCH"
          );
        }
      } catch {
        addIssue(
          "CAPSULE_DESCRIPTOR_HASH_MISMATCH"
        );
      }
    }

    let signatureVerified = false;

    if (
      this.providers.signatureVerifier ===
      undefined
    ) {
      addIssue(
        "SIGNATURE_PROVIDER_UNAVAILABLE"
      );
    } else if (
      capsule !== null &&
      descriptorHashVerified &&
      computedDescriptorHash !== null
    ) {
      try {
        signatureVerified =
          await this.providers
            .signatureVerifier
            .verify({
              signerId:
                capsule.signerId,
              descriptorHash:
                computedDescriptorHash,
              canonicalPayload,
              signature:
                capsule.signature,
            });

        if (!signatureVerified) {
          addIssue(
            "SIGNATURE_VERIFICATION_FAILED"
          );
        }
      } catch {
        addIssue(
          "SIGNATURE_VERIFICATION_FAILED"
        );
      }
    } else {
      addIssue(
        "SIGNATURE_VERIFICATION_FAILED"
      );
    }

    let nowMilliseconds:
      number | null = null;

    try {
      const now =
        this.providers.now();

      const candidate =
        now.getTime();

      if (
        Number.isFinite(candidate)
      ) {
        nowMilliseconds =
          candidate;
      } else {
        addIssue(
          "PROVIDER_FAILURE"
        );
      }
    } catch {
      addIssue(
        "PROVIDER_FAILURE"
      );
    }

    let capsuleFresh = false;

    if (
      capsule !== null &&
      nowMilliseconds !== null
    ) {
      const issuedMilliseconds =
        validDateMilliseconds(
          capsule.issuedAt
        );

      const expiresMilliseconds =
        validDateMilliseconds(
          capsule.expiresAt
        );

      capsuleFresh =
        issuedMilliseconds !== null &&
        expiresMilliseconds !== null &&
        issuedMilliseconds <=
          nowMilliseconds &&
        expiresMilliseconds >
          nowMilliseconds &&
        expiresMilliseconds >
          issuedMilliseconds &&
        (
          nowMilliseconds -
          issuedMilliseconds
        ) <=
          this.policy
            .maximumCapsuleAgeMilliseconds;
    }

    if (
      capsule !== null &&
      !capsuleFresh
    ) {
      addIssue(
        "CAPSULE_FRESHNESS_FAILED"
      );
    }

    let canonicalAuthority:
      CanonicalAuthorityEvidence | null =
      null;

    try {
      canonicalAuthority =
        parseCanonicalAuthorityEvidence(
          this.providers
            .canonicalAuthorityReader
            .getState()
        );

      if (
        canonicalAuthority === null
      ) {
        addIssue(
          "CANONICAL_AUTHORITY_STATE_INVALID"
        );
      }
    } catch {
      addIssue(
        "CANONICAL_AUTHORITY_STATE_INVALID"
      );
    }

    if (
      canonicalAuthority !== null &&
      canonicalAuthority
        .verificationResult !==
        "VERIFIED"
    ) {
      addIssue(
        "CANONICAL_AUTHORITY_NOT_VERIFIED"
      );
    }

    let runtimeSession:
      RuntimeSessionEvidence | null =
      null;

    if (capsule !== null) {
      try {
        runtimeSession =
          parseRuntimeSessionEvidence(
            this.providers
              .runtimeSessionReader
              .readSession(
                capsule.sessionId
              )
          );

        if (runtimeSession === null) {
          addIssue(
            "SESSION_RECORD_INVALID"
          );
        }
      } catch {
        addIssue(
          "SESSION_RECORD_INVALID"
        );
      }
    }

    let sessionFresh = false;

    if (
      runtimeSession !== null &&
      nowMilliseconds !== null
    ) {
      const createdMilliseconds =
        validDateMilliseconds(
          runtimeSession.createdAt
        );

      const expiresMilliseconds =
        runtimeSession.expiresAt === null
          ? null
          : validDateMilliseconds(
              runtimeSession.expiresAt
            );

      sessionFresh =
        createdMilliseconds !== null &&
        createdMilliseconds <=
          nowMilliseconds &&
        (
          runtimeSession.expiresAt ===
            null ||
          (
            expiresMilliseconds !==
              null &&
            expiresMilliseconds >
              nowMilliseconds
          )
        );
    }

    if (
      runtimeSession !== null &&
      !sessionFresh
    ) {
      addIssue(
        "SESSION_FRESHNESS_FAILED"
      );
    }

    const expectedProjectIdentityMatched =
      capsule !== null &&
      capsule.projectId ===
        this.policy.expectedProjectId;

    const canonicalProjectIdentityMatched =
      capsule !== null &&
      canonicalAuthority !== null &&
      canonicalAuthority
        .projectIdentity ===
        capsule.projectId;

    if (
      capsule !== null &&
      (
        !expectedProjectIdentityMatched ||
        !canonicalProjectIdentityMatched
      )
    ) {
      addIssue(
        "CAPSULE_PROJECT_IDENTITY_MISMATCH"
      );
    }

    const signerIdentityMatched =
      capsule !== null &&
      this.policy.expectedSignerIds
        .includes(
          capsule.signerId
        );

    if (
      capsule !== null &&
      !signerIdentityMatched
    ) {
      addIssue(
        "SIGNER_IDENTITY_MISMATCH"
      );
    }

    const workspaceIdentityMatched =
      capsule !== null &&
      canonicalAuthority !== null &&
      canonicalAuthority.workspaceId ===
        capsule.workspaceId;

    if (
      capsule !== null &&
      !workspaceIdentityMatched
    ) {
      addIssue(
        "CAPSULE_WORKSPACE_IDENTITY_MISMATCH"
      );
    }

    const presentedSessionId =
      input.presentedSessionId.trim();

    const sessionIdentityMatched =
      capsule !== null &&
      canonicalAuthority !== null &&
      runtimeSession !== null &&
      presentedSessionId.length > 0 &&
      presentedSessionId ===
        capsule.sessionId &&
      canonicalAuthority.sessionId ===
        capsule.sessionId &&
      runtimeSession.sessionId ===
        capsule.sessionId;

    if (
      capsule !== null &&
      !sessionIdentityMatched
    ) {
      addIssue(
        "CAPSULE_SESSION_ID_MISMATCH"
      );
    }

    const capsuleNonceHash =
      capsule === null
        ? null
        : normalizeSha256(
            capsule.approvalNonceSha256
          );

    const presentedNonceHash =
      normalizeSha256(
        input.presentedApprovalNonceSha256
      );

    const canonicalNonceHash =
      canonicalAuthority === null
        ? null
        : normalizeSha256(
            canonicalAuthority
              .approvalNonceSha256
          );

    const sessionNonceHash =
      runtimeSession === null
        ? null
        : normalizeSha256(
            runtimeSession
              .approvalNonceSha256
          );

    const nonceHashMatched =
      capsuleNonceHash !== null &&
      presentedNonceHash !== null &&
      canonicalNonceHash !== null &&
      sessionNonceHash !== null &&
      capsuleNonceHash ===
        presentedNonceHash &&
      capsuleNonceHash ===
        canonicalNonceHash &&
      capsuleNonceHash ===
        sessionNonceHash;

    if (
      capsule !== null &&
      !nonceHashMatched
    ) {
      addIssue(
        "CAPSULE_NONCE_HASH_MISMATCH"
      );
    }

    const sessionPending =
      canonicalAuthority !== null &&
      runtimeSession !== null &&
      canonicalAuthority
        .approvalNonceState ===
        "ISSUED" &&
      runtimeSession.lifecyclePhase ===
        "ALLOW_PENDING_EXECUTION" &&
      runtimeSession.nonceConsumed ===
        false;

    if (
      capsule !== null &&
      !sessionPending
    ) {
      addIssue(
        "SESSION_NOT_PENDING"
      );
    }

    let authorityBinding:
      AuthorityBindingEvidence | null =
      null;

    try {
      authorityBinding =
        parseAuthorityBindingEvidence(
          await this.providers
            .authorityBindingReadPort
            .readCurrentBinding()
        );

      if (
        authorityBinding === null
      ) {
        addIssue(
          "AUTHORITY_BINDING_INVALID"
        );
      }
    } catch {
      addIssue(
        "AUTHORITY_BINDING_READ_FAILED"
      );
    }

    const bindingMatches =
      capsule !== null &&
      canonicalAuthority !== null &&
      authorityBinding !== null &&
      authorityBinding.authorityRevision ===
        capsule.authorityRevision &&
      authorityBinding.authorityRevision ===
        canonicalAuthority.revision &&
      authorityBinding.workspaceId ===
        capsule.workspaceId &&
      authorityBinding.workspaceId ===
        canonicalAuthority.workspaceId &&
      normalizeSha256(
        authorityBinding
          .snapshotBindingSha256
      ) ===
        normalizeSha256(
          capsule.snapshotBindingSha256
        );

    if (
      capsule !== null &&
      !bindingMatches
    ) {
      addIssue(
        "AUTHORITY_BINDING_MISMATCH"
      );
    }

    let bindingVerificationResult:
      | "verified"
      | "authority_drift"
      | "snapshot_failed" =
      "authority_drift";

    if (
      capsule !== null &&
      authorityBinding !== null &&
      capsuleNonceHash !== null
    ) {
      try {
        bindingVerificationResult =
          await this.providers
            .authorityBindingVerifier
            .verify({
              authorityRevision:
                authorityBinding
                  .authorityRevision,
              workspaceId:
                authorityBinding
                  .workspaceId,
              snapshotBindingSha256:
                prefixedSha256(
                  authorityBinding
                    .snapshotBindingSha256
                ) ?? "",
              actionId:
                "SESSION_HANDOFF_LOCAL_VERIFICATION_ADAPTER_V1",
              sessionId:
                capsule.sessionId,
              approvalNonceSha256:
                "sha256:" +
                capsuleNonceHash,
              commandSha256:
                "sha256:" +
                sha256SessionHandoffBytes(
                  input.capsuleText
                ),
            });

        if (
          bindingVerificationResult !==
          "verified"
        ) {
          addIssue(
            "AUTHORITY_BINDING_VERIFICATION_FAILED"
          );
        }
      } catch {
        addIssue(
          "AUTHORITY_BINDING_VERIFICATION_FAILED"
        );
      }
    } else {
      addIssue(
        "AUTHORITY_BINDING_VERIFICATION_FAILED"
      );
    }

    const authorityClosureVerified =
      authorityHashMatched &&
      canonicalAuthority !== null &&
      canonicalAuthority
        .verificationResult ===
        "VERIFIED" &&
      bindingMatches &&
      bindingVerificationResult ===
        "verified";

    let dependencyClosureVerified = false;

    if (capsule !== null) {
      dependencyClosureVerified = true;

      const entryNames =
        Object.keys(
          capsule.requiredEntryHashes
        ).sort();

      for (const entryName of entryNames) {
        let entryBytes:
          SessionHandoffLocalVerificationBytes | null =
          null;

        try {
          entryBytes =
            await this.providers
              .readRequiredEntryBytes(
                entryName
              );
        } catch {
          entryBytes = null;
        }

        if (entryBytes === null) {
          dependencyClosureVerified =
            false;

          addIssue(
            "REQUIRED_ENTRY_MISSING"
          );

          continue;
        }

        const expectedEntryHash =
          normalizeSha256(
            capsule.requiredEntryHashes[
              entryName
            ]
          );

        let actualEntryHash:
          string | null = null;

        try {
          actualEntryHash =
            sha256SessionHandoffBytes(
              entryBytes
            );
        } catch {
          actualEntryHash = null;
        }

        if (
          expectedEntryHash === null ||
          actualEntryHash !==
            expectedEntryHash
        ) {
          dependencyClosureVerified =
            false;

          addIssue(
            "REQUIRED_ENTRY_HASH_MISMATCH"
          );
        }
      }
    }

    let receiptText = "";
    let ledgerText = "";

    try {
      receiptText =
        await this.providers
          .readReceiptText();

      if (
        typeof receiptText !== "string" ||
        receiptText.length === 0
      ) {
        throw new Error(
          "EMPTY_RECEIPT_TEXT"
        );
      }
    } catch {
      receiptText = "";

      addIssue(
        "RECEIPT_READ_FAILED"
      );
    }

    try {
      ledgerText =
        await this.providers
          .readLedgerText();

      if (
        typeof ledgerText !== "string" ||
        ledgerText.length === 0
      ) {
        throw new Error(
          "EMPTY_LEDGER_TEXT"
        );
      }
    } catch {
      ledgerText = "";

      addIssue(
        "LEDGER_READ_FAILED"
      );
    }

    let receiptLedgerIntegrityVerified =
      false;

    try {
      const binding =
        verifyReceiptLedgerBinding(
          receiptText,
          ledgerText
        );

      receiptLedgerIntegrityVerified =
        binding.ok;

      if (!binding.ok) {
        addIssue(
          "RECEIPT_LEDGER_INTEGRITY_FAILED"
        );
      }
    } catch {
      addIssue(
        "RECEIPT_LEDGER_INTEGRITY_FAILED"
      );
    }

    const identityVerified =
      capsule !== null &&
      descriptorHashVerified &&
      expectedProjectIdentityMatched &&
      canonicalProjectIdentityMatched &&
      signerIdentityMatched &&
      workspaceIdentityMatched &&
      sessionIdentityMatched;

    const freshnessVerified =
      capsuleFresh &&
      sessionFresh;

    const nonceStatus:
      SessionHandoffVerificationInput[
        "nonce"
      ]["status"] =
      sessionPending
        ? "PENDING"
        : canonicalAuthority
              ?.approvalNonceState ===
            "CONSUMED"
          ? "CONSUMED"
          : canonicalAuthority
                ?.approvalNonceState ===
              "TIMED_OUT"
            ? "TIMED_OUT"
            : "CANCELLED";

    let sequenceFresh = false;
    let sequenceClaimed = false;

    if (
      this.providers.sequenceStore ===
      undefined
    ) {
      addIssue(
        "SEQUENCE_STORE_UNAVAILABLE"
      );
    } else if (
      capsule !== null &&
      computedDescriptorHash !== null
    ) {
      try {
        const highestSequence =
          await this.providers
            .sequenceStore
            .readHighestAcceptedSequence({
              projectId:
                capsule.projectId,
              signerId:
                capsule.signerId,
            });

        if (
          highestSequence !== null &&
          (
            !Number.isSafeInteger(
              highestSequence
            ) ||
            highestSequence < 0
          )
        ) {
          throw new Error(
            "INVALID_HIGHEST_SEQUENCE"
          );
        }

        sequenceFresh =
          highestSequence === null ||
          capsule.handoffSequence >
            highestSequence;

        if (!sequenceFresh) {
          addIssue(
            "HANDOFF_SEQUENCE_REPLAY_OR_ROLLBACK"
          );
        }
      } catch {
        sequenceFresh = false;

        addIssue(
          "SEQUENCE_STORE_FAILURE"
        );
      }
    }

    const preliminaryEvidenceComplete =
      capsule !== null &&
      operationClass !== null &&
      descriptorHashVerified &&
      signatureVerified &&
      freshnessVerified &&
      identityVerified &&
      nonceHashMatched &&
      sessionPending &&
      canonicalStateHashMatched &&
      checkerHashMatched &&
      authorityHashMatched &&
      dependencyClosureVerified &&
      authorityClosureVerified &&
      currentStatePointerClosureVerified &&
      receiptLedgerIntegrityVerified &&
      sequenceFresh;

    let antiRollbackVerified =
      sequenceFresh;

    if (
      capsule !== null &&
      computedDescriptorHash !== null &&
      operationClass !== null &&
      EFFECT_OPERATION_CLASSES.has(
        operationClass
      ) &&
      preliminaryEvidenceComplete
    ) {
      if (
        this.providers.sequenceStore ===
        undefined
      ) {
        antiRollbackVerified = false;
      } else {
        try {
          sequenceClaimed =
            await this.providers
              .sequenceStore
              .claimSequence({
                projectId:
                  capsule.projectId,
                signerId:
                  capsule.signerId,
                sequence:
                  capsule.handoffSequence,
                descriptorHash:
                  computedDescriptorHash,
              });

          antiRollbackVerified =
            sequenceClaimed;

          if (!sequenceClaimed) {
            addIssue(
              "HANDOFF_SEQUENCE_REPLAY_OR_ROLLBACK"
            );
          }
        } catch {
          antiRollbackVerified =
            false;

          addIssue(
            "SEQUENCE_STORE_FAILURE"
          );
        }
      }
    }

    const expectedNonceForGate =
      capsuleNonceHash ?? "";

    const presentedNonceForGate =
      presentedNonceHash ?? "";

    const verification:
      SessionHandoffVerificationInput = {
      canonicalState: {
        expectedSha256:
          expectedCanonicalStateHash,
        actualSha256:
          actualCanonicalStateHash,
      },
      checker: {
        expectedSha256:
          expectedCheckerHash,
        actualSha256:
          actualCheckerHash,
      },
      authority: {
        expectedSha256:
          expectedAuthorityHash,
        actualSha256:
          actualAuthorityHash,
      },
      signatureVerified:
        signatureVerified &&
        descriptorHashVerified,
      freshnessVerified,
      antiRollbackVerified,
      identityVerified,
      nonce: {
        expectedNonce:
          expectedNonceForGate,
        presentedNonce:
          presentedNonceForGate,
        status:
          nonceStatus,
        inheritPreviousExecutionAuthority:
          false,
      },
      dependencyClosureVerified,
      authorityClosureVerified,
      currentStatePointerClosureVerified,
      receiptText,
      ledgerText,
    };

    const gateResult =
      evaluateSessionHandoffRuntimeGate({
        operationClass:
          input.operationClass,
        verification,
      });

    return Object.freeze({
      authorized:
        gateResult.operationAllowed &&
        gateResult.runtimeState ===
          "SESSION_AUTHORIZED",
      bootstrapReadOnlyAllowed:
        gateResult.operationAllowed &&
        gateResult.runtimeState ===
          "HANDOFF_BOOTSTRAP_READ_ONLY",
      descriptorHash:
        computedDescriptorHash,
      sequenceClaimed,
      adapterIssueCodes:
        frozenIssues(issues),
      gateResult,
      callerVerificationBooleanAccepted:
        false,
      productPassClaimed: false,
      finalClaimed: false,
      releaseReadyClaimed: false,
      uploadReadyClaimed: false,
    });
  }
}