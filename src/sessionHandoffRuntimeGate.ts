import {
  verifyReceiptLedgerBinding,
} from "../packages/aegis-core";

export const SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION =
  "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1" as const;

export type SessionHandoffOperationClass =
  | "READ_ONLY"
  | "MUTATION"
  | "EXECUTE"
  | "NETWORK"
  | "DELETE"
  | "PACKAGE"
  | "EXPORT";

export type SessionHandoffRuntimeState =
  | "HANDOFF_BOOTSTRAP_READ_ONLY"
  | "SESSION_AUTHORIZED"
  | "BLOCKED";

export type SessionHandoffVerificationState =
  | "SESSION_AUTHORIZED"
  | "BLOCKED";

export type SessionHandoffNonceStatus =
  | "PENDING"
  | "CONSUMED"
  | "CANCELLED"
  | "TIMED_OUT";

export type SessionHandoffRuntimeGateIssueCode =
  | "CANONICAL_STATE_HASH_INVALID"
  | "CANONICAL_STATE_HASH_MISMATCH"
  | "CHECKER_HASH_INVALID"
  | "CHECKER_HASH_MISMATCH"
  | "AUTHORITY_HASH_INVALID"
  | "AUTHORITY_HASH_MISMATCH"
  | "SIGNATURE_VERIFICATION_FAILED"
  | "FRESHNESS_VERIFICATION_FAILED"
  | "ANTI_ROLLBACK_VERIFICATION_FAILED"
  | "IDENTITY_VERIFICATION_FAILED"
  | "NONCE_NOT_PENDING"
  | "NONCE_MISMATCH"
  | "NONCE_REUSE"
  | "PREVIOUS_NONCE_NOT_TERMINAL"
  | "PREVIOUS_NONCE_AUTHORITY_INHERITANCE_FORBIDDEN"
  | "DEPENDENCY_CLOSURE_FAILED"
  | "AUTHORITY_CLOSURE_FAILED"
  | "CURRENT_STATE_POINTER_CLOSURE_FAILED"
  | "RECEIPT_LEDGER_INTEGRITY_FAILED"
  | "UNKNOWN_OPERATION_CLASS";

export interface SessionHandoffHashBinding {
  readonly expectedSha256: string;
  readonly actualSha256: string;
}

export interface SessionHandoffNonceInput {
  readonly expectedNonce: string;
  readonly presentedNonce: string;
  readonly status: SessionHandoffNonceStatus;
  readonly previousNonce?: string;
  readonly previousNonceStatus?: SessionHandoffNonceStatus;
  readonly inheritPreviousExecutionAuthority: boolean;
}

export interface SessionHandoffVerificationInput {
  readonly canonicalState: SessionHandoffHashBinding;
  readonly checker: SessionHandoffHashBinding;
  readonly authority: SessionHandoffHashBinding;
  readonly signatureVerified: boolean;
  readonly freshnessVerified: boolean;
  readonly antiRollbackVerified: boolean;
  readonly identityVerified: boolean;
  readonly nonce: SessionHandoffNonceInput;
  readonly dependencyClosureVerified: boolean;
  readonly authorityClosureVerified: boolean;
  readonly currentStatePointerClosureVerified: boolean;
  readonly receiptText: string;
  readonly ledgerText: string;
}

export interface SessionHandoffVerificationResult {
  readonly verified: boolean;
  readonly state: SessionHandoffVerificationState;
  readonly issueCodes:
    readonly SessionHandoffRuntimeGateIssueCode[];
  readonly receiptLedgerIssueCode?: string;
  readonly previousNonceExecutionAuthorityInherited: false;
  readonly productPassClaimed: false;
  readonly finalClaimed: false;
  readonly releaseReadyClaimed: false;
  readonly uploadReadyClaimed: false;
}

export interface SessionHandoffRuntimeGateInput {
  readonly operationClass: unknown;
  readonly verification: SessionHandoffVerificationInput;
}

export interface SessionHandoffRuntimeGateResult {
  readonly operationAllowed: boolean;
  readonly operationClass:
    | SessionHandoffOperationClass
    | "UNKNOWN";
  readonly runtimeState: SessionHandoffRuntimeState;
  readonly verificationState:
    SessionHandoffVerificationState;
  readonly firstRequiredAction:
    typeof SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION;
  readonly issueCodes:
    readonly SessionHandoffRuntimeGateIssueCode[];
  readonly receiptLedgerIssueCode?: string;
  readonly previousNonceExecutionAuthorityInherited: false;
  readonly productPassClaimed: false;
  readonly finalClaimed: false;
  readonly releaseReadyClaimed: false;
  readonly uploadReadyClaimed: false;
}

const OPERATION_CLASSES =
  new Set<SessionHandoffOperationClass>([
    "READ_ONLY",
    "MUTATION",
    "EXECUTE",
    "NETWORK",
    "DELETE",
    "PACKAGE",
    "EXPORT",
  ]);

const TERMINAL_NONCE_STATUSES =
  new Set<SessionHandoffNonceStatus>([
    "CONSUMED",
    "CANCELLED",
    "TIMED_OUT",
  ]);

function isSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/i.test(value);
}

function equalSha256(
  left: string,
  right: string
): boolean {
  return (
    left.toLowerCase() ===
    right.toLowerCase()
  );
}

function validateHashBinding(
  binding: SessionHandoffHashBinding,
  invalidCode:
    SessionHandoffRuntimeGateIssueCode,
  mismatchCode:
    SessionHandoffRuntimeGateIssueCode,
  issues:
    SessionHandoffRuntimeGateIssueCode[]
): void {
  if (
    !isSha256(binding.expectedSha256) ||
    !isSha256(binding.actualSha256)
  ) {
    issues.push(invalidCode);
    return;
  }

  if (
    !equalSha256(
      binding.expectedSha256,
      binding.actualSha256
    )
  ) {
    issues.push(mismatchCode);
  }
}

function frozenIssues(
  issues:
    SessionHandoffRuntimeGateIssueCode[]
): readonly SessionHandoffRuntimeGateIssueCode[] {
  return Object.freeze([...issues]);
}

export function verifySessionHandoffAuthority(
  input: SessionHandoffVerificationInput
): SessionHandoffVerificationResult {
  const issues:
    SessionHandoffRuntimeGateIssueCode[] = [];

  validateHashBinding(
    input.canonicalState,
    "CANONICAL_STATE_HASH_INVALID",
    "CANONICAL_STATE_HASH_MISMATCH",
    issues
  );

  validateHashBinding(
    input.checker,
    "CHECKER_HASH_INVALID",
    "CHECKER_HASH_MISMATCH",
    issues
  );

  validateHashBinding(
    input.authority,
    "AUTHORITY_HASH_INVALID",
    "AUTHORITY_HASH_MISMATCH",
    issues
  );

  if (!input.signatureVerified) {
    issues.push(
      "SIGNATURE_VERIFICATION_FAILED"
    );
  }

  if (!input.freshnessVerified) {
    issues.push(
      "FRESHNESS_VERIFICATION_FAILED"
    );
  }

  if (!input.antiRollbackVerified) {
    issues.push(
      "ANTI_ROLLBACK_VERIFICATION_FAILED"
    );
  }

  if (!input.identityVerified) {
    issues.push(
      "IDENTITY_VERIFICATION_FAILED"
    );
  }

  if (input.nonce.status !== "PENDING") {
    issues.push("NONCE_NOT_PENDING");
  }

  if (
    input.nonce.expectedNonce.length === 0 ||
    input.nonce.presentedNonce.length === 0 ||
    input.nonce.expectedNonce !==
      input.nonce.presentedNonce
  ) {
    issues.push("NONCE_MISMATCH");
  }

  if (
    input.nonce.previousNonce !== undefined &&
    input.nonce.previousNonce ===
      input.nonce.presentedNonce
  ) {
    issues.push("NONCE_REUSE");
  }

  if (
    input.nonce.previousNonce !== undefined &&
    (
      input.nonce.previousNonceStatus ===
        undefined ||
      !TERMINAL_NONCE_STATUSES.has(
        input.nonce.previousNonceStatus
      )
    )
  ) {
    issues.push(
      "PREVIOUS_NONCE_NOT_TERMINAL"
    );
  }

  if (
    input.nonce
      .inheritPreviousExecutionAuthority
  ) {
    issues.push(
      "PREVIOUS_NONCE_AUTHORITY_INHERITANCE_FORBIDDEN"
    );
  }

  if (!input.dependencyClosureVerified) {
    issues.push(
      "DEPENDENCY_CLOSURE_FAILED"
    );
  }

  if (!input.authorityClosureVerified) {
    issues.push(
      "AUTHORITY_CLOSURE_FAILED"
    );
  }

  if (
    !input.currentStatePointerClosureVerified
  ) {
    issues.push(
      "CURRENT_STATE_POINTER_CLOSURE_FAILED"
    );
  }

  let receiptLedgerIssueCode:
    string | undefined;

  try {
    const binding =
      verifyReceiptLedgerBinding(
        input.receiptText,
        input.ledgerText
      );

    if (!binding.ok) {
      issues.push(
        "RECEIPT_LEDGER_INTEGRITY_FAILED"
      );

      receiptLedgerIssueCode =
        binding.issueCode;
    }
  } catch {
    issues.push(
      "RECEIPT_LEDGER_INTEGRITY_FAILED"
    );

    receiptLedgerIssueCode =
      "RECEIPT_LEDGER_VERIFICATION_THROW";
  }

  const verified = issues.length === 0;

  return {
    verified,
    state:
      verified
        ? "SESSION_AUTHORIZED"
        : "BLOCKED",
    issueCodes: frozenIssues(issues),
    receiptLedgerIssueCode,
    previousNonceExecutionAuthorityInherited:
      false,
    productPassClaimed: false,
    finalClaimed: false,
    releaseReadyClaimed: false,
    uploadReadyClaimed: false,
  };
}

export function evaluateSessionHandoffRuntimeGate(
  input: SessionHandoffRuntimeGateInput
): SessionHandoffRuntimeGateResult {
  const verification =
    verifySessionHandoffAuthority(
      input.verification
    );

  const knownOperation =
    typeof input.operationClass === "string" &&
    OPERATION_CLASSES.has(
      input.operationClass as
        SessionHandoffOperationClass
    );

  if (!knownOperation) {
    return {
      operationAllowed: false,
      operationClass: "UNKNOWN",
      runtimeState: "BLOCKED",
      verificationState:
        verification.state,
      firstRequiredAction:
        SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION,
      issueCodes: frozenIssues([
        ...verification.issueCodes,
        "UNKNOWN_OPERATION_CLASS",
      ]),
      receiptLedgerIssueCode:
        verification.receiptLedgerIssueCode,
      previousNonceExecutionAuthorityInherited:
        false,
      productPassClaimed: false,
      finalClaimed: false,
      releaseReadyClaimed: false,
      uploadReadyClaimed: false,
    };
  }

  const operationClass =
    input.operationClass as
      SessionHandoffOperationClass;

  if (verification.verified) {
    return {
      operationAllowed: true,
      operationClass,
      runtimeState: "SESSION_AUTHORIZED",
      verificationState:
        "SESSION_AUTHORIZED",
      firstRequiredAction:
        SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION,
      issueCodes:
        verification.issueCodes,
      receiptLedgerIssueCode:
        verification.receiptLedgerIssueCode,
      previousNonceExecutionAuthorityInherited:
        false,
      productPassClaimed: false,
      finalClaimed: false,
      releaseReadyClaimed: false,
      uploadReadyClaimed: false,
    };
  }

  if (operationClass === "READ_ONLY") {
    return {
      operationAllowed: true,
      operationClass,
      runtimeState:
        "HANDOFF_BOOTSTRAP_READ_ONLY",
      verificationState: "BLOCKED",
      firstRequiredAction:
        SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION,
      issueCodes:
        verification.issueCodes,
      receiptLedgerIssueCode:
        verification.receiptLedgerIssueCode,
      previousNonceExecutionAuthorityInherited:
        false,
      productPassClaimed: false,
      finalClaimed: false,
      releaseReadyClaimed: false,
      uploadReadyClaimed: false,
    };
  }

  return {
    operationAllowed: false,
    operationClass,
    runtimeState: "BLOCKED",
    verificationState: "BLOCKED",
    firstRequiredAction:
      SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION,
    issueCodes:
      verification.issueCodes,
    receiptLedgerIssueCode:
      verification.receiptLedgerIssueCode,
    previousNonceExecutionAuthorityInherited:
      false,
    productPassClaimed: false,
    finalClaimed: false,
    releaseReadyClaimed: false,
    uploadReadyClaimed: false,
  };
}