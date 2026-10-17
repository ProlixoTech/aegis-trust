import * as crypto from "node:crypto";

import {
  assessSignedRulesetSemanticCandidate,
  type SignedRulesetMetadata,
} from "../packages/aegis-core";

import {
  compileServerRulesetSafeRegex,
} from "./serverRulesetSafeRegex";

export const DEFAULT_SERVER_RULESET_JSON_BYTES =
  2 * 1024 * 1024;

export const ABSOLUTE_SERVER_RULESET_JSON_BYTES =
  5 * 1024 * 1024;

export const MAX_SERVER_RULESET_RULES = 256;

export type ServerRulesetRuleCategory =
  | "catastrophic"
  | "destructive"
  | "secret-exposure"
  | "policy-bypass";

export interface TrustedServerRulesetRule {
  readonly ruleId: string;
  readonly category: ServerRulesetRuleCategory;
  readonly pattern: string;
}

export interface TrustedServerRuleset {
  readonly schemaVersion: 1;
  readonly rulesetId: string;
  readonly rulesetVersion: number;
  readonly monotonicCounter: number;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly rules: readonly TrustedServerRulesetRule[];
}

export interface ServerRulesetTrustState {
  readonly highestIntermediateSequence: number;
  readonly intermediateKeyId: string;
  readonly intermediateKeySha256: string;
  readonly activeRuleset: SignedRulesetMetadata;
  readonly rulesetSha256: string;
}

export interface VerifySignedServerRulesetPackageOptions {
  readonly pinnedRootPublicKeyPem: string;
  readonly activeState: ServerRulesetTrustState | null;
  readonly nowEpochMs: number;
  readonly maximumJsonBytes?: number;
}

export interface VerifySignedServerRulesetPackageResult {
  readonly accepted: boolean;
  readonly error: string | null;
  readonly ruleset: TrustedServerRuleset | null;
  readonly nextState: ServerRulesetTrustState | null;
}

interface IntermediateCertificateV1 {
  readonly schemaVersion: 1;
  readonly keyId: string;
  readonly sequence: number;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly revoked: boolean;
  readonly publicKeyPem: string;
  readonly signature: string;
}

interface ServerRulesetPackageV1 {
  readonly schemaVersion: 1;
  readonly intermediateCertificate: IntermediateCertificateV1;
  readonly ruleset: TrustedServerRuleset;
  readonly rulesetSignature: string;
}

const RULE_CATEGORIES =
  new Set<string>([
    "catastrophic",
    "destructive",
    "secret-exposure",
    "policy-bypass",
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

function hasExactKeys(
  value: Record<string, unknown>,
  expectedKeys: readonly string[]
): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();

  return (
    actual.length === expected.length &&
    actual.every(
      (key, index) =>
        key === expected[index]
    )
  );
}

function isIdentifier(
  value: unknown
): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(
      value
    )
  );
}

function strictBase64(
  value: unknown
): Buffer | null {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value
    )
  ) {
    return null;
  }

  const decoded =
    Buffer.from(value, "base64");

  return (
    decoded.toString("base64") === value
      ? decoded
      : null
  );
}

function sha256Utf8(
  value: string
): string {
  return crypto
    .createHash("sha256")
    .update(
      Buffer.from(value, "utf8")
    )
    .digest("hex");
}

function parseTimestamp(
  value: unknown,
  errorCode: string
): {
  readonly source: string;
  readonly epochMs: number;
} {
  if (
    typeof value !== "string" ||
    value.trim() === ""
  ) {
    throw new Error(errorCode);
  }

  const epochMs = Date.parse(value);

  if (!Number.isFinite(epochMs)) {
    throw new Error(errorCode);
  }

  return {
    source: value,
    epochMs,
  };
}

function createEd25519PublicKey(
  publicKeyPem: string,
  errorCode: string
): crypto.KeyObject {
  let key: crypto.KeyObject;

  try {
    key = crypto.createPublicKey(
      publicKeyPem
    );
  } catch {
    throw new Error(errorCode);
  }

  if (
    key.type !== "public" ||
    key.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error(errorCode);
  }

  return key;
}

export function canonicalizeServerRulesetValue(
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
          canonicalizeServerRulesetValue(
            item
          )
        )
        .join(",") +
      "]"
    );
  }

  if (isRecord(value)) {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map(
          key =>
            JSON.stringify(key) +
            ":" +
            canonicalizeServerRulesetValue(
              value[key]
            )
        )
        .join(",") +
      "}"
    );
  }

  throw new Error(
    "UNSUPPORTED_CANONICAL_VALUE"
  );
}

function parseRule(
  value: unknown
): TrustedServerRulesetRule {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "category",
        "pattern",
        "ruleId",
      ]
    ) ||
    !isIdentifier(value.ruleId) ||
    typeof value.category !== "string" ||
    !RULE_CATEGORIES.has(
      value.category
    ) ||
    typeof value.pattern !== "string"
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_RULE"
    );
  }

  const compiled =
    compileServerRulesetSafeRegex(
      value.pattern
    );

  if (!compiled.accepted) {
    throw new Error(
      "UNSAFE_SERVER_RULESET_PATTERN=" +
      String(compiled.error)
    );
  }

  return Object.freeze({
    ruleId: value.ruleId,
    category:
      value.category as
        ServerRulesetRuleCategory,
    pattern: value.pattern,
  });
}

function parseRuleset(
  value: unknown
): TrustedServerRuleset {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "monotonicCounter",
        "notAfter",
        "notBefore",
        "rules",
        "rulesetId",
        "rulesetVersion",
        "schemaVersion",
      ]
    ) ||
    value.schemaVersion !== 1 ||
    !isIdentifier(value.rulesetId) ||
    !Number.isSafeInteger(
      value.rulesetVersion
    ) ||
    (
      value.rulesetVersion as number
    ) < 1 ||
    !Number.isSafeInteger(
      value.monotonicCounter
    ) ||
    (
      value.monotonicCounter as number
    ) < 1 ||
    !Array.isArray(value.rules) ||
    value.rules.length < 1 ||
    value.rules.length >
      MAX_SERVER_RULESET_RULES
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_PAYLOAD"
    );
  }

  const notBefore =
    parseTimestamp(
      value.notBefore,
      "INVALID_SERVER_RULESET_NOT_BEFORE"
    );

  const notAfter =
    parseTimestamp(
      value.notAfter,
      "INVALID_SERVER_RULESET_NOT_AFTER"
    );

  if (
    notAfter.epochMs <=
    notBefore.epochMs
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_VALIDITY_WINDOW"
    );
  }

  const ruleIds = new Set<string>();

  const rules =
    value.rules.map(candidate => {
      const rule = parseRule(candidate);

      if (ruleIds.has(rule.ruleId)) {
        throw new Error(
          "DUPLICATE_SERVER_RULESET_RULE_ID"
        );
      }

      ruleIds.add(rule.ruleId);
      return rule;
    });

  return Object.freeze({
    schemaVersion: 1,
    rulesetId: value.rulesetId,
    rulesetVersion:
      value.rulesetVersion as number,
    monotonicCounter:
      value.monotonicCounter as number,
    notBefore: notBefore.source,
    notAfter: notAfter.source,
    rules: Object.freeze(rules),
  });
}

function parseCertificate(
  value: unknown
): IntermediateCertificateV1 {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "keyId",
        "notAfter",
        "notBefore",
        "publicKeyPem",
        "revoked",
        "schemaVersion",
        "sequence",
        "signature",
      ]
    ) ||
    value.schemaVersion !== 1 ||
    !isIdentifier(value.keyId) ||
    !Number.isSafeInteger(
      value.sequence
    ) ||
    (
      value.sequence as number
    ) < 1 ||
    typeof value.publicKeyPem !==
      "string" ||
    value.publicKeyPem.length < 1 ||
    value.publicKeyPem.length >
      16384 ||
    typeof value.revoked !==
      "boolean" ||
    typeof value.signature !==
      "string"
  ) {
    throw new Error(
      "INVALID_INTERMEDIATE_CERTIFICATE"
    );
  }

  const notBefore =
    parseTimestamp(
      value.notBefore,
      "INVALID_INTERMEDIATE_NOT_BEFORE"
    );

  const notAfter =
    parseTimestamp(
      value.notAfter,
      "INVALID_INTERMEDIATE_NOT_AFTER"
    );

  if (
    notAfter.epochMs <=
    notBefore.epochMs
  ) {
    throw new Error(
      "INVALID_INTERMEDIATE_VALIDITY_WINDOW"
    );
  }

  return Object.freeze({
    schemaVersion: 1,
    keyId: value.keyId,
    sequence:
      value.sequence as number,
    notBefore: notBefore.source,
    notAfter: notAfter.source,
    revoked: value.revoked,
    publicKeyPem:
      value.publicKeyPem.trim() + "\n",
    signature: value.signature,
  });
}

function parsePackage(
  text: string
): ServerRulesetPackageV1 {
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(
      "INVALID_SERVER_RULESET_JSON"
    );
  }

  if (
    !isRecord(parsed) ||
    !hasExactKeys(
      parsed,
      [
        "intermediateCertificate",
        "ruleset",
        "rulesetSignature",
        "schemaVersion",
      ]
    ) ||
    parsed.schemaVersion !== 1 ||
    typeof parsed.rulesetSignature !==
      "string"
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_PACKAGE"
    );
  }

  return Object.freeze({
    schemaVersion: 1,
    intermediateCertificate:
      parseCertificate(
        parsed.intermediateCertificate
      ),
    ruleset:
      parseRuleset(parsed.ruleset),
    rulesetSignature:
      parsed.rulesetSignature,
  });
}

function validateActiveState(
  state: ServerRulesetTrustState
): void {
  if (
    !Number.isSafeInteger(
      state.highestIntermediateSequence
    ) ||
    state.highestIntermediateSequence < 1 ||
    !isIdentifier(
      state.intermediateKeyId
    ) ||
    !/^[a-f0-9]{64}$/.test(
      state.intermediateKeySha256
    ) ||
    !Number.isSafeInteger(
      state.activeRuleset.rulesetVersion
    ) ||
    state.activeRuleset.rulesetVersion < 1 ||
    !Number.isSafeInteger(
      state.activeRuleset.monotonicCounter
    ) ||
    state.activeRuleset.monotonicCounter! < 1 ||
    !/^[a-f0-9]{64}$/.test(
      state.rulesetSha256
    )
  ) {
    throw new Error(
      "INVALID_ACTIVE_SERVER_RULESET_STATE"
    );
  }
}

function verifyInternal(
  text: string,
  options:
    VerifySignedServerRulesetPackageOptions
): {
  readonly ruleset: TrustedServerRuleset;
  readonly nextState: ServerRulesetTrustState;
} {
  if (typeof text !== "string") {
    throw new Error(
      "INVALID_SERVER_RULESET_TEXT"
    );
  }

  const maximumJsonBytes =
    options.maximumJsonBytes ??
    DEFAULT_SERVER_RULESET_JSON_BYTES;

  if (
    !Number.isSafeInteger(
      maximumJsonBytes
    ) ||
    maximumJsonBytes < 1
  ) {
    throw new Error(
      "INVALID_MAXIMUM_JSON_BYTES"
    );
  }

  if (
    maximumJsonBytes >
    ABSOLUTE_SERVER_RULESET_JSON_BYTES
  ) {
    throw new Error(
      "MAXIMUM_JSON_BYTES_EXCEEDS_ABSOLUTE_LIMIT"
    );
  }

  if (
    Buffer.byteLength(
      text,
      "utf8"
    ) > maximumJsonBytes
  ) {
    throw new Error(
      "SERVER_RULESET_JSON_TOO_LARGE"
    );
  }

  if (!Number.isFinite(options.nowEpochMs)) {
    throw new Error(
      "INVALID_SERVER_RULESET_CURRENT_TIME"
    );
  }

  if (
    typeof options.pinnedRootPublicKeyPem !==
      "string" ||
    options.pinnedRootPublicKeyPem.trim() === ""
  ) {
    throw new Error(
      "INVALID_PINNED_ROOT_PUBLIC_KEY"
    );
  }

  if (options.activeState !== null) {
    validateActiveState(
      options.activeState
    );
  }

  const packageValue =
    parsePackage(text);

  const certificate =
    packageValue.intermediateCertificate;

  if (certificate.revoked) {
    throw new Error(
      "INTERMEDIATE_CERTIFICATE_REVOKED"
    );
  }

  const certificateNotBefore =
    Date.parse(certificate.notBefore);

  const certificateNotAfter =
    Date.parse(certificate.notAfter);

  if (
    certificateNotBefore >
    options.nowEpochMs
  ) {
    throw new Error(
      "INTERMEDIATE_CERTIFICATE_NOT_YET_VALID"
    );
  }

  if (
    certificateNotAfter <=
    options.nowEpochMs
  ) {
    throw new Error(
      "INTERMEDIATE_CERTIFICATE_EXPIRED"
    );
  }

  const rootKey =
    createEd25519PublicKey(
      options.pinnedRootPublicKeyPem,
      "INVALID_PINNED_ROOT_PUBLIC_KEY"
    );

  const certificateSignature =
    strictBase64(
      certificate.signature
    );

  if (
    certificateSignature === null ||
    certificateSignature.length !== 64
  ) {
    throw new Error(
      "INVALID_INTERMEDIATE_CERTIFICATE_SIGNATURE"
    );
  }

  const certificatePayload = {
    schemaVersion:
      certificate.schemaVersion,
    keyId: certificate.keyId,
    sequence: certificate.sequence,
    notBefore:
      certificate.notBefore,
    notAfter:
      certificate.notAfter,
    revoked:
      certificate.revoked,
    publicKeyPem:
      certificate.publicKeyPem,
  };

  if (
    !crypto.verify(
      null,
      Buffer.from(
        canonicalizeServerRulesetValue(
          certificatePayload
        ),
        "utf8"
      ),
      rootKey,
      certificateSignature
    )
  ) {
    throw new Error(
      "INTERMEDIATE_CERTIFICATE_ROOT_SIGNATURE_INVALID"
    );
  }

  const intermediateKey =
    createEd25519PublicKey(
      certificate.publicKeyPem,
      "INVALID_INTERMEDIATE_PUBLIC_KEY"
    );

  const intermediateKeySha256 =
    sha256Utf8(
      certificate.publicKeyPem
    );

  if (options.activeState !== null) {
    if (
      certificate.sequence <
      options.activeState
        .highestIntermediateSequence
    ) {
      throw new Error(
        "INTERMEDIATE_KEY_SEQUENCE_ROLLBACK"
      );
    }

    if (
      certificate.sequence ===
        options.activeState
          .highestIntermediateSequence &&
      (
        certificate.keyId !==
          options.activeState
            .intermediateKeyId ||
        intermediateKeySha256 !==
          options.activeState
            .intermediateKeySha256
      )
    ) {
      throw new Error(
        "INTERMEDIATE_KEY_SEQUENCE_REBOUND"
      );
    }
  }

  const rulesetSignature =
    strictBase64(
      packageValue.rulesetSignature
    );

  if (
    rulesetSignature === null ||
    rulesetSignature.length !== 64
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_SIGNATURE"
    );
  }

  const canonicalRuleset =
    canonicalizeServerRulesetValue(
      packageValue.ruleset
    );

  if (
    !crypto.verify(
      null,
      Buffer.from(
        canonicalRuleset,
        "utf8"
      ),
      intermediateKey,
      rulesetSignature
    )
  ) {
    throw new Error(
      "SERVER_RULESET_SIGNATURE_INVALID"
    );
  }

  const activeMetadata =
    options.activeState === null
      ? null
      : options.activeState
          .activeRuleset;

  const semantic =
    assessSignedRulesetSemanticCandidate(
      activeMetadata,
      {
        rulesetVersion:
          packageValue.ruleset
            .rulesetVersion,
        monotonicCounter:
          packageValue.ruleset
            .monotonicCounter,
        notBefore:
          packageValue.ruleset
            .notBefore,
        notAfter:
          packageValue.ruleset
            .notAfter,
      },
      options.nowEpochMs
    );

  if (!semantic.accepted) {
    throw new Error(
      "SERVER_RULESET_SEMANTIC_REJECTION=" +
      String(semantic.reason)
    );
  }

  const rulesetSha256 =
    sha256Utf8(canonicalRuleset);

  if (
    options.activeState !== null &&
    packageValue.ruleset
      .rulesetVersion ===
      options.activeState
        .activeRuleset.rulesetVersion &&
    packageValue.ruleset
      .monotonicCounter ===
      options.activeState
        .activeRuleset.monotonicCounter &&
    rulesetSha256 !==
      options.activeState.rulesetSha256
  ) {
    throw new Error(
      "SERVER_RULESET_VERSION_REBOUND"
    );
  }

  const nextState:
    ServerRulesetTrustState =
      Object.freeze({
        highestIntermediateSequence:
          certificate.sequence,
        intermediateKeyId:
          certificate.keyId,
        intermediateKeySha256,
        activeRuleset:
          Object.freeze({
            rulesetVersion:
              packageValue.ruleset
                .rulesetVersion,
            monotonicCounter:
              packageValue.ruleset
                .monotonicCounter,
            notBefore:
              packageValue.ruleset
                .notBefore,
            notAfter:
              packageValue.ruleset
                .notAfter,
          }),
        rulesetSha256,
      });

  return {
    ruleset: packageValue.ruleset,
    nextState,
  };
}

export function verifySignedServerRulesetPackageText(
  text: string,
  options:
    VerifySignedServerRulesetPackageOptions
): VerifySignedServerRulesetPackageResult {
  try {
    const verified =
      verifyInternal(text, options);

    return {
      accepted: true,
      error: null,
      ruleset: verified.ruleset,
      nextState: verified.nextState,
    };
  } catch (error) {
    return {
      accepted: false,
      error:
        error instanceof Error
          ? error.message
          : String(error),
      ruleset: null,
      nextState: null,
    };
  }
}
