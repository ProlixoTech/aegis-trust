import * as crypto from "node:crypto";

import type {
  StoredServerRulesetSnapshot,
} from "./serverRulesetLocalPersistence";

import {
  canonicalizeServerRulesetValue,
  verifySignedServerRulesetPackageText,
  type ServerRulesetTrustState,
  type TrustedServerRuleset,
} from "./serverRulesetTrustProvider";

import {
  resolveServerRulesetFallback,
  type AnchoredTrustedServerRuleset,
  type ResolveServerRulesetFallbackResult,
  type ServerRulesetAntiRollbackFloor,
  type ServerRulesetDistributionChannel,
} from "./serverRulesetFallbackResolution";

export interface ComposeServerRulesetRuntimeResolutionInput {
  readonly channel: ServerRulesetDistributionChannel;
  readonly nowEpochMs: number;
  readonly pinnedRootPublicKeyPem: string;
  readonly fallbackRuleset: TrustedServerRuleset;
  readonly currentPackageText?: string | null;
  readonly currentAnchoredAtEpochMs?: number | null;
  readonly persistedSnapshot?: StoredServerRulesetSnapshot | null;
  readonly lkgAnchoredAtEpochMs?: number | null;
}

export interface ComposeServerRulesetRuntimeResolutionResult {
  readonly accepted: boolean;
  readonly resolution: ResolveServerRulesetFallbackResult;
  readonly currentVerificationAccepted: boolean;
  readonly currentVerificationError: string | null;
  readonly lkgVerificationAccepted: boolean;
  readonly lkgVerificationError: string | null;
  readonly antiRollbackFloorApplied: boolean;
}

export interface ServerRulesetRuntimeCompositionDependencies {
  readonly verifyPackageText:
    typeof verifySignedServerRulesetPackageText;
  readonly resolveFallback:
    typeof resolveServerRulesetFallback;
}

interface ValidatedPersistedSnapshot {
  readonly trustState: ServerRulesetTrustState;
  readonly antiRollbackFloor: ServerRulesetAntiRollbackFloor;
  readonly packageText: string;
}

const DEFAULT_DEPENDENCIES:
  ServerRulesetRuntimeCompositionDependencies =
  Object.freeze({
    verifyPackageText:
      verifySignedServerRulesetPackageText,
    resolveFallback:
      resolveServerRulesetFallback,
  });

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

function isPositiveSafeInteger(
  value: unknown
): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) > 0
  );
}

function isEpochMs(
  value: unknown
): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= 0
  );
}

function isSha256(
  value: unknown
): value is string {
  if (
    typeof value !== "string" ||
    value.length !== 64
  ) {
    return false;
  }

  const alphabet =
    "0123456789abcdef";

  for (const character of value) {
    if (!alphabet.includes(character)) {
      return false;
    }
  }

  return true;
}

function isPinnedRootPem(
  value: unknown
): value is string {
  if (typeof value !== "string") {
    return false;
  }

  const normalized = value.trim();

  return (
    normalized.startsWith(
      "-----BEGIN PUBLIC KEY-----"
    ) &&
    normalized.endsWith(
      "-----END PUBLIC KEY-----"
    ) &&
    normalized.length >
      (
        "-----BEGIN PUBLIC KEY-----" +
        "-----END PUBLIC KEY-----"
      ).length
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

function errorText(
  error: unknown
): string {
  return (
    error instanceof Error
      ? error.message
      : String(error)
  );
}

function rejectedResolution(
  reason: string
): ResolveServerRulesetFallbackResult {
  return Object.freeze({
    accepted: false,
    source: null,
    reason,
    freshUntilEpochMs: null,
    hardUntilEpochMs: null,
    rules: Object.freeze([]),
    currentDiagnostic:
      "NOT_EVALUATED",
    lkgDiagnostic:
      "NOT_EVALUATED",
  });
}

function rejectedComposition(
  reason: string,
  currentVerificationError:
    string | null = null,
  lkgVerificationError:
    string | null = null
): ComposeServerRulesetRuntimeResolutionResult {
  return Object.freeze({
    accepted: false,
    resolution:
      rejectedResolution(reason),
    currentVerificationAccepted: false,
    currentVerificationError,
    lkgVerificationAccepted: false,
    lkgVerificationError,
    antiRollbackFloorApplied: false,
  });
}

function validateActiveRuleset(
  value: unknown
): {
  readonly rulesetVersion: number;
  readonly monotonicCounter: number;
  readonly notBefore: string;
  readonly notAfter: string;
} {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "monotonicCounter",
        "notAfter",
        "notBefore",
        "rulesetVersion",
      ]
    ) ||
    !isPositiveSafeInteger(
      value.rulesetVersion
    ) ||
    !isPositiveSafeInteger(
      value.monotonicCounter
    ) ||
    typeof value.notBefore !==
      "string" ||
    typeof value.notAfter !==
      "string"
  ) {
    throw new Error(
      "INVALID_PERSISTED_ACTIVE_RULESET"
    );
  }

  const notBeforeEpochMs =
    Date.parse(value.notBefore);

  const notAfterEpochMs =
    Date.parse(value.notAfter);

  if (
    !Number.isFinite(
      notBeforeEpochMs
    ) ||
    !Number.isFinite(
      notAfterEpochMs
    ) ||
    notAfterEpochMs <=
      notBeforeEpochMs
  ) {
    throw new Error(
      "INVALID_PERSISTED_ACTIVE_RULESET_WINDOW"
    );
  }

  return Object.freeze({
    rulesetVersion:
      value.rulesetVersion,
    monotonicCounter:
      value.monotonicCounter,
    notBefore:
      value.notBefore,
    notAfter:
      value.notAfter,
  });
}

function validatePersistedSnapshot(
  value: unknown
): ValidatedPersistedSnapshot {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "lkg",
        "state",
      ]
    ) ||
    !isRecord(value.state) ||
    !hasExactKeys(
      value.state,
      [
        "activeRuleset",
        "highestIntermediateSequence",
        "intermediateKeyId",
        "intermediateKeySha256",
        "lkgPackageSha256",
        "rulesetSha256",
        "schemaVersion",
      ]
    ) ||
    value.state.schemaVersion !== 1 ||
    !isPositiveSafeInteger(
      value.state
        .highestIntermediateSequence
    ) ||
    typeof value.state
      .intermediateKeyId !== "string" ||
    value.state
      .intermediateKeyId.length < 1 ||
    !isSha256(
      value.state
        .intermediateKeySha256
    ) ||
    !isSha256(
      value.state.rulesetSha256
    ) ||
    !isSha256(
      value.state
        .lkgPackageSha256
    ) ||
    !isRecord(value.lkg) ||
    !hasExactKeys(
      value.lkg,
      [
        "packageSha256",
        "packageText",
        "schemaVersion",
      ]
    ) ||
    value.lkg.schemaVersion !== 1 ||
    !isSha256(
      value.lkg.packageSha256
    ) ||
    typeof value.lkg.packageText !==
      "string" ||
    value.lkg.packageText.length < 1
  ) {
    throw new Error(
      "INVALID_PERSISTED_SERVER_RULESET_SNAPSHOT"
    );
  }

  const activeRuleset =
    validateActiveRuleset(
      value.state.activeRuleset
    );

  if (
    value.state
      .lkgPackageSha256 !==
    value.lkg.packageSha256
  ) {
    throw new Error(
      "PERSISTED_STATE_LKG_SHA256_MISMATCH"
    );
  }

  const rawPackageSha256 =
    sha256Utf8(
      value.lkg.packageText
    );

  if (
    rawPackageSha256 !==
    value.lkg.packageSha256
  ) {
    throw new Error(
      "PERSISTED_LKG_PACKAGE_SHA256_MISMATCH"
    );
  }

  const trustState:
    ServerRulesetTrustState =
    Object.freeze({
      highestIntermediateSequence:
        value.state
          .highestIntermediateSequence,
      intermediateKeyId:
        value.state
          .intermediateKeyId,
      intermediateKeySha256:
        value.state
          .intermediateKeySha256,
      activeRuleset,
      rulesetSha256:
        value.state.rulesetSha256,
    });

  const antiRollbackFloor:
    ServerRulesetAntiRollbackFloor =
    Object.freeze({
      highestIntermediateSequence:
        trustState
          .highestIntermediateSequence,
      rulesetVersion:
        activeRuleset.rulesetVersion,
      monotonicCounter:
        activeRuleset.monotonicCounter,
      rulesetSha256:
        trustState.rulesetSha256,
    });

  return Object.freeze({
    trustState,
    antiRollbackFloor,
    packageText:
      value.lkg.packageText,
  });
}

function trustStatesEqual(
  left: ServerRulesetTrustState,
  right: ServerRulesetTrustState
): boolean {
  return (
    canonicalizeServerRulesetValue(
      left
    ) ===
    canonicalizeServerRulesetValue(
      right
    )
  );
}

function candidateAnchorError(
  anchor: number | null | undefined,
  nowEpochMs: number,
  missingCode: string,
  invalidCode: string,
  futureCode: string
): string | null {
  if (
    anchor === undefined ||
    anchor === null
  ) {
    return missingCode;
  }

  if (!isEpochMs(anchor)) {
    return invalidCode;
  }

  if (anchor > nowEpochMs) {
    return futureCode;
  }

  return null;
}

function verifyCandidate(
  packageText: string,
  activeState:
    ServerRulesetTrustState | null,
  pinnedRootPublicKeyPem: string,
  nowEpochMs: number,
  anchoredAtEpochMs: number,
  dependencies:
    ServerRulesetRuntimeCompositionDependencies
): {
  readonly candidate:
    AnchoredTrustedServerRuleset | null;
  readonly error: string | null;
} {
  try {
    const verification =
      dependencies.verifyPackageText(
        packageText,
        {
          pinnedRootPublicKeyPem,
          activeState,
          nowEpochMs,
        }
      );

    if (
      !verification.accepted ||
      verification.ruleset === null ||
      verification.nextState === null
    ) {
      return Object.freeze({
        candidate: null,
        error:
          verification.error ??
          "SERVER_RULESET_VERIFICATION_REJECTED",
      });
    }

    return Object.freeze({
      candidate:
        Object.freeze({
          ruleset:
            verification.ruleset,
          state:
            verification.nextState,
          anchoredAtEpochMs,
        }),
      error: null,
    });
  } catch (error) {
    return Object.freeze({
      candidate: null,
      error:
        "SERVER_RULESET_VERIFICATION_THROW=" +
        errorText(error),
    });
  }
}

export function composeServerRulesetRuntimeResolution(
  input:
    ComposeServerRulesetRuntimeResolutionInput,
  dependencies:
    ServerRulesetRuntimeCompositionDependencies =
    DEFAULT_DEPENDENCIES
): ComposeServerRulesetRuntimeResolutionResult {
  if (
    !isRecord(input) ||
    (
      input.channel !==
        "free-stable" &&
      input.channel !==
        "fast-strict"
    ) ||
    !isEpochMs(input.nowEpochMs) ||
    !isPinnedRootPem(
      input.pinnedRootPublicKeyPem
    ) ||
    !isRecord(input.fallbackRuleset) ||
    !isRecord(dependencies) ||
    typeof dependencies
      .verifyPackageText !== "function" ||
    typeof dependencies
      .resolveFallback !== "function"
  ) {
    return rejectedComposition(
      "INVALID_RUNTIME_COMPOSITION_INPUT"
    );
  }

  const currentPackageProvided =
    input.currentPackageText !==
      undefined &&
    input.currentPackageText !== null;

  const currentAnchorProvided =
    input.currentAnchoredAtEpochMs !==
      undefined &&
    input.currentAnchoredAtEpochMs !==
      null;

  const snapshotProvided =
    input.persistedSnapshot !==
      undefined &&
    input.persistedSnapshot !== null;

  const lkgAnchorProvided =
    input.lkgAnchoredAtEpochMs !==
      undefined &&
    input.lkgAnchoredAtEpochMs !==
      null;

  if (
    currentAnchorProvided &&
    !currentPackageProvided
  ) {
    return rejectedComposition(
      "CURRENT_ANCHOR_WITHOUT_PACKAGE"
    );
  }

  if (
    lkgAnchorProvided &&
    !snapshotProvided
  ) {
    return rejectedComposition(
      "LKG_ANCHOR_WITHOUT_SNAPSHOT"
    );
  }

  if (
    currentPackageProvided &&
    (
      typeof input
        .currentPackageText !==
        "string" ||
      input.currentPackageText
        .length < 1
    )
  ) {
    return rejectedComposition(
      "INVALID_CURRENT_PACKAGE_TEXT",
      "INVALID_CURRENT_PACKAGE_TEXT"
    );
  }

  let validatedSnapshot:
    ValidatedPersistedSnapshot | null =
    null;

  let lkgCandidate:
    AnchoredTrustedServerRuleset | null =
    null;

  let currentCandidate:
    AnchoredTrustedServerRuleset | null =
    null;

  let lkgVerificationAccepted =
    false;

  let currentVerificationAccepted =
    false;

  let lkgVerificationError:
    string | null = null;

  let currentVerificationError:
    string | null = null;

  let antiRollbackFloorApplied =
    false;

  if (snapshotProvided) {
    try {
      validatedSnapshot =
        validatePersistedSnapshot(
          input.persistedSnapshot
        );
    } catch (error) {
      lkgVerificationError =
        errorText(error);
    }

    if (validatedSnapshot !== null) {
      const lkgAnchorError =
        candidateAnchorError(
          input.lkgAnchoredAtEpochMs,
          input.nowEpochMs,
          "LKG_ANCHOR_REQUIRED",
          "LKG_ANCHOR_INVALID",
          "LKG_ANCHOR_IN_FUTURE"
        );

      let lkgVerificationStateAccepted =
        false;

      try {
        const lkgVerification =
          dependencies.verifyPackageText(
            validatedSnapshot
              .packageText,
            {
              pinnedRootPublicKeyPem:
                input
                  .pinnedRootPublicKeyPem,
              activeState: null,
              nowEpochMs:
                input.nowEpochMs,
            }
          );

        if (
          !lkgVerification.accepted ||
          lkgVerification.ruleset ===
            null ||
          lkgVerification.nextState ===
            null
        ) {
          lkgVerificationError =
            lkgVerification.error ??
            "LKG_VERIFICATION_REJECTED";
        } else if (
          !trustStatesEqual(
            lkgVerification.nextState,
            validatedSnapshot
              .trustState
          )
        ) {
          lkgVerificationError =
            "LKG_VERIFIED_STATE_MISMATCH";
        } else {
          lkgVerificationStateAccepted =
            true;

          antiRollbackFloorApplied =
            true;

          if (lkgAnchorError !== null) {
            lkgVerificationError =
              lkgAnchorError;
          } else {
            lkgCandidate =
              Object.freeze({
                ruleset:
                  lkgVerification.ruleset,
                state:
                  lkgVerification
                    .nextState,
                anchoredAtEpochMs:
                  input
                    .lkgAnchoredAtEpochMs as number,
              });

            lkgVerificationAccepted =
              true;

            lkgVerificationError =
              null;
          }
        }
      } catch (error) {
        lkgVerificationError =
          "LKG_VERIFICATION_THROW=" +
          errorText(error);
      }

      if (
        !lkgVerificationStateAccepted
      ) {
        validatedSnapshot = null;
        antiRollbackFloorApplied =
          false;
      }
    }
  }

  if (currentPackageProvided) {
    const currentAnchorError =
      candidateAnchorError(
        input.currentAnchoredAtEpochMs,
        input.nowEpochMs,
        "CURRENT_ANCHOR_REQUIRED",
        "CURRENT_ANCHOR_INVALID",
        "CURRENT_ANCHOR_IN_FUTURE"
      );

    if (
      snapshotProvided &&
      validatedSnapshot === null
    ) {
      currentVerificationError =
        "PERSISTED_SNAPSHOT_UNUSABLE";
    } else if (
      currentAnchorError !== null
    ) {
      currentVerificationError =
        currentAnchorError;
    } else {
      const currentVerification =
        verifyCandidate(
          input.currentPackageText as string,
          validatedSnapshot === null
            ? null
            : validatedSnapshot
                .trustState,
          input.pinnedRootPublicKeyPem,
          input.nowEpochMs,
          input
            .currentAnchoredAtEpochMs as number,
          dependencies
        );

      currentCandidate =
        currentVerification.candidate;

      currentVerificationError =
        currentVerification.error;

      currentVerificationAccepted =
        currentCandidate !== null;
    }
  }

  let resolution:
    ResolveServerRulesetFallbackResult;

  try {
    resolution =
      dependencies.resolveFallback({
        channel: input.channel,
        nowEpochMs:
          input.nowEpochMs,
        current:
          currentCandidate,
        lkg:
          lkgCandidate,
        fallbackRuleset:
          input.fallbackRuleset,
        ...(
          validatedSnapshot === null
            ? {}
            : {
                antiRollbackFloor:
                  validatedSnapshot
                    .antiRollbackFloor,
              }
        ),
      });
  } catch (error) {
    resolution =
      rejectedResolution(
        "RUNTIME_RESOLVER_THROW=" +
        errorText(error)
      );
  }

  return Object.freeze({
    accepted:
      resolution.accepted,
    resolution,
    currentVerificationAccepted,
    currentVerificationError,
    lkgVerificationAccepted,
    lkgVerificationError,
    antiRollbackFloorApplied,
  });
}
