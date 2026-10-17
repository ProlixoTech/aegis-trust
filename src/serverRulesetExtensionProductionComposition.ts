import type {
  StoredServerRulesetSnapshot,
} from "./serverRulesetLocalPersistence";

import type {
  ResolveServerRulesetFallbackResult,
  ServerRulesetDistributionChannel,
  ServerRulesetResolutionSource,
} from "./serverRulesetFallbackResolution";

import type {
  ServerRulesetRuleCategory,
  TrustedServerRuleset,
} from "./serverRulesetTrustProvider";

import {
  composeServerRulesetRuntimeResolution,
  type ComposeServerRulesetRuntimeResolutionInput,
  type ComposeServerRulesetRuntimeResolutionResult,
} from "./serverRulesetRuntimeComposition";

import {
  buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines,
  evaluateAiExecutionGatewayMvp0ServerRuleset,
  type AiExecutionGatewayMvp0ServerRulesetEvaluationResult,
  type AiExecutionGatewayMvp0ServerRulesetReason,
} from "./aiExecutionGatewayMvp0Policy";

export type ServerRulesetExtensionProductionMaybePromise<T> =
  T | Promise<T>;

export interface ServerRulesetExtensionCurrentPackageSupply {
  readonly packageText: string;
  readonly anchoredAtEpochMs: number;
}

export interface ServerRulesetExtensionPersistedSupply {
  readonly snapshot: StoredServerRulesetSnapshot;
  readonly lkgAnchoredAtEpochMs: number;
}

export interface ServerRulesetExtensionProductionSupplyPorts {
  readonly readDistributionChannel:
    () => ServerRulesetExtensionProductionMaybePromise<
      ServerRulesetDistributionChannel
    >;

  readonly readNowEpochMs:
    () => ServerRulesetExtensionProductionMaybePromise<number>;

  readonly readPinnedRootPublicKeyPem:
    () => ServerRulesetExtensionProductionMaybePromise<string>;

  readonly readBundledFallbackRuleset:
    () => ServerRulesetExtensionProductionMaybePromise<
      TrustedServerRuleset
    >;

  readonly readCurrentPackage:
    () => ServerRulesetExtensionProductionMaybePromise<
      ServerRulesetExtensionCurrentPackageSupply | null
    >;

  readonly readPersistedSupply:
    () => ServerRulesetExtensionProductionMaybePromise<
      ServerRulesetExtensionPersistedSupply | null
    >;
}

export type ServerRulesetExtensionProductionIssue =
  | "NONE"
  | "PROPOSED_INPUT_INVALID"
  | "SUPPLY_PORTS_INVALID"
  | "DEPENDENCIES_INVALID"
  | "DISTRIBUTION_CHANNEL_READ_FAILED"
  | "DISTRIBUTION_CHANNEL_INVALID"
  | "NOW_EPOCH_MS_READ_FAILED"
  | "NOW_EPOCH_MS_INVALID"
  | "PINNED_ROOT_READ_FAILED"
  | "PINNED_ROOT_INVALID"
  | "BUNDLED_FALLBACK_READ_FAILED"
  | "BUNDLED_FALLBACK_INVALID"
  | "CURRENT_PACKAGE_READ_FAILED"
  | "CURRENT_PACKAGE_INVALID"
  | "CURRENT_ANCHOR_INVALID"
  | "PERSISTED_SUPPLY_READ_FAILED"
  | "PERSISTED_SUPPLY_INVALID"
  | "LKG_ANCHOR_INVALID"
  | "RUNTIME_COMPOSITION_FAILED"
  | "RUNTIME_COMPOSITION_INVALID"
  | "RUNTIME_RESOLUTION_REJECTED"
  | "RUNTIME_RESOLUTION_SOURCE_MISSING"
  | "GATEWAY_EVALUATION_FAILED"
  | "RECEIPT_BUILD_FAILED";

export interface ServerRulesetExtensionProductionEvaluationResult {
  readonly blocked: boolean;
  readonly accepted: boolean;
  readonly source: ServerRulesetResolutionSource | null;
  readonly matchedRuleId: string;
  readonly matchedCategory: ServerRulesetRuleCategory | null;
  readonly reason: AiExecutionGatewayMvp0ServerRulesetReason;
  readonly supplyIssue: ServerRulesetExtensionProductionIssue;
  readonly runtimeCompositionAccepted: boolean;
  readonly runtimeResolutionAccepted: boolean;
  readonly currentVerificationAccepted: boolean;
  readonly lkgVerificationAccepted: boolean;
  readonly antiRollbackFloorApplied: boolean;
  readonly receiptLines: readonly string[];
}

export interface ServerRulesetExtensionProductionComposition {
  readonly evaluate:
    (
      proposed: string
    ) => Promise<ServerRulesetExtensionProductionEvaluationResult>;
}

export interface ServerRulesetExtensionProductionDependencies {
  readonly composeRuntimeResolution:
    typeof composeServerRulesetRuntimeResolution;

  readonly evaluateGateway:
    typeof evaluateAiExecutionGatewayMvp0ServerRuleset;

  readonly buildBlockedReceiptLines:
    typeof buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines;
}

const DEFAULT_DEPENDENCIES:
  ServerRulesetExtensionProductionDependencies =
  Object.freeze({
    composeRuntimeResolution:
      composeServerRulesetRuntimeResolution,
    evaluateGateway:
      evaluateAiExecutionGatewayMvp0ServerRuleset,
    buildBlockedReceiptLines:
      buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines,
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

function isEpochMs(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isPositiveSafeInteger(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value > 0
  );
}

function isNonEmptyString(
  value: unknown
): value is string {
  return (
    typeof value === "string" &&
    value.length > 0
  );
}

function isSha256Text(
  value: unknown
): value is string {
  if (
    typeof value !== "string" ||
    value.length !== 64
  ) {
    return false;
  }

  const alphabet =
    "0123456789abcdefABCDEF";

  for (const character of value) {
    if (!alphabet.includes(character)) {
      return false;
    }
  }

  return true;
}

function isStoredServerRulesetSnapshot(
  value: unknown
): value is StoredServerRulesetSnapshot {
  if (!isRecord(value)) {
    return false;
  }

  const state =
    value.state;

  const lkg =
    value.lkg;

  if (
    !isRecord(state) ||
    !isRecord(lkg)
  ) {
    return false;
  }

  const activeRuleset =
    state.activeRuleset;

  if (!isRecord(activeRuleset)) {
    return false;
  }

  return (
    state.schemaVersion === 1 &&
    isPositiveSafeInteger(
      state.highestIntermediateSequence
    ) &&
    isNonEmptyString(
      state.intermediateKeyId
    ) &&
    isSha256Text(
      state.intermediateKeySha256
    ) &&
    isPositiveSafeInteger(
      activeRuleset.rulesetVersion
    ) &&
    isPositiveSafeInteger(
      activeRuleset.monotonicCounter
    ) &&
    isNonEmptyString(
      activeRuleset.notBefore
    ) &&
    isNonEmptyString(
      activeRuleset.notAfter
    ) &&
    isSha256Text(
      state.rulesetSha256
    ) &&
    isSha256Text(
      state.lkgPackageSha256
    ) &&
    lkg.schemaVersion === 1 &&
    isSha256Text(
      lkg.packageSha256
    ) &&
    isNonEmptyString(
      lkg.packageText
    )
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

function fixedGatewayFailure():
  AiExecutionGatewayMvp0ServerRulesetEvaluationResult {
  return Object.freeze({
    blocked: true,
    accepted: false,
    source: null,
    matchedRuleId: "",
    matchedCategory: null,
    reason:
      "SERVER_RULESET_MATCH_FAILED",
  });
}

function isSupplyPortsValid(
  ports:
    ServerRulesetExtensionProductionSupplyPorts
): boolean {
  return (
    isRecord(ports) &&
    typeof ports
      .readDistributionChannel ===
      "function" &&
    typeof ports
      .readNowEpochMs ===
      "function" &&
    typeof ports
      .readPinnedRootPublicKeyPem ===
      "function" &&
    typeof ports
      .readBundledFallbackRuleset ===
      "function" &&
    typeof ports
      .readCurrentPackage ===
      "function" &&
    typeof ports
      .readPersistedSupply ===
      "function"
  );
}

function areDependenciesValid(
  dependencies:
    ServerRulesetExtensionProductionDependencies
): boolean {
  return (
    isRecord(dependencies) &&
    typeof dependencies
      .composeRuntimeResolution ===
      "function" &&
    typeof dependencies
      .evaluateGateway ===
      "function" &&
    typeof dependencies
      .buildBlockedReceiptLines ===
      "function"
  );
}

function makeEvaluationResult(
  proposed: string,
  resolution:
    ResolveServerRulesetFallbackResult,
  issue:
    ServerRulesetExtensionProductionIssue,
  runtimeCompositionAccepted: boolean,
  currentVerificationAccepted: boolean,
  lkgVerificationAccepted: boolean,
  antiRollbackFloorApplied: boolean,
  dependencies:
    ServerRulesetExtensionProductionDependencies
): ServerRulesetExtensionProductionEvaluationResult {
  let gatewayResult:
    AiExecutionGatewayMvp0ServerRulesetEvaluationResult;

  let finalIssue = issue;

  try {
    gatewayResult =
      dependencies.evaluateGateway(
        proposed,
        resolution
      );
  } catch {
    gatewayResult =
      fixedGatewayFailure();

    finalIssue =
      "GATEWAY_EVALUATION_FAILED";
  }

  let receiptLines:
    readonly string[] =
    Object.freeze([]);

  if (gatewayResult.blocked) {
    try {
      receiptLines =
        Object.freeze([
          ...dependencies
            .buildBlockedReceiptLines({
              resolutionAccepted:
                resolution.accepted,
              resolutionSource:
                gatewayResult.source,
              matchedRuleId:
                gatewayResult
                  .matchedRuleId,
              matchedCategory:
                gatewayResult
                  .matchedCategory,
              reason:
                gatewayResult.reason,
            }),
        ]);
    } catch {
      receiptLines =
        Object.freeze([]);

      finalIssue =
        "RECEIPT_BUILD_FAILED";
    }
  }

  return Object.freeze({
    blocked:
      gatewayResult.blocked,
    accepted:
      (
        !gatewayResult.blocked &&
        gatewayResult.accepted &&
        finalIssue === "NONE"
      ),
    source:
      gatewayResult.source,
    matchedRuleId:
      gatewayResult.matchedRuleId,
    matchedCategory:
      gatewayResult.matchedCategory,
    reason:
      gatewayResult.reason,
    supplyIssue:
      finalIssue,
    runtimeCompositionAccepted,
    runtimeResolutionAccepted:
      resolution.accepted,
    currentVerificationAccepted,
    lkgVerificationAccepted,
    antiRollbackFloorApplied,
    receiptLines,
  });
}

function failClosed(
  proposed: string,
  issue:
    ServerRulesetExtensionProductionIssue,
  dependencies:
    ServerRulesetExtensionProductionDependencies
): ServerRulesetExtensionProductionEvaluationResult {
  return makeEvaluationResult(
    proposed,
    rejectedResolution(issue),
    issue,
    false,
    false,
    false,
    false,
    dependencies
  );
}

function validateCurrentSupply(
  value: unknown,
  nowEpochMs: number
):
  | {
      readonly accepted: true;
      readonly value:
        ServerRulesetExtensionCurrentPackageSupply | null;
    }
  | {
      readonly accepted: false;
      readonly issue:
        ServerRulesetExtensionProductionIssue;
    } {
  if (value === null) {
    return Object.freeze({
      accepted: true,
      value: null,
    });
  }

  if (
    !isRecord(value) ||
    typeof value.packageText !==
      "string" ||
    value.packageText.length < 1
  ) {
    return Object.freeze({
      accepted: false,
      issue:
        "CURRENT_PACKAGE_INVALID",
    });
  }

  if (
    !isEpochMs(
      value.anchoredAtEpochMs
    ) ||
    value.anchoredAtEpochMs >
      nowEpochMs
  ) {
    return Object.freeze({
      accepted: false,
      issue:
        "CURRENT_ANCHOR_INVALID",
    });
  }

  return Object.freeze({
    accepted: true,
    value:
      Object.freeze({
        packageText:
          value.packageText,
        anchoredAtEpochMs:
          value.anchoredAtEpochMs,
      }),
  });
}

function validatePersistedSupply(
  value: unknown,
  nowEpochMs: number
):
  | {
      readonly accepted: true;
      readonly value:
        ServerRulesetExtensionPersistedSupply | null;
    }
  | {
      readonly accepted: false;
      readonly issue:
        ServerRulesetExtensionProductionIssue;
    } {
  if (value === null) {
    return Object.freeze({
      accepted: true,
      value: null,
    });
  }

  if (!isRecord(value)) {
    return Object.freeze({
      accepted: false,
      issue:
        "PERSISTED_SUPPLY_INVALID",
    });
  }

  const snapshot =
    value.snapshot;

  if (
    !isStoredServerRulesetSnapshot(
      snapshot
    )
  ) {
    return Object.freeze({
      accepted: false,
      issue:
        "PERSISTED_SUPPLY_INVALID",
    });
  }

  if (
    !isEpochMs(
      value.lkgAnchoredAtEpochMs
    ) ||
    value.lkgAnchoredAtEpochMs >
      nowEpochMs
  ) {
    return Object.freeze({
      accepted: false,
      issue:
        "LKG_ANCHOR_INVALID",
    });
  }

  return Object.freeze({
    accepted: true,
    value:
      Object.freeze({
        snapshot,
        lkgAnchoredAtEpochMs:
          value.lkgAnchoredAtEpochMs,
      }),
  });
}

export function createServerRulesetExtensionProductionComposition(
  ports:
    ServerRulesetExtensionProductionSupplyPorts,
  dependencies:
    ServerRulesetExtensionProductionDependencies =
    DEFAULT_DEPENDENCIES
): ServerRulesetExtensionProductionComposition {
  return Object.freeze({
    evaluate:
      async (
        proposed: string
      ): Promise<ServerRulesetExtensionProductionEvaluationResult> => {
        if (
          typeof proposed !==
          "string"
        ) {
          return failClosed(
            "",
            "PROPOSED_INPUT_INVALID",
            dependencies
          );
        }

        if (
          !isSupplyPortsValid(
            ports
          )
        ) {
          return failClosed(
            proposed,
            "SUPPLY_PORTS_INVALID",
            dependencies
          );
        }

        if (
          !areDependenciesValid(
            dependencies
          )
        ) {
          return Object.freeze({
            blocked: true,
            accepted: false,
            source: null,
            matchedRuleId: "",
            matchedCategory: null,
            reason:
              "SERVER_RULESET_MATCH_FAILED",
            supplyIssue:
              "DEPENDENCIES_INVALID",
            runtimeCompositionAccepted:
              false,
            runtimeResolutionAccepted:
              false,
            currentVerificationAccepted:
              false,
            lkgVerificationAccepted:
              false,
            antiRollbackFloorApplied:
              false,
            receiptLines:
              Object.freeze([]),
          });
        }

        let channel:
          ServerRulesetDistributionChannel;

        try {
          channel =
            await ports
              .readDistributionChannel();
        } catch {
          return failClosed(
            proposed,
            "DISTRIBUTION_CHANNEL_READ_FAILED",
            dependencies
          );
        }

        if (
          channel !==
            "free-stable" &&
          channel !==
            "fast-strict"
        ) {
          return failClosed(
            proposed,
            "DISTRIBUTION_CHANNEL_INVALID",
            dependencies
          );
        }

        let nowEpochMs: number;

        try {
          nowEpochMs =
            await ports
              .readNowEpochMs();
        } catch {
          return failClosed(
            proposed,
            "NOW_EPOCH_MS_READ_FAILED",
            dependencies
          );
        }

        if (
          !isEpochMs(
            nowEpochMs
          )
        ) {
          return failClosed(
            proposed,
            "NOW_EPOCH_MS_INVALID",
            dependencies
          );
        }

        let pinnedRootPublicKeyPem:
          string;

        try {
          pinnedRootPublicKeyPem =
            await ports
              .readPinnedRootPublicKeyPem();
        } catch {
          return failClosed(
            proposed,
            "PINNED_ROOT_READ_FAILED",
            dependencies
          );
        }

        if (
          typeof pinnedRootPublicKeyPem !==
            "string" ||
          pinnedRootPublicKeyPem
            .trim()
            .length < 1
        ) {
          return failClosed(
            proposed,
            "PINNED_ROOT_INVALID",
            dependencies
          );
        }

        let fallbackRuleset:
          TrustedServerRuleset;

        try {
          fallbackRuleset =
            await ports
              .readBundledFallbackRuleset();
        } catch {
          return failClosed(
            proposed,
            "BUNDLED_FALLBACK_READ_FAILED",
            dependencies
          );
        }

        if (
          !isRecord(
            fallbackRuleset
          )
        ) {
          return failClosed(
            proposed,
            "BUNDLED_FALLBACK_INVALID",
            dependencies
          );
        }

        let currentSupplyRaw:
          ServerRulesetExtensionCurrentPackageSupply |
          null;

        try {
          currentSupplyRaw =
            await ports
              .readCurrentPackage();
        } catch {
          return failClosed(
            proposed,
            "CURRENT_PACKAGE_READ_FAILED",
            dependencies
          );
        }

        const currentSupply =
          validateCurrentSupply(
            currentSupplyRaw,
            nowEpochMs
          );

        if (!currentSupply.accepted) {
          return failClosed(
            proposed,
            currentSupply.issue,
            dependencies
          );
        }

        let persistedSupplyRaw:
          ServerRulesetExtensionPersistedSupply |
          null;

        try {
          persistedSupplyRaw =
            await ports
              .readPersistedSupply();
        } catch {
          return failClosed(
            proposed,
            "PERSISTED_SUPPLY_READ_FAILED",
            dependencies
          );
        }

        const persistedSupply =
          validatePersistedSupply(
            persistedSupplyRaw,
            nowEpochMs
          );

        if (!persistedSupply.accepted) {
          return failClosed(
            proposed,
            persistedSupply.issue,
            dependencies
          );
        }

        const runtimeInput:
          ComposeServerRulesetRuntimeResolutionInput =
          Object.freeze({
            channel,
            nowEpochMs,
            pinnedRootPublicKeyPem,
            fallbackRuleset,
            currentPackageText:
              currentSupply.value ===
                null
                ? null
                : currentSupply.value
                    .packageText,
            currentAnchoredAtEpochMs:
              currentSupply.value ===
                null
                ? null
                : currentSupply.value
                    .anchoredAtEpochMs,
            persistedSnapshot:
              persistedSupply.value ===
                null
                ? null
                : persistedSupply.value
                    .snapshot,
            lkgAnchoredAtEpochMs:
              persistedSupply.value ===
                null
                ? null
                : persistedSupply.value
                    .lkgAnchoredAtEpochMs,
          });

        let runtimeResult:
          ComposeServerRulesetRuntimeResolutionResult;

        try {
          runtimeResult =
            dependencies
              .composeRuntimeResolution(
                runtimeInput
              );
        } catch {
          return failClosed(
            proposed,
            "RUNTIME_COMPOSITION_FAILED",
            dependencies
          );
        }

        if (
          !isRecord(runtimeResult) ||
          !isRecord(
            runtimeResult.resolution
          )
        ) {
          return failClosed(
            proposed,
            "RUNTIME_COMPOSITION_INVALID",
            dependencies
          );
        }

        let issue:
          ServerRulesetExtensionProductionIssue =
          "NONE";

        if (
          !runtimeResult.accepted ||
          !runtimeResult
            .resolution
            .accepted
        ) {
          issue =
            "RUNTIME_RESOLUTION_REJECTED";
        } else if (
          runtimeResult
            .resolution
            .source === null
        ) {
          issue =
            "RUNTIME_RESOLUTION_SOURCE_MISSING";
        }

        return makeEvaluationResult(
          proposed,
          runtimeResult.resolution,
          issue,
          runtimeResult.accepted,
          runtimeResult
            .currentVerificationAccepted,
          runtimeResult
            .lkgVerificationAccepted,
          runtimeResult
            .antiRollbackFloorApplied,
          dependencies
        );
      },
  });
}
