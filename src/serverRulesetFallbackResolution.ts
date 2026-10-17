import * as crypto from "node:crypto";

import {
  canonicalizeServerRulesetValue,
  type ServerRulesetRuleCategory,
  type ServerRulesetTrustState,
  type TrustedServerRuleset,
  type TrustedServerRulesetRule,
} from "./serverRulesetTrustProvider";

import {
  compileServerRulesetSafeRegex,
} from "./serverRulesetSafeRegex";

export const SERVER_RULESET_DAY_MS =
  24 * 60 * 60 * 1000;

export const FREE_STABLE_FRESHNESS_DAYS =
  30;

export const FREE_STABLE_HARD_LIMIT_DAYS =
  60;

export const FAST_STRICT_FRESHNESS_DAYS =
  7;

export const FAST_STRICT_HARD_LIMIT_DAYS =
  30;

export type ServerRulesetDistributionChannel =
  | "free-stable"
  | "fast-strict";

export type ServerRulesetResolutionSource =
  | "CURRENT"
  | "LKG"
  | "FALLBACK";

export interface AnchoredTrustedServerRuleset {
  readonly ruleset: TrustedServerRuleset;
  readonly state: ServerRulesetTrustState;
  readonly anchoredAtEpochMs: number;
}

export interface ServerRulesetAntiRollbackFloor {
  readonly highestIntermediateSequence: number;
  readonly rulesetVersion: number;
  readonly monotonicCounter: number;
  readonly rulesetSha256: string;
}

export interface ResolveServerRulesetFallbackInput {
  readonly channel: ServerRulesetDistributionChannel;
  readonly nowEpochMs: number;
  readonly current: AnchoredTrustedServerRuleset | null;
  readonly lkg: AnchoredTrustedServerRuleset | null;
  readonly fallbackRuleset: TrustedServerRuleset;
  readonly antiRollbackFloor?: ServerRulesetAntiRollbackFloor;
}

export interface ResolveServerRulesetFallbackResult {
  readonly accepted: boolean;
  readonly source: ServerRulesetResolutionSource | null;
  readonly reason: string;
  readonly freshUntilEpochMs: number | null;
  readonly hardUntilEpochMs: number | null;
  readonly rules: readonly TrustedServerRulesetRule[];
  readonly currentDiagnostic: string;
  readonly lkgDiagnostic: string;
}

interface ValidatedActiveRulesetMetadata {
  readonly rulesetVersion: number;
  readonly monotonicCounter: number;
  readonly notBefore: string;
  readonly notAfter: string;
}

interface ValidatedServerRulesetTrustState {
  readonly highestIntermediateSequence: number;
  readonly intermediateKeyId: string;
  readonly intermediateKeySha256: string;
  readonly activeRuleset: ValidatedActiveRulesetMetadata;
  readonly rulesetSha256: string;
}

interface ChannelLimits {
  readonly freshnessDays: number;
  readonly hardLimitDays: number;
}

interface CandidateAssessment {
  readonly usable: boolean;
  readonly fresh: boolean;
  readonly diagnostic: string;
  readonly freshUntilEpochMs: number | null;
  readonly hardUntilEpochMs: number | null;
  readonly ruleset: TrustedServerRuleset | null;
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

function isSha256(
  value: unknown
): value is string {
  return (
    typeof value === "string" &&
    /^[a-f0-9]{64}$/.test(value)
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

function channelLimits(
  channel: ServerRulesetDistributionChannel
): ChannelLimits {
  if (channel === "free-stable") {
    return {
      freshnessDays:
        FREE_STABLE_FRESHNESS_DAYS,
      hardLimitDays:
        FREE_STABLE_HARD_LIMIT_DAYS,
    };
  }

  if (channel === "fast-strict") {
    return {
      freshnessDays:
        FAST_STRICT_FRESHNESS_DAYS,
      hardLimitDays:
        FAST_STRICT_HARD_LIMIT_DAYS,
    };
  }

  throw new Error(
    "INVALID_SERVER_RULESET_CHANNEL"
  );
}

function parseTimestamp(
  value: unknown,
  errorCode: string
): number {
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

  return epochMs;
}

function validateRule(
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
      "INVALID_RESOLUTION_RULE"
    );
  }

  const compiled =
    compileServerRulesetSafeRegex(
      value.pattern
    );

  if (!compiled.accepted) {
    throw new Error(
      "UNSAFE_RESOLUTION_RULE_PATTERN=" +
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

function validateRuleset(
  value: unknown,
  requireFallbackOnlyCategories: boolean
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
    value.rules.length < 1
  ) {
    throw new Error(
      "INVALID_RESOLUTION_RULESET"
    );
  }

  const notBeforeEpochMs =
    parseTimestamp(
      value.notBefore,
      "INVALID_RESOLUTION_NOT_BEFORE"
    );

  const notAfterEpochMs =
    parseTimestamp(
      value.notAfter,
      "INVALID_RESOLUTION_NOT_AFTER"
    );

  if (
    notAfterEpochMs <=
    notBeforeEpochMs
  ) {
    throw new Error(
      "INVALID_RESOLUTION_VALIDITY_WINDOW"
    );
  }

  const identifiers =
    new Set<string>();

  const rules =
    value.rules.map(candidate => {
      const rule =
        validateRule(candidate);

      if (identifiers.has(rule.ruleId)) {
        throw new Error(
          "DUPLICATE_RESOLUTION_RULE_ID"
        );
      }

      if (
        requireFallbackOnlyCategories &&
        rule.category !== "catastrophic"
      ) {
        throw new Error(
          "FALLBACK_RULE_MUST_BE_CATASTROPHIC"
        );
      }

      identifiers.add(rule.ruleId);
      return rule;
    });

  return Object.freeze({
    schemaVersion: 1,
    rulesetId: value.rulesetId,
    rulesetVersion:
      value.rulesetVersion as number,
    monotonicCounter:
      value.monotonicCounter as number,
    notBefore: value.notBefore as string,
    notAfter: value.notAfter as string,
    rules: Object.freeze(rules),
  });
}

function validateState(
  value: unknown
): ValidatedServerRulesetTrustState {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "activeRuleset",
        "highestIntermediateSequence",
        "intermediateKeyId",
        "intermediateKeySha256",
        "rulesetSha256",
      ]
    ) ||
    !Number.isSafeInteger(
      value.highestIntermediateSequence
    ) ||
    (
      value.highestIntermediateSequence as number
    ) < 1 ||
    !isIdentifier(
      value.intermediateKeyId
    ) ||
    !isSha256(
      value.intermediateKeySha256
    ) ||
    !isSha256(
      value.rulesetSha256
    ) ||
    !isRecord(value.activeRuleset) ||
    !hasExactKeys(
      value.activeRuleset,
      [
        "monotonicCounter",
        "notAfter",
        "notBefore",
        "rulesetVersion",
      ]
    ) ||
    !Number.isSafeInteger(
      value.activeRuleset.rulesetVersion
    ) ||
    (
      value.activeRuleset.rulesetVersion as number
    ) < 1 ||
    !Number.isSafeInteger(
      value.activeRuleset.monotonicCounter
    ) ||
    (
      value.activeRuleset.monotonicCounter as number
    ) < 1 ||
    typeof value.activeRuleset.notBefore !==
      "string" ||
    typeof value.activeRuleset.notAfter !==
      "string"
  ) {
    throw new Error(
      "INVALID_RESOLUTION_TRUST_STATE"
    );
  }

  parseTimestamp(
    value.activeRuleset.notBefore,
    "INVALID_STATE_NOT_BEFORE"
  );

  parseTimestamp(
    value.activeRuleset.notAfter,
    "INVALID_STATE_NOT_AFTER"
  );

  return Object.freeze({
    highestIntermediateSequence:
      value.highestIntermediateSequence as number,
    intermediateKeyId:
      value.intermediateKeyId,
    intermediateKeySha256:
      value.intermediateKeySha256,
    activeRuleset:
      Object.freeze({
        rulesetVersion:
          value.activeRuleset.rulesetVersion as number,
        monotonicCounter:
          value.activeRuleset.monotonicCounter as number,
        notBefore:
          value.activeRuleset.notBefore,
        notAfter:
          value.activeRuleset.notAfter,
      }),
    rulesetSha256:
      value.rulesetSha256,
  });
}

function validateFloor(
  value: unknown
): ServerRulesetAntiRollbackFloor {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "highestIntermediateSequence",
        "monotonicCounter",
        "rulesetSha256",
        "rulesetVersion",
      ]
    ) ||
    !Number.isSafeInteger(
      value.highestIntermediateSequence
    ) ||
    (
      value.highestIntermediateSequence as number
    ) < 1 ||
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
    !isSha256(
      value.rulesetSha256
    )
  ) {
    throw new Error(
      "INVALID_ANTI_ROLLBACK_FLOOR"
    );
  }

  return Object.freeze({
    highestIntermediateSequence:
      value.highestIntermediateSequence as number,
    rulesetVersion:
      value.rulesetVersion as number,
    monotonicCounter:
      value.monotonicCounter as number,
    rulesetSha256:
      value.rulesetSha256,
  });
}

function assertRulesetStateLinkage(
  ruleset: TrustedServerRuleset,
  state: ValidatedServerRulesetTrustState
): void {
  if (
    state.activeRuleset.rulesetVersion !==
      ruleset.rulesetVersion ||
    state.activeRuleset.monotonicCounter !==
      ruleset.monotonicCounter ||
    state.activeRuleset.notBefore !==
      ruleset.notBefore ||
    state.activeRuleset.notAfter !==
      ruleset.notAfter
  ) {
    throw new Error(
      "RULESET_STATE_METADATA_MISMATCH"
    );
  }

  const rulesetSha256 =
    sha256Utf8(
      canonicalizeServerRulesetValue(
        ruleset
      )
    );

  if (
    rulesetSha256 !==
    state.rulesetSha256
  ) {
    throw new Error(
      "RULESET_STATE_HASH_MISMATCH"
    );
  }
}

function assertFloor(
  state: ValidatedServerRulesetTrustState,
  floor:
    ServerRulesetAntiRollbackFloor | undefined
): void {
  if (floor === undefined) {
    return;
  }

  if (
    state.highestIntermediateSequence <
    floor.highestIntermediateSequence
  ) {
    throw new Error(
      "ANTI_ROLLBACK_INTERMEDIATE_SEQUENCE"
    );
  }

  if (
    state.activeRuleset.rulesetVersion <
    floor.rulesetVersion
  ) {
    throw new Error(
      "ANTI_ROLLBACK_RULESET_VERSION"
    );
  }

  if (
    state.activeRuleset.monotonicCounter <
    floor.monotonicCounter
  ) {
    throw new Error(
      "ANTI_ROLLBACK_MONOTONIC_COUNTER"
    );
  }

  if (
    state.activeRuleset.rulesetVersion ===
      floor.rulesetVersion &&
    state.activeRuleset.monotonicCounter ===
      floor.monotonicCounter &&
    state.rulesetSha256 !==
      floor.rulesetSha256
  ) {
    throw new Error(
      "ANTI_ROLLBACK_RULESET_HASH_REBOUND"
    );
  }
}

function assessCandidate(
  candidate:
    AnchoredTrustedServerRuleset | null,
  label: "CURRENT" | "LKG",
  limits: ChannelLimits,
  nowEpochMs: number,
  floor:
    ServerRulesetAntiRollbackFloor | undefined
): CandidateAssessment {
  if (candidate === null) {
    return {
      usable: false,
      fresh: false,
      diagnostic:
        label + "_ABSENT",
      freshUntilEpochMs: null,
      hardUntilEpochMs: null,
      ruleset: null,
    };
  }

  try {
    if (
      !isRecord(candidate) ||
      !hasExactKeys(
        candidate,
        [
          "anchoredAtEpochMs",
          "ruleset",
          "state",
        ]
      ) ||
      !Number.isSafeInteger(
        candidate.anchoredAtEpochMs
      ) ||
      candidate.anchoredAtEpochMs < 0
    ) {
      throw new Error(
        "INVALID_ANCHORED_CANDIDATE"
      );
    }

    if (
      candidate.anchoredAtEpochMs >
      nowEpochMs
    ) {
      throw new Error(
        "ANCHOR_TIME_IN_FUTURE"
      );
    }

    const ruleset =
      validateRuleset(
        candidate.ruleset,
        false
      );

    const state =
      validateState(
        candidate.state
      );

    assertRulesetStateLinkage(
      ruleset,
      state
    );

    assertFloor(
      state,
      floor
    );

    const notBeforeEpochMs =
      parseTimestamp(
        ruleset.notBefore,
        "INVALID_CANDIDATE_NOT_BEFORE"
      );

    const notAfterEpochMs =
      parseTimestamp(
        ruleset.notAfter,
        "INVALID_CANDIDATE_NOT_AFTER"
      );

    const freshUntilEpochMs =
      Math.min(
        candidate.anchoredAtEpochMs +
          limits.freshnessDays *
          SERVER_RULESET_DAY_MS,
        notAfterEpochMs
      );

    const hardUntilEpochMs =
      Math.min(
        candidate.anchoredAtEpochMs +
          limits.hardLimitDays *
          SERVER_RULESET_DAY_MS,
        notAfterEpochMs
      );

    if (
      nowEpochMs <
      notBeforeEpochMs
    ) {
      return {
        usable: false,
        fresh: false,
        diagnostic:
          label + "_NOT_YET_VALID",
        freshUntilEpochMs,
        hardUntilEpochMs,
        ruleset: null,
      };
    }

    if (
      nowEpochMs >=
      hardUntilEpochMs
    ) {
      return {
        usable: false,
        fresh: false,
        diagnostic:
          label + "_HARD_EXPIRED",
        freshUntilEpochMs,
        hardUntilEpochMs,
        ruleset: null,
      };
    }

    const fresh =
      nowEpochMs <
      freshUntilEpochMs;

    return {
      usable: true,
      fresh,
      diagnostic:
        fresh
          ? label + "_FRESH"
          : label + "_STALE_HARD_VALID",
      freshUntilEpochMs,
      hardUntilEpochMs,
      ruleset,
    };
  } catch (error) {
    return {
      usable: false,
      fresh: false,
      diagnostic:
        label +
        "_REJECTED=" +
        (
          error instanceof Error
            ? error.message
            : String(error)
        ),
      freshUntilEpochMs: null,
      hardUntilEpochMs: null,
      ruleset: null,
    };
  }
}

function mergeStrictestRules(
  baseRules:
    readonly TrustedServerRulesetRule[],
  fallbackRules:
    readonly TrustedServerRulesetRule[]
): readonly TrustedServerRulesetRule[] {
  const byId =
    new Map<string, TrustedServerRulesetRule>();

  for (const rule of baseRules) {
    byId.set(
      rule.ruleId,
      Object.freeze({
        ruleId: rule.ruleId,
        category: rule.category,
        pattern: rule.pattern,
      })
    );
  }

  for (const rule of fallbackRules) {
    byId.set(
      rule.ruleId,
      Object.freeze({
        ruleId: rule.ruleId,
        category: rule.category,
        pattern: rule.pattern,
      })
    );
  }

  return Object.freeze(
    Array.from(byId.values())
      .sort(
        (left, right) =>
          left.ruleId.localeCompare(
            right.ruleId
          ) ||
          left.category.localeCompare(
            right.category
          ) ||
          left.pattern.localeCompare(
            right.pattern
          )
      )
  );
}

export function resolveServerRulesetFallback(
  input: ResolveServerRulesetFallbackInput
): ResolveServerRulesetFallbackResult {
  try {
    if (
      !isRecord(input) ||
      !hasExactKeys(
        input,
        [
          "antiRollbackFloor",
          "channel",
          "current",
          "fallbackRuleset",
          "lkg",
          "nowEpochMs",
        ].filter(
          key =>
            key !==
              "antiRollbackFloor" ||
            Object.prototype
              .hasOwnProperty.call(
                input,
                key
              )
        )
      ) ||
      !Number.isSafeInteger(
        input.nowEpochMs
      ) ||
      input.nowEpochMs < 0
    ) {
      throw new Error(
        "INVALID_FALLBACK_RESOLUTION_INPUT"
      );
    }

    const limits =
      channelLimits(input.channel);

    const floor =
      input.antiRollbackFloor ===
      undefined
        ? undefined
        : validateFloor(
            input.antiRollbackFloor
          );

    const fallback =
      validateRuleset(
        input.fallbackRuleset,
        true
      );

    const current =
      assessCandidate(
        input.current,
        "CURRENT",
        limits,
        input.nowEpochMs,
        floor
      );

    const lkg =
      assessCandidate(
        input.lkg,
        "LKG",
        limits,
        input.nowEpochMs,
        floor
      );

    if (
      current.usable &&
      current.fresh &&
      current.ruleset !== null
    ) {
      return Object.freeze({
        accepted: true,
        source: "CURRENT" as const,
        reason:
          "FRESH_CURRENT_SELECTED",
        freshUntilEpochMs:
          current.freshUntilEpochMs,
        hardUntilEpochMs:
          current.hardUntilEpochMs,
        rules:
          mergeStrictestRules(
            current.ruleset.rules,
            fallback.rules
          ),
        currentDiagnostic:
          current.diagnostic,
        lkgDiagnostic:
          lkg.diagnostic,
      });
    }

    if (
      lkg.usable &&
      lkg.ruleset !== null
    ) {
      return Object.freeze({
        accepted: true,
        source: "LKG" as const,
        reason:
          "CURRENT_UNAVAILABLE_LKG_SELECTED",
        freshUntilEpochMs:
          lkg.freshUntilEpochMs,
        hardUntilEpochMs:
          lkg.hardUntilEpochMs,
        rules:
          mergeStrictestRules(
            lkg.ruleset.rules,
            fallback.rules
          ),
        currentDiagnostic:
          current.diagnostic,
        lkgDiagnostic:
          lkg.diagnostic,
      });
    }

    return Object.freeze({
      accepted: true,
      source: "FALLBACK" as const,
      reason:
        "NO_USABLE_CURRENT_OR_LKG",
      freshUntilEpochMs: null,
      hardUntilEpochMs: null,
      rules:
        mergeStrictestRules(
          [],
          fallback.rules
        ),
      currentDiagnostic:
        current.diagnostic,
      lkgDiagnostic:
        lkg.diagnostic,
    });
  } catch (error) {
    return Object.freeze({
      accepted: false,
      source: null,
      reason:
        error instanceof Error
          ? error.message
          : String(error),
      freshUntilEpochMs: null,
      hardUntilEpochMs: null,
      rules: Object.freeze([]),
      currentDiagnostic:
        "NOT_EVALUATED",
      lkgDiagnostic:
        "NOT_EVALUATED",
    });
  }
}
