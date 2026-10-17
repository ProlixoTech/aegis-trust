import test from "node:test";
import assert from "node:assert/strict";

import type {
  ResolveServerRulesetFallbackResult,
} from "./serverRulesetFallbackResolution";

import type {
  ComposeServerRulesetRuntimeResolutionResult,
} from "./serverRulesetRuntimeComposition";

import type {
  TrustedServerRuleset,
} from "./serverRulesetTrustProvider";

import {
  createServerRulesetExtensionProductionComposition,
  type ServerRulesetExtensionProductionDependencies,
  type ServerRulesetExtensionProductionSupplyPorts,
} from "./serverRulesetExtensionProductionComposition";

import {
  buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines,
  evaluateAiExecutionGatewayMvp0ServerRuleset,
} from "./aiExecutionGatewayMvp0Policy";

const nowEpochMs =
  Date.parse(
    "2026-07-26T00:00:00.000Z"
  );

const pinnedRootPublicKeyPem =
  [
    "-----BEGIN PUBLIC KEY-----",
    "cHJvZHVjdGlvbi1ib3VuZGFyeS10ZXN0",
    "-----END PUBLIC KEY-----",
  ].join("\n");

function fallbackRuleset(
  pattern =
    "blocked-command"
): TrustedServerRuleset {
  return {
    schemaVersion: 1,
    rulesetId:
      "bundled-fallback",
    rulesetVersion: 1,
    monotonicCounter: 1,
    notBefore:
      "2026-01-01T00:00:00.000Z",
    notAfter:
      "2027-01-01T00:00:00.000Z",
    rules: [
      {
        ruleId:
          "fallback-critical",
        category:
          "catastrophic",
        pattern,
      },
    ],
  };
}

function supplyPorts(
  overrides:
    Partial<ServerRulesetExtensionProductionSupplyPorts> = {}
): ServerRulesetExtensionProductionSupplyPorts {
  return {
    readDistributionChannel:
      () => "free-stable",

    readNowEpochMs:
      () => nowEpochMs,

    readPinnedRootPublicKeyPem:
      () =>
        pinnedRootPublicKeyPem,

    readBundledFallbackRuleset:
      () =>
        fallbackRuleset(),

    readCurrentPackage:
      () => null,

    readPersistedSupply:
      () => null,

    ...overrides,
  };
}

function rejectedResolution(
  reason =
    "TEST_REJECTED"
): ResolveServerRulesetFallbackResult {
  return {
    accepted: false,
    source: null,
    reason,
    freshUntilEpochMs: null,
    hardUntilEpochMs: null,
    rules: [],
    currentDiagnostic:
      "NOT_EVALUATED",
    lkgDiagnostic:
      "NOT_EVALUATED",
  };
}

function runtimeResult(
  resolution:
    ResolveServerRulesetFallbackResult,
  accepted =
    resolution.accepted
): ComposeServerRulesetRuntimeResolutionResult {
  return {
    accepted,
    resolution,
    currentVerificationAccepted:
      false,
    currentVerificationError:
      null,
    lkgVerificationAccepted:
      false,
    lkgVerificationError:
      null,
    antiRollbackFloorApplied:
      false,
  };
}

function dependenciesWithRuntimeResult(
  result:
    ComposeServerRulesetRuntimeResolutionResult
): ServerRulesetExtensionProductionDependencies {
  return {
    composeRuntimeResolution:
      () => result,

    evaluateGateway:
      evaluateAiExecutionGatewayMvp0ServerRuleset,

    buildBlockedReceiptLines:
      buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines,
  };
}

test("extension production composition passes through an allowed resolved ruleset", async () => {
  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts()
    );

  const result =
    await composition.evaluate(
      "Get-Content package.json"
    );

  assert.equal(
    result.blocked,
    false
  );

  assert.equal(
    result.accepted,
    true
  );

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.equal(
    result.supplyIssue,
    "NONE"
  );

  assert.deepEqual(
    result.receiptLines,
    []
  );
});

test("extension production composition blocks a matching resolved rule", async () => {
  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts()
    );

  const result =
    await composition.evaluate(
      "prefix blocked-command suffix"
    );

  assert.equal(
    result.blocked,
    true
  );

  assert.equal(
    result.accepted,
    false
  );

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.equal(
    result.matchedRuleId,
    "fallback-critical"
  );

  assert.equal(
    result.reason,
    "SERVER_RULESET_MATCHED"
  );

  assert.equal(
    result.receiptLines.length >
      0,
    true
  );
});

test("extension production composition fails closed on rejected runtime resolution", async () => {
  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts(),
      dependenciesWithRuntimeResult(
        runtimeResult(
          rejectedResolution(),
          false
        )
      )
    );

  const result =
    await composition.evaluate(
      "Get-Content package.json"
    );

  assert.equal(
    result.blocked,
    true
  );

  assert.equal(
    result.supplyIssue,
    "RUNTIME_RESOLUTION_REJECTED"
  );

  assert.equal(
    result.runtimeResolutionAccepted,
    false
  );
});

test("extension production composition fails closed on null runtime source", async () => {
  const resolution:
    ResolveServerRulesetFallbackResult = {
      accepted: true,
      source: null,
      reason:
        "TEST_NULL_SOURCE",
      freshUntilEpochMs:
        null,
      hardUntilEpochMs:
        null,
      rules:
        fallbackRuleset().rules,
      currentDiagnostic:
        "CURRENT_NONE",
      lkgDiagnostic:
        "LKG_NONE",
    };

  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts(),
      dependenciesWithRuntimeResult(
        runtimeResult(
          resolution,
          true
        )
      )
    );

  const result =
    await composition.evaluate(
      "Get-Content package.json"
    );

  assert.equal(
    result.blocked,
    true
  );

  assert.equal(
    result.supplyIssue,
    "RUNTIME_RESOLUTION_SOURCE_MISSING"
  );

  assert.equal(
    result.source,
    null
  );
});

test("extension production composition fails closed when pinned root provider throws", async () => {
  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts({
        readPinnedRootPublicKeyPem:
          () => {
            throw new Error(
              "root unavailable"
            );
          },
      })
    );

  const result =
    await composition.evaluate(
      "Get-Content package.json"
    );

  assert.equal(
    result.blocked,
    true
  );

  assert.equal(
    result.supplyIssue,
    "PINNED_ROOT_READ_FAILED"
  );
});

test("extension production composition fails closed when fallback provider throws", async () => {
  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts({
        readBundledFallbackRuleset:
          () => {
            throw new Error(
              "fallback unavailable"
            );
          },
      })
    );

  const result =
    await composition.evaluate(
      "Get-Content package.json"
    );

  assert.equal(
    result.blocked,
    true
  );

  assert.equal(
    result.supplyIssue,
    "BUNDLED_FALLBACK_READ_FAILED"
  );
});

test("extension production composition fails closed when current package provider throws", async () => {
  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts({
        readCurrentPackage:
          () => {
            throw new Error(
              "current unavailable"
            );
          },
      })
    );

  const result =
    await composition.evaluate(
      "Get-Content package.json"
    );

  assert.equal(
    result.blocked,
    true
  );

  assert.equal(
    result.supplyIssue,
    "CURRENT_PACKAGE_READ_FAILED"
  );
});

test("extension production composition fails closed when persisted supply provider throws", async () => {
  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts({
        readPersistedSupply:
          () => {
            throw new Error(
              "persisted unavailable"
            );
          },
      })
    );

  const result =
    await composition.evaluate(
      "Get-Content package.json"
    );

  assert.equal(
    result.blocked,
    true
  );

  assert.equal(
    result.supplyIssue,
    "PERSISTED_SUPPLY_READ_FAILED"
  );
});

test("extension production composition fails closed on invalid future anchor", async () => {
  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts({
        readCurrentPackage:
          () => ({
            packageText:
              "signed-current-package",
            anchoredAtEpochMs:
              nowEpochMs + 1,
          }),
      })
    );

  const result =
    await composition.evaluate(
      "Get-Content package.json"
    );

  assert.equal(
    result.blocked,
    true
  );

  assert.equal(
    result.supplyIssue,
    "CURRENT_ANCHOR_INVALID"
  );

  assert.equal(
    result.runtimeCompositionAccepted,
    false
  );
});

test("extension production composition produces deterministic repeated evaluation", async () => {
  const composition =
    createServerRulesetExtensionProductionComposition(
      supplyPorts()
    );

  const first =
    await composition.evaluate(
      "prefix blocked-command suffix"
    );

  const second =
    await composition.evaluate(
      "prefix blocked-command suffix"
    );

  assert.deepEqual(
    first,
    second
  );
});

test("extension production composition does not mutate provider results", async () => {
  const fallback =
    Object.freeze(
      fallbackRuleset()
    );

  const current =
    Object.freeze({
      packageText:
        "current-package",
      anchoredAtEpochMs:
        nowEpochMs - 1,
    });

  const ports =
    supplyPorts({
      readBundledFallbackRuleset:
        () => fallback,

      readCurrentPackage:
        () => current,
    });

  const beforeFallback =
    JSON.stringify(fallback);

  const beforeCurrent =
    JSON.stringify(current);

  const composition =
    createServerRulesetExtensionProductionComposition(
      ports,
      dependenciesWithRuntimeResult(
        runtimeResult({
          accepted: true,
          source:
            "FALLBACK",
          reason:
            "TEST_FALLBACK",
          freshUntilEpochMs:
            null,
          hardUntilEpochMs:
            null,
          rules:
            fallback.rules,
          currentDiagnostic:
            "CURRENT_REJECTED",
          lkgDiagnostic:
            "LKG_ABSENT",
        })
      )
    );

  await composition.evaluate(
    "Get-Content package.json"
  );

  assert.equal(
    JSON.stringify(fallback),
    beforeFallback
  );

  assert.equal(
    JSON.stringify(current),
    beforeCurrent
  );
});

test("extension production composition receipt omits raw command pattern and key material", async () => {
  const rawCommand =
    "raw-command-secret-token";

  const rawPattern =
    "secret-pattern-token";

  const rawKeyMaterial =
    "private-root-material-token";

  const ports =
    supplyPorts({
      readPinnedRootPublicKeyPem:
        () =>
          [
            "-----BEGIN PUBLIC KEY-----",
            rawKeyMaterial,
            "-----END PUBLIC KEY-----",
          ].join("\n"),

      readBundledFallbackRuleset:
        () =>
          fallbackRuleset(
            rawPattern
          ),
    });

  const composition =
    createServerRulesetExtensionProductionComposition(
      ports
    );

  const result =
    await composition.evaluate(
      rawCommand +
      " " +
      rawPattern
    );

  const receiptText =
    result.receiptLines
      .join("\n");

  assert.equal(
    result.blocked,
    true
  );

  assert.equal(
    receiptText.includes(
      rawCommand
    ),
    false
  );

  assert.equal(
    receiptText.includes(
      rawPattern
    ),
    false
  );

  assert.equal(
    receiptText.includes(
      rawKeyMaterial
    ),
    false
  );
});
