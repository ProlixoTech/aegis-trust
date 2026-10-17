import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";

import type {
  StoredServerRulesetSnapshot,
} from "./serverRulesetLocalPersistence";

import {
  canonicalizeServerRulesetValue,
  type ServerRulesetTrustState,
  type TrustedServerRuleset,
} from "./serverRulesetTrustProvider";

import {
  composeServerRulesetRuntimeResolution,
  type ComposeServerRulesetRuntimeResolutionInput,
  type ServerRulesetRuntimeCompositionDependencies,
} from "./serverRulesetRuntimeComposition";

import {
  resolveServerRulesetFallback,
} from "./serverRulesetFallbackResolution";

const nowEpochMs =
  Date.parse(
    "2026-07-26T00:00:00.000Z"
  );

const validPinnedRoot =
  [
    "-----BEGIN PUBLIC KEY-----",
    "ZmFrZS10ZXN0LXB1YmxpYy1rZXk=",
    "-----END PUBLIC KEY-----",
  ].join("\n");

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

function ruleset(
  id: string,
  version: number,
  counter: number,
  ruleId: string,
  pattern: string,
  category:
    | "catastrophic"
    | "destructive"
    | "secret-exposure"
    | "policy-bypass" =
      "catastrophic"
): TrustedServerRuleset {
  return {
    schemaVersion: 1,
    rulesetId: id,
    rulesetVersion: version,
    monotonicCounter: counter,
    notBefore:
      "2026-01-01T00:00:00.000Z",
    notAfter:
      "2027-01-01T00:00:00.000Z",
    rules: [
      {
        ruleId,
        category,
        pattern,
      },
    ],
  };
}

function stateFor(
  value: TrustedServerRuleset,
  sequence: number
): ServerRulesetTrustState {
  return {
    highestIntermediateSequence:
      sequence,
    intermediateKeyId:
      "intermediate-" +
      sequence.toString(10),
    intermediateKeySha256:
      sha256Utf8(
        "intermediate-" +
        sequence.toString(10)
      ),
    activeRuleset: {
      rulesetVersion:
        value.rulesetVersion,
      monotonicCounter:
        value.monotonicCounter,
      notBefore:
        value.notBefore,
      notAfter:
        value.notAfter,
    },
    rulesetSha256:
      sha256Utf8(
        canonicalizeServerRulesetValue(
          value
        )
      ),
  };
}

function snapshotFor(
  packageText: string,
  value: TrustedServerRuleset,
  state: ServerRulesetTrustState
): StoredServerRulesetSnapshot {
  const packageSha256 =
    sha256Utf8(packageText);

  return {
    state: {
      schemaVersion: 1,
      highestIntermediateSequence:
        state
          .highestIntermediateSequence,
      intermediateKeyId:
        state.intermediateKeyId,
      intermediateKeySha256:
        state
          .intermediateKeySha256,
      activeRuleset: {
        rulesetVersion:
          value.rulesetVersion,
        monotonicCounter:
          value.monotonicCounter,
        notBefore:
          value.notBefore,
        notAfter:
          value.notAfter,
      },
      rulesetSha256:
        state.rulesetSha256,
      lkgPackageSha256:
        packageSha256,
    },
    lkg: {
      schemaVersion: 1,
      packageSha256,
      packageText,
    },
  };
}

interface VerificationFixture {
  readonly accepted: boolean;
  readonly error: string | null;
  readonly ruleset:
    TrustedServerRuleset | null;
  readonly state:
    ServerRulesetTrustState | null;
}

function dependenciesFor(
  fixtures:
    Readonly<Record<string, VerificationFixture>>
): ServerRulesetRuntimeCompositionDependencies {
  return {
    verifyPackageText: (
      packageText
    ) => {
      const fixture =
        fixtures[packageText];

      if (fixture === undefined) {
        return {
          accepted: false,
          error:
            "UNKNOWN_TEST_PACKAGE",
          ruleset: null,
          nextState: null,
        };
      }

      return {
        accepted:
          fixture.accepted,
        error:
          fixture.error,
        ruleset:
          fixture.ruleset,
        nextState:
          fixture.state,
      };
    },
    resolveFallback:
      resolveServerRulesetFallback,
  };
}

function fallbackRuleset(
  pattern = "fallbackblock"
): TrustedServerRuleset {
  return ruleset(
    "bundled-fallback",
    1,
    1,
    "fallback-critical",
    pattern
  );
}

function baseInput(
  overrides:
    Partial<ComposeServerRulesetRuntimeResolutionInput> = {}
): ComposeServerRulesetRuntimeResolutionInput {
  return {
    channel: "free-stable",
    nowEpochMs,
    pinnedRootPublicKeyPem:
      validPinnedRoot,
    fallbackRuleset:
      fallbackRuleset(),
    ...overrides,
  };
}

test("runtime composition selects caller fallback on first install", () => {
  const result =
    composeServerRulesetRuntimeResolution(
      baseInput(),
      dependenciesFor({})
    );

  assert.equal(result.accepted, true);
  assert.equal(
    result.resolution.source,
    "FALLBACK"
  );
  assert.equal(
    result.antiRollbackFloorApplied,
    false
  );
});

test("runtime composition selects a reverified persisted LKG", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      2,
      2,
      "lkg-rule",
      "lkgblock",
      "destructive"
    );

  const lkgState =
    stateFor(lkgRuleset, 2);

  const lkgPackageText =
    "lkg-package";

  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          snapshotFor(
            lkgPackageText,
            lkgRuleset,
            lkgState
          ),
        lkgAnchoredAtEpochMs:
          nowEpochMs -
          2 * 24 * 60 * 60 * 1000,
      }),
      dependenciesFor({
        [lkgPackageText]: {
          accepted: true,
          error: null,
          ruleset: lkgRuleset,
          state: lkgState,
        },
      })
    );

  assert.equal(result.accepted, true);
  assert.equal(
    result.resolution.source,
    "LKG"
  );
  assert.equal(
    result.lkgVerificationAccepted,
    true
  );
  assert.equal(
    result.antiRollbackFloorApplied,
    true
  );
});

test("runtime composition gives a valid current ruleset priority over LKG", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      2,
      2,
      "lkg-rule",
      "lkgblock"
    );

  const currentRuleset =
    ruleset(
      "current",
      3,
      3,
      "current-rule",
      "currentblock",
      "policy-bypass"
    );

  const lkgState =
    stateFor(lkgRuleset, 2);

  const currentState =
    stateFor(currentRuleset, 3);

  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          snapshotFor(
            "lkg-package",
            lkgRuleset,
            lkgState
          ),
        lkgAnchoredAtEpochMs:
          nowEpochMs -
          3 * 24 * 60 * 60 * 1000,
        currentPackageText:
          "current-package",
        currentAnchoredAtEpochMs:
          nowEpochMs -
          24 * 60 * 60 * 1000,
      }),
      dependenciesFor({
        "lkg-package": {
          accepted: true,
          error: null,
          ruleset: lkgRuleset,
          state: lkgState,
        },
        "current-package": {
          accepted: true,
          error: null,
          ruleset:
            currentRuleset,
          state:
            currentState,
        },
      })
    );

  assert.equal(
    result.resolution.source,
    "CURRENT"
  );
  assert.equal(
    result.currentVerificationAccepted,
    true
  );
});

test("runtime composition narrows an invalid current package to LKG", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      2,
      2,
      "lkg-rule",
      "lkgblock"
    );

  const lkgState =
    stateFor(lkgRuleset, 2);

  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          snapshotFor(
            "lkg-package",
            lkgRuleset,
            lkgState
          ),
        lkgAnchoredAtEpochMs:
          nowEpochMs -
          2 * 24 * 60 * 60 * 1000,
        currentPackageText:
          "invalid-current",
        currentAnchoredAtEpochMs:
          nowEpochMs -
          24 * 60 * 60 * 1000,
      }),
      dependenciesFor({
        "lkg-package": {
          accepted: true,
          error: null,
          ruleset: lkgRuleset,
          state: lkgState,
        },
        "invalid-current": {
          accepted: false,
          error:
            "CURRENT_SIGNATURE_INVALID",
          ruleset: null,
          state: null,
        },
      })
    );

  assert.equal(
    result.resolution.source,
    "LKG"
  );
  assert.equal(
    result.currentVerificationAccepted,
    false
  );
  assert.equal(
    result.currentVerificationError,
    "CURRENT_SIGNATURE_INVALID"
  );
});

test("runtime composition narrows an invalid LKG package to fallback", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      2,
      2,
      "lkg-rule",
      "lkgblock"
    );

  const lkgState =
    stateFor(lkgRuleset, 2);

  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          snapshotFor(
            "invalid-lkg",
            lkgRuleset,
            lkgState
          ),
        lkgAnchoredAtEpochMs:
          nowEpochMs -
          2 * 24 * 60 * 60 * 1000,
      }),
      dependenciesFor({
        "invalid-lkg": {
          accepted: false,
          error:
            "LKG_SIGNATURE_INVALID",
          ruleset: null,
          state: null,
        },
      })
    );

  assert.equal(
    result.resolution.source,
    "FALLBACK"
  );
  assert.equal(
    result.lkgVerificationAccepted,
    false
  );
  assert.equal(
    result.lkgVerificationError,
    "LKG_SIGNATURE_INVALID"
  );
});

test("runtime composition rejects persisted LKG package hash linkage mismatch", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      2,
      2,
      "lkg-rule",
      "lkgblock"
    );

  const lkgState =
    stateFor(lkgRuleset, 2);

  const originalSnapshot =
    snapshotFor(
      "lkg-package",
      lkgRuleset,
      lkgState
    );

  const corruptedSnapshot:
    StoredServerRulesetSnapshot = {
      state:
        originalSnapshot.state,
      lkg: {
        ...originalSnapshot.lkg,
        packageSha256:
          "a".repeat(64),
      },
    };

  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          corruptedSnapshot,
        lkgAnchoredAtEpochMs:
          nowEpochMs -
          24 * 60 * 60 * 1000,
      }),
      dependenciesFor({})
    );

  assert.equal(
    result.resolution.source,
    "FALLBACK"
  );
  assert.match(
    result.lkgVerificationError ?? "",
    /SHA256_MISMATCH/
  );
});

test("runtime composition rejects LKG verified state mismatch", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      2,
      2,
      "lkg-rule",
      "lkgblock"
    );

  const persistedState =
    stateFor(lkgRuleset, 2);

  const mismatchedState =
    stateFor(lkgRuleset, 3);

  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          snapshotFor(
            "lkg-package",
            lkgRuleset,
            persistedState
          ),
        lkgAnchoredAtEpochMs:
          nowEpochMs -
          24 * 60 * 60 * 1000,
      }),
      dependenciesFor({
        "lkg-package": {
          accepted: true,
          error: null,
          ruleset: lkgRuleset,
          state: mismatchedState,
        },
      })
    );

  assert.equal(
    result.resolution.source,
    "FALLBACK"
  );
  assert.equal(
    result.lkgVerificationError,
    "LKG_VERIFIED_STATE_MISMATCH"
  );
});

test("runtime composition supplies persisted active state to block current rollback", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      5,
      5,
      "lkg-rule",
      "lkgblock"
    );

  const lkgState =
    stateFor(lkgRuleset, 5);

  let currentSawActiveState =
    false;

  const dependencies:
    ServerRulesetRuntimeCompositionDependencies = {
      verifyPackageText: (
        packageText,
        options
      ) => {
        if (
          packageText ===
          "lkg-package"
        ) {
          return {
            accepted: true,
            error: null,
            ruleset: lkgRuleset,
            nextState: lkgState,
          };
        }

        currentSawActiveState =
          options.activeState !== null;

        return {
          accepted: false,
          error:
            "RULESET_VERSION_ROLLBACK",
          ruleset: null,
          nextState: null,
        };
      },
      resolveFallback:
        resolveServerRulesetFallback,
    };

  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          snapshotFor(
            "lkg-package",
            lkgRuleset,
            lkgState
          ),
        lkgAnchoredAtEpochMs:
          nowEpochMs -
          24 * 60 * 60 * 1000,
        currentPackageText:
          "rollback-current",
        currentAnchoredAtEpochMs:
          nowEpochMs -
          60 * 60 * 1000,
      }),
      dependencies
    );

  assert.equal(
    currentSawActiveState,
    true
  );
  assert.equal(
    result.currentVerificationError,
    "RULESET_VERSION_ROLLBACK"
  );
  assert.equal(
    result.resolution.source,
    "LKG"
  );
});

test("runtime composition applies persisted anti-rollback floor to accepted current candidate", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      5,
      5,
      "lkg-rule",
      "lkgblock"
    );

  const lowerCurrentRuleset =
    ruleset(
      "lower-current",
      4,
      4,
      "current-rule",
      "currentblock"
    );

  const lkgState =
    stateFor(lkgRuleset, 5);

  const lowerCurrentState =
    stateFor(
      lowerCurrentRuleset,
      5
    );

  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          snapshotFor(
            "lkg-package",
            lkgRuleset,
            lkgState
          ),
        lkgAnchoredAtEpochMs:
          nowEpochMs -
          24 * 60 * 60 * 1000,
        currentPackageText:
          "lower-current",
        currentAnchoredAtEpochMs:
          nowEpochMs -
          60 * 60 * 1000,
      }),
      dependenciesFor({
        "lkg-package": {
          accepted: true,
          error: null,
          ruleset: lkgRuleset,
          state: lkgState,
        },
        "lower-current": {
          accepted: true,
          error: null,
          ruleset:
            lowerCurrentRuleset,
          state:
            lowerCurrentState,
        },
      })
    );

  assert.equal(
    result.currentVerificationAccepted,
    true
  );
  assert.equal(
    result.antiRollbackFloorApplied,
    true
  );
  assert.equal(
    result.resolution.source,
    "LKG"
  );
  assert.match(
    result.resolution
      .currentDiagnostic,
    /ANTI_ROLLBACK_RULESET_VERSION/
  );
});

test("runtime composition rejects missing and future current anchors", () => {
  const missing =
    composeServerRulesetRuntimeResolution(
      baseInput({
        currentPackageText:
          "current-package",
      }),
      dependenciesFor({})
    );

  const future =
    composeServerRulesetRuntimeResolution(
      baseInput({
        currentPackageText:
          "current-package",
        currentAnchoredAtEpochMs:
          nowEpochMs + 1,
      }),
      dependenciesFor({})
    );

  assert.equal(
    missing.resolution.source,
    "FALLBACK"
  );
  assert.equal(
    missing.currentVerificationError,
    "CURRENT_ANCHOR_REQUIRED"
  );
  assert.equal(
    future.resolution.source,
    "FALLBACK"
  );
  assert.equal(
    future.currentVerificationError,
    "CURRENT_ANCHOR_IN_FUTURE"
  );
});

test("runtime composition rejects missing and future LKG anchors", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      2,
      2,
      "lkg-rule",
      "lkgblock"
    );

  const lkgState =
    stateFor(lkgRuleset, 2);

  const snapshot =
    snapshotFor(
      "lkg-package",
      lkgRuleset,
      lkgState
    );

  const dependencies =
    dependenciesFor({
      "lkg-package": {
        accepted: true,
        error: null,
        ruleset: lkgRuleset,
        state: lkgState,
      },
    });

  const missing =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          snapshot,
      }),
      dependencies
    );

  const future =
    composeServerRulesetRuntimeResolution(
      baseInput({
        persistedSnapshot:
          snapshot,
        lkgAnchoredAtEpochMs:
          nowEpochMs + 1,
      }),
      dependencies
    );

  assert.equal(
    missing.resolution.source,
    "FALLBACK"
  );
  assert.equal(
    missing.lkgVerificationError,
    "LKG_ANCHOR_REQUIRED"
  );
  assert.equal(
    future.resolution.source,
    "FALLBACK"
  );
  assert.equal(
    future.lkgVerificationError,
    "LKG_ANCHOR_IN_FUTURE"
  );
});

test("runtime composition fails closed for invalid pinned root", () => {
  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        pinnedRootPublicKeyPem:
          "not-a-public-key",
      }),
      dependenciesFor({})
    );

  assert.equal(
    result.accepted,
    false
  );
  assert.equal(
    result.resolution.source,
    null
  );
  assert.equal(
    result.resolution.reason,
    "INVALID_RUNTIME_COMPOSITION_INPUT"
  );
});

test("runtime composition propagates resolver rejection", () => {
  const result =
    composeServerRulesetRuntimeResolution(
      baseInput({
        fallbackRuleset:
          fallbackRuleset(
            ".*secret"
          ),
      }),
      dependenciesFor({})
    );

  assert.equal(
    result.accepted,
    false
  );
  assert.equal(
    result.resolution.accepted,
    false
  );
  assert.equal(
    result.resolution.source,
    null
  );
});

test("runtime composition is deterministic and does not mutate inputs", () => {
  const lkgRuleset =
    ruleset(
      "lkg",
      2,
      2,
      "lkg-rule",
      "lkgblock"
    );

  const lkgState =
    stateFor(lkgRuleset, 2);

  const input =
    baseInput({
      persistedSnapshot:
        snapshotFor(
          "lkg-package",
          lkgRuleset,
          lkgState
        ),
      lkgAnchoredAtEpochMs:
        nowEpochMs -
        24 * 60 * 60 * 1000,
    });

  const before =
    JSON.stringify(input);

  const dependencies =
    dependenciesFor({
      "lkg-package": {
        accepted: true,
        error: null,
        ruleset: lkgRuleset,
        state: lkgState,
      },
    });

  const first =
    composeServerRulesetRuntimeResolution(
      input,
      dependencies
    );

  const second =
    composeServerRulesetRuntimeResolution(
      input,
      dependencies
    );

  assert.deepEqual(
    first,
    second
  );

  assert.equal(
    JSON.stringify(input),
    before
  );
});
