import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";

import {
  canonicalizeServerRulesetValue,
  type ServerRulesetTrustState,
  type TrustedServerRuleset,
  type TrustedServerRulesetRule,
} from "./serverRulesetTrustProvider";

import {
  SERVER_RULESET_DAY_MS,
  type AnchoredTrustedServerRuleset,
  type ServerRulesetAntiRollbackFloor,
  resolveServerRulesetFallback,
} from "./serverRulesetFallbackResolution";

const now =
  Date.parse(
    "2026-07-26T00:00:00.000Z"
  );

function sha256(
  value: string
): string {
  return crypto
    .createHash("sha256")
    .update(
      Buffer.from(value, "utf8")
    )
    .digest("hex");
}

interface RulesetOptions {
  readonly id?: string;
  readonly version?: number;
  readonly counter?: number;
  readonly notBefore?: string;
  readonly notAfter?: string;
  readonly rules?:
    readonly TrustedServerRulesetRule[];
}

function ruleset(
  options: RulesetOptions = {}
): TrustedServerRuleset {
  return {
    schemaVersion: 1,
    rulesetId:
      options.id ?? "ruleset-1",
    rulesetVersion:
      options.version ?? 1,
    monotonicCounter:
      options.counter ?? 1,
    notBefore:
      options.notBefore ??
      "2025-01-01T00:00:00.000Z",
    notAfter:
      options.notAfter ??
      "2027-01-01T00:00:00.000Z",
    rules:
      options.rules ?? [
        {
          ruleId: "remote-rule",
          category: "destructive",
          pattern: "remoteblock",
        },
      ],
  };
}

function fallbackRuleset(
  rules:
    readonly TrustedServerRulesetRule[] = [
      {
        ruleId: "fallback-critical",
        category: "catastrophic",
        pattern: "fallbackblock",
      },
    ]
): TrustedServerRuleset {
  return ruleset({
    id: "bundled-fallback",
    rules,
  });
}

function stateFor(
  value: TrustedServerRuleset,
  sequence = 1
): ServerRulesetTrustState {
  return {
    highestIntermediateSequence:
      sequence,
    intermediateKeyId:
      "intermediate-" +
      sequence.toString(10),
    intermediateKeySha256:
      sha256(
        "intermediate-key-" +
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
      sha256(
        canonicalizeServerRulesetValue(
          value
        )
      ),
  };
}

function anchored(
  value: TrustedServerRuleset,
  anchoredAtEpochMs: number,
  sequence = 1
): AnchoredTrustedServerRuleset {
  return {
    ruleset: value,
    state:
      stateFor(value, sequence),
    anchoredAtEpochMs,
  };
}

function resolve(
  options: {
    readonly channel?:
      "free-stable" | "fast-strict";
    readonly current?:
      AnchoredTrustedServerRuleset | null;
    readonly lkg?:
      AnchoredTrustedServerRuleset | null;
    readonly fallback?:
      TrustedServerRuleset;
    readonly floor?:
      ServerRulesetAntiRollbackFloor;
  } = {}
) {
  return resolveServerRulesetFallback({
    channel:
      options.channel ??
      "free-stable",
    nowEpochMs: now,
    current:
      options.current ?? null,
    lkg:
      options.lkg ?? null,
    fallbackRuleset:
      options.fallback ??
      fallbackRuleset(),
    ...(options.floor === undefined
      ? {}
      : {
          antiRollbackFloor:
            options.floor,
        }),
  });
}

test("free stable freshness expires exactly at 30 days", () => {
  const current =
    anchored(
      ruleset(),
      now -
        30 * SERVER_RULESET_DAY_MS
    );

  const result =
    resolve({
      current,
    });

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.equal(
    result.currentDiagnostic,
    "CURRENT_STALE_HARD_VALID"
  );
});

test("free stable hard limit expires exactly at 60 days", () => {
  const lkg =
    anchored(
      ruleset(),
      now -
        60 * SERVER_RULESET_DAY_MS
    );

  const result =
    resolve({
      lkg,
    });

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.equal(
    result.lkgDiagnostic,
    "LKG_HARD_EXPIRED"
  );
});

test("fast strict freshness expires exactly at 7 days", () => {
  const current =
    anchored(
      ruleset(),
      now -
        7 * SERVER_RULESET_DAY_MS
    );

  const result =
    resolve({
      channel: "fast-strict",
      current,
    });

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.equal(
    result.currentDiagnostic,
    "CURRENT_STALE_HARD_VALID"
  );
});

test("fast strict hard limit expires exactly at 30 days", () => {
  const lkg =
    anchored(
      ruleset(),
      now -
        30 * SERVER_RULESET_DAY_MS
    );

  const result =
    resolve({
      channel: "fast-strict",
      lkg,
    });

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.equal(
    result.lkgDiagnostic,
    "LKG_HARD_EXPIRED"
  );
});

test("signed notAfter caps freshness and hard windows", () => {
  const currentRuleset =
    ruleset({
      notAfter:
        new Date(now).toISOString(),
    });

  const result =
    resolve({
      current:
        anchored(
          currentRuleset,
          now -
            SERVER_RULESET_DAY_MS
        ),
    });

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.equal(
    result.currentDiagnostic,
    "CURRENT_HARD_EXPIRED"
  );
});

test("fresh current is selected before LKG", () => {
  const currentRuleset =
    ruleset({
      id: "current",
      version: 2,
      counter: 2,
    });

  const lkgRuleset =
    ruleset({
      id: "lkg",
      version: 3,
      counter: 3,
    });

  const result =
    resolve({
      current:
        anchored(
          currentRuleset,
          now -
            SERVER_RULESET_DAY_MS,
          2
        ),
      lkg:
        anchored(
          lkgRuleset,
          now -
            SERVER_RULESET_DAY_MS,
          3
        ),
    });

  assert.equal(
    result.source,
    "CURRENT"
  );

  assert.equal(
    result.reason,
    "FRESH_CURRENT_SELECTED"
  );
});

test("stale current falls back to hard-valid LKG", () => {
  const currentRuleset =
    ruleset({
      id: "stale-current",
    });

  const lkgRuleset =
    ruleset({
      id: "valid-lkg",
      version: 2,
      counter: 2,
    });

  const result =
    resolve({
      current:
        anchored(
          currentRuleset,
          now -
            31 * SERVER_RULESET_DAY_MS
        ),
      lkg:
        anchored(
          lkgRuleset,
          now -
            10 * SERVER_RULESET_DAY_MS,
          2
        ),
    });

  assert.equal(
    result.source,
    "LKG"
  );

  assert.equal(
    result.currentDiagnostic,
    "CURRENT_STALE_HARD_VALID"
  );
});

test("first install without current or LKG uses bundled fallback", () => {
  const result = resolve();

  assert.equal(
    result.accepted,
    true
  );

  assert.equal(
    result.source,
    "FALLBACK"
  );
});

test("cache deletion state without LKG uses bundled fallback", () => {
  const result =
    resolve({
      current: null,
      lkg: null,
    });

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.equal(
    result.currentDiagnostic,
    "CURRENT_ABSENT"
  );

  assert.equal(
    result.lkgDiagnostic,
    "LKG_ABSENT"
  );
});

test("current state hash mismatch causes LKG selection", () => {
  const currentRuleset =
    ruleset({
      id: "bad-current",
    });

  const current =
    anchored(
      currentRuleset,
      now -
        SERVER_RULESET_DAY_MS
    );

  const corruptedCurrent = {
    ...current,
    state: {
      ...current.state,
      rulesetSha256:
        "a".repeat(64),
    },
  };

  const lkgRuleset =
    ruleset({
      id: "good-lkg",
      version: 2,
      counter: 2,
    });

  const result =
    resolve({
      current: corruptedCurrent,
      lkg:
        anchored(
          lkgRuleset,
          now -
            2 * SERVER_RULESET_DAY_MS,
          2
        ),
    });

  assert.equal(
    result.source,
    "LKG"
  );

  assert.match(
    result.currentDiagnostic,
    /RULESET_STATE_HASH_MISMATCH/
  );
});

test("LKG state hash mismatch causes fallback-only selection", () => {
  const lkgRuleset =
    ruleset({
      id: "bad-lkg",
    });

  const lkg =
    anchored(
      lkgRuleset,
      now -
        SERVER_RULESET_DAY_MS
    );

  const corruptedLkg = {
    ...lkg,
    state: {
      ...lkg.state,
      rulesetSha256:
        "b".repeat(64),
    },
  };

  const result =
    resolve({
      lkg: corruptedLkg,
    });

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.match(
    result.lkgDiagnostic,
    /RULESET_STATE_HASH_MISMATCH/
  );
});

test("anti rollback floor violation blocks candidate", () => {
  const currentRuleset =
    ruleset({
      version: 4,
      counter: 4,
    });

  const result =
    resolve({
      current:
        anchored(
          currentRuleset,
          now -
            SERVER_RULESET_DAY_MS,
          4
        ),
      floor: {
        highestIntermediateSequence: 5,
        rulesetVersion: 5,
        monotonicCounter: 5,
        rulesetSha256:
          sha256("floor"),
      },
    });

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.match(
    result.currentDiagnostic,
    /ANTI_ROLLBACK_INTERMEDIATE_SEQUENCE/
  );
});

test("same version and counter hash rebound is blocked", () => {
  const currentRuleset =
    ruleset({
      version: 7,
      counter: 11,
    });

  const current =
    anchored(
      currentRuleset,
      now -
        SERVER_RULESET_DAY_MS,
      9
    );

  const result =
    resolve({
      current,
      floor: {
        highestIntermediateSequence: 9,
        rulesetVersion: 7,
        monotonicCounter: 11,
        rulesetSha256:
          sha256(
            "different-ruleset"
          ),
      },
    });

  assert.equal(
    result.source,
    "FALLBACK"
  );

  assert.match(
    result.currentDiagnostic,
    /ANTI_ROLLBACK_RULESET_HASH_REBOUND/
  );
});

test("fallback catastrophic rules remain present with current rules", () => {
  const currentRuleset =
    ruleset({
      rules: [
        {
          ruleId: "current-only",
          category: "destructive",
          pattern: "currentblock",
        },
      ],
    });

  const result =
    resolve({
      current:
        anchored(
          currentRuleset,
          now -
            SERVER_RULESET_DAY_MS
        ),
    });

  assert.equal(
    result.source,
    "CURRENT"
  );

  assert.deepEqual(
    result.rules.map(
      rule => rule.ruleId
    ),
    [
      "current-only",
      "fallback-critical",
    ]
  );
});

test("fallback rule wins an identifier conflict", () => {
  const currentRuleset =
    ruleset({
      rules: [
        {
          ruleId:
            "fallback-critical",
          category: "destructive",
          pattern: "weakerblock",
        },
      ],
    });

  const result =
    resolve({
      current:
        anchored(
          currentRuleset,
          now -
            SERVER_RULESET_DAY_MS
        ),
    });

  assert.equal(
    result.rules.length,
    1
  );

  assert.deepEqual(
    result.rules[0],
    {
      ruleId:
        "fallback-critical",
      category:
        "catastrophic",
      pattern:
        "fallbackblock",
    }
  );
});

test("unsafe fallback pattern fails closed", () => {
  const result =
    resolve({
      fallback:
        fallbackRuleset([
          {
            ruleId:
              "unsafe-fallback",
            category:
              "catastrophic",
            pattern:
              ".*secret",
          },
        ]),
    });

  assert.equal(
    result.accepted,
    false
  );

  assert.equal(
    result.source,
    null
  );

  assert.match(
    result.reason,
    /UNSAFE_RESOLUTION_RULE_PATTERN/
  );
});

test("ordering is deterministic and inputs are not mutated", () => {
  const currentRuleset =
    ruleset({
      rules: [
        {
          ruleId: "z-rule",
          category:
            "policy-bypass",
          pattern: "zblock",
        },
        {
          ruleId: "a-rule",
          category:
            "secret-exposure",
          pattern: "ablock",
        },
      ],
    });

  const fallback =
    fallbackRuleset([
      {
        ruleId: "m-rule",
        category: "catastrophic",
        pattern: "mblock",
      },
    ]);

  const currentBefore =
    JSON.stringify(currentRuleset);

  const fallbackBefore =
    JSON.stringify(fallback);

  const first =
    resolve({
      current:
        anchored(
          currentRuleset,
          now -
            SERVER_RULESET_DAY_MS
        ),
      fallback,
    });

  const second =
    resolve({
      current:
        anchored(
          currentRuleset,
          now -
            SERVER_RULESET_DAY_MS
        ),
      fallback,
    });

  assert.deepEqual(
    first.rules,
    second.rules
  );

  assert.deepEqual(
    first.rules.map(
      rule => rule.ruleId
    ),
    [
      "a-rule",
      "m-rule",
      "z-rule",
    ]
  );

  assert.equal(
    JSON.stringify(currentRuleset),
    currentBefore
  );

  assert.equal(
    JSON.stringify(fallback),
    fallbackBefore
  );
});

test("unsafe current candidate falls back to safe LKG", () => {
  const unsafeCurrent =
    ruleset({
      id: "unsafe-current",
      rules: [
        {
          ruleId: "unsafe",
          category:
            "policy-bypass",
          pattern: ".*secret",
        },
      ],
    });

  const safeLkg =
    ruleset({
      id: "safe-lkg",
      version: 2,
      counter: 2,
    });

  const result =
    resolve({
      current:
        anchored(
          unsafeCurrent,
          now -
            SERVER_RULESET_DAY_MS
        ),
      lkg:
        anchored(
          safeLkg,
          now -
            SERVER_RULESET_DAY_MS,
          2
        ),
    });

  assert.equal(
    result.source,
    "LKG"
  );

  assert.match(
    result.currentDiagnostic,
    /UNSAFE_RESOLUTION_RULE_PATTERN/
  );
});
