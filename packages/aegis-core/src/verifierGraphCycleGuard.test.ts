import test from "node:test";
import assert from "node:assert/strict";

import {
  VerifierRecursionGuard,
  verifyVerifierGraphAcyclic,
  type VerifierGraphGuardedExecutionFailure,
  type VerifierGraphVerificationResult,
} from "./verifierGraphCycleGuard";

function assertFailClosed(
  result:
    | VerifierGraphVerificationResult
    | VerifierGraphGuardedExecutionFailure
): void {
  assert.equal(
    result.trustedStatusAllowed,
    false
  );

  assert.equal(
    result.safeStatusAllowed,
    false
  );

  assert.equal(
    result.executionAllowed,
    false
  );

  assert.equal(
    result.restoreAllowed,
    false
  );

  assert.equal(
    result.exportAllowed,
    false
  );

  assert.equal(
    result.releaseReadyAllowed,
    false
  );

  assert.equal(
    result
      .callerVerificationBooleanAccepted,
    false
  );
}

test(
  "C08 normal DAG is accepted without mutating the declaration",
  () => {
    const nodes = [
      {
        id: "receipt",
        dependencies: ["ledger"],
      },
      {
        id: "ledger",
        dependencies: [],
      },
    ] as const;

    const before =
      JSON.stringify(nodes);

    const result =
      verifyVerifierGraphAcyclic({
        nodes,
      });

    assert.equal(
      result.verified,
      true
    );

    assert.equal(
      result.acyclic,
      true
    );

    assert.deepEqual(
      result.issueCodes,
      []
    );

    assert.deepEqual(
      result.cyclePath,
      []
    );

    assert.equal(
      JSON.stringify(nodes),
      before
    );
  }
);

test(
  "C08 disconnected DAG is accepted",
  () => {
    const result =
      verifyVerifierGraphAcyclic({
        nodes: [
          {
            id: "a",
            dependencies: ["b"],
          },
          {
            id: "b",
            dependencies: [],
          },
          {
            id: "c",
            dependencies: ["d"],
          },
          {
            id: "d",
            dependencies: [],
          },
        ],
      });

    assert.equal(
      result.verified,
      true
    );

    assert.equal(
      result.acyclic,
      true
    );
  }
);

test(
  "C08 diamond DAG is accepted",
  () => {
    const result =
      verifyVerifierGraphAcyclic({
        nodes: [
          {
            id: "root",
            dependencies: [
              "left",
              "right",
            ],
          },
          {
            id: "left",
            dependencies: ["leaf"],
          },
          {
            id: "right",
            dependencies: ["leaf"],
          },
          {
            id: "leaf",
            dependencies: [],
          },
        ],
      });

    assert.equal(
      result.verified,
      true
    );

    assert.equal(
      result.acyclic,
      true
    );
  }
);

test(
  "C08 self cycle fails closed and caller booleans cannot authorize it",
  () => {
    const result =
      verifyVerifierGraphAcyclic({
        nodes: [
          {
            id: "self",
            dependencies: ["self"],
          },
        ],
        verified: true,
        trustedStatusAllowed: true,
        executionAllowed: true,
      });

    assert.equal(
      result.verified,
      false
    );

    assert.deepEqual(
      result.issueCodes,
      [
        "SELF_DEPENDENCY",
        "CYCLE_DETECTED",
      ]
    );

    assert.deepEqual(
      result.cyclePath,
      ["self", "self"]
    );

    assertFailClosed(result);
  }
);

test(
  "C08 two-node cycle fails closed",
  () => {
    const result =
      verifyVerifierGraphAcyclic({
        nodes: [
          {
            id: "a",
            dependencies: ["b"],
          },
          {
            id: "b",
            dependencies: ["a"],
          },
        ],
      });

    assert.equal(
      result.verified,
      false
    );

    assert.deepEqual(
      result.issueCodes,
      ["CYCLE_DETECTED"]
    );

    assert.deepEqual(
      result.cyclePath,
      ["a", "b", "a"]
    );

    assertFailClosed(result);
  }
);

test(
  "C08 three-node cycle fails closed",
  () => {
    const result =
      verifyVerifierGraphAcyclic({
        nodes: [
          {
            id: "c",
            dependencies: ["a"],
          },
          {
            id: "a",
            dependencies: ["b"],
          },
          {
            id: "b",
            dependencies: ["c"],
          },
        ],
      });

    assert.equal(
      result.verified,
      false
    );

    assert.deepEqual(
      result.cyclePath,
      ["a", "b", "c", "a"]
    );

    assertFailClosed(result);
  }
);

test(
  "C08 duplicate node identifier fails closed",
  () => {
    const result =
      verifyVerifierGraphAcyclic({
        nodes: [
          {
            id: "duplicate",
            dependencies: [],
          },
          {
            id: "duplicate",
            dependencies: [],
          },
        ],
      });

    assert.equal(
      result.verified,
      false
    );

    assert.deepEqual(
      result.issueCodes,
      ["DUPLICATE_NODE_ID"]
    );

    assertFailClosed(result);
  }
);

test(
  "C08 missing dependency fails closed",
  () => {
    const result =
      verifyVerifierGraphAcyclic({
        nodes: [
          {
            id: "root",
            dependencies: ["missing"],
          },
        ],
      });

    assert.equal(
      result.verified,
      false
    );

    assert.deepEqual(
      result.issueCodes,
      ["MISSING_DEPENDENCY"]
    );

    assertFailClosed(result);
  }
);

test(
  "C08 equivalent graph input orders produce the same deterministic cycle",
  () => {
    const first =
      verifyVerifierGraphAcyclic({
        nodes: [
          {
            id: "z",
            dependencies: ["y"],
          },
          {
            id: "y",
            dependencies: ["z"],
          },
          {
            id: "b",
            dependencies: ["a"],
          },
          {
            id: "a",
            dependencies: ["b"],
          },
        ],
      });

    const second =
      verifyVerifierGraphAcyclic({
        nodes: [
          {
            id: "a",
            dependencies: ["b"],
          },
          {
            id: "b",
            dependencies: ["a"],
          },
          {
            id: "y",
            dependencies: ["z"],
          },
          {
            id: "z",
            dependencies: ["y"],
          },
        ],
      });

    assert.deepEqual(first, second);

    assert.deepEqual(
      first.cyclePath,
      ["a", "b", "a"]
    );
  }
);

test(
  "C08 runtime guard blocks direct self recursion",
  async () => {
    const guard =
      new VerifierRecursionGuard();

    const result =
      await guard.run(
        "self",
        async () =>
          guard.run(
            "self",
            async () => "unreachable"
          )
      );

    assert.equal(result.ok, false);

    if (result.ok) {
      throw new Error(
        "EXPECTED_GUARD_FAILURE"
      );
    }

    assert.deepEqual(
      result.issueCodes,
      ["RECURSION_REENTRY_BLOCKED"]
    );

    assert.deepEqual(
      result.cyclePath,
      ["self", "self"]
    );

    assert.deepEqual(
      guard.activePath,
      []
    );

    assertFailClosed(result);
  }
);

test(
  "C08 runtime guard blocks mutual recursion",
  async () => {
    const guard =
      new VerifierRecursionGuard();

    const result =
      await guard.run(
        "a",
        async () =>
          guard.run(
            "b",
            async () =>
              guard.run(
                "a",
                async () =>
                  "unreachable"
              )
          )
      );

    assert.equal(result.ok, false);

    if (result.ok) {
      throw new Error(
        "EXPECTED_GUARD_FAILURE"
      );
    }

    assert.deepEqual(
      result.issueCodes,
      ["RECURSION_REENTRY_BLOCKED"]
    );

    assert.deepEqual(
      result.cyclePath,
      ["a", "b", "a"]
    );

    assert.deepEqual(
      guard.activePath,
      []
    );

    assertFailClosed(result);
  }
);

test(
  "C08 runtime guard cleans its stack after an exception and permits a later run",
  async () => {
    const guard =
      new VerifierRecursionGuard();

    const failed =
      await guard.run(
        "unstable",
        async () => {
          throw new Error(
            "expected test failure"
          );
        }
      );

    assert.equal(
      failed.ok,
      false
    );

    if (failed.ok) {
      throw new Error(
        "EXPECTED_GUARD_FAILURE"
      );
    }

    assert.deepEqual(
      failed.issueCodes,
      ["VERIFIER_EXECUTION_FAILED"]
    );

    assert.deepEqual(
      guard.activePath,
      []
    );

    assertFailClosed(failed);

    const recovered =
      await guard.run(
        "unstable",
        async () => "recovered"
      );

    assert.equal(
      recovered.ok,
      true
    );

    if (!recovered.ok) {
      throw new Error(
        "EXPECTED_GUARD_SUCCESS"
      );
    }

    assert.equal(
      recovered.value,
      "recovered"
    );

    assert.deepEqual(
      guard.activePath,
      []
    );
  }
);