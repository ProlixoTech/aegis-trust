import test from "node:test";
import assert from "node:assert/strict";

import type {
  AegisExecutionPort,
  AegisExecutionRequest,
  AegisExecutionResult,
} from "../packages/aegis-core";

import {
  SafetyKernelV31AllowedExecutionCoordinator,
  type SafetyKernelV31AllowedExecutionBindingVerifier,
} from "./safetyKernelV31AllowedExecutionCoordinator";

import {
  SAFETY_KERNEL_V31_ALLOWED_EXECUTION_COORDINATOR_COMPOSITION_INVARIANT,
  createSafetyKernelV31AllowedExecutionCoordinatorComposition,
} from "./safetyKernelV31AllowedExecutionCoordinatorComposition";

import {
  createSafetyKernelV31AuthoritySnapshotBindingComposition,
  type SafetyKernelV31AuthoritySnapshotBindingComposition,
} from "./safetyKernelV31AuthoritySnapshotBindingComposition";

import type {
  SafetyKernelV31CanonicalAuthorityReader,
  SafetyKernelV31SnapshotTargetIndexReader,
} from "./safetyKernelV31AuthoritySnapshotBindingReadPort";

class NoExecuteExecutionPort
  implements AegisExecutionPort {
  calls = 0;

  async execute(
    _request: AegisExecutionRequest
  ): Promise<AegisExecutionResult> {
    this.calls += 1;

    throw new Error(
      "EXECUTION_DURING_COMPOSITION"
    );
  }
}

function createNoReadAuthorityComposition(): {
  composition:
    SafetyKernelV31AuthoritySnapshotBindingComposition;

  counters: {
    authorityReads: number;
    indexReads: number;
  };
} {
  const counters = {
    authorityReads: 0,
    indexReads: 0,
  };

  const authorityReader:
    SafetyKernelV31CanonicalAuthorityReader = {
      getState(): unknown {
        counters.authorityReads += 1;

        throw new Error(
          "AUTHORITY_READ_DURING_COMPOSITION"
        );
      },
    };

  const targetReaders:
    readonly SafetyKernelV31SnapshotTargetIndexReader[] = [
      {
        targetId: "env_default",
        relativePath: ".env",
        snapshotIndexFile:
          "latest-safe-snapshot.json",

        async readIndex(): Promise<unknown> {
          counters.indexReads += 1;

          throw new Error(
            "INDEX_READ_DURING_COMPOSITION"
          );
        },
      },
    ];

  return {
    composition:
      createSafetyKernelV31AuthoritySnapshotBindingComposition({
        authorityReader,
        targetReaders,
        projectRoot: "/workspace",
        aegisDir: "/workspace/.aegis",
      }),
    counters,
  };
}

test("coordinator composition invariant remains detached and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_ALLOWED_EXECUTION_COORDINATOR_COMPOSITION_INVARIANT,
    {
      COORDINATOR_CONSTRUCTED_EXACTLY_ONCE: true,
      COORDINATOR_RECEIVES_EXACT_EXECUTION_PORT_INSTANCE: true,
      COORDINATOR_RECEIVES_EXACT_A2F_VERIFIER_INSTANCE: true,
      A2F_COMPOSITION_REFERENCE_REUSED_UNCHANGED: true,
      EXECUTION_PORT_REFERENCE_CLONED: false,
      A2F_COMPOSITION_REFERENCE_CLONED: false,
      EXECUTION_CALL_DURING_COMPOSITION: false,
      VERIFICATION_CALL_DURING_COMPOSITION: false,
      AUTHORITY_READ_DURING_COMPOSITION: false,
      INDEX_READ_DURING_COMPOSITION: false,
      BASELINE_FILE_READ_DURING_COMPOSITION: false,
      SESSION_CLAIM_CREATED_DURING_COMPOSITION: false,
      CACHE_CREATED: false,
      OUTPUT_OBJECT_FROZEN: true,
      PIPELINE_CONNECTED: false,
      RUNTIME_CONTROLLER_CONNECTED: false,
      EXTENSION_CONNECTED: false,
      NODE_PROCESS_ADAPTER_CONNECTED: false,
      RECEIPT_CONNECTED: false,
      LEDGER_CONNECTED: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
    }
  );
});

test("factory returns a frozen coordinator and A2f composition bundle", () => {
  const execution =
    new NoExecuteExecutionPort();

  const authority =
    createNoReadAuthorityComposition();

  const composition =
    createSafetyKernelV31AllowedExecutionCoordinatorComposition({
      execution,
      authorityBindingComposition:
        authority.composition,
    });

  assert.equal(
    Object.isFrozen(composition),
    true
  );

  assert.equal(
    composition.coordinator instanceof
      SafetyKernelV31AllowedExecutionCoordinator,
    true
  );

  assert.equal(
    composition.authorityBindingComposition,
    authority.composition
  );

  assert.equal(
    execution.calls,
    0
  );

  assert.equal(
    authority.counters.authorityReads,
    0
  );

  assert.equal(
    authority.counters.indexReads,
    0
  );
});

test("coordinator receives the exact execution and verifier instances", () => {
  const execution =
    new NoExecuteExecutionPort();

  const authority =
    createNoReadAuthorityComposition();

  const composition =
    createSafetyKernelV31AllowedExecutionCoordinatorComposition({
      execution,
      authorityBindingComposition:
        authority.composition,
    });

  const internals =
    composition.coordinator as unknown as {
      readonly execution:
        AegisExecutionPort;

      readonly bindingVerifier:
        SafetyKernelV31AllowedExecutionBindingVerifier;

      readonly claimedSessions:
        Set<string>;
    };

  assert.equal(
    internals.execution,
    execution
  );

  assert.equal(
    internals.bindingVerifier,
    authority.composition.verifier
  );

  assert.equal(
    internals.claimedSessions.size,
    0
  );
});

test("composition performs no execute, verify, or authority reads", () => {
  const execution =
    new NoExecuteExecutionPort();

  const authority =
    createNoReadAuthorityComposition();

  let verificationCalls = 0;

  authority.composition.verifier.verify =
    async () => {
      verificationCalls += 1;
      return "verified" as const;
    };

  const composition =
    createSafetyKernelV31AllowedExecutionCoordinatorComposition({
      execution,
      authorityBindingComposition:
        authority.composition,
    });

  const internals =
    composition.coordinator as unknown as {
      readonly claimedSessions:
        Set<string>;
    };

  assert.equal(
    execution.calls,
    0
  );

  assert.equal(
    verificationCalls,
    0
  );

  assert.equal(
    authority.counters.authorityReads,
    0
  );

  assert.equal(
    authority.counters.indexReads,
    0
  );

  assert.equal(
    internals.claimedSessions.size,
    0
  );
});

test("A2f composition reference is reused unchanged", () => {
  const execution =
    new NoExecuteExecutionPort();

  const authority =
    createNoReadAuthorityComposition();

  const readPort =
    authority.composition.readPort;

  const verifier =
    authority.composition.verifier;

  const composition =
    createSafetyKernelV31AllowedExecutionCoordinatorComposition({
      execution,
      authorityBindingComposition:
        authority.composition,
    });

  assert.equal(
    composition.authorityBindingComposition,
    authority.composition
  );

  assert.equal(
    composition.authorityBindingComposition.readPort,
    readPort
  );

  assert.equal(
    composition.authorityBindingComposition.verifier,
    verifier
  );

  assert.equal(
    execution.calls,
    0
  );

  assert.equal(
    authority.counters.authorityReads,
    0
  );

  assert.equal(
    authority.counters.indexReads,
    0
  );
});