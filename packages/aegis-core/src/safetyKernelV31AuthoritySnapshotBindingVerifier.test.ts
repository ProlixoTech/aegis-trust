import test from "node:test";
import assert from "node:assert/strict";

import type {
  SafetyKernelV31AllowedExecutionBinding,
} from "./safetyKernelV31AllowedExecutionCoordinator";

import {
  SAFETY_KERNEL_V31_AUTHORITY_SNAPSHOT_BINDING_VERIFIER_INVARIANT,
  SafetyKernelV31AuthoritySnapshotBindingReadPort,
  SafetyKernelV31AuthoritySnapshotBindingVerifier,
} from "./safetyKernelV31AuthoritySnapshotBindingVerifier";

const SNAPSHOT_HASH_A = "sha256:" + "a".repeat(64);
const SNAPSHOT_HASH_B = "sha256:" + "b".repeat(64);

function binding(
  patch: Partial<SafetyKernelV31AllowedExecutionBinding> = {}
): SafetyKernelV31AllowedExecutionBinding {
  return {
    authorityRevision: 7,
    workspaceId: "workspace-1",
    actionId: "action-1",
    sessionId: "session-1",
    approvalNonceSha256: "sha256:" + "c".repeat(64),
    commandSha256: "sha256:" + "d".repeat(64),
    snapshotBindingSha256: SNAPSHOT_HASH_A,
    ...patch,
  };
}

function currentBinding(
  patch: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    authorityRevision: 7,
    workspaceId: "workspace-1",
    snapshotBindingSha256: SNAPSHOT_HASH_A,
    ...patch,
  };
}

type ReadValue =
  | unknown
  | (() => unknown | Promise<unknown>);

class FakeReadPort
  implements SafetyKernelV31AuthoritySnapshotBindingReadPort {
  calls = 0;

  constructor(
    private readonly values: readonly ReadValue[]
  ) {}

  async readCurrentBinding(): Promise<unknown> {
    this.calls += 1;

    const index = Math.min(
      this.calls - 1,
      this.values.length - 1
    );

    const value = this.values[index];

    if (typeof value === "function") {
      return await value();
    }

    return value;
  }
}

test("verifier invariant stays detached and fail-closed", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_AUTHORITY_SNAPSHOT_BINDING_VERIFIER_INVARIANT,
    {
      READ_PORT_CALLED_ON_EVERY_VERIFY: true,
      STATE_CACHE_ALLOWED: false,
      READ_FAILURE_FAILS_CLOSED: true,
      MALFORMED_READBACK_MAPS_TO_AUTHORITY_DRIFT: true,
      AUTHORITY_REVISION_MISMATCH_MAPS_TO_AUTHORITY_DRIFT: true,
      WORKSPACE_ID_MISMATCH_MAPS_TO_AUTHORITY_DRIFT: true,
      SNAPSHOT_BINDING_MISMATCH_MAPS_TO_SNAPSHOT_FAILED: true,
      CANONICAL_AUTHORITY_IMPORTED: false,
      SNAPSHOT_STORE_IMPORTED: false,
      EXTENSION_CONNECTED: false,
      NODE_PROCESS_ADAPTER_CONNECTED: false,
      REAL_PROCESS_REQUIRED_BY_TESTS: false,
      RAW_APPROVAL_NONCE_EXPOSED: false,
      RAW_STDOUT_EXPOSED: false,
      RAW_STDERR_EXPOSED: false,
    }
  );
});

test("exact authority and snapshot binding verifies", async () => {
  const readPort = new FakeReadPort([
    currentBinding(),
  ]);

  const verifier =
    new SafetyKernelV31AuthoritySnapshotBindingVerifier(
      readPort
    );

  assert.equal(
    await verifier.verify(binding()),
    "verified"
  );

  assert.equal(readPort.calls, 1);
});

test("authority revision drift fails closed", async () => {
  const readPort = new FakeReadPort([
    currentBinding({ authorityRevision: 8 }),
  ]);

  const verifier =
    new SafetyKernelV31AuthoritySnapshotBindingVerifier(
      readPort
    );

  assert.equal(
    await verifier.verify(binding()),
    "authority_drift"
  );

  assert.equal(readPort.calls, 1);
});

test("workspace drift fails closed", async () => {
  const readPort = new FakeReadPort([
    currentBinding({ workspaceId: "workspace-2" }),
  ]);

  const verifier =
    new SafetyKernelV31AuthoritySnapshotBindingVerifier(
      readPort
    );

  assert.equal(
    await verifier.verify(binding()),
    "authority_drift"
  );

  assert.equal(readPort.calls, 1);
});

test("snapshot binding drift maps to snapshot_failed", async () => {
  const readPort = new FakeReadPort([
    currentBinding({
      snapshotBindingSha256: SNAPSHOT_HASH_B,
    }),
  ]);

  const verifier =
    new SafetyKernelV31AuthoritySnapshotBindingVerifier(
      readPort
    );

  assert.equal(
    await verifier.verify(binding()),
    "snapshot_failed"
  );

  assert.equal(readPort.calls, 1);
});

test("read exception fails closed as authority_drift", async () => {
  const readPort = new FakeReadPort([
    () => {
      throw new Error("READ_FAILED");
    },
  ]);

  const verifier =
    new SafetyKernelV31AuthoritySnapshotBindingVerifier(
      readPort
    );

  assert.equal(
    await verifier.verify(binding()),
    "authority_drift"
  );

  assert.equal(readPort.calls, 1);
});

test("malformed readbacks fail closed", async () => {
  const malformedValues: readonly unknown[] = [
    null,
    undefined,
    {},
    {
      authorityRevision: -1,
      workspaceId: "workspace-1",
      snapshotBindingSha256: SNAPSHOT_HASH_A,
    },
    {
      authorityRevision: 7,
      workspaceId: "",
      snapshotBindingSha256: SNAPSHOT_HASH_A,
    },
    {
      authorityRevision: 7,
      workspaceId: "workspace-1\nworkspace-2",
      snapshotBindingSha256: SNAPSHOT_HASH_A,
    },
    {
      authorityRevision: 7,
      workspaceId: "workspace-1",
      snapshotBindingSha256: "invalid",
    },
  ];

  for (const malformed of malformedValues) {
    const verifier =
      new SafetyKernelV31AuthoritySnapshotBindingVerifier(
        new FakeReadPort([malformed])
      );

    assert.equal(
      await verifier.verify(binding()),
      "authority_drift"
    );
  }
});

test("every verify call reads fresh state without cache", async () => {
  const readPort = new FakeReadPort([
    currentBinding(),
    currentBinding({ authorityRevision: 8 }),
  ]);

  const verifier =
    new SafetyKernelV31AuthoritySnapshotBindingVerifier(
      readPort
    );

  assert.equal(
    await verifier.verify(binding()),
    "verified"
  );

  assert.equal(
    await verifier.verify(binding()),
    "authority_drift"
  );

  assert.equal(readPort.calls, 2);
});

test("malformed bound values fail closed before readback", async () => {
  const readPort = new FakeReadPort([
    currentBinding(),
  ]);

  const verifier =
    new SafetyKernelV31AuthoritySnapshotBindingVerifier(
      readPort
    );

  assert.equal(
    await verifier.verify(
      binding({ authorityRevision: -1 })
    ),
    "authority_drift"
  );

  assert.equal(
    await verifier.verify(
      binding({ workspaceId: " workspace-1" })
    ),
    "authority_drift"
  );

  assert.equal(
    await verifier.verify(
      binding({ snapshotBindingSha256: "invalid" })
    ),
    "snapshot_failed"
  );

  assert.equal(readPort.calls, 0);
});