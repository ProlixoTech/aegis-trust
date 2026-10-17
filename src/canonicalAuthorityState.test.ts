import test from "node:test";
import assert from "node:assert/strict";

import {
  CANONICAL_AUTHORITY_RULESET_VERSION,
  CanonicalAuthorityStateStore,
} from "./canonicalAuthorityState";
import { getProtectedTargets } from "./protectedTargets";
import {
  SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH,
} from "../packages/aegis-core";

const workspaceId = "sha256:" + "a".repeat(64);

test("canonical authority state initializes from existing authority sources without release claims", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
    timestamp: "2026-07-19T00:00:00.000Z",
  });
  const state = store.getState();

  assert.equal(state.revision, 0);
  assert.equal(state.projectIdentity, "prolixo-aegis-personal");
  assert.equal(state.workspaceId, workspaceId);
  assert.deepEqual(
    state.protectedTargets,
    getProtectedTargets().map(target => target.target_id).sort()
  );
  assert.equal(
    state.capabilityManifestId,
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH.manifest_id
  );
  assert.equal(
    state.capabilityManifestVersion,
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH.manifest_version
  );
  assert.equal(
    state.policyVersion,
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH.policy_version
  );
  assert.equal(
    state.rulesetVersion,
    CANONICAL_AUTHORITY_RULESET_VERSION
  );
  assert.equal(state.verificationResult, "UNVERIFIED");
  assert.equal(state.productPass, false);
  assert.equal(state.releaseReady, false);
  assert.equal(state.uploadReady, false);
  assert.equal(state.finalArtifactCreated, false);
});

test("canonical authority state stores target ids only and never stores workspace paths or raw nonces", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "WARNING",
  });
  const serialized = JSON.stringify(store.getState());

  assert.equal(serialized.includes("/Users/"), false);
  assert.equal(serialized.includes('approvalNonce"'), false);
  assert.equal(serialized.includes("relative_path"), false);
});

test("canonical authority state defaults invalid capability manifests closed", () => {
  assert.throws(
    () => CanonicalAuthorityStateStore.create({
      workspaceId,
      protectedTargets: getProtectedTargets(),
      initialUserVisibleState: "WARNING",
      capabilityManifest: {
        ...SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH,
        trusted_capabilities: [],
      },
    }),
    /INVALID_CAPABILITY_MANIFEST_EMPTY/
  );
});

test("canonical authority state rejects incomplete capability metadata", () => {
  const [first, ...rest] =
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
      .trusted_capabilities;
  assert.ok(first);

  assert.throws(
    () => CanonicalAuthorityStateStore.create({
      workspaceId,
      protectedTargets: getProtectedTargets(),
      initialUserVisibleState: "WARNING",
      capabilityManifest: {
        ...SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH,
        trusted_capabilities: [
          { ...first, handler_id: "" },
          ...rest,
        ],
      },
    }),
    /INVALID_CAPABILITY_HANDLER_ID/
  );
});

test("canonical authority state uses monotonic revision checks and nonce hashes only", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
  });

  const updated = store.update(
    0,
    {
      actionId: "action-1",
      sessionId: "session-1",
      approvalNonceSha256: "sha256:" + "b".repeat(64),
      approvalNonceState: "ISSUED",
    },
    "2026-07-19T00:00:01.000Z"
  );

  assert.equal(updated.revision, 1);
  assert.equal(updated.approvalNonceState, "ISSUED");
  assert.throws(
    () => store.update(
      0,
      { verificationResult: "VERIFIED" }
    ),
    /STALE_CANONICAL_AUTHORITY_REVISION/
  );
  assert.throws(
    () => store.update(
      1,
      { approvalNonceSha256: null }
    ),
    /NONCE_STATE_HASH_MISMATCH/
  );
});

test("canonical authority state returns detached snapshots and tracks L1 visible state", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
  });

  const first = store.getState();
  const changed = store.synchronizeUserVisibleState(
    "BLOCKED",
    "2026-07-19T00:00:02.000Z"
  );

  assert.equal(first.userVisibleState, "SAFE");
  assert.equal(changed.userVisibleState, "BLOCKED");
  assert.equal(changed.revision, 1);
  assert.notEqual(
    first.protectedTargets,
    changed.protectedTargets
  );
});

test("canonical authority state synchronizes pending Safety Kernel session and nonce hash", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
  });

  const warnPending = store.synchronizeSafetyKernelState(
    {
      actionId: "kernel-action-1",
      sessionId: "kernel-session-1",
      approvalNonceSha256: "b".repeat(64),
      lifecyclePhase: "WARN_PENDING",
    },
    "2026-07-19T00:00:03.000Z"
  );

  assert.equal(warnPending.actionId, "kernel-action-1");
  assert.equal(warnPending.sessionId, "kernel-session-1");
  assert.equal(
    warnPending.approvalNonceSha256,
    "sha256:" + "b".repeat(64)
  );
  assert.equal(warnPending.approvalNonceState, "WARN_PENDING");

  const confirmed = store.synchronizeSafetyKernelState(
    {
      actionId: "kernel-action-1",
      sessionId: "kernel-session-1",
      approvalNonceSha256: "sha256:" + "b".repeat(64),
      lifecyclePhase: "ALLOW_PENDING_EXECUTION",
    },
    "2026-07-19T00:00:04.000Z"
  );

  assert.equal(confirmed.sessionId, "kernel-session-1");
  assert.equal(confirmed.approvalNonceState, "ISSUED");
});

test("canonical authority state records terminal Kernel nonce state and rejects invalid bindings", () => {
  const cancelledStore = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
  });

  cancelledStore.synchronizeSafetyKernelState({
    actionId: "kernel-action-cancel",
    sessionId: "kernel-session-cancel",
    approvalNonceSha256: "c".repeat(64),
    lifecyclePhase: "WARN_PENDING",
  });

  const cancelled = cancelledStore.synchronizeSafetyKernelState({
    actionId: "kernel-action-cancel",
    sessionId: null,
    approvalNonceSha256: "c".repeat(64),
    lifecyclePhase: "CONSUMED",
    terminalReason: "cancel_by_user",
  });

  assert.equal(cancelled.sessionId, null);
  assert.equal(cancelled.approvalNonceState, "CANCELLED");

  const timedOutStore = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
  });

  const timedOut = timedOutStore.synchronizeSafetyKernelState({
    actionId: "kernel-action-timeout",
    sessionId: null,
    approvalNonceSha256: "d".repeat(64),
    lifecyclePhase: "CONSUMED",
    terminalReason: "timeout_expired",
  });

  assert.equal(timedOut.approvalNonceState, "TIMED_OUT");

  assert.throws(
    () => timedOutStore.synchronizeSafetyKernelState({
      actionId: "kernel-action-invalid-session",
      sessionId: "terminal-session-must-not-remain",
      approvalNonceSha256: "e".repeat(64),
      lifecyclePhase: "BLOCKED",
    }),
    /TERMINAL_KERNEL_SESSION_FORBIDDEN/
  );

  assert.throws(
    () => timedOutStore.synchronizeSafetyKernelState({
      actionId: "kernel-action-invalid-hash",
      sessionId: "kernel-session-invalid-hash",
      approvalNonceSha256: "invalid",
      lifecyclePhase: "WARN_PENDING",
    }),
    /INVALID_APPROVAL_NONCE_SHA256/
  );
});

test("canonical authority snapshot serialization is deterministic and hydrates an equivalent detached state", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
    timestamp: "2026-07-19T01:00:00.000Z",
  });

  const first =
    store.serializeSnapshotEnvelope();
  const second =
    store.serializeSnapshotEnvelope();

  assert.equal(first, second);

  const parsed =
    JSON.parse(first) as Record<string, unknown>;

  assert.equal(
    parsed.envelopeSchemaVersion,
    "1.0.0"
  );

  assert.match(
    String(parsed.payloadSha256),
    /^sha256:[a-f0-9]{64}$/
  );

  const hydrated =
    CanonicalAuthorityStateStore
      .hydrateSnapshotJson(first);

  assert.deepEqual(
    hydrated.getState(),
    store.getState()
  );

  assert.notEqual(
    hydrated.getState(),
    hydrated.getState()
  );
});

test("canonical authority snapshot hydration preserves revision and authority bindings", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "WARNING",
    timestamp: "2026-07-19T01:01:00.000Z",
  });

  const updated = store.update(
    0,
    {
      actionId: "action-1",
      sessionId: "session-1",
    },
    "2026-07-19T01:01:01.000Z"
  );

  const hydrated =
    CanonicalAuthorityStateStore
      .hydrateSnapshotJson(
        store.serializeSnapshotEnvelope()
      );

  assert.deepEqual(
    hydrated.getState(),
    updated
  );

  assert.equal(
    hydrated.getState().revision,
    1
  );

  assert.equal(
    hydrated.getState().actionId,
    "action-1"
  );

  assert.equal(
    hydrated.getState().sessionId,
    "session-1"
  );

  assert.equal(
    hydrated.getState().approvalNonceState,
    "NONE"
  );
});

test("canonical authority snapshot hydration rejects payload hash tampering", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
  });

  const envelope =
    JSON.parse(
      store.serializeSnapshotEnvelope()
    ) as Record<string, unknown>;

  envelope.payloadSha256 =
    "sha256:" + "0".repeat(64);

  assert.throws(
    () =>
      CanonicalAuthorityStateStore
        .hydrateSnapshot(envelope),
    /CANONICAL_AUTHORITY_SNAPSHOT_HASH_MISMATCH/
  );
});

test("canonical authority snapshot hydration rejects schema identity and release claim tampering", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
  });

  const envelope =
    JSON.parse(
      store.serializeSnapshotEnvelope()
    ) as {
      envelopeSchemaVersion: string;
      projectIdentity: string;
      state: Record<string, unknown>;
      [key: string]: unknown;
    };

  assert.throws(
    () =>
      CanonicalAuthorityStateStore
        .hydrateSnapshot({
          ...envelope,
          envelopeSchemaVersion: "9.0.0",
        }),
    /UNSUPPORTED_CANONICAL_AUTHORITY_SNAPSHOT_ENVELOPE_SCHEMA_VERSION/
  );

  assert.throws(
    () =>
      CanonicalAuthorityStateStore
        .hydrateSnapshot({
          ...envelope,
          projectIdentity: "other-project",
        }),
    /CANONICAL_AUTHORITY_SNAPSHOT_PROJECT_IDENTITY_MISMATCH/
  );

  assert.throws(
    () =>
      CanonicalAuthorityStateStore
        .hydrateSnapshot({
          ...envelope,
          state: {
            ...envelope.state,
            productPass: true,
          },
        }),
    /CANONICAL_AUTHORITY_RELEASE_CLAIM_FORBIDDEN/
  );
});

test("canonical authority snapshot hydration rejects malformed revision targets and decision scope", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
  });

  const envelope =
    JSON.parse(
      store.serializeSnapshotEnvelope()
    ) as {
      state: {
        decisionScope: Record<string, unknown>;
        [key: string]: unknown;
      };
      [key: string]: unknown;
    };

  assert.throws(
    () =>
      CanonicalAuthorityStateStore
        .hydrateSnapshot({
          ...envelope,
          state: {
            ...envelope.state,
            revision: 1.5,
          },
        }),
    /INVALID_CANONICAL_AUTHORITY_REVISION/
  );

  assert.throws(
    () =>
      CanonicalAuthorityStateStore
        .hydrateSnapshot({
          ...envelope,
          state: {
            ...envelope.state,
            protectedTargets: [
              "z-target",
              "a-target",
            ],
          },
        }),
    /CANONICAL_AUTHORITY_PROTECTED_TARGETS_NOT_SORTED/
  );

  assert.throws(
    () =>
      CanonicalAuthorityStateStore
        .hydrateSnapshot({
          ...envelope,
          state: {
            ...envelope.state,
            decisionScope: {
              ...envelope.state.decisionScope,
              timestamp: "not-a-timestamp",
            },
          },
        }),
    /INVALID_AUTHORITY_TIMESTAMP/
  );
});

test("hydrated canonical authority store retains stale revision rejection and monotonic updates", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId,
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
  });

  store.update(
    0,
    {
      actionId: "hydrated-action-1",
    },
    "2026-07-19T01:02:00.000Z"
  );

  const hydrated =
    CanonicalAuthorityStateStore
      .hydrateSnapshotJson(
        store.serializeSnapshotEnvelope()
      );

  assert.throws(
    () =>
      hydrated.update(
        0,
        {
          actionId: "stale-action",
        }
      ),
    /STALE_CANONICAL_AUTHORITY_REVISION/
  );

  const updated = hydrated.update(
    1,
    {
      actionId: "hydrated-action-2",
    },
    "2026-07-19T01:02:01.000Z"
  );

  assert.equal(updated.revision, 2);
  assert.equal(
    updated.actionId,
    "hydrated-action-2"
  );
  assert.equal(updated.productPass, false);
  assert.equal(updated.releaseReady, false);
  assert.equal(updated.uploadReady, false);
  assert.equal(
    updated.finalArtifactCreated,
    false
  );
});
