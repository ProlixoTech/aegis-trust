import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";

import {
  completeSafetyKernelV31AllowedExecution,
  confirmSafetyKernelV31Warn,
} from "./safetyKernelV31NonceLifecyclePolicy";
import type {
  SafetyKernelV31NonceLifecycleRecord,
} from "./safetyKernelV31NonceLifecyclePolicy";
import {
  SAFETY_KERNEL_V31_TRANSACTION_SESSION_STORE_INVARIANT,
  SafetyKernelV31TransactionSessionStore,
} from "./safetyKernelV31TransactionSessionStore";
import type { SafetyKernelV31TransactionSessionPublicRecord } from "./safetyKernelV31TransactionSessionStore";

const publicSessionTypeBase = { sessionId: "a".repeat(48), actionId: "session-type-sentinel", approvalNonceSha256: "b".repeat(64), createdAt: "2026-07-14T12:00:00.000Z", memoryOnly: true, rawApprovalNonceExposed: false, runtimeConnected: false, executionAuthorityGranted: false } as const;
// @ts-expect-error WARN session requires a non-null expiry
const invalidWarnSessionRecord: SafetyKernelV31TransactionSessionPublicRecord = { ...publicSessionTypeBase, lifecyclePhase: "WARN_PENDING", nonceConsumed: false, expiresAt: null };
// @ts-expect-error ALLOW pending session cannot retain an expiry
const invalidAllowSessionRecord: SafetyKernelV31TransactionSessionPublicRecord = { ...publicSessionTypeBase, lifecyclePhase: "ALLOW_PENDING_EXECUTION", nonceConsumed: false, expiresAt: "2026-07-14T12:01:00.000Z" };
// @ts-expect-error consumed session must report the nonce as consumed
const invalidConsumedSessionRecord: SafetyKernelV31TransactionSessionPublicRecord = { ...publicSessionTypeBase, lifecyclePhase: "CONSUMED", nonceConsumed: false, expiresAt: null };
// @ts-expect-error non-session lifecycle phases cannot be publicly represented
const invalidBlockedSessionRecord: SafetyKernelV31TransactionSessionPublicRecord = { ...publicSessionTypeBase, lifecyclePhase: "BLOCKED", nonceConsumed: true, expiresAt: null };
void invalidWarnSessionRecord;
void invalidAllowSessionRecord;
void invalidConsumedSessionRecord;
void invalidBlockedSessionRecord;

if (false) {
  const storeTypeSentinel = new SafetyKernelV31TransactionSessionStore();
  const warnLifecycleTypeSentinel = {} as Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "WARN_PENDING" }>;
  const allowLifecycleTypeSentinel = {} as Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "ALLOW_PENDING_EXECUTION" }>;
  const consumedLifecycleTypeSentinel = {} as Extract<SafetyKernelV31NonceLifecycleRecord, { phase: "CONSUMED" }>;
  const warnCreatedTypeSentinel = storeTypeSentinel.create(warnLifecycleTypeSentinel);
  const warnCreatedExpectedType: Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: "WARN_PENDING" }> = warnCreatedTypeSentinel;
  // @ts-expect-error WARN lifecycle creation cannot expose an ALLOW pending session
  const invalidWarnCreateAllowType: Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: "ALLOW_PENDING_EXECUTION" }> = warnCreatedTypeSentinel;
  const allowReplacedTypeSentinel = storeTypeSentinel.replace(warnCreatedTypeSentinel.sessionId, allowLifecycleTypeSentinel);
  const allowReplacedExpectedType: Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: "ALLOW_PENDING_EXECUTION" }> = allowReplacedTypeSentinel;
  // @ts-expect-error ALLOW pending replacement cannot expose a consumed session
  const invalidAllowReplaceConsumedType: Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: "CONSUMED" }> = allowReplacedTypeSentinel;
  const consumedReplacedTypeSentinel = storeTypeSentinel.replace(warnCreatedTypeSentinel.sessionId, consumedLifecycleTypeSentinel);
  const consumedReplacedExpectedType: Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: "CONSUMED" }> = consumedReplacedTypeSentinel;
  // @ts-expect-error consumed replacement cannot expose an ALLOW pending session
  const invalidConsumedReplaceAllowType: Extract<SafetyKernelV31TransactionSessionPublicRecord, { lifecyclePhase: "ALLOW_PENDING_EXECUTION" }> = consumedReplacedTypeSentinel;
  void warnCreatedExpectedType;
  void invalidWarnCreateAllowType;
  void allowReplacedExpectedType;
  void invalidAllowReplaceConsumedType;
  void consumedReplacedExpectedType;
  void invalidConsumedReplaceAllowType;
}

function warnPending(
  actionId: string,
  approvalNonce: string
): SafetyKernelV31NonceLifecycleRecord {
  return {
    actionId,
    approvalNonce,
    phase: "WARN_PENDING",
    decision: "WARN",
    nonceConsumed: false,
    warnTimeoutSeconds: 60,
    warnMustNeverAutoProceed: true,
    parentEnvelopeInvalidated: false,
    childNoncesRequired: false,
    receiptRequired: true,
    ledgerRequired: true,
  };
}

test("transaction session store invariant remains memory-only, nonce-safe, disconnected, and non-executing", () => {
  assert.deepEqual(SAFETY_KERNEL_V31_TRANSACTION_SESSION_STORE_INVARIANT, {
    MEMORY_ONLY: true,
    RAW_APPROVAL_NONCE_PERSISTED: false,
    RAW_APPROVAL_NONCE_LOGGED: false,
    OPAQUE_SESSION_ID_REQUIRED: true,
    SESSION_ID_DERIVED_FROM_NONCE: false,
    AUTOMATIC_EXECUTION_ALLOWED: false,
    RUNTIME_CONNECTED: false,
    EXECUTION_AUTHORITY_GRANTED: false,
  });
});

test("transaction session store creates an opaque session without exposing the raw nonce", () => {
  const store = new SafetyKernelV31TransactionSessionStore();
  const nonce = "raw-session-nonce";
  const record = store.create(warnPending("session-create", nonce));
  const expectedHash = crypto.createHash("sha256").update(nonce, "utf8").digest("hex");

  assert.match(record.sessionId, /^[a-f0-9]{48}$/);
  assert.notEqual(record.sessionId, nonce);
  assert.notEqual(record.sessionId, expectedHash);
  assert.equal(record.approvalNonceSha256, expectedHash);
  assert.equal(JSON.stringify(record).includes(nonce), false);
  assert.equal(record.memoryOnly, true);
  assert.equal(record.rawApprovalNonceExposed, false);
  assert.equal(record.runtimeConnected, false);
  assert.equal(record.executionAuthorityGranted, false);
  assert.equal(store.size, 1);
  assert.deepEqual(store.read(record.sessionId), record);
});

test("transaction session store exposes deterministic WARN timeout metadata and preserves creation time across replace", () => {
  const now = new Date("2026-07-14T12:00:00.000Z");
  const store = new SafetyKernelV31TransactionSessionStore(() => now);
  const created = store.create(warnPending("session-timeout", "session-timeout-nonce"));

  assert.equal(created.createdAt, "2026-07-14T12:00:00.000Z");
  assert.equal(created.expiresAt, "2026-07-14T12:01:00.000Z");
  assert.deepEqual(store.read(created.sessionId), created);

  const confirmed = confirmSafetyKernelV31Warn(
    store.getLifecycleForInternalUse(created.sessionId)
  );
  const replaced = store.replace(created.sessionId, confirmed);
  assert.equal(replaced.createdAt, created.createdAt);
  assert.equal(replaced.expiresAt, null);
});


test("transaction session store keeps defensive lifecycle copies", () => {
  const store = new SafetyKernelV31TransactionSessionStore();
  const original = warnPending("session-copy", "session-copy-nonce");
  const record = store.create(original);

  Object.assign(original as unknown as { phase: string; nonceConsumed: boolean }, { phase: "CONSUMED", nonceConsumed: true });
  const first = store.getLifecycleForInternalUse(record.sessionId);
  assert.equal(first.phase, "WARN_PENDING");
  assert.equal(first.nonceConsumed, false);

  Object.assign(first as unknown as { phase: string; nonceConsumed: boolean }, { phase: "CONSUMED", nonceConsumed: true });
  const second = store.getLifecycleForInternalUse(record.sessionId);
  assert.equal(second.phase, "WARN_PENDING");
  assert.equal(second.nonceConsumed, false);
});

test("transaction session store replaces a bound pending lifecycle", () => {
  const store = new SafetyKernelV31TransactionSessionStore();
  const created = store.create(warnPending("session-replace", "session-replace-nonce"));
  const pending = store.getLifecycleForInternalUse(created.sessionId);
  const confirmed = confirmSafetyKernelV31Warn(pending);
  const replaced = store.replace(created.sessionId, confirmed);

  assert.equal(replaced.lifecyclePhase, "ALLOW_PENDING_EXECUTION");
  assert.equal(replaced.nonceConsumed, false);
  assert.equal(store.size, 1);
  assert.equal(store.read(created.sessionId)?.lifecyclePhase, "ALLOW_PENDING_EXECUTION");
  assert.throws(
    () => store.replace(created.sessionId, warnPending("session-replace", "session-replace-nonce")),
    /SESSION_LIFECYCLE_REGRESSION/
  );
});

test("transaction session store removes a session when its nonce is consumed", () => {
  const store = new SafetyKernelV31TransactionSessionStore();
  const created = store.create(warnPending("session-consume", "session-consume-nonce"));
  const confirmed = confirmSafetyKernelV31Warn(
    store.getLifecycleForInternalUse(created.sessionId)
  );
  store.replace(created.sessionId, confirmed);
  const consumed = completeSafetyKernelV31AllowedExecution(
    store.getLifecycleForInternalUse(created.sessionId)
  );
  const result = store.replace(created.sessionId, consumed);

  assert.equal(result.lifecyclePhase, "CONSUMED");
  assert.equal(result.nonceConsumed, true);
  assert.equal(result.expiresAt, null);
  assert.equal(store.size, 0);
  assert.equal(store.read(created.sessionId), null);
  assert.throws(
    () => store.getLifecycleForInternalUse(created.sessionId),
    /SESSION_NOT_FOUND/
  );
});

test("transaction session store rejects invalid lifecycle and session bindings", () => {
  const store = new SafetyKernelV31TransactionSessionStore();
  const invalid = warnPending("session-invalid", "session-invalid-nonce");
  invalid.phase = "CONSUMED";
  invalid.nonceConsumed = true;
  assert.throws(() => store.create(invalid), /SESSION_LIFECYCLE_NOT_PENDING/);

  const created = store.create(warnPending("session-bound", "session-bound-nonce"));
  const stored = store.getLifecycleForInternalUse(created.sessionId);
  assert.throws(
    () => store.replace(created.sessionId, { ...stored, actionId: "other-action" }),
    /SESSION_BINDING_MISMATCH/
  );
  assert.throws(() => store.read("invalid"), /INVALID_SESSION_ID/);
});

test("transaction session store delete and clear remove only in-memory sessions", () => {
  const store = new SafetyKernelV31TransactionSessionStore();
  const first = store.create(warnPending("session-delete", "session-delete-nonce"));
  store.create(warnPending("session-clear", "session-clear-nonce"));
  assert.equal(store.delete(first.sessionId), true);
  assert.equal(store.size, 1);
  store.clear();
  assert.equal(store.size, 0);
});


test("consumed nonce with a non-consumed phase is rejected directly", () => {
  const store = new SafetyKernelV31TransactionSessionStore();
  const created = store.create(warnPending("session-invalid-consumed-phase", "session-invalid-consumed-phase-nonce"));
  const current = store.getLifecycleForInternalUse(created.sessionId);
  const invalid = { ...current, nonceConsumed: true } as unknown as SafetyKernelV31NonceLifecycleRecord;
  assert.throws(() => store.replace(created.sessionId, invalid), /INVALID_CONSUMED_SESSION_PHASE/);
});


test("invalid public record states are rejected directly", () => {
  type Stored = { lifecycle: SafetyKernelV31NonceLifecycleRecord; createdAt: string; expiresAt: string | null };
  const store = new SafetyKernelV31TransactionSessionStore();
  const sessions = (store as unknown as { sessions: Map<string, Stored> }).sessions;

  const warn = store.create(warnPending("session-invalid-warn-record", "session-invalid-warn-record-nonce"));
  const warnStored = sessions.get(warn.sessionId);
  assert.ok(warnStored);
  warnStored.expiresAt = null;
  assert.throws(() => store.read(warn.sessionId), /INVALID_WARN_SESSION_RECORD/);

  const allow = store.create(warnPending("session-invalid-allow-record", "session-invalid-allow-record-nonce"));
  const allowStored = sessions.get(allow.sessionId);
  assert.ok(allowStored);
  Object.assign(allowStored.lifecycle as unknown as { phase: string; decision: string; nonceConsumed: boolean }, { phase: "ALLOW_PENDING_EXECUTION", decision: "ALLOW", nonceConsumed: false });
  assert.throws(() => store.read(allow.sessionId), /INVALID_ALLOW_SESSION_RECORD/);

  const consumed = store.create(warnPending("session-invalid-consumed-record", "session-invalid-consumed-record-nonce"));
  const consumedStored = sessions.get(consumed.sessionId);
  assert.ok(consumedStored);
  Object.assign(consumedStored.lifecycle as unknown as { phase: string; decision: string; nonceConsumed: boolean }, { phase: "CONSUMED", decision: "ALLOW", nonceConsumed: false });
  consumedStored.expiresAt = null;
  assert.throws(() => store.read(consumed.sessionId), /INVALID_CONSUMED_SESSION_RECORD/);

  const blocked = store.create(warnPending("session-non-public-record", "session-non-public-record-nonce"));
  const blockedStored = sessions.get(blocked.sessionId);
  assert.ok(blockedStored);
  Object.assign(blockedStored.lifecycle as unknown as { phase: string; decision: string; nonceConsumed: boolean }, { phase: "BLOCKED", decision: "BLOCK", nonceConsumed: true });
  blockedStored.expiresAt = null;
  assert.throws(() => store.read(blocked.sessionId), /SESSION_LIFECYCLE_NOT_PUBLIC/);
});

test("transaction session store covers default timeout, nonce binding, and remaining invalid public states", () => {
  const now = new Date("2026-07-14T12:00:00.000Z");
  const store = new SafetyKernelV31TransactionSessionStore(() => now);

  const defaultTimeoutLifecycle = warnPending(
    "session-default-timeout",
    "session-default-timeout-nonce"
  );
  delete (defaultTimeoutLifecycle as { warnTimeoutSeconds?: number })
    .warnTimeoutSeconds;
  const defaultTimeout = store.create(defaultTimeoutLifecycle);
  assert.equal(defaultTimeout.expiresAt, "2026-07-14T12:01:00.000Z");

  const bound = store.create(
    warnPending("session-nonce-bound", "session-nonce-bound-value")
  );
  const boundLifecycle = store.getLifecycleForInternalUse(bound.sessionId);
  assert.throws(
    () =>
      store.replace(bound.sessionId, {
        ...boundLifecycle,
        approvalNonce: "other-session-nonce",
      }),
    /SESSION_BINDING_MISMATCH/
  );

  type Stored = {
    lifecycle: SafetyKernelV31NonceLifecycleRecord;
    createdAt: string;
    expiresAt: string | null;
  };
  const sessions = (
    store as unknown as { sessions: Map<string, Stored> }
  ).sessions;

  const warn = store.create(
    warnPending("session-warn-consumed-record", "session-warn-consumed-nonce")
  );
  const warnStored = sessions.get(warn.sessionId);
  assert.ok(warnStored);
  Object.assign(
    warnStored.lifecycle as unknown as { nonceConsumed: boolean },
    { nonceConsumed: true }
  );
  assert.throws(
    () => store.read(warn.sessionId),
    /INVALID_WARN_SESSION_RECORD/
  );

  const allow = store.create(
    warnPending("session-allow-consumed-record", "session-allow-consumed-nonce")
  );
  const allowStored = sessions.get(allow.sessionId);
  assert.ok(allowStored);
  Object.assign(
    allowStored.lifecycle as unknown as {
      phase: string;
      decision: string;
      nonceConsumed: boolean;
    },
    {
      phase: "ALLOW_PENDING_EXECUTION",
      decision: "ALLOW",
      nonceConsumed: true,
    }
  );
  allowStored.expiresAt = null;
  assert.throws(
    () => store.read(allow.sessionId),
    /INVALID_ALLOW_SESSION_RECORD/
  );

  const consumed = store.create(
    warnPending(
      "session-consumed-expiry-record",
      "session-consumed-expiry-nonce"
    )
  );
  const consumedStored = sessions.get(consumed.sessionId);
  assert.ok(consumedStored);
  Object.assign(
    consumedStored.lifecycle as unknown as {
      phase: string;
      decision: string;
      nonceConsumed: boolean;
    },
    {
      phase: "CONSUMED",
      decision: "ALLOW",
      nonceConsumed: true,
    }
  );
  assert.throws(
    () => store.read(consumed.sessionId),
    /INVALID_CONSUMED_SESSION_RECORD/
  );
});

test("transaction session store sanitizes bounded public action ids and preserves defensive WARN replacement metadata", () => {
  let now = new Date("2026-07-14T12:00:00.000Z");
  const store = new SafetyKernelV31TransactionSessionStore(() => now);
  const nonce = "raw-session-boundary-nonce";
  const actionId = `  session   ${nonce}   ${"x".repeat(400)}  `;
  const lifecycle = warnPending(actionId, nonce);
  const lifecycleBefore = JSON.stringify(lifecycle);

  const created = store.create(lifecycle);
  const expectedActionId = actionId
    .split(nonce)
    .join("<redacted-nonce>")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 320);

  assert.equal(created.actionId, expectedActionId);
  assert.equal(created.actionId.includes(nonce), false);
  assert.equal(created.actionId.length, 320);
  assert.equal(JSON.stringify(lifecycle), lifecycleBefore);

  const createdAt = created.createdAt;
  const expiresAt = created.expiresAt;
  now = new Date("2026-07-14T13:00:00.000Z");

  const replacement = store.getLifecycleForInternalUse(created.sessionId);
  const replacementBefore = JSON.stringify(replacement);
  const replaced = store.replace(created.sessionId, replacement);

  assert.equal(replaced.createdAt, createdAt);
  assert.equal(replaced.expiresAt, expiresAt);
  assert.equal(JSON.stringify(replacement), replacementBefore);

  Object.assign(
    replacement as unknown as {
      phase: string;
      decision: string;
      nonceConsumed: boolean;
      warnTimeoutSeconds: number;
    },
    {
      phase: "CONSUMED",
      decision: "ALLOW",
      nonceConsumed: true,
      warnTimeoutSeconds: 999,
    }
  );

  const stored = store.getLifecycleForInternalUse(created.sessionId);
  assert.equal(stored.phase, "WARN_PENDING");
  assert.equal(stored.decision, "WARN");
  assert.equal(stored.nonceConsumed, false);
  assert.equal(stored.warnTimeoutSeconds, 60);

  const publicAfterReplace = store.read(created.sessionId);
  assert.ok(publicAfterReplace);
  assert.equal(publicAfterReplace.actionId, expectedActionId);
  assert.equal(publicAfterReplace.createdAt, createdAt);
  assert.equal(publicAfterReplace.expiresAt, expiresAt);
});

test("transaction session store rejects pending phase and decision mismatches before storage and during public reads", () => {
  const store = new SafetyKernelV31TransactionSessionStore();

  const invalidWarn = warnPending(
    "session-create-decision-mismatch",
    "session-create-decision-mismatch-nonce"
  );
  invalidWarn.decision = "ALLOW";
  assert.throws(
    () => store.create(invalidWarn),
    /SESSION_LIFECYCLE_NOT_PENDING/
  );
  assert.equal(store.size, 0);

  const created = store.create(
    warnPending(
      "session-replace-decision-mismatch",
      "session-replace-decision-mismatch-nonce"
    )
  );
  const confirmed = confirmSafetyKernelV31Warn(
    store.getLifecycleForInternalUse(created.sessionId)
  );
  const invalidAllow = {
    ...confirmed,
    decision: "WARN",
  } as unknown as SafetyKernelV31NonceLifecycleRecord;
  assert.throws(
    () => store.replace(created.sessionId, invalidAllow),
    /SESSION_LIFECYCLE_NOT_PENDING/
  );
  assert.equal(
    store.read(created.sessionId)?.lifecyclePhase,
    "WARN_PENDING"
  );

  type Stored = {
    lifecycle: SafetyKernelV31NonceLifecycleRecord;
    createdAt: string;
    expiresAt: string | null;
  };
  const sessions = (
    store as unknown as { sessions: Map<string, Stored> }
  ).sessions;
  const warnStored = sessions.get(created.sessionId);
  assert.ok(warnStored);
  warnStored.lifecycle.decision = "ALLOW";
  assert.throws(
    () => store.read(created.sessionId),
    /INVALID_WARN_SESSION_RECORD/
  );

  const allowCreated = store.create(
    warnPending(
      "session-public-allow-decision-mismatch",
      "session-public-allow-decision-mismatch-nonce"
    )
  );
  const allowStored = sessions.get(allowCreated.sessionId);
  assert.ok(allowStored);
  Object.assign(
    allowStored.lifecycle as unknown as {
      phase: string;
      decision: string;
      nonceConsumed: boolean;
    },
    {
      phase: "ALLOW_PENDING_EXECUTION",
      decision: "WARN",
      nonceConsumed: false,
    }
  );
  allowStored.expiresAt = null;
  assert.throws(
    () => store.read(allowCreated.sessionId),
    /INVALID_ALLOW_SESSION_RECORD/
  );
});
