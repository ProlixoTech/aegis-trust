import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";

import {
  SAFETY_KERNEL_V31_ALLOWED_EXECUTION_SESSION_BINDING_STORE_INVARIANT,
  SafetyKernelV31AllowedExecutionSessionBindingStore,
} from "./safetyKernelV31AllowedExecutionSessionBindingStore";

function digest(value: string): string {
  return (
    "sha256:" +
    crypto.createHash("sha256").update(value, "utf8").digest("hex")
  );
}

const sessionOne = "a".repeat(48);
const sessionTwo = "b".repeat(48);
const approvalHash = "sha256:" + "1".repeat(64);
const snapshotHash = "sha256:" + "2".repeat(64);

test("binding store remains memory-only, detached, nonce-safe, and non-executing", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_ALLOWED_EXECUTION_SESSION_BINDING_STORE_INVARIANT,
    {
      MEMORY_ONLY: true,
      RAW_APPROVAL_NONCE_ACCEPTED: false,
      RAW_APPROVAL_NONCE_PERSISTED: false,
      REVIEWED_COMMAND_IMMUTABLE: true,
      COMMAND_SHA256_COMPUTED_FROM_REVIEWED_COMMAND: true,
      AUTHORITY_BINDING_EXACTLY_ONCE: true,
      DEFENSIVE_COPY_REQUIRED: true,
      PIPELINE_CONNECTED: false,
      RUNTIME_CONNECTED: false,
      REAL_PROCESS_EXECUTION_ALLOWED: false,
    }
  );
});

test("registerReviewedCommand preserves the exact reviewed command and computes its SHA-256", () => {
  const store =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  const commandText =
    "Get-Content src/example.ts\n" +
    "| Select-Object -First 5";

  const registered = store.registerReviewedCommand({
    sessionId: sessionOne,
    actionId: "action-reviewed-command",
    approvalNonceSha256: approvalHash,
    commandText,
  });

  assert.deepEqual(registered, {
    sessionId: sessionOne,
    actionId: "action-reviewed-command",
    approvalNonceSha256: approvalHash,
    commandText,
    commandSha256: digest(commandText),
    authorityBound: false,
  });

  assert.equal(store.size, 1);
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      registered,
      "approvalNonce"
    ),
    false
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      registered,
      "rawApprovalNonce"
    ),
    false
  );
});

test("reviewed binding is immutable in the store and reads are defensive copies", () => {
  const store =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  const commandText = "Get-ChildItem src";

  const first = store.registerReviewedCommand({
    sessionId: sessionOne,
    actionId: "action-defensive-copy",
    approvalNonceSha256: approvalHash,
    commandText,
  });

  const mutable = first as unknown as {
    actionId: string;
    commandText: string;
    commandSha256: string;
  };

  mutable.actionId = "mutated-action";
  mutable.commandText = "Remove-Item -Recurse src";
  mutable.commandSha256 = "sha256:" + "f".repeat(64);

  assert.deepEqual(store.read(sessionOne), {
    sessionId: sessionOne,
    actionId: "action-defensive-copy",
    approvalNonceSha256: approvalHash,
    commandText,
    commandSha256: digest(commandText),
    authorityBound: false,
  });

  assert.throws(
    () =>
      store.registerReviewedCommand({
        sessionId: sessionOne,
        actionId: "action-duplicate",
        approvalNonceSha256: approvalHash,
        commandText: "Get-Date",
      }),
    /EXECUTION_SESSION_BINDING_ALREADY_REGISTERED/
  );
});

test("raw nonce input and malformed reviewed bindings are rejected", () => {
  const store =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  assert.throws(
    () =>
      store.registerReviewedCommand({
        sessionId: sessionOne,
        actionId: "action-raw-nonce",
        approvalNonceSha256: approvalHash,
        commandText: "Get-Date",
        approvalNonce: "raw-secret-nonce",
      } as never),
    /RAW_APPROVAL_NONCE_INPUT_FORBIDDEN/
  );

  assert.throws(
    () =>
      store.registerReviewedCommand({
        sessionId: "not-a-session",
        actionId: "action-invalid-session",
        approvalNonceSha256: approvalHash,
        commandText: "Get-Date",
      }),
    /INVALID_SESSION_ID/
  );

  assert.throws(
    () =>
      store.registerReviewedCommand({
        sessionId: sessionOne,
        actionId: "action-invalid-hash",
        approvalNonceSha256: "1".repeat(64),
        commandText: "Get-Date",
      }),
    /INVALID_APPROVAL_NONCE_SHA256/
  );

  assert.throws(
    () =>
      store.registerReviewedCommand({
        sessionId: sessionOne,
        actionId: "action-empty-command",
        approvalNonceSha256: approvalHash,
        commandText: "   ",
      }),
    /INVALID_REVIEWED_COMMAND_TEXT/
  );

  assert.equal(store.size, 0);
});

test("authority and snapshot context bind exactly once and produce a coordinator request", () => {
  const store =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  const commandText = "npm test";

  store.registerReviewedCommand({
    sessionId: sessionOne,
    actionId: "action-bound-authority",
    approvalNonceSha256: approvalHash,
    commandText,
  });

  assert.throws(
    () => store.getExecutionRequest(sessionOne),
    /EXECUTION_SESSION_AUTHORITY_NOT_BOUND/
  );

  const bound = store.bindAuthority(sessionOne, {
    authorityRevision: 42,
    workspaceId: "workspace-main",
    snapshotBindingSha256: snapshotHash,
    cwd: "/workspace/project",
  });

  assert.deepEqual(bound, {
    sessionId: sessionOne,
    actionId: "action-bound-authority",
    approvalNonceSha256: approvalHash,
    commandText,
    commandSha256: digest(commandText),
    authorityBound: true,
    authorityRevision: 42,
    workspaceId: "workspace-main",
    snapshotBindingSha256: snapshotHash,
    cwd: "/workspace/project",
  });

  assert.deepEqual(store.getExecutionRequest(sessionOne), {
    binding: {
      authorityRevision: 42,
      workspaceId: "workspace-main",
      actionId: "action-bound-authority",
      sessionId: sessionOne,
      approvalNonceSha256: approvalHash,
      commandSha256: digest(commandText),
      snapshotBindingSha256: snapshotHash,
    },
    commandText,
    cwd: "/workspace/project",
  });

  assert.throws(
    () =>
      store.bindAuthority(sessionOne, {
        authorityRevision: 43,
        workspaceId: "workspace-other",
        snapshotBindingSha256:
          "sha256:" + "3".repeat(64),
        cwd: "/workspace/other",
      }),
    /EXECUTION_SESSION_AUTHORITY_ALREADY_BOUND/
  );

  assert.deepEqual(
    store.getExecutionRequest(sessionOne).binding,
    {
      authorityRevision: 42,
      workspaceId: "workspace-main",
      actionId: "action-bound-authority",
      sessionId: sessionOne,
      approvalNonceSha256: approvalHash,
      commandSha256: digest(commandText),
      snapshotBindingSha256: snapshotHash,
    }
  );
});

test("delete and clear remove both reviewed and authority-bound material", () => {
  const store =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  assert.throws(
    () =>
      store.bindAuthority(sessionOne, {
        authorityRevision: 1,
        workspaceId: "workspace-missing",
        snapshotBindingSha256: snapshotHash,
        cwd: "/workspace/missing",
      }),
    /EXECUTION_SESSION_BINDING_NOT_FOUND/
  );

  store.registerReviewedCommand({
    sessionId: sessionOne,
    actionId: "action-delete",
    approvalNonceSha256: approvalHash,
    commandText: "Get-Date",
  });

  store.bindAuthority(sessionOne, {
    authorityRevision: 1,
    workspaceId: "workspace-delete",
    snapshotBindingSha256: snapshotHash,
    cwd: "/workspace/delete",
  });

  store.registerReviewedCommand({
    sessionId: sessionTwo,
    actionId: "action-clear",
    approvalNonceSha256:
      "sha256:" + "4".repeat(64),
    commandText: "Get-Location",
  });

  assert.equal(store.size, 2);
  assert.equal(store.delete(sessionOne), true);
  assert.equal(store.read(sessionOne), null);
  assert.throws(
    () => store.getExecutionRequest(sessionOne),
    /EXECUTION_SESSION_BINDING_NOT_FOUND/
  );
  assert.equal(store.size, 1);

  store.clear();

  assert.equal(store.size, 0);
  assert.equal(store.read(sessionTwo), null);
});