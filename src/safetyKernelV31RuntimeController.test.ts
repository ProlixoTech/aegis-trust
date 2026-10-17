import test from "node:test";
import assert from "node:assert/strict";

import type {
  ActionQualityResult,
  SafetyKernelV31WarnTerminalEvidenceReason,
} from "../packages/aegis-core";
import type { SafetyKernelV31TransactionCallerContext } from "../packages/aegis-core";
import {
  SafetyKernelV31TransactionReviewPipeline,
} from "../packages/aegis-core";
import type {
  SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult,
  SafetyKernelV31TransactionReviewPipelineCoordinatedExecutionSessionResult,
  SafetyKernelV31TransactionReviewPipelineResult,
  SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult,
  SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult,
} from "../packages/aegis-core";
import type { SafetyKernelV31TransactionSessionPublicRecord } from "../packages/aegis-core";
import type {
  SafetyKernelV31AllowedExecutionAuthorityBindingInput,
  SafetyKernelV31AllowedExecutionSessionBoundBinding,
} from "../packages/aegis-core";
import {
  SAFETY_KERNEL_V31_RUNTIME_CONTROLLER_INVARIANT,
  SafetyKernelV31RuntimeController,
  SafetyKernelV31RuntimeControllerPipelinePort,
} from "./safetyKernelV31RuntimeController";

type RuntimeControllerConfirmResult = Awaited<ReturnType<SafetyKernelV31RuntimeControllerPipelinePort["confirmWarnSession"]>>;
type RuntimeControllerCompleteResult = Awaited<ReturnType<SafetyKernelV31RuntimeControllerPipelinePort["completeAllowedExecutionSession"]>>;
type RuntimeControllerTerminateResult = Awaited<ReturnType<SafetyKernelV31RuntimeControllerPipelinePort["terminateWarnSession"]>>;
const warnConfirmationControllerResultType = {} as SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult;
const allowedCompletionControllerResultType = {} as SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult;
// @ts-expect-error confirm method cannot expose allowed-completion result
const invalidRuntimeControllerConfirmResult: RuntimeControllerConfirmResult = allowedCompletionControllerResultType;
// @ts-expect-error completion method cannot expose WARN-confirmation result
const invalidRuntimeControllerCompleteResult: RuntimeControllerCompleteResult = warnConfirmationControllerResultType;
// @ts-expect-error termination method cannot expose WARN-confirmation result
const invalidRuntimeControllerTerminateResult: RuntimeControllerTerminateResult = warnConfirmationControllerResultType;
void invalidRuntimeControllerConfirmResult;
void invalidRuntimeControllerCompleteResult;
void invalidRuntimeControllerTerminateResult;

class PipelineStub implements SafetyKernelV31RuntimeControllerPipelinePort {
  reviewCalls = 0;
  readCalls = 0;
  confirmCalls = 0;
  completeCalls = 0;
  terminateCalls = 0;
  lastSessionId: string | null = null;
  lastTimestamp: string | undefined;
  lastReason: SafetyKernelV31WarnTerminalEvidenceReason | null = null;

  readonly reviewResult = {} as SafetyKernelV31TransactionReviewPipelineResult;
  readonly confirmResult = {} as SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult;
  readonly completeResult = {} as SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult;
  readonly terminateResult = {} as SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult;
  readonly readResult = {} as SafetyKernelV31TransactionSessionPublicRecord;

  async review(
    _caller: SafetyKernelV31TransactionCallerContext,
    _actionQuality: ActionQualityResult
  ): Promise<SafetyKernelV31TransactionReviewPipelineResult> {
    this.reviewCalls += 1;
    return this.reviewResult;
  }

  readSession(sessionId: string): SafetyKernelV31TransactionSessionPublicRecord | null {
    this.readCalls += 1;
    this.lastSessionId = sessionId;
    return this.readResult;
  }

  async confirmWarnSession(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult> {
    this.confirmCalls += 1;
    this.lastSessionId = sessionId;
    this.lastTimestamp = timestamp;
    return this.confirmResult;
  }

  async completeAllowedExecutionSession(
    sessionId: string,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult> {
    this.completeCalls += 1;
    this.lastSessionId = sessionId;
    this.lastTimestamp = timestamp;
    return this.completeResult;
  }

  async terminateWarnSession(
    sessionId: string,
    reason: SafetyKernelV31WarnTerminalEvidenceReason,
    timestamp?: string
  ): Promise<SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult> {
    this.terminateCalls += 1;
    this.lastSessionId = sessionId;
    this.lastReason = reason;
    this.lastTimestamp = timestamp;
    return this.terminateResult;
  }
}

test("runtime controller invariant remains session-only, disconnected, and non-executing", () => {
  assert.deepEqual(SAFETY_KERNEL_V31_RUNTIME_CONTROLLER_INVARIANT, {
    SINGLE_PIPELINE_INSTANCE_REQUIRED: true,
    SESSION_BASED_PUBLIC_API_ONLY: true,
    RAW_LIFECYCLE_API_EXPOSED: false,
    RAW_APPROVAL_NONCE_EXPOSED: false,
    AUTOMATIC_EXECUTION_ALLOWED: false,
    RUNTIME_CONNECTED: false,
    EXECUTION_AUTHORITY_GRANTED: false,
  });
});

test("runtime controller delegates only the session-based pipeline surface", async () => {
  const pipeline = new PipelineStub();
  const controller = new SafetyKernelV31RuntimeController(pipeline);
  const caller = {} as SafetyKernelV31TransactionCallerContext;
  const actionQuality = {} as ActionQualityResult;
  const timestamp = "2026-01-01T00:00:00.000Z";

  assert.equal(await controller.review(caller, actionQuality), pipeline.reviewResult);
  assert.equal(controller.readSession("session-read"), pipeline.readResult);
  assert.equal(await controller.confirmWarnSession("session-confirm"), pipeline.confirmResult);
  assert.equal(
    await controller.completeAllowedExecutionSession("session-complete", timestamp),
    pipeline.completeResult
  );
  assert.equal(
    await controller.terminateWarnSession("session-terminate", "cancel_by_user", timestamp),
    pipeline.terminateResult
  );

  assert.equal(pipeline.reviewCalls, 1);
  assert.equal(pipeline.readCalls, 1);
  assert.equal(pipeline.confirmCalls, 1);
  assert.equal(pipeline.completeCalls, 1);
  assert.equal(pipeline.terminateCalls, 1);
  assert.equal(pipeline.lastSessionId, "session-terminate");
  assert.equal(pipeline.lastReason, "cancel_by_user");
  assert.equal(pipeline.lastTimestamp, timestamp);
  assert.equal("confirmWarn" in controller, false);
  assert.equal("completeAllowedExecution" in controller, false);
  assert.equal("terminateWarn" in controller, false);
});

test("runtime controller rejects an empty Aegis directory before pipeline creation", () => {
  assert.throws(
    () => SafetyKernelV31RuntimeController.createForAegisDir("   "),
    /INVALID_AEGIS_DIR/
  );
});


test("runtime controller creates from a non-empty Aegis directory", () => {
  const controller = SafetyKernelV31RuntimeController.createForAegisDir(
    "/tmp/safety-kernel-v31-runtime-controller-test"
  );
  assert.equal(controller instanceof SafetyKernelV31RuntimeController, true);
});

test("runtime controller preserves delegation arguments, null results, and pipeline errors", async () => {
  const caller = { marker: "caller" } as unknown as SafetyKernelV31TransactionCallerContext;
  const actionQuality = { marker: "action-quality" } as unknown as ActionQualityResult;
  const failure = new Error("PIPELINE_FAILURE");
  const seen: {
    reviewCaller?: SafetyKernelV31TransactionCallerContext;
    reviewActionQuality?: ActionQualityResult;
    confirm?: [string, string | undefined];
    complete?: [string, string | undefined];
    terminate?: [string, SafetyKernelV31WarnTerminalEvidenceReason, string | undefined];
  } = {};

  const pipeline: SafetyKernelV31RuntimeControllerPipelinePort = {
    async review(actualCaller, actualActionQuality) {
      seen.reviewCaller = actualCaller;
      seen.reviewActionQuality = actualActionQuality;
      return {} as SafetyKernelV31TransactionReviewPipelineResult;
    },
    readSession(sessionId) {
      assert.equal(sessionId, "missing-session");
      return null;
    },
    async confirmWarnSession(sessionId, timestamp) {
      seen.confirm = [sessionId, timestamp];
      return {} as SafetyKernelV31TransactionReviewPipelineWarnConfirmationSessionResult;
    },
    async completeAllowedExecutionSession(sessionId, timestamp) {
      seen.complete = [sessionId, timestamp];
      return {} as SafetyKernelV31TransactionReviewPipelineAllowedCompletionSessionResult;
    },
    async terminateWarnSession(sessionId, reason, timestamp) {
      if (sessionId === "error-session") throw failure;
      seen.terminate = [sessionId, reason, timestamp];
      return {} as SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult;
    },
  };

  const controller = new SafetyKernelV31RuntimeController(pipeline);
  await controller.review(caller, actionQuality);
  assert.equal(seen.reviewCaller, caller);
  assert.equal(seen.reviewActionQuality, actionQuality);
  assert.equal(controller.readSession("missing-session"), null);

  await controller.confirmWarnSession("confirm-session");
  await controller.completeAllowedExecutionSession(
    "complete-session",
    "2026-07-16T23:12:00.000Z"
  );
  await controller.terminateWarnSession(
    "terminate-session",
    "cancel_by_user",
    "2026-07-16T23:13:00.000Z"
  );

  assert.deepEqual(seen.confirm, ["confirm-session", undefined]);
  assert.deepEqual(seen.complete, [
    "complete-session",
    "2026-07-16T23:12:00.000Z",
  ]);
  assert.deepEqual(seen.terminate, [
    "terminate-session",
    "cancel_by_user",
    "2026-07-16T23:13:00.000Z",
  ]);
  await assert.rejects(
    () => controller.terminateWarnSession("error-session", "cancel_by_user"),
    (error) => error === failure
  );
});

test("runtime controller preserves failure inputs and propagates every pipeline error unchanged", async () => {
  const caller = {
    marker: "failure-caller",
    nested: { value: "caller-value" },
  } as unknown as SafetyKernelV31TransactionCallerContext;
  const actionQuality = {
    marker: "failure-action-quality",
    nested: { value: "action-quality-value" },
  } as unknown as ActionQualityResult;
  const callerBefore = JSON.stringify(caller);
  const actionQualityBefore = JSON.stringify(actionQuality);
  const reviewFailure = new Error("REVIEW_PIPELINE_FAILURE");
  const readFailure = new Error("READ_PIPELINE_FAILURE");
  const confirmFailure = new Error("CONFIRM_PIPELINE_FAILURE");
  const completeFailure = new Error("COMPLETE_PIPELINE_FAILURE");
  const seen: {
    review?: [
      SafetyKernelV31TransactionCallerContext,
      ActionQualityResult
    ];
    read?: string;
    confirm?: [string, string | undefined];
    complete?: [string, string | undefined];
  } = {};

  const pipeline: SafetyKernelV31RuntimeControllerPipelinePort = {
    async review(actualCaller, actualActionQuality) {
      seen.review = [actualCaller, actualActionQuality];
      throw reviewFailure;
    },
    readSession(sessionId) {
      seen.read = sessionId;
      throw readFailure;
    },
    async confirmWarnSession(sessionId, timestamp) {
      seen.confirm = [sessionId, timestamp];
      throw confirmFailure;
    },
    async completeAllowedExecutionSession(sessionId, timestamp) {
      seen.complete = [sessionId, timestamp];
      throw completeFailure;
    },
    async terminateWarnSession() {
      return {} as SafetyKernelV31TransactionReviewPipelineWarnTerminationSessionResult;
    },
  };
  const controller = new SafetyKernelV31RuntimeController(pipeline);

  await assert.rejects(
    () => controller.review(caller, actionQuality),
    (error) => error === reviewFailure
  );
  assert.throws(
    () => controller.readSession("read-failure-session"),
    (error) => error === readFailure
  );
  await assert.rejects(
    () =>
      controller.confirmWarnSession(
        "confirm-failure-session",
        "2026-07-17T00:20:01.001Z"
      ),
    (error) => error === confirmFailure
  );
  await assert.rejects(
    () =>
      controller.completeAllowedExecutionSession(
        "complete-failure-session",
        "2026-07-17T00:20:02.002Z"
      ),
    (error) => error === completeFailure
  );

  assert.equal(seen.review?.[0], caller);
  assert.equal(seen.review?.[1], actionQuality);
  assert.equal(seen.read, "read-failure-session");
  assert.deepEqual(seen.confirm, [
    "confirm-failure-session",
    "2026-07-17T00:20:01.001Z",
  ]);
  assert.deepEqual(seen.complete, [
    "complete-failure-session",
    "2026-07-17T00:20:02.002Z",
  ]);
  assert.equal(JSON.stringify(caller), callerBefore);
  assert.equal(JSON.stringify(actionQuality), actionQualityBefore);
});

test("runtime controller normalizes the Aegis directory before pipeline creation", () => {
  const originalCreateForAegisDir =
    SafetyKernelV31TransactionReviewPipeline.createForAegisDir;
  let receivedAegisDir: string | null = null;

  (
    SafetyKernelV31TransactionReviewPipeline as unknown as {
      createForAegisDir: (
        aegisDir: string
      ) => SafetyKernelV31RuntimeControllerPipelinePort;
    }
  ).createForAegisDir = (aegisDir: string) => {
    receivedAegisDir = aegisDir;
    return new PipelineStub();
  };

  try {
    const controller = SafetyKernelV31RuntimeController.createForAegisDir(
      "  /tmp/safety-kernel-v31-runtime-controller-normalized  "
    );
    assert.equal(controller instanceof SafetyKernelV31RuntimeController, true);
    assert.equal(
      receivedAegisDir,
      "/tmp/safety-kernel-v31-runtime-controller-normalized"
    );
  } finally {
    (
      SafetyKernelV31TransactionReviewPipeline as unknown as {
        createForAegisDir: typeof originalCreateForAegisDir;
      }
    ).createForAegisDir = originalCreateForAegisDir;
  }
});

test("runtime controller forwards detached authority binding and coordinated execution without transformation", async () => {
  const base = new PipelineStub();

  const authorityInput: SafetyKernelV31AllowedExecutionAuthorityBindingInput = {
    authorityRevision: 91,
    workspaceId: "sha256:" + "a".repeat(64),
    snapshotBindingSha256: "sha256:" + "b".repeat(64),
    cwd: "/workspace/detached-runtime-controller",
  };

  const authorityInputBefore = JSON.stringify(authorityInput);

  const boundResult = {
    marker: "bound-result",
  } as unknown as SafetyKernelV31AllowedExecutionSessionBoundBinding;

  const coordinatedResult = {
    status: "rejected",
    sessionId: "coordinate-session",
    code: "EXECUTION_SESSION_ALREADY_CLAIMED",
  } as SafetyKernelV31TransactionReviewPipelineCoordinatedExecutionSessionResult;

  const bindFailure = new Error("BIND_PIPELINE_FAILURE");
  const coordinateFailure = new Error("COORDINATE_PIPELINE_FAILURE");

  const bindCalls: Array<
    [
      string,
      SafetyKernelV31AllowedExecutionAuthorityBindingInput
    ]
  > = [];

  const coordinateCalls: Array<
    [string, string | undefined]
  > = [];

  const pipeline: SafetyKernelV31RuntimeControllerPipelinePort = {
    review(caller, actionQuality) {
      return base.review(caller, actionQuality);
    },

    readSession(sessionId) {
      return base.readSession(sessionId);
    },

    confirmWarnSession(sessionId, timestamp) {
      return base.confirmWarnSession(sessionId, timestamp);
    },

    completeAllowedExecutionSession(sessionId, timestamp) {
      return base.completeAllowedExecutionSession(
        sessionId,
        timestamp
      );
    },

    terminateWarnSession(sessionId, reason, timestamp) {
      return base.terminateWarnSession(
        sessionId,
        reason,
        timestamp
      );
    },

    bindAllowedExecutionSessionAuthority(sessionId, input) {
      bindCalls.push([sessionId, input]);

      if (sessionId === "bind-failure-session") {
        throw bindFailure;
      }

      return boundResult;
    },

    async coordinateAllowedExecutionSession(
      sessionId,
      timestamp
    ) {
      coordinateCalls.push([sessionId, timestamp]);

      if (sessionId === "coordinate-failure-session") {
        throw coordinateFailure;
      }

      return coordinatedResult;
    },
  };

  const controller =
    new SafetyKernelV31RuntimeController(pipeline);

  assert.equal(
    controller.bindAllowedExecutionSessionAuthority(
      "bind-session",
      authorityInput
    ),
    boundResult
  );

  assert.equal(
    await controller.coordinateAllowedExecutionSession(
      "coordinate-session",
      "2026-07-20T18:00:00.000Z"
    ),
    coordinatedResult
  );

  assert.deepEqual(bindCalls[0], [
    "bind-session",
    authorityInput,
  ]);

  assert.equal(bindCalls[0][1], authorityInput);

  assert.deepEqual(coordinateCalls[0], [
    "coordinate-session",
    "2026-07-20T18:00:00.000Z",
  ]);

  assert.equal(
    JSON.stringify(authorityInput),
    authorityInputBefore
  );

  assert.throws(
    () =>
      controller.bindAllowedExecutionSessionAuthority(
        "bind-failure-session",
        authorityInput
      ),
    (error) => error === bindFailure
  );

  await assert.rejects(
    () =>
      controller.coordinateAllowedExecutionSession(
        "coordinate-failure-session"
      ),
    (error) => error === coordinateFailure
  );
});

test("runtime controller fails closed when detached coordination methods are unavailable", async () => {
  const pipeline = new PipelineStub();

  const controller =
    new SafetyKernelV31RuntimeController(pipeline);

  const authorityInput: SafetyKernelV31AllowedExecutionAuthorityBindingInput = {
    authorityRevision: 92,
    workspaceId: "sha256:" + "c".repeat(64),
    snapshotBindingSha256: "sha256:" + "d".repeat(64),
    cwd: "/workspace/unavailable-runtime-controller",
  };

  assert.throws(
    () =>
      controller.bindAllowedExecutionSessionAuthority(
        "unavailable-bind-session",
        authorityInput
      ),
    /ALLOWED_EXECUTION_AUTHORITY_BINDING_PIPELINE_UNAVAILABLE/
  );

  await assert.rejects(
    () =>
      controller.coordinateAllowedExecutionSession(
        "unavailable-coordinate-session",
        "2026-07-20T18:01:00.000Z"
      ),
    /ALLOWED_EXECUTION_COORDINATION_PIPELINE_UNAVAILABLE/
  );

  assert.equal(pipeline.reviewCalls, 0);
  assert.equal(pipeline.readCalls, 0);
  assert.equal(pipeline.confirmCalls, 0);
  assert.equal(pipeline.completeCalls, 0);
  assert.equal(pipeline.terminateCalls, 0);
});