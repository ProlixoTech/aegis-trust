import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";

import type {
  AegisExecutionPort,
  AegisExecutionResult,
} from "./platformPorts";
import {
  SAFETY_KERNEL_V31_ALLOWED_EXECUTION_COORDINATOR_INVARIANT,
  SafetyKernelV31AllowedExecutionBinding,
  SafetyKernelV31AllowedExecutionBindingVerifier,
  SafetyKernelV31AllowedExecutionCoordinator,
} from "./safetyKernelV31AllowedExecutionCoordinator";

type BindingVerificationResult =
  | "verified"
  | "authority_drift"
  | "snapshot_failed";

function sha256(value: string): string {
  return (
    "sha256:" +
    crypto.createHash("sha256").update(value, "utf8").digest("hex")
  );
}

function binding(
  commandText = "npm test",
  sessionId = "session-1"
): SafetyKernelV31AllowedExecutionBinding {
  return {
    authorityRevision: 7,
    workspaceId: "workspace-1",
    actionId: "action-1",
    sessionId,
    approvalNonceSha256: "sha256:" + "a".repeat(64),
    commandSha256: sha256(commandText),
    snapshotBindingSha256: "sha256:" + "b".repeat(64),
  };
}

class FakeExecutionPort implements AegisExecutionPort {
  calls = 0;

  constructor(
    private readonly result:
      | AegisExecutionResult
      | (() => Promise<AegisExecutionResult>)
  ) {}

  async execute(): Promise<AegisExecutionResult> {
    this.calls += 1;

    if (typeof this.result === "function") {
      return this.result();
    }

    return this.result;
  }
}

class FakeBindingVerifier
  implements SafetyKernelV31AllowedExecutionBindingVerifier {
  calls = 0;

  constructor(
    private readonly result: BindingVerificationResult = "verified"
  ) {}

  async verify(): Promise<BindingVerificationResult> {
    this.calls += 1;
    return this.result;
  }
}

test("coordinator invariant stays detached and fail-closed", () => {
  assert.deepEqual(
    SAFETY_KERNEL_V31_ALLOWED_EXECUTION_COORDINATOR_INVARIANT,
    {
      SESSION_EXECUTION_CLAIM_EXACTLY_ONCE: true,
      COMMAND_SHA256_RECHECK_REQUIRED: true,
      AUTHORITY_AND_SNAPSHOT_BINDING_VERIFICATION_REQUIRED: true,
      EXIT_CODE_ZERO_REQUIRED_FOR_COMPLETION: true,
      RAW_STDOUT_STORED_IN_RESULT: false,
      RAW_STDERR_STORED_IN_RESULT: false,
      PIPELINE_CONNECTED: false,
      RUNTIME_CONTROLLER_CONNECTED: false,
      EXTENSION_RUNTIME_CONNECTED: false,
      REAL_PROCESS_REQUIRED_BY_TESTS: false,
    }
  );
});

test("exit code zero produces only a bounded completion candidate", async () => {
  const execution = new FakeExecutionPort({
    status: "completed",
    exitCode: 0,
    stdout: "secret-output",
    stderr: "bounded-warning",
  });

  const coordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      execution,
      new FakeBindingVerifier()
    );

  const result = await coordinator.executeAllowed({
    binding: binding(),
    commandText: "npm test",
    cwd: "/workspace",
  });

  assert.equal(result.status, "completion_candidate");
  assert.equal(execution.calls, 1);

  if (result.status !== "completion_candidate") {
    throw new Error("EXPECTED_COMPLETION_CANDIDATE");
  }

  assert.equal(result.exitCode, 0);
  assert.equal(result.commandSha256, sha256("npm test"));
  assert.equal(result.output.stdoutSha256, sha256("secret-output"));
  assert.equal(result.output.stderrSha256, sha256("bounded-warning"));
  assert.equal(result.output.stdoutBytes, 13);
  assert.equal(result.output.stderrBytes, 15);
  assert.equal(JSON.stringify(result).includes("secret-output"), false);
  assert.equal(JSON.stringify(result).includes("bounded-warning"), false);
});

test("concurrent calls claim one session before asynchronous verification", async () => {
  let releaseVerification = (): void => {
    throw new Error("VERIFICATION_GATE_NOT_INITIALIZED");
  };

  const gate = new Promise<void>((resolve) => {
    releaseVerification = () => resolve();
  });

  const bindingVerifier: SafetyKernelV31AllowedExecutionBindingVerifier = {
    async verify() {
      await gate;
      return "verified";
    },
  };

  const execution = new FakeExecutionPort({
    status: "completed",
    exitCode: 0,
    stdout: "",
    stderr: "",
  });

  const coordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      execution,
      bindingVerifier
    );

  const request = {
    binding: binding("npm test", "concurrent-session"),
    commandText: "npm test",
    cwd: "/workspace",
  };

  const first = coordinator.executeAllowed(request);
  const second = await coordinator.executeAllowed(request);

  assert.deepEqual(second, {
    status: "rejected",
    sessionId: "concurrent-session",
    code: "EXECUTION_SESSION_ALREADY_CLAIMED",
  });

  assert.equal(execution.calls, 0);

  releaseVerification();

  assert.equal((await first).status, "completion_candidate");
  assert.equal(execution.calls, 1);
});

test("settled sessions cannot execute again", async () => {
  const execution = new FakeExecutionPort({
    status: "completed",
    exitCode: 0,
    stdout: "",
    stderr: "",
  });

  const coordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      execution,
      new FakeBindingVerifier()
    );

  const request = {
    binding: binding("npm test", "settled-session"),
    commandText: "npm test",
    cwd: "/workspace",
  };

  assert.equal(
    (await coordinator.executeAllowed(request)).status,
    "completion_candidate"
  );

  assert.deepEqual(await coordinator.executeAllowed(request), {
    status: "rejected",
    sessionId: "settled-session",
    code: "EXECUTION_SESSION_ALREADY_CLAIMED",
  });

  assert.equal(execution.calls, 1);
});

test("command SHA drift aborts before verifier and execution", async () => {
  const execution = new FakeExecutionPort({
    status: "completed",
    exitCode: 0,
    stdout: "",
    stderr: "",
  });

  const bindingVerifier = new FakeBindingVerifier();

  const coordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      execution,
      bindingVerifier
    );

  const result = await coordinator.executeAllowed({
    binding: binding("npm test", "command-drift-session"),
    commandText: "npm run changed",
    cwd: "/workspace",
  });

  assert.deepEqual(result, {
    status: "abort_candidate",
    sessionId: "command-drift-session",
    actionId: "action-1",
    reason: "authority_drift",
  });

  assert.equal(bindingVerifier.calls, 0);
  assert.equal(execution.calls, 0);
});

test("authority drift and verifier failure abort without execution", async () => {
  const execution = new FakeExecutionPort({
    status: "completed",
    exitCode: 0,
    stdout: "",
    stderr: "",
  });

  const driftCoordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      execution,
      new FakeBindingVerifier("authority_drift")
    );

  const drift = await driftCoordinator.executeAllowed({
    binding: binding("npm test", "authority-drift-session"),
    commandText: "npm test",
    cwd: "/workspace",
  });

  assert.equal(drift.status, "abort_candidate");

  if (drift.status !== "abort_candidate") {
    throw new Error("EXPECTED_AUTHORITY_ABORT");
  }

  assert.equal(drift.reason, "authority_drift");

  const throwingVerifier: SafetyKernelV31AllowedExecutionBindingVerifier = {
    async verify() {
      throw new Error("verification unavailable");
    },
  };

  const failureCoordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      execution,
      throwingVerifier
    );

  const failed = await failureCoordinator.executeAllowed({
    binding: binding("npm test", "verification-failure-session"),
    commandText: "npm test",
    cwd: "/workspace",
  });

  assert.equal(failed.status, "abort_candidate");

  if (failed.status !== "abort_candidate") {
    throw new Error("EXPECTED_VERIFICATION_ABORT");
  }

  assert.equal(failed.reason, "authority_drift");
  assert.equal(execution.calls, 0);
});

test("snapshot verification failure maps to snapshot_failed", async () => {
  const execution = new FakeExecutionPort({
    status: "completed",
    exitCode: 0,
    stdout: "",
    stderr: "",
  });

  const coordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      execution,
      new FakeBindingVerifier("snapshot_failed")
    );

  const result = await coordinator.executeAllowed({
    binding: binding("npm test", "snapshot-failure-session"),
    commandText: "npm test",
    cwd: "/workspace",
  });

  assert.equal(result.status, "abort_candidate");

  if (result.status !== "abort_candidate") {
    throw new Error("EXPECTED_SNAPSHOT_ABORT");
  }

  assert.equal(result.reason, "snapshot_failed");
  assert.equal(execution.calls, 0);
});

test("nonzero exit code maps to execution_failed", async () => {
  const execution = new FakeExecutionPort({
    status: "completed",
    exitCode: 7,
    stdout: "",
    stderr: "failure detail",
  });

  const coordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      execution,
      new FakeBindingVerifier()
    );

  const result = await coordinator.executeAllowed({
    binding: binding("npm test", "nonzero-session"),
    commandText: "npm test",
    cwd: "/workspace",
  });

  assert.equal(result.status, "abort_candidate");

  if (result.status !== "abort_candidate") {
    throw new Error("EXPECTED_NONZERO_ABORT");
  }

  assert.equal(result.reason, "execution_failed");
  assert.equal(result.exitCode, 7);
  assert.equal(result.output?.stderrSha256, sha256("failure detail"));
  assert.equal(JSON.stringify(result).includes("failure detail"), false);
  assert.equal(execution.calls, 1);
});

test("execution failures and thrown ports map to execution_failed", async () => {
  const failedPort = new FakeExecutionPort({
    status: "failed",
    errorCode: "EXECUTION_START_FAILED",
    message: "sensitive spawn detail",
    stdout: "",
    stderr: "",
  });

  const failedCoordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      failedPort,
      new FakeBindingVerifier()
    );

  const failed = await failedCoordinator.executeAllowed({
    binding: binding("npm test", "failed-port-session"),
    commandText: "npm test",
    cwd: "/workspace",
  });

  assert.equal(failed.status, "abort_candidate");

  if (failed.status !== "abort_candidate") {
    throw new Error("EXPECTED_FAILED_PORT_ABORT");
  }

  assert.equal(failed.reason, "execution_failed");
  assert.equal(
    failed.executionErrorCode,
    "EXECUTION_START_FAILED"
  );
  assert.equal(
    JSON.stringify(failed).includes("sensitive spawn detail"),
    false
  );

  const thrownPort = new FakeExecutionPort(async () => {
    throw new Error("unexpected execution throw");
  });

  const thrownCoordinator =
    new SafetyKernelV31AllowedExecutionCoordinator(
      thrownPort,
      new FakeBindingVerifier()
    );

  const thrown = await thrownCoordinator.executeAllowed({
    binding: binding("npm test", "thrown-port-session"),
    commandText: "npm test",
    cwd: "/workspace",
  });

  assert.equal(thrown.status, "abort_candidate");

  if (thrown.status !== "abort_candidate") {
    throw new Error("EXPECTED_THROWN_PORT_ABORT");
  }

  assert.equal(thrown.reason, "execution_failed");
  assert.equal(
    JSON.stringify(thrown).includes("unexpected execution throw"),
    false
  );
  assert.equal(failedPort.calls, 1);
  assert.equal(thrownPort.calls, 1);
});