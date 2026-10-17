import test from "node:test";
import assert from "node:assert/strict";

import {
  NodeProcessExecutionAdapter,
  type NodeProcessExecutionHandle,
  type NodeProcessSpawner,
} from "./nodeProcessExecutionAdapter";

class FakeProcessExecutionHandle
  implements NodeProcessExecutionHandle {
  private readonly stdoutListeners: Array<(chunk: unknown) => void> = [];
  private readonly stderrListeners: Array<(chunk: unknown) => void> = [];
  private readonly errorListeners: Array<(error: Error) => void> = [];
  private readonly closeListeners: Array<(exitCode: number | null) => void> = [];

  onStdout(listener: (chunk: unknown) => void): void {
    this.stdoutListeners.push(listener);
  }

  onStderr(listener: (chunk: unknown) => void): void {
    this.stderrListeners.push(listener);
  }

  onError(listener: (error: Error) => void): void {
    this.errorListeners.push(listener);
  }

  onClose(listener: (exitCode: number | null) => void): void {
    this.closeListeners.push(listener);
  }

  emitStdout(chunk: unknown): void {
    for (const listener of this.stdoutListeners) {
      listener(chunk);
    }
  }

  emitStderr(chunk: unknown): void {
    for (const listener of this.stderrListeners) {
      listener(chunk);
    }
  }

  emitError(error: Error): void {
    for (const listener of this.errorListeners) {
      listener(error);
    }
  }

  emitClose(exitCode: number | null): void {
    for (const listener of this.closeListeners) {
      listener(exitCode);
    }
  }
}

test("node execution adapter observes stdout, stderr, and exit code", async () => {
  const handle = new FakeProcessExecutionHandle();
  const requests: Array<{ commandText: string; cwd: string }> = [];

  const spawner: NodeProcessSpawner = (request) => {
    requests.push({ ...request });
    return handle;
  };

  const adapter = new NodeProcessExecutionAdapter(spawner);
  const resultPromise = adapter.execute({
    commandText: "example command",
    cwd: "/workspace",
  });

  handle.emitStdout(Buffer.from("first "));
  handle.emitStdout("second");
  handle.emitStderr(Buffer.from("warning"));
  handle.emitClose(0);

  assert.deepEqual(await resultPromise, {
    status: "completed",
    exitCode: 0,
    stdout: "first second",
    stderr: "warning",
  });

  assert.deepEqual(requests, [
    {
      commandText: "example command",
      cwd: "/workspace",
    },
  ]);
});

test("node execution adapter returns an observed non-zero exit code as completed", async () => {
  const handle = new FakeProcessExecutionHandle();
  const adapter = new NodeProcessExecutionAdapter(() => handle);

  const resultPromise = adapter.execute({
    commandText: "failing example",
    cwd: "/workspace",
  });

  handle.emitStderr("failure output");
  handle.emitClose(7);

  assert.deepEqual(await resultPromise, {
    status: "completed",
    exitCode: 7,
    stdout: "",
    stderr: "failure output",
  });
});

test("node execution adapter maps spawn failure and settles only once", async () => {
  const handle = new FakeProcessExecutionHandle();
  const adapter = new NodeProcessExecutionAdapter(() => handle);

  const resultPromise = adapter.execute({
    commandText: "unavailable example",
    cwd: "/workspace",
  });

  handle.emitError(new Error("spawn denied"));
  handle.emitClose(0);
  handle.emitStdout("must not be appended");

  assert.deepEqual(await resultPromise, {
    status: "failed",
    errorCode: "EXECUTION_START_FAILED",
    message: "spawn denied",
    stdout: "",
    stderr: "",
  });
});

test("node execution adapter fails closed when exit code is unobservable", async () => {
  const handle = new FakeProcessExecutionHandle();
  const adapter = new NodeProcessExecutionAdapter(() => handle);

  const resultPromise = adapter.execute({
    commandText: "unobservable example",
    cwd: "/workspace",
  });

  handle.emitStdout("partial output");
  handle.emitClose(null);

  assert.deepEqual(await resultPromise, {
    status: "failed",
    errorCode: "EXECUTION_OBSERVATION_FAILED",
    message: "Process closed without an observable exit code.",
    stdout: "partial output",
    stderr: "",
  });
});