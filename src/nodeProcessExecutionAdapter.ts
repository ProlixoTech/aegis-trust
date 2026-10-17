// src/nodeProcessExecutionAdapter.ts
// Detached Node process adapter for the result-observable execution port.
// This adapter is not connected to AegisPlatformPorts or extension runtime.

import { spawn } from "node:child_process";

import type {
  AegisExecutionPort,
  AegisExecutionRequest,
  AegisExecutionResult,
} from "../packages/aegis-core";

export interface NodeProcessExecutionHandle {
  onStdout(listener: (chunk: unknown) => void): void;
  onStderr(listener: (chunk: unknown) => void): void;
  onError(listener: (error: Error) => void): void;
  onClose(listener: (exitCode: number | null) => void): void;
}

export type NodeProcessSpawner = (
  request: AegisExecutionRequest
) => NodeProcessExecutionHandle;

function chunkToUtf8(chunk: unknown): string {
  if (typeof chunk === "string") {
    return chunk;
  }

  if (Buffer.isBuffer(chunk)) {
    return chunk.toString("utf8");
  }

  if (chunk === null || chunk === undefined) {
    return "";
  }

  return String(chunk);
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }

  return "Unknown process execution failure.";
}

export function spawnNodeProcess(
  request: AegisExecutionRequest
): NodeProcessExecutionHandle {
  const child = spawn(request.commandText, {
    cwd: request.cwd,
    shell: true,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });

  return {
    onStdout(listener): void {
      child.stdout.on("data", listener);
    },

    onStderr(listener): void {
      child.stderr.on("data", listener);
    },

    onError(listener): void {
      child.once("error", listener);
    },

    onClose(listener): void {
      child.once("close", (exitCode) => {
        listener(exitCode);
      });
    },
  };
}

export class NodeProcessExecutionAdapter implements AegisExecutionPort {
  constructor(
    private readonly spawnProcess: NodeProcessSpawner = spawnNodeProcess
  ) {}

  execute(
    request: AegisExecutionRequest
  ): Promise<AegisExecutionResult> {
    return new Promise((resolve) => {
      let stdout = "";
      let stderr = "";
      let settled = false;

      const finish = (result: AegisExecutionResult): void => {
        if (settled) {
          return;
        }

        settled = true;
        resolve(result);
      };

      let processHandle: NodeProcessExecutionHandle;

      try {
        processHandle = this.spawnProcess(request);
      } catch (error) {
        finish({
          status: "failed",
          errorCode: "EXECUTION_START_FAILED",
          message: errorMessage(error),
          stdout,
          stderr,
        });
        return;
      }

      try {
        processHandle.onStdout((chunk) => {
          if (!settled) {
            stdout += chunkToUtf8(chunk);
          }
        });

        processHandle.onStderr((chunk) => {
          if (!settled) {
            stderr += chunkToUtf8(chunk);
          }
        });

        processHandle.onError((error) => {
          finish({
            status: "failed",
            errorCode: "EXECUTION_START_FAILED",
            message: errorMessage(error),
            stdout,
            stderr,
          });
        });

        processHandle.onClose((exitCode) => {
          if (exitCode === null) {
            finish({
              status: "failed",
              errorCode: "EXECUTION_OBSERVATION_FAILED",
              message: "Process closed without an observable exit code.",
              stdout,
              stderr,
            });
            return;
          }

          finish({
            status: "completed",
            exitCode,
            stdout,
            stderr,
          });
        });
      } catch (error) {
        finish({
          status: "failed",
          errorCode: "EXECUTION_OBSERVATION_FAILED",
          message: errorMessage(error),
          stdout,
          stderr,
        });
      }
    });
  }
}

export const NODE_PROCESS_EXECUTION_ADAPTER_INVARIANT = {
  DETACHED_FROM_AEGIS_PLATFORM_PORTS: true,
  DETACHED_FROM_EXTENSION_RUNTIME: true,
  DETACHED_FROM_PROTECTED_TERMINAL: true,
  RESULT_SETTLED_EXACTLY_ONCE: true,
} as const;