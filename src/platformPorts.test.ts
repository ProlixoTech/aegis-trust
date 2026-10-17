import test from "node:test";
import assert from "node:assert/strict";

import {
  PLATFORM_PORTS_INVARIANT,
  type AegisDisposable,
  type AegisExecutionPort,
  type AegisExecutionResult,
  type AegisPlatformPorts,
} from "./platformPorts";

test("platformPorts exposes core boundary invariants as true", () => {
  assert.equal(PLATFORM_PORTS_INVARIANT.AEGIS_CORE_MUST_NOT_IMPORT_VSCODE, true);
  assert.equal(PLATFORM_PORTS_INVARIANT.VSCODE_API_DIRECT_USE_LIMITED_TO_ADAPTER, true);
  assert.equal(PLATFORM_PORTS_INVARIANT.PROTECTED_TERMINAL_SENDTEXT_FALSE_INVARIANT_REQUIRED, true);
});

test("platformPorts interface contract supports injected UI, clipboard, workspace, terminal, documents, and commands", async () => {
  const events: string[] = [];
  let clipboardText = "initial";
  let disposed = false;

  const disposable: AegisDisposable = {
    dispose: () => {
      disposed = true;
      events.push("disposed");
    },
  };

  const ports: AegisPlatformPorts = {
    ui: {
      showWarning: async (message) => {
        events.push(`warning:${message}`);
      },
      showInfo: async (message) => {
        events.push(`info:${message}`);
      },
      showError: async (message) => {
        events.push(`error:${message}`);
      },
      showInputBox: async (options) => options?.value,
      showQuickPick: async (items) => items[0],
    },
    clipboard: {
      readText: async () => clipboardText,
      writeText: async (text) => {
        clipboardText = text;
      },
    },
    documents: {
      showTextDocument: async (content, language, preview) => {
        events.push(`doc:${content}:${language}:${preview}`);
      },
      openFile: async (path, preview) => {
        events.push(`file:${path}:${preview}`);
      },
    },
    terminalHost: {
      createDedicatedTerminal: (name) => ({
        sendText: (text, addNewLine) => {
          events.push(`terminal:${name}:${text}:${addNewLine}`);
        },
        show: () => {
          events.push(`terminal-show:${name}`);
        },
      }),
    },
    workspace: {
      getWorkspaceRoot: () => "C:\\workspace",
    },
    commands: {
      registerCommand: (commandId, handler) => {
        events.push(`register:${commandId}`);
        handler("payload");
        return disposable;
      },
      executeCommand: async (commandId, ...args) => ({ commandId, args }),
    },
  };

  await ports.ui.showWarning("careful");
  await ports.ui.showInfo("ready");
  await ports.ui.showError("blocked");
  assert.equal(await ports.ui.showInputBox({ value: "typed" }), "typed");
  assert.equal(await ports.ui.showQuickPick(["one", "two"]), "one");

  await ports.clipboard.writeText("updated");
  assert.equal(await ports.clipboard.readText(), "updated");

  await ports.documents.showTextDocument("body", "plaintext", true);
  await ports.documents.openFile("C:\\workspace\\.env", false);

  const terminal = ports.terminalHost.createDedicatedTerminal("Aegis");
  terminal.sendText("echo safe", false);
  terminal.show();

  assert.equal(ports.workspace.getWorkspaceRoot(), "C:\\workspace");

  const registered = ports.commands.registerCommand("aegis.safe", (payload) => {
    events.push(`handler:${String(payload)}`);
  });
  registered.dispose();

  assert.deepEqual(await ports.commands.executeCommand("aegis.safe", 1, "two"), {
    commandId: "aegis.safe",
    args: [1, "two"],
  });

  assert.equal(disposed, true);
  assert.deepEqual(events, [
    "warning:careful",
    "info:ready",
    "error:blocked",
    "doc:body:plaintext:true",
    "file:C:\\workspace\\.env:false",
    "terminal:Aegis:echo safe:false",
    "terminal-show:Aegis",
    "register:aegis.safe",
    "handler:payload",
    "disposed",
  ]);
});

test("platformPorts terminal contract preserves explicit addNewLine false", () => {
  const sent: Array<{ text: string; addNewLine: boolean }> = [];

  const ports: Pick<AegisPlatformPorts, "terminalHost"> = {
    terminalHost: {
      createDedicatedTerminal: () => ({
        sendText: (text, addNewLine) => {
          sent.push({ text, addNewLine });
        },
        show: () => undefined,
      }),
    },
  };

  const terminal = ports.terminalHost.createDedicatedTerminal("Protected");
  terminal.sendText("do-not-auto-enter", false);

  assert.deepEqual(sent, [{ text: "do-not-auto-enter", addNewLine: false }]);
});
test("platformPorts result-observable execution contract distinguishes completion from observation failure", async () => {
  const requests: Array<{ commandText: string; cwd: string }> = [];
  const queuedResults: AegisExecutionResult[] = [
    {
      status: "completed",
      exitCode: 0,
      stdout: "verified output",
      stderr: "",
    },
    {
      status: "failed",
      errorCode: "EXECUTION_OBSERVATION_FAILED",
      message: "process result could not be observed",
      stdout: "",
      stderr: "",
    },
  ];

  const executionPort: AegisExecutionPort = {
    execute: async (request) => {
      requests.push(request);
      const result = queuedResults.shift();

      if (!result) {
        throw new Error("MISSING_EXECUTION_TEST_RESULT");
      }

      return result;
    },
  };

  const completed = await executionPort.execute({
    commandText: "printf verified",
    cwd: "/workspace",
  });

  if (completed.status !== "completed") {
    throw new Error("EXPECTED_COMPLETED_EXECUTION_RESULT");
  }

  assert.equal(completed.exitCode, 0);
  assert.equal(completed.stdout, "verified output");
  assert.equal(completed.stderr, "");

  const failed = await executionPort.execute({
    commandText: "printf unobservable",
    cwd: "/workspace",
  });

  if (failed.status !== "failed") {
    throw new Error("EXPECTED_FAILED_EXECUTION_RESULT");
  }

  assert.equal(failed.errorCode, "EXECUTION_OBSERVATION_FAILED");
  assert.equal(failed.message, "process result could not be observed");
  assert.equal(failed.stdout, "");
  assert.equal(failed.stderr, "");

  assert.deepEqual(requests, [
    {
      commandText: "printf verified",
      cwd: "/workspace",
    },
    {
      commandText: "printf unobservable",
      cwd: "/workspace",
    },
  ]);
});
