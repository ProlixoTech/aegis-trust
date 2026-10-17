// src/platformPorts.ts
// Platform-neutral ports for Prolixo Aegis. This file must not import vscode.

export interface AegisDisposable { dispose(): void }

export interface AegisUI {
  showWarning(message: string): Promise<void>;
  showInfo(message: string): Promise<void>;
  showError(message: string): Promise<void>;
  showInputBox(options?: { prompt?: string; placeHolder?: string; value?: string }): Promise<string | undefined>;
  showQuickPick(items: string[], options?: { placeHolder?: string }): Promise<string | undefined>;
}

export interface AegisClipboard {
  readText(): Promise<string>;
  writeText(text: string): Promise<void>;
}

export interface AegisDocumentViewer {
  showTextDocument(content: string, language?: string, preview?: boolean): Promise<void>;
  openFile(path: string, preview?: boolean): Promise<void>;
}

export interface AegisTerminal {
  sendText(text: string, addNewLine: boolean): void;
  show(): void;
}

export interface AegisTerminalHost {
  createDedicatedTerminal(name: string): AegisTerminal;
}

/**
 * Result-observable execution contract only.
 *
 * This port is intentionally not part of AegisPlatformPorts until a separate
 * adapter and protected execution path are explicitly approved and verified.
 * The existing Protected Terminal remains user-visible insert-only.
 */
export interface AegisExecutionRequest {
  commandText: string;
  cwd: string;
}

export type AegisExecutionResult =
  | {
      status: "completed";
      exitCode: number;
      stdout: string;
      stderr: string;
    }
  | {
      status: "failed";
      errorCode:
        | "EXECUTION_START_FAILED"
        | "EXECUTION_OBSERVATION_FAILED";
      message: string;
      stdout: string;
      stderr: string;
      exitCode?: number;
    };

export interface AegisExecutionPort {
  execute(request: AegisExecutionRequest): Promise<AegisExecutionResult>;
}
export interface AegisWorkspace {
  getWorkspaceRoot(): string | undefined;
}

export interface AegisCommandRegistry {
  registerCommand(commandId: string, handler: (...args: unknown[]) => unknown): AegisDisposable;
  executeCommand(commandId: string, ...args: unknown[]): Promise<unknown>;
}

export interface AegisPlatformPorts {
  ui: AegisUI;
  clipboard: AegisClipboard;
  documents: AegisDocumentViewer;
  terminalHost: AegisTerminalHost;
  workspace: AegisWorkspace;
  commands: AegisCommandRegistry;
}

export const PLATFORM_PORTS_INVARIANT = {
  AEGIS_CORE_MUST_NOT_IMPORT_VSCODE: true,
  VSCODE_API_DIRECT_USE_LIMITED_TO_ADAPTER: true,
  PROTECTED_TERMINAL_SENDTEXT_FALSE_INVARIANT_REQUIRED: true,
} as const;
