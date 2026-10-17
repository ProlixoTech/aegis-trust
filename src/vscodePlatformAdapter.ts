// src/vscodePlatformAdapter.ts
// VS Code implementation of platform-neutral Aegis ports.
import * as vscode from "vscode";
import { AegisCommandRegistry, AegisDocumentViewer, AegisPlatformPorts, AegisTerminal, AegisTerminalHost, AegisUI, AegisWorkspace } from "../packages/aegis-core";

class VscodeAegisUI implements AegisUI {
  async showWarning(message: string): Promise<void> { await vscode.window.showWarningMessage(message); }
  async showInfo(message: string): Promise<void> { await vscode.window.showInformationMessage(message); }
  async showError(message: string): Promise<void> { await vscode.window.showErrorMessage(message); }
  async showInputBox(options?: { prompt?: string; placeHolder?: string; value?: string }): Promise<string | undefined> { return vscode.window.showInputBox(options); }
  async showQuickPick(items: string[], options?: { placeHolder?: string }): Promise<string | undefined> { return vscode.window.showQuickPick(items, options); }
}

class VscodeAegisClipboard {
  async readText(): Promise<string> { return vscode.env.clipboard.readText(); }
  async writeText(text: string): Promise<void> { await vscode.env.clipboard.writeText(text); }
}

class VscodeAegisDocumentViewer implements AegisDocumentViewer {
  async showTextDocument(content: string, language = "markdown", preview = false): Promise<void> {
    const doc = await vscode.workspace.openTextDocument({ content, language });
    await vscode.window.showTextDocument(doc, { preview });
  }
  async openFile(path: string, preview = true): Promise<void> {
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(path));
    await vscode.window.showTextDocument(doc, { preview });
  }
}

class VscodeAegisTerminal implements AegisTerminal {
  constructor(private readonly terminal: vscode.Terminal) {}
  sendText(text: string, addNewLine: boolean): void { this.terminal.sendText(text, addNewLine); }
  show(): void { this.terminal.show(); }
}

class VscodeAegisTerminalHost implements AegisTerminalHost {
  createDedicatedTerminal(name: string): AegisTerminal {
    return new VscodeAegisTerminal(vscode.window.createTerminal(name));
  }
}

class VscodeAegisWorkspace implements AegisWorkspace {
  getWorkspaceRoot(): string | undefined {
    return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  }
}

class VscodeAegisCommandRegistry implements AegisCommandRegistry {
  registerCommand(commandId: string, handler: (...args: unknown[]) => unknown): vscode.Disposable {
    return vscode.commands.registerCommand(commandId, handler);
  }
  async executeCommand(commandId: string, ...args: unknown[]): Promise<unknown> {
    return vscode.commands.executeCommand(commandId, ...args);
  }
}

export function createVscodePlatformPorts(): AegisPlatformPorts {
  return {
    ui: new VscodeAegisUI(),
    clipboard: new VscodeAegisClipboard(),
    documents: new VscodeAegisDocumentViewer(),
    terminalHost: new VscodeAegisTerminalHost(),
    workspace: new VscodeAegisWorkspace(),
    commands: new VscodeAegisCommandRegistry(),
  };
}

export const VSCODE_PLATFORM_ADAPTER_INVARIANT = {
  VSCODE_API_CONTAINED_IN_ADAPTER: true,
  PROTECTED_TERMINAL_SENDTEXT_FALSE_CALLER_MUST_PRESERVE: true,
} as const;
