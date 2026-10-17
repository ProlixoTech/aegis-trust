import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";

const sourcePath = path.join(__dirname, "..", "src", "vscodePlatformAdapter.ts");

function readAdapterSource(): string {
  return fs.readFileSync(sourcePath, "utf8");
}

test("vscodePlatformAdapter contains the VS Code API boundary invariant", () => {
  const source = readAdapterSource();

  assert.match(source, /export const VSCODE_PLATFORM_ADAPTER_INVARIANT/);
  assert.match(source, /VSCODE_API_CONTAINED_IN_ADAPTER:\s*true/);
  assert.match(source, /PROTECTED_TERMINAL_SENDTEXT_FALSE_CALLER_MUST_PRESERVE:\s*true/);
});

test("vscodePlatformAdapter creates every platform port required by the port contract", () => {
  const source = readAdapterSource();

  assert.match(source, /export function createVscodePlatformPorts\(\): AegisPlatformPorts/);
  assert.match(source, /ui:\s*new VscodeAegisUI\(\)/);
  assert.match(source, /clipboard:\s*new VscodeAegisClipboard\(\)/);
  assert.match(source, /documents:\s*new VscodeAegisDocumentViewer\(\)/);
  assert.match(source, /terminalHost:\s*new VscodeAegisTerminalHost\(\)/);
  assert.match(source, /workspace:\s*new VscodeAegisWorkspace\(\)/);
  assert.match(source, /commands:\s*new VscodeAegisCommandRegistry\(\)/);
});

test("vscodePlatformAdapter preserves explicit terminal sendText addNewLine forwarding", () => {
  const source = readAdapterSource();

  assert.match(source, /sendText\(text: string, addNewLine: boolean\): void/);
  assert.match(source, /this\.terminal\.sendText\(text, addNewLine\)/);
  assert.doesNotMatch(source, /this\.terminal\.sendText\(text,\s*true\)/);
});
