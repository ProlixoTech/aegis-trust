import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { deriveServerRulesetCommandCandidates } from "./serverRulesetCommandNormalization";

const wrapperCases = Object.freeze([
  { caseId: "WRAP-001", input: "sh -c 'rm -rf /*'", normalized: "rm -rf /*" },
  { caseId: "WRAP-002", input: 'bash -c "rm -rf /*"', normalized: "rm -rf /*" },
  { caseId: "WRAP-003", input: "zsh -c 'sudo rm -rf /*'", normalized: "sudo rm -rf /*" },
  { caseId: "WRAP-004", input: "/bin/sh -c 'find / -delete'", normalized: "find / -delete" },
  { caseId: "WRAP-005", input: "env sh -c 'rm -rf ${HOME}'", normalized: "rm -rf ${HOME}" },
  { caseId: "WRAP-006", input: "sudo sh -c 'dd if=/dev/zero of=/dev/disk0'", normalized: "dd if=/dev/zero of=/dev/disk0" },
  { caseId: "WRAP-007", input: 'pwsh -NoProfile -Command "Remove-Item C:\\* -Recurse -Force"', normalized: "Remove-Item C:\\* -Recurse -Force" },
  { caseId: "WRAP-008", input: 'powershell.exe -NoProfile -Command "Clear-Disk -Number 0 -RemoveData"', normalized: "Clear-Disk -Number 0 -RemoveData" },
  { caseId: "WRAP-009", input: "cmd.exe /c rd /s /q C:\\", normalized: "rd /s /q C:\\" },
  { caseId: "WRAP-010", input: "cmd /c del /f /s /q C:\\*", normalized: "del /f /s /q C:\\*" },
  { caseId: "WRAP-011", input: "C:\\Windows\\System32\\cmd.exe /c format C: /y", normalized: "format C: /y" },
  { caseId: "WRAP-012", input: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command Remove-Item C:\\* -Recurse -Force", normalized: "Remove-Item C:\\* -Recurse -Force" },
  { caseId: "WRAP-013", input: "/usr/bin/find / -delete", normalized: "find / -delete" },
  { caseId: "WRAP-014", input: "/bin/dd if=/dev/zero of=/dev/disk0", normalized: "dd if=/dev/zero of=/dev/disk0" },
  { caseId: "WRAP-015", input: "/usr/sbin/diskutil zeroDisk /dev/disk0", normalized: "diskutil zeroDisk /dev/disk0" },
] as const);

const negativeCases = Object.freeze([
  { caseId: "NEG-001", input: "rm -rf ./build", expected: ["rm -rf ./build"] },
  { caseId: "NEG-002", input: "/bin/rm -rf /tmp/aegis-g00a", expected: ["/bin/rm -rf /tmp/aegis-g00a"] },
  { caseId: "NEG-003", input: "sudo rm -rf /var/tmp/aegis-g00a", expected: ["sudo rm -rf /var/tmp/aegis-g00a"] },
  { caseId: "NEG-004", input: "find ./workspace -delete", expected: ["find ./workspace -delete"] },
  { caseId: "NEG-005", input: "dd if=/dev/zero of=./disk.img", expected: ["dd if=/dev/zero of=./disk.img"] },
  { caseId: "NEG-006", input: "diskutil list", expected: ["diskutil list"] },
  { caseId: "NEG-007", input: "Remove-Item .\\dist -Recurse -Force", expected: ["Remove-Item .\\dist -Recurse -Force"] },
  { caseId: "NEG-008", input: "Clear-Disk -Number 1 -RemoveData", expected: ["Clear-Disk -Number 1 -RemoveData"] },
  { caseId: "NEG-009", input: "rd /s /q C:\\temp", expected: ["rd /s /q C:\\temp"] },
  { caseId: "NEG-010", input: "del /f /s /q C:\\temp\\*", expected: ["del /f /s /q C:\\temp\\*"] },
  { caseId: "NEG-011", input: "format D: /y", expected: ["format D: /y"] },
  { caseId: "NEG-012", input: "Get-Content package.json", expected: ["Get-Content package.json"] },
  { caseId: "NEG-013", input: "echo rm -rf /*", expected: ["echo rm -rf /*"] },
  { caseId: "NEG-014", input: 'Write-Output "Remove-Item C:\\* -Recurse -Force"', expected: ['Write-Output "Remove-Item C:\\* -Recurse -Force"'] },
  { caseId: "NEG-015", input: "sh -c 'echo aegis-safe'", expected: ["sh -c 'echo aegis-safe'", "echo aegis-safe"] },
] as const);

test("server ruleset command normalization derives the exact 15 wrapper candidates", () => {
  for (const entry of wrapperCases) {
    const result = deriveServerRulesetCommandCandidates(entry.input);
    assert.equal(result.accepted, true, entry.caseId);
    assert.equal(result.reason, "COMMAND_CANDIDATES_DERIVED", entry.caseId);
    assert.deepEqual(result.candidates, [entry.input, entry.normalized], entry.caseId);
    assert.equal(Object.isFrozen(result), true, entry.caseId);
    assert.equal(Object.isFrozen(result.candidates), true, entry.caseId);
  }
});

test("server ruleset command normalization preserves the exact 15 negative controls", () => {
  for (const entry of negativeCases) {
    const result = deriveServerRulesetCommandCandidates(entry.input);
    assert.equal(result.accepted, true, entry.caseId);
    assert.deepEqual(result.candidates, entry.expected, entry.caseId);
  }
});

test("server ruleset command normalization rejects malformed recognized wrappers", () => {
  for (const input of [
    "sh -c rm -rf /*",
    "bash -c 'unterminated",
    "pwsh -NoProfile -Command",
    "cmd.exe /c",
    "/usr/bin/find",
    "sh -c 'bash -c \\\"zsh -c \\\'rm -rf /*\\\'\\\"'",
  ]) {
    const result = deriveServerRulesetCommandCandidates(input);
    assert.equal(result.accepted, false, input);
    assert.deepEqual(result.candidates, [], input);
    assert.equal(result.reason, "MALFORMED_RECOGNIZED_WRAPPER", input);
  }
});

test("server ruleset command normalization is bounded, deduplicated, and idempotent", () => {
  for (const entry of wrapperCases) {
    const first = deriveServerRulesetCommandCandidates(entry.input);
    assert.ok(first.candidates.length <= 2, entry.caseId);
    assert.equal(new Set(first.candidates).size, first.candidates.length, entry.caseId);

    const second = deriveServerRulesetCommandCandidates(entry.normalized);
    assert.equal(second.accepted, true, entry.caseId);
    assert.deepEqual(second.candidates, [entry.normalized], entry.caseId);
  }
});

test("server ruleset command normalization source has no execution or I/O imports", () => {
  const source = readFileSync(
    join(process.cwd(), "src", "serverRulesetCommandNormalization.ts"),
    "utf8"
  );

  for (const forbidden of [
    "node:child_process",
    "node:fs",
    "node:net",
    "node:http",
    "node:https",
    "node:dgram",
    "node:worker_threads",
    "eval(",
    "Function(",
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
});
