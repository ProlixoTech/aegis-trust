import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  SAFETY_KERNEL_V31_EVIDENCE_WRITER_INVARIANT,
  SafetyKernelV31EvidenceIntegrityReport,
  SafetyKernelV31EvidenceWriter,
} from "./safetyKernelV31EvidenceWriter";

import type {
  SafetyKernelV31KernelDecisionResult,
  SafetyKernelV31WarnTerminalEvidence,
} from "./types";

// @ts-expect-error successful integrity report cannot include an issue code
const invalidSuccessfulIntegrityReport: SafetyKernelV31EvidenceIntegrityReport = { ok: true, ledgerExists: true, ledgerPath: "/evidence.jsonl", eventCount: 1, headHash: "head", issueCode: "CHAIN_HASH_MISMATCH", issueLineNumber: 1 };
// @ts-expect-error missing-ledger success must have zero events
const invalidMissingLedgerSuccess: SafetyKernelV31EvidenceIntegrityReport = { ok: true, ledgerExists: false, ledgerPath: "/evidence.jsonl", eventCount: 1, headHash: "head" };
// @ts-expect-error integrity failure with an existing ledger requires a line number
const invalidIntegrityFailure: SafetyKernelV31EvidenceIntegrityReport = { ok: false, ledgerExists: true, ledgerPath: "/evidence.jsonl", eventCount: 0, headHash: "head", issueCode: "MALFORMED_EVENT" };
// @ts-expect-error read failure cannot claim that the ledger exists
const invalidReadFailure: SafetyKernelV31EvidenceIntegrityReport = { ok: false, ledgerExists: true, ledgerPath: "/evidence.jsonl", eventCount: 0, headHash: "head", issueCode: "READ_FAILED" };
void invalidSuccessfulIntegrityReport;
void invalidMissingLedgerSuccess;
void invalidIntegrityFailure;
void invalidReadFailure;

function makeTempAegisDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "aegis-safety-kernel-evidence-"));
}

function removeTempAegisDir(aegisDir: string): void {
  fs.rmSync(aegisDir, { recursive: true, force: true });
}

function makeDecision(
  actionId: string,
  nonce: string,
  decision: SafetyKernelV31KernelDecisionResult["decision"] = "ALLOW"
): SafetyKernelV31KernelDecisionResult {
  return {
    action_id: actionId,
    decision,
    approval_nonce: nonce,
    policy_version: "policy-test",
    reasons: ["reason-one"],
    human_readable_summary: "Evidence writer test",
    receipt_required: true,
    ledger_required: true,
  };
}

function makeWarnTerminal(
  actionId: string,
  nonce: string
): SafetyKernelV31WarnTerminalEvidence {
  return {
    action_id: actionId,
    approval_nonce: nonce,
    reason: "cancel_by_user",
    nonce_consumed: true,
    return_state: "IDLE",
    receipt_required: true,
    ledger_required: true,
    warn_must_never_auto_proceed: true,
  };
}

function readEvents(aegisDir: string): Array<Record<string, unknown>> {
  const ledgerPath = path.join(aegisDir, "safety-kernel-v31", "evidence.jsonl");
  return fs.readFileSync(ledgerPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

test("evidence writer invariant keeps runtime and protected-file ledger disconnected", () => {
  assert.equal(SAFETY_KERNEL_V31_EVIDENCE_WRITER_INVARIANT.RUNTIME_CONNECTED, false);
  assert.equal(SAFETY_KERNEL_V31_EVIDENCE_WRITER_INVARIANT.PROTECTED_FILE_LEDGER_REUSED, false);
  assert.equal(SAFETY_KERNEL_V31_EVIDENCE_WRITER_INVARIANT.RAW_APPROVAL_NONCE_STORED, false);
  assert.equal(SAFETY_KERNEL_V31_EVIDENCE_WRITER_INVARIANT.RECEIPT_AND_LEDGER_REQUIRED, true);
  assert.equal(SAFETY_KERNEL_V31_EVIDENCE_WRITER_INVARIANT.APPEND_ONLY_HASH_CHAIN, true);
});

test("appendDecision writes a chained ledger event and receipt without raw nonce", async () => {
  const aegisDir = makeTempAegisDir();
  const nonce = "nonce-secret-decision";

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    const result = await writer.appendDecision(
      makeDecision("ACTION_DECISION", nonce),
      "2026-01-01T00:00:00.000Z"
    );

    assert.equal(result.ok, true);
    assert.equal(result.reason, "success");
    assert.ok(result.ledgerPath);
    assert.ok(result.receiptPath);
    assert.equal(fs.existsSync(result.ledgerPath), true);
    assert.equal(fs.existsSync(result.receiptPath), true);

    const ledgerText = fs.readFileSync(result.ledgerPath, "utf8");
    const receiptText = fs.readFileSync(result.receiptPath, "utf8");
    assert.equal(ledgerText.includes(nonce), false);
    assert.equal(receiptText.includes(nonce), false);

    const events = readEvents(aegisDir);
    assert.equal(events.length, 1);
    assert.equal(events[0].eventType, "kernel_decision");
    assert.equal(events[0].actionId, "ACTION_DECISION");
    assert.equal(events[0].decision, "ALLOW");
    assert.equal(events[0].evidenceChainVersion, 1);
    assert.equal(events[0].evidenceSequence, 1);
    assert.equal(events[0].evidencePrevHash, "GENESIS");
    assert.equal(typeof events[0].approvalNonceSha256, "string");
    assert.equal((events[0].approvalNonceSha256 as string).length, 64);
    assert.equal(typeof events[0].evidenceEventHash, "string");
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("allowed execution completion evidence appends a nonce-safe verifiable event", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    const nonce = "nonce-allowed-completion";
    const result = await writer.appendAllowedExecutionCompletion(
      {
        action_id: "ACTION_ALLOWED_COMPLETION",
        approval_nonce: nonce,
        nonce_consumed: true,
        receipt_required: true,
        ledger_required: true,
      },
      "2026-01-01T00:02:00.000Z"
    );

    assert.equal(result.ok, true);
    const events = readEvents(aegisDir);
    assert.equal(events.length, 1);
    assert.equal(events[0].eventType, "allowed_execution_completed");
    assert.equal(events[0].nonceStateAfterEvidence, "CONSUMED");
    assert.equal(events[0].nonceConsumed, true);
    assert.equal(events[0].receiptRequired, true);
    assert.equal(events[0].ledgerRequired, true);
    assert.equal(JSON.stringify(events[0]).includes(nonce), false);
    assert.equal(typeof events[0].approvalNonceSha256, "string");

    const report = await writer.verifyIntegrity();
    assert.equal(report.ok, true);
    assert.equal(report.eventCount, 1);
    assert.equal(report.headHash, events[0].evidenceEventHash);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("WARN confirmation evidence appends a nonce-safe verifiable event and receipt", async () => {
  const aegisDir = makeTempAegisDir();
  const nonce = "nonce-warn-confirmation";

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    const result = await writer.appendWarnConfirmation(
      {
        action_id: "ACTION_WARN_CONFIRMATION",
        approval_nonce: nonce,
        nonce_consumed: false,
        next_state: "ALLOW_PENDING_EXECUTION",
        receipt_required: true,
        ledger_required: true,
        execution_authority_granted: false,
      },
      "2026-01-01T00:01:00.000Z"
    );

    assert.equal(result.ok, true);
    assert.ok(result.ledgerPath);
    assert.ok(result.receiptPath);

    const ledgerText = fs.readFileSync(result.ledgerPath, "utf8");
    const receiptText = fs.readFileSync(result.receiptPath, "utf8");
    assert.equal(ledgerText.includes(nonce), false);
    assert.equal(receiptText.includes(nonce), false);
    assert.equal(receiptText.includes("- WARN confirmed: true"), true);
    assert.equal(receiptText.includes("- Execution authority granted: false"), true);

    const events = readEvents(aegisDir);
    assert.equal(events.length, 1);
    assert.equal(events[0].eventType, "warn_confirmed");
    assert.equal(events[0].actionId, "ACTION_WARN_CONFIRMATION");
    assert.equal(events[0].nonceStateAfterEvidence, "ALLOW_PENDING_EXECUTION");
    assert.equal(events[0].warnConfirmed, true);
    assert.equal(events[0].executionAuthorityGranted, false);
    assert.equal(events[0].evidenceSequence, 1);
    assert.equal(events[0].evidencePrevHash, "GENESIS");
    assert.equal(typeof events[0].approvalNonceSha256, "string");
    assert.equal(typeof events[0].evidenceEventHash, "string");

    const report = await writer.verifyIntegrity();
    assert.equal(report.ok, true);
    assert.equal(report.eventCount, 1);
    assert.equal(report.headHash, events[0].evidenceEventHash);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("decision and WARN terminal evidence append into one verifiable chain", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    assert.equal(
      (await writer.appendDecision(
        makeDecision("ACTION_WARN", "nonce-warn", "WARN"),
        "2026-01-01T00:00:00.000Z"
      )).ok,
      true
    );
    assert.equal(
      (await writer.appendWarnTerminal(
        makeWarnTerminal("ACTION_WARN", "nonce-warn"),
        "2026-01-01T00:01:00.000Z"
      )).ok,
      true
    );

    const events = readEvents(aegisDir);
    assert.equal(events.length, 2);
    assert.equal(events[0].evidenceSequence, 1);
    assert.equal(events[1].evidenceSequence, 2);
    assert.equal(events[1].evidencePrevHash, events[0].evidenceEventHash);
    assert.equal(events[1].eventType, "warn_terminal");
    assert.equal(events[1].warnReason, "cancel_by_user");
    assert.equal(events[1].nonceConsumed, true);
    assert.equal(events[1].returnState, "IDLE");
    assert.equal(events[1].warnMustNeverAutoProceed, true);

    const report = await writer.verifyIntegrity();
    assert.equal(report.ok, true);
    assert.equal(report.ledgerExists, true);
    assert.equal(report.eventCount, 2);
    assert.equal(report.headHash, events[1].evidenceEventHash);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("verifyIntegrity detects tampered evidence", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    assert.equal(
      (await writer.appendDecision(
        makeDecision("ACTION_TAMPER", "nonce-tamper"),
        "2026-01-01T00:00:00.000Z"
      )).ok,
      true
    );

    const ledgerPath = path.join(aegisDir, "safety-kernel-v31", "evidence.jsonl");
    const events = readEvents(aegisDir);
    events[0].actionId = "ACTION_CHANGED";
    fs.writeFileSync(ledgerPath, `${JSON.stringify(events[0])}\n`, "utf8");

    const report = await writer.verifyIntegrity();
    assert.equal(report.ok, false);
    assert.equal(report.ledgerExists, true);
    assert.equal(report.issueCode, "CHAIN_HASH_MISMATCH");
    assert.equal(report.issueLineNumber, 1);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("verifyIntegrity detects an evidence sequence mismatch", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    assert.equal((await writer.appendDecision(makeDecision("ACTION_SEQUENCE_1", "nonce-sequence-1"), "2026-01-01T00:00:00.000Z")).ok, true);
    assert.equal((await writer.appendDecision(makeDecision("ACTION_SEQUENCE_2", "nonce-sequence-2"), "2026-01-01T00:01:00.000Z")).ok, true);

    const ledgerPath = path.join(aegisDir, "safety-kernel-v31", "evidence.jsonl");
    const events = readEvents(aegisDir);
    events[1].evidenceSequence = 9;
    fs.writeFileSync(ledgerPath, `${events.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");

    const report = await writer.verifyIntegrity();
    assert.equal(report.ok, false);
    assert.equal(report.issueCode, "CHAIN_SEQUENCE_MISMATCH");
    assert.equal(report.issueLineNumber, 2);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("verifyIntegrity detects an evidence previous-hash mismatch", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    assert.equal((await writer.appendDecision(makeDecision("ACTION_PREV_HASH_1", "nonce-prev-hash-1"), "2026-01-01T00:00:00.000Z")).ok, true);
    assert.equal((await writer.appendDecision(makeDecision("ACTION_PREV_HASH_2", "nonce-prev-hash-2"), "2026-01-01T00:01:00.000Z")).ok, true);

    const ledgerPath = path.join(aegisDir, "safety-kernel-v31", "evidence.jsonl");
    const events = readEvents(aegisDir);
    events[1].evidencePrevHash = "0".repeat(64);
    fs.writeFileSync(ledgerPath, `${events.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");

    const report = await writer.verifyIntegrity();
    assert.equal(report.ok, false);
    assert.equal(report.issueCode, "CHAIN_PREV_HASH_MISMATCH");
    assert.equal(report.issueLineNumber, 2);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("invalid evidence input is rejected without writing files", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    const invalid = makeDecision("", "nonce-invalid");
    const result = await writer.appendDecision(invalid);

    assert.deepEqual(result, {
      ok: false,
      ledgerPath: null,
      receiptPath: null,
      reason: "invalid_input",
    });
    assert.equal(
      fs.existsSync(path.join(aegisDir, "safety-kernel-v31", "evidence.jsonl")),
      false
    );
  } finally {
    removeTempAegisDir(aegisDir);
  }
});


test("remaining evidence writer error contracts are handled directly", async () => {
  const dirs = Array.from({ length: 7 }, () => makeTempAegisDir());
  const invalidResult = { ok: false, ledgerPath: null, receiptPath: null, reason: "invalid_input" };

  try {
    const warnConfirmationWriter = new SafetyKernelV31EvidenceWriter(dirs[0]);
    assert.deepEqual(
      await warnConfirmationWriter.appendWarnConfirmation(
        { action_id: "", approval_nonce: "nonce-invalid" } as Parameters<SafetyKernelV31EvidenceWriter["appendWarnConfirmation"]>[0]
      ),
      invalidResult
    );

    const completionWriter = new SafetyKernelV31EvidenceWriter(dirs[1]);
    assert.deepEqual(
      await completionWriter.appendAllowedExecutionCompletion(
        { action_id: "", approval_nonce: "nonce-invalid" } as Parameters<SafetyKernelV31EvidenceWriter["appendAllowedExecutionCompletion"]>[0]
      ),
      invalidResult
    );

    const terminalWriter = new SafetyKernelV31EvidenceWriter(dirs[2]);
    assert.deepEqual(
      await terminalWriter.appendWarnTerminal(
        { action_id: "", approval_nonce: "nonce-invalid" } as Parameters<SafetyKernelV31EvidenceWriter["appendWarnTerminal"]>[0]
      ),
      invalidResult
    );

    const malformedJsonDir = path.join(dirs[3], "safety-kernel-v31");
    fs.mkdirSync(malformedJsonDir, { recursive: true });
    fs.writeFileSync(path.join(malformedJsonDir, "evidence.jsonl"), "{not-json}\n", "utf8");
    const malformedJsonReport = await new SafetyKernelV31EvidenceWriter(dirs[3]).verifyIntegrity();
    assert.equal(malformedJsonReport.ok, false);
    assert.equal(malformedJsonReport.issueCode, "MALFORMED_EVENT");
    assert.equal(malformedJsonReport.issueLineNumber, 1);

    const malformedRecordDir = path.join(dirs[4], "safety-kernel-v31");
    fs.mkdirSync(malformedRecordDir, { recursive: true });
    fs.writeFileSync(path.join(malformedRecordDir, "evidence.jsonl"), "{}\n", "utf8");
    const malformedRecordReport = await new SafetyKernelV31EvidenceWriter(dirs[4]).verifyIntegrity();
    assert.equal(malformedRecordReport.ok, false);
    assert.equal(malformedRecordReport.issueCode, "MALFORMED_EVENT");
    assert.equal(malformedRecordReport.issueLineNumber, 1);

    const missingLedgerReport = await new SafetyKernelV31EvidenceWriter(dirs[5]).verifyIntegrity();
    assert.equal(missingLedgerReport.ok, true);
    assert.equal(missingLedgerReport.ledgerExists, false);
    assert.equal(missingLedgerReport.eventCount, 0);

    fs.mkdirSync(path.join(dirs[6], "safety-kernel-v31", "evidence.jsonl"), { recursive: true });
    const readFailedReport = await new SafetyKernelV31EvidenceWriter(dirs[6]).verifyIntegrity();
    assert.equal(readFailedReport.ok, false);
    assert.equal(readFailedReport.ledgerExists, false);
    assert.equal(readFailedReport.issueCode, "READ_FAILED");
  } finally {
    for (const dir of dirs) removeTempAegisDir(dir);
  }
});


test("evidence writer returns write_failed when the existing ledger cannot be read", async () => {
  const aegisDir = makeTempAegisDir();
  try {
    fs.mkdirSync(path.join(aegisDir, "safety-kernel-v31", "evidence.jsonl"), { recursive: true });
    const result = await new SafetyKernelV31EvidenceWriter(aegisDir).appendDecision(
      makeDecision("ACTION_WRITE_FAILED", "nonce-write-failed"),
      "2026-01-01T00:00:00.000Z"
    );
    assert.deepEqual(result, { ok: false, ledgerPath: null, receiptPath: null, reason: "write_failed" });
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("evidence writer rejects extending a ledger with a malformed final line", async () => {
  const aegisDir = makeTempAegisDir();
  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    assert.equal((await writer.appendDecision(makeDecision("ACTION_VALID_HEAD_1", "nonce-valid-head-1"), "2026-01-01T00:00:00.000Z")).ok, true);
    const ledgerPath = path.join(aegisDir, "safety-kernel-v31", "evidence.jsonl");
    fs.appendFileSync(ledgerPath, "{not-json}\n", "utf8");
    const before = fs.readFileSync(ledgerPath, "utf8");

    const result = await writer.appendDecision(
      makeDecision("ACTION_REJECT_MALFORMED_HEAD", "nonce-reject-malformed-head"),
      "2026-01-01T00:01:00.000Z"
    );

    assert.deepEqual(result, {
      ok: false,
      ledgerPath: null,
      receiptPath: null,
      reason: "write_failed",
    });
    assert.equal(fs.readFileSync(ledgerPath, "utf8"), before);

    const report = await writer.verifyIntegrity();
    assert.equal(report.ok, false);
    assert.equal(report.issueCode, "MALFORMED_EVENT");
    assert.equal(report.issueLineNumber, 2);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("evidence writer handles unknown error shapes without throwing", async () => {
  const dirs = [makeTempAegisDir(), makeTempAegisDir(), makeTempAegisDir(), makeTempAegisDir()];
  const promises = fs.promises as unknown as {
    readFile: typeof fs.promises.readFile;
    mkdir: typeof fs.promises.mkdir;
  };
  const originalReadFile = promises.readFile;
  const originalMkdir = promises.mkdir;
  const originalConsoleError = console.error;
  const logged: unknown[][] = [];

  try {
    console.error = (...args: unknown[]) => {
      logged.push(args);
    };

    promises.readFile = (async () => {
      throw null;
    }) as typeof fs.promises.readFile;
    const nullReadReport = await new SafetyKernelV31EvidenceWriter(dirs[0]).verifyIntegrity();
    assert.equal(nullReadReport.ok, false);
    assert.equal(nullReadReport.ledgerExists, false);
    assert.equal(nullReadReport.issueCode, "READ_FAILED");

    promises.readFile = (async () => {
      throw { code: 5 };
    }) as typeof fs.promises.readFile;
    const nonStringCodeReport = await new SafetyKernelV31EvidenceWriter(dirs[1]).verifyIntegrity();
    assert.equal(nonStringCodeReport.ok, false);
    assert.equal(nonStringCodeReport.ledgerExists, false);
    assert.equal(nonStringCodeReport.issueCode, "READ_FAILED");

    promises.readFile = originalReadFile;
    promises.mkdir = (async () => {
      throw null;
    }) as typeof fs.promises.mkdir;
    const nullWriteResult = await new SafetyKernelV31EvidenceWriter(dirs[2]).appendDecision(
      makeDecision("ACTION_NULL_ERROR", "nonce-null-error")
    );
    assert.deepEqual(nullWriteResult, {
      ok: false,
      ledgerPath: null,
      receiptPath: null,
      reason: "write_failed",
    });

    promises.mkdir = (async () => {
      throw { message: 42 };
    }) as typeof fs.promises.mkdir;
    const nonStringMessageResult = await new SafetyKernelV31EvidenceWriter(dirs[3]).appendDecision(
      makeDecision("ACTION_NON_STRING_MESSAGE", "nonce-non-string-message")
    );
    assert.deepEqual(nonStringMessageResult, {
      ok: false,
      ledgerPath: null,
      receiptPath: null,
      reason: "write_failed",
    });
    assert.equal(logged.length, 2);
    assert.equal(logged[0][1], undefined);
    assert.equal(logged[1][1], 42);
  } finally {
    promises.readFile = originalReadFile;
    promises.mkdir = originalMkdir;
    console.error = originalConsoleError;
    for (const dir of dirs) removeTempAegisDir(dir);
  }
});

test("verifyIntegrity rejects a non-numeric evidence sequence as malformed", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    assert.equal(
      (await writer.appendDecision(
        makeDecision("ACTION_SEQUENCE_TYPE", "nonce-sequence-type"),
        "2026-01-01T00:00:00.000Z"
      )).ok,
      true
    );

    const ledgerPath = path.join(aegisDir, "safety-kernel-v31", "evidence.jsonl");
    const events = readEvents(aegisDir);
    Object.assign(events[0] as object, { evidenceSequence: "1" });
    fs.writeFileSync(ledgerPath, `${JSON.stringify(events[0])}\n`, "utf8");

    const report = await writer.verifyIntegrity();
    assert.equal(report.ok, false);
    assert.equal(report.issueCode, "MALFORMED_EVENT");
    assert.equal(report.issueLineNumber, 1);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("verifyIntegrity rejects a non-string evidence event hash as malformed", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    assert.equal(
      (await writer.appendDecision(
        makeDecision("ACTION_EVENT_HASH_TYPE", "nonce-event-hash-type"),
        "2026-01-01T00:00:00.000Z"
      )).ok,
      true
    );

    const ledgerPath = path.join(aegisDir, "safety-kernel-v31", "evidence.jsonl");
    const events = readEvents(aegisDir);
    Object.assign(events[0] as object, { evidenceEventHash: 7 });
    fs.writeFileSync(ledgerPath, `${JSON.stringify(events[0])}\n`, "utf8");

    const report = await writer.verifyIntegrity();
    assert.equal(report.ok, false);
    assert.equal(report.issueCode, "MALFORMED_EVENT");
    assert.equal(report.issueLineNumber, 1);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("allowed completion persists a complete execution binding without raw output", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    const result = await writer.appendAllowedExecutionCompletion(
      {
        action_id: "ACTION_EXECUTION_BOUND_COMPLETION",
        approval_nonce: "execution-bound-completion-nonce",
        nonce_consumed: true,
        receipt_required: true,
        ledger_required: true,
        execution_binding: {
          authority_revision: 17,
          command_sha256: "sha256:" + "a".repeat(64),
          snapshot_binding_sha256:
            "sha256:" + "b".repeat(64),
          exit_code: 0,
          stdout_sha256: "sha256:" + "c".repeat(64),
          stderr_sha256: "sha256:" + "d".repeat(64),
          stdout_bytes: 12,
          stderr_bytes: 13,
        },
      },
      "2026-07-19T10:00:00.000Z"
    );

    assert.equal(result.ok, true);
    if (!result.ok) return;

    const events = readEvents(aegisDir);
    const event = events[0] as {
      executionBinding?: Record<string, unknown>;
    };

    assert.deepEqual(event.executionBinding, {
      authority_revision: 17,
      command_sha256: "sha256:" + "a".repeat(64),
      snapshot_binding_sha256:
        "sha256:" + "b".repeat(64),
      exit_code: 0,
      stdout_sha256: "sha256:" + "c".repeat(64),
      stderr_sha256: "sha256:" + "d".repeat(64),
      stdout_bytes: 12,
      stderr_bytes: 13,
    });

    const ledger = fs.readFileSync(result.ledgerPath, "utf8");
    const receipt = fs.readFileSync(
      result.receiptPath,
      "utf8"
    );

    assert.equal(ledger.includes('"stdout":'), false);
    assert.equal(ledger.includes('"stderr":'), false);
    assert.match(receipt, /Authority revision: 17/);
    assert.match(receipt, /Exit code: 0/);
    assert.match(receipt, /stdout bytes: 12/);
    assert.match(receipt, /stderr bytes: 13/);
  } finally {
    removeTempAegisDir(aegisDir);
  }
});

test("allowed completion rejects partial, malformed, or nonzero execution bindings", async () => {
  const aegisDir = makeTempAegisDir();

  try {
    const writer = new SafetyKernelV31EvidenceWriter(aegisDir);
    const base = {
      action_id: "ACTION_INVALID_EXECUTION_BINDING",
      approval_nonce: "invalid-execution-binding-nonce",
      nonce_consumed: true,
      receipt_required: true,
      ledger_required: true,
    } as const;

    const invalidCases = [
      {
        ...base,
        execution_binding: {
          authority_revision: 1,
        },
      },
      {
        ...base,
        execution_binding: {
          authority_revision: 1,
          command_sha256: "invalid",
          snapshot_binding_sha256:
            "sha256:" + "b".repeat(64),
          exit_code: 0,
          stdout_sha256: "sha256:" + "c".repeat(64),
          stderr_sha256: "sha256:" + "d".repeat(64),
          stdout_bytes: 0,
          stderr_bytes: 0,
        },
      },
      {
        ...base,
        execution_binding: {
          authority_revision: 1,
          command_sha256: "sha256:" + "a".repeat(64),
          snapshot_binding_sha256:
            "sha256:" + "b".repeat(64),
          exit_code: 7,
          stdout_sha256: "sha256:" + "c".repeat(64),
          stderr_sha256: "sha256:" + "d".repeat(64),
          stdout_bytes: 0,
          stderr_bytes: 0,
        },
      },
    ];

    for (const invalid of invalidCases) {
      assert.deepEqual(
        await writer.appendAllowedExecutionCompletion(
          invalid as never
        ),
        {
          ok: false,
          ledgerPath: null,
          receiptPath: null,
          reason: "invalid_input",
        }
      );
    }

    assert.equal(
      fs.existsSync(
        path.join(
          aegisDir,
          "safety-kernel-v31",
          "evidence.jsonl"
        )
      ),
      false
    );
  } finally {
    removeTempAegisDir(aegisDir);
  }
});