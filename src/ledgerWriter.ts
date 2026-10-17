// src/ledgerWriter.ts - Truthful Ledger for Prolixo Aegis Personal v0.1 Prototype
//
// ROLE: Record sanitized facts about snapshot/restore outcomes.
//       Called ONLY from extension.ts Orchestrator.
//
// MUST NOT:
//   - Restore files
//   - Create snapshots
//   - Read .env content
//   - Write raw secret values
//   - Control UI or own state
//   - Import envCoreEngine, snapshotStore, stateManager, or webviewPanel
//
// FORMAT: .aegis/ledger/events.jsonl
//   One complete JSON object per line.
//   Append-only - existing lines are never modified.
//   Hash-chained through receiptLedgerHashChain.ts.
//
// FAILURE RULE:
//   append() must never throw. It returns false on failure.
//   The caller (extension.ts) decides what to show the user.
//   A ledger write failure must never change the restore result.

import * as fs from "fs";
import * as path from "path";

import {
  buildReceiptLedgerChainedEvent,
  planReceiptLedgerAppend,
  verifyReceiptLedgerHashChainText,
} from "../packages/aegis-core";
import { LedgerEvent } from "../packages/aegis-core";

function logLedgerWriterError(message: string, detail?: unknown): void {
  console.error(...(typeof detail === "undefined" ? [message] : [message, detail]));
}


export interface LedgerStartupIntegrityReport {
  ok: boolean;
  ledgerExists: boolean;
  ledgerPath: string;
  rawLineCount: number;
  parsedLineCount: number;
  chainedEventCount: number;
  headHash: string;
  issueCode?: string;
  issueLineNumber?: number;
  expected?: string;
  actual?: string;
}

export class LedgerWriter {
  private readonly ledgerDir:  string;
  private readonly eventsFile: string;
  // LEDGER_APPEND_QUEUE_RUNTIME_GUARD_V1
  private appendQueue: Promise<void> = Promise.resolve();

  constructor(aegisDir: string) {
    this.ledgerDir  = path.join(aegisDir, "ledger");
    this.eventsFile = path.join(this.ledgerDir, "events.jsonl");
  }

// Directory setup

  /**
   * Ensure .aegis/ledger/ exists.
   * Called once during initializeAegis() after workspace root is known.
 * Non-fatal if it fails - append() will handle the missing directory too.
   */
  async ensureDirs(): Promise<void> {
    await fs.promises.mkdir(this.ledgerDir, { recursive: true });
  }

// Append

  /**
   * Serialize `event` as a single JSON line and append it to events.jsonl.
   *
   * Returns true on success, false on any failure.
 * Never throws - all errors are caught internally.
   *
   * The caller must not pass raw file content, secret values, or
   * free-form error message strings in any event field. The LedgerEvent
   * type enforces fixed reason / errorCode enums to prevent this.
   */
  private async buildChainedEvent(
    event: LedgerEvent
  ): Promise<{
    chainedEvent: LedgerEvent;
    appendPrefix: "" | "\n";
  }> {
    let existingLedger = "";

    try {
      existingLedger =
        await fs.promises.readFile(
          this.eventsFile,
          "utf8"
        );
    } catch (err) {
      const code =
        (err as { code?: string }).code;

      if (code !== "ENOENT") {
        throw err;
      }
    }

    const appendPlan =
      planReceiptLedgerAppend(
        existingLedger
      );

    if (!appendPlan.ok) {
      throw new Error(
        "LEDGER_APPEND_INTEGRITY_FAILED:" +
        appendPlan.issueCode
      );
    }

    const chainedEvent =
      buildReceiptLedgerChainedEvent(
        event as unknown as
          Record<string, unknown>,
        appendPlan.previousHash,
        appendPlan.sequence
      ) as unknown as LedgerEvent;

    return {
      chainedEvent,
      appendPrefix:
        appendPlan.appendPrefix,
    };
  }
  async verifyStartupIntegrity(): Promise<LedgerStartupIntegrityReport> {
    const countNonEmptyLines = (
      text: string
    ): number =>
      text
        .split(/\r\n|\r|\n/)
        .filter(
          line => line.trim().length > 0
        ).length;

    const successFromText = (
      text: string,
      issueCode?: string,
      issueLineNumber?: number
    ): LedgerStartupIntegrityReport => {
      const rawLineCount =
        countNonEmptyLines(text);

      if (rawLineCount === 0) {
        return {
          ok: true,
          ledgerExists: true,
          ledgerPath: this.eventsFile,
          rawLineCount: 0,
          parsedLineCount: 0,
          chainedEventCount: 0,
          headHash: "NO_CHAIN",
          issueCode,
          issueLineNumber,
        };
      }

      const report =
        verifyReceiptLedgerHashChainText(
          text
        );

      if (report.ok) {
        return {
          ok: true,
          ledgerExists: true,
          ledgerPath: this.eventsFile,
          rawLineCount:
            report.ledgerRawLineCount,
          parsedLineCount:
            report.ledgerRawLineCount,
          chainedEventCount:
            report.ledgerChainEventCount,
          headHash:
            report.ledgerChainHeadHash,
          issueCode,
          issueLineNumber,
        };
      }

      if (
        report.issueCode ===
        "NO_CHAINED_EVENTS"
      ) {
        return {
          ok: true,
          ledgerExists: true,
          ledgerPath: this.eventsFile,
          rawLineCount,
          parsedLineCount:
            rawLineCount,
          chainedEventCount: 0,
          headHash: "NO_CHAIN",
          issueCode,
          issueLineNumber,
        };
      }

      return {
        ok: false,
        ledgerExists: true,
        ledgerPath: this.eventsFile,
        rawLineCount,
        parsedLineCount: Math.max(
          0,
          (report.issueLineNumber ?? 1) - 1
        ),
        chainedEventCount: 0,
        headHash: "INVALID_CHAIN",
        issueCode:
          report.issueCode,
        issueLineNumber:
          report.issueLineNumber,
        expected:
          report.expected,
        actual:
          report.actual,
      };
    };

    try {
      const ledgerText =
        await fs.promises.readFile(
          this.eventsFile,
          "utf8"
        );

      const initial =
        successFromText(ledgerText);

      if (initial.ok) {
        return initial;
      }

      if (
        initial.issueCode !==
          "MALFORMED_LEDGER_LINE" ||
        initial.issueLineNumber ===
          undefined
      ) {
        return initial;
      }

      const physicalLines: Array<{
        text: string;
        startOffset: number;
        lineNumber: number;
      }> = [];

      let startOffset = 0;
      let lineNumber = 1;
      let index = 0;

      while (index < ledgerText.length) {
        const character =
          ledgerText[index];

        if (
          character !== "\n" &&
          character !== "\r"
        ) {
          index++;
          continue;
        }

        physicalLines.push({
          text: ledgerText.slice(
            startOffset,
            index
          ),
          startOffset,
          lineNumber,
        });

        if (
          character === "\r" &&
          ledgerText[index + 1] === "\n"
        ) {
          index += 2;
        } else {
          index++;
        }

        startOffset = index;
        lineNumber++;
      }

      if (startOffset < ledgerText.length) {
        physicalLines.push({
          text:
            ledgerText.slice(startOffset),
          startOffset,
          lineNumber,
        });
      }

      const nonEmptyLines =
        physicalLines.filter(
          line =>
            line.text.trim().length > 0
        );

      const malformedLine =
        physicalLines.find(
          line =>
            line.lineNumber ===
            initial.issueLineNumber
        );

      const finalNonEmptyLine =
        nonEmptyLines.length > 0
          ? nonEmptyLines[
              nonEmptyLines.length - 1
            ]
          : undefined;

      if (
        !malformedLine ||
        !finalNonEmptyLine ||
        malformedLine.lineNumber !==
          finalNonEmptyLine.lineNumber
      ) {
        return initial;
      }

      const recoveredText =
        ledgerText.slice(
          0,
          malformedLine.startOffset
        );

      const recoveredReport =
        successFromText(recoveredText);

      if (!recoveredReport.ok) {
        return initial;
      }

      const backupPath =
        this.eventsFile +
        ".tail-corrupt-" +
        Date.now() +
        ".bak";

      await fs.promises.copyFile(
        this.eventsFile,
        backupPath
      );

      const handle =
        await fs.promises.open(
          this.eventsFile,
          "w"
        );

      try {
        await handle.writeFile(
          recoveredText,
          "utf8"
        );
        await handle.sync();
      } finally {
        await handle.close();
      }

      return successFromText(
        recoveredText,
        "RECOVERED_MALFORMED_LEDGER_TAIL",
        initial.issueLineNumber
      );
    } catch (err) {
      const code =
        (err as { code?: string }).code;

      return {
        ok: code === "ENOENT",
        ledgerExists: false,
        ledgerPath: this.eventsFile,
        rawLineCount: 0,
        parsedLineCount: 0,
        chainedEventCount: 0,
        headHash: "NO_LEDGER",
        issueCode:
          code === "ENOENT"
            ? "NO_LEDGER"
            : "READ_FAILED",
      };
    }
  }
  async append(event: LedgerEvent): Promise<boolean> {
    const operation = this.appendQueue.then(
      () => this.appendSerialized(event),
      () => this.appendSerialized(event)
    );

    this.appendQueue = operation.then(
      () => undefined,
      () => undefined
    );

    return operation;
  }

  private async appendSerialized(event: LedgerEvent): Promise<boolean> {
    try {
      // Ensure directory exists in case ensureDirs() was not called or failed
      await fs.promises.mkdir(this.ledgerDir, { recursive: true });

      // LEDGER_HASH_CHAIN_RUNTIME_GUARD_V1
      const {
        chainedEvent,
        appendPrefix,
      } = await this.buildChainedEvent(
        event
      );

      const line =
        appendPrefix +
        JSON.stringify(chainedEvent) +
        "\n";
      await this.appendDurableLine(line);
      return true;
    } catch (err) {
      // Log the fact of failure but not the event content (which may be safe,
      // but we keep this module's logging surface minimal).
      logLedgerWriterError("[Aegis Ledger] Failed to append event:", (err as Error).message);
      return false;
    }
  }

  private async appendDurableLine(line: string): Promise<void> {
    // LEDGER_DURABLE_APPEND_RUNTIME_GUARD_V1
    const handle = await fs.promises.open(this.eventsFile, "a");
    try {
      await handle.writeFile(line, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
}
