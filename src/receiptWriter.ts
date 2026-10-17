// src/receiptWriter.ts - Markdown Work Receipt for Prolixo Aegis Personal v0.1 Prototype
//
// ROLE: Read .aegis/ledger/events.jsonl and render a local Markdown receipt.
//       Called ONLY from extension.ts Orchestrator.
//
// MUST NOT:
//   Read .env content.
//   Read snapshot file content.
//   Read .aegis/snapshots/** or latest-safe-snapshot.json.
//   Import envCoreEngine, snapshotStore, stateManager, webviewPanel, or ledgerWriter.
//   Decide restore success (only summarise what the ledger says).
//   Render arbitrary JSON fields (whitelist only).
//   Include raw secret values.
//
// FIELD WHITELIST:
//   Only these LedgerEvent fields are rendered in the receipt:
//     schemaVersion, eventType, timestamp, protectedPath,
//     snapshotId, success, verified, snapshotHash, reason, errorCode
//
// RECEIPT INTEGRITY:
//   A SHA-256 hash of the receipt Markdown text (up to and excluding the
//   hash line itself) is appended at the bottom. This is a local integrity
//   marker for the receipt file - not a hash chain, not a digital signature,
//   not cloud verification.

import * as fs from "fs";
import * as path from "path";

import {
  sha256ReceiptLedgerText,
  verifyReceiptLedgerBinding,
  verifyReceiptLedgerHashChainText,
} from "../packages/aegis-core";
import {
  LedgerEvent,
  LedgerEventType,
  LedgerErrorCode,
  LedgerReason,
} from "../packages/aegis-core";

// Maximum number of events to include in the timeline table.
// If the ledger has more valid events, only the most recent N are shown.
const MAX_TIMELINE_EVENTS = 50;

// Types local to this module

/** Safe whitelisted snapshot of one LedgerEvent - no arbitrary fields. */
interface SafeEvent {
  schemaVersion: number;
  eventType:     string;
  timestamp:     string;
  protectedPath: string;
  snapshotId?:   string;
  success:       boolean;
  verified:      boolean;
  snapshotHash?: string;
  reason:        string;
  errorCode?:    string;
}

/** Return value from generate(). */
export interface ReceiptResult {
  ok:          boolean;
  receiptPath: string | null;
  reason: "success" | "no_ledger" | "write_failed" | "ledger_integrity_failed" | "unknown";
}

// ReceiptWriter

export class ReceiptWriter {
  private readonly ledgerFile:   string;
  private readonly receiptsDir:  string;

  constructor(aegisDir: string) {
    this.ledgerFile  = path.join(aegisDir, "ledger", "events.jsonl");
    this.receiptsDir = path.join(aegisDir, "receipts");
  }

// Directory setup

  async ensureDirs(): Promise<void> {
    await fs.promises.mkdir(this.receiptsDir, { recursive: true });
  }

// Main entry point

  async generate(): Promise<ReceiptResult> {
    try {
      await fs.promises.access(
        this.ledgerFile
      );
    } catch {
      return {
        ok: false,
        receiptPath: null,
        reason: "no_ledger",
      };
    }

    let ledgerContent: string;

    try {
      ledgerContent =
        await fs.promises.readFile(
          this.ledgerFile,
          "utf8"
        );
    } catch {
      return {
        ok: false,
        receiptPath: null,
        reason: "unknown",
      };
    }

    const ledgerIntegrity =
      verifyReceiptLedgerHashChainText(
        ledgerContent
      );

    if (!ledgerIntegrity.ok) {
      return {
        ok: false,
        receiptPath: null,
        reason:
          "ledger_integrity_failed",
      };
    }

    const rawLines =
      ledgerContent
        .split(/\r\n|\r|\n/)
        .filter(
          line => line.trim().length > 0
        );

    let skippedCount = 0;
    const allEvents: SafeEvent[] = [];

    for (const line of rawLines) {
      try {
        const parsed =
          JSON.parse(line);

        if (
          typeof parsed !== "object" ||
          parsed === null ||
          parsed.schemaVersion !== 1 ||
          typeof parsed.eventType !==
            "string"
        ) {
          skippedCount++;
          continue;
        }

        allEvents.push(
          extractSafeEvent(parsed)
        );
      } catch {
        return {
          ok: false,
          receiptPath: null,
          reason:
            "ledger_integrity_failed",
        };
      }
    }

    const totalValid =
      allEvents.length;

    const events =
      allEvents.slice(
        -MAX_TIMELINE_EVENTS
      );

    const truncated =
      totalValid >
      MAX_TIMELINE_EVENTS;

    const snapshotCount =
      allEvents.filter(
        event =>
          event.eventType ===
          "snapshot_created"
      ).length;

    const completedCount =
      allEvents.filter(
        event =>
          event.eventType ===
          "restore_completed"
      ).length;

    const failedCount =
      allEvents.filter(
        event =>
          event.eventType ===
          "restore_failed"
      ).length;

    const hasVerifiedRestore =
      allEvents.some(
        event =>
          event.eventType ===
            "restore_completed" &&
          event.success === true &&
          event.verified === true
      );

    const protectedPath =
      allEvents.find(
        event => event.protectedPath
      )?.protectedPath ?? ".env";

    const md = renderMarkdown({
      now: new Date().toISOString(),
      protectedPath,
      totalValid,
      truncated,
      events,
      skippedCount,
      snapshotCount,
      completedCount,
      failedCount,
      hasVerifiedRestore,
      ledgerFileHash:
        ledgerIntegrity
          .ledgerFileSha256,
      ledgerRawLineCount:
        ledgerIntegrity
          .ledgerRawLineCount,
      ledgerChainVerified: true,
      ledgerChainEventCount:
        ledgerIntegrity
          .ledgerChainEventCount,
      ledgerChainHeadHash:
        ledgerIntegrity
          .ledgerChainHeadHash,
    });

    const integrityHash =
      sha256ReceiptLedgerText(md);

    const finalMd =
      md +
      `- Receipt SHA-256: \`${integrityHash}\`\n`;

    const stamp =
      formatTimestamp(new Date());

    const filename =
      `work-receipt-${stamp}.md`;

    const outPath =
      path.join(
        this.receiptsDir,
        filename
      );

    try {
      await fs.promises.mkdir(
        this.receiptsDir,
        { recursive: true }
      );

      await writeDurableUtf8File(
        outPath,
        finalMd
      );
    } catch {
      return {
        ok: false,
        receiptPath: null,
        reason: "write_failed",
      };
    }

    try {
      const [
        persistedReceipt,
        currentLedger,
      ] = await Promise.all([
        fs.promises.readFile(
          outPath,
          "utf8"
        ),
        fs.promises.readFile(
          this.ledgerFile,
          "utf8"
        ),
      ]);

      const binding =
        verifyReceiptLedgerBinding(
          persistedReceipt,
          currentLedger
        );

      if (!binding.ok) {
        throw new Error(
          "RECEIPT_LEDGER_BINDING_FAILED:" +
          binding.issueCode
        );
      }
    } catch {
      try {
        await fs.promises.unlink(
          outPath
        );
      } catch {
        // Best-effort removal of an untrusted receipt.
      }

      return {
        ok: false,
        receiptPath: null,
        reason:
          "ledger_integrity_failed",
      };
    }

    return {
      ok: true,
      receiptPath: outPath,
      reason: "success",
    };
  }
}

async function writeDurableUtf8File(targetPath: string, content: string): Promise<void> {
  // RECEIPT_CRASH_SAFE_DURABLE_WRITE_RUNTIME_GUARD_V1
  const targetDir = path.dirname(targetPath);
  const tempPath = path.join(
    targetDir,
    `.${path.basename(targetPath)}.${process.pid}.${Date.now()}.tmp`
  );

  let keepTemp = true;
  try {
    const handle = await fs.promises.open(tempPath, "w");
    try {
      await handle.writeFile(content, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }

    await fs.promises.rename(tempPath, targetPath);
    keepTemp = false;
    await bestEffortSyncDirectory(targetDir);
  } finally {
    if (keepTemp) {
      try { await fs.promises.unlink(tempPath); } catch { /* best effort cleanup */ }
    }
  }
}

async function bestEffortSyncDirectory(targetDir: string): Promise<void> {
  // RECEIPT_DIRECTORY_SYNC_BEST_EFFORT_GUARD_V1
  try {
    const dirHandle = await fs.promises.open(targetDir, "r");
    try {
      await dirHandle.sync();
    } finally {
      await dirHandle.close();
    }
  } catch {
    // Directory fsync is best-effort across platforms.
  }
}
// Whitelist extractor

/**
 * Extract only the approved fields from a parsed ledger event.
 * Any field not in the whitelist is silently dropped.
 * This prevents unknown or unexpected content from entering the receipt.
 */
function extractSafeEvent(raw: Record<string, unknown>): SafeEvent {
  return {
    schemaVersion: typeof raw.schemaVersion === "number" ? raw.schemaVersion : 0,
    eventType:     typeof raw.eventType     === "string" ? raw.eventType     : "unknown",
    timestamp:     typeof raw.timestamp     === "string" ? raw.timestamp     : "",
    protectedPath: typeof raw.protectedPath === "string" ? sanitizePath(raw.protectedPath) : ".env",
    snapshotId:    typeof raw.snapshotId    === "string" ? raw.snapshotId    : undefined,
    success:       typeof raw.success       === "boolean" ? raw.success      : false,
    verified:      typeof raw.verified      === "boolean" ? raw.verified     : false,
    snapshotHash:  typeof raw.snapshotHash  === "string" ? raw.snapshotHash  : undefined,
    reason:        typeof raw.reason        === "string" ? raw.reason        : "",
    errorCode:     typeof raw.errorCode     === "string" ? raw.errorCode     : undefined,
  };
}

/**
 * Ensure protectedPath is relative. Reject any value that looks like an
 * absolute path (starts with "/" or contains ":" for Windows drive letters).
 * Falls back to ".env" if the value looks suspicious.
 */
function sanitizePath(p: string): string {
  if (p.startsWith("/") || p.includes(":") || p.includes("..")) {
    return ".env";
  }
  return p;
}

// Markdown renderer

interface RenderArgs {
  now:             string;
  protectedPath:   string;
  totalValid:      number;
  truncated:       boolean;
  events:          SafeEvent[];
  skippedCount:    number;
  snapshotCount:   number;
  completedCount:  number;
  failedCount:     number;
  hasVerifiedRestore: boolean;
  ledgerFileHash:      string;
  ledgerRawLineCount:  number;
  ledgerChainVerified: boolean;
  ledgerChainEventCount: number;
  ledgerChainHeadHash: string;
}

function renderMarkdown(a: RenderArgs): string {
  const truncNote = a.truncated
    ? `\n_Showing most recent ${MAX_TIMELINE_EVENTS} of ${a.totalValid} valid ledger events._\n`
    : "";

  const skipNote = a.skippedCount > 0
    ? `\n> _${a.skippedCount} invalid ledger line${a.skippedCount === 1 ? "" : "s"} w${a.skippedCount === 1 ? "as" : "ere"} skipped._\n`
    : "";

// Build timeline rows - whitelist only
  const rows = a.events.map((e) => {
    const time      = e.timestamp ? e.timestamp.replace("T", " ").replace("Z", " UTC") : "-";
    const evType    = mdEsc(e.eventType);
    const pathCol   = mdEsc(e.protectedPath);
    const snapId    = e.snapshotId   ? mdEsc(e.snapshotId.slice(0, 20) + "...") : "-";
    const success   = e.success  ? "yes" : "no";
    const verified  = e.verified ? "yes" : "no";
    const reason    = e.reason    ? mdEsc(e.reason) : "-";
    const errCode   = e.errorCode ? mdEsc(e.errorCode) : "-";
    return `| ${time} | ${evType} | ${pathCol} | ${snapId} | ${success} | ${verified} | ${reason} | ${errCode} |`;
  });

  const timelineTable = rows.length > 0
    ? [
        "| Time (UTC) | Event | Path | Snapshot (prefix) | Success | Verified | Reason | Error Code |",
        "|---|---|---|---|---|---|---|---|",
        ...rows,
      ].join("\n")
    : "_No events to display._";

  return `# Prolixo Aegis Personal - Work Receipt

## Receipt Metadata
- Product: Prolixo Aegis Personal
- Build Target: v0.1 Prototype
- Ledger Schema: v1
- Generated At: ${a.now}
- Source: Local Aegis Ledger (\`.aegis/ledger/events.jsonl\`)
- Ledger File SHA-256: \`${a.ledgerFileHash}\`
- Ledger Raw Line Count: ${a.ledgerRawLineCount}
- Ledger Chain Verified: ${a.ledgerChainVerified ? "**Yes**" : "No"}
- Ledger Chain Events: ${a.ledgerChainEventCount}
- Ledger Chain Head: \`${a.ledgerChainHeadHash}\`

## Summary
- Protected File: \`${mdEsc(a.protectedPath)}\`
- Total Valid Events Included: ${a.totalValid}
- Snapshot Events: ${a.snapshotCount}
- Restore Completed Events: ${a.completedCount}
- Restore Failed Events: ${a.failedCount}
- Latest Verified Restore: ${a.hasVerifiedRestore ? "**Yes**" : "No"}
${truncNote}
## Event Timeline
${timelineTable}
${skipNote}
## Human Review
- [ ] Human Review Completed

## Safety Notes
- This receipt contains no raw secret values.
- This receipt was generated from local Aegis ledger events only.
- This receipt is Markdown only - not PDF.
- This receipt is not cloud verified.
- This receipt does not read \`.env\` or snapshot file contents.
- Fields shown are a whitelist subset of the ledger schema.

## Receipt Integrity
`;
  // NOTE: the SHA-256 line is appended by generate() after hashing this string.
// Do not add anything after this line - it must be the last line before the hash.
}

// Helpers

/** Escape pipe characters in Markdown table cells. */
function mdEsc(s: string): string {
  return s.replace(/\|/g, "\\|");
}

/** Format a Date as YYYYMMDD-HHMMSS for use in filenames. */
function formatTimestamp(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}` +
    `-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`
  );
}
