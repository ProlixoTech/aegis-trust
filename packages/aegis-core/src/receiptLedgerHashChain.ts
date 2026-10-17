import { createHash } from "node:crypto";

export const RECEIPT_LEDGER_CHAIN_VERSION = 1 as const;
export const RECEIPT_LEDGER_GENESIS_HASH = "GENESIS";

export type ReceiptLedgerHashChainIssueCode =
  | "EMPTY_LEDGER"
  | "MALFORMED_LEDGER_LINE"
  | "INVALID_LEDGER_RECORD"
  | "PARTIAL_CHAIN_FIELDS"
  | "UNSUPPORTED_CHAIN_VERSION"
  | "INVALID_CHAIN_SEQUENCE"
  | "INVALID_CHAIN_PREVIOUS_HASH"
  | "INVALID_CHAIN_EVENT_HASH"
  | "CHAIN_EVENT_HASH_MISMATCH"
  | "CHAIN_PREVIOUS_HASH_MISMATCH"
  | "CHAIN_SEQUENCE_MISMATCH"
  | "NON_CHAIN_EVENT_AFTER_CHAIN"
  | "NO_CHAINED_EVENTS"
  | "LEDGER_INTEGRITY_FAILED"
  | "RECEIPT_HASH_LINE_MISSING"
  | "RECEIPT_HASH_LINE_DUPLICATE"
  | "RECEIPT_HASH_LINE_NOT_FINAL"
  | "RECEIPT_HASH_MISMATCH"
  | "RECEIPT_METADATA_MISSING"
  | "RECEIPT_METADATA_DUPLICATE"
  | "RECEIPT_LEDGER_FILE_HASH_MISMATCH"
  | "RECEIPT_LEDGER_RAW_LINE_COUNT_MISMATCH"
  | "RECEIPT_LEDGER_CHAIN_VERIFIED_REQUIRED"
  | "RECEIPT_LEDGER_CHAIN_EVENT_COUNT_MISMATCH"
  | "RECEIPT_LEDGER_CHAIN_HEAD_MISMATCH";

export interface ReceiptLedgerHashChainFailure {
  readonly ok: false;
  readonly issueCode: ReceiptLedgerHashChainIssueCode;
  readonly issueLineNumber?: number;
  readonly expected?: string;
  readonly actual?: string;
  readonly causeIssueCode?: ReceiptLedgerHashChainIssueCode;
}

export interface ReceiptLedgerHashChainSuccess {
  readonly ok: true;
  readonly ledgerFileSha256: string;
  readonly ledgerRawLineCount: number;
  readonly ledgerLegacyLineCount: number;
  readonly ledgerChainEventCount: number;
  readonly ledgerChainHeadHash: string;
}

export type ReceiptLedgerHashChainReport =
  | ReceiptLedgerHashChainSuccess
  | ReceiptLedgerHashChainFailure;

export interface ReceiptLedgerBindingSuccess
  extends ReceiptLedgerHashChainSuccess {
  readonly receiptSha256: string;
  readonly receiptLedgerBindingId: string;
  readonly productPassClaimed: false;
  readonly finalClaimed: false;
  readonly releaseReadyClaimed: false;
  readonly uploadReadyClaimed: false;
}

export type ReceiptLedgerBindingReport =
  | ReceiptLedgerBindingSuccess
  | ReceiptLedgerHashChainFailure;

interface PhysicalLedgerLine {
  readonly text: string;
  readonly startOffset: number;
  readonly lineNumber: number;
}

const CHAIN_FIELD_NAMES = [
  "ledgerChainVersion",
  "ledgerSequence",
  "ledgerPrevHash",
  "ledgerEventHash",
] as const;

function hasOwn(
  value: Record<string, unknown>,
  key: string
): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function sha256Hex(
  value: string | Buffer
): string {
  return createHash("sha256")
    .update(value)
    .digest("hex");
}

export function sha256ReceiptLedgerText(
  value: string
): string {
  return sha256Hex(Buffer.from(value, "utf8"));
}

function canonicalize(
  value: unknown
): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("NON_FINITE_LEDGER_NUMBER");
    }

    return value;
  }

  if (Array.isArray(value)) {
    return value.map(item => canonicalize(item));
  }

  if (typeof value === "object") {
    const source = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};

    for (const key of Object.keys(source).sort()) {
      if (source[key] === undefined) {
        throw new Error("UNDEFINED_LEDGER_VALUE");
      }

      output[key] = canonicalize(source[key]);
    }

    return output;
  }

  throw new Error("UNSUPPORTED_LEDGER_VALUE");
}

function canonicalJson(
  value: unknown
): string {
  return JSON.stringify(canonicalize(value));
}

export function computeReceiptLedgerEventHash(
  event: Readonly<Record<string, unknown>>
): string {
  const eventForHash: Record<string, unknown> = {
    ...event,
  };

  delete eventForHash.ledgerEventHash;

  return sha256Hex(canonicalJson(eventForHash));
}

export function buildReceiptLedgerChainedEvent(
  event: Readonly<Record<string, unknown>>,
  previousHash: string,
  sequence: number
): Record<string, unknown> {
  for (const field of CHAIN_FIELD_NAMES) {
    if (hasOwn(event as Record<string, unknown>, field)) {
      throw new Error("EVENT_ALREADY_CONTAINS_CHAIN_FIELDS");
    }
  }

  if (
    previousHash !== RECEIPT_LEDGER_GENESIS_HASH &&
    !/^[a-f0-9]{64}$/.test(previousHash)
  ) {
    throw new Error("INVALID_CHAIN_PREVIOUS_HASH");
  }

  if (
    !Number.isSafeInteger(sequence) ||
    sequence < 1
  ) {
    throw new Error("INVALID_CHAIN_SEQUENCE");
  }

  const eventForHash: Record<string, unknown> = {
    ...event,
    ledgerChainVersion: RECEIPT_LEDGER_CHAIN_VERSION,
    ledgerSequence: sequence,
    ledgerPrevHash: previousHash,
  };

  return {
    ...eventForHash,
    ledgerEventHash:
      computeReceiptLedgerEventHash(eventForHash),
  };
}

function splitPhysicalLines(
  text: string
): PhysicalLedgerLine[] {
  const lines: PhysicalLedgerLine[] = [];

  let startOffset = 0;
  let lineNumber = 1;
  let index = 0;

  while (index < text.length) {
    const character = text[index];

    if (
      character !== "\n" &&
      character !== "\r"
    ) {
      index++;
      continue;
    }

    lines.push({
      text: text.slice(startOffset, index),
      startOffset,
      lineNumber,
    });

    if (
      character === "\r" &&
      text[index + 1] === "\n"
    ) {
      index += 2;
    } else {
      index++;
    }

    startOffset = index;
    lineNumber++;
  }

  if (startOffset < text.length) {
    lines.push({
      text: text.slice(startOffset),
      startOffset,
      lineNumber,
    });
  }

  return lines;
}

function failure(
  issueCode: ReceiptLedgerHashChainIssueCode,
  values: Omit<
    ReceiptLedgerHashChainFailure,
    "ok" | "issueCode"
  > = {}
): ReceiptLedgerHashChainFailure {
  return {
    ok: false,
    issueCode,
    ...values,
  };
}

export function verifyReceiptLedgerHashChainText(
  ledgerText: string
): ReceiptLedgerHashChainReport {
  const physicalLines = splitPhysicalLines(ledgerText);

  const nonEmptyLines = physicalLines.filter(
    line => line.text.trim().length > 0
  );

  if (nonEmptyLines.length === 0) {
    return failure("EMPTY_LEDGER");
  }

  const ledgerFileSha256 =
    sha256ReceiptLedgerText(ledgerText);

  let chainStarted = false;
  let legacyLineCount = 0;
  let chainEventCount = 0;
  let chainHeadHash = "NO_CHAIN";

  for (const line of nonEmptyLines) {
    let parsed: unknown;

    try {
      parsed = JSON.parse(line.text);
    } catch {
      return failure("MALFORMED_LEDGER_LINE", {
        issueLineNumber: line.lineNumber,
      });
    }

    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      return failure("INVALID_LEDGER_RECORD", {
        issueLineNumber: line.lineNumber,
      });
    }

    const record = parsed as Record<string, unknown>;

    const presentChainFields = CHAIN_FIELD_NAMES.filter(
      field => hasOwn(record, field)
    );

    if (presentChainFields.length === 0) {
      if (chainStarted) {
        return failure("NON_CHAIN_EVENT_AFTER_CHAIN", {
          issueLineNumber: line.lineNumber,
        });
      }

      legacyLineCount++;
      continue;
    }

    if (
      presentChainFields.length !==
      CHAIN_FIELD_NAMES.length
    ) {
      return failure("PARTIAL_CHAIN_FIELDS", {
        issueLineNumber: line.lineNumber,
      });
    }

    chainStarted = true;

    if (
      record.ledgerChainVersion !==
      RECEIPT_LEDGER_CHAIN_VERSION
    ) {
      return failure("UNSUPPORTED_CHAIN_VERSION", {
        issueLineNumber: line.lineNumber,
        expected: String(RECEIPT_LEDGER_CHAIN_VERSION),
        actual: String(record.ledgerChainVersion),
      });
    }

    const sequence = record.ledgerSequence;

    if (
      typeof sequence !== "number" ||
      !Number.isSafeInteger(sequence) ||
      sequence < 1
    ) {
      return failure("INVALID_CHAIN_SEQUENCE", {
        issueLineNumber: line.lineNumber,
      });
    }

    const previousHash = record.ledgerPrevHash;

    if (
      typeof previousHash !== "string" ||
      (
        previousHash !== RECEIPT_LEDGER_GENESIS_HASH &&
        !/^[a-f0-9]{64}$/.test(previousHash)
      )
    ) {
      return failure("INVALID_CHAIN_PREVIOUS_HASH", {
        issueLineNumber: line.lineNumber,
      });
    }

    const eventHash = record.ledgerEventHash;

    if (
      typeof eventHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(eventHash)
    ) {
      return failure("INVALID_CHAIN_EVENT_HASH", {
        issueLineNumber: line.lineNumber,
      });
    }

    const recalculatedHash =
      computeReceiptLedgerEventHash(record);

    if (eventHash !== recalculatedHash) {
      return failure("CHAIN_EVENT_HASH_MISMATCH", {
        issueLineNumber: line.lineNumber,
        expected: recalculatedHash,
        actual: eventHash,
      });
    }

    const expectedSequence = chainEventCount + 1;

    if (sequence !== expectedSequence) {
      return failure("CHAIN_SEQUENCE_MISMATCH", {
        issueLineNumber: line.lineNumber,
        expected: String(expectedSequence),
        actual: String(sequence),
      });
    }

    let expectedPreviousHash: string;

    if (chainEventCount > 0) {
      expectedPreviousHash = chainHeadHash;
    } else if (legacyLineCount > 0) {
      const exactLegacyPrefix = ledgerText.slice(
        0,
        line.startOffset
      );

      expectedPreviousHash =
        sha256ReceiptLedgerText(exactLegacyPrefix);
    } else {
      expectedPreviousHash =
        RECEIPT_LEDGER_GENESIS_HASH;
    }

    if (previousHash !== expectedPreviousHash) {
      return failure("CHAIN_PREVIOUS_HASH_MISMATCH", {
        issueLineNumber: line.lineNumber,
        expected: expectedPreviousHash,
        actual: previousHash,
      });
    }

    chainEventCount++;
    chainHeadHash = eventHash;
  }

  if (chainEventCount === 0) {
    return failure("NO_CHAINED_EVENTS");
  }

  return {
    ok: true,
    ledgerFileSha256,
    ledgerRawLineCount: nonEmptyLines.length,
    ledgerLegacyLineCount: legacyLineCount,
    ledgerChainEventCount: chainEventCount,
    ledgerChainHeadHash: chainHeadHash,
  };
}

export interface ReceiptLedgerAppendPlanSuccess {
  readonly ok: true;
  readonly previousHash: string;
  readonly sequence: number;
  readonly appendPrefix: "" | "\n";
  readonly existingChainEventCount: number;
}

export type ReceiptLedgerAppendPlan =
  | ReceiptLedgerAppendPlanSuccess
  | ReceiptLedgerHashChainFailure;

export function planReceiptLedgerAppend(
  ledgerText: string
): ReceiptLedgerAppendPlan {
  const appendPrefix: "" | "\n" =
    ledgerText.length > 0 &&
    !/[\r\n]$/.test(ledgerText)
      ? "\n"
      : "";

  const hasNonEmptyLine =
    ledgerText
      .split(/\r\n|\r|\n/)
      .some(
        line => line.trim().length > 0
      );

  if (!hasNonEmptyLine) {
    return {
      ok: true,
      previousHash:
        RECEIPT_LEDGER_GENESIS_HASH,
      sequence: 1,
      appendPrefix,
      existingChainEventCount: 0,
    };
  }

  const report =
    verifyReceiptLedgerHashChainText(
      ledgerText
    );

  if (report.ok) {
    return {
      ok: true,
      previousHash:
        report.ledgerChainHeadHash,
      sequence:
        report.ledgerChainEventCount + 1,
      appendPrefix,
      existingChainEventCount:
        report.ledgerChainEventCount,
    };
  }

  if (
    report.issueCode ===
    "NO_CHAINED_EVENTS"
  ) {
    return {
      ok: true,
      previousHash:
        sha256ReceiptLedgerText(
          ledgerText + appendPrefix
        ),
      sequence: 1,
      appendPrefix,
      existingChainEventCount: 0,
    };
  }

  return report;
}
interface MetadataMatch {
  readonly value: string;
  readonly index: number;
  readonly endIndex: number;
}

function collectMatches(
  text: string,
  pattern: RegExp
): MetadataMatch[] {
  const matches: MetadataMatch[] = [];

  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    matches.push({
      value: match[1],
      index: match.index,
      endIndex: match.index + match[0].length,
    });

    if (match[0].length === 0) {
      pattern.lastIndex++;
    }
  }

  return matches;
}

function extractSingleMetadata(
  receiptText: string,
  pattern: RegExp
):
  | {
      ok: true;
      match: MetadataMatch;
    }
  | ReceiptLedgerHashChainFailure {
  const matches = collectMatches(receiptText, pattern);

  if (matches.length === 0) {
    return failure("RECEIPT_METADATA_MISSING");
  }

  if (matches.length !== 1) {
    return failure("RECEIPT_METADATA_DUPLICATE");
  }

  return {
    ok: true,
    match: matches[0],
  };
}

export function verifyReceiptLedgerBinding(
  receiptText: string,
  ledgerText: string
): ReceiptLedgerBindingReport {
  const ledgerReport =
    verifyReceiptLedgerHashChainText(ledgerText);

  if (!ledgerReport.ok) {
    return failure("LEDGER_INTEGRITY_FAILED", {
      causeIssueCode: ledgerReport.issueCode,
      issueLineNumber: ledgerReport.issueLineNumber,
      expected: ledgerReport.expected,
      actual: ledgerReport.actual,
    });
  }

  const receiptHashMatches = collectMatches(
    receiptText,
    /^- Receipt SHA-256: `([a-f0-9]{64})`\r?$/gm
  );

  if (receiptHashMatches.length === 0) {
    return failure("RECEIPT_HASH_LINE_MISSING");
  }

  if (receiptHashMatches.length !== 1) {
    return failure("RECEIPT_HASH_LINE_DUPLICATE");
  }

  const receiptHashMatch = receiptHashMatches[0];

  const tail = receiptText.slice(
    receiptHashMatch.endIndex
  );

  if (
    tail !== "" &&
    tail !== "\n"
  ) {
    return failure("RECEIPT_HASH_LINE_NOT_FINAL");
  }

  const receiptHashPrefix = receiptText.slice(
    0,
    receiptHashMatch.index
  );

  const recalculatedReceiptHash =
    sha256ReceiptLedgerText(receiptHashPrefix);

  if (
    recalculatedReceiptHash !==
    receiptHashMatch.value
  ) {
    return failure("RECEIPT_HASH_MISMATCH", {
      expected: recalculatedReceiptHash,
      actual: receiptHashMatch.value,
    });
  }

  const fileHashMetadata = extractSingleMetadata(
    receiptText,
    /^- Ledger File SHA-256: `([a-f0-9]{64})`\r?$/gm
  );

  if (!fileHashMetadata.ok) {
    return fileHashMetadata;
  }

  const rawLineMetadata = extractSingleMetadata(
    receiptText,
    /^- Ledger Raw Line Count: ([0-9]+)\r?$/gm
  );

  if (!rawLineMetadata.ok) {
    return rawLineMetadata;
  }

  const chainVerifiedMetadata = extractSingleMetadata(
    receiptText,
    /^- Ledger Chain Verified: (\*\*Yes\*\*|No)\r?$/gm
  );

  if (!chainVerifiedMetadata.ok) {
    return chainVerifiedMetadata;
  }

  const chainEventCountMetadata = extractSingleMetadata(
    receiptText,
    /^- Ledger Chain Events: ([0-9]+)\r?$/gm
  );

  if (!chainEventCountMetadata.ok) {
    return chainEventCountMetadata;
  }

  const chainHeadMetadata = extractSingleMetadata(
    receiptText,
    /^- Ledger Chain Head: `([^`\r\n]+)`\r?$/gm
  );

  if (!chainHeadMetadata.ok) {
    return chainHeadMetadata;
  }

  if (
    fileHashMetadata.match.value !==
    ledgerReport.ledgerFileSha256
  ) {
    return failure(
      "RECEIPT_LEDGER_FILE_HASH_MISMATCH",
      {
        expected: ledgerReport.ledgerFileSha256,
        actual: fileHashMetadata.match.value,
      }
    );
  }

  const rawLineCount =
    Number(rawLineMetadata.match.value);

  if (
    rawLineCount !==
    ledgerReport.ledgerRawLineCount
  ) {
    return failure(
      "RECEIPT_LEDGER_RAW_LINE_COUNT_MISMATCH",
      {
        expected: String(
          ledgerReport.ledgerRawLineCount
        ),
        actual: rawLineMetadata.match.value,
      }
    );
  }

  if (
    chainVerifiedMetadata.match.value !==
    "**Yes**"
  ) {
    return failure(
      "RECEIPT_LEDGER_CHAIN_VERIFIED_REQUIRED",
      {
        expected: "**Yes**",
        actual:
          chainVerifiedMetadata.match.value,
      }
    );
  }

  const chainEventCount = Number(
    chainEventCountMetadata.match.value
  );

  if (
    chainEventCount !==
    ledgerReport.ledgerChainEventCount
  ) {
    return failure(
      "RECEIPT_LEDGER_CHAIN_EVENT_COUNT_MISMATCH",
      {
        expected: String(
          ledgerReport.ledgerChainEventCount
        ),
        actual:
          chainEventCountMetadata.match.value,
      }
    );
  }

  if (
    chainHeadMetadata.match.value !==
    ledgerReport.ledgerChainHeadHash
  ) {
    return failure(
      "RECEIPT_LEDGER_CHAIN_HEAD_MISMATCH",
      {
        expected:
          ledgerReport.ledgerChainHeadHash,
        actual: chainHeadMetadata.match.value,
      }
    );
  }

  const receiptLedgerBindingId =
    "sha256:" +
    sha256Hex(
      canonicalJson({
        schemaVersion: "1.0.0",
        receiptSha256: recalculatedReceiptHash,
        ledgerFileSha256:
          ledgerReport.ledgerFileSha256,
        ledgerRawLineCount:
          ledgerReport.ledgerRawLineCount,
        ledgerLegacyLineCount:
          ledgerReport.ledgerLegacyLineCount,
        ledgerChainEventCount:
          ledgerReport.ledgerChainEventCount,
        ledgerChainHeadHash:
          ledgerReport.ledgerChainHeadHash,
      })
    );

  return {
    ok: true,
    receiptSha256: recalculatedReceiptHash,
    receiptLedgerBindingId,
    ledgerFileSha256:
      ledgerReport.ledgerFileSha256,
    ledgerRawLineCount:
      ledgerReport.ledgerRawLineCount,
    ledgerLegacyLineCount:
      ledgerReport.ledgerLegacyLineCount,
    ledgerChainEventCount:
      ledgerReport.ledgerChainEventCount,
    ledgerChainHeadHash:
      ledgerReport.ledgerChainHeadHash,
    productPassClaimed: false,
    finalClaimed: false,
    releaseReadyClaimed: false,
    uploadReadyClaimed: false,
  };
}