import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { LedgerWriter } from "./ledgerWriter";
import {
  sha256ReceiptLedgerText,
} from "./receiptLedgerHashChain";
import type { LedgerEvent } from "../packages/aegis-core";

function makeTempAegisDir(): string {
  return fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      "aegis-ledger-writer-"
    )
  );
}

function removeTempAegisDir(
  aegisDir: string
): void {
  fs.rmSync(
    aegisDir,
    {
      recursive: true,
      force: true,
    }
  );
}

function makeLedgerEvent(
  label: string
): LedgerEvent {
  return {
    schemaVersion: 1,
    eventType: "snapshot_created",
    timestamp:
      `2026-01-01T00:00:00.00${label}Z`,
    protectedPath: ".env",
    snapshotId: `snapshot-${label}`,
    success: true,
    verified: true,
    reason:
      "pre_save_snapshot_created",
  };
}

function ledgerPath(
  aegisDir: string
): string {
  return path.join(
    aegisDir,
    "ledger",
    "events.jsonl"
  );
}

function readLedgerEvents(
  aegisDir: string
): Array<Record<string, unknown>> {
  return fs
    .readFileSync(
      ledgerPath(aegisDir),
      "utf8"
    )
    .trim()
    .split(/\r\n|\r|\n/)
    .filter(line => line.length > 0)
    .map(
      line =>
        JSON.parse(line) as
          Record<string, unknown>
    );
}

test(
  "ledgerWriter append creates a durable chained ledger event",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const writer =
        new LedgerWriter(aegisDir);

      assert.equal(
        await writer.append(
          makeLedgerEvent("1")
        ),
        true
      );

      const events =
        readLedgerEvents(aegisDir);

      assert.equal(events.length, 1);
      assert.equal(
        events[0].ledgerChainVersion,
        1
      );
      assert.equal(
        events[0].ledgerSequence,
        1
      );
      assert.equal(
        events[0].ledgerPrevHash,
        "GENESIS"
      );
      assert.equal(
        typeof events[0].ledgerEventHash,
        "string"
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "ledgerWriter serializes sequential appends into a verified chain",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const writer =
        new LedgerWriter(aegisDir);

      assert.equal(
        await writer.append(
          makeLedgerEvent("1")
        ),
        true
      );

      assert.equal(
        await writer.append(
          makeLedgerEvent("2")
        ),
        true
      );

      const events =
        readLedgerEvents(aegisDir);

      assert.equal(
        events[1].ledgerSequence,
        2
      );

      assert.equal(
        events[1].ledgerPrevHash,
        events[0].ledgerEventHash
      );

      const report =
        await writer
          .verifyStartupIntegrity();

      assert.equal(report.ok, true);
      assert.equal(
        report.chainedEventCount,
        2
      );
      assert.equal(
        report.headHash,
        events[1].ledgerEventHash
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "startup integrity detects a changed chained event",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const writer =
        new LedgerWriter(aegisDir);

      assert.equal(
        await writer.append(
          makeLedgerEvent("1")
        ),
        true
      );

      const events =
        readLedgerEvents(aegisDir);

      events[0].protectedPath =
        ".env.local";

      fs.writeFileSync(
        ledgerPath(aegisDir),
        JSON.stringify(events[0]) +
          "\n",
        "utf8"
      );

      const report =
        await writer
          .verifyStartupIntegrity();

      assert.equal(report.ok, false);
      assert.equal(
        report.issueCode,
        "CHAIN_EVENT_HASH_MISMATCH"
      );
      assert.equal(
        report.issueLineNumber,
        1
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "append rejects a damaged ledger without changing its bytes",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const writer =
        new LedgerWriter(aegisDir);

      assert.equal(
        await writer.append(
          makeLedgerEvent("1")
        ),
        true
      );

      const file =
        ledgerPath(aegisDir);

      const events =
        readLedgerEvents(aegisDir);

      events[0].protectedPath =
        ".env.local";

      const damaged =
        JSON.stringify(events[0]) +
        "\n";

      fs.writeFileSync(
        file,
        damaged,
        "utf8"
      );

      assert.equal(
        await writer.append(
          makeLedgerEvent("2")
        ),
        false
      );

      assert.equal(
        fs.readFileSync(file, "utf8"),
        damaged
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "legacy prefix is anchored using its exact original bytes",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const directory =
        path.dirname(
          ledgerPath(aegisDir)
        );

      fs.mkdirSync(
        directory,
        { recursive: true }
      );

      const prefix =
        JSON.stringify({
          schemaVersion: 1,
          eventType:
            "legacy_snapshot",
          protectedPath: ".env",
          success: true,
        }) +
        "\r\n" +
        "\r\n";

      fs.writeFileSync(
        ledgerPath(aegisDir),
        prefix,
        "utf8"
      );

      const writer =
        new LedgerWriter(aegisDir);

      assert.equal(
        await writer.append(
          makeLedgerEvent("1")
        ),
        true
      );

      const events =
        readLedgerEvents(aegisDir);

      const chained =
        events[events.length - 1];

      assert.equal(
        chained.ledgerPrevHash,
        sha256ReceiptLedgerText(
          prefix
        )
      );

      assert.equal(
        chained.ledgerSequence,
        1
      );

      const report =
        await writer
          .verifyStartupIntegrity();

      assert.equal(report.ok, true);
      assert.equal(
        report.chainedEventCount,
        1
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "non-chain records after chain start block verification and append",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const writer =
        new LedgerWriter(aegisDir);

      assert.equal(
        await writer.append(
          makeLedgerEvent("1")
        ),
        true
      );

      const file =
        ledgerPath(aegisDir);

      fs.appendFileSync(
        file,
        JSON.stringify(
          makeLedgerEvent("2")
        ) + "\n",
        "utf8"
      );

      const before =
        fs.readFileSync(file, "utf8");

      const report =
        await writer
          .verifyStartupIntegrity();

      assert.equal(report.ok, false);
      assert.equal(
        report.issueCode,
        "NON_CHAIN_EVENT_AFTER_CHAIN"
      );

      assert.equal(
        await writer.append(
          makeLedgerEvent("3")
        ),
        false
      );

      assert.equal(
        fs.readFileSync(file, "utf8"),
        before
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "startup recovery removes only a malformed final ledger line",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const writer =
        new LedgerWriter(aegisDir);

      assert.equal(
        await writer.append(
          makeLedgerEvent("1")
        ),
        true
      );

      const file =
        ledgerPath(aegisDir);

      const validPrefix =
        fs.readFileSync(file, "utf8");

      fs.appendFileSync(
        file,
        '{"malformed"',
        "utf8"
      );

      const report =
        await writer
          .verifyStartupIntegrity();

      assert.equal(report.ok, true);
      assert.equal(
        report.issueCode,
        "RECOVERED_MALFORMED_LEDGER_TAIL"
      );

      assert.equal(
        fs.readFileSync(file, "utf8"),
        validPrefix
      );

      const backups =
        fs.readdirSync(
          path.dirname(file)
        ).filter(
          name =>
            name.startsWith(
              "events.jsonl.tail-corrupt-"
            ) &&
            name.endsWith(".bak")
        );

      assert.equal(
        backups.length,
        1
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);