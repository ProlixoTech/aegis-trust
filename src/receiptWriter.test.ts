import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { ReceiptWriter } from "./receiptWriter";
import {
  RECEIPT_LEDGER_GENESIS_HASH,
  buildReceiptLedgerChainedEvent,
  sha256ReceiptLedgerText,
  verifyReceiptLedgerBinding,
} from "./receiptLedgerHashChain";

function makeTempAegisDir(): string {
  return fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      "aegis-receipt-writer-"
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

function ledgerPath(
  aegisDir: string
): string {
  return path.join(
    aegisDir,
    "ledger",
    "events.jsonl"
  );
}

function writeValidLedger(
  aegisDir: string,
  records:
    Array<Record<string, unknown>>
): string {
  let previousHash =
    RECEIPT_LEDGER_GENESIS_HASH;

  const lines: string[] = [];

  for (
    let index = 0;
    index < records.length;
    index++
  ) {
    const chained =
      buildReceiptLedgerChainedEvent(
        records[index],
        previousHash,
        index + 1
      );

    previousHash =
      chained.ledgerEventHash as string;

    lines.push(
      JSON.stringify(chained)
    );
  }

  const text =
    lines.join("\n") + "\n";

  fs.mkdirSync(
    path.dirname(
      ledgerPath(aegisDir)
    ),
    { recursive: true }
  );

  fs.writeFileSync(
    ledgerPath(aegisDir),
    text,
    "utf8"
  );

  return text;
}

function baseRecord(
  label: string
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    eventType: "snapshot_created",
    timestamp:
      `2026-01-01T00:00:0${label}.000Z`,
    protectedPath: ".env",
    snapshotId:
      `snapshot-${label}`,
    success: true,
    verified: true,
    snapshotHash:
      label.repeat(64),
    reason:
      "pre_save_snapshot_created",
  };
}

test(
  "receiptWriter returns no_ledger when the ledger file is missing",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const result =
        await new ReceiptWriter(
          aegisDir
        ).generate();

      assert.deepEqual(
        result,
        {
          ok: false,
          receiptPath: null,
          reason: "no_ledger",
        }
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "receiptWriter creates a receipt bound to a verified ledger",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const ledgerText =
        writeValidLedger(
          aegisDir,
          [
            {
              ...baseRecord("1"),
              secretValue:
                "SHOULD_NOT_RENDER",
            },
          ]
        );

      const result =
        await new ReceiptWriter(
          aegisDir
        ).generate();

      assert.equal(result.ok, true);
      assert.equal(
        result.reason,
        "success"
      );
      assert.equal(
        typeof result.receiptPath,
        "string"
      );

      const receipt =
        fs.readFileSync(
          result.receiptPath as string,
          "utf8"
        );

      assert.match(
        receipt,
        /Ledger Chain Verified: \*\*Yes\*\*/
      );

      assert.match(
        receipt,
        /- Receipt SHA-256: `/
      );

      assert.doesNotMatch(
        receipt,
        /SHOULD_NOT_RENDER/
      );

      const binding =
        verifyReceiptLedgerBinding(
          receipt,
          ledgerText
        );

      assert.equal(binding.ok, true);
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "receiptWriter fails closed on malformed ledger content",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      fs.mkdirSync(
        path.dirname(
          ledgerPath(aegisDir)
        ),
        { recursive: true }
      );

      fs.writeFileSync(
        ledgerPath(aegisDir),
        "not-json\n",
        "utf8"
      );

      const result =
        await new ReceiptWriter(
          aegisDir
        ).generate();

      assert.deepEqual(
        result,
        {
          ok: false,
          receiptPath: null,
          reason:
            "ledger_integrity_failed",
        }
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "receiptWriter fails closed on a tampered chain",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      writeValidLedger(
        aegisDir,
        [baseRecord("1")]
      );

      const file =
        ledgerPath(aegisDir);

      const event =
        JSON.parse(
          fs.readFileSync(
            file,
            "utf8"
          ).trim()
        ) as Record<string, unknown>;

      event.protectedPath =
        ".env.local";

      fs.writeFileSync(
        file,
        JSON.stringify(event) + "\n",
        "utf8"
      );

      const result =
        await new ReceiptWriter(
          aegisDir
        ).generate();

      assert.equal(result.ok, false);
      assert.equal(
        result.reason,
        "ledger_integrity_failed"
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "receiptWriter supports an exactly anchored legacy prefix",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      const prefix =
        JSON.stringify({
          schemaVersion: 1,
          eventType:
            "legacy_snapshot",
          protectedPath: ".env",
          success: true,
          verified: true,
          reason:
            "pre_save_snapshot_created",
        }) +
        "\r\n" +
        "\r\n";

      const chained =
        buildReceiptLedgerChainedEvent(
          baseRecord("1"),
          sha256ReceiptLedgerText(
            prefix
          ),
          1
        );

      const ledgerText =
        prefix +
        JSON.stringify(chained) +
        "\r\n";

      fs.mkdirSync(
        path.dirname(
          ledgerPath(aegisDir)
        ),
        { recursive: true }
      );

      fs.writeFileSync(
        ledgerPath(aegisDir),
        ledgerText,
        "utf8"
      );

      const result =
        await new ReceiptWriter(
          aegisDir
        ).generate();

      assert.equal(result.ok, true);

      const receipt =
        fs.readFileSync(
          result.receiptPath as string,
          "utf8"
        );

      assert.equal(
        verifyReceiptLedgerBinding(
          receipt,
          ledgerText
        ).ok,
        true
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);

test(
  "receiptWriter returns write_failed when the receipt directory is blocked",
  async () => {
    const aegisDir =
      makeTempAegisDir();

    try {
      writeValidLedger(
        aegisDir,
        [baseRecord("1")]
      );

      fs.writeFileSync(
        path.join(
          aegisDir,
          "receipts"
        ),
        "blocked",
        "utf8"
      );

      const result =
        await new ReceiptWriter(
          aegisDir
        ).generate();

      assert.deepEqual(
        result,
        {
          ok: false,
          receiptPath: null,
          reason: "write_failed",
        }
      );
    } finally {
      removeTempAegisDir(aegisDir);
    }
  }
);