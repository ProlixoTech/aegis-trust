import { test } from "node:test";
import * as assert from "node:assert/strict";

import {
  RECEIPT_LEDGER_GENESIS_HASH,
  buildReceiptLedgerChainedEvent,
  computeReceiptLedgerEventHash,
  sha256ReceiptLedgerText,
  verifyReceiptLedgerBinding,
  verifyReceiptLedgerHashChainText,
  planReceiptLedgerAppend,
} from "./receiptLedgerHashChain";

function baseEvent(
  label: string
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    eventType: "snapshot_created",
    timestamp:
      `2026-07-26T00:00:0${label}.000Z`,
    protectedPath: ".env",
    snapshotId: `snapshot-${label}`,
    success: true,
    verified: true,
    snapshotHash: label.repeat(64),
    reason: "pre_save_snapshot_created",
  };
}

function createTwoEventLedger(): {
  readonly ledgerText: string;
  readonly first: Record<string, unknown>;
  readonly second: Record<string, unknown>;
} {
  const first =
    buildReceiptLedgerChainedEvent(
      baseEvent("1"),
      RECEIPT_LEDGER_GENESIS_HASH,
      1
    );

  const second =
    buildReceiptLedgerChainedEvent(
      baseEvent("2"),
      first.ledgerEventHash as string,
      2
    );

  return {
    ledgerText:
      JSON.stringify(first) +
      "\n" +
      JSON.stringify(second) +
      "\n",
    first,
    second,
  };
}

function createReceipt(
  ledgerText: string,
  overrides: Partial<{
    fileHash: string;
    rawLineCount: number;
    chainVerified: string;
    chainEventCount: number;
    chainHead: string;
    extraBody: string;
  }> = {}
): string {
  const report =
    verifyReceiptLedgerHashChainText(
      ledgerText
    );

  if (!report.ok) {
    throw new Error(
      "EXPECTED_LEDGER_SUCCESS"
    );
  }

  assert.equal(report.ok, true);

  const body = [
    "# Test Work Receipt",
    "",
    "## Receipt Metadata",
    `- Ledger File SHA-256: \`${overrides.fileHash ?? report.ledgerFileSha256}\``,
    `- Ledger Raw Line Count: ${overrides.rawLineCount ?? report.ledgerRawLineCount}`,
    `- Ledger Chain Verified: ${overrides.chainVerified ?? "**Yes**"}`,
    `- Ledger Chain Events: ${overrides.chainEventCount ?? report.ledgerChainEventCount}`,
    `- Ledger Chain Head: \`${overrides.chainHead ?? report.ledgerChainHeadHash}\``,
    "",
    overrides.extraBody ??
      "Verified local receipt.",
    "",
  ].join("\n");

  const receiptHash =
    sha256ReceiptLedgerText(body);

  return (
    body +
    `- Receipt SHA-256: \`${receiptHash}\`\n`
  );
}

test(
  "valid chained ledger and receipt binding pass deterministically",
  () => {
    const fixture = createTwoEventLedger();

    const ledgerReport =
      verifyReceiptLedgerHashChainText(
        fixture.ledgerText
      );

    if (!ledgerReport.ok) {
      throw new Error(
        "EXPECTED_LEDGER_SUCCESS"
      );
    }

    assert.equal(ledgerReport.ok, true);
    assert.equal(
      ledgerReport.ledgerRawLineCount,
      2
    );
    assert.equal(
      ledgerReport.ledgerLegacyLineCount,
      0
    );
    assert.equal(
      ledgerReport.ledgerChainEventCount,
      2
    );
    assert.equal(
      ledgerReport.ledgerChainHeadHash,
      fixture.second.ledgerEventHash
    );

    const receipt =
      createReceipt(fixture.ledgerText);

    const firstBinding =
      verifyReceiptLedgerBinding(
        receipt,
        fixture.ledgerText
      );

    const secondBinding =
      verifyReceiptLedgerBinding(
        receipt,
        fixture.ledgerText
      );

    if (!firstBinding.ok) {
      throw new Error(
        "EXPECTED_FIRST_BINDING_SUCCESS"
      );
    }

    if (!secondBinding.ok) {
      throw new Error(
        "EXPECTED_SECOND_BINDING_SUCCESS"
      );
    }

    assert.equal(firstBinding.ok, true);
    assert.equal(secondBinding.ok, true);

    assert.match(
      firstBinding.receiptLedgerBindingId,
      /^sha256:[a-f0-9]{64}$/
    );

    assert.equal(
      firstBinding.receiptLedgerBindingId,
      secondBinding.receiptLedgerBindingId
    );

    assert.equal(
      firstBinding.productPassClaimed,
      false
    );
    assert.equal(
      firstBinding.finalClaimed,
      false
    );
    assert.equal(
      firstBinding.releaseReadyClaimed,
      false
    );
    assert.equal(
      firstBinding.uploadReadyClaimed,
      false
    );
  }
);

test(
  "valid legacy JSON prefix uses its exact original byte anchor",
  () => {
    const legacyPrefix =
      JSON.stringify({
        schemaVersion: 1,
        eventType: "legacy_snapshot",
        protectedPath: ".env",
        success: true,
      }) +
      "\r\n" +
      "\r\n";

    const anchoredEvent =
      buildReceiptLedgerChainedEvent(
        baseEvent("1"),
        sha256ReceiptLedgerText(
          legacyPrefix
        ),
        1
      );

    const ledgerText =
      legacyPrefix +
      JSON.stringify(anchoredEvent) +
      "\r\n";

    const report =
      verifyReceiptLedgerHashChainText(
        ledgerText
      );

    if (!report.ok) {
      throw new Error(
        "EXPECTED_LEGACY_LEDGER_SUCCESS"
      );
    }

    assert.equal(report.ok, true);
    assert.equal(
      report.ledgerLegacyLineCount,
      1
    );
    assert.equal(
      report.ledgerChainEventCount,
      1
    );
  }
);

test(
  "malformed and non-object ledger rows fail closed",
  () => {
    const malformed =
      verifyReceiptLedgerHashChainText(
        "not-json\n"
      );

    assert.equal(malformed.ok, false);

    if (malformed.ok) {
      throw new Error(
        "EXPECTED_MALFORMED_FAILURE"
      );
    }

    assert.equal(
      malformed.issueCode,
      "MALFORMED_LEDGER_LINE"
    );

    const nonObject =
      verifyReceiptLedgerHashChainText(
        "[]\n"
      );

    assert.equal(nonObject.ok, false);

    if (nonObject.ok) {
      throw new Error(
        "EXPECTED_RECORD_FAILURE"
      );
    }

    assert.equal(
      nonObject.issueCode,
      "INVALID_LEDGER_RECORD"
    );
  }
);

test(
  "event hash, previous hash, and sequence tampering fail closed",
  () => {
    const fixture = createTwoEventLedger();

    const changedFirst:
      Record<string, unknown> = {
      ...fixture.first,
      protectedPath: ".env.local",
    };

    const hashTamperedText =
      JSON.stringify(changedFirst) +
      "\n" +
      JSON.stringify(fixture.second) +
      "\n";

    const hashReport =
      verifyReceiptLedgerHashChainText(
        hashTamperedText
      );

    assert.equal(hashReport.ok, false);

    if (hashReport.ok) {
      throw new Error(
        "EXPECTED_HASH_FAILURE"
      );
    }

    assert.equal(
      hashReport.issueCode,
      "CHAIN_EVENT_HASH_MISMATCH"
    );

    const changedPrevious:
      Record<string, unknown> = {
      ...fixture.second,
      ledgerPrevHash: "a".repeat(64),
    };

    changedPrevious.ledgerEventHash =
      computeReceiptLedgerEventHash(
        changedPrevious
      );

    const previousReport =
      verifyReceiptLedgerHashChainText(
        JSON.stringify(fixture.first) +
        "\n" +
        JSON.stringify(changedPrevious) +
        "\n"
      );

    assert.equal(previousReport.ok, false);

    if (previousReport.ok) {
      throw new Error(
        "EXPECTED_PREVIOUS_FAILURE"
      );
    }

    assert.equal(
      previousReport.issueCode,
      "CHAIN_PREVIOUS_HASH_MISMATCH"
    );

    const changedSequence:
      Record<string, unknown> = {
      ...fixture.second,
      ledgerSequence: 7,
    };

    changedSequence.ledgerEventHash =
      computeReceiptLedgerEventHash(
        changedSequence
      );

    const sequenceReport =
      verifyReceiptLedgerHashChainText(
        JSON.stringify(fixture.first) +
        "\n" +
        JSON.stringify(changedSequence) +
        "\n"
      );

    assert.equal(sequenceReport.ok, false);

    if (sequenceReport.ok) {
      throw new Error(
        "EXPECTED_SEQUENCE_FAILURE"
      );
    }

    assert.equal(
      sequenceReport.issueCode,
      "CHAIN_SEQUENCE_MISMATCH"
    );
  }
);

test(
  "non-chain rows after chain start and partial chain fields fail closed",
  () => {
    const fixture = createTwoEventLedger();

    const afterChain =
      verifyReceiptLedgerHashChainText(
        JSON.stringify(fixture.first) +
        "\n" +
        JSON.stringify(baseEvent("2")) +
        "\n"
      );

    assert.equal(afterChain.ok, false);

    if (afterChain.ok) {
      throw new Error(
        "EXPECTED_AFTER_CHAIN_FAILURE"
      );
    }

    assert.equal(
      afterChain.issueCode,
      "NON_CHAIN_EVENT_AFTER_CHAIN"
    );

    const partial =
      verifyReceiptLedgerHashChainText(
        JSON.stringify({
          ...baseEvent("1"),
          ledgerSequence: 1,
        }) + "\n"
      );

    assert.equal(partial.ok, false);

    if (partial.ok) {
      throw new Error(
        "EXPECTED_PARTIAL_FAILURE"
      );
    }

    assert.equal(
      partial.issueCode,
      "PARTIAL_CHAIN_FIELDS"
    );
  }
);

test(
  "receipt hash and ledger metadata drift fail closed",
  () => {
    const fixture = createTwoEventLedger();

    const receipt =
      createReceipt(fixture.ledgerText);

    const changedReceipt = receipt.replace(
      "Verified local receipt.",
      "Changed local receipt."
    );

    const hashReport =
      verifyReceiptLedgerBinding(
        changedReceipt,
        fixture.ledgerText
      );

    assert.equal(hashReport.ok, false);

    if (hashReport.ok) {
      throw new Error(
        "EXPECTED_RECEIPT_HASH_FAILURE"
      );
    }

    assert.equal(
      hashReport.issueCode,
      "RECEIPT_HASH_MISMATCH"
    );

    const wrongHeadReceipt =
      createReceipt(
        fixture.ledgerText,
        {
          chainHead: "f".repeat(64),
        }
      );

    const metadataReport =
      verifyReceiptLedgerBinding(
        wrongHeadReceipt,
        fixture.ledgerText
      );

    assert.equal(metadataReport.ok, false);

    if (metadataReport.ok) {
      throw new Error(
        "EXPECTED_METADATA_FAILURE"
      );
    }

    assert.equal(
      metadataReport.issueCode,
      "RECEIPT_LEDGER_CHAIN_HEAD_MISMATCH"
    );

    const unverifiedReceipt =
      createReceipt(
        fixture.ledgerText,
        {
          chainVerified: "No",
        }
      );

    const verifiedFlagReport =
      verifyReceiptLedgerBinding(
        unverifiedReceipt,
        fixture.ledgerText
      );

    assert.equal(
      verifiedFlagReport.ok,
      false
    );

    if (verifiedFlagReport.ok) {
      throw new Error(
        "EXPECTED_VERIFIED_FLAG_FAILURE"
      );
    }

    assert.equal(
      verifiedFlagReport.issueCode,
      "RECEIPT_LEDGER_CHAIN_VERIFIED_REQUIRED"
    );
  }
);

test(
  "trusted receipt requires at least one chained ledger event",
  () => {
    const legacyOnly =
      JSON.stringify({
        schemaVersion: 1,
        eventType: "legacy_snapshot",
        protectedPath: ".env",
        success: true,
      }) + "\n";

    const report =
      verifyReceiptLedgerHashChainText(
        legacyOnly
      );

    assert.equal(report.ok, false);

    if (report.ok) {
      throw new Error(
        "EXPECTED_NO_CHAIN_FAILURE"
      );
    }

    assert.equal(
      report.issueCode,
      "NO_CHAINED_EVENTS"
    );
  }
);

test(
  "append plan starts a new ledger at genesis",
  () => {
    const plan =
      planReceiptLedgerAppend("");

    assert.equal(plan.ok, true);

    if (!plan.ok) {
      throw new Error(
        "EXPECTED_APPEND_PLAN_SUCCESS"
      );
    }

    assert.equal(
      plan.previousHash,
      RECEIPT_LEDGER_GENESIS_HASH
    );
    assert.equal(plan.sequence, 1);
    assert.equal(plan.appendPrefix, "");
  }
);

test(
  "append plan anchors an exact legacy byte prefix",
  () => {
    const legacy =
      JSON.stringify({
        schemaVersion: 1,
        eventType: "legacy_snapshot",
      }) +
      "\r\n" +
      "\r\n";

    const plan =
      planReceiptLedgerAppend(legacy);

    assert.equal(plan.ok, true);

    if (!plan.ok) {
      throw new Error(
        "EXPECTED_LEGACY_APPEND_PLAN_SUCCESS"
      );
    }

    assert.equal(
      plan.previousHash,
      sha256ReceiptLedgerText(legacy)
    );
    assert.equal(plan.sequence, 1);
    assert.equal(plan.appendPrefix, "");
  }
);

test(
  "append plan continues a verified chain",
  () => {
    const fixture =
      createTwoEventLedger();

    const plan =
      planReceiptLedgerAppend(
        fixture.ledgerText
      );

    assert.equal(plan.ok, true);

    if (!plan.ok) {
      throw new Error(
        "EXPECTED_CHAIN_APPEND_PLAN_SUCCESS"
      );
    }

    assert.equal(
      plan.previousHash,
      fixture.second.ledgerEventHash
    );
    assert.equal(plan.sequence, 3);
    assert.equal(
      plan.existingChainEventCount,
      2
    );
  }
);

test(
  "append plan rejects a damaged existing ledger",
  () => {
    const fixture =
      createTwoEventLedger();

    const changed = {
      ...fixture.first,
      protectedPath: ".env.local",
    };

    const damaged =
      JSON.stringify(changed) +
      "\n" +
      JSON.stringify(fixture.second) +
      "\n";

    const plan =
      planReceiptLedgerAppend(damaged);

    assert.equal(plan.ok, false);

    if (plan.ok) {
      throw new Error(
        "EXPECTED_APPEND_PLAN_FAILURE"
      );
    }

    assert.equal(
      plan.issueCode,
      "CHAIN_EVENT_HASH_MISMATCH"
    );
  }
);
