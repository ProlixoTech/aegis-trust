import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { LedgerWriter } from "./ledgerWriter";
import { ReceiptWriter } from "./receiptWriter";
import type { LedgerEvent } from "../packages/aegis-core";

import {
  SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION,
  evaluateSessionHandoffRuntimeGate,
  type SessionHandoffHashBinding,
  type SessionHandoffNonceInput,
  type SessionHandoffOperationClass,
  type SessionHandoffVerificationInput,
} from "./sessionHandoffRuntimeGate";

interface ReceiptLedgerFixture {
  readonly directory: string;
  readonly ledgerText: string;
  readonly receiptText: string;
}

type VerificationOverrides =
  Partial<
    Omit<
      SessionHandoffVerificationInput,
      | "canonicalState"
      | "checker"
      | "authority"
      | "nonce"
      | "receiptText"
      | "ledgerText"
    >
  > & {
    readonly canonicalState?:
      Partial<SessionHandoffHashBinding>;
    readonly checker?:
      Partial<SessionHandoffHashBinding>;
    readonly authority?:
      Partial<SessionHandoffHashBinding>;
    readonly nonce?:
      Partial<SessionHandoffNonceInput>;
    readonly receiptText?: string;
    readonly ledgerText?: string;
  };

function event(): LedgerEvent {
  return {
    schemaVersion: 1,
    eventType: "snapshot_created",
    timestamp:
      "2026-07-25T00:00:00.000Z",
    protectedPath: ".env",
    snapshotId:
      "c07-session-handoff-runtime-gate",
    success: true,
    verified: true,
    snapshotHash: "a".repeat(64),
    reason:
      "pre_save_snapshot_created",
  };
}

async function createFixture():
Promise<ReceiptLedgerFixture> {
  const directory =
    fs.mkdtempSync(
      path.join(
        os.tmpdir(),
        "aegis-c07-runtime-gate-"
      )
    );

  const ledgerWriter =
    new LedgerWriter(directory);

  assert.equal(
    await ledgerWriter.append(event()),
    true
  );

  const receiptResult =
    await new ReceiptWriter(
      directory
    ).generate();

  assert.equal(receiptResult.ok, true);
  assert.equal(
    typeof receiptResult.receiptPath,
    "string"
  );

  const ledgerText =
    fs.readFileSync(
      path.join(
        directory,
        "ledger",
        "events.jsonl"
      ),
      "utf8"
    );

  const receiptText =
    fs.readFileSync(
      receiptResult.receiptPath as string,
      "utf8"
    );

  return {
    directory,
    ledgerText,
    receiptText,
  };
}

function removeFixture(
  fixture: ReceiptLedgerFixture
): void {
  fs.rmSync(
    fixture.directory,
    {
      recursive: true,
      force: true,
    }
  );
}

function hashBinding(
  value: string
): SessionHandoffHashBinding {
  return {
    expectedSha256: value,
    actualSha256: value,
  };
}

function validVerification(
  fixture: ReceiptLedgerFixture,
  overrides:
    VerificationOverrides = {}
): SessionHandoffVerificationInput {
  const canonicalState =
    hashBinding("a".repeat(64));

  const checker =
    hashBinding("b".repeat(64));

  const authority =
    hashBinding("c".repeat(64));

  const nonce:
    SessionHandoffNonceInput = {
      expectedNonce:
        "nonce-current",
      presentedNonce:
        "nonce-current",
      status: "PENDING",
      previousNonce:
        "nonce-previous",
      previousNonceStatus:
        "CONSUMED",
      inheritPreviousExecutionAuthority:
        false,
  };

  return {
    canonicalState: {
      ...canonicalState,
      ...overrides.canonicalState,
    },
    checker: {
      ...checker,
      ...overrides.checker,
    },
    authority: {
      ...authority,
      ...overrides.authority,
    },
    signatureVerified:
      overrides.signatureVerified ??
      true,
    freshnessVerified:
      overrides.freshnessVerified ??
      true,
    antiRollbackVerified:
      overrides.antiRollbackVerified ??
      true,
    identityVerified:
      overrides.identityVerified ??
      true,
    nonce: {
      ...nonce,
      ...overrides.nonce,
    },
    dependencyClosureVerified:
      overrides
        .dependencyClosureVerified ??
      true,
    authorityClosureVerified:
      overrides
        .authorityClosureVerified ??
      true,
    currentStatePointerClosureVerified:
      overrides
        .currentStatePointerClosureVerified ??
      true,
    receiptText:
      overrides.receiptText ??
      fixture.receiptText,
    ledgerText:
      overrides.ledgerText ??
      fixture.ledgerText,
  };
}

test(
  "bootstrap permits read-only inspection before authorization",
  async () => {
    const fixture =
      await createFixture();

    try {
      const result =
        evaluateSessionHandoffRuntimeGate({
          operationClass: "READ_ONLY",
          verification:
            validVerification(
              fixture,
              {
                signatureVerified:
                  false,
              }
            ),
        });

      assert.equal(
        result.operationAllowed,
        true
      );

      assert.equal(
        result.runtimeState,
        "HANDOFF_BOOTSTRAP_READ_ONLY"
      );

      assert.equal(
        result.verificationState,
        "BLOCKED"
      );

      assert.equal(
        result.firstRequiredAction,
        SESSION_HANDOFF_BOOTSTRAP_FIRST_ACTION
      );

      assert.equal(
        result.issueCodes.includes(
          "SIGNATURE_VERIFICATION_FAILED"
        ),
        true
      );
    } finally {
      removeFixture(fixture);
    }
  }
);

test(
  "bootstrap blocks every effect operation before authorization",
  async () => {
    const fixture =
      await createFixture();

    try {
      const effectOperations:
        SessionHandoffOperationClass[] = [
          "MUTATION",
          "EXECUTE",
          "NETWORK",
          "DELETE",
          "PACKAGE",
          "EXPORT",
        ];

      for (
        const operationClass of
        effectOperations
      ) {
        const result =
          evaluateSessionHandoffRuntimeGate({
            operationClass,
            verification:
              validVerification(
                fixture,
                {
                  freshnessVerified:
                    false,
                }
              ),
          });

        assert.equal(
          result.operationAllowed,
          false,
          operationClass
        );

        assert.equal(
          result.runtimeState,
          "BLOCKED",
          operationClass
        );
      }
    } finally {
      removeFixture(fixture);
    }
  }
);

test(
  "complete verification grants session authority",
  async () => {
    const fixture =
      await createFixture();

    try {
      const result =
        evaluateSessionHandoffRuntimeGate({
          operationClass: "MUTATION",
          verification:
            validVerification(
              fixture
            ),
        });

      assert.equal(
        result.operationAllowed,
        true
      );

      assert.equal(
        result.runtimeState,
        "SESSION_AUTHORIZED"
      );

      assert.equal(
        result.verificationState,
        "SESSION_AUTHORIZED"
      );

      assert.deepEqual(
        result.issueCodes,
        []
      );
    } finally {
      removeFixture(fixture);
    }
  }
);

test(
  "local canonical checker and authority trust-root failures block",
  async () => {
    const fixture =
      await createFixture();

    try {
      const cases: Array<{
        readonly overrides:
          VerificationOverrides;
        readonly issueCode: string;
      }> = [
        {
          overrides: {
            canonicalState: {
              actualSha256:
                "d".repeat(64),
            },
          },
          issueCode:
            "CANONICAL_STATE_HASH_MISMATCH",
        },
        {
          overrides: {
            checker: {
              actualSha256:
                "d".repeat(64),
            },
          },
          issueCode:
            "CHECKER_HASH_MISMATCH",
        },
        {
          overrides: {
            authority: {
              actualSha256:
                "d".repeat(64),
            },
          },
          issueCode:
            "AUTHORITY_HASH_MISMATCH",
        },
      ];

      for (const item of cases) {
        const result =
          evaluateSessionHandoffRuntimeGate({
            operationClass: "EXECUTE",
            verification:
              validVerification(
                fixture,
                item.overrides
              ),
          });

        assert.equal(
          result.operationAllowed,
          false,
          item.issueCode
        );

        assert.equal(
          result.issueCodes.includes(
            item.issueCode as never
          ),
          true,
          item.issueCode
        );
      }
    } finally {
      removeFixture(fixture);
    }
  }
);

test(
  "signature freshness anti-rollback and identity failures block",
  async () => {
    const fixture =
      await createFixture();

    try {
      const cases: Array<{
        readonly overrides:
          VerificationOverrides;
        readonly issueCode: string;
      }> = [
        {
          overrides: {
            signatureVerified: false,
          },
          issueCode:
            "SIGNATURE_VERIFICATION_FAILED",
        },
        {
          overrides: {
            freshnessVerified: false,
          },
          issueCode:
            "FRESHNESS_VERIFICATION_FAILED",
        },
        {
          overrides: {
            antiRollbackVerified:
              false,
          },
          issueCode:
            "ANTI_ROLLBACK_VERIFICATION_FAILED",
        },
        {
          overrides: {
            identityVerified: false,
          },
          issueCode:
            "IDENTITY_VERIFICATION_FAILED",
        },
      ];

      for (const item of cases) {
        const result =
          evaluateSessionHandoffRuntimeGate({
            operationClass: "NETWORK",
            verification:
              validVerification(
                fixture,
                item.overrides
              ),
          });

        assert.equal(
          result.operationAllowed,
          false,
          item.issueCode
        );

        assert.equal(
          result.issueCodes.includes(
            item.issueCode as never
          ),
          true,
          item.issueCode
        );
      }
    } finally {
      removeFixture(fixture);
    }
  }
);

test(
  "nonce continuity failures and previous authority inheritance block",
  async () => {
    const fixture =
      await createFixture();

    try {
      const cases: Array<{
        readonly nonce:
          Partial<SessionHandoffNonceInput>;
        readonly issueCode: string;
      }> = [
        {
          nonce: {
            status: "CONSUMED",
          },
          issueCode:
            "NONCE_NOT_PENDING",
        },
        {
          nonce: {
            presentedNonce:
              "nonce-other",
          },
          issueCode:
            "NONCE_MISMATCH",
        },
        {
          nonce: {
            presentedNonce:
              "nonce-previous",
            expectedNonce:
              "nonce-previous",
          },
          issueCode:
            "NONCE_REUSE",
        },
        {
          nonce: {
            previousNonceStatus:
              "PENDING",
          },
          issueCode:
            "PREVIOUS_NONCE_NOT_TERMINAL",
        },
        {
          nonce: {
            inheritPreviousExecutionAuthority:
              true,
          },
          issueCode:
            "PREVIOUS_NONCE_AUTHORITY_INHERITANCE_FORBIDDEN",
        },
      ];

      for (const item of cases) {
        const result =
          evaluateSessionHandoffRuntimeGate({
            operationClass: "DELETE",
            verification:
              validVerification(
                fixture,
                {
                  nonce: item.nonce,
                }
              ),
          });

        assert.equal(
          result.operationAllowed,
          false,
          item.issueCode
        );

        assert.equal(
          result.issueCodes.includes(
            item.issueCode as never
          ),
          true,
          item.issueCode
        );

        assert.equal(
          result
            .previousNonceExecutionAuthorityInherited,
          false
        );
      }
    } finally {
      removeFixture(fixture);
    }
  }
);

test(
  "each closure fails independently and blocks authorization",
  async () => {
    const fixture =
      await createFixture();

    try {
      const cases: Array<{
        readonly overrides:
          VerificationOverrides;
        readonly issueCode: string;
      }> = [
        {
          overrides: {
            dependencyClosureVerified:
              false,
          },
          issueCode:
            "DEPENDENCY_CLOSURE_FAILED",
        },
        {
          overrides: {
            authorityClosureVerified:
              false,
          },
          issueCode:
            "AUTHORITY_CLOSURE_FAILED",
        },
        {
          overrides: {
            currentStatePointerClosureVerified:
              false,
          },
          issueCode:
            "CURRENT_STATE_POINTER_CLOSURE_FAILED",
        },
      ];

      for (const item of cases) {
        const result =
          evaluateSessionHandoffRuntimeGate({
            operationClass: "PACKAGE",
            verification:
              validVerification(
                fixture,
                item.overrides
              ),
          });

        assert.equal(
          result.operationAllowed,
          false,
          item.issueCode
        );

        assert.equal(
          result.issueCodes.includes(
            item.issueCode as never
          ),
          true,
          item.issueCode
        );
      }
    } finally {
      removeFixture(fixture);
    }
  }
);

test(
  "receipt ledger damage blocks and product claims remain false",
  async () => {
    const fixture =
      await createFixture();

    try {
      const damagedLedger =
        fixture.ledgerText.replace(
          '"protectedPath":".env"',
          '"protectedPath":".env.local"'
        );

      assert.notEqual(
        damagedLedger,
        fixture.ledgerText
      );

      const result =
        evaluateSessionHandoffRuntimeGate({
          operationClass: "EXPORT",
          verification:
            validVerification(
              fixture,
              {
                ledgerText:
                  damagedLedger,
              }
            ),
        });

      assert.equal(
        result.operationAllowed,
        false
      );

      assert.equal(
        result.issueCodes.includes(
          "RECEIPT_LEDGER_INTEGRITY_FAILED"
        ),
        true
      );

      assert.equal(
        typeof result
          .receiptLedgerIssueCode,
        "string"
      );

      assert.equal(
        result.productPassClaimed,
        false
      );

      assert.equal(
        result.finalClaimed,
        false
      );

      assert.equal(
        result.releaseReadyClaimed,
        false
      );

      assert.equal(
        result.uploadReadyClaimed,
        false
      );
    } finally {
      removeFixture(fixture);
    }
  }
);