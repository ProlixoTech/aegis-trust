import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { LedgerWriter } from "./ledgerWriter";
import { ReceiptWriter } from "./receiptWriter";
import type { LedgerEvent } from "../packages/aegis-core";

import {
  SessionHandoffLocalVerificationAdapter,
  computeSessionHandoffDescriptorHash,
  sha256SessionHandoffBytes,
  type SessionHandoffLocalVerificationAdapterInput,
  type SessionHandoffLocalVerificationBytes,
  type SessionHandoffLocalVerificationProviders,
  type SessionHandoffPersistentSequenceStore,
  type SessionHandoffCurrentStatePointerClosureV1,
  type SessionHandoffVerificationCapsuleUnsignedV1,
  type SessionHandoffVerificationCapsuleV1,
} from "./sessionHandoffLocalVerificationAdapter";

interface ReceiptLedgerFixture {
  readonly directory: string;
  readonly ledgerText: string;
  readonly receiptText: string;
}

class MemorySequenceStore
  implements SessionHandoffPersistentSequenceStore {
  highest: number | null = null;
  claimCount = 0;
  rejectClaims = false;

  async readHighestAcceptedSequence():
  Promise<number | null> {
    return this.highest;
  }

  async claimSequence(input: {
    readonly sequence: number;
  }): Promise<boolean> {
    this.claimCount += 1;

    if (
      this.rejectClaims ||
      (
        this.highest !== null &&
        input.sequence <= this.highest
      )
    ) {
      return false;
    }

    this.highest =
      input.sequence;

    return true;
  }
}

interface TestEnvironment {
  readonly now: Date;
  readonly projectId: string;
  readonly signerId: string;
  readonly workspaceId: string;
  readonly sessionId: string;
  readonly nonceHex: string;
  readonly noncePrefixed: string;
  readonly snapshotBindingSha256: string;
  readonly canonicalStateBytes: Buffer;
  readonly checkerBytes: Buffer;
  readonly authorityBytes: Buffer;
  readonly currentStatePointerBytes: Buffer;
  readonly requiredEntries:
    Map<string, Buffer>;
  readonly sequenceStore:
    MemorySequenceStore;
  readonly fixture:
    ReceiptLedgerFixture;

  canonicalAuthorityState:
    Record<string, unknown>;

  runtimeSession:
    Record<string, unknown>;

  authorityBinding:
    Record<string, unknown>;

  authorityVerificationResult:
    | "verified"
    | "authority_drift"
    | "snapshot_failed";

  signatureResult: boolean;
  receiptText: string;
  ledgerText: string;
}

// NT19_A2_FIELD_LEVEL_CURRENT_STATE_POINTER_CLOSURE

const NT19_CURRENT_STATE_POINTER_CLOSURE_KEYS = [
  "currentPolicyPointer",
  "currentRulesetPointer",
  "currentActionPointer",
  "currentLockPointer",
  "currentReceiptPointer",
  "currentPhase",
  "currentLock",
  "currentResultLock",
  "currentResultLockFile",
  "policyVersion",
  "rulesetVersion",
  "capabilityManifest",
] as const;

const NT19_CURRENT_STATE_DOCUMENT_KEY_BY_CLOSURE_KEY:
  Readonly<
    Record<
      keyof SessionHandoffCurrentStatePointerClosureV1,
      string
    >
  > = Object.freeze({
    currentPolicyPointer: "CURRENT_POLICY_POINTER",
    currentRulesetPointer: "CURRENT_RULESET_POINTER",
    currentActionPointer: "CURRENT_ACTION_POINTER",
    currentLockPointer: "CURRENT_LOCK_POINTER",
    currentReceiptPointer: "CURRENT_RECEIPT_POINTER",
    currentPhase: "CURRENT_PHASE",
    currentLock: "CURRENT_LOCK",
    currentResultLock: "CURRENT_RESULT_LOCK",
    currentResultLockFile: "CURRENT_RESULT_LOCK_FILE",
    policyVersion: "POLICY_VERSION",
    rulesetVersion: "RULESET_VERSION",
    capabilityManifest: "CAPABILITY_MANIFEST",
  });

const NT19_CURRENT_STATE_POINTER_CLOSURE:
  SessionHandoffCurrentStatePointerClosureV1 =
    Object.freeze({
      currentPolicyPointer: "policy://c10/current",
      currentRulesetPointer: "ruleset://c10/current",
      currentActionPointer: "action://c10/current",
      currentLockPointer: "lock://c10/current",
      currentReceiptPointer: "receipt://c10/current",
      currentPhase: "C-10",
      currentLock: "NT19",
      currentResultLock: "PENDING",
      currentResultLockFile:
        ".aegis/result-locks/c10.lock",
      policyVersion: "policy-v1",
      rulesetVersion: "ruleset-v1",
      capabilityManifest:
        "capability-manifest-v1",
    });

function nt19CurrentStatePointerText(
  options: {
    readonly overrides?: Partial<
      SessionHandoffCurrentStatePointerClosureV1
    >;
    readonly omitDocumentKey?: string;
    readonly duplicateDocumentKey?: string;
  } = {}
): string {
  const closure:
    SessionHandoffCurrentStatePointerClosureV1 =
      Object.freeze({
        ...NT19_CURRENT_STATE_POINTER_CLOSURE,
        ...(options.overrides ?? {}),
      });

  const historicalLines: string[] = [];
  const finalLines: string[] = [];

  for (
    const closureKey of
      NT19_CURRENT_STATE_POINTER_CLOSURE_KEYS
  ) {
    const documentKey =
      NT19_CURRENT_STATE_DOCUMENT_KEY_BY_CLOSURE_KEY[
        closureKey
      ];

    historicalLines.push(
      documentKey +
      "=historical-" +
      String(closure[closureKey])
    );

    if (
      documentKey !== options.omitDocumentKey
    ) {
      const line =
        documentKey +
        "=" +
        String(closure[closureKey]);

      finalLines.push(line);

      if (
        documentKey ===
        options.duplicateDocumentKey
      ) {
        finalLines.push(line);
      }
    }
  }

  return [
    "CURRENT_TASK=C-10",
    ...historicalLines,
    "CURRENT_TASK=C-09",
    "CURRENT_TASK=C-10",
    ...finalLines,
  ].join("\n") + "\n";
}


function ledgerEvent(): LedgerEvent {
  return {
    schemaVersion: 1,
    eventType: "snapshot_created",
    timestamp:
      "2026-07-25T12:00:00.000Z",
    protectedPath: ".env",
    snapshotId:
      "c07-local-verification-adapter",
    success: true,
    verified: true,
    snapshotHash: "a".repeat(64),
    reason:
      "pre_save_snapshot_created",
  };
}

async function createReceiptLedgerFixture():
Promise<ReceiptLedgerFixture> {
  const directory =
    fs.mkdtempSync(
      path.join(
        os.tmpdir(),
        "aegis-c07-local-adapter-"
      )
    );

  const ledgerWriter =
    new LedgerWriter(directory);

  assert.equal(
    await ledgerWriter.append(
      ledgerEvent()
    ),
    true
  );

  const receiptResult =
    await new ReceiptWriter(
      directory
    ).generate();

  assert.equal(
    receiptResult.ok,
    true
  );

  assert.equal(
    typeof receiptResult.receiptPath,
    "string"
  );

  return {
    directory,
    ledgerText:
      fs.readFileSync(
        path.join(
          directory,
          "ledger",
          "events.jsonl"
        ),
        "utf8"
      ),
    receiptText:
      fs.readFileSync(
        receiptResult.receiptPath as string,
        "utf8"
      ),
  };
}

async function createEnvironment():
Promise<TestEnvironment> {
  const fixture =
    await createReceiptLedgerFixture();

  const now =
    new Date(
      "2026-07-25T12:00:00.000Z"
    );

  const projectId =
    "prolixo-aegis-personal";

  const signerId =
    "trusted-local-signer-v1";

  const workspaceId =
    "sha256:" +
    "b".repeat(64);

  const sessionId =
    "c".repeat(48);

  const nonceHex =
    "d".repeat(64);

  const noncePrefixed =
    "sha256:" +
    nonceHex;

  const snapshotBindingSha256 =
    "sha256:" +
    "e".repeat(64);

  const canonicalStateBytes =
    Buffer.from(
      "canonical-current-state-v1",
      "utf8"
    );

  const checkerBytes =
    Buffer.from(
      "canonical-checker-v1",
      "utf8"
    );

  const authorityBytes =
    Buffer.from(
      "canonical-authority-v1",
      "utf8"
    );

  const currentStatePointerBytes =
    Buffer.from(
      nt19CurrentStatePointerText(),
      "utf8"
    );

  const requiredEntries =
    new Map<string, Buffer>([
      [
        "manifest.json",
        Buffer.from(
          "manifest-v1",
          "utf8"
        ),
      ],
      [
        "authority.json",
        Buffer.from(
          "authority-entry-v1",
          "utf8"
        ),
      ],
    ]);

  const sequenceStore =
    new MemorySequenceStore();

  return {
    now,
    projectId,
    signerId,
    workspaceId,
    sessionId,
    nonceHex,
    noncePrefixed,
    snapshotBindingSha256,
    canonicalStateBytes,
    checkerBytes,
    authorityBytes,
    currentStatePointerBytes,
    requiredEntries,
    sequenceStore,
    fixture,
    canonicalAuthorityState: {
      projectIdentity:
        projectId,
      workspaceId,
      revision: 7,
      sessionId,
      approvalNonceSha256:
        noncePrefixed,
      approvalNonceState:
        "ISSUED",
      verificationResult:
        "VERIFIED",
    },
    runtimeSession: {
      sessionId,
      approvalNonceSha256:
        nonceHex,
      createdAt:
        "2026-07-25T11:59:00.000Z",
      lifecyclePhase:
        "ALLOW_PENDING_EXECUTION",
      nonceConsumed: false,
      expiresAt: null,
    },
    authorityBinding: {
      authorityRevision: 7,
      workspaceId,
      snapshotBindingSha256,
    },
    authorityVerificationResult:
      "verified",
    signatureResult: true,
    receiptText:
      fixture.receiptText,
    ledgerText:
      fixture.ledgerText,
  };
}

function cleanupEnvironment(
  environment: TestEnvironment
): void {
  fs.rmSync(
    environment.fixture.directory,
    {
      recursive: true,
      force: true,
    }
  );
}

function requiredEntryHashes(
  environment: TestEnvironment
): Readonly<Record<string, string>> {
  const result:
    Record<string, string> = {};

  for (
    const [name, bytes] of
    [...environment.requiredEntries]
      .sort(
        ([left], [right]) =>
          left.localeCompare(right)
      )
  ) {
    result[name] =
      sha256SessionHandoffBytes(
        bytes
      );
  }

  return result;
}

function unsignedCapsule(
  environment: TestEnvironment,
  overrides:
    Partial<
      SessionHandoffVerificationCapsuleUnsignedV1
    > = {}
): SessionHandoffVerificationCapsuleUnsignedV1 {
  const base:
    SessionHandoffVerificationCapsuleUnsignedV1 = {
    capsuleSchemaVersion:
      "1.0.0",
    capsuleKind:
      "HANDOFF_RESUME",
    firstRequiredAction:
      "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    projectId:
      environment.projectId,
    workspaceId:
      environment.workspaceId,
    sessionId:
      environment.sessionId,
    approvalNonceSha256:
      environment.noncePrefixed,
    signerId:
      environment.signerId,
    issuedAt:
      "2026-07-25T11:59:00.000Z",
    expiresAt:
      "2026-07-25T12:10:00.000Z",
    handoffSequence: 1,
    authorityRevision: 7,
    snapshotBindingSha256:
      environment.snapshotBindingSha256,
    canonicalStateSha256:
      sha256SessionHandoffBytes(
        environment.canonicalStateBytes
      ),
    checkerSha256:
      sha256SessionHandoffBytes(
        environment.checkerBytes
      ),
    authoritySha256:
      sha256SessionHandoffBytes(
        environment.authorityBytes
      ),
    currentStatePointerSha256:
      sha256SessionHandoffBytes(
        environment
          .currentStatePointerBytes
      ),
    currentStatePointerClosure:
      NT19_CURRENT_STATE_POINTER_CLOSURE,
    requiredEntryHashes:
      requiredEntryHashes(
        environment
      ),
  };

  return {
    ...base,
    ...overrides,
    requiredEntryHashes:
      overrides.requiredEntryHashes ??
      base.requiredEntryHashes,
  };
}

function signedCapsule(
  environment: TestEnvironment,
  overrides:
    Partial<
      SessionHandoffVerificationCapsuleUnsignedV1
    > = {},
  signatureOverride?: string
): SessionHandoffVerificationCapsuleV1 {
  const unsigned =
    unsignedCapsule(
      environment,
      overrides
    );

  const descriptorHash =
    computeSessionHandoffDescriptorHash(
      unsigned
    );

  return {
    ...unsigned,
    descriptorHash,
    signature:
      signatureOverride ??
      "sig:" +
      descriptorHash,
  };
}

function providersFor(
  environment: TestEnvironment,
  options: {
    readonly omitSignatureVerifier?: boolean;
    readonly omitSequenceStore?: boolean;
  } = {}
): SessionHandoffLocalVerificationProviders {
  const providers:
    SessionHandoffLocalVerificationProviders = {
    canonicalAuthorityReader: {
      getState: () =>
        environment
          .canonicalAuthorityState,
    },
    runtimeSessionReader: {
      readSession: sessionId =>
        sessionId ===
        environment.sessionId
          ? environment.runtimeSession
          : null,
    },
    authorityBindingReadPort: {
      readCurrentBinding: async () =>
        environment.authorityBinding,
    },
    authorityBindingVerifier: {
      verify: async () =>
        environment
          .authorityVerificationResult,
    },
    readCanonicalStateBytes:
      async () =>
        environment
          .canonicalStateBytes,
    readCheckerBytes:
      async () =>
        environment.checkerBytes,
    readAuthorityBytes:
      async () =>
        environment.authorityBytes,
    readCurrentStatePointerBytes:
      async () =>
        environment
          .currentStatePointerBytes,
    readRequiredEntryBytes:
      async (
        entryName: string
      ): Promise<
        SessionHandoffLocalVerificationBytes | null
      > =>
        environment.requiredEntries
          .get(entryName) ??
        null,
    readReceiptText:
      async () =>
        environment.receiptText,
    readLedgerText:
      async () =>
        environment.ledgerText,
    now: () =>
      new Date(
        environment.now.getTime()
      ),
    signatureVerifier:
      options.omitSignatureVerifier
        ? undefined
        : {
            verify: async input =>
              environment.signatureResult &&
              input.signerId ===
                environment.signerId &&
              input.signature ===
                "sig:" +
                input.descriptorHash,
          },
    sequenceStore:
      options.omitSequenceStore
        ? undefined
        : environment.sequenceStore,
  };

  return providers;
}

function adapterFor(
  environment: TestEnvironment,
  options: {
    readonly omitSignatureVerifier?: boolean;
    readonly omitSequenceStore?: boolean;
  } = {}
): SessionHandoffLocalVerificationAdapter {
  return new SessionHandoffLocalVerificationAdapter(
    {
      expectedProjectId:
        environment.projectId,
      expectedSignerIds: [
        environment.signerId,
      ],
      maximumCapsuleAgeMilliseconds:
        10 * 60 * 1000,
    },
    providersFor(
      environment,
      options
    )
  );
}

function inputFor(
  environment: TestEnvironment,
  capsule:
    SessionHandoffVerificationCapsuleV1,
  operationClass: unknown =
    "EXECUTE"
): SessionHandoffLocalVerificationAdapterInput {
  return {
    operationClass,
    capsuleText:
      JSON.stringify(capsule),
    presentedSessionId:
      environment.sessionId,
    presentedApprovalNonceSha256:
      environment.noncePrefixed,
  };
}

test(
  "complete trusted local evidence authorizes one effect operation",
  async () => {
    const environment =
      await createEnvironment();

    try {
      const result =
        await adapterFor(
          environment
        ).evaluate(
          inputFor(
            environment,
            signedCapsule(
              environment
            )
          )
        );

      assert.equal(
        result.authorized,
        true
      );

      assert.equal(
        result.gateResult.runtimeState,
        "SESSION_AUTHORIZED"
      );

      assert.equal(
        result.sequenceClaimed,
        true
      );

      assert.equal(
        environment.sequenceStore
          .claimCount,
        1
      );

      assert.deepEqual(
        result.adapterIssueCodes,
        []
      );
    } finally {
      cleanupEnvironment(
        environment
      );
    }
  }
);

test(
  "caller supplied verification booleans are ignored",
  async () => {
    const environment =
      await createEnvironment();

    try {
      const baseInput =
        inputFor(
          environment,
          signedCapsule(
            environment
          )
        );

      const injectedInput = {
        ...baseInput,
        signatureVerified: true,
        freshnessVerified: true,
        antiRollbackVerified: true,
        identityVerified: true,
      } as unknown as
        SessionHandoffLocalVerificationAdapterInput;

      const result =
        await adapterFor(
          environment,
          {
            omitSignatureVerifier:
              true,
          }
        ).evaluate(
          injectedInput
        );

      assert.equal(
        result.authorized,
        false
      );

      assert.equal(
        result
          .callerVerificationBooleanAccepted,
        false
      );

      assert.equal(
        result.adapterIssueCodes.includes(
          "SIGNATURE_PROVIDER_UNAVAILABLE"
        ),
        true
      );

      assert.equal(
        environment.sequenceStore
          .claimCount,
        0
      );
    } finally {
      cleanupEnvironment(
        environment
      );
    }
  }
);

test(
  "missing or failing trusted signature verification blocks",
  async () => {
    const missingEnvironment =
      await createEnvironment();

    const failingEnvironment =
      await createEnvironment();

    try {
      const missingResult =
        await adapterFor(
          missingEnvironment,
          {
            omitSignatureVerifier:
              true,
          }
        ).evaluate(
          inputFor(
            missingEnvironment,
            signedCapsule(
              missingEnvironment
            )
          )
        );

      assert.equal(
        missingResult.authorized,
        false
      );

      assert.equal(
        missingResult
          .adapterIssueCodes
          .includes(
            "SIGNATURE_PROVIDER_UNAVAILABLE"
          ),
        true
      );

      failingEnvironment
        .signatureResult =
        false;

      const failingResult =
        await adapterFor(
          failingEnvironment
        ).evaluate(
          inputFor(
            failingEnvironment,
            signedCapsule(
              failingEnvironment
            )
          )
        );

      assert.equal(
        failingResult.authorized,
        false
      );

      assert.equal(
        failingResult
          .adapterIssueCodes
          .includes(
            "SIGNATURE_VERIFICATION_FAILED"
          ),
        true
      );
    } finally {
      cleanupEnvironment(
        missingEnvironment
      );

      cleanupEnvironment(
        failingEnvironment
      );
    }
  }
);

test(
  "stale and expired capsules block without claiming sequence",
  async () => {
    const environment =
      await createEnvironment();

    try {
      const staleResult =
        await adapterFor(
          environment
        ).evaluate(
          inputFor(
            environment,
            signedCapsule(
              environment,
              {
                issuedAt:
                  "2026-07-25T11:30:00.000Z",
                expiresAt:
                  "2026-07-25T12:30:00.000Z",
              }
            )
          )
        );

      assert.equal(
        staleResult.authorized,
        false
      );

      assert.equal(
        staleResult
          .adapterIssueCodes
          .includes(
            "CAPSULE_FRESHNESS_FAILED"
          ),
        true
      );

      const expiredResult =
        await adapterFor(
          environment
        ).evaluate(
          inputFor(
            environment,
            signedCapsule(
              environment,
              {
                expiresAt:
                  "2026-07-25T11:59:59.000Z",
              }
            )
          )
        );

      assert.equal(
        expiredResult.authorized,
        false
      );

      assert.equal(
        expiredResult
          .adapterIssueCodes
          .includes(
            "CAPSULE_FRESHNESS_FAILED"
          ),
        true
      );

      assert.equal(
        environment.sequenceStore
          .claimCount,
        0
      );
    } finally {
      cleanupEnvironment(
        environment
      );
    }
  }
);

test(
  "persistent sequence rollback and replay are blocked",
  async () => {
    const environment =
      await createEnvironment();

    try {
      environment.sequenceStore.highest =
        3;

      const replayResult =
        await adapterFor(
          environment
        ).evaluate(
          inputFor(
            environment,
            signedCapsule(
              environment,
              {
                handoffSequence: 3,
              }
            )
          )
        );

      assert.equal(
        replayResult.authorized,
        false
      );

      assert.equal(
        replayResult
          .adapterIssueCodes
          .includes(
            "HANDOFF_SEQUENCE_REPLAY_OR_ROLLBACK"
          ),
        true
      );

      const rollbackResult =
        await adapterFor(
          environment
        ).evaluate(
          inputFor(
            environment,
            signedCapsule(
              environment,
              {
                handoffSequence: 2,
              }
            )
          )
        );

      assert.equal(
        rollbackResult.authorized,
        false
      );

      assert.equal(
        rollbackResult
          .adapterIssueCodes
          .includes(
            "HANDOFF_SEQUENCE_REPLAY_OR_ROLLBACK"
          ),
        true
      );

      assert.equal(
        environment.sequenceStore
          .claimCount,
        0
      );
    } finally {
      cleanupEnvironment(
        environment
      );
    }
  }
);

test(
  "workspace session and nonce identity mismatches block",
  async () => {
    const environment =
      await createEnvironment();

    try {
      const workspaceResult =
        await adapterFor(
          environment
        ).evaluate(
          inputFor(
            environment,
            signedCapsule(
              environment,
              {
                workspaceId:
                  "sha256:" +
                  "f".repeat(64),
              }
            )
          )
        );

      assert.equal(
        workspaceResult.authorized,
        false
      );

      assert.equal(
        workspaceResult
          .adapterIssueCodes
          .includes(
            "CAPSULE_WORKSPACE_IDENTITY_MISMATCH"
          ),
        true
      );

      const sessionInput =
        inputFor(
          environment,
          signedCapsule(
            environment
          )
        );

      const sessionResult =
        await adapterFor(
          environment
        ).evaluate({
          ...sessionInput,
          presentedSessionId:
            "a".repeat(48),
        });

      assert.equal(
        sessionResult.authorized,
        false
      );

      assert.equal(
        sessionResult
          .adapterIssueCodes
          .includes(
            "CAPSULE_SESSION_ID_MISMATCH"
          ),
        true
      );

      const nonceResult =
        await adapterFor(
          environment
        ).evaluate({
          ...sessionInput,
          presentedApprovalNonceSha256:
            "sha256:" +
            "9".repeat(64),
        });

      assert.equal(
        nonceResult.authorized,
        false
      );

      assert.equal(
        nonceResult
          .adapterIssueCodes
          .includes(
            "CAPSULE_NONCE_HASH_MISMATCH"
          ),
        true
      );
    } finally {
      cleanupEnvironment(
        environment
      );
    }
  }
);

test(
  "authority drift and snapshot binding mismatch block",
  async () => {
    const driftEnvironment =
      await createEnvironment();

    const snapshotEnvironment =
      await createEnvironment();

    try {
      driftEnvironment
        .authorityVerificationResult =
        "authority_drift";

      const driftResult =
        await adapterFor(
          driftEnvironment
        ).evaluate(
          inputFor(
            driftEnvironment,
            signedCapsule(
              driftEnvironment
            )
          )
        );

      assert.equal(
        driftResult.authorized,
        false
      );

      assert.equal(
        driftResult
          .adapterIssueCodes
          .includes(
            "AUTHORITY_BINDING_VERIFICATION_FAILED"
          ),
        true
      );

      snapshotEnvironment
        .authorityBinding = {
        ...snapshotEnvironment
          .authorityBinding,
        snapshotBindingSha256:
          "sha256:" +
          "1".repeat(64),
      };

      snapshotEnvironment
        .authorityVerificationResult =
        "snapshot_failed";

      const snapshotResult =
        await adapterFor(
          snapshotEnvironment
        ).evaluate(
          inputFor(
            snapshotEnvironment,
            signedCapsule(
              snapshotEnvironment
            )
          )
        );

      assert.equal(
        snapshotResult.authorized,
        false
      );

      assert.equal(
        snapshotResult
          .adapterIssueCodes
          .includes(
            "AUTHORITY_BINDING_MISMATCH"
          ),
        true
      );

      assert.equal(
        snapshotResult
          .adapterIssueCodes
          .includes(
            "AUTHORITY_BINDING_VERIFICATION_FAILED"
          ),
        true
      );
    } finally {
      cleanupEnvironment(
        driftEnvironment
      );

      cleanupEnvironment(
        snapshotEnvironment
      );
    }
  }
);

test(
  "required entry tampering blocks dependency closure",
  async () => {
    const environment =
      await createEnvironment();

    try {
      const capsule =
        signedCapsule(
          environment
        );

      environment.requiredEntries.set(
        "manifest.json",
        Buffer.from(
          "tampered-manifest",
          "utf8"
        )
      );

      const result =
        await adapterFor(
          environment
        ).evaluate(
          inputFor(
            environment,
            capsule
          )
        );

      assert.equal(
        result.authorized,
        false
      );

      assert.equal(
        result.adapterIssueCodes.includes(
          "REQUIRED_ENTRY_HASH_MISMATCH"
        ),
        true
      );

      assert.equal(
        result.gateResult
          .issueCodes.includes(
            "DEPENDENCY_CLOSURE_FAILED"
          ),
        true
      );
    } finally {
      cleanupEnvironment(
        environment
      );
    }
  }
);

test(
  "receipt or ledger tampering blocks local authorization",
  async () => {
    const receiptEnvironment =
      await createEnvironment();

    const ledgerEnvironment =
      await createEnvironment();

    try {
      receiptEnvironment.receiptText +=
        "\nunauthorized-change";

      const receiptResult =
        await adapterFor(
          receiptEnvironment
        ).evaluate(
          inputFor(
            receiptEnvironment,
            signedCapsule(
              receiptEnvironment
            )
          )
        );

      assert.equal(
        receiptResult.authorized,
        false
      );

      assert.equal(
        receiptResult
          .adapterIssueCodes
          .includes(
            "RECEIPT_LEDGER_INTEGRITY_FAILED"
          ),
        true
      );

      const damagedLedger =
        ledgerEnvironment
          .ledgerText
          .replace(
            '"protectedPath":".env"',
            '"protectedPath":".env.local"'
          );

      assert.notEqual(
        damagedLedger,
        ledgerEnvironment.ledgerText
      );

      ledgerEnvironment.ledgerText =
        damagedLedger;

      const ledgerResult =
        await adapterFor(
          ledgerEnvironment
        ).evaluate(
          inputFor(
            ledgerEnvironment,
            signedCapsule(
              ledgerEnvironment
            )
          )
        );

      assert.equal(
        ledgerResult.authorized,
        false
      );

      assert.equal(
        ledgerResult
          .adapterIssueCodes
          .includes(
            "RECEIPT_LEDGER_INTEGRITY_FAILED"
          ),
        true
      );
    } finally {
      cleanupEnvironment(
        receiptEnvironment
      );

      cleanupEnvironment(
        ledgerEnvironment
      );
    }
  }
);

test(
  "insufficient evidence permits bootstrap read-only only and never claims product status",
  async () => {
    const environment =
      await createEnvironment();

    try {
      const result =
        await adapterFor(
          environment,
          {
            omitSignatureVerifier:
              true,
            omitSequenceStore:
              true,
          }
        ).evaluate(
          inputFor(
            environment,
            signedCapsule(
              environment
            ),
            "READ_ONLY"
          )
        );

      assert.equal(
        result.authorized,
        false
      );

      assert.equal(
        result.bootstrapReadOnlyAllowed,
        true
      );

      assert.equal(
        result.gateResult.runtimeState,
        "HANDOFF_BOOTSTRAP_READ_ONLY"
      );

      assert.equal(
        result.sequenceClaimed,
        false
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
      cleanupEnvironment(
        environment
      );
    }
  }
);
// NT19_A2_FIELD_LEVEL_CURRENT_STATE_POINTER_TESTS_BEGIN

test(
  "NT-19 currentPhase mismatch blocks local authorization",
  async () => {
    const environment =
      await createEnvironment();

    try {
      const result =
        await adapterFor(
          environment
        ).evaluate(
          inputFor(
            environment,
            signedCapsule(
              environment,
              {
                currentStatePointerClosure: {
                  ...NT19_CURRENT_STATE_POINTER_CLOSURE,
                  currentPhase: "C-09",
                },
              }
            )
          )
        );

      assert.equal(result.authorized, false);
      assert.equal(result.sequenceClaimed, false);
      assert.equal(
        result.adapterIssueCodes.includes(
          "CURRENT_STATE_POINTER_FIELD_CLOSURE_FAILED"
        ),
        true
      );
      assert.equal(
        result.gateResult.issueCodes.includes(
          "CURRENT_STATE_POINTER_CLOSURE_FAILED"
        ),
        true
      );
    } finally {
      cleanupEnvironment(environment);
    }
  }
);

test(
  "NT-19 currentLock mismatch blocks local authorization",
  async () => {
    const environment =
      await createEnvironment();

    try {
      const result =
        await adapterFor(
          environment
        ).evaluate(
          inputFor(
            environment,
            signedCapsule(
              environment,
              {
                currentStatePointerClosure: {
                  ...NT19_CURRENT_STATE_POINTER_CLOSURE,
                  currentLock: "NT19-MISMATCH",
                },
              }
            )
          )
        );

      assert.equal(result.authorized, false);
      assert.equal(result.sequenceClaimed, false);
      assert.equal(
        result.adapterIssueCodes.includes(
          "CURRENT_STATE_POINTER_FIELD_CLOSURE_FAILED"
        ),
        true
      );
      assert.equal(
        result.gateResult.issueCodes.includes(
          "CURRENT_STATE_POINTER_CLOSURE_FAILED"
        ),
        true
      );
    } finally {
      cleanupEnvironment(environment);
    }
  }
);

test(
  "NT-19 every remaining signed current-state closure field mismatch blocks local authorization",
  async () => {
    const fields: readonly (
      keyof SessionHandoffCurrentStatePointerClosureV1
    )[] = [
      "currentPolicyPointer",
      "currentRulesetPointer",
      "currentActionPointer",
      "currentLockPointer",
      "currentReceiptPointer",
      "currentResultLock",
      "currentResultLockFile",
      "policyVersion",
      "rulesetVersion",
      "capabilityManifest",
    ];

    for (const field of fields) {
      const environment =
        await createEnvironment();

      try {
        const mismatchedClosure = {
          ...NT19_CURRENT_STATE_POINTER_CLOSURE,
          [field]:
            "mismatch-" +
            String(field),
        } as
          SessionHandoffCurrentStatePointerClosureV1;

        const result =
          await adapterFor(
            environment
          ).evaluate(
            inputFor(
              environment,
              signedCapsule(
                environment,
                {
                  currentStatePointerClosure:
                    mismatchedClosure,
                }
              )
            )
          );

        assert.equal(result.authorized, false);
        assert.equal(result.sequenceClaimed, false);
        assert.equal(
          result.adapterIssueCodes.includes(
            "CURRENT_STATE_POINTER_FIELD_CLOSURE_FAILED"
          ),
          true
        );
        assert.equal(
          result.gateResult.issueCodes.includes(
            "CURRENT_STATE_POINTER_CLOSURE_FAILED"
          ),
          true
        );
      } finally {
        cleanupEnvironment(environment);
      }
    }
  }
);

test(
  "NT-19 missing or duplicate local C-10 current-state field blocks local authorization",
  async () => {
    const variants = [
      {
        omitDocumentKey:
          "CURRENT_RECEIPT_POINTER",
      },
      {
        duplicateDocumentKey:
          "CURRENT_LOCK",
      },
    ];

    for (const variant of variants) {
      const environment =
        await createEnvironment();

      try {
        const changed = Reflect.set(
          environment,
          "currentStatePointerBytes",
          Buffer.from(
            nt19CurrentStatePointerText(
              variant
            ),
            "utf8"
          )
        );

        assert.equal(changed, true);

        const result =
          await adapterFor(
            environment
          ).evaluate(
            inputFor(
              environment,
              signedCapsule(
                environment
              )
            )
          );

        assert.equal(result.authorized, false);
        assert.equal(result.sequenceClaimed, false);
        assert.equal(
          result.adapterIssueCodes.includes(
            "CURRENT_STATE_POINTER_HASH_MISMATCH"
          ),
          false
        );
        assert.equal(
          result.adapterIssueCodes.includes(
            "CURRENT_STATE_POINTER_FIELD_CLOSURE_FAILED"
          ),
          true
        );
        assert.equal(
          result.gateResult.issueCodes.includes(
            "CURRENT_STATE_POINTER_CLOSURE_FAILED"
          ),
          true
        );
      } finally {
        cleanupEnvironment(environment);
      }
    }
  }
);

// NT19_A2_FIELD_LEVEL_CURRENT_STATE_POINTER_TESTS_END
