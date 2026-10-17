import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { LedgerWriter } from "./ledgerWriter";
import { ReceiptWriter } from "./receiptWriter";
import type { LedgerEvent } from "../packages/aegis-core";

import {
  canonicalizeSessionHandoffUnsignedCapsule,
  computeSessionHandoffDescriptorHash,
  sha256SessionHandoffBytes,
  type SessionHandoffCurrentStatePointerClosureV1,
  type SessionHandoffVerificationCapsuleUnsignedV1,
  type SessionHandoffVerificationCapsuleV1,
} from "./sessionHandoffLocalVerificationAdapter";

import {
  SESSION_HANDOFF_PRODUCTION_VERIFICATION_INVARIANT,
  SESSION_HANDOFF_RUNTIME_CAPSULE_RELATIVE_PATH,
  SESSION_HANDOFF_RUNTIME_EVIDENCE_MANIFEST_RELATIVE_PATH,
  SessionHandoffProductionVerificationComposition,
} from "./sessionHandoffProductionVerificationComposition";

interface Fixture {
  readonly root: string;
  readonly aegisDir: string;
  readonly now: Date;
  readonly projectId: string;
  readonly signerId: string;
  readonly workspaceId: string;
  readonly sessionId: string;
  readonly nonceHex: string;
  readonly noncePrefixed: string;
  readonly snapshotBindingSha256: string;
  readonly privateKey: crypto.KeyObject;
  readonly publicKeyPem: string;
  readonly manifest: Record<string, unknown>;
  readonly manifestRelativePath: string;
  readonly roleEntries: Record<string, string>;
  readonly canonicalAuthorityState: Record<string, unknown>;
  readonly runtimeSession: Record<string, unknown>;
  readonly authorityBinding: Record<string, unknown>;
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


function createRoot(prefix: string): string {
  return fs.mkdtempSync(
    path.join(os.tmpdir(), prefix)
  );
}

function cleanupRoot(root: string): void {
  fs.rmSync(root, {
    recursive: true,
    force: true,
  });
}

function writeProjectFile(
  root: string,
  relativePath: string,
  content: string | Buffer
): void {
  const literalPath = path.join(
    root,
    ...relativePath.split("/")
  );

  fs.mkdirSync(path.dirname(literalPath), {
    recursive: true,
  });

  fs.writeFileSync(literalPath, content);
}

function readProjectFile(
  root: string,
  relativePath: string
): Buffer {
  return fs.readFileSync(
    path.join(root, ...relativePath.split("/"))
  );
}

function ledgerEvent(): LedgerEvent {
  return {
    schemaVersion: 1,
    eventType: "snapshot_created",
    timestamp: "2026-07-25T12:00:00.000Z",
    protectedPath: ".env",
    snapshotId: "c07-production-composition",
    success: true,
    verified: true,
    snapshotHash: "a".repeat(64),
    reason: "pre_save_snapshot_created",
  };
}

async function createFixture(): Promise<Fixture> {
  const root = createRoot(
    "aegis-c07-production-composition-"
  );

  const aegisDir = path.join(root, ".aegis");
  const now = new Date("2026-07-25T12:00:00.000Z");
  const projectId = "prolixo-aegis-personal";
  const signerId = "trusted-local-signer-v1";
  const workspaceId = "sha256:" + "b".repeat(64);
  const sessionId = "c".repeat(48);
  const nonceHex = "d".repeat(64);
  const noncePrefixed = "sha256:" + nonceHex;
  const snapshotBindingSha256 =
    "sha256:" + "e".repeat(64);

  const { publicKey, privateKey } =
    crypto.generateKeyPairSync("ed25519");

  const publicKeyPem = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();

  writeProjectFile(
    root,
    ".aegis/session-handoff/trusted-signers.json",
    JSON.stringify(
      {
        schemaVersion: 1,
        signers: [
          {
            signerId,
            algorithm: "ed25519",
            publicKeyPem,
          },
        ],
      },
      null,
      2
    ) + "\n"
  );

  const roleEntries = {
    canonicalStateEntry:
      ".aegis/session-handoff/evidence/canonical-state.bin",
    checkerEntry:
      ".aegis/session-handoff/evidence/checker.bin",
    authorityEntry:
      ".aegis/session-handoff/evidence/authority.bin",
    currentStatePointerEntry:
      "AEGIS-CURRENT-STATE.md",
    receiptEntry: "",
    ledgerEntry: ".aegis/ledger/events.jsonl",
  };

  writeProjectFile(
    root,
    roleEntries.canonicalStateEntry,
    "canonical-state-v1"
  );
  writeProjectFile(
    root,
    roleEntries.checkerEntry,
    "checker-v1"
  );
  writeProjectFile(
    root,
    roleEntries.authorityEntry,
    "authority-v1"
  );
  writeProjectFile(
    root,
    roleEntries.currentStatePointerEntry,
    nt19CurrentStatePointerText()
  );

  const ledgerWriter = new LedgerWriter(aegisDir);
  assert.equal(await ledgerWriter.append(ledgerEvent()), true);

  const receiptResult = await new ReceiptWriter(aegisDir).generate();
  assert.equal(receiptResult.ok, true);
  assert.equal(typeof receiptResult.receiptPath, "string");

  roleEntries.receiptEntry = path
    .relative(root, receiptResult.receiptPath as string)
    .split(path.sep)
    .join("/");

  const manifestRelativePath =
    SESSION_HANDOFF_RUNTIME_EVIDENCE_MANIFEST_RELATIVE_PATH;

  const manifest = {
    schemaVersion: 1,
    ...roleEntries,
  };

  writeProjectFile(
    root,
    manifestRelativePath,
    JSON.stringify(manifest, null, 2) + "\n"
  );

  return {
    root,
    aegisDir,
    now,
    projectId,
    signerId,
    workspaceId,
    sessionId,
    nonceHex,
    noncePrefixed,
    snapshotBindingSha256,
    privateKey,
    publicKeyPem,
    manifest,
    manifestRelativePath,
    roleEntries,
    canonicalAuthorityState: {
      projectIdentity: projectId,
      workspaceId,
      revision: 7,
      sessionId,
      approvalNonceSha256: noncePrefixed,
      approvalNonceState: "ISSUED",
      verificationResult: "VERIFIED",
    },
    runtimeSession: {
      sessionId,
      approvalNonceSha256: nonceHex,
      createdAt: "2026-07-25T11:59:00.000Z",
      lifecyclePhase: "ALLOW_PENDING_EXECUTION",
      nonceConsumed: false,
      expiresAt: null,
    },
    authorityBinding: {
      authorityRevision: 7,
      workspaceId,
      snapshotBindingSha256,
    },
  };
}

function requiredEntryHashes(
  fixture: Fixture,
  manifestOverride?: Record<string, unknown>
): Record<string, string> {
  if (manifestOverride !== undefined) {
    writeProjectFile(
      fixture.root,
      fixture.manifestRelativePath,
      JSON.stringify(manifestOverride, null, 2) + "\n"
    );
  }

  const manifest = manifestOverride ?? fixture.manifest;
  const entries = [
    fixture.manifestRelativePath,
    String(manifest.canonicalStateEntry),
    String(manifest.checkerEntry),
    String(manifest.authorityEntry),
    String(manifest.currentStatePointerEntry),
    String(manifest.receiptEntry),
    String(manifest.ledgerEntry),
  ];

  const result: Record<string, string> = {};

  for (const entry of entries) {
    if (
      entry.length > 0 &&
      fs.existsSync(
        path.join(fixture.root, ...entry.split("/"))
      )
    ) {
      result[entry] = sha256SessionHandoffBytes(
        readProjectFile(fixture.root, entry)
      );
    }
  }

  return result;
}

function writeSignedCapsule(
  fixture: Fixture,
  options: {
    readonly manifestOverride?: Record<string, unknown>;
    readonly mutateHashes?: (
      hashes: Record<string, string>
    ) => void;
    readonly mutateCurrentStatePointerClosure?: (
      closure: Record<
        keyof SessionHandoffCurrentStatePointerClosureV1,
        string
      >
    ) => void;
  } = {}
): SessionHandoffVerificationCapsuleV1 {
  const hashes = requiredEntryHashes(
    fixture,
    options.manifestOverride
  );

  options.mutateHashes?.(hashes);

  const currentStatePointerClosure:
    Record<
      keyof SessionHandoffCurrentStatePointerClosureV1,
      string
    > = {
      ...NT19_CURRENT_STATE_POINTER_CLOSURE,
    };

  options
    .mutateCurrentStatePointerClosure?.(
      currentStatePointerClosure
    );

  const unsigned:
    SessionHandoffVerificationCapsuleUnsignedV1 = {
    capsuleSchemaVersion: "1.0.0",
    capsuleKind: "HANDOFF_RESUME",
    firstRequiredAction:
      "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1",
    projectId: fixture.projectId,
    workspaceId: fixture.workspaceId,
    sessionId: fixture.sessionId,
    approvalNonceSha256: fixture.noncePrefixed,
    signerId: fixture.signerId,
    issuedAt: "2026-07-25T11:59:00.000Z",
    expiresAt: "2026-07-25T12:10:00.000Z",
    handoffSequence: 1,
    authorityRevision: 7,
    snapshotBindingSha256:
      fixture.snapshotBindingSha256,
    canonicalStateSha256:
      hashes[fixture.roleEntries.canonicalStateEntry] ??
      "0".repeat(64),
    checkerSha256:
      hashes[fixture.roleEntries.checkerEntry] ??
      "0".repeat(64),
    authoritySha256:
      hashes[fixture.roleEntries.authorityEntry] ??
      "0".repeat(64),
    currentStatePointerSha256:
      hashes[
        fixture.roleEntries.currentStatePointerEntry
      ] ?? "0".repeat(64),
    currentStatePointerClosure:
      Object.freeze({
        ...currentStatePointerClosure,
      }),
    requiredEntryHashes: hashes,
  };

  const descriptorHash =
    computeSessionHandoffDescriptorHash(unsigned);

  const canonicalPayload =
    canonicalizeSessionHandoffUnsignedCapsule(unsigned);

  const signature = crypto
    .sign(
      null,
      Buffer.from(canonicalPayload, "utf8"),
      fixture.privateKey
    )
    .toString("base64");

  const capsule = {
    ...unsigned,
    descriptorHash,
    signature,
  };

  writeProjectFile(
    fixture.root,
    SESSION_HANDOFF_RUNTIME_CAPSULE_RELATIVE_PATH,
    JSON.stringify(capsule, null, 2) + "\n"
  );

  return capsule;
}

function compositionFor(
  fixture: Fixture
): SessionHandoffProductionVerificationComposition {
  return new SessionHandoffProductionVerificationComposition(
    fixture.root,
    {
      expectedProjectId: fixture.projectId,
      expectedSignerIds: [fixture.signerId],
      maximumCapsuleAgeMilliseconds: 10 * 60 * 1000,
    },
    {
      canonicalAuthorityReader: {
        getState: () => fixture.canonicalAuthorityState,
      },
      runtimeSessionReader: {
        readSession: sessionId =>
          sessionId === fixture.sessionId
            ? fixture.runtimeSession
            : null,
      },
      authorityBindingReadPort: {
        readCurrentBinding: async () =>
          fixture.authorityBinding,
      },
      authorityBindingVerifier: {
        verify: async () => "verified",
      },
      now: () => new Date(fixture.now.getTime()),
    }
  );
}

function inputFor(
  fixture: Fixture,
  operationClass: unknown = "EXECUTE"
) {
  return {
    operationClass,
    presentedSessionId: fixture.sessionId,
    presentedApprovalNonceSha256:
      fixture.noncePrefixed,
  };
}

test(
  "valid fixed production evidence authorizes one effect operation",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture);

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, true);
      assert.deepEqual(result.compositionIssueCodes, []);
      assert.equal(result.adapterResult.sequenceClaimed, true);
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "legacy root bootstrap capsule is never used as the runtime capsule",
  async () => {
    const fixture = await createFixture();

    try {
      writeProjectFile(
        fixture.root,
        "AEGIS-HANDOFF-CAPSULE.json",
        JSON.stringify({ capsuleKind: "HANDOFF_RESUME" })
      );

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture, "READ_ONLY")
      );

      assert.equal(result.authorized, false);
      assert.equal(result.bootstrapReadOnlyAllowed, true);
      assert.equal(
        result.rootBootstrapCapsuleUsedAsRuntimeCapsule,
        false
      );
      assert.equal(
        result.compositionIssueCodes.includes(
          "RUNTIME_CAPSULE_READ_FAILED"
        ),
        true
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "missing evidence manifest blocks effects and preserves bootstrap read only",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture);
      fs.unlinkSync(
        path.join(
          fixture.root,
          ...fixture.manifestRelativePath.split("/")
        )
      );

      const effectResult = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );
      const readResult = await compositionFor(fixture).evaluate(
        inputFor(fixture, "READ_ONLY")
      );

      assert.equal(effectResult.authorized, false);
      assert.equal(readResult.bootstrapReadOnlyAllowed, true);
      assert.equal(
        effectResult.compositionIssueCodes.includes(
          "EVIDENCE_MANIFEST_READ_FAILED"
        ),
        true
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "manifest must be hash bound by the signed runtime capsule",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture, {
        mutateHashes: hashes => {
          delete hashes[fixture.manifestRelativePath];
        },
      });

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, false);
      assert.equal(
        result.compositionIssueCodes.includes(
          "EVIDENCE_MANIFEST_NOT_HASH_BOUND"
        ),
        true
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "every manifest role must be hash bound by the signed runtime capsule",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture, {
        mutateHashes: hashes => {
          delete hashes[fixture.roleEntries.checkerEntry];
        },
      });

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, false);
      assert.equal(
        result.compositionIssueCodes.includes(
          "EVIDENCE_ROLE_NOT_HASH_BOUND"
        ),
        true
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "absolute evidence paths are rejected",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture, {
        manifestOverride: {
          ...fixture.manifest,
          checkerEntry: "/tmp/checker.bin",
        },
      });

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, false);
      assert.equal(
        result.compositionIssueCodes.includes(
          "EVIDENCE_MANIFEST_INVALID"
        ),
        true
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "parent traversal evidence paths are rejected",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture, {
        manifestOverride: {
          ...fixture.manifest,
          checkerEntry: "../checker.bin",
        },
      });

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, false);
      assert.equal(
        result.compositionIssueCodes.includes(
          "EVIDENCE_MANIFEST_INVALID"
        ),
        true
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "backslash evidence paths are rejected",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture, {
        manifestOverride: {
          ...fixture.manifest,
          checkerEntry:
            ".aegis\\session-handoff\\checker.bin",
        },
      });

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, false);
      assert.equal(
        result.compositionIssueCodes.includes(
          "EVIDENCE_MANIFEST_INVALID"
        ),
        true
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "symbolic link evidence is blocked",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture);
      const checkerPath = path.join(
        fixture.root,
        ...fixture.roleEntries.checkerEntry.split("/")
      );
      const targetPath = checkerPath + ".target";
      fs.renameSync(checkerPath, targetPath);
      fs.symlinkSync(targetPath, checkerPath);

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, false);
      assert.equal(
        result.compositionIssueCodes.includes(
          "EVIDENCE_FILE_SYMLINK_BLOCKED"
        ),
        true
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "an unrelated newer receipt is never auto selected",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture);
      writeProjectFile(
        fixture.root,
        ".aegis/receipts/99999999T999999999Z.md",
        "untrusted newer receipt"
      );
      fs.unlinkSync(
        path.join(
          fixture.root,
          ...fixture.roleEntries.receiptEntry.split("/")
        )
      );

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, false);
      assert.equal(result.latestReceiptAutoSelected, false);
      assert.equal(
        result.compositionIssueCodes.includes(
          "EVIDENCE_FILE_READ_FAILED"
        ),
        true
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "incomplete read only verification generates no receipt and claims no sequence",
  async () => {
    const fixture = await createFixture();

    try {
      const receiptsDirectory = path.join(
        fixture.aegisDir,
        "receipts"
      );
      const beforeReceipts = fs.existsSync(receiptsDirectory)
        ? fs.readdirSync(receiptsDirectory).sort()
        : [];

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture, "READ_ONLY")
      );

      const afterReceipts = fs.existsSync(receiptsDirectory)
        ? fs.readdirSync(receiptsDirectory).sort()
        : [];

      assert.deepEqual(afterReceipts, beforeReceipts);
      assert.equal(result.receiptAutoGenerated, false);
      assert.equal(result.adapterResult.sequenceClaimed, false);
      assert.equal(
        fs.existsSync(
          path.join(
            fixture.aegisDir,
            "session-handoff",
            "accepted-sequences.json"
          )
        ),
        false
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "caller verification booleans and product completion claims remain prohibited",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture);

      const injectedInput = {
        ...inputFor(fixture),
        signatureVerified: true,
        freshnessVerified: true,
        antiRollbackVerified: true,
      } as unknown as Parameters<
        SessionHandoffProductionVerificationComposition["evaluate"]
      >[0];

      const result = await compositionFor(fixture).evaluate(
        injectedInput
      );

      assert.equal(
        result.callerVerificationBooleanAccepted,
        false
      );
      assert.equal(result.productPassClaimed, false);
      assert.equal(result.finalClaimed, false);
      assert.equal(result.releaseReadyClaimed, false);
      assert.equal(result.uploadReadyClaimed, false);
      assert.equal(
        SESSION_HANDOFF_PRODUCTION_VERIFICATION_INVARIANT
          .LATEST_RECEIPT_AUTO_SELECTED,
        false
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

// C07_FINAL_GATE_PRODUCTION_POLICY_TESTS_START

test("C07_FINAL_GATE production policy reads signer ids from the trust file", () => {
  const source = (require("node:fs") as typeof import("node:fs")).readFileSync(
    (require("node:path") as typeof import("node:path")).join(
      process.cwd(),
      "src",
      "sessionHandoffProductionVerificationComposition.ts"
    ),
    "utf8"
  );
  assert.match(source, /await readSessionHandoffTrustedSignerIds\s*\(\s*this\.aegisDir\s*\)/);
  assert.match(source, /TRUSTED_SIGNERS_READ_FAILED/);
  assert.match(source, /expectedSignerIds:\s*trustedSignerIds/);
});

test("C07_FINAL_GATE extension factory fixes capsule age and hides signer policy", () => {
  const source = (require("node:fs") as typeof import("node:fs")).readFileSync(
    (require("node:path") as typeof import("node:path")).join(
      process.cwd(),
      "src",
      "sessionHandoffProductionVerificationComposition.ts"
    ),
    "utf8"
  );
  assert.match(source, /SESSION_HANDOFF_PRODUCTION_MAXIMUM_CAPSULE_AGE_MILLISECONDS\s*=\s*15 \* 60 \* 1000/);
  const start = source.indexOf("export function createSessionHandoffExtensionProductionVerificationComposition");
  assert.ok(start >= 0);
  const block = source.slice(start);
  assert.match(block, /dependencies: SessionHandoffProductionVerificationRuntimeDependencies/);
  assert.doesNotMatch(block, /expectedSignerIds:\s*readonly|string\[\]/);
  assert.doesNotMatch(block, /maximumCapsuleAgeMilliseconds:\s*number/);
});

// C07_FINAL_GATE_PRODUCTION_POLICY_TESTS_END

// NT19_A1_CANONICAL_CURRENT_STATE_POINTER_TESTS_BEGIN

test(
  "NT-19 canonical current-state pointer reads local AEGIS-CURRENT-STATE.md",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture);

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, true);
      assert.deepEqual(result.compositionIssueCodes, []);
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "NT-19 manifest-selected alternate pointer cannot replace local canonical state",
  async () => {
    const fixture = await createFixture();

    try {
      const alternatePointerEntry =
        ".aegis/session-handoff/evidence/alternate-current-state.bin";

      writeProjectFile(
        fixture.root,
        alternatePointerEntry,
        "alternate-current-state-pointer-v1"
      );

      fixture.roleEntries.currentStatePointerEntry =
        alternatePointerEntry;

      writeSignedCapsule(fixture, {
        manifestOverride: {
          ...fixture.manifest,
          currentStatePointerEntry:
            alternatePointerEntry,
        },
      });

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, false);
      assert.match(
        JSON.stringify(result),
        /CURRENT_STATE_POINTER_(?:READ_FAILED|ENTRY_MISMATCH)/
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "NT-19 current-state pointer hash mismatch blocks authorization",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(fixture, {
        mutateHashes: hashes => {
          hashes[
            fixture.roleEntries.currentStatePointerEntry
          ] = "f".repeat(64);
        },
      });

      const result = await compositionFor(fixture).evaluate(
        inputFor(fixture)
      );

      assert.equal(result.authorized, false);
      assert.match(
        JSON.stringify(result),
        /CURRENT_STATE_POINTER_HASH_MISMATCH/
      );
    } finally {
      cleanupRoot(fixture.root);
    }
  }
);

// NT19_A1_CANONICAL_CURRENT_STATE_POINTER_TESTS_END
// NT19_A2_FIELD_LEVEL_CURRENT_STATE_POINTER_TESTS_BEGIN

test(
  "NT-19 production currentPhase mismatch blocks authorization",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(
        fixture,
        {
          mutateCurrentStatePointerClosure:
            closure => {
              closure.currentPhase =
                "C-09";
            },
        }
      );

      const result =
        await compositionFor(
          fixture
        ).evaluate(
          inputFor(fixture)
        );

      assert.equal(result.authorized, false);
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
      cleanupRoot(fixture.root);
    }
  }
);

test(
  "NT-19 production currentLock mismatch blocks authorization",
  async () => {
    const fixture = await createFixture();

    try {
      writeSignedCapsule(
        fixture,
        {
          mutateCurrentStatePointerClosure:
            closure => {
              closure.currentLock =
                "NT19-MISMATCH";
            },
        }
      );

      const result =
        await compositionFor(
          fixture
        ).evaluate(
          inputFor(fixture)
        );

      assert.equal(result.authorized, false);
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
      cleanupRoot(fixture.root);
    }
  }
);

// NT19_A2_FIELD_LEVEL_CURRENT_STATE_POINTER_TESTS_END
