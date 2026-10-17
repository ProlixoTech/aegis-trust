import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  FileSessionHandoffPersistentSequenceStore,
  FileSessionHandoffTrustedSignatureVerifier,
  SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT,
} from "./sessionHandoffLocalTrustProviders";

function root(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function cleanup(value: string): void {
  fs.rmSync(value, { recursive: true, force: true });
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function signatureFixture(): {
  readonly root: string;
  readonly aegisDir: string;
  readonly signerId: string;
  readonly payload: string;
  readonly descriptorHash: string;
  readonly signature: string;
  readonly publicKeyPem: string;
} {
  const directory = root("aegis-c07-trust-");
  const aegisDir = path.join(directory, ".aegis");
  const signerId = "trusted-local-signer-v1";
  const payload = JSON.stringify({ capsuleKind: "HANDOFF_RESUME", handoffSequence: 1, projectId: "prolixo-aegis-personal" });
  const descriptorHash = sha256(payload);
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const signature = crypto.sign(null, Buffer.from(payload, "utf8"), privateKey).toString("base64");
  const trustDir = path.join(aegisDir, "session-handoff");
  fs.mkdirSync(trustDir, { recursive: true });
  fs.writeFileSync(path.join(trustDir, "trusted-signers.json"), JSON.stringify({
    schemaVersion: 1,
    signers: [{ signerId, algorithm: "ed25519", publicKeyPem }],
  }, null, 2) + "\n", "utf8");
  return { root: directory, aegisDir, signerId, payload, descriptorHash, signature, publicKeyPem };
}

function sequenceInput(sequence: number) {
  return {
    projectId: "prolixo-aegis-personal",
    signerId: "trusted-signer",
    sequence,
    descriptorHash: sha256("sequence-" + sequence.toString(10)),
  };
}

test("trusted Ed25519 signer verifies canonical payload", async () => {
  const fixture = signatureFixture();
  try {
    const verifier = new FileSessionHandoffTrustedSignatureVerifier(fixture.aegisDir);
    assert.equal(await verifier.verify({ signerId: fixture.signerId, descriptorHash: fixture.descriptorHash, canonicalPayload: fixture.payload, signature: fixture.signature }), true);
  } finally {
    cleanup(fixture.root);
  }
});

test("unknown signer is blocked", async () => {
  const fixture = signatureFixture();
  try {
    const verifier = new FileSessionHandoffTrustedSignatureVerifier(fixture.aegisDir);
    assert.equal(await verifier.verify({ signerId: "unknown-signer", descriptorHash: fixture.descriptorHash, canonicalPayload: fixture.payload, signature: fixture.signature }), false);
  } finally {
    cleanup(fixture.root);
  }
});

test("tampered payload descriptor and signature are blocked", async () => {
  const fixture = signatureFixture();
  try {
    const verifier = new FileSessionHandoffTrustedSignatureVerifier(fixture.aegisDir);
    assert.equal(await verifier.verify({ signerId: fixture.signerId, descriptorHash: fixture.descriptorHash, canonicalPayload: fixture.payload + "x", signature: fixture.signature }), false);
    assert.equal(await verifier.verify({ signerId: fixture.signerId, descriptorHash: "a".repeat(64), canonicalPayload: fixture.payload, signature: fixture.signature }), false);
    assert.equal(await verifier.verify({ signerId: fixture.signerId, descriptorHash: fixture.descriptorHash, canonicalPayload: fixture.payload, signature: Buffer.alloc(64, 7).toString("base64") }), false);
  } finally {
    cleanup(fixture.root);
  }
});

test("missing malformed and duplicate trust files are blocked", async () => {
  const missingRoot = root("aegis-c07-missing-");
  const malformedRoot = root("aegis-c07-malformed-");
  const duplicate = signatureFixture();
  try {
    const missingVerifier = new FileSessionHandoffTrustedSignatureVerifier(path.join(missingRoot, ".aegis"));
    assert.equal(await missingVerifier.verify({ signerId: duplicate.signerId, descriptorHash: duplicate.descriptorHash, canonicalPayload: duplicate.payload, signature: duplicate.signature }), false);

    const malformedAegis = path.join(malformedRoot, ".aegis");
    fs.mkdirSync(path.join(malformedAegis, "session-handoff"), { recursive: true });
    fs.writeFileSync(path.join(malformedAegis, "session-handoff", "trusted-signers.json"), "{not-json", "utf8");
    const malformedVerifier = new FileSessionHandoffTrustedSignatureVerifier(malformedAegis);
    assert.equal(await malformedVerifier.verify({ signerId: duplicate.signerId, descriptorHash: duplicate.descriptorHash, canonicalPayload: duplicate.payload, signature: duplicate.signature }), false);

    fs.writeFileSync(path.join(duplicate.aegisDir, "session-handoff", "trusted-signers.json"), JSON.stringify({
      schemaVersion: 1,
      signers: [
        { signerId: duplicate.signerId, algorithm: "ed25519", publicKeyPem: duplicate.publicKeyPem },
        { signerId: duplicate.signerId, algorithm: "ed25519", publicKeyPem: duplicate.publicKeyPem },
      ],
    }), "utf8");
    const duplicateVerifier = new FileSessionHandoffTrustedSignatureVerifier(duplicate.aegisDir);
    assert.equal(await duplicateVerifier.verify({ signerId: duplicate.signerId, descriptorHash: duplicate.descriptorHash, canonicalPayload: duplicate.payload, signature: duplicate.signature }), false);
  } finally {
    cleanup(missingRoot);
    cleanup(malformedRoot);
    cleanup(duplicate.root);
  }
});

test("first sequence claim succeeds", async () => {
  const directory = root("aegis-c07-sequence-first-");
  try {
    const store = new FileSessionHandoffPersistentSequenceStore(path.join(directory, ".aegis"));
    assert.equal(await store.claimSequence(sequenceInput(1)), true);
    assert.equal(await store.readHighestAcceptedSequence({ projectId: "prolixo-aegis-personal", signerId: "trusted-signer" }), 1);
  } finally {
    cleanup(directory);
  }
});

test("strictly increasing sequence claim succeeds", async () => {
  const directory = root("aegis-c07-sequence-increase-");
  try {
    const store = new FileSessionHandoffPersistentSequenceStore(path.join(directory, ".aegis"));
    assert.equal(await store.claimSequence(sequenceInput(1)), true);
    assert.equal(await store.claimSequence(sequenceInput(2)), true);
    assert.equal(await store.readHighestAcceptedSequence({ projectId: "prolixo-aegis-personal", signerId: "trusted-signer" }), 2);
  } finally {
    cleanup(directory);
  }
});

test("identical sequence replay is blocked", async () => {
  const directory = root("aegis-c07-sequence-replay-");
  try {
    const store = new FileSessionHandoffPersistentSequenceStore(path.join(directory, ".aegis"));
    assert.equal(await store.claimSequence(sequenceInput(4)), true);
    assert.equal(await store.claimSequence(sequenceInput(4)), false);
  } finally {
    cleanup(directory);
  }
});

test("lower sequence rollback is blocked", async () => {
  const directory = root("aegis-c07-sequence-rollback-");
  try {
    const store = new FileSessionHandoffPersistentSequenceStore(path.join(directory, ".aegis"));
    assert.equal(await store.claimSequence(sequenceInput(8)), true);
    assert.equal(await store.claimSequence(sequenceInput(7)), false);
  } finally {
    cleanup(directory);
  }
});

test("concurrent identical claims permit exactly one success", async () => {
  const directory = root("aegis-c07-sequence-concurrent-");
  try {
    const aegisDir = path.join(directory, ".aegis");
    const results = await Promise.all([
      new FileSessionHandoffPersistentSequenceStore(aegisDir).claimSequence(sequenceInput(11)),
      new FileSessionHandoffPersistentSequenceStore(aegisDir).claimSequence(sequenceInput(11)),
    ]);
    assert.equal(results.filter(Boolean).length, 1);
    assert.equal(results.filter(value => !value).length, 1);
  } finally {
    cleanup(directory);
  }
});

test("corrupt state and unavailable lock fail closed", async () => {
  const corruptRoot = root("aegis-c07-sequence-corrupt-");
  const lockedRoot = root("aegis-c07-sequence-locked-");
  try {
    const corruptStore = new FileSessionHandoffPersistentSequenceStore(path.join(corruptRoot, ".aegis"));
    fs.mkdirSync(corruptStore.directoryPath, { recursive: true });
    fs.writeFileSync(corruptStore.statePath, "{invalid-json", "utf8");
    assert.equal(await corruptStore.claimSequence(sequenceInput(1)), false);
    await assert.rejects(corruptStore.readHighestAcceptedSequence({ projectId: "prolixo-aegis-personal", signerId: "trusted-signer" }));

    const lockedStore = new FileSessionHandoffPersistentSequenceStore(path.join(lockedRoot, ".aegis"));
    fs.mkdirSync(lockedStore.directoryPath, { recursive: true });
    fs.writeFileSync(lockedStore.lockPath, "existing-lock\n", "utf8");
    assert.equal(await lockedStore.claimSequence(sequenceInput(1)), false);
    assert.equal(fs.readFileSync(lockedStore.lockPath, "utf8"), "existing-lock\n");
  } finally {
    cleanup(corruptRoot);
    cleanup(lockedRoot);
  }
});

test("read-only sequence lookup never changes persistent state", async () => {
  const directory = root("aegis-c07-sequence-read-only-");
  try {
    const store = new FileSessionHandoffPersistentSequenceStore(path.join(directory, ".aegis"));
    assert.equal(await store.claimSequence(sequenceInput(5)), true);
    const before = fs.readFileSync(store.statePath);
    const beforeMtime = fs.statSync(store.statePath).mtimeMs;
    assert.equal(await store.readHighestAcceptedSequence({ projectId: "prolixo-aegis-personal", signerId: "trusted-signer" }), 5);
    assert.deepEqual(fs.readFileSync(store.statePath), before);
    assert.equal(fs.statSync(store.statePath).mtimeMs, beforeMtime);
    assert.equal(fs.existsSync(store.lockPath), false);
  } finally {
    cleanup(directory);
  }
});

test("invariants prohibit key creation TOFU and product completion claims", () => {
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.SIGNATURE_ALGORITHM, "ed25519");
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.TRUST_ON_FIRST_USE_ALLOWED, false);
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.PUBLIC_KEY_AUTO_GENERATION_ALLOWED, false);
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.PRIVATE_KEY_GENERATION_ALLOWED, false);
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.PRIVATE_KEY_STORAGE_ALLOWED, false);
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.READ_MUTATES_SEQUENCE_STATE, false);
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.PRODUCT_PASS_CLAIMED, false);
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.FINAL_CLAIMED, false);
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.RELEASE_READY_CLAIMED, false);
  assert.equal(SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT.UPLOAD_READY_CLAIMED, false);
});

// C07_FINAL_GATE_TRUST_POLICY_TESTS_START

test("C07_FINAL_GATE trusted signer ids reuse the strict trust parser", () => {
  const source = (require("node:fs") as typeof import("node:fs")).readFileSync(
    (require("node:path") as typeof import("node:path")).join(
      process.cwd(),
      "src",
      "sessionHandoffLocalTrustProviders.ts"
    ),
    "utf8"
  );
  assert.match(source, /export async function readSessionHandoffTrustedSignerIds/);
  assert.match(source, /parseTrustedSignerFile\s*\(/);
  assert.match(source, /readRegularUtf8File\s*\([\s\S]*?MAX_TRUST_FILE_BYTES/);
});

test("C07_FINAL_GATE trusted signer id reader is read only and fail closed", () => {
  const source = (require("node:fs") as typeof import("node:fs")).readFileSync(
    (require("node:path") as typeof import("node:path")).join(
      process.cwd(),
      "src",
      "sessionHandoffLocalTrustProviders.ts"
    ),
    "utf8"
  );
  const start = source.indexOf("export async function readSessionHandoffTrustedSignerIds");
  const end = source.indexOf("export class FileSessionHandoffTrustedSignatureVerifier", start);
  assert.ok(start >= 0 && end > start);
  const block = source.slice(start, end);
  assert.match(block, /EMPTY_TRUSTED_SIGNER_SET/);
  assert.doesNotMatch(block, /writeFile|mkdir|rename|unlink|generateKeyPair|privateKey/);
});

// C07_FINAL_GATE_TRUST_POLICY_TESTS_END