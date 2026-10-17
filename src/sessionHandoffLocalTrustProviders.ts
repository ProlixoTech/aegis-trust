import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import type {
  SessionHandoffPersistentSequenceStore,
  SessionHandoffTrustedSignatureVerifier,
} from "./sessionHandoffLocalVerificationAdapter";

export const SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_VERSION = 1 as const;
export const SESSION_HANDOFF_TRUSTED_SIGNERS_RELATIVE_PATH = path.join("session-handoff", "trusted-signers.json");
export const SESSION_HANDOFF_ACCEPTED_SEQUENCES_RELATIVE_PATH = path.join("session-handoff", "accepted-sequences.json");

export const SESSION_HANDOFF_LOCAL_TRUST_PROVIDERS_INVARIANT = Object.freeze({
  SIGNATURE_ALGORITHM: "ed25519",
  TRUST_ON_FIRST_USE_ALLOWED: false,
  PUBLIC_KEY_AUTO_GENERATION_ALLOWED: false,
  PRIVATE_KEY_GENERATION_ALLOWED: false,
  PRIVATE_KEY_STORAGE_ALLOWED: false,
  UNKNOWN_SIGNER_ALLOWED: false,
  REPLAY_ALLOWED: false,
  ROLLBACK_ALLOWED: false,
  READ_MUTATES_SEQUENCE_STATE: false,
  PRODUCT_PASS_CLAIMED: false,
  FINAL_CLAIMED: false,
  RELEASE_READY_CLAIMED: false,
  UPLOAD_READY_CLAIMED: false,
} as const);

interface TrustedSignerRecordV1 {
  readonly signerId: string;
  readonly algorithm: "ed25519";
  readonly publicKeyPem: string;
}

interface AcceptedSequenceEntryV1 {
  readonly projectId: string;
  readonly signerId: string;
  readonly highestAcceptedSequence: number;
  readonly descriptorHash: string;
}

interface AcceptedSequenceStateV1 {
  readonly schemaVersion: 1;
  readonly entries: readonly AcceptedSequenceEntryV1[];
}

const MAX_TRUST_FILE_BYTES = 1024 * 1024;
const MAX_SEQUENCE_FILE_BYTES = 4 * 1024 * 1024;
const MAX_TRUSTED_SIGNERS = 256;
const MAX_SEQUENCE_ENTRIES = 10000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
}

function normalizeSha256(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(normalized) ? normalized : null;
}

function sha256Utf8(value: string): string {
  return crypto.createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex");
}

function strictBase64(value: unknown): Buffer | null {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    return null;
  }
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64") === value ? decoded : null;
}

function requireAbsoluteAegisDir(aegisDir: string): string {
  const normalized = aegisDir.trim();
  if (!normalized || !path.isAbsolute(normalized)) throw new Error("INVALID_AEGIS_DIR");
  return path.resolve(normalized);
}

async function readRegularUtf8File(literalPath: string, maximumBytes: number): Promise<string> {
  const metadata = await fs.promises.lstat(literalPath);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size < 1 || metadata.size > maximumBytes) {
    throw new Error("UNTRUSTED_FILE_METADATA");
  }
  return fs.promises.readFile(literalPath, "utf8");
}

function parseTrustedSignerFile(text: string): readonly TrustedSignerRecordV1[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("INVALID_TRUSTED_SIGNER_JSON");
  }
  if (
    !isRecord(parsed) ||
    !hasExactKeys(parsed, ["schemaVersion", "signers"]) ||
    parsed.schemaVersion !== 1 ||
    !Array.isArray(parsed.signers) ||
    parsed.signers.length < 1 ||
    parsed.signers.length > MAX_TRUSTED_SIGNERS
  ) {
    throw new Error("INVALID_TRUSTED_SIGNER_FILE");
  }

  const signerIds = new Set<string>();
  const result: TrustedSignerRecordV1[] = [];
  for (const candidate of parsed.signers) {
    if (
      !isRecord(candidate) ||
      !hasExactKeys(candidate, ["algorithm", "publicKeyPem", "signerId"]) ||
      !isIdentifier(candidate.signerId) ||
      candidate.algorithm !== "ed25519" ||
      typeof candidate.publicKeyPem !== "string"
    ) {
      throw new Error("INVALID_TRUSTED_SIGNER_RECORD");
    }
    if (signerIds.has(candidate.signerId)) throw new Error("DUPLICATE_TRUSTED_SIGNER");
    signerIds.add(candidate.signerId);
    const publicKeyPem = candidate.publicKeyPem.trim();
    if (
      !publicKeyPem ||
      publicKeyPem.length > 16384 ||
      !publicKeyPem.includes("-----BEGIN PUBLIC KEY-----") ||
      !publicKeyPem.includes("-----END PUBLIC KEY-----") ||
      publicKeyPem.includes("PRIVATE KEY") ||
      publicKeyPem.includes("\0")
    ) {
      throw new Error("INVALID_TRUSTED_PUBLIC_KEY");
    }
    let publicKey: crypto.KeyObject;
    try {
      publicKey = crypto.createPublicKey(publicKeyPem);
    } catch {
      throw new Error("INVALID_TRUSTED_PUBLIC_KEY");
    }
    if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") {
      throw new Error("INVALID_TRUSTED_PUBLIC_KEY_TYPE");
    }
    result.push(Object.freeze({ signerId: candidate.signerId, algorithm: "ed25519", publicKeyPem }));
  }
  return Object.freeze(result);
}

function emptySequenceState(): AcceptedSequenceStateV1 {
  return Object.freeze({ schemaVersion: 1, entries: Object.freeze([]) });
}

function parseSequenceState(text: string): AcceptedSequenceStateV1 {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("INVALID_SEQUENCE_STATE_JSON");
  }
  if (
    !isRecord(parsed) ||
    !hasExactKeys(parsed, ["entries", "schemaVersion"]) ||
    parsed.schemaVersion !== 1 ||
    !Array.isArray(parsed.entries) ||
    parsed.entries.length > MAX_SEQUENCE_ENTRIES
  ) {
    throw new Error("INVALID_SEQUENCE_STATE");
  }

  const identities = new Set<string>();
  const entries: AcceptedSequenceEntryV1[] = [];
  for (const candidate of parsed.entries) {
    if (
      !isRecord(candidate) ||
      !hasExactKeys(candidate, ["descriptorHash", "highestAcceptedSequence", "projectId", "signerId"]) ||
      !isIdentifier(candidate.projectId) ||
      !isIdentifier(candidate.signerId) ||
      typeof candidate.highestAcceptedSequence !== "number" ||
      !Number.isSafeInteger(candidate.highestAcceptedSequence) ||
      candidate.highestAcceptedSequence < 1
    ) {
      throw new Error("INVALID_SEQUENCE_ENTRY");
    }
    const descriptorHash = normalizeSha256(candidate.descriptorHash);
    if (descriptorHash === null) throw new Error("INVALID_SEQUENCE_DESCRIPTOR_HASH");
    const identity = candidate.projectId + "\n" + candidate.signerId;
    if (!identities.add(identity)) throw new Error("DUPLICATE_SEQUENCE_IDENTITY");
    entries.push(Object.freeze({
      projectId: candidate.projectId,
      signerId: candidate.signerId,
      highestAcceptedSequence: candidate.highestAcceptedSequence,
      descriptorHash,
    }));
  }
  entries.sort((left, right) => left.projectId.localeCompare(right.projectId) || left.signerId.localeCompare(right.signerId));
  return Object.freeze({ schemaVersion: 1, entries: Object.freeze(entries) });
}

function serializeSequenceState(state: AcceptedSequenceStateV1): string {
  return JSON.stringify({ schemaVersion: 1, entries: state.entries }, null, 2) + "\n";
}

export async function readSessionHandoffTrustedSignerIds(
  aegisDir: string
): Promise<readonly string[]> {
  const trustedSignersPath = path.join(
    requireAbsoluteAegisDir(aegisDir),
    SESSION_HANDOFF_TRUSTED_SIGNERS_RELATIVE_PATH
  );
  const signers = parseTrustedSignerFile(
    await readRegularUtf8File(
      trustedSignersPath,
      MAX_TRUST_FILE_BYTES
    )
  );
  const signerIds = signers
    .map((signer) => signer.signerId)
    .sort((left, right) => left.localeCompare(right));
  if (signerIds.length === 0) {
    throw new Error("EMPTY_TRUSTED_SIGNER_SET");
  }
  return Object.freeze(signerIds);
}

export class FileSessionHandoffTrustedSignatureVerifier implements SessionHandoffTrustedSignatureVerifier {
  readonly trustedSignersPath: string;

  constructor(aegisDir: string) {
    this.trustedSignersPath = path.join(requireAbsoluteAegisDir(aegisDir), SESSION_HANDOFF_TRUSTED_SIGNERS_RELATIVE_PATH);
  }

  async verify(input: {
    readonly signerId: string;
    readonly descriptorHash: string;
    readonly canonicalPayload: string;
    readonly signature: string;
  }): Promise<boolean> {
    try {
      if (!isIdentifier(input.signerId) || typeof input.canonicalPayload !== "string" || input.canonicalPayload.length < 1 || input.canonicalPayload.length > 4 * 1024 * 1024) {
        return false;
      }
      const descriptorHash = normalizeSha256(input.descriptorHash);
      if (descriptorHash === null || sha256Utf8(input.canonicalPayload) !== descriptorHash) return false;
      const signature = strictBase64(input.signature);
      if (signature === null || signature.length !== 64) return false;
      const signers = parseTrustedSignerFile(await readRegularUtf8File(this.trustedSignersPath, MAX_TRUST_FILE_BYTES));
      const signer = signers.find(candidate => candidate.signerId === input.signerId);
      if (signer === undefined) return false;
      return crypto.verify(null, Buffer.from(input.canonicalPayload, "utf8"), crypto.createPublicKey(signer.publicKeyPem), signature);
    } catch {
      return false;
    }
  }
}

export class FileSessionHandoffPersistentSequenceStore implements SessionHandoffPersistentSequenceStore {
  readonly directoryPath: string;
  readonly statePath: string;
  readonly lockPath: string;

  constructor(aegisDir: string) {
    const normalizedAegisDir = requireAbsoluteAegisDir(aegisDir);
    this.directoryPath = path.join(normalizedAegisDir, "session-handoff");
    this.statePath = path.join(normalizedAegisDir, SESSION_HANDOFF_ACCEPTED_SEQUENCES_RELATIVE_PATH);
    this.lockPath = this.statePath + ".lock";
  }

  private async readState(): Promise<AcceptedSequenceStateV1> {
    try {
      return parseSequenceState(await readRegularUtf8File(this.statePath, MAX_SEQUENCE_FILE_BYTES));
    } catch (error) {
      const code = isRecord(error) ? error.code : undefined;
      if (code === "ENOENT") return emptySequenceState();
      throw error;
    }
  }

  private async ensureDirectory(): Promise<void> {
    await fs.promises.mkdir(this.directoryPath, { recursive: true, mode: 0o700 });
    const metadata = await fs.promises.lstat(this.directoryPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("INVALID_SEQUENCE_DIRECTORY");
  }

  private async writeStateAtomically(state: AcceptedSequenceStateV1): Promise<void> {
    const temporaryPath = this.statePath + "." + process.pid.toString(10) + "." + crypto.randomBytes(16).toString("hex") + ".tmp";
    let handle: fs.promises.FileHandle | null = null;
    try {
      handle = await fs.promises.open(temporaryPath, "wx", 0o600);
      await handle.writeFile(serializeSequenceState(state), { encoding: "utf8" });
      await handle.sync();
      await handle.close();
      handle = null;
      await fs.promises.rename(temporaryPath, this.statePath);
    } finally {
      if (handle !== null) await handle.close().catch(() => undefined);
      await fs.promises.unlink(temporaryPath).catch((error: unknown) => {
        const code = isRecord(error) ? error.code : undefined;
        if (code !== "ENOENT") throw error;
      });
    }
  }

  async readHighestAcceptedSequence(input: { readonly projectId: string; readonly signerId: string }): Promise<number | null> {
    if (!isIdentifier(input.projectId) || !isIdentifier(input.signerId)) throw new Error("INVALID_SEQUENCE_IDENTITY");
    const current = (await this.readState()).entries.find(entry => entry.projectId === input.projectId && entry.signerId === input.signerId);
    return current?.highestAcceptedSequence ?? null;
  }

  async claimSequence(input: {
    readonly projectId: string;
    readonly signerId: string;
    readonly sequence: number;
    readonly descriptorHash: string;
  }): Promise<boolean> {
    if (!isIdentifier(input.projectId) || !isIdentifier(input.signerId) || !Number.isSafeInteger(input.sequence) || input.sequence < 1) return false;
    const descriptorHash = normalizeSha256(input.descriptorHash);
    if (descriptorHash === null) return false;

    try {
      await this.ensureDirectory();
    } catch {
      return false;
    }

    let lockHandle: fs.promises.FileHandle;
    try {
      lockHandle = await fs.promises.open(this.lockPath, "wx", 0o600);
    } catch {
      return false;
    }

    let result = false;
    let cleanupFailed = false;
    try {
      await lockHandle.writeFile(JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }) + "\n", { encoding: "utf8" });
      await lockHandle.sync();
      const state = await this.readState();
      const entries = state.entries.map(entry => ({ ...entry }));
      const index = entries.findIndex(entry => entry.projectId === input.projectId && entry.signerId === input.signerId);
      if (index >= 0 && input.sequence <= entries[index].highestAcceptedSequence) {
        result = false;
      } else {
        const nextEntry: AcceptedSequenceEntryV1 = {
          projectId: input.projectId,
          signerId: input.signerId,
          highestAcceptedSequence: input.sequence,
          descriptorHash,
        };
        if (index >= 0) entries[index] = nextEntry;
        else entries.push(nextEntry);
        entries.sort((left, right) => left.projectId.localeCompare(right.projectId) || left.signerId.localeCompare(right.signerId));
        await this.writeStateAtomically(Object.freeze({ schemaVersion: 1, entries: Object.freeze(entries.map(entry => Object.freeze({ ...entry }))) }));
        result = true;
      }
    } catch {
      result = false;
    } finally {
      try {
        await lockHandle.close();
      } catch {
        cleanupFailed = true;
      }
      try {
        await fs.promises.unlink(this.lockPath);
      } catch {
        cleanupFailed = true;
      }
    }
    return result && !cleanupFailed;
  }
}
