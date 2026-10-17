import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  ABSOLUTE_SERVER_RULESET_JSON_BYTES,
  canonicalizeServerRulesetValue,
  type ServerRulesetTrustState,
} from "./serverRulesetTrustProvider";

export const SERVER_RULESET_DIRECTORY_RELATIVE_PATH =
  path.join(".aegis", "server-ruleset");

export const SERVER_RULESET_STATE_FILE_NAME =
  "state.json";

export const SERVER_RULESET_LKG_FILE_NAME =
  "lkg.json";

export const SERVER_RULESET_LOCK_FILE_NAME =
  "accept.lock";

export const MAX_SERVER_RULESET_STATE_FILE_BYTES =
  64 * 1024;

export const MAX_SERVER_RULESET_LKG_FILE_BYTES =
  32 * 1024 * 1024;

export interface PersistentServerRulesetStateV1 {
  readonly schemaVersion: 1;
  readonly highestIntermediateSequence: number;
  readonly intermediateKeyId: string;
  readonly intermediateKeySha256: string;
  readonly activeRuleset: {
    readonly rulesetVersion: number;
    readonly monotonicCounter: number;
    readonly notBefore: string;
    readonly notAfter: string;
  };
  readonly rulesetSha256: string;
  readonly lkgPackageSha256: string;
}

export interface PersistentServerRulesetLkgV1 {
  readonly schemaVersion: 1;
  readonly packageSha256: string;
  readonly packageText: string;
}

export interface StoredServerRulesetSnapshot {
  readonly state: PersistentServerRulesetStateV1;
  readonly lkg: PersistentServerRulesetLkgV1;
}

export interface ServerRulesetSnapshotInput {
  readonly state: ServerRulesetTrustState;
  readonly packageText: string;
}

export type ServerRulesetCommitStatus =
  | "COMMITTED"
  | "UNCHANGED"
  | "REJECTED";

export interface ServerRulesetCommitResult {
  readonly status: ServerRulesetCommitStatus;
  readonly error: string | null;
}

function isRecord(
  value: unknown
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function hasExactKeys(
  value: Record<string, unknown>,
  expectedKeys: readonly string[]
): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();

  return (
    actual.length === expected.length &&
    actual.every(
      (key, index) =>
        key === expected[index]
    )
  );
}

function isErrnoCode(
  error: unknown,
  expectedCode: string
): boolean {
  return (
    isRecord(error) &&
    error.code === expectedCode
  );
}

function isIdentifier(
  value: unknown
): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(
      value
    )
  );
}

function isSha256(
  value: unknown
): value is string {
  return (
    typeof value === "string" &&
    /^[a-f0-9]{64}$/.test(value)
  );
}

function sha256Utf8(
  value: string
): string {
  return crypto
    .createHash("sha256")
    .update(
      Buffer.from(value, "utf8")
    )
    .digest("hex");
}

function parseTimestamp(
  value: unknown,
  errorCode: string
): {
  readonly source: string;
  readonly epochMs: number;
} {
  if (
    typeof value !== "string" ||
    value.trim() === ""
  ) {
    throw new Error(errorCode);
  }

  const epochMs = Date.parse(value);

  if (!Number.isFinite(epochMs)) {
    throw new Error(errorCode);
  }

  return {
    source: value,
    epochMs,
  };
}

function parseActiveRuleset(
  value: unknown
): PersistentServerRulesetStateV1["activeRuleset"] {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "monotonicCounter",
        "notAfter",
        "notBefore",
        "rulesetVersion",
      ]
    ) ||
    !Number.isSafeInteger(
      value.rulesetVersion
    ) ||
    (
      value.rulesetVersion as number
    ) < 1 ||
    !Number.isSafeInteger(
      value.monotonicCounter
    ) ||
    (
      value.monotonicCounter as number
    ) < 1
  ) {
    throw new Error(
      "INVALID_PERSISTED_ACTIVE_RULESET"
    );
  }

  const notBefore =
    parseTimestamp(
      value.notBefore,
      "INVALID_PERSISTED_RULESET_NOT_BEFORE"
    );

  const notAfter =
    parseTimestamp(
      value.notAfter,
      "INVALID_PERSISTED_RULESET_NOT_AFTER"
    );

  if (
    notAfter.epochMs <=
    notBefore.epochMs
  ) {
    throw new Error(
      "INVALID_PERSISTED_RULESET_VALIDITY_WINDOW"
    );
  }

  return Object.freeze({
    rulesetVersion:
      value.rulesetVersion as number,
    monotonicCounter:
      value.monotonicCounter as number,
    notBefore: notBefore.source,
    notAfter: notAfter.source,
  });
}

function parsePersistentState(
  text: string
): PersistentServerRulesetStateV1 {
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(
      "INVALID_SERVER_RULESET_STATE_JSON"
    );
  }

  if (
    !isRecord(parsed) ||
    !hasExactKeys(
      parsed,
      [
        "activeRuleset",
        "highestIntermediateSequence",
        "intermediateKeyId",
        "intermediateKeySha256",
        "lkgPackageSha256",
        "rulesetSha256",
        "schemaVersion",
      ]
    ) ||
    parsed.schemaVersion !== 1 ||
    !Number.isSafeInteger(
      parsed.highestIntermediateSequence
    ) ||
    (
      parsed.highestIntermediateSequence as number
    ) < 1 ||
    !isIdentifier(
      parsed.intermediateKeyId
    ) ||
    !isSha256(
      parsed.intermediateKeySha256
    ) ||
    !isSha256(
      parsed.rulesetSha256
    ) ||
    !isSha256(
      parsed.lkgPackageSha256
    )
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_STATE"
    );
  }

  return Object.freeze({
    schemaVersion: 1,
    highestIntermediateSequence:
      parsed.highestIntermediateSequence as number,
    intermediateKeyId:
      parsed.intermediateKeyId,
    intermediateKeySha256:
      parsed.intermediateKeySha256,
    activeRuleset:
      parseActiveRuleset(
        parsed.activeRuleset
      ),
    rulesetSha256:
      parsed.rulesetSha256,
    lkgPackageSha256:
      parsed.lkgPackageSha256,
  });
}

function parsePersistentLkg(
  text: string
): PersistentServerRulesetLkgV1 {
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(
      "INVALID_SERVER_RULESET_LKG_JSON"
    );
  }

  if (
    !isRecord(parsed) ||
    !hasExactKeys(
      parsed,
      [
        "packageSha256",
        "packageText",
        "schemaVersion",
      ]
    ) ||
    parsed.schemaVersion !== 1 ||
    !isSha256(
      parsed.packageSha256
    ) ||
    typeof parsed.packageText !== "string" ||
    parsed.packageText.length < 1 ||
    Buffer.byteLength(
      parsed.packageText,
      "utf8"
    ) >
      ABSOLUTE_SERVER_RULESET_JSON_BYTES
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_LKG"
    );
  }

  if (
    sha256Utf8(
      parsed.packageText
    ) !== parsed.packageSha256
  ) {
    throw new Error(
      "SERVER_RULESET_LKG_PACKAGE_HASH_MISMATCH"
    );
  }

  return Object.freeze({
    schemaVersion: 1,
    packageSha256:
      parsed.packageSha256,
    packageText:
      parsed.packageText,
  });
}

function extractCanonicalRulesetSha256(
  packageText: string
): string {
  let parsed: unknown;

  try {
    parsed = JSON.parse(packageText);
  } catch {
    throw new Error(
      "INVALID_LKG_PACKAGE_JSON"
    );
  }

  if (
    !isRecord(parsed) ||
    !Object.prototype.hasOwnProperty.call(
      parsed,
      "ruleset"
    )
  ) {
    throw new Error(
      "LKG_PACKAGE_RULESET_MISSING"
    );
  }

  return sha256Utf8(
    canonicalizeServerRulesetValue(
      parsed.ruleset
    )
  );
}

function buildCandidateSnapshot(
  input: ServerRulesetSnapshotInput
): StoredServerRulesetSnapshot {
  if (
    !isRecord(input.state) ||
    !hasExactKeys(
      input.state,
      [
        "activeRuleset",
        "highestIntermediateSequence",
        "intermediateKeyId",
        "intermediateKeySha256",
        "rulesetSha256",
      ]
    ) ||
    typeof input.packageText !== "string" ||
    input.packageText.length < 1 ||
    Buffer.byteLength(
      input.packageText,
      "utf8"
    ) >
      ABSOLUTE_SERVER_RULESET_JSON_BYTES
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_SNAPSHOT_INPUT"
    );
  }

  const activeRuleset =
    parseActiveRuleset(
      input.state.activeRuleset
    );

  if (
    !Number.isSafeInteger(
      input.state
        .highestIntermediateSequence
    ) ||
    input.state
      .highestIntermediateSequence < 1 ||
    !isIdentifier(
      input.state.intermediateKeyId
    ) ||
    !isSha256(
      input.state.intermediateKeySha256
    ) ||
    !isSha256(
      input.state.rulesetSha256
    )
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_TRUST_STATE"
    );
  }

  const packageSha256 =
    sha256Utf8(
      input.packageText
    );

  const rulesetSha256 =
    extractCanonicalRulesetSha256(
      input.packageText
    );

  if (
    rulesetSha256 !==
    input.state.rulesetSha256
  ) {
    throw new Error(
      "LKG_RULESET_HASH_DOES_NOT_MATCH_STATE"
    );
  }

  const state =
    Object.freeze({
      schemaVersion: 1 as const,
      highestIntermediateSequence:
        input.state
          .highestIntermediateSequence,
      intermediateKeyId:
        input.state.intermediateKeyId,
      intermediateKeySha256:
        input.state
          .intermediateKeySha256,
      activeRuleset,
      rulesetSha256:
        input.state.rulesetSha256,
      lkgPackageSha256:
        packageSha256,
    });

  const lkg =
    Object.freeze({
      schemaVersion: 1 as const,
      packageSha256,
      packageText:
        input.packageText,
    });

  return Object.freeze({
    state,
    lkg,
  });
}

function validateSnapshotLinkage(
  snapshot: StoredServerRulesetSnapshot
): void {
  if (
    snapshot.state
      .lkgPackageSha256 !==
    snapshot.lkg.packageSha256
  ) {
    throw new Error(
      "SERVER_RULESET_STATE_LKG_HASH_MISMATCH"
    );
  }

  const actualRulesetSha256 =
    extractCanonicalRulesetSha256(
      snapshot.lkg.packageText
    );

  if (
    actualRulesetSha256 !==
    snapshot.state.rulesetSha256
  ) {
    throw new Error(
      "SERVER_RULESET_STATE_RULESET_HASH_MISMATCH"
    );
  }
}

function serializeState(
  state: PersistentServerRulesetStateV1
): string {
  return (
    JSON.stringify(
      {
        schemaVersion:
          state.schemaVersion,
        highestIntermediateSequence:
          state.highestIntermediateSequence,
        intermediateKeyId:
          state.intermediateKeyId,
        intermediateKeySha256:
          state.intermediateKeySha256,
        activeRuleset: {
          rulesetVersion:
            state.activeRuleset
              .rulesetVersion,
          monotonicCounter:
            state.activeRuleset
              .monotonicCounter,
          notBefore:
            state.activeRuleset
              .notBefore,
          notAfter:
            state.activeRuleset
              .notAfter,
        },
        rulesetSha256:
          state.rulesetSha256,
        lkgPackageSha256:
          state.lkgPackageSha256,
      },
      null,
      2
    ) + "\n"
  );
}

function serializeLkg(
  lkg: PersistentServerRulesetLkgV1
): string {
  return (
    JSON.stringify(
      {
        schemaVersion:
          lkg.schemaVersion,
        packageSha256:
          lkg.packageSha256,
        packageText:
          lkg.packageText,
      },
      null,
      2
    ) + "\n"
  );
}

function snapshotsEqual(
  left: StoredServerRulesetSnapshot,
  right: StoredServerRulesetSnapshot
): boolean {
  return (
    serializeState(left.state) ===
      serializeState(right.state) &&
    serializeLkg(left.lkg) ===
      serializeLkg(right.lkg)
  );
}

function assertAdvanceAllowed(
  current: StoredServerRulesetSnapshot,
  candidate: StoredServerRulesetSnapshot
): void {
  if (
    candidate.state
      .highestIntermediateSequence <
    current.state
      .highestIntermediateSequence
  ) {
    throw new Error(
      "PERSISTED_INTERMEDIATE_SEQUENCE_DOWNGRADE"
    );
  }

  if (
    candidate.state
      .highestIntermediateSequence ===
      current.state
        .highestIntermediateSequence &&
    (
      candidate.state
        .intermediateKeyId !==
        current.state
          .intermediateKeyId ||
      candidate.state
        .intermediateKeySha256 !==
        current.state
          .intermediateKeySha256
    )
  ) {
    throw new Error(
      "PERSISTED_INTERMEDIATE_KEY_REBOUND"
    );
  }

  if (
    candidate.state.activeRuleset
      .rulesetVersion <
    current.state.activeRuleset
      .rulesetVersion
  ) {
    throw new Error(
      "PERSISTED_RULESET_VERSION_DOWNGRADE"
    );
  }

  if (
    candidate.state.activeRuleset
      .monotonicCounter <
    current.state.activeRuleset
      .monotonicCounter
  ) {
    throw new Error(
      "PERSISTED_RULESET_COUNTER_DOWNGRADE"
    );
  }

  if (
    candidate.state.activeRuleset
      .rulesetVersion ===
      current.state.activeRuleset
        .rulesetVersion &&
    candidate.state.activeRuleset
      .monotonicCounter ===
      current.state.activeRuleset
        .monotonicCounter &&
    candidate.state.rulesetSha256 !==
      current.state.rulesetSha256
  ) {
    throw new Error(
      "PERSISTED_RULESET_HASH_REBOUND"
    );
  }

  if (
    candidate.state
      .highestIntermediateSequence ===
      current.state
        .highestIntermediateSequence &&
    candidate.state.activeRuleset
      .rulesetVersion ===
      current.state.activeRuleset
        .rulesetVersion &&
    candidate.state.activeRuleset
      .monotonicCounter ===
      current.state.activeRuleset
        .monotonicCounter &&
    candidate.state
      .lkgPackageSha256 !==
      current.state
        .lkgPackageSha256
  ) {
    throw new Error(
      "PERSISTED_SNAPSHOT_REBOUND"
    );
  }
}

async function lstatOrNull(
  literalPath: string
): Promise<fs.Stats | null> {
  try {
    return await fs.promises.lstat(
      literalPath
    );
  } catch (error) {
    if (isErrnoCode(error, "ENOENT")) {
      return null;
    }

    throw error;
  }
}

function assertTrustedDirectoryMetadata(
  metadata: fs.Stats,
  errorCode: string
): void {
  if (
    metadata.isSymbolicLink() ||
    !metadata.isDirectory()
  ) {
    throw new Error(errorCode);
  }
}

async function readRegularUtf8File(
  literalPath: string,
  maximumBytes: number
): Promise<string> {
  const metadata =
    await fs.promises.lstat(
      literalPath
    );

  if (
    metadata.isSymbolicLink() ||
    !metadata.isFile() ||
    metadata.size < 1 ||
    metadata.size > maximumBytes
  ) {
    throw new Error(
      "UNTRUSTED_SERVER_RULESET_FILE_METADATA"
    );
  }

  return fs.promises.readFile(
    literalPath,
    "utf8"
  );
}

async function writeUtf8FileAtomically(
  literalPath: string,
  value: string
): Promise<void> {
  const temporaryPath =
    literalPath +
    "." +
    process.pid.toString(10) +
    "." +
    crypto
      .randomBytes(16)
      .toString("hex") +
    ".tmp";

  let handle:
    fs.promises.FileHandle | null =
      null;

  try {
    handle =
      await fs.promises.open(
        temporaryPath,
        "wx",
        0o600
      );

    await handle.writeFile(
      value,
      {
        encoding: "utf8",
      }
    );

    await handle.sync();
    await handle.close();
    handle = null;

    await fs.promises.rename(
      temporaryPath,
      literalPath
    );
  } finally {
    if (handle !== null) {
      await handle
        .close()
        .catch(() => undefined);
    }

    await fs.promises
      .unlink(temporaryPath)
      .catch((error: unknown) => {
        if (
          !isErrnoCode(
            error,
            "ENOENT"
          )
        ) {
          throw error;
        }
      });
  }
}

export class FileServerRulesetLocalPersistence {
  readonly workspaceRoot: string;
  readonly aegisDirectoryPath: string;
  readonly directoryPath: string;
  readonly statePath: string;
  readonly lkgPath: string;
  readonly lockPath: string;

  constructor(
    workspaceRoot: string
  ) {
    const normalized =
      workspaceRoot.trim();

    if (
      normalized.length === 0 ||
      !path.isAbsolute(normalized)
    ) {
      throw new Error(
        "INVALID_SERVER_RULESET_WORKSPACE_ROOT"
      );
    }

    this.workspaceRoot =
      path.resolve(normalized);

    this.aegisDirectoryPath =
      path.join(
        this.workspaceRoot,
        ".aegis"
      );

    this.directoryPath =
      path.join(
        this.workspaceRoot,
        SERVER_RULESET_DIRECTORY_RELATIVE_PATH
      );

    this.statePath =
      path.join(
        this.directoryPath,
        SERVER_RULESET_STATE_FILE_NAME
      );

    this.lkgPath =
      path.join(
        this.directoryPath,
        SERVER_RULESET_LKG_FILE_NAME
      );

    this.lockPath =
      path.join(
        this.directoryPath,
        SERVER_RULESET_LOCK_FILE_NAME
      );
  }

  private async assertWorkspaceRoot():
    Promise<void> {
    const metadata =
      await fs.promises.lstat(
        this.workspaceRoot
      );

    assertTrustedDirectoryMetadata(
      metadata,
      "INVALID_SERVER_RULESET_WORKSPACE_ROOT_METADATA"
    );
  }

  private async ensureDirectory():
    Promise<void> {
    await this.assertWorkspaceRoot();

    const aegisMetadata =
      await lstatOrNull(
        this.aegisDirectoryPath
      );

    if (aegisMetadata === null) {
      await fs.promises.mkdir(
        this.aegisDirectoryPath,
        {
          mode: 0o700,
        }
      );
    } else {
      assertTrustedDirectoryMetadata(
        aegisMetadata,
        "INVALID_AEGIS_DIRECTORY_METADATA"
      );
    }

    const verifiedAegisMetadata =
      await fs.promises.lstat(
        this.aegisDirectoryPath
      );

    assertTrustedDirectoryMetadata(
      verifiedAegisMetadata,
      "INVALID_AEGIS_DIRECTORY_METADATA"
    );

    const directoryMetadata =
      await lstatOrNull(
        this.directoryPath
      );

    if (directoryMetadata === null) {
      await fs.promises.mkdir(
        this.directoryPath,
        {
          mode: 0o700,
        }
      );
    } else {
      assertTrustedDirectoryMetadata(
        directoryMetadata,
        "INVALID_SERVER_RULESET_DIRECTORY_METADATA"
      );
    }

    const verifiedDirectoryMetadata =
      await fs.promises.lstat(
        this.directoryPath
      );

    assertTrustedDirectoryMetadata(
      verifiedDirectoryMetadata,
      "INVALID_SERVER_RULESET_DIRECTORY_METADATA"
    );
  }

  private async readExistingDirectory():
    Promise<boolean> {
    await this.assertWorkspaceRoot();

    const aegisMetadata =
      await lstatOrNull(
        this.aegisDirectoryPath
      );

    if (aegisMetadata === null) {
      return false;
    }

    assertTrustedDirectoryMetadata(
      aegisMetadata,
      "INVALID_AEGIS_DIRECTORY_METADATA"
    );

    const directoryMetadata =
      await lstatOrNull(
        this.directoryPath
      );

    if (directoryMetadata === null) {
      return false;
    }

    assertTrustedDirectoryMetadata(
      directoryMetadata,
      "INVALID_SERVER_RULESET_DIRECTORY_METADATA"
    );

    return true;
  }

  private async readSnapshotFromDirectory():
    Promise<StoredServerRulesetSnapshot | null> {
    const stateMetadata =
      await lstatOrNull(
        this.statePath
      );

    const lkgMetadata =
      await lstatOrNull(
        this.lkgPath
      );

    if (
      stateMetadata === null &&
      lkgMetadata === null
    ) {
      return null;
    }

    if (
      stateMetadata === null ||
      lkgMetadata === null
    ) {
      throw new Error(
        "INCOMPLETE_SERVER_RULESET_SNAPSHOT"
      );
    }

    const state =
      parsePersistentState(
        await readRegularUtf8File(
          this.statePath,
          MAX_SERVER_RULESET_STATE_FILE_BYTES
        )
      );

    const lkg =
      parsePersistentLkg(
        await readRegularUtf8File(
          this.lkgPath,
          MAX_SERVER_RULESET_LKG_FILE_BYTES
        )
      );

    const snapshot =
      Object.freeze({
        state,
        lkg,
      });

    validateSnapshotLinkage(
      snapshot
    );

    return snapshot;
  }

  async readSnapshot():
    Promise<StoredServerRulesetSnapshot | null> {
    if (
      !await this.readExistingDirectory()
    ) {
      return null;
    }

    return this.readSnapshotFromDirectory();
  }

  async commitSnapshot(
    input: ServerRulesetSnapshotInput
  ): Promise<ServerRulesetCommitResult> {
    let lockHandle:
      fs.promises.FileHandle | null =
        null;

    let lockCreated = false;

    let result:
      ServerRulesetCommitResult = {
        status: "REJECTED",
        error:
          "SERVER_RULESET_COMMIT_NOT_STARTED",
      };

    try {
      const candidate =
        buildCandidateSnapshot(input);

      await this.ensureDirectory();

      lockHandle =
        await fs.promises.open(
          this.lockPath,
          "wx",
          0o600
        );

      lockCreated = true;

      await lockHandle.writeFile(
        JSON.stringify(
          {
            pid: process.pid,
            createdAt:
              new Date().toISOString(),
          }
        ) + "\n",
        {
          encoding: "utf8",
        }
      );

      await lockHandle.sync();

      await new Promise<void>(
        resolve =>
          setImmediate(resolve)
      );

      const current =
        await this
          .readSnapshotFromDirectory();

      if (
        current !== null &&
        snapshotsEqual(
          current,
          candidate
        )
      ) {
        result = {
          status: "UNCHANGED",
          error: null,
        };

        return result;
      }

      if (current !== null) {
        assertAdvanceAllowed(
          current,
          candidate
        );
      }

      const stateText =
        serializeState(
          candidate.state
        );

      const lkgText =
        serializeLkg(
          candidate.lkg
        );

      if (
        Buffer.byteLength(
          stateText,
          "utf8"
        ) >
        MAX_SERVER_RULESET_STATE_FILE_BYTES
      ) {
        throw new Error(
          "SERVER_RULESET_STATE_TOO_LARGE"
        );
      }

      if (
        Buffer.byteLength(
          lkgText,
          "utf8"
        ) >
        MAX_SERVER_RULESET_LKG_FILE_BYTES
      ) {
        throw new Error(
          "SERVER_RULESET_LKG_TOO_LARGE"
        );
      }

      await writeUtf8FileAtomically(
        this.lkgPath,
        lkgText
      );

      await writeUtf8FileAtomically(
        this.statePath,
        stateText
      );

      const verified =
        await this
          .readSnapshotFromDirectory();

      if (
        verified === null ||
        !snapshotsEqual(
          verified,
          candidate
        )
      ) {
        throw new Error(
          "POST_COMMIT_SERVER_RULESET_VERIFICATION_FAILED"
        );
      }

      result = {
        status: "COMMITTED",
        error: null,
      };

      return result;
    } catch (error) {
      result = {
        status: "REJECTED",
        error:
          error instanceof Error
            ? error.message
            : String(error),
      };

      return result;
    } finally {
      let cleanupFailed = false;

      if (lockHandle !== null) {
        try {
          await lockHandle.close();
        } catch {
          cleanupFailed = true;
        }
      }

      if (lockCreated) {
        try {
          await fs.promises.unlink(
            this.lockPath
          );
        } catch {
          cleanupFailed = true;
        }
      }

      if (cleanupFailed) {
        result = {
          status: "REJECTED",
          error:
            "SERVER_RULESET_LOCK_CLEANUP_FAILED",
        };
      }
    }
  }
}
