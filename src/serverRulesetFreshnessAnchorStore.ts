import * as fs from "node:fs";
import * as path from "node:path";

export const SERVER_RULESET_FRESHNESS_ANCHOR_DIRECTORY_RELATIVE_PATH =
  path.join(
    ".aegis",
    "server-ruleset"
  );

export const SERVER_RULESET_FRESHNESS_ANCHOR_FILE_NAME =
  "freshness-anchor.json";

export const SERVER_RULESET_FRESHNESS_ANCHOR_LOCK_FILE_NAME =
  "freshness-anchor.lock";

export const MAX_SERVER_RULESET_FRESHNESS_ANCHOR_FILE_BYTES =
  16 * 1024;

const LOCK_RETRY_ATTEMPTS = 2000;
const LOCK_RETRY_DELAY_MS = 2;

let temporaryFileSequence = 0;

export interface ServerRulesetFreshnessAnchorRecordV1 {
  readonly packageSha256: string;
  readonly rulesetSha256: string;
  readonly highestIntermediateSequence: number;
  readonly rulesetVersion: number;
  readonly monotonicCounter: number;
  readonly anchoredAtEpochMs: number;
}

export interface PersistentServerRulesetFreshnessAnchorsV1 {
  readonly schemaVersion: 1;
  readonly current:
    ServerRulesetFreshnessAnchorRecordV1 | null;
  readonly lkg:
    ServerRulesetFreshnessAnchorRecordV1 | null;
}

export interface ServerRulesetFreshnessAnchorCommitInput {
  readonly nowEpochMs: number;
  readonly current:
    ServerRulesetFreshnessAnchorRecordV1 | null;
  readonly lkg:
    ServerRulesetFreshnessAnchorRecordV1 | null;
}

export type ServerRulesetFreshnessAnchorCommitStatus =
  | "COMMITTED"
  | "UNCHANGED"
  | "REJECTED";

export interface ServerRulesetFreshnessAnchorCommitResult {
  readonly status:
    ServerRulesetFreshnessAnchorCommitStatus;
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
  const actualKeys =
    Object.keys(value).sort();

  const sortedExpected =
    [...expectedKeys].sort();

  return (
    actualKeys.length ===
      sortedExpected.length &&
    actualKeys.every(
      (key, index) =>
        key === sortedExpected[index]
    )
  );
}

function isNonNegativeSafeInteger(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isPositiveSafeInteger(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 1
  );
}

function isSha256(
  value: unknown
): value is string {
  if (
    typeof value !== "string" ||
    value.length !== 64
  ) {
    return false;
  }

  const alphabet =
    "0123456789abcdefABCDEF";

  for (const character of value) {
    if (!alphabet.includes(character)) {
      return false;
    }
  }

  return true;
}

function errorCode(
  error: unknown
): string | null {
  if (
    isRecord(error) &&
    typeof error.code === "string"
  ) {
    return error.code;
  }

  return null;
}

function errorText(
  error: unknown
): string {
  return (
    error instanceof Error
      ? error.message
      : String(error)
  );
}

function appendError(
  existing: string | null,
  next: string
): string {
  return (
    existing === null ||
    existing.length === 0
      ? next
      : existing + "|" + next
  );
}

function freezeAnchorRecord(
  value:
    ServerRulesetFreshnessAnchorRecordV1
): ServerRulesetFreshnessAnchorRecordV1 {
  return Object.freeze({
    packageSha256:
      value.packageSha256.toLowerCase(),
    rulesetSha256:
      value.rulesetSha256.toLowerCase(),
    highestIntermediateSequence:
      value.highestIntermediateSequence,
    rulesetVersion:
      value.rulesetVersion,
    monotonicCounter:
      value.monotonicCounter,
    anchoredAtEpochMs:
      value.anchoredAtEpochMs,
  });
}

function parseAnchorRecord(
  value: unknown,
  label: string
): ServerRulesetFreshnessAnchorRecordV1 {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "anchoredAtEpochMs",
        "highestIntermediateSequence",
        "monotonicCounter",
        "packageSha256",
        "rulesetSha256",
        "rulesetVersion",
      ]
    ) ||
    !isSha256(
      value.packageSha256
    ) ||
    !isSha256(
      value.rulesetSha256
    ) ||
    !isPositiveSafeInteger(
      value.highestIntermediateSequence
    ) ||
    !isPositiveSafeInteger(
      value.rulesetVersion
    ) ||
    !isPositiveSafeInteger(
      value.monotonicCounter
    ) ||
    !isNonNegativeSafeInteger(
      value.anchoredAtEpochMs
    )
  ) {
    throw new Error(
      "INVALID_" +
      label +
      "_SERVER_RULESET_FRESHNESS_ANCHOR"
    );
  }

  return freezeAnchorRecord({
    packageSha256:
      value.packageSha256,
    rulesetSha256:
      value.rulesetSha256,
    highestIntermediateSequence:
      value.highestIntermediateSequence,
    rulesetVersion:
      value.rulesetVersion,
    monotonicCounter:
      value.monotonicCounter,
    anchoredAtEpochMs:
      value.anchoredAtEpochMs,
  });
}

function parseNullableAnchorRecord(
  value: unknown,
  label: string
):
  ServerRulesetFreshnessAnchorRecordV1 | null {
  if (value === null) {
    return null;
  }

  return parseAnchorRecord(
    value,
    label
  );
}

function parsePersistentAnchors(
  text: string
): PersistentServerRulesetFreshnessAnchorsV1 {
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(
      "INVALID_SERVER_RULESET_FRESHNESS_ANCHOR_JSON"
    );
  }

  if (
    !isRecord(parsed) ||
    !hasExactKeys(
      parsed,
      [
        "current",
        "lkg",
        "schemaVersion",
      ]
    ) ||
    parsed.schemaVersion !== 1
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_FRESHNESS_ANCHOR_DOCUMENT"
    );
  }

  const current =
    parseNullableAnchorRecord(
      parsed.current,
      "CURRENT"
    );

  const lkg =
    parseNullableAnchorRecord(
      parsed.lkg,
      "LKG"
    );

  return Object.freeze({
    schemaVersion: 1,
    current,
    lkg,
  });
}

function buildCandidateAnchors(
  input: unknown
): PersistentServerRulesetFreshnessAnchorsV1 {
  if (
    !isRecord(input) ||
    !hasExactKeys(
      input,
      [
        "current",
        "lkg",
        "nowEpochMs",
      ]
    ) ||
    !isNonNegativeSafeInteger(
      input.nowEpochMs
    )
  ) {
    throw new Error(
      "INVALID_SERVER_RULESET_FRESHNESS_ANCHOR_COMMIT_INPUT"
    );
  }

  const current =
    parseNullableAnchorRecord(
      input.current,
      "CURRENT"
    );

  const lkg =
    parseNullableAnchorRecord(
      input.lkg,
      "LKG"
    );

  if (
    current !== null &&
    current.anchoredAtEpochMs >
      input.nowEpochMs
  ) {
    throw new Error(
      "CURRENT_FRESHNESS_ANCHOR_IN_FUTURE"
    );
  }

  if (
    lkg !== null &&
    lkg.anchoredAtEpochMs >
      input.nowEpochMs
  ) {
    throw new Error(
      "LKG_FRESHNESS_ANCHOR_IN_FUTURE"
    );
  }

  return Object.freeze({
    schemaVersion: 1,
    current,
    lkg,
  });
}

function serializeAnchors(
  value:
    PersistentServerRulesetFreshnessAnchorsV1
): string {
  return (
    JSON.stringify(
      {
        schemaVersion:
          value.schemaVersion,
        current:
          value.current === null
            ? null
            : {
                packageSha256:
                  value.current
                    .packageSha256,
                rulesetSha256:
                  value.current
                    .rulesetSha256,
                highestIntermediateSequence:
                  value.current
                    .highestIntermediateSequence,
                rulesetVersion:
                  value.current
                    .rulesetVersion,
                monotonicCounter:
                  value.current
                    .monotonicCounter,
                anchoredAtEpochMs:
                  value.current
                    .anchoredAtEpochMs,
              },
        lkg:
          value.lkg === null
            ? null
            : {
                packageSha256:
                  value.lkg
                    .packageSha256,
                rulesetSha256:
                  value.lkg
                    .rulesetSha256,
                highestIntermediateSequence:
                  value.lkg
                    .highestIntermediateSequence,
                rulesetVersion:
                  value.lkg
                    .rulesetVersion,
                monotonicCounter:
                  value.lkg
                    .monotonicCounter,
                anchoredAtEpochMs:
                  value.lkg
                    .anchoredAtEpochMs,
              },
      },
      null,
      2
    ) + "\n"
  );
}

function anchorsEqual(
  left:
    PersistentServerRulesetFreshnessAnchorsV1,
  right:
    PersistentServerRulesetFreshnessAnchorsV1
): boolean {
  return (
    serializeAnchors(left) ===
    serializeAnchors(right)
  );
}

function assertRecordAdvanceAllowed(
  current:
    ServerRulesetFreshnessAnchorRecordV1 |
    null,
  candidate:
    ServerRulesetFreshnessAnchorRecordV1 |
    null,
  label: "CURRENT" | "LKG"
): void {
  if (current === null) {
    return;
  }

  if (candidate === null) {
    throw new Error(
      label +
      "_FRESHNESS_ANCHOR_DELETE_REJECTED"
    );
  }

  if (
    candidate.highestIntermediateSequence <
    current.highestIntermediateSequence
  ) {
    throw new Error(
      label +
      "_INTERMEDIATE_SEQUENCE_DOWNGRADE"
    );
  }

  if (
    candidate.rulesetVersion <
    current.rulesetVersion
  ) {
    throw new Error(
      label +
      "_RULESET_VERSION_DOWNGRADE"
    );
  }

  if (
    candidate.monotonicCounter <
    current.monotonicCounter
  ) {
    throw new Error(
      label +
      "_RULESET_COUNTER_DOWNGRADE"
    );
  }

  if (
    candidate.anchoredAtEpochMs <
    current.anchoredAtEpochMs
  ) {
    throw new Error(
      label +
      "_FRESHNESS_ANCHOR_TIME_DOWNGRADE"
    );
  }

  const samePackage =
    candidate.packageSha256 ===
    current.packageSha256;

  const sameTrustTuple =
    candidate.highestIntermediateSequence ===
      current.highestIntermediateSequence &&
    candidate.rulesetVersion ===
      current.rulesetVersion &&
    candidate.monotonicCounter ===
      current.monotonicCounter;

  if (samePackage) {
    if (
      !sameTrustTuple ||
      candidate.rulesetSha256 !==
        current.rulesetSha256
    ) {
      throw new Error(
        label +
        "_PACKAGE_IDENTITY_REBOUND"
      );
    }

    return;
  }

  if (sameTrustTuple) {
    throw new Error(
      label +
      "_TRUST_TUPLE_HASH_REBOUND"
    );
  }
}

function assertAdvanceAllowed(
  current:
    PersistentServerRulesetFreshnessAnchorsV1,
  candidate:
    PersistentServerRulesetFreshnessAnchorsV1
): void {
  assertRecordAdvanceAllowed(
    current.current,
    candidate.current,
    "CURRENT"
  );

  assertRecordAdvanceAllowed(
    current.lkg,
    candidate.lkg,
    "LKG"
  );
}

async function lstatOrNull(
  literalPath: string
): Promise<fs.Stats | null> {
  try {
    return await fs.promises.lstat(
      literalPath
    );
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      return null;
    }

    throw error;
  }
}

function assertTrustedDirectoryMetadata(
  metadata: fs.Stats,
  errorName: string
): void {
  if (
    metadata.isSymbolicLink() ||
    !metadata.isDirectory()
  ) {
    throw new Error(errorName);
  }
}

async function readRegularUtf8File(
  literalPath: string
): Promise<string> {
  const metadata =
    await fs.promises.lstat(
      literalPath
    );

  if (
    metadata.isSymbolicLink() ||
    !metadata.isFile() ||
    metadata.size >
      MAX_SERVER_RULESET_FRESHNESS_ANCHOR_FILE_BYTES
  ) {
    throw new Error(
      "UNTRUSTED_SERVER_RULESET_FRESHNESS_ANCHOR_FILE_METADATA"
    );
  }

  const text =
    await fs.promises.readFile(
      literalPath,
      {
        encoding: "utf8",
      }
    );

  if (
    Buffer.byteLength(
      text,
      "utf8"
    ) >
    MAX_SERVER_RULESET_FRESHNESS_ANCHOR_FILE_BYTES
  ) {
    throw new Error(
      "SERVER_RULESET_FRESHNESS_ANCHOR_FILE_TOO_LARGE"
    );
  }

  return text;
}

function nextTemporaryPath(
  targetPath: string
): string {
  temporaryFileSequence += 1;

  return path.join(
    path.dirname(targetPath),
    "." +
    path.basename(targetPath) +
    "." +
    process.pid.toString(10) +
    "." +
    temporaryFileSequence.toString(10) +
    ".tmp"
  );
}

async function writeUtf8FileAtomically(
  targetPath: string,
  text: string
): Promise<void> {
  if (
    Buffer.byteLength(
      text,
      "utf8"
    ) >
    MAX_SERVER_RULESET_FRESHNESS_ANCHOR_FILE_BYTES
  ) {
    throw new Error(
      "SERVER_RULESET_FRESHNESS_ANCHOR_FILE_TOO_LARGE"
    );
  }

  const temporaryPath =
    nextTemporaryPath(targetPath);

  let handle:
    fs.promises.FileHandle | null =
    null;

  let primaryError:
    string | null =
    null;

  try {
    handle =
      await fs.promises.open(
        temporaryPath,
        "wx",
        0o600
      );

    await handle.writeFile(
      text,
      {
        encoding: "utf8",
      }
    );

    await handle.sync();
    await handle.close();
    handle = null;

    await fs.promises.rename(
      temporaryPath,
      targetPath
    );
  } catch (error) {
    primaryError =
      errorText(error);

    throw error;
  } finally {
    let cleanupError:
      string | null =
      null;

    if (handle !== null) {
      try {
        await handle.close();
      } catch (error) {
        cleanupError =
          appendError(
            cleanupError,
            "TEMP_HANDLE_CLOSE_FAILED=" +
            errorText(error)
          );
      }
    }

    try {
      await fs.promises.unlink(
        temporaryPath
      );
    } catch (error) {
      if (
        errorCode(error) !== "ENOENT"
      ) {
        cleanupError =
          appendError(
            cleanupError,
            "TEMP_FILE_CLEANUP_FAILED=" +
            errorText(error)
          );
      }
    }

    if (
      cleanupError !== null &&
      primaryError === null
    ) {
      throw new Error(
        cleanupError
      );
    }
  }
}

function delay(
  milliseconds: number
): Promise<void> {
  return new Promise(
    resolve =>
      setTimeout(
        resolve,
        milliseconds
      )
  );
}

async function acquireExclusiveLock(
  lockPath: string,
  nowEpochMs: number
): Promise<fs.promises.FileHandle> {
  for (
    let attempt = 0;
    attempt < LOCK_RETRY_ATTEMPTS;
    attempt++
  ) {
    let handle:
      fs.promises.FileHandle | null =
      null;

    try {
      handle =
        await fs.promises.open(
          lockPath,
          "wx",
          0o600
        );

      await handle.writeFile(
        JSON.stringify({
          pid: process.pid,
          nowEpochMs,
        }) + "\n",
        {
          encoding: "utf8",
        }
      );

      await handle.sync();

      return handle;
    } catch (error) {
      let cleanupError:
        string | null =
        null;

      if (handle !== null) {
        try {
          await handle.close();
        } catch (closeError) {
          cleanupError =
            appendError(
              cleanupError,
              "LOCK_HANDLE_CLOSE_FAILED=" +
              errorText(closeError)
            );
        }

        try {
          await fs.promises.unlink(
            lockPath
          );
        } catch (unlinkError) {
          if (
            errorCode(unlinkError) !==
            "ENOENT"
          ) {
            cleanupError =
              appendError(
                cleanupError,
                "LOCK_FILE_CLEANUP_FAILED=" +
                errorText(unlinkError)
              );
          }
        }
      }

      if (cleanupError !== null) {
        throw new Error(
          cleanupError
        );
      }

      if (
        errorCode(error) !== "EEXIST"
      ) {
        throw error;
      }

      await delay(
        LOCK_RETRY_DELAY_MS
      );
    }
  }

  throw new Error(
    "SERVER_RULESET_FRESHNESS_ANCHOR_LOCK_UNAVAILABLE"
  );
}

export class FileServerRulesetFreshnessAnchorStore {
  readonly workspaceRoot: string;
  readonly aegisDirectoryPath: string;
  readonly directoryPath: string;
  readonly anchorPath: string;
  readonly lockPath: string;

  constructor(
    workspaceRoot: string
  ) {
    if (
      typeof workspaceRoot !== "string" ||
      workspaceRoot.trim().length < 1 ||
      !path.isAbsolute(workspaceRoot)
    ) {
      throw new Error(
        "INVALID_SERVER_RULESET_FRESHNESS_ANCHOR_WORKSPACE_ROOT"
      );
    }

    this.workspaceRoot =
      workspaceRoot;

    this.aegisDirectoryPath =
      path.join(
        workspaceRoot,
        ".aegis"
      );

    this.directoryPath =
      path.join(
        workspaceRoot,
        SERVER_RULESET_FRESHNESS_ANCHOR_DIRECTORY_RELATIVE_PATH
      );

    this.anchorPath =
      path.join(
        this.directoryPath,
        SERVER_RULESET_FRESHNESS_ANCHOR_FILE_NAME
      );

    this.lockPath =
      path.join(
        this.directoryPath,
        SERVER_RULESET_FRESHNESS_ANCHOR_LOCK_FILE_NAME
      );
  }

  private async ensureDirectory():
    Promise<void> {
    const aegisMetadata =
      await lstatOrNull(
        this.aegisDirectoryPath
      );

    if (aegisMetadata === null) {
      try {
        await fs.promises.mkdir(
          this.aegisDirectoryPath,
          {
            mode: 0o700,
          }
        );
      } catch (error) {
        if (
          errorCode(error) !==
          "EEXIST"
        ) {
          throw error;
        }
      }
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
      try {
        await fs.promises.mkdir(
          this.directoryPath,
          {
            mode: 0o700,
          }
        );
      } catch (error) {
        if (
          errorCode(error) !==
          "EEXIST"
        ) {
          throw error;
        }
      }
    }

    const verifiedDirectoryMetadata =
      await fs.promises.lstat(
        this.directoryPath
      );

    assertTrustedDirectoryMetadata(
      verifiedDirectoryMetadata,
      "INVALID_SERVER_RULESET_FRESHNESS_ANCHOR_DIRECTORY_METADATA"
    );
  }

  private async readExistingDirectory():
    Promise<boolean> {
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
      "INVALID_SERVER_RULESET_FRESHNESS_ANCHOR_DIRECTORY_METADATA"
    );

    return true;
  }

  private async readRawTextFromDirectory():
    Promise<string | null> {
    const metadata =
      await lstatOrNull(
        this.anchorPath
      );

    if (metadata === null) {
      return null;
    }

    return readRegularUtf8File(
      this.anchorPath
    );
  }

  private async readAnchorsFromDirectory():
    Promise<
      PersistentServerRulesetFreshnessAnchorsV1 |
      null
    > {
    const text =
      await this
        .readRawTextFromDirectory();

    if (text === null) {
      return null;
    }

    return parsePersistentAnchors(
      text
    );
  }

  async readAnchors():
    Promise<
      PersistentServerRulesetFreshnessAnchorsV1 |
      null
    > {
    if (
      !await this
        .readExistingDirectory()
    ) {
      return null;
    }

    return this
      .readAnchorsFromDirectory();
  }

  async commitAnchors(
    input:
      ServerRulesetFreshnessAnchorCommitInput
  ): Promise<
    ServerRulesetFreshnessAnchorCommitResult
  > {
    let lockHandle:
      fs.promises.FileHandle | null =
      null;

    let lockCreated = false;
    let physicalReplacement = false;

    let previousText:
      string | null =
      null;

    let result:
      ServerRulesetFreshnessAnchorCommitResult =
      {
        status: "REJECTED",
        error:
          "SERVER_RULESET_FRESHNESS_ANCHOR_COMMIT_NOT_STARTED",
      };

    try {
      const candidate =
        buildCandidateAnchors(
          input
        );

      await this.ensureDirectory();

      lockHandle =
        await acquireExclusiveLock(
          this.lockPath,
          input.nowEpochMs
        );

      lockCreated = true;

      previousText =
        await this
          .readRawTextFromDirectory();

      const current =
        previousText === null
          ? null
          : parsePersistentAnchors(
              previousText
            );

      if (
        current !== null &&
        anchorsEqual(
          current,
          candidate
        )
      ) {
        result = {
          status: "UNCHANGED",
          error: null,
        };
      } else {
        if (current !== null) {
          assertAdvanceAllowed(
            current,
            candidate
          );
        }

        const candidateText =
          serializeAnchors(
            candidate
          );

        await writeUtf8FileAtomically(
          this.anchorPath,
          candidateText
        );

        physicalReplacement = true;

        const verified =
          await this
            .readAnchorsFromDirectory();

        if (
          verified === null ||
          !anchorsEqual(
            verified,
            candidate
          )
        ) {
          throw new Error(
            "POST_COMMIT_SERVER_RULESET_FRESHNESS_ANCHOR_VERIFICATION_FAILED"
          );
        }

        result = {
          status: "COMMITTED",
          error: null,
        };
      }
    } catch (error) {
      const originalError =
        errorText(error);

      let rollbackError:
        string | null =
        null;

      if (physicalReplacement) {
        try {
          if (previousText === null) {
            try {
              await fs.promises.unlink(
                this.anchorPath
              );
            } catch (unlinkError) {
              if (
                errorCode(unlinkError) !==
                "ENOENT"
              ) {
                throw unlinkError;
              }
            }

            const restoredMetadata =
              await lstatOrNull(
                this.anchorPath
              );

            if (
              restoredMetadata !== null
            ) {
              throw new Error(
                "SERVER_RULESET_FRESHNESS_ANCHOR_ROLLBACK_DELETE_FAILED"
              );
            }
          } else {
            await writeUtf8FileAtomically(
              this.anchorPath,
              previousText
            );

            const restoredText =
              await this
                .readRawTextFromDirectory();

            if (
              restoredText !==
              previousText
            ) {
              throw new Error(
                "SERVER_RULESET_FRESHNESS_ANCHOR_ROLLBACK_CONTENT_MISMATCH"
              );
            }
          }
        } catch (restoreError) {
          rollbackError =
            errorText(
              restoreError
            );
        }
      }

      result = {
        status: "REJECTED",
        error:
          rollbackError === null
            ? originalError
            : originalError +
              "|ROLLBACK_FAILED=" +
              rollbackError,
      };
    } finally {
      let cleanupError:
        string | null =
        null;

      if (lockHandle !== null) {
        try {
          await lockHandle.close();
        } catch (error) {
          cleanupError =
            appendError(
              cleanupError,
              "LOCK_HANDLE_CLOSE_FAILED=" +
              errorText(error)
            );
        }
      }

      if (lockCreated) {
        try {
          await fs.promises.unlink(
            this.lockPath
          );
        } catch (error) {
          if (
            errorCode(error) !==
            "ENOENT"
          ) {
            cleanupError =
              appendError(
                cleanupError,
                "LOCK_FILE_CLEANUP_FAILED=" +
                errorText(error)
              );
          }
        }
      }

      if (cleanupError !== null) {
        result = {
          status: "REJECTED",
          error:
            appendError(
              result.error,
              cleanupError
            ),
        };
      }
    }

    return result;
  }
}
