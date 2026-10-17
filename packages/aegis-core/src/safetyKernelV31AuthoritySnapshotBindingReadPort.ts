import * as crypto from "crypto";
import * as fs from "fs";
import * as nodePath from "path";

import type {
  SafetyKernelV31AuthoritySnapshotBindingReadback,
  SafetyKernelV31AuthoritySnapshotBindingReadPort as SafetyKernelV31AuthoritySnapshotBindingReadPortContract,
} from "./safetyKernelV31AuthoritySnapshotBindingVerifier";

export interface SafetyKernelV31CanonicalAuthorityReader {
  getState(): unknown;
}

export interface SafetyKernelV31SnapshotTargetIndexReader {
  readonly targetId: string;
  readonly relativePath: string;
  readonly snapshotIndexFile: string;
  readIndex(): Promise<unknown>;
}

export const SAFETY_KERNEL_V31_AUTHORITY_SNAPSHOT_BINDING_READ_PORT_INVARIANT =
  Object.freeze({
    AUTHORITY_STATE_READ_ON_EVERY_CALL: true,
    EACH_INDEX_READ_ON_EVERY_CALL: true,
    NULL_INDEX_SKIPPED_AS_UNREGISTERED: true,
    AT_LEAST_ONE_REGISTERED_INDEX_REQUIRED: true,
    NON_NULL_MALFORMED_INDEX_REJECTED: true,
    BASELINE_FILE_BYTES_READ_ON_EVERY_CALL: true,
    STATE_CACHE_ALLOWED: false,
    AUTHORITY_TARGET_SET_EXACT_MATCH_REQUIRED: true,
    DUPLICATE_TARGET_ID_REJECTED: true,
    DUPLICATE_INDEX_FILENAME_REJECTED: true,
    ORIGINAL_PATH_BINDING_REQUIRED: true,
    NORMALIZED_KEY_BINDING_REQUIRED: true,
    BASELINE_PATH_MUST_BE_ABSOLUTE: true,
    BASELINE_PATH_MUST_BE_INSIDE_SNAPSHOTS: true,
    BASELINE_REALPATH_CONTAINMENT_REQUIRED: true,
    BASELINE_FILE_SHA256_RECHECK_REQUIRED: true,
    ROLLING_FIELDS_INCLUDED_IN_AGGREGATE: false,
    SNAPSHOT_ID_INCLUDED_IN_AGGREGATE: false,
    CREATED_AT_INCLUDED_IN_AGGREGATE: false,
    EXTENSION_CONNECTED: false,
    NODE_PROCESS_ADAPTER_CONNECTED: false,
    REAL_COMMAND_EXECUTION_REQUIRED: false,
  } as const);

interface AuthorityStateReadback {
  readonly revision: number;
  readonly workspaceId: string;
  readonly protectedTargets: readonly string[];
}

interface ImmutableSnapshotBindingEntry {
  readonly targetId: string;
  readonly relativePath: string;
  readonly snapshotIndexFile: string;
  readonly baselineSnapshotFile: string;
  readonly baselineContentSha256: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function codeUnitCompare(left: string, right: string): number {
  if (left < right) {
    return -1;
  }

  if (left > right) {
    return 1;
  }

  return 0;
}

function requireInlineIdentifier(
  value: unknown,
  errorCode: string
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 300 ||
    value.trim() !== value ||
    /[\r\n\u0000]/.test(value)
  ) {
    throw new Error(errorCode);
  }

  return value;
}

function requireAuthorityState(value: unknown): AuthorityStateReadback {
  if (!isRecord(value)) {
    throw new Error("MALFORMED_AUTHORITY_STATE");
  }

  if (
    typeof value.revision !== "number" ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0
  ) {
    throw new Error("INVALID_AUTHORITY_REVISION");
  }

  const workspaceId =
    requireInlineIdentifier(
      value.workspaceId,
      "INVALID_AUTHORITY_WORKSPACE_ID"
    );

  if (!/^sha256:[a-f0-9]{64}$/.test(workspaceId)) {
    throw new Error("INVALID_AUTHORITY_WORKSPACE_ID");
  }

  if (!Array.isArray(value.protectedTargets)) {
    throw new Error("INVALID_AUTHORITY_PROTECTED_TARGETS");
  }

  const protectedTargets = value.protectedTargets.map(
    targetId =>
      requireInlineIdentifier(
        targetId,
        "INVALID_AUTHORITY_PROTECTED_TARGET_ID"
      )
  );

  if (
    protectedTargets.length === 0 ||
    new Set(protectedTargets).size !== protectedTargets.length
  ) {
    throw new Error("INVALID_AUTHORITY_PROTECTED_TARGET_SET");
  }

  return {
    revision: value.revision,
    workspaceId,
    protectedTargets,
  };
}

function normalizePathForBinding(value: string): string {
  return value.replace(/\\/g, "/").toLowerCase();
}

function isInsidePath(root: string, candidate: string): boolean {
  const normalizedRoot = normalizePathForBinding(root);
  const normalizedCandidate =
    normalizePathForBinding(candidate);

  return (
    normalizedCandidate === normalizedRoot ||
    normalizedCandidate.startsWith(
      normalizedRoot + "/"
    )
  );
}

function requireIndexFileName(value: unknown): string {
  const result =
    requireInlineIdentifier(
      value,
      "INVALID_SNAPSHOT_INDEX_FILENAME"
    );

  if (
    nodePath.isAbsolute(result) ||
    nodePath.basename(result) !== result ||
    result === "." ||
    result === ".."
  ) {
    throw new Error("INVALID_SNAPSHOT_INDEX_FILENAME");
  }

  return result;
}

function requireRelativeTargetPath(value: unknown): string {
  const result =
    requireInlineIdentifier(
      value,
      "INVALID_TARGET_RELATIVE_PATH"
    );

  if (nodePath.isAbsolute(result)) {
    throw new Error("INVALID_TARGET_RELATIVE_PATH");
  }

  return result;
}

function requireIndexRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error("MALFORMED_SNAPSHOT_INDEX");
  }

  return value;
}

function requireSha256Hex(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[a-f0-9]{64}$/.test(value)
  ) {
    throw new Error("INVALID_BASELINE_CONTENT_SHA256");
  }

  return value;
}

function encodeField(name: string, value: string): string {
  return (
    name +
    ":" +
    Buffer.byteLength(value, "utf8") +
    ":" +
    value
  );
}

function encodeAggregate(
  entries: readonly ImmutableSnapshotBindingEntry[]
): string {
  const lines: string[] = [
    encodeField(
      "domain",
      "aegis-authority-snapshot-binding-v1"
    ),
    encodeField(
      "targetCount",
      String(entries.length)
    ),
  ];

  entries.forEach((entry, index) => {
    const prefix = "target[" + index + "]";

    lines.push(
      encodeField(
        prefix + ".targetId",
        entry.targetId
      ),
      encodeField(
        prefix + ".relativePath",
        entry.relativePath
      ),
      encodeField(
        prefix + ".snapshotIndexFile",
        entry.snapshotIndexFile
      ),
      encodeField(
        prefix + ".baselineSnapshotFile",
        entry.baselineSnapshotFile
      ),
      encodeField(
        prefix + ".baselineContentSha256",
        entry.baselineContentSha256
      )
    );
  });

  return lines.join("\n");
}

function sha256Prefixed(value: Buffer | string): string {
  return (
    "sha256:" +
    crypto
      .createHash("sha256")
      .update(value)
      .digest("hex")
  );
}

export class SafetyKernelV31AuthoritySnapshotBindingReadPort
  implements SafetyKernelV31AuthoritySnapshotBindingReadPortContract {
  private readonly projectRoot: string;
  private readonly snapshotsDir: string;

  constructor(
    private readonly authorityReader:
      SafetyKernelV31CanonicalAuthorityReader,
    private readonly targetReaders:
      readonly SafetyKernelV31SnapshotTargetIndexReader[],
    projectRoot: string,
    aegisDir: string
  ) {
    this.projectRoot = nodePath.resolve(
      requireInlineIdentifier(
        projectRoot,
        "INVALID_PROJECT_ROOT"
      )
    );

    this.snapshotsDir = nodePath.resolve(
      requireInlineIdentifier(
        aegisDir,
        "INVALID_AEGIS_DIR"
      ),
      "snapshots"
    );
  }

  async readCurrentBinding():
    Promise<SafetyKernelV31AuthoritySnapshotBindingReadback> {
    const authority =
      requireAuthorityState(
        this.authorityReader.getState()
      );

    if (
      !Array.isArray(this.targetReaders) ||
      this.targetReaders.length === 0
    ) {
      throw new Error("EMPTY_SNAPSHOT_TARGET_READERS");
    }

    const descriptors =
      this.targetReaders.map(reader => {
        if (
          reader === null ||
          typeof reader !== "object" ||
          typeof reader.readIndex !== "function"
        ) {
          throw new Error("INVALID_SNAPSHOT_TARGET_READER");
        }

        const targetId =
          requireInlineIdentifier(
            reader.targetId,
            "INVALID_TARGET_ID"
          );

        const relativePath =
          requireRelativeTargetPath(
            reader.relativePath
          );

        const snapshotIndexFile =
          requireIndexFileName(
            reader.snapshotIndexFile
          );

        const expectedTargetPath =
          nodePath.resolve(
            this.projectRoot,
            relativePath
          );

        if (
          !isInsidePath(
            this.projectRoot,
            expectedTargetPath
          )
        ) {
          throw new Error(
            "TARGET_PATH_OUTSIDE_PROJECT_ROOT"
          );
        }

        return {
          reader,
          targetId,
          relativePath,
          snapshotIndexFile,
          expectedTargetPath,
        };
      });

    const targetIds =
      descriptors.map(value => value.targetId);

    if (new Set(targetIds).size !== targetIds.length) {
      throw new Error("DUPLICATE_TARGET_ID");
    }

    const indexFileNames =
      descriptors.map(
        value => value.snapshotIndexFile
      );

    if (
      new Set(indexFileNames).size !==
      indexFileNames.length
    ) {
      throw new Error(
        "DUPLICATE_SNAPSHOT_INDEX_FILENAME"
      );
    }

    const authorityTargetIds =
      [...authority.protectedTargets].
        sort(codeUnitCompare);

    const descriptorTargetIds =
      [...targetIds].sort(codeUnitCompare);

    if (
      authorityTargetIds.length !==
      descriptorTargetIds.length ||
      authorityTargetIds.some(
        (targetId, index) =>
          targetId !== descriptorTargetIds[index]
      )
    ) {
      throw new Error(
        "AUTHORITY_PROTECTED_TARGET_SET_MISMATCH"
      );
    }

    const snapshotsRealPath =
      await fs.promises.realpath(
        this.snapshotsDir
      );

    const sortedDescriptors =
      [...descriptors].sort(
        (left, right) =>
          codeUnitCompare(
            left.targetId,
            right.targetId
          )
      );

    const entries:
      ImmutableSnapshotBindingEntry[] = [];

    for (const descriptor of sortedDescriptors) {
      const indexValue =
        await descriptor.reader.readIndex();

      if (indexValue === null) {
        continue;
      }

      const index =
        requireIndexRecord(indexValue);

      const originalPath =
        requireInlineIdentifier(
          index.original_path,
          "INVALID_INDEX_ORIGINAL_PATH"
        );

      if (!nodePath.isAbsolute(originalPath)) {
        throw new Error(
          "INDEX_ORIGINAL_PATH_NOT_ABSOLUTE"
        );
      }

      const expectedTargetKey =
        normalizePathForBinding(
          nodePath.resolve(
            descriptor.expectedTargetPath
          )
        );

      const actualTargetKey =
        normalizePathForBinding(
          nodePath.resolve(originalPath)
        );

      if (actualTargetKey !== expectedTargetKey) {
        throw new Error(
          "INDEX_ORIGINAL_PATH_BINDING_MISMATCH"
        );
      }

      const normalizedKey =
        requireInlineIdentifier(
          index.normalized_key,
          "INVALID_INDEX_NORMALIZED_KEY"
        );

      if (normalizedKey !== expectedTargetKey) {
        throw new Error(
          "INDEX_NORMALIZED_KEY_BINDING_MISMATCH"
        );
      }

      const baselineSnapshotFile =
        requireInlineIdentifier(
          index.baseline_snapshot_file,
          "INVALID_BASELINE_SNAPSHOT_FILE"
        );

      if (!nodePath.isAbsolute(baselineSnapshotFile)) {
        throw new Error(
          "BASELINE_SNAPSHOT_FILE_NOT_ABSOLUTE"
        );
      }

      const resolvedBaselinePath =
        nodePath.resolve(
          baselineSnapshotFile
        );

      if (
        !isInsidePath(
          this.snapshotsDir,
          resolvedBaselinePath
        )
      ) {
        throw new Error(
          "BASELINE_SNAPSHOT_PATH_OUTSIDE_SNAPSHOTS"
        );
      }

      const baselineRealPath =
        await fs.promises.realpath(
          resolvedBaselinePath
        );

      if (
        !isInsidePath(
          snapshotsRealPath,
          baselineRealPath
        )
      ) {
        throw new Error(
          "BASELINE_SNAPSHOT_REALPATH_OUTSIDE_SNAPSHOTS"
        );
      }

      const baselineContentSha256 =
        requireSha256Hex(
          index.baseline_content_sha256
        );

      const baselineBytes =
        await fs.promises.readFile(
          baselineRealPath
        );

      const actualBaselineSha256 =
        crypto
          .createHash("sha256")
          .update(baselineBytes)
          .digest("hex");

      if (
        actualBaselineSha256 !==
        baselineContentSha256
      ) {
        throw new Error(
          "BASELINE_SNAPSHOT_SHA256_MISMATCH"
        );
      }

      const relativeBaselinePath =
        nodePath
          .relative(
            snapshotsRealPath,
            baselineRealPath
          )
          .replace(/\\/g, "/");

      if (
        relativeBaselinePath.length === 0 ||
        relativeBaselinePath === ".." ||
        relativeBaselinePath.startsWith("../")
      ) {
        throw new Error(
          "INVALID_BASELINE_SNAPSHOT_RELATIVE_PATH"
        );
      }

      entries.push({
        targetId: descriptor.targetId,
        relativePath: descriptor.relativePath,
        snapshotIndexFile:
          descriptor.snapshotIndexFile,
        baselineSnapshotFile:
          relativeBaselinePath,
        baselineContentSha256,
      });
    }

    if (entries.length === 0) {
      throw new Error(
        "NO_REGISTERED_SNAPSHOT_INDEXES"
      );
    }

    const snapshotBindingSha256 =
      sha256Prefixed(
        encodeAggregate(entries)
      );

    return Object.freeze({
      authorityRevision:
        authority.revision,
      workspaceId:
        authority.workspaceId,
      snapshotBindingSha256,
    });
  }
}