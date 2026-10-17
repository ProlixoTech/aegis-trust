import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
} from "node:path";

import {
  CanonicalAuthorityStateStore,
} from "./canonicalAuthorityState";

export interface CanonicalAuthorityStateFileOperations {
  mkdir(
    path: string,
    options: { readonly recursive: true }
  ): Promise<string | undefined>;

  open(
    path: string,
    flags: string,
    mode: number
  ): Promise<FileHandle>;

  rename(
    oldPath: string,
    newPath: string
  ): Promise<void>;

  readFile(
    path: string,
    encoding: "utf8"
  ): Promise<string>;

  unlink(
    path: string
  ): Promise<void>;
}

export function createNodeCanonicalAuthorityStateFileOperations():
  CanonicalAuthorityStateFileOperations {
  return Object.freeze({
    mkdir: (
      path: string,
      options: { readonly recursive: true }
    ) =>
      fs.mkdir(
        path,
        options
      ),

    open: (
      path: string,
      flags: string,
      mode: number
    ) =>
      fs.open(
        path,
        flags,
        mode
      ),

    rename: (
      oldPath: string,
      newPath: string
    ) =>
      fs.rename(
        oldPath,
        newPath
      ),

    readFile: (
      path: string,
      encoding: "utf8"
    ) =>
      fs.readFile(
        path,
        encoding
      ),

    unlink: (
      path: string
    ) =>
      fs.unlink(path),
  });
}

function isErrnoCode(
  error: unknown,
  code: string
): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === code
  );
}

function requireAbsoluteSnapshotPath(
  snapshotPath: string
): string {
  if (
    typeof snapshotPath !== "string" ||
    snapshotPath.length === 0 ||
    snapshotPath.includes("\0") ||
    !isAbsolute(snapshotPath) ||
    basename(snapshotPath).length === 0
  ) {
    throw new Error(
      "INVALID_CANONICAL_AUTHORITY_SNAPSHOT_PATH"
    );
  }

  return snapshotPath;
}

export class CanonicalAuthorityStateFilePersistence {
  private readonly snapshotPath: string;

  private readonly operations:
    CanonicalAuthorityStateFileOperations;

  constructor(
    snapshotPath: string,
    operations =
      createNodeCanonicalAuthorityStateFileOperations()
  ) {
    this.snapshotPath =
      requireAbsoluteSnapshotPath(
        snapshotPath
      );

    this.operations = operations;
  }

  async load():
    Promise<CanonicalAuthorityStateStore | null> {
    let serializedEnvelope: string;

    try {
      serializedEnvelope =
        await this.operations.readFile(
          this.snapshotPath,
          "utf8"
        );
    } catch (error) {
      if (
        isErrnoCode(
          error,
          "ENOENT"
        )
      ) {
        return null;
      }

      throw error;
    }

    return CanonicalAuthorityStateStore
      .hydrateSnapshotJson(
        serializedEnvelope
      );
  }

  async save(
    store: CanonicalAuthorityStateStore
  ): Promise<void> {
    if (
      !(store instanceof CanonicalAuthorityStateStore)
    ) {
      throw new Error(
        "INVALID_CANONICAL_AUTHORITY_STATE_STORE"
      );
    }

    const serializedEnvelope =
      store.serializeSnapshotEnvelope();

    const targetDirectory =
      dirname(this.snapshotPath);

    const temporaryPath =
      join(
        targetDirectory,
        "." +
          basename(this.snapshotPath) +
          ".tmp-" +
          process.pid.toString(10) +
          "-" +
          randomBytes(16).toString("hex")
      );

    let handle:
      FileHandle | undefined;

    try {
      await this.operations.mkdir(
        targetDirectory,
        {
          recursive: true,
        }
      );

      handle =
        await this.operations.open(
          temporaryPath,
          "wx",
          0o600
        );

      await handle.writeFile(
        serializedEnvelope,
        {
          encoding: "utf8",
        }
      );

      await handle.sync();
      await handle.close();
      handle = undefined;

      await this.operations.rename(
        temporaryPath,
        this.snapshotPath
      );
    } catch (error) {
      if (handle !== undefined) {
        try {
          await handle.close();
        } catch {
          // Cleanup continues below.
        }
      }

      let cleanupFailure:
        unknown | undefined;

      try {
        await this.operations.unlink(
          temporaryPath
        );
      } catch (cleanupError) {
        if (
          !isErrnoCode(
            cleanupError,
            "ENOENT"
          )
        ) {
          cleanupFailure =
            cleanupError;
        }
      }

      if (cleanupFailure !== undefined) {
        const failure =
          new Error(
            "CANONICAL_AUTHORITY_SNAPSHOT_SAVE_CLEANUP_FAILED"
          );

        (
          failure as Error & {
            cause?: unknown;
          }
        ).cause = {
          saveError: error,
          cleanupError:
            cleanupFailure,
        };

        throw failure;
      }

      throw error;
    }
  }
}