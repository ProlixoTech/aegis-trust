import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as nodePath from "node:path";
import { pathToFileURL } from "node:url";
import type {
  CanonicalAuthorityState,
} from "./canonicalAuthorityState";
import type {
  PersistedArtifactAuthorityRecord,
} from "./postArtifactAuthorityVerifier";
import {
  verifyPostArtifactInternalAuthority,
} from "./postArtifactAuthorityVerifier";

export const RESPONSE_RENDERING_GATE_SCHEMA_VERSION =
  "1.0.0";

const WORK_RECEIPT_ARTIFACT_KIND =
  "work_receipt";

const WORK_RECEIPT_TARGET_PATH =
  ".aegis/receipts";

const WORK_RECEIPT_AUTHORITY_SURFACE =
  "receipt";

const WORK_RECEIPT_AUTHORITY_RULE_ID =
  "work-receipt-receipt-surface-v1";

export interface VerifiedArtifactResponseRecord
  extends PersistedArtifactAuthorityRecord {
  readonly postArtifactAuthorityVerificationId: string;
  readonly postArtifactAuthorityStateSha256: string;
  readonly postArtifactAuthorityRevision: number;
}

export interface ResponseRenderingGateInput {
  readonly workspaceRoot: string;
  readonly receiptPath: string;
  readonly manifestPath: string;
  readonly artifact: VerifiedArtifactResponseRecord;
  readonly preArtifactAuthorityState:
    CanonicalAuthorityState;
  readonly postArtifactAuthorityState:
    CanonicalAuthorityState;
}

export interface TrustedLocalArtifactLink {
  readonly kind: "local_file";
  readonly scheme: "file";
  readonly trustedFileName: string;
  readonly absolutePath: string;
  readonly uri: string;
}

export interface VerifiedArtifactResponsePlan {
  readonly accepted: true;
  readonly renderAllowed: true;
  readonly downloadLinkAllowed: true;
  readonly responseGateId: string;
  readonly artifactId: string;
  readonly postArtifactAuthorityVerificationId: string;
  readonly trustedArtifactName: string;
  readonly displayTitle: string;
  readonly displaySummary: string;
  readonly receiptLink: TrustedLocalArtifactLink;
  readonly manifestLink: TrustedLocalArtifactLink;
  readonly productPassClaimed: false;
  readonly finalClaimed: false;
  readonly releaseReadyClaimed: false;
  readonly uploadReadyClaimed: false;
}

function canonicalize(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(
        "NON_FINITE_RESPONSE_RENDERING_NUMBER"
      );
    }

    return value;
  }

  if (Array.isArray(value)) {
    return value.map(item => canonicalize(item));
  }

  if (typeof value === "object") {
    const source =
      value as Record<string, unknown>;

    const output:
      Record<string, unknown> = {};

    for (const key of Object.keys(source).sort()) {
      if (source[key] === undefined) {
        throw new Error(
          "UNDEFINED_RESPONSE_RENDERING_VALUE"
        );
      }

      output[key] =
        canonicalize(source[key]);
    }

    return output;
  }

  throw new Error(
    "UNSUPPORTED_RESPONSE_RENDERING_VALUE"
  );
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function sha256(
  value: string | Buffer
): string {
  return `sha256:${createHash("sha256")
    .update(value)
    .digest("hex")}`;
}

function requireSha256(
  value: string,
  errorCode: string
): string {
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) {
    throw new Error(errorCode);
  }

  return value;
}

function requireAbsoluteLocalPath(
  value: string,
  errorCode: string
): string {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    /[\r\n\u0000-\u001f\u007f]/.test(value) ||
    /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value)
  ) {
    throw new Error(errorCode);
  }

  const resolved = nodePath.resolve(value);

  if (!nodePath.isAbsolute(resolved)) {
    throw new Error(errorCode);
  }

  return resolved;
}

function pathIsInside(
  parentPath: string,
  childPath: string
): boolean {
  const relative = nodePath.relative(
    parentPath,
    childPath
  );

  return (
    relative !== "" &&
    relative !== ".." &&
    !relative.startsWith(
      ".." + nodePath.sep
    ) &&
    !nodePath.isAbsolute(relative)
  );
}

function requireTrustedReceiptName(
  value: string
): string {
  if (
    !/^work-receipt-[0-9]{8}-[0-9]{6}\.md$/.test(
      value
    )
  ) {
    throw new Error(
      "INVALID_TRUSTED_RECEIPT_FILE_NAME"
    );
  }

  return value;
}

async function resolveTrustedLocalFile(
  inputPath: string,
  receiptsRootRealPath: string,
  invalidPathCode: string,
  missingFileCode: string
): Promise<string> {
  const resolvedPath =
    requireAbsoluteLocalPath(
      inputPath,
      invalidPathCode
    );

  let fileStats;

  try {
    fileStats = await fs.lstat(resolvedPath);
  } catch {
    throw new Error(missingFileCode);
  }

  if (
    !fileStats.isFile() ||
    fileStats.isSymbolicLink()
  ) {
    throw new Error(missingFileCode);
  }

  const realPath =
    await fs.realpath(resolvedPath);

  if (
    !pathIsInside(
      receiptsRootRealPath,
      realPath
    ) ||
    nodePath.dirname(realPath) !==
      receiptsRootRealPath
  ) {
    throw new Error(
      "RESPONSE_ARTIFACT_PATH_OUTSIDE_TRUSTED_ROOT"
    );
  }

  return realPath;
}

function createTrustedLocalLink(
  absolutePath: string
): TrustedLocalArtifactLink {
  return {
    kind: "local_file",
    scheme: "file",
    trustedFileName:
      nodePath.basename(absolutePath),
    absolutePath,
    uri:
      pathToFileURL(absolutePath).toString(),
  };
}

export async function buildVerifiedArtifactResponsePlan(
  input: ResponseRenderingGateInput
): Promise<VerifiedArtifactResponsePlan> {
  const workspaceRoot =
    requireAbsoluteLocalPath(
      input.workspaceRoot,
      "INVALID_RESPONSE_WORKSPACE_ROOT"
    );

  const receiptsRoot = nodePath.join(
    workspaceRoot,
    ".aegis",
    "receipts"
  );

  let receiptsRootStats;

  try {
    receiptsRootStats =
      await fs.lstat(receiptsRoot);
  } catch {
    throw new Error(
      "TRUSTED_RECEIPTS_ROOT_NOT_FOUND"
    );
  }

  if (
    !receiptsRootStats.isDirectory() ||
    receiptsRootStats.isSymbolicLink()
  ) {
    throw new Error(
      "INVALID_TRUSTED_RECEIPTS_ROOT"
    );
  }

  const receiptsRootRealPath =
    await fs.realpath(receiptsRoot);

  const receiptRealPath =
    await resolveTrustedLocalFile(
      input.receiptPath,
      receiptsRootRealPath,
      "INVALID_RESPONSE_RECEIPT_PATH",
      "TRUSTED_RECEIPT_FILE_NOT_FOUND"
    );

  const manifestRealPath =
    await resolveTrustedLocalFile(
      input.manifestPath,
      receiptsRootRealPath,
      "INVALID_RESPONSE_MANIFEST_PATH",
      "TRUSTED_MANIFEST_FILE_NOT_FOUND"
    );

  const receiptFileName =
    requireTrustedReceiptName(
      nodePath.basename(receiptRealPath)
    );

  const expectedManifestFileName =
    receiptFileName + ".artifact.json";

  if (
    nodePath.basename(manifestRealPath) !==
      expectedManifestFileName ||
    manifestRealPath !==
      receiptRealPath + ".artifact.json"
  ) {
    throw new Error(
      "RESPONSE_MANIFEST_FILE_NAME_MISMATCH"
    );
  }

  const manifestBytes =
    await fs.readFile(manifestRealPath);

  let persistedManifest: unknown;

  try {
    persistedManifest = JSON.parse(
      manifestBytes.toString("utf8")
    );
  } catch {
    throw new Error(
      "INVALID_RESPONSE_MANIFEST_JSON"
    );
  }

  if (
    canonicalJson(persistedManifest) !==
    canonicalJson(input.artifact)
  ) {
    throw new Error(
      "RESPONSE_RENDERING_MANIFEST_RECORD_MISMATCH"
    );
  }

  const persistedVerificationId =
    requireSha256(
      input.artifact
        .postArtifactAuthorityVerificationId,
      "INVALID_RESPONSE_AUTHORITY_VERIFICATION_ID"
    );

  const verification =
    verifyPostArtifactInternalAuthority({
      artifact: input.artifact,
      preArtifactAuthorityState:
        input.preArtifactAuthorityState,
      postArtifactAuthorityState:
        input.postArtifactAuthorityState,
      allowedArtifactKinds: [
        WORK_RECEIPT_ARTIFACT_KIND,
      ],
      allowedTargetPrefixes: [
        WORK_RECEIPT_TARGET_PATH,
      ],
      expectedAuthoritySurface:
        WORK_RECEIPT_AUTHORITY_SURFACE,
      expectedAuthoritySurfaceRuleId:
        WORK_RECEIPT_AUTHORITY_RULE_ID,
    });

  if (
    persistedVerificationId !==
    verification.verificationId
  ) {
    throw new Error(
      "RESPONSE_AUTHORITY_VERIFICATION_ID_MISMATCH"
    );
  }

  if (
    input.artifact
      .postArtifactAuthorityStateSha256 !==
    verification.postArtifactAuthorityStateSha256
  ) {
    throw new Error(
      "RESPONSE_POST_AUTHORITY_SHA256_MISMATCH"
    );
  }

  if (
    input.artifact
      .postArtifactAuthorityRevision !==
    verification.postArtifactAuthorityRevision
  ) {
    throw new Error(
      "RESPONSE_POST_AUTHORITY_REVISION_MISMATCH"
    );
  }

  if (
    input.postArtifactAuthorityState
      .currentArtifactId !==
    input.artifact.artifactId
  ) {
    throw new Error(
      "RESPONSE_CURRENT_ARTIFACT_ID_MISMATCH"
    );
  }

  if (
    input.artifact.manifest.artifactKind !==
      WORK_RECEIPT_ARTIFACT_KIND ||
    input.artifact.intent.artifactKind !==
      WORK_RECEIPT_ARTIFACT_KIND ||
    input.artifact.intent.provenance !==
      "local_user_command" ||
    input.artifact.intent.targetPath !==
      WORK_RECEIPT_TARGET_PATH ||
    input.artifact.authoritySurface !==
      WORK_RECEIPT_AUTHORITY_SURFACE ||
    input.artifact.authoritySurfaceRuleId !==
      WORK_RECEIPT_AUTHORITY_RULE_ID
  ) {
    throw new Error(
      "RESPONSE_ARTIFACT_CONTRACT_MISMATCH"
    );
  }

  const expectedEntryPath =
    "receipts/" + receiptFileName;

  if (
    input.artifact.manifest.entries.length !== 1 ||
    input.artifact.intent.entryPaths.length !== 1 ||
    input.artifact.manifest.entries[0]?.path !==
      expectedEntryPath ||
    input.artifact.intent.entryPaths[0] !==
      expectedEntryPath
  ) {
    throw new Error(
      "RESPONSE_ARTIFACT_ENTRY_SCOPE_MISMATCH"
    );
  }

  const receiptBytes =
    await fs.readFile(receiptRealPath);

  const receiptEntry =
    input.artifact.manifest.entries[0];

  if (
    !receiptEntry ||
    receiptEntry.contentSha256 !==
      sha256(receiptBytes) ||
    receiptEntry.byteLength !==
      receiptBytes.byteLength
  ) {
    throw new Error(
      "RESPONSE_RECEIPT_CONTENT_INTEGRITY_MISMATCH"
    );
  }

  if (
    input.preArtifactAuthorityState.productPass !==
      false ||
    input.preArtifactAuthorityState.releaseReady !==
      false ||
    input.preArtifactAuthorityState.uploadReady !==
      false ||
    input.preArtifactAuthorityState
      .finalArtifactCreated !== false ||
    input.postArtifactAuthorityState.productPass !==
      false ||
    input.postArtifactAuthorityState.releaseReady !==
      false ||
    input.postArtifactAuthorityState.uploadReady !==
      false ||
    input.postArtifactAuthorityState
      .finalArtifactCreated !== false
  ) {
    throw new Error(
      "UNAUTHORIZED_RESPONSE_FINAL_STATE_CLAIM"
    );
  }

  const trustedArtifactName =
    expectedManifestFileName;

  const responseGateId = sha256(
    canonicalJson({
      schemaVersion:
        RESPONSE_RENDERING_GATE_SCHEMA_VERSION,
      artifactId:
        input.artifact.artifactId,
      postArtifactAuthorityVerificationId:
        verification.verificationId,
      trustedArtifactName,
      receiptFileName,
      receiptContentSha256:
        receiptEntry.contentSha256,
      receiptByteLength:
        receiptEntry.byteLength,
    })
  );

  return {
    accepted: true,
    renderAllowed: true,
    downloadLinkAllowed: true,
    responseGateId,
    artifactId:
      input.artifact.artifactId,
    postArtifactAuthorityVerificationId:
      verification.verificationId,
    trustedArtifactName,
    displayTitle:
      "Aegis Verified Work Receipt",
    displaySummary:
      `Verified artifact: ${trustedArtifactName}`,
    receiptLink:
      createTrustedLocalLink(
        receiptRealPath
      ),
    manifestLink:
      createTrustedLocalLink(
        manifestRealPath
      ),
    productPassClaimed: false,
    finalClaimed: false,
    releaseReadyClaimed: false,
    uploadReadyClaimed: false,
  };
}