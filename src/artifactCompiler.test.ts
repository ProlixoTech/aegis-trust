import { test } from "node:test";
import * as assert from "node:assert/strict";
import type { CanonicalAuthorityState } from "./canonicalAuthorityState";
import {
  compileArtifact,
  type ArtifactCompilerEntryInput,
} from "./artifactCompiler";

function createAuthorityState(): CanonicalAuthorityState {
  return {
    schemaVersion: "1.0.0",
    revision: 4,
    projectIdentity: "prolixo-aegis-personal",
    workspaceId:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    safeBaselineId: null,
    protectedTargets: ["protected-env"],
    capabilityManifestId: "local_client_default_v1",
    capabilityManifestVersion: "0.1.0-mvp0",
    policyVersion: "safety-kernel-v3.1-local-client-mvp0",
    rulesetVersion: "bundled-local-ruleset-v1",
    actionId: null,
    sessionId: null,
    approvalNonceSha256: null,
    approvalNonceState: "NONE",
    currentArtifactId: null,
    recoveryPackageId: null,
    receiptId: null,
    ledgerHeadHash: null,
    verificationResult: "UNVERIFIED",
    userVisibleState: "SAFE",
    decisionScope: {
      decisionSchemaVersion: "1.0.0",
      rulesetVersion: "bundled-local-ruleset-v1",
      policyVersion: "safety-kernel-v3.1-local-client-mvp0",
      checkerVersions: {},
      capabilityManifestVersion: "0.1.0-mvp0",
      coveredScope: ["L2_CANONICAL_AUTHORITY_STATE"],
      timestamp: "2026-07-26T00:00:00.000Z",
    },
    productPass: false,
    releaseReady: false,
    uploadReady: false,
    finalArtifactCreated: false,
  };
}

const entries: ArtifactCompilerEntryInput[] = [
  {
    path: "manifest/data.json",
    contentSha256:
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    byteLength: 25,
  },
  {
    path: "payload/content.txt",
    contentSha256:
      "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    byteLength: 12,
  },
];

test("same input produces the same artifact identity", () => {
  const input = {
    artifactKind: "handoff_capsule",
    authorityState: createAuthorityState(),
    entries,
  };

  assert.deepEqual(
    compileArtifact(input),
    compileArtifact(input)
  );
});

test("entry order does not change the artifact identity", () => {
  const forward = compileArtifact({
    artifactKind: "handoff_capsule",
    authorityState: createAuthorityState(),
    entries,
  });

  const reversed = compileArtifact({
    artifactKind: "handoff_capsule",
    authorityState: createAuthorityState(),
    entries: [...entries].reverse(),
  });

  assert.equal(forward.artifactId, reversed.artifactId);
  assert.equal(
    forward.canonicalManifestJson,
    reversed.canonicalManifestJson
  );
});

test("invalid and duplicate inputs fail closed", () => {
  assert.throws(
    () =>
      compileArtifact({
        artifactKind: "",
        authorityState: createAuthorityState(),
        entries,
      }),
    /INVALID_ARTIFACT_KIND/
  );

  assert.throws(
    () =>
      compileArtifact({
        artifactKind: "handoff_capsule",
        authorityState: createAuthorityState(),
        entries: [
          {
            path: "payload/content.txt",
            contentSha256: "not-a-sha256",
            byteLength: 1,
          },
        ],
      }),
    /INVALID_ARTIFACT_ENTRY_SHA256/
  );

  assert.throws(
    () =>
      compileArtifact({
        artifactKind: "handoff_capsule",
        authorityState: createAuthorityState(),
        entries: [entries[0], entries[0]],
      }),
    /DUPLICATE_ARTIFACT_ENTRY_PATH/
  );
});