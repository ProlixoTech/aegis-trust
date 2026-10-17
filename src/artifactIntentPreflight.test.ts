import { test } from "node:test";
import * as assert from "node:assert/strict";
import type {
  CanonicalAuthorityState,
} from "./canonicalAuthorityState";
import {
  preflightArtifactIntent,
  type ArtifactIntentEnvelope,
} from "./artifactIntentPreflight";

function createAuthorityState(): CanonicalAuthorityState {
  return {
    schemaVersion: "1.0.0",
    revision: 7,
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
      policyVersion:
        "safety-kernel-v3.1-local-client-mvp0",
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

function createIntent(
  entryPaths: readonly string[] = [
    "receipts/work-receipt.md",
    "receipts/work-receipt.md.artifact.json",
  ]
): ArtifactIntentEnvelope {
  return {
    schemaVersion: "1.0.0",
    intentId: "generate-work-receipt-artifact",
    artifactKind: "work_receipt",
    provenance: "local_user_command",
    targetPath: ".aegis/receipts",
    entryPaths,
    authorityBinding: {
      revision: 7,
      workspaceId:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      policyVersion:
        "safety-kernel-v3.1-local-client-mvp0",
      rulesetVersion: "bundled-local-ruleset-v1",
      capabilityManifestVersion: "0.1.0-mvp0",
      actionId: null,
      sessionId: null,
      approvalNonceSha256: null,
    },
  };
}

const allowedArtifactKinds = ["work_receipt"];
const allowedTargetPrefixes = [".aegis/receipts"];

test("valid artifact intent passes preflight", () => {
  const result = preflightArtifactIntent({
    intent: createIntent(),
    authorityState: createAuthorityState(),
    allowedArtifactKinds,
    allowedTargetPrefixes,
  });

  assert.equal(result.accepted, true);
  assert.match(result.preflightId, /^sha256:[a-f0-9]{64}$/);
  assert.match(
    result.authorityStateSha256,
    /^sha256:[a-f0-9]{64}$/
  );
});

test("entry order does not change preflight identity", () => {
  const forward = preflightArtifactIntent({
    intent: createIntent(),
    authorityState: createAuthorityState(),
    allowedArtifactKinds,
    allowedTargetPrefixes,
  });

  const reversed = preflightArtifactIntent({
    intent: createIntent([
      "receipts/work-receipt.md.artifact.json",
      "receipts/work-receipt.md",
    ]),
    authorityState: createAuthorityState(),
    allowedArtifactKinds,
    allowedTargetPrefixes,
  });

  assert.equal(forward.preflightId, reversed.preflightId);
  assert.deepEqual(
    forward.normalizedIntent.entryPaths,
    reversed.normalizedIntent.entryPaths
  );
});

test("authority drift fails closed", () => {
  const intent = createIntent();

  assert.throws(
    () =>
      preflightArtifactIntent({
        intent: {
          ...intent,
          authorityBinding: {
            ...intent.authorityBinding,
            revision: 8,
          },
        },
        authorityState: createAuthorityState(),
        allowedArtifactKinds,
        allowedTargetPrefixes,
      }),
    /ARTIFACT_AUTHORITY_BINDING_MISMATCH/
  );
});

test("unauthorized kind, target, and duplicate entries fail closed", () => {
  assert.throws(
    () =>
      preflightArtifactIntent({
        intent: {
          ...createIntent(),
          artifactKind: "final_release_zip",
        },
        authorityState: createAuthorityState(),
        allowedArtifactKinds,
        allowedTargetPrefixes,
      }),
    /ARTIFACT_KIND_NOT_ALLOWED/
  );

  assert.throws(
    () =>
      preflightArtifactIntent({
        intent: {
          ...createIntent(),
          targetPath: "../outside",
        },
        authorityState: createAuthorityState(),
        allowedArtifactKinds,
        allowedTargetPrefixes,
      }),
    /INVALID_ARTIFACT_TARGET_PATH/
  );

  assert.throws(
    () =>
      preflightArtifactIntent({
        intent: createIntent([
          "receipts/work-receipt.md",
          "receipts/work-receipt.md",
        ]),
        authorityState: createAuthorityState(),
        allowedArtifactKinds,
        allowedTargetPrefixes,
      }),
    /DUPLICATE_ARTIFACT_INTENT_ENTRY_PATH/
  );
});