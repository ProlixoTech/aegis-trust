import { test } from "node:test";
import * as assert from "node:assert/strict";
import {
  CanonicalAuthorityStateStore,
  type CanonicalAuthorityState,
} from "./canonicalAuthorityState";
import { getProtectedTargets } from "./protectedTargets";
import { compileArtifact } from "./artifactCompiler";
import {
  preflightArtifactIntent,
  type ArtifactIntentEnvelope,
} from "./artifactIntentPreflight";
import {
  classifyArtifactAuthoritySurface,
} from "./authoritySurfaceClassifier";
import {
  verifyPostArtifactInternalAuthority,
  type PersistedArtifactAuthorityRecord,
} from "./postArtifactAuthorityVerifier";

interface Fixture {
  readonly artifact: PersistedArtifactAuthorityRecord;
  readonly preState: CanonicalAuthorityState;
  readonly postState: CanonicalAuthorityState;
}

function createFixture(): Fixture {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
    timestamp: "2026-07-26T00:00:00.000Z",
  });

  const preState = store.getState();

  const intent: ArtifactIntentEnvelope = {
    schemaVersion: "1.0.0",
    intentId: "generate-work-receipt-artifact",
    artifactKind: "work_receipt",
    provenance: "local_user_command",
    targetPath: ".aegis/receipts",
    entryPaths: ["receipts/work-receipt.md"],
    authorityBinding: {
      revision: preState.revision,
      workspaceId: preState.workspaceId,
      policyVersion: preState.policyVersion,
      rulesetVersion: preState.rulesetVersion,
      capabilityManifestVersion:
        preState.capabilityManifestVersion,
      actionId: preState.actionId,
      sessionId: preState.sessionId,
      approvalNonceSha256:
        preState.approvalNonceSha256,
    },
  };

  const preflight = preflightArtifactIntent({
    intent,
    authorityState: preState,
    allowedArtifactKinds: ["work_receipt"],
    allowedTargetPrefixes: [".aegis/receipts"],
  });

  const classification =
    classifyArtifactAuthoritySurface({
      intent: preflight.normalizedIntent,
    });

  const compiled = compileArtifact({
    artifactKind: "work_receipt",
    authorityState: preState,
    entries: [{
      path: "receipts/work-receipt.md",
      contentSha256:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      byteLength: 128,
    }],
  });

  const postState = store.update(
    preState.revision,
    {
      currentArtifactId: compiled.artifactId,
    },
    "2026-07-26T00:00:01.000Z"
  );

  const artifact: PersistedArtifactAuthorityRecord = {
    preflightId: preflight.preflightId,
    preflightAuthorityStateSha256:
      preflight.authorityStateSha256,
    intent: preflight.normalizedIntent,
    authoritySurfaceClassificationId:
      classification.classificationId,
    authoritySurface:
      classification.authoritySurface,
    authoritySurfaceRuleId:
      classification.matchedRuleId,
    artifactId: compiled.artifactId,
    manifest: compiled.manifest,
  };

  return {
    artifact,
    preState,
    postState,
  };
}

function verifyFixture(fixture: Fixture) {
  return verifyPostArtifactInternalAuthority({
    artifact: fixture.artifact,
    preArtifactAuthorityState: fixture.preState,
    postArtifactAuthorityState: fixture.postState,
    allowedArtifactKinds: ["work_receipt"],
    allowedTargetPrefixes: [".aegis/receipts"],
    expectedAuthoritySurface: "receipt",
    expectedAuthoritySurfaceRuleId:
      "work-receipt-receipt-surface-v1",
  });
}

test("valid post-artifact authority transition verifies", () => {
  const fixture = createFixture();

  const first = verifyFixture(fixture);
  const second = verifyFixture(fixture);

  assert.equal(first.accepted, true);
  assert.equal(
    first.artifactId,
    fixture.artifact.artifactId
  );
  assert.equal(
    first.postArtifactAuthorityRevision,
    fixture.preState.revision + 1
  );
  assert.match(
    first.verificationId,
    /^sha256:[a-f0-9]{64}$/
  );
  assert.equal(
    first.verificationId,
    second.verificationId
  );
});

test("artifact identity tampering fails closed", () => {
  const fixture = createFixture();

  assert.throws(
    () =>
      verifyFixture({
        ...fixture,
        artifact: {
          ...fixture.artifact,
          artifactId:
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        },
      }),
    /POST_ARTIFACT_ID_MISMATCH/
  );
});

test("stale revision and authority drift fail closed", () => {
  const fixture = createFixture();

  assert.throws(
    () =>
      verifyFixture({
        ...fixture,
        postState: {
          ...fixture.postState,
          revision: fixture.preState.revision,
        },
      }),
    /POST_ARTIFACT_AUTHORITY_REVISION_MISMATCH/
  );

  assert.throws(
    () =>
      verifyFixture({
        ...fixture,
        postState: {
          ...fixture.postState,
          policyVersion:
            "unauthorized-policy-drift",
        },
      }),
    /POST_ARTIFACT_AUTHORITY_STATE_DRIFT/
  );
});

test("preflight and classification tampering fail closed", () => {
  const fixture = createFixture();

  assert.throws(
    () =>
      verifyFixture({
        ...fixture,
        artifact: {
          ...fixture.artifact,
          preflightId:
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        },
      }),
    /POST_ARTIFACT_PREFLIGHT_ID_MISMATCH/
  );

  assert.throws(
    () =>
      verifyFixture({
        ...fixture,
        artifact: {
          ...fixture.artifact,
          authoritySurfaceClassificationId:
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        },
      }),
    /POST_ARTIFACT_CLASSIFICATION_ID_MISMATCH/
  );
});

// NT12-A1-POST-ARTIFACT-AMBIGUOUS-AUTHORITY-FAIL-CLOSED BEGIN
test("NT-12 post-artifact verification fails closed on ambiguous authority references", () => {
  const store = CanonicalAuthorityStateStore.create({
    workspaceId:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    protectedTargets: getProtectedTargets(),
    initialUserVisibleState: "SAFE",
    timestamp: "2026-07-26T00:00:00.000Z",
  });

  const preState = store.getState();

  const intent: ArtifactIntentEnvelope = {
    schemaVersion: "1.0.0",
    intentId: "generate-work-receipt-archive-artifact",
    artifactKind: "work_receipt",
    provenance: "local_user_command",
    targetPath: ".aegis/receipts/archive",
    entryPaths: ["receipts/archive/work-receipt.md"],
    authorityBinding: {
      revision: preState.revision,
      workspaceId: preState.workspaceId,
      policyVersion: preState.policyVersion,
      rulesetVersion: preState.rulesetVersion,
      capabilityManifestVersion:
        preState.capabilityManifestVersion,
      actionId: preState.actionId,
      sessionId: preState.sessionId,
      approvalNonceSha256:
        preState.approvalNonceSha256,
    },
  };

  const preflight = preflightArtifactIntent({
    intent,
    authorityState: preState,
    allowedArtifactKinds: ["work_receipt"],
    allowedTargetPrefixes: [".aegis/receipts"],
  });

  const baselineClassification =
    classifyArtifactAuthoritySurface({
      intent: preflight.normalizedIntent,
    });

  const compiled = compileArtifact({
    artifactKind: "work_receipt",
    authorityState: preState,
    entries: [{
      path: "receipts/archive/work-receipt.md",
      contentSha256:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      byteLength: 128,
    }],
  });

  const postState = store.update(
    preState.revision,
    {
      currentArtifactId: compiled.artifactId,
    },
    "2026-07-26T00:00:01.000Z"
  );

  const artifact: PersistedArtifactAuthorityRecord = {
    preflightId: preflight.preflightId,
    preflightAuthorityStateSha256:
      preflight.authorityStateSha256,
    intent: preflight.normalizedIntent,
    authoritySurfaceClassificationId:
      baselineClassification.classificationId,
    authoritySurface:
      baselineClassification.authoritySurface,
    authoritySurfaceRuleId:
      baselineClassification.matchedRuleId,
    artifactId: compiled.artifactId,
    manifest: compiled.manifest,
  };

  const overlappingRules = [
    {
      ruleId: "work-receipt-receipt-surface-v1",
      artifactKind: "work_receipt",
      provenance: "local_user_command",
      targetPrefix: ".aegis/receipts",
      authoritySurface: "receipt",
    },
    {
      ruleId: "work-receipt-archive-surface-v1",
      artifactKind: "work_receipt",
      provenance: "local_user_command",
      targetPrefix: ".aegis/receipts/archive",
      authoritySurface: "receipt",
    },
  ] as const;

  assert.throws(
    () =>
      verifyPostArtifactInternalAuthority({
        artifact,
        preArtifactAuthorityState: preState,
        postArtifactAuthorityState: postState,
        allowedArtifactKinds: ["work_receipt"],
        allowedTargetPrefixes: [".aegis/receipts"],
        authoritySurfaceRules: overlappingRules,
        expectedAuthoritySurface: "receipt",
        expectedAuthoritySurfaceRuleId:
          "work-receipt-receipt-surface-v1",
      }),
    /AMBIGUOUS_AUTHORITY_SURFACE_RULE/
  );
});
// NT12-A1-POST-ARTIFACT-AMBIGUOUS-AUTHORITY-FAIL-CLOSED END
