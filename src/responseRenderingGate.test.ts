import { createHash } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import * as nodePath from "node:path";
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
} from "./postArtifactAuthorityVerifier";
import {
  buildVerifiedArtifactResponsePlan,
  type VerifiedArtifactResponseRecord,
} from "./responseRenderingGate";

interface Fixture {
  readonly workspaceRoot: string;
  readonly receiptsDir: string;
  readonly receiptPath: string;
  readonly manifestPath: string;
  readonly artifact:
    VerifiedArtifactResponseRecord;
  readonly preState:
    CanonicalAuthorityState;
  readonly postState:
    CanonicalAuthorityState;
  readonly cleanup: () => void;
}

function sha256(value: Buffer): string {
  return `sha256:${createHash("sha256")
    .update(value)
    .digest("hex")}`;
}

function writeArtifact(
  fixture: Fixture,
  artifact:
    VerifiedArtifactResponseRecord
): void {
  writeFileSync(
    fixture.manifestPath,
    JSON.stringify(
      artifact,
      null,
      2
    ) + "\n",
    "utf8"
  );
}

function createFixture(): Fixture {
  const workspaceRoot = mkdtempSync(
    nodePath.join(
      tmpdir(),
      "aegis-c05-test-"
    )
  );

  const receiptsDir = nodePath.join(
    workspaceRoot,
    ".aegis",
    "receipts"
  );

  mkdirSync(
    receiptsDir,
    { recursive: true }
  );

  const receiptFileName =
    "work-receipt-20260726-000000.md";

  const receiptPath = nodePath.join(
    receiptsDir,
    receiptFileName
  );

  const manifestPath =
    receiptPath + ".artifact.json";

  const receiptBytes = Buffer.from(
    "# Aegis Work Receipt\n\nVerified test receipt.\n",
    "utf8"
  );

  writeFileSync(
    receiptPath,
    receiptBytes
  );

  const store =
    CanonicalAuthorityStateStore.create({
      workspaceId:
        "sha256:" +
        "a".repeat(64),
      protectedTargets:
        getProtectedTargets(),
      initialUserVisibleState:
        "SAFE",
      timestamp:
        "2026-07-26T00:00:00.000Z",
    });

  const preState =
    store.getState();

  const entryPath =
    "receipts/" + receiptFileName;

  const intent:
    ArtifactIntentEnvelope = {
    schemaVersion: "1.0.0",
    intentId:
      "generate-work-receipt-artifact",
    artifactKind:
      "work_receipt",
    provenance:
      "local_user_command",
    targetPath:
      ".aegis/receipts",
    entryPaths: [
      entryPath,
    ],
    authorityBinding: {
      revision:
        preState.revision,
      workspaceId:
        preState.workspaceId,
      policyVersion:
        preState.policyVersion,
      rulesetVersion:
        preState.rulesetVersion,
      capabilityManifestVersion:
        preState
          .capabilityManifestVersion,
      actionId:
        preState.actionId,
      sessionId:
        preState.sessionId,
      approvalNonceSha256:
        preState
          .approvalNonceSha256,
    },
  };

  const preflight =
    preflightArtifactIntent({
      intent,
      authorityState:
        preState,
      allowedArtifactKinds: [
        "work_receipt",
      ],
      allowedTargetPrefixes: [
        ".aegis/receipts",
      ],
    });

  const classification =
    classifyArtifactAuthoritySurface({
      intent:
        preflight.normalizedIntent,
    });

  const compiled =
    compileArtifact({
      artifactKind:
        "work_receipt",
      authorityState:
        preState,
      entries: [{
        path:
          entryPath,
        contentSha256:
          sha256(receiptBytes),
        byteLength:
          receiptBytes.byteLength,
      }],
    });

  const postState =
    store.update(
      preState.revision,
      {
        currentArtifactId:
          compiled.artifactId,
      },
      "2026-07-26T00:00:01.000Z"
    );

  const persistedRecord = {
    preflightId:
      preflight.preflightId,
    preflightAuthorityStateSha256:
      preflight.authorityStateSha256,
    intent:
      preflight.normalizedIntent,
    authoritySurfaceClassificationId:
      classification.classificationId,
    authoritySurface:
      classification.authoritySurface,
    authoritySurfaceRuleId:
      classification.matchedRuleId,
    artifactId:
      compiled.artifactId,
    manifest:
      compiled.manifest,
  };

  const verification =
    verifyPostArtifactInternalAuthority({
      artifact:
        persistedRecord,
      preArtifactAuthorityState:
        preState,
      postArtifactAuthorityState:
        postState,
      allowedArtifactKinds: [
        "work_receipt",
      ],
      allowedTargetPrefixes: [
        ".aegis/receipts",
      ],
      expectedAuthoritySurface:
        "receipt",
      expectedAuthoritySurfaceRuleId:
        "work-receipt-receipt-surface-v1",
    });

  const artifact:
    VerifiedArtifactResponseRecord = {
    ...persistedRecord,
    postArtifactAuthorityVerificationId:
      verification.verificationId,
    postArtifactAuthorityStateSha256:
      verification
        .postArtifactAuthorityStateSha256,
    postArtifactAuthorityRevision:
      verification
        .postArtifactAuthorityRevision,
  };

  const fixture: Fixture = {
    workspaceRoot,
    receiptsDir,
    receiptPath,
    manifestPath,
    artifact,
    preState,
    postState,
    cleanup: () => {
      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    },
  };

  writeArtifact(
    fixture,
    artifact
  );

  return fixture;
}

async function buildPlan(
  fixture: Fixture,
  overrides: Partial<{
    workspaceRoot: string;
    receiptPath: string;
    manifestPath: string;
    artifact:
      VerifiedArtifactResponseRecord;
    preState:
      CanonicalAuthorityState;
    postState:
      CanonicalAuthorityState;
  }> = {}
) {
  return buildVerifiedArtifactResponsePlan({
    workspaceRoot:
      overrides.workspaceRoot ??
      fixture.workspaceRoot,
    receiptPath:
      overrides.receiptPath ??
      fixture.receiptPath,
    manifestPath:
      overrides.manifestPath ??
      fixture.manifestPath,
    artifact:
      overrides.artifact ??
      fixture.artifact,
    preArtifactAuthorityState:
      overrides.preState ??
      fixture.preState,
    postArtifactAuthorityState:
      overrides.postState ??
      fixture.postState,
  });
}

test(
  "verified local artifact receives rendering and file-link authority",
  async () => {
    const fixture = createFixture();

    try {
      const first =
        await buildPlan(fixture);

      const second =
        await buildPlan(fixture);

      assert.equal(
        first.accepted,
        true
      );

      assert.equal(
        first.renderAllowed,
        true
      );

      assert.equal(
        first.downloadLinkAllowed,
        true
      );

      assert.equal(
        first.trustedArtifactName,
        "work-receipt-20260726-000000.md.artifact.json"
      );

      assert.equal(
        first.displaySummary,
        "Verified artifact: work-receipt-20260726-000000.md.artifact.json"
      );

      assert.equal(
        first.receiptLink.scheme,
        "file"
      );

      assert.equal(
        first.manifestLink.scheme,
        "file"
      );

      assert.match(
        first.responseGateId,
        /^sha256:[a-f0-9]{64}$/
      );

      assert.equal(
        first.responseGateId,
        second.responseGateId
      );

      assert.equal(
        first.productPassClaimed,
        false
      );

      assert.equal(
        first.releaseReadyClaimed,
        false
      );

      assert.equal(
        first.uploadReadyClaimed,
        false
      );
    } finally {
      fixture.cleanup();
    }
  }
);

test(
  "verification metadata tampering fails closed",
  async () => {
    const fixture = createFixture();

    try {
      const tampered = {
        ...fixture.artifact,
        postArtifactAuthorityVerificationId:
          "sha256:" +
          "b".repeat(64),
      };

      writeArtifact(
        fixture,
        tampered
      );

      await assert.rejects(
        () =>
          buildPlan(
            fixture,
            {
              artifact:
                tampered,
            }
          ),
        /RESPONSE_AUTHORITY_VERIFICATION_ID_MISMATCH/
      );
    } finally {
      fixture.cleanup();
    }
  }
);

test(
  "external, escaped, and misnamed paths fail closed",
  async () => {
    const fixture = createFixture();

    try {
      await assert.rejects(
        () =>
          buildPlan(
            fixture,
            {
              receiptPath:
                "https://example.invalid/work-receipt.md",
            }
          ),
        /INVALID_RESPONSE_RECEIPT_PATH/
      );

      const outsidePath =
        nodePath.join(
          fixture.workspaceRoot,
          "outside.md"
        );

      writeFileSync(
        outsidePath,
        "outside",
        "utf8"
      );

      await assert.rejects(
        () =>
          buildPlan(
            fixture,
            {
              receiptPath:
                outsidePath,
            }
          ),
        /RESPONSE_ARTIFACT_PATH_OUTSIDE_TRUSTED_ROOT/
      );

      const wrongManifestPath =
        nodePath.join(
          fixture.receiptsDir,
          "wrong-name.artifact.json"
        );

      writeFileSync(
        wrongManifestPath,
        readFileSync(
          fixture.manifestPath
        )
      );

      await assert.rejects(
        () =>
          buildPlan(
            fixture,
            {
              manifestPath:
                wrongManifestPath,
            }
          ),
        /RESPONSE_MANIFEST_FILE_NAME_MISMATCH/
      );
    } finally {
      fixture.cleanup();
    }
  }
);

test(
  "receipt content drift fails closed",
  async () => {
    const fixture = createFixture();

    try {
      writeFileSync(
        fixture.receiptPath,
        "tampered receipt",
        "utf8"
      );

      await assert.rejects(
        () => buildPlan(fixture),
        /RESPONSE_RECEIPT_CONTENT_INTEGRITY_MISMATCH/
      );
    } finally {
      fixture.cleanup();
    }
  }
);

test(
  "manifest record and post-authority drift fail closed",
  async () => {
    const fixture = createFixture();

    try {
      const parsed = JSON.parse(
        readFileSync(
          fixture.manifestPath,
          "utf8"
        )
      ) as Record<string, unknown>;

      parsed.untrustedExtraField =
        true;

      writeFileSync(
        fixture.manifestPath,
        JSON.stringify(
          parsed,
          null,
          2
        ) + "\n",
        "utf8"
      );

      await assert.rejects(
        () => buildPlan(fixture),
        /RESPONSE_RENDERING_MANIFEST_RECORD_MISMATCH/
      );

      writeArtifact(
        fixture,
        fixture.artifact
      );

      const driftedPostState = {
        ...fixture.postState,
        policyVersion:
          "unauthorized-policy-drift",
      };

      await assert.rejects(
        () =>
          buildPlan(
            fixture,
            {
              postState:
                driftedPostState,
            }
          ),
        /POST_ARTIFACT_AUTHORITY_STATE_DRIFT/
      );
    } finally {
      fixture.cleanup();
    }
  }
);