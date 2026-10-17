import { test } from "node:test";
import * as assert from "node:assert/strict";
import type {
  ArtifactIntentEnvelope,
} from "./artifactIntentPreflight";
import {
  classifyArtifactAuthoritySurface,
  DEFAULT_ARTIFACT_AUTHORITY_SURFACE_RULES,
  type AuthoritySurfaceRule,
} from "./authoritySurfaceClassifier";

function createIntent(
  overrides: Partial<ArtifactIntentEnvelope> = {}
): ArtifactIntentEnvelope {
  return {
    schemaVersion: "1.0.0",
    intentId: "generate-work-receipt-artifact",
    artifactKind: "work_receipt",
    provenance: "local_user_command",
    targetPath: ".aegis/receipts",
    entryPaths: ["receipts/work-receipt.md"],
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
    ...overrides,
  };
}

test("work receipt intent classifies as receipt", () => {
  const first = classifyArtifactAuthoritySurface({
    intent: createIntent(),
  });

  const second = classifyArtifactAuthoritySurface({
    intent: createIntent(),
  });

  assert.equal(first.accepted, true);
  assert.equal(first.authoritySurface, "receipt");
  assert.equal(
    first.matchedRuleId,
    "work-receipt-receipt-surface-v1"
  );
  assert.match(
    first.classificationId,
    /^sha256:[a-f0-9]{64}$/
  );
  assert.equal(
    first.classificationId,
    second.classificationId
  );
});

test("unsupported kind, target, and provenance fail closed", () => {
  assert.throws(
    () =>
      classifyArtifactAuthoritySurface({
        intent: createIntent({
          artifactKind: "final_release_zip",
        }),
      }),
    /NO_MATCHING_AUTHORITY_SURFACE_RULE/
  );

  assert.throws(
    () =>
      classifyArtifactAuthoritySurface({
        intent: createIntent({
          targetPath: ".aegis/ledger",
        }),
      }),
    /NO_MATCHING_AUTHORITY_SURFACE_RULE/
  );

  assert.throws(
    () =>
      classifyArtifactAuthoritySurface({
        intent: createIntent({
          provenance: "aegis_runtime",
        }),
      }),
    /NO_MATCHING_AUTHORITY_SURFACE_RULE/
  );
});

test("duplicate authority rules fail closed", () => {
  const original =
    DEFAULT_ARTIFACT_AUTHORITY_SURFACE_RULES[0];

  assert.ok(original);

  const duplicate: AuthoritySurfaceRule = {
    ...original,
    ruleId: "work-receipt-receipt-surface-v1-copy",
  };

  assert.throws(
    () =>
      classifyArtifactAuthoritySurface({
        intent: createIntent(),
        rules: [original, duplicate],
      }),
    /DUPLICATE_AUTHORITY_SURFACE_RULE/
  );
});

test("overlapping matching rules fail as ambiguous", () => {
  const original =
    DEFAULT_ARTIFACT_AUTHORITY_SURFACE_RULES[0];

  assert.ok(original);

  const narrowerRule: AuthoritySurfaceRule = {
    ruleId: "work-receipt-archive-surface-v1",
    artifactKind: "work_receipt",
    provenance: "local_user_command",
    targetPrefix: ".aegis/receipts/archive",
    authoritySurface: "receipt",
  };

  assert.throws(
    () =>
      classifyArtifactAuthoritySurface({
        intent: createIntent({
          targetPath: ".aegis/receipts/archive",
        }),
        rules: [original, narrowerRule],
      }),
    /AMBIGUOUS_AUTHORITY_SURFACE_RULE/
  );
});