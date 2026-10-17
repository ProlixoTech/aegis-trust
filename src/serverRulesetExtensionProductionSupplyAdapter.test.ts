import test from "node:test";
import assert from "node:assert/strict";

import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";

import {
  tmpdir,
} from "node:os";

import * as path from "node:path";

import type {
  StoredServerRulesetSnapshot,
} from "./serverRulesetLocalPersistence";

import type {
  PersistentServerRulesetFreshnessAnchorsV1,
} from "./serverRulesetFreshnessAnchorStore";

import type {
  TrustedServerRuleset,
} from "./serverRulesetTrustProvider";

import {
  createServerRulesetExtensionProductionSupplyAdapter,
  type ServerRulesetCanonicalTrustMaterialLoaderPort,
  type ServerRulesetExtensionProductionSupplyAdapterDependencies,
} from "./serverRulesetExtensionProductionSupplyAdapter";

function createTemporaryRoot(): string {
  return mkdtempSync(
    path.join(
      tmpdir(),
      "aegis-c10a4b2b3-test-"
    )
  );
}

function materialDirectory(
  extensionRoot: string
): string {
  return path.join(
    extensionRoot,
    "resources",
    "server-ruleset"
  );
}

function createMaterialDirectory(
  extensionRoot: string
): string {
  const directory =
    materialDirectory(
      extensionRoot
    );

  mkdirSync(
    directory,
    {
      recursive: true,
    }
  );

  return directory;
}

function adapterInput(
  extensionRoot: string,
  workspaceRoot: string
) {
  return {
    extensionRoot,
    workspaceRoot,
    distributionChannel:
      "free-stable" as const,
    readNowEpochMs:
      () => 1_800_000_000_000,
  };
}

function validatedFallbackRuleset():
  TrustedServerRuleset {
  return Object.freeze({
    schemaVersion: 1,
    rulesetId:
      "validated-test-fallback",
    rulesetVersion: 1,
    monotonicCounter: 1,
    notBefore:
      "2026-01-01T00:00:00.000Z",
    notAfter:
      "2099-01-01T00:00:00.000Z",
    rules: Object.freeze([]),
  }) as unknown as TrustedServerRuleset;
}

function validatedAssetLoader():
  ServerRulesetCanonicalTrustMaterialLoaderPort {
  const fallback =
    validatedFallbackRuleset();

  return Object.freeze({
    readPinnedRootPublicKeyPem:
      async () =>
        [
          "-----BEGIN PUBLIC KEY-----",
          "VALIDATED_TEST_KEY",
          "-----END PUBLIC KEY-----",
        ].join("\n"),

    readBundledFallbackRuleset:
      async () =>
        fallback,
  });
}

function matchingSnapshot():
  StoredServerRulesetSnapshot {
  const packageSha256 =
    "c".repeat(64);

  const rulesetSha256 =
    "b".repeat(64);

  return {
    state: {
      schemaVersion: 1,
      highestIntermediateSequence: 4,
      intermediateKeyId:
        "intermediate-key-1",
      intermediateKeySha256:
        "a".repeat(64),
      activeRuleset: {
        rulesetVersion: 3,
        monotonicCounter: 5,
        notBefore:
          "2026-01-01T00:00:00.000Z",
        notAfter:
          "2099-01-01T00:00:00.000Z",
      },
      rulesetSha256,
      lkgPackageSha256:
        packageSha256,
    },
    lkg: {
      schemaVersion: 1,
      packageSha256,
      packageText:
        "signed-package-text",
    },
  };
}

function matchingAnchors():
  PersistentServerRulesetFreshnessAnchorsV1 {
  return {
    schemaVersion: 1,
    current: null,
    lkg: {
      packageSha256:
        "c".repeat(64),
      rulesetSha256:
        "b".repeat(64),
      highestIntermediateSequence: 4,
      rulesetVersion: 3,
      monotonicCounter: 5,
      anchoredAtEpochMs:
        1_700_000_000_000,
    },
  };
}

function currentOnlyAnchors():
  PersistentServerRulesetFreshnessAnchorsV1 {
  const matching =
    matchingAnchors();

  if (matching.lkg === null) {
    throw new Error(
      "EXPECTED_TEST_LKG_ANCHOR"
    );
  }

  return {
    schemaVersion: 1,
    current: {
      ...matching.lkg,
    },
    lkg: null,
  };
}

function injectedDependencies(
  snapshot:
    StoredServerRulesetSnapshot |
    null,
  anchors:
    PersistentServerRulesetFreshnessAnchorsV1 |
    null
): ServerRulesetExtensionProductionSupplyAdapterDependencies {
  return Object.freeze({
    lstat:
      async (
        literalPath: string
      ) =>
        lstatSync(
          literalPath
        ),

    createAssetLoader:
      () =>
        validatedAssetLoader(),

    createLocalPersistence:
      () =>
        Object.freeze({
          readSnapshot:
            async () =>
              snapshot,
        }),

    createFreshnessAnchorStore:
      () =>
        Object.freeze({
          readAnchors:
            async () =>
              anchors,
        }),
  });
}

test(
  "missing canonical material directory returns DISABLED",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    try {
      const materialPath =
        materialDirectory(
          extensionRoot
        );

      assert.equal(
        existsSync(materialPath),
        false
      );

      const result =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          )
        );

      assert.equal(
        result.status,
        "DISABLED"
      );

      assert.equal(
        result.issue,
        "CANONICAL_TRUST_MATERIAL_ABSENT"
      );

      assert.equal(
        result.ports,
        null
      );

      assert.equal(
        Object.isFrozen(result),
        true
      );

      assert.equal(
        existsSync(materialPath),
        false
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "invalid input returns REJECTED",
  async () => {
    const absoluteRoot =
      createTemporaryRoot();

    try {
      const invalidExtension =
        await createServerRulesetExtensionProductionSupplyAdapter({
          extensionRoot:
            "relative-extension",
          workspaceRoot:
            absoluteRoot,
          distributionChannel:
            "free-stable",
        });

      assert.equal(
        invalidExtension.issue,
        "INVALID_EXTENSION_ROOT"
      );

      const invalidWorkspace =
        await createServerRulesetExtensionProductionSupplyAdapter({
          extensionRoot:
            absoluteRoot,
          workspaceRoot:
            "relative-workspace",
          distributionChannel:
            "free-stable",
        });

      assert.equal(
        invalidWorkspace.issue,
        "INVALID_WORKSPACE_ROOT"
      );

      const invalidChannel =
        await createServerRulesetExtensionProductionSupplyAdapter({
          extensionRoot:
            absoluteRoot,
          workspaceRoot:
            absoluteRoot,
          distributionChannel:
            "invalid-channel" as
              "free-stable",
        });

      assert.equal(
        invalidChannel.issue,
        "INVALID_DISTRIBUTION_CHANNEL"
      );

      const invalidNow =
        await createServerRulesetExtensionProductionSupplyAdapter({
          extensionRoot:
            absoluteRoot,
          workspaceRoot:
            absoluteRoot,
          distributionChannel:
            "free-stable",
          readNowEpochMs:
            "invalid" as unknown as
              () => number,
        });

      assert.equal(
        invalidNow.issue,
        "INVALID_NOW_PROVIDER"
      );
    } finally {
      rmSync(
        absoluteRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "partial canonical trust material returns REJECTED",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    try {
      const directory =
        createMaterialDirectory(
          extensionRoot
        );

      writeFileSync(
        path.join(
          directory,
          "pinned-root-public-key.pem"
        ),
        "partial-test-key",
        "utf8"
      );

      const result =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          )
        );

      assert.equal(
        result.status,
        "REJECTED"
      );

      assert.equal(
        result.issue,
        "CANONICAL_TRUST_MATERIAL_INVALID"
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "malformed canonical trust material returns REJECTED",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    try {
      const directory =
        createMaterialDirectory(
          extensionRoot
        );

      writeFileSync(
        path.join(
          directory,
          "pinned-root-public-key.pem"
        ),
        "not-a-public-key",
        "utf8"
      );

      writeFileSync(
        path.join(
          directory,
          "bundled-catastrophic-fallback.json"
        ),
        JSON.stringify({
          invalid: true,
        }),
        "utf8"
      );

      const result =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          )
        );

      assert.equal(
        result.status,
        "REJECTED"
      );

      assert.equal(
        result.issue,
        "CANONICAL_TRUST_MATERIAL_INVALID"
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "symlink material directory returns REJECTED",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    const externalDirectory =
      createTemporaryRoot();

    try {
      mkdirSync(
        path.join(
          extensionRoot,
          "resources"
        ),
        {
          recursive: true,
        }
      );

      symlinkSync(
        externalDirectory,
        materialDirectory(
          extensionRoot
        )
      );

      const result =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          )
        );

      assert.equal(
        result.status,
        "REJECTED"
      );

      assert.equal(
        result.issue,
        "CANONICAL_TRUST_MATERIAL_DIRECTORY_UNTRUSTED"
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        externalDirectory,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "validated test material enables frozen ports",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    try {
      createMaterialDirectory(
        extensionRoot
      );

      const result =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          ),
          injectedDependencies(
            null,
            null
          )
        );

      if (result.status !== "ENABLED") {
        throw new Error(
          "EXPECTED_ENABLED_ADAPTER"
        );
      }

      assert.equal(
        Object.isFrozen(result),
        true
      );

      assert.equal(
        Object.isFrozen(result.ports),
        true
      );

      assert.match(
        await result.ports
          .readPinnedRootPublicKeyPem(),
        /BEGIN PUBLIC KEY/
      );

      assert.equal(
        Object.isFrozen(
          await result.ports
            .readBundledFallbackRuleset()
        ),
        true
      );

      assert.equal(
        await result.ports
          .readDistributionChannel(),
        "free-stable"
      );

      assert.equal(
        await result.ports
          .readNowEpochMs(),
        1_800_000_000_000
      );

      assert.equal(
        await result.ports
          .readCurrentPackage(),
        null
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "absent persisted snapshot and anchors return null",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    try {
      createMaterialDirectory(
        extensionRoot
      );

      const result =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          ),
          injectedDependencies(
            null,
            null
          )
        );

      if (result.status !== "ENABLED") {
        throw new Error(
          "EXPECTED_ENABLED_ADAPTER"
        );
      }

      assert.equal(
        await result.ports
          .readPersistedSupply(),
        null
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "current-only anchor state fails closed",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    try {
      createMaterialDirectory(
        extensionRoot
      );

      const result =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          ),
          injectedDependencies(
            null,
            currentOnlyAnchors()
          )
        );

      if (result.status !== "ENABLED") {
        throw new Error(
          "EXPECTED_ENABLED_ADAPTER"
        );
      }

      await assert.rejects(
        async () => {
          await result.ports
            .readPersistedSupply();
        },
        /SERVER_RULESET_PERSISTED_SUPPLY_PARTIAL_STATE/
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "matching snapshot and LKG anchor return persisted supply",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    try {
      createMaterialDirectory(
        extensionRoot
      );

      const snapshot =
        matchingSnapshot();

      const result =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          ),
          injectedDependencies(
            snapshot,
            matchingAnchors()
          )
        );

      if (result.status !== "ENABLED") {
        throw new Error(
          "EXPECTED_ENABLED_ADAPTER"
        );
      }

      const persisted =
        await result.ports
          .readPersistedSupply();

      assert.ok(persisted);

      assert.equal(
        persisted.snapshot,
        snapshot
      );

      assert.equal(
        persisted.lkgAnchoredAtEpochMs,
        1_700_000_000_000
      );

      assert.equal(
        Object.isFrozen(persisted),
        true
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "snapshot-only and LKG-only persisted states fail closed",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    try {
      createMaterialDirectory(
        extensionRoot
      );

      const snapshotOnly =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          ),
          injectedDependencies(
            matchingSnapshot(),
            null
          )
        );

      if (snapshotOnly.status !== "ENABLED") {
        throw new Error(
          "EXPECTED_SNAPSHOT_ONLY_ADAPTER"
        );
      }

      await assert.rejects(
        async () => {
          await snapshotOnly.ports
            .readPersistedSupply();
        },
        /SERVER_RULESET_PERSISTED_SUPPLY_PARTIAL_STATE/
      );

      const anchorOnly =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          ),
          injectedDependencies(
            null,
            matchingAnchors()
          )
        );

      if (anchorOnly.status !== "ENABLED") {
        throw new Error(
          "EXPECTED_ANCHOR_ONLY_ADAPTER"
        );
      }

      await assert.rejects(
        async () => {
          await anchorOnly.ports
            .readPersistedSupply();
        },
        /SERVER_RULESET_PERSISTED_SUPPLY_PARTIAL_STATE/
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);

test(
  "persisted anchor mismatch fails closed",
  async () => {
    const extensionRoot =
      createTemporaryRoot();

    const workspaceRoot =
      createTemporaryRoot();

    try {
      createMaterialDirectory(
        extensionRoot
      );

      const anchors =
        matchingAnchors();

      if (anchors.lkg === null) {
        throw new Error(
          "EXPECTED_LKG_ANCHOR"
        );
      }

      const mismatched:
        PersistentServerRulesetFreshnessAnchorsV1 =
        {
          schemaVersion: 1,
          current: null,
          lkg: {
            ...anchors.lkg,
            rulesetSha256:
              "d".repeat(64),
          },
        };

      const result =
        await createServerRulesetExtensionProductionSupplyAdapter(
          adapterInput(
            extensionRoot,
            workspaceRoot
          ),
          injectedDependencies(
            matchingSnapshot(),
            mismatched
          )
        );

      if (result.status !== "ENABLED") {
        throw new Error(
          "EXPECTED_ENABLED_ADAPTER"
        );
      }

      await assert.rejects(
        async () => {
          await result.ports
            .readPersistedSupply();
        },
        /SERVER_RULESET_PERSISTED_SUPPLY_ANCHOR_MISMATCH/
      );
    } finally {
      rmSync(
        extensionRoot,
        {
          recursive: true,
          force: true,
        }
      );

      rmSync(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        }
      );
    }
  }
);