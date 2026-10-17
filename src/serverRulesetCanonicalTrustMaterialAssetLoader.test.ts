import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  FileServerRulesetCanonicalTrustMaterialAssetLoader,
  MAX_SERVER_RULESET_BUNDLED_FALLBACK_BYTES,
  MAX_SERVER_RULESET_BUNDLED_FALLBACK_RULES,
  MAX_SERVER_RULESET_PINNED_ROOT_PUBLIC_KEY_BYTES,
  SERVER_RULESET_BUNDLED_CATASTROPHIC_FALLBACK_FILE_NAME,
  SERVER_RULESET_CANONICAL_TRUST_RESOURCE_DIRECTORY,
  SERVER_RULESET_PINNED_ROOT_PUBLIC_KEY_FILE_NAME,
} from "./serverRulesetCanonicalTrustMaterialAssetLoader";

interface AssetRoot {
  readonly root: string;
  readonly resources: string;
  readonly material: string;
  readonly rootKey: string;
  readonly fallback: string;
}

function temporaryDirectory(
  prefix: string
): string {
  return fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      prefix
    )
  );
}

function createRoot(
  prefix: string
): AssetRoot {
  const root =
    temporaryDirectory(prefix);

  const resources =
    path.join(
      root,
      "resources"
    );

  const material =
    path.join(
      resources,
      "server-ruleset"
    );

  fs.mkdirSync(
    material,
    {
      recursive: true,
    }
  );

  return {
    root,
    resources,
    material,
    rootKey:
      path.join(
        material,
        SERVER_RULESET_PINNED_ROOT_PUBLIC_KEY_FILE_NAME
      ),
    fallback:
      path.join(
        material,
        SERVER_RULESET_BUNDLED_CATASTROPHIC_FALLBACK_FILE_NAME
      ),
  };
}

function cleanup(
  literalPath: string
): void {
  fs.rmSync(
    literalPath,
    {
      recursive: true,
      force: true,
    }
  );
}

function publicKeyPem(
  key: crypto.KeyObject
): string {
  return key
    .export({
      type: "spki",
      format: "pem",
    })
    .toString();
}

function privateKeyPem(
  key: crypto.KeyObject
): string {
  return key
    .export({
      type: "pkcs8",
      format: "pem",
    })
    .toString();
}

function validFallback(
  overrides:
    Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    rulesetId:
      "bundled-catastrophic-fallback",
    rulesetVersion: 1,
    monotonicCounter: 1,
    notBefore:
      "2025-01-01T00:00:00.000Z",
    notAfter:
      "2029-01-01T00:00:00.000Z",
    rules: [
      {
        ruleId:
          "catastrophic-delete-all",
        category:
          "catastrophic",
        pattern:
          "fataldelete",
      },
    ],
    ...overrides,
  };
}

function writeFallback(
  target: string,
  value: unknown
): void {
  fs.writeFileSync(
    target,
    JSON.stringify(
      value,
      null,
      2
    ) + "\n",
    "utf8"
  );
}

async function expectFallbackRejected(
  prefix: string,
  value: unknown,
  pattern: RegExp
): Promise<void> {
  const assetRoot =
    createRoot(prefix);

  try {
    writeFallback(
      assetRoot.fallback,
      value
    );

    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    await assert.rejects(
      () =>
        loader.readBundledFallbackRuleset(),
      pattern
    );
  } finally {
    cleanup(assetRoot.root);
  }
}

test("canonical trust material loader calculates fixed resource paths", () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-paths-"
    );

  try {
    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    assert.equal(
      SERVER_RULESET_CANONICAL_TRUST_RESOURCE_DIRECTORY,
      path.join(
        "resources",
        "server-ruleset"
      )
    );

    assert.equal(
      loader.resourceDirectoryPath,
      assetRoot.resources
    );

    assert.equal(
      loader.materialDirectoryPath,
      assetRoot.material
    );

    assert.equal(
      loader.pinnedRootPublicKeyPath,
      assetRoot.rootKey
    );

    assert.equal(
      loader.bundledCatastrophicFallbackPath,
      assetRoot.fallback
    );
  } finally {
    cleanup(assetRoot.root);
  }
});

test("valid canonical Ed25519 pinned root is normalized deterministically", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-root-valid-"
    );

  try {
    const keyPair =
      crypto.generateKeyPairSync(
        "ed25519"
      );

    const pem =
      publicKeyPem(
        keyPair.publicKey
      );

    fs.writeFileSync(
      assetRoot.rootKey,
      "\n  " + pem + "  \n",
      "utf8"
    );

    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    const loaded =
      await loader
        .readPinnedRootPublicKeyPem();

    assert.equal(
      loaded,
      pem.trim() + "\n"
    );
  } finally {
    cleanup(assetRoot.root);
  }
});

test("missing pinned root asset fails closed", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-root-missing-"
    );

  try {
    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    await assert.rejects(
      () =>
        loader.readPinnedRootPublicKeyPem(),
      /PINNED_ROOT_PUBLIC_KEY_ASSET_NOT_FOUND/
    );
  } finally {
    cleanup(assetRoot.root);
  }
});

test("extension root resources material directory and root file symlinks fail closed", async () => {
  const targetRoot =
    createRoot(
      "aegis-c10a4b2b2a-link-target-"
    );

  const rootLinkParent =
    temporaryDirectory(
      "aegis-c10a4b2b2a-root-link-parent-"
    );

  const resourceRoot =
    temporaryDirectory(
      "aegis-c10a4b2b2a-resource-link-root-"
    );

  const outsideResources =
    temporaryDirectory(
      "aegis-c10a4b2b2a-resource-link-outside-"
    );

  const materialRoot =
    temporaryDirectory(
      "aegis-c10a4b2b2a-material-link-root-"
    );

  const outsideMaterial =
    temporaryDirectory(
      "aegis-c10a4b2b2a-material-link-outside-"
    );

  const fileRoot =
    createRoot(
      "aegis-c10a4b2b2a-file-link-root-"
    );

  const outsideFileRoot =
    temporaryDirectory(
      "aegis-c10a4b2b2a-file-link-outside-"
    );

  try {
    const keyPair =
      crypto.generateKeyPairSync(
        "ed25519"
      );

    fs.writeFileSync(
      targetRoot.rootKey,
      publicKeyPem(
        keyPair.publicKey
      ),
      "utf8"
    );

    const rootLink =
      path.join(
        rootLinkParent,
        "extension-root"
      );

    fs.symlinkSync(
      targetRoot.root,
      rootLink,
      "dir"
    );

    await assert.rejects(
      () =>
        new FileServerRulesetCanonicalTrustMaterialAssetLoader(
          rootLink
        ).readPinnedRootPublicKeyPem(),
      /UNTRUSTED_CANONICAL_EXTENSION_ROOT_METADATA/
    );

    fs.symlinkSync(
      outsideResources,
      path.join(
        resourceRoot,
        "resources"
      ),
      "dir"
    );

    await assert.rejects(
      () =>
        new FileServerRulesetCanonicalTrustMaterialAssetLoader(
          resourceRoot
        ).readPinnedRootPublicKeyPem(),
      /UNTRUSTED_CANONICAL_RESOURCE_DIRECTORY_METADATA/
    );

    const materialResources =
      path.join(
        materialRoot,
        "resources"
      );

    fs.mkdirSync(
      materialResources
    );

    fs.symlinkSync(
      outsideMaterial,
      path.join(
        materialResources,
        "server-ruleset"
      ),
      "dir"
    );

    await assert.rejects(
      () =>
        new FileServerRulesetCanonicalTrustMaterialAssetLoader(
          materialRoot
        ).readPinnedRootPublicKeyPem(),
      /UNTRUSTED_CANONICAL_SERVER_RULESET_RESOURCE_DIRECTORY_METADATA/
    );

    const outsideKey =
      path.join(
        outsideFileRoot,
        "root.pem"
      );

    fs.writeFileSync(
      outsideKey,
      publicKeyPem(
        keyPair.publicKey
      ),
      "utf8"
    );

    fs.symlinkSync(
      outsideKey,
      fileRoot.rootKey
    );

    await assert.rejects(
      () =>
        new FileServerRulesetCanonicalTrustMaterialAssetLoader(
          fileRoot.root
        ).readPinnedRootPublicKeyPem(),
      /UNTRUSTED_PINNED_ROOT_PUBLIC_KEY_ASSET_METADATA/
    );
  } finally {
    cleanup(targetRoot.root);
    cleanup(rootLinkParent);
    cleanup(resourceRoot);
    cleanup(outsideResources);
    cleanup(materialRoot);
    cleanup(outsideMaterial);
    cleanup(fileRoot.root);
    cleanup(outsideFileRoot);
  }
});

test("private NUL and multiple PEM material are rejected", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-root-content-"
    );

  try {
    const first =
      crypto.generateKeyPairSync(
        "ed25519"
      );

    const second =
      crypto.generateKeyPairSync(
        "ed25519"
      );

    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    fs.writeFileSync(
      assetRoot.rootKey,
      privateKeyPem(
        first.privateKey
      ),
      "utf8"
    );

    await assert.rejects(
      () =>
        loader.readPinnedRootPublicKeyPem(),
      /PRIVATE_KEY_MATERIAL_REJECTED/
    );

    fs.writeFileSync(
      assetRoot.rootKey,
      publicKeyPem(
        first.publicKey
      ) + "\0",
      "utf8"
    );

    await assert.rejects(
      () =>
        loader.readPinnedRootPublicKeyPem(),
      /PINNED_ROOT_PUBLIC_KEY_CONTAINS_NUL/
    );

    fs.writeFileSync(
      assetRoot.rootKey,
      publicKeyPem(
        first.publicKey
      ) +
      publicKeyPem(
        second.publicKey
      ),
      "utf8"
    );

    await assert.rejects(
      () =>
        loader.readPinnedRootPublicKeyPem(),
      /(INVALID_PINNED_ROOT_PUBLIC_KEY|PINNED_ROOT_PUBLIC_KEY_NOT_CANONICAL)/
    );
  } finally {
    cleanup(assetRoot.root);
  }
});

test("non Ed25519 public key is rejected", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-non-ed25519-"
    );

  try {
    const keyPair =
      crypto.generateKeyPairSync(
        "ec",
        {
          namedCurve:
            "prime256v1",
        }
      );

    fs.writeFileSync(
      assetRoot.rootKey,
      publicKeyPem(
        keyPair.publicKey
      ),
      "utf8"
    );

    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    await assert.rejects(
      () =>
        loader.readPinnedRootPublicKeyPem(),
      /PINNED_ROOT_PUBLIC_KEY_NOT_ED25519/
    );
  } finally {
    cleanup(assetRoot.root);
  }
});

test("oversized pinned root asset is rejected", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-root-large-"
    );

  try {
    fs.writeFileSync(
      assetRoot.rootKey,
      "x".repeat(
        MAX_SERVER_RULESET_PINNED_ROOT_PUBLIC_KEY_BYTES +
        1
      ),
      "utf8"
    );

    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    await assert.rejects(
      () =>
        loader.readPinnedRootPublicKeyPem(),
      /PINNED_ROOT_PUBLIC_KEY_ASSET_SIZE_INVALID/
    );
  } finally {
    cleanup(assetRoot.root);
  }
});

test("valid catastrophic fallback is loaded and deeply frozen", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-fallback-valid-"
    );

  try {
    writeFallback(
      assetRoot.fallback,
      validFallback()
    );

    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    const fallback =
      await loader
        .readBundledFallbackRuleset();

    assert.equal(
      fallback.schemaVersion,
      1
    );

    assert.equal(
      fallback.rules.length,
      1
    );

    assert.equal(
      fallback.rules[0]?.category,
      "catastrophic"
    );

    assert.equal(
      Object.isFrozen(fallback),
      true
    );

    assert.equal(
      Object.isFrozen(
        fallback.rules
      ),
      true
    );

    assert.equal(
      Object.isFrozen(
        fallback.rules[0]
      ),
      true
    );
  } finally {
    cleanup(assetRoot.root);
  }
});

test("missing bundled fallback asset fails closed", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-fallback-missing-"
    );

  try {
    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    await assert.rejects(
      () =>
        loader.readBundledFallbackRuleset(),
      /BUNDLED_CATASTROPHIC_FALLBACK_ASSET_NOT_FOUND/
    );
  } finally {
    cleanup(assetRoot.root);
  }
});

test("bundled fallback file symlink fails closed", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-fallback-symlink-"
    );

  const outsideRoot =
    temporaryDirectory(
      "aegis-c10a4b2b2a-fallback-outside-"
    );

  try {
    const outsideFile =
      path.join(
        outsideRoot,
        "fallback.json"
      );

    writeFallback(
      outsideFile,
      validFallback()
    );

    fs.symlinkSync(
      outsideFile,
      assetRoot.fallback
    );

    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    await assert.rejects(
      () =>
        loader.readBundledFallbackRuleset(),
      /UNTRUSTED_BUNDLED_CATASTROPHIC_FALLBACK_ASSET_METADATA/
    );
  } finally {
    cleanup(assetRoot.root);
    cleanup(outsideRoot);
  }
});

test("malformed unknown-field and wrong-schema fallback documents fail closed", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-fallback-document-"
    );

  try {
    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    fs.writeFileSync(
      assetRoot.fallback,
      "{invalid-json",
      "utf8"
    );

    await assert.rejects(
      () =>
        loader.readBundledFallbackRuleset(),
      /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_JSON/
    );

    writeFallback(
      assetRoot.fallback,
      validFallback({
        execute:
          "child-process",
      })
    );

    await assert.rejects(
      () =>
        loader.readBundledFallbackRuleset(),
      /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
    );

    writeFallback(
      assetRoot.fallback,
      validFallback({
        schemaVersion: 2,
      })
    );

    await assert.rejects(
      () =>
        loader.readBundledFallbackRuleset(),
      /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
    );
  } finally {
    cleanup(assetRoot.root);
  }
});

test("non catastrophic fallback category is rejected", async () => {
  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-category-",
    validFallback({
      rules: [
        {
          ruleId:
            "destructive-rule",
          category:
            "destructive",
          pattern:
            "fataldelete",
        },
      ],
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_RULE/
  );
});

test("empty over-limit and oversized fallback assets are rejected", async () => {
  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-empty-",
    validFallback({
      rules: [],
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
  );

  const rules =
    Array.from(
      {
        length:
          MAX_SERVER_RULESET_BUNDLED_FALLBACK_RULES +
          1,
      },
      (_, index) => ({
        ruleId:
          "rule-" +
          String(index + 1),
        category:
          "catastrophic",
        pattern:
          "block" +
          String(index + 1),
      })
    );

  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-many-",
    validFallback({
      rules,
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
  );

  const oversizedRoot =
    createRoot(
      "aegis-c10a4b2b2a-fallback-large-"
    );

  try {
    fs.writeFileSync(
      oversizedRoot.fallback,
      "x".repeat(
        MAX_SERVER_RULESET_BUNDLED_FALLBACK_BYTES +
        1
      ),
      "utf8"
    );

    await assert.rejects(
      () =>
        new FileServerRulesetCanonicalTrustMaterialAssetLoader(
          oversizedRoot.root
        ).readBundledFallbackRuleset(),
      /BUNDLED_CATASTROPHIC_FALLBACK_ASSET_SIZE_INVALID/
    );
  } finally {
    cleanup(oversizedRoot.root);
  }
});

test("unsafe overlength duplicate and invalid-ID fallback rules are rejected", async () => {
  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-unsafe-",
    validFallback({
      rules: [
        {
          ruleId:
            "unsafe-rule",
          category:
            "catastrophic",
          pattern:
            ".*secret",
        },
      ],
    }),
    /UNSAFE_BUNDLED_CATASTROPHIC_FALLBACK_PATTERN/
  );

  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-pattern-large-",
    validFallback({
      rules: [
        {
          ruleId:
            "large-pattern",
          category:
            "catastrophic",
          pattern:
            "a".repeat(513),
        },
      ],
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_RULE/
  );

  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-duplicate-",
    validFallback({
      rules: [
        {
          ruleId:
            "duplicate-rule",
          category:
            "catastrophic",
          pattern:
            "blockone",
        },
        {
          ruleId:
            "duplicate-rule",
          category:
            "catastrophic",
          pattern:
            "blocktwo",
        },
      ],
    }),
    /DUPLICATE_BUNDLED_CATASTROPHIC_FALLBACK_RULE_ID/
  );

  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-rule-id-",
    validFallback({
      rules: [
        {
          ruleId:
            "invalid rule id",
          category:
            "catastrophic",
          pattern:
            "fataldelete",
        },
      ],
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_RULE/
  );
});

test("invalid document identifiers counters versions and timestamps fail closed", async () => {
  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-id-",
    validFallback({
      rulesetId:
        "invalid identifier",
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
  );

  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-version-",
    validFallback({
      rulesetVersion: 0,
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
  );

  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-counter-",
    validFallback({
      monotonicCounter: 0,
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
  );

  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-time-format-",
    validFallback({
      notBefore:
        "invalid-time",
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
  );

  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-impossible-date-",
    validFallback({
      notBefore:
        "2025-02-30T00:00:00.000Z",
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
  );

  await expectFallbackRejected(
    "aegis-c10a4b2b2a-fallback-window-",
    validFallback({
      notBefore:
        "2029-01-01T00:00:00.000Z",
      notAfter:
        "2025-01-01T00:00:00.000Z",
    }),
    /INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT/
  );
});

test("repeated reads are deterministic and preserve asset bytes and mtimes", async () => {
  const assetRoot =
    createRoot(
      "aegis-c10a4b2b2a-deterministic-"
    );

  try {
    const keyPair =
      crypto.generateKeyPairSync(
        "ed25519"
      );

    fs.writeFileSync(
      assetRoot.rootKey,
      publicKeyPem(
        keyPair.publicKey
      ),
      "utf8"
    );

    writeFallback(
      assetRoot.fallback,
      validFallback()
    );

    const rootBytesBefore =
      fs.readFileSync(
        assetRoot.rootKey
      );

    const fallbackBytesBefore =
      fs.readFileSync(
        assetRoot.fallback
      );

    const rootMtimeBefore =
      fs.statSync(
        assetRoot.rootKey
      ).mtimeMs;

    const fallbackMtimeBefore =
      fs.statSync(
        assetRoot.fallback
      ).mtimeMs;

    const loader =
      new FileServerRulesetCanonicalTrustMaterialAssetLoader(
        assetRoot.root
      );

    const firstRoot =
      await loader
        .readPinnedRootPublicKeyPem();

    const secondRoot =
      await loader
        .readPinnedRootPublicKeyPem();

    const firstFallback =
      await loader
        .readBundledFallbackRuleset();

    const secondFallback =
      await loader
        .readBundledFallbackRuleset();

    assert.equal(
      firstRoot,
      secondRoot
    );

    assert.deepEqual(
      firstFallback,
      secondFallback
    );

    assert.deepEqual(
      fs.readFileSync(
        assetRoot.rootKey
      ),
      rootBytesBefore
    );

    assert.deepEqual(
      fs.readFileSync(
        assetRoot.fallback
      ),
      fallbackBytesBefore
    );

    assert.equal(
      fs.statSync(
        assetRoot.rootKey
      ).mtimeMs,
      rootMtimeBefore
    );

    assert.equal(
      fs.statSync(
        assetRoot.fallback
      ).mtimeMs,
      fallbackMtimeBefore
    );
  } finally {
    cleanup(assetRoot.root);
  }
});
