import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  MAX_SERVER_RULESET_PATTERN_LENGTH,
  compileServerRulesetSafeRegex,
} from "./serverRulesetSafeRegex";

import type {
  TrustedServerRuleset,
  TrustedServerRulesetRule,
} from "./serverRulesetTrustProvider";

export const SERVER_RULESET_CANONICAL_TRUST_RESOURCE_DIRECTORY =
  path.join(
    "resources",
    "server-ruleset"
  );

export const SERVER_RULESET_PINNED_ROOT_PUBLIC_KEY_FILE_NAME =
  "pinned-root-public-key.pem";

export const SERVER_RULESET_BUNDLED_CATASTROPHIC_FALLBACK_FILE_NAME =
  "bundled-catastrophic-fallback.json";

export const MAX_SERVER_RULESET_PINNED_ROOT_PUBLIC_KEY_BYTES =
  16 * 1024;

export const MAX_SERVER_RULESET_BUNDLED_FALLBACK_BYTES =
  2 * 1024 * 1024;

export const MAX_SERVER_RULESET_BUNDLED_FALLBACK_RULES =
  256;

function isRecord(
  value: unknown
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function hasExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[]
): boolean {
  const actual =
    Object.keys(value).sort();

  const expected =
    [...keys].sort();

  return (
    actual.length === expected.length &&
    actual.every(
      (key, index) =>
        key === expected[index]
    )
  );
}

function isIdentifier(
  value: unknown
): value is string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 128
  ) {
    return false;
  }

  const first =
    value[0];

  if (
    first === undefined ||
    !(
      first >= "A" &&
      first <= "Z"
    ) &&
    !(
      first >= "a" &&
      first <= "z"
    ) &&
    !(
      first >= "0" &&
      first <= "9"
    )
  ) {
    return false;
  }

  const allowed =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
    "abcdefghijklmnopqrstuvwxyz" +
    "0123456789._:-";

  for (const character of value) {
    if (!allowed.includes(character)) {
      return false;
    }
  }

  return true;
}

function isPositiveSafeInteger(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 1
  );
}

function isCanonicalIsoTimestamp(
  value: unknown
): value is string {
  if (
    typeof value !== "string" ||
    value.length !== 24 ||
    value[4] !== "-" ||
    value[7] !== "-" ||
    value[10] !== "T" ||
    value[13] !== ":" ||
    value[16] !== ":" ||
    value[19] !== "." ||
    value[23] !== "Z"
  ) {
    return false;
  }

  const digitIndices = [
    0, 1, 2, 3,
    5, 6,
    8, 9,
    11, 12,
    14, 15,
    17, 18,
    20, 21, 22,
  ];

  for (const index of digitIndices) {
    const character =
      value[index];

    if (
      character === undefined ||
      character < "0" ||
      character > "9"
    ) {
      return false;
    }
  }

  const epochMs =
    Date.parse(value);

  return (
    Number.isFinite(epochMs) &&
    new Date(epochMs).toISOString() ===
      value
  );
}

function errorCode(
  error: unknown
): string | null {
  if (
    isRecord(error) &&
    typeof error.code === "string"
  ) {
    return error.code;
  }

  return null;
}

async function lstatOrNull(
  literalPath: string
): Promise<fs.Stats | null> {
  try {
    return await fs.promises.lstat(
      literalPath
    );
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      return null;
    }

    throw error;
  }
}

function assertTrustedDirectory(
  metadata: fs.Stats,
  errorName: string
): void {
  if (
    metadata.isSymbolicLink() ||
    !metadata.isDirectory()
  ) {
    throw new Error(errorName);
  }
}

async function assertCanonicalDirectoryChain(
  extensionRoot: string,
  resourceDirectoryPath: string,
  materialDirectoryPath: string
): Promise<void> {
  const extensionRootMetadata =
    await lstatOrNull(
      extensionRoot
    );

  if (extensionRootMetadata === null) {
    throw new Error(
      "CANONICAL_EXTENSION_ROOT_NOT_FOUND"
    );
  }

  assertTrustedDirectory(
    extensionRootMetadata,
    "UNTRUSTED_CANONICAL_EXTENSION_ROOT_METADATA"
  );

  const resourceDirectoryMetadata =
    await lstatOrNull(
      resourceDirectoryPath
    );

  if (resourceDirectoryMetadata === null) {
    throw new Error(
      "CANONICAL_RESOURCE_DIRECTORY_NOT_FOUND"
    );
  }

  assertTrustedDirectory(
    resourceDirectoryMetadata,
    "UNTRUSTED_CANONICAL_RESOURCE_DIRECTORY_METADATA"
  );

  const materialDirectoryMetadata =
    await lstatOrNull(
      materialDirectoryPath
    );

  if (materialDirectoryMetadata === null) {
    throw new Error(
      "CANONICAL_SERVER_RULESET_RESOURCE_DIRECTORY_NOT_FOUND"
    );
  }

  assertTrustedDirectory(
    materialDirectoryMetadata,
    "UNTRUSTED_CANONICAL_SERVER_RULESET_RESOURCE_DIRECTORY_METADATA"
  );
}

async function readRegularUtf8Asset(
  literalPath: string,
  maximumBytes: number,
  missingError: string,
  metadataError: string,
  sizeError: string
): Promise<string> {
  let handle:
    fs.promises.FileHandle;

  try {
    handle =
      await fs.promises.open(
        literalPath,
        fs.constants.O_RDONLY |
          fs.constants.O_NOFOLLOW
      );
  } catch (error) {
    const code =
      errorCode(error);

    if (code === "ENOENT") {
      throw new Error(missingError);
    }

    if (
      code === "ELOOP" ||
      code === "EMLINK"
    ) {
      throw new Error(metadataError);
    }

    throw error;
  }

  try {
    const metadata =
      await handle.stat();

    if (!metadata.isFile()) {
      throw new Error(metadataError);
    }

    if (
      metadata.size < 1 ||
      metadata.size > maximumBytes
    ) {
      throw new Error(sizeError);
    }

    const text =
      await handle.readFile({
        encoding: "utf8",
      });

    const bytes =
      Buffer.byteLength(
        text,
        "utf8"
      );

    if (
      bytes < 1 ||
      bytes > maximumBytes
    ) {
      throw new Error(sizeError);
    }

    return text;
  } finally {
    await handle.close();
  }
}

function normalizePemLineEndings(
  value: string
): string {
  return value
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
}

function validatePinnedRootPublicKeyPem(
  text: string
): string {
  if (text.includes("\0")) {
    throw new Error(
      "PINNED_ROOT_PUBLIC_KEY_CONTAINS_NUL"
    );
  }

  if (text.includes("PRIVATE KEY")) {
    throw new Error(
      "PRIVATE_KEY_MATERIAL_REJECTED"
    );
  }

  const normalized =
    normalizePemLineEndings(
      text
    ).trim() + "\n";

  if (
    !normalized.startsWith(
      "-----BEGIN PUBLIC KEY-----\n"
    ) ||
    !normalized.endsWith(
      "-----END PUBLIC KEY-----\n"
    )
  ) {
    throw new Error(
      "INVALID_PINNED_ROOT_PUBLIC_KEY_PEM"
    );
  }

  let key:
    crypto.KeyObject;

  try {
    key =
      crypto.createPublicKey(
        normalized
      );
  } catch {
    throw new Error(
      "INVALID_PINNED_ROOT_PUBLIC_KEY"
    );
  }

  if (
    key.type !== "public" ||
    key.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error(
      "PINNED_ROOT_PUBLIC_KEY_NOT_ED25519"
    );
  }

  const canonical =
    normalizePemLineEndings(
      key.export({
        type: "spki",
        format: "pem",
      }).toString()
    ).trim() + "\n";

  if (normalized !== canonical) {
    throw new Error(
      "PINNED_ROOT_PUBLIC_KEY_NOT_CANONICAL"
    );
  }

  return canonical;
}

function validateFallbackRule(
  value: unknown,
  ruleIds: Set<string>
): TrustedServerRulesetRule {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "category",
        "pattern",
        "ruleId",
      ]
    ) ||
    !isIdentifier(value.ruleId) ||
    value.category !== "catastrophic" ||
    typeof value.pattern !== "string" ||
    value.pattern.length < 1 ||
    value.pattern.length >
      MAX_SERVER_RULESET_PATTERN_LENGTH
  ) {
    throw new Error(
      "INVALID_BUNDLED_CATASTROPHIC_FALLBACK_RULE"
    );
  }

  if (ruleIds.has(value.ruleId)) {
    throw new Error(
      "DUPLICATE_BUNDLED_CATASTROPHIC_FALLBACK_RULE_ID"
    );
  }

  const compileResult =
    compileServerRulesetSafeRegex(
      value.pattern
    );

  if (!compileResult.accepted) {
    throw new Error(
      "UNSAFE_BUNDLED_CATASTROPHIC_FALLBACK_PATTERN"
    );
  }

  ruleIds.add(value.ruleId);

  return Object.freeze({
    ruleId: value.ruleId,
    category: "catastrophic",
    pattern: value.pattern,
  });
}

function parseBundledCatastrophicFallback(
  text: string
): TrustedServerRuleset {
  let parsed: unknown;

  try {
    parsed =
      JSON.parse(text);
  } catch {
    throw new Error(
      "INVALID_BUNDLED_CATASTROPHIC_FALLBACK_JSON"
    );
  }

  if (
    !isRecord(parsed) ||
    !hasExactKeys(
      parsed,
      [
        "monotonicCounter",
        "notAfter",
        "notBefore",
        "rules",
        "rulesetId",
        "rulesetVersion",
        "schemaVersion",
      ]
    ) ||
    parsed.schemaVersion !== 1 ||
    !isIdentifier(parsed.rulesetId) ||
    !isPositiveSafeInteger(
      parsed.rulesetVersion
    ) ||
    !isPositiveSafeInteger(
      parsed.monotonicCounter
    ) ||
    !isCanonicalIsoTimestamp(
      parsed.notBefore
    ) ||
    !isCanonicalIsoTimestamp(
      parsed.notAfter
    ) ||
    Date.parse(parsed.notBefore) >=
      Date.parse(parsed.notAfter) ||
    !Array.isArray(parsed.rules) ||
    parsed.rules.length < 1 ||
    parsed.rules.length >
      MAX_SERVER_RULESET_BUNDLED_FALLBACK_RULES
  ) {
    throw new Error(
      "INVALID_BUNDLED_CATASTROPHIC_FALLBACK_DOCUMENT"
    );
  }

  const ruleIds =
    new Set<string>();

  const rules =
    parsed.rules.map(
      value =>
        validateFallbackRule(
          value,
          ruleIds
        )
    );

  Object.freeze(rules);

  return Object.freeze({
    schemaVersion: 1,
    rulesetId:
      parsed.rulesetId,
    rulesetVersion:
      parsed.rulesetVersion,
    monotonicCounter:
      parsed.monotonicCounter,
    notBefore:
      parsed.notBefore,
    notAfter:
      parsed.notAfter,
    rules,
  });
}

export class FileServerRulesetCanonicalTrustMaterialAssetLoader {
  readonly extensionRoot: string;
  readonly resourceDirectoryPath: string;
  readonly materialDirectoryPath: string;
  readonly pinnedRootPublicKeyPath: string;
  readonly bundledCatastrophicFallbackPath: string;

  constructor(
    extensionRoot: string
  ) {
    if (
      typeof extensionRoot !== "string" ||
      extensionRoot.trim().length < 1 ||
      !path.isAbsolute(extensionRoot)
    ) {
      throw new Error(
        "INVALID_CANONICAL_TRUST_MATERIAL_EXTENSION_ROOT"
      );
    }

    this.extensionRoot =
      path.resolve(
        extensionRoot
      );

    this.resourceDirectoryPath =
      path.join(
        this.extensionRoot,
        "resources"
      );

    this.materialDirectoryPath =
      path.join(
        this.extensionRoot,
        SERVER_RULESET_CANONICAL_TRUST_RESOURCE_DIRECTORY
      );

    this.pinnedRootPublicKeyPath =
      path.join(
        this.materialDirectoryPath,
        SERVER_RULESET_PINNED_ROOT_PUBLIC_KEY_FILE_NAME
      );

    this.bundledCatastrophicFallbackPath =
      path.join(
        this.materialDirectoryPath,
        SERVER_RULESET_BUNDLED_CATASTROPHIC_FALLBACK_FILE_NAME
      );
  }

  private async assertDirectoryChain():
    Promise<void> {
    await assertCanonicalDirectoryChain(
      this.extensionRoot,
      this.resourceDirectoryPath,
      this.materialDirectoryPath
    );
  }

  async readPinnedRootPublicKeyPem():
    Promise<string> {
    await this.assertDirectoryChain();

    const text =
      await readRegularUtf8Asset(
        this.pinnedRootPublicKeyPath,
        MAX_SERVER_RULESET_PINNED_ROOT_PUBLIC_KEY_BYTES,
        "PINNED_ROOT_PUBLIC_KEY_ASSET_NOT_FOUND",
        "UNTRUSTED_PINNED_ROOT_PUBLIC_KEY_ASSET_METADATA",
        "PINNED_ROOT_PUBLIC_KEY_ASSET_SIZE_INVALID"
      );

    return validatePinnedRootPublicKeyPem(
      text
    );
  }

  async readBundledFallbackRuleset():
    Promise<TrustedServerRuleset> {
    await this.assertDirectoryChain();

    const text =
      await readRegularUtf8Asset(
        this.bundledCatastrophicFallbackPath,
        MAX_SERVER_RULESET_BUNDLED_FALLBACK_BYTES,
        "BUNDLED_CATASTROPHIC_FALLBACK_ASSET_NOT_FOUND",
        "UNTRUSTED_BUNDLED_CATASTROPHIC_FALLBACK_ASSET_METADATA",
        "BUNDLED_CATASTROPHIC_FALLBACK_ASSET_SIZE_INVALID"
      );

    return parseBundledCatastrophicFallback(
      text
    );
  }
}
