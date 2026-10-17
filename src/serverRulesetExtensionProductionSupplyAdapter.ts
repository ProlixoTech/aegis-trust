import * as fs from "node:fs";
import * as path from "node:path";

import {
  FileServerRulesetCanonicalTrustMaterialAssetLoader,
  SERVER_RULESET_CANONICAL_TRUST_RESOURCE_DIRECTORY,
} from "./serverRulesetCanonicalTrustMaterialAssetLoader";

import {
  FileServerRulesetLocalPersistence,
  type StoredServerRulesetSnapshot,
} from "./serverRulesetLocalPersistence";

import {
  FileServerRulesetFreshnessAnchorStore,
  type PersistentServerRulesetFreshnessAnchorsV1,
  type ServerRulesetFreshnessAnchorRecordV1,
} from "./serverRulesetFreshnessAnchorStore";

import type {
  ServerRulesetDistributionChannel,
} from "./serverRulesetFallbackResolution";

import type {
  ServerRulesetExtensionPersistedSupply,
  ServerRulesetExtensionProductionSupplyPorts,
} from "./serverRulesetExtensionProductionComposition";

import type {
  TrustedServerRuleset,
} from "./serverRulesetTrustProvider";

export type ServerRulesetExtensionProductionSupplyAdapterStatus =
  | "ENABLED"
  | "DISABLED"
  | "REJECTED";

export type ServerRulesetExtensionProductionSupplyAdapterIssue =
  | "NONE"
  | "INPUT_INVALID"
  | "INVALID_EXTENSION_ROOT"
  | "INVALID_WORKSPACE_ROOT"
  | "INVALID_DISTRIBUTION_CHANNEL"
  | "INVALID_NOW_PROVIDER"
  | "DEPENDENCIES_INVALID"
  | "CANONICAL_TRUST_MATERIAL_ABSENT"
  | "CANONICAL_TRUST_MATERIAL_DIRECTORY_READ_FAILED"
  | "CANONICAL_TRUST_MATERIAL_DIRECTORY_UNTRUSTED"
  | "CANONICAL_TRUST_MATERIAL_INVALID"
  | "PERSISTENCE_INITIALIZATION_FAILED";

export interface ServerRulesetExtensionProductionSupplyAdapterInput {
  readonly extensionRoot: string;
  readonly workspaceRoot: string;
  readonly distributionChannel:
    ServerRulesetDistributionChannel;
  readonly readNowEpochMs?: () => number;
}

export interface ServerRulesetCanonicalTrustMaterialLoaderPort {
  readonly readPinnedRootPublicKeyPem:
    () => Promise<string>;

  readonly readBundledFallbackRuleset:
    () => Promise<TrustedServerRuleset>;
}

export interface ServerRulesetLocalPersistenceReadPort {
  readonly readSnapshot:
    () => Promise<StoredServerRulesetSnapshot | null>;
}

export interface ServerRulesetFreshnessAnchorReadPort {
  readonly readAnchors:
    () => Promise<
      PersistentServerRulesetFreshnessAnchorsV1 |
      null
    >;
}

export interface ServerRulesetExtensionProductionSupplyAdapterDependencies {
  readonly lstat:
    (literalPath: string) => Promise<fs.Stats>;

  readonly createAssetLoader:
    (
      extensionRoot: string
    ) => ServerRulesetCanonicalTrustMaterialLoaderPort;

  readonly createLocalPersistence:
    (
      workspaceRoot: string
    ) => ServerRulesetLocalPersistenceReadPort;

  readonly createFreshnessAnchorStore:
    (
      workspaceRoot: string
    ) => ServerRulesetFreshnessAnchorReadPort;
}

export interface ServerRulesetExtensionProductionSupplyAdapterEnabled {
  readonly status: "ENABLED";
  readonly issue: "NONE";
  readonly ports:
    Readonly<ServerRulesetExtensionProductionSupplyPorts>;
}

export interface ServerRulesetExtensionProductionSupplyAdapterDisabled {
  readonly status: "DISABLED";
  readonly issue: "CANONICAL_TRUST_MATERIAL_ABSENT";
  readonly ports: null;
}

export interface ServerRulesetExtensionProductionSupplyAdapterRejected {
  readonly status: "REJECTED";
  readonly issue:
    Exclude<
      ServerRulesetExtensionProductionSupplyAdapterIssue,
      | "NONE"
      | "CANONICAL_TRUST_MATERIAL_ABSENT"
    >;
  readonly ports: null;
}

export type ServerRulesetExtensionProductionSupplyAdapterResult =
  | ServerRulesetExtensionProductionSupplyAdapterEnabled
  | ServerRulesetExtensionProductionSupplyAdapterDisabled
  | ServerRulesetExtensionProductionSupplyAdapterRejected;

const DEFAULT_DEPENDENCIES:
  ServerRulesetExtensionProductionSupplyAdapterDependencies =
  Object.freeze({
    lstat:
      (literalPath: string) =>
        fs.promises.lstat(
          literalPath
        ),

    createAssetLoader:
      (extensionRoot: string) =>
        new FileServerRulesetCanonicalTrustMaterialAssetLoader(
          extensionRoot
        ),

    createLocalPersistence:
      (workspaceRoot: string) =>
        new FileServerRulesetLocalPersistence(
          workspaceRoot
        ),

    createFreshnessAnchorStore:
      (workspaceRoot: string) =>
        new FileServerRulesetFreshnessAnchorStore(
          workspaceRoot
        ),
  });

function isRecord(
  value: unknown
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isAbsoluteNonEmptyPath(
  value: unknown
): value is string {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    path.isAbsolute(value)
  );
}

function isDistributionChannel(
  value: unknown
): value is ServerRulesetDistributionChannel {
  return (
    value === "free-stable" ||
    value === "fast-strict"
  );
}

function areDependenciesValid(
  value: unknown
): value is
  ServerRulesetExtensionProductionSupplyAdapterDependencies {
  if (!isRecord(value)) {
    return false;
  }

  return (
    typeof value.lstat === "function" &&
    typeof value.createAssetLoader === "function" &&
    typeof value.createLocalPersistence === "function" &&
    typeof value.createFreshnessAnchorStore === "function"
  );
}

function isAssetLoaderPort(
  value: unknown
): value is ServerRulesetCanonicalTrustMaterialLoaderPort {
  return (
    isRecord(value) &&
    typeof value.readPinnedRootPublicKeyPem === "function" &&
    typeof value.readBundledFallbackRuleset === "function"
  );
}

function isLocalPersistencePort(
  value: unknown
): value is ServerRulesetLocalPersistenceReadPort {
  return (
    isRecord(value) &&
    typeof value.readSnapshot === "function"
  );
}

function isFreshnessAnchorPort(
  value: unknown
): value is ServerRulesetFreshnessAnchorReadPort {
  return (
    isRecord(value) &&
    typeof value.readAnchors === "function"
  );
}

function isMissingPathError(
  error: unknown
): boolean {
  return (
    isRecord(error) &&
    error.code === "ENOENT"
  );
}

function disabledResult():
  ServerRulesetExtensionProductionSupplyAdapterDisabled {
  return Object.freeze({
    status: "DISABLED",
    issue: "CANONICAL_TRUST_MATERIAL_ABSENT",
    ports: null,
  });
}

function rejectedResult(
  issue:
    ServerRulesetExtensionProductionSupplyAdapterRejected[
      "issue"
    ]
): ServerRulesetExtensionProductionSupplyAdapterRejected {
  return Object.freeze({
    status: "REJECTED",
    issue,
    ports: null,
  });
}

function assertLkgAnchorMatchesSnapshot(
  snapshot: StoredServerRulesetSnapshot,
  lkgAnchor: ServerRulesetFreshnessAnchorRecordV1
): void {
  if (
    snapshot.lkg.packageSha256 !==
      lkgAnchor.packageSha256 ||
    snapshot.state.lkgPackageSha256 !==
      lkgAnchor.packageSha256 ||
    snapshot.state.rulesetSha256 !==
      lkgAnchor.rulesetSha256 ||
    snapshot.state.highestIntermediateSequence !==
      lkgAnchor.highestIntermediateSequence ||
    snapshot.state.activeRuleset.rulesetVersion !==
      lkgAnchor.rulesetVersion ||
    snapshot.state.activeRuleset.monotonicCounter !==
      lkgAnchor.monotonicCounter
  ) {
    throw new Error(
      "SERVER_RULESET_PERSISTED_SUPPLY_ANCHOR_MISMATCH"
    );
  }
}

async function readPersistedSupply(
  persistence:
    ServerRulesetLocalPersistenceReadPort,
  freshnessStore:
    ServerRulesetFreshnessAnchorReadPort
): Promise<
  ServerRulesetExtensionPersistedSupply |
  null
> {
  const [
    snapshot,
    anchors,
  ] = await Promise.all([
    persistence.readSnapshot(),
    freshnessStore.readAnchors(),
  ]);

  if (
    snapshot === null &&
    anchors === null
  ) {
    return null;
  }

  if (
    snapshot === null ||
    anchors === null ||
    anchors.lkg === null
  ) {
    throw new Error(
      "SERVER_RULESET_PERSISTED_SUPPLY_PARTIAL_STATE"
    );
  }

  assertLkgAnchorMatchesSnapshot(
    snapshot,
    anchors.lkg
  );

  return Object.freeze({
    snapshot,
    lkgAnchoredAtEpochMs:
      anchors.lkg.anchoredAtEpochMs,
  });
}

export async function createServerRulesetExtensionProductionSupplyAdapter(
  input:
    ServerRulesetExtensionProductionSupplyAdapterInput,
  dependencies:
    ServerRulesetExtensionProductionSupplyAdapterDependencies =
      DEFAULT_DEPENDENCIES
): Promise<
  ServerRulesetExtensionProductionSupplyAdapterResult
> {
  if (!isRecord(input)) {
    return rejectedResult(
      "INPUT_INVALID"
    );
  }

  if (
    !isAbsoluteNonEmptyPath(
      input.extensionRoot
    )
  ) {
    return rejectedResult(
      "INVALID_EXTENSION_ROOT"
    );
  }

  if (
    !isAbsoluteNonEmptyPath(
      input.workspaceRoot
    )
  ) {
    return rejectedResult(
      "INVALID_WORKSPACE_ROOT"
    );
  }

  if (
    !isDistributionChannel(
      input.distributionChannel
    )
  ) {
    return rejectedResult(
      "INVALID_DISTRIBUTION_CHANNEL"
    );
  }

  if (
    input.readNowEpochMs !== undefined &&
    typeof input.readNowEpochMs !== "function"
  ) {
    return rejectedResult(
      "INVALID_NOW_PROVIDER"
    );
  }

  if (!areDependenciesValid(dependencies)) {
    return rejectedResult(
      "DEPENDENCIES_INVALID"
    );
  }

  const extensionRoot =
    path.resolve(
      input.extensionRoot.trim()
    );

  const workspaceRoot =
    path.resolve(
      input.workspaceRoot.trim()
    );

  const materialDirectoryPath =
    path.join(
      extensionRoot,
      SERVER_RULESET_CANONICAL_TRUST_RESOURCE_DIRECTORY
    );

  let materialDirectoryMetadata:
    fs.Stats;

  try {
    materialDirectoryMetadata =
      await dependencies.lstat(
        materialDirectoryPath
      );
  } catch (error) {
    if (isMissingPathError(error)) {
      return disabledResult();
    }

    return rejectedResult(
      "CANONICAL_TRUST_MATERIAL_DIRECTORY_READ_FAILED"
    );
  }

  if (
    materialDirectoryMetadata.isSymbolicLink() ||
    !materialDirectoryMetadata.isDirectory()
  ) {
    return rejectedResult(
      "CANONICAL_TRUST_MATERIAL_DIRECTORY_UNTRUSTED"
    );
  }

  let assetLoader:
    ServerRulesetCanonicalTrustMaterialLoaderPort;

  try {
    const candidate =
      dependencies.createAssetLoader(
        extensionRoot
      );

    if (!isAssetLoaderPort(candidate)) {
      return rejectedResult(
        "CANONICAL_TRUST_MATERIAL_INVALID"
      );
    }

    assetLoader = candidate;

    await Promise.all([
      assetLoader
        .readPinnedRootPublicKeyPem(),

      assetLoader
        .readBundledFallbackRuleset(),
    ]);
  } catch {
    return rejectedResult(
      "CANONICAL_TRUST_MATERIAL_INVALID"
    );
  }

  let persistence:
    ServerRulesetLocalPersistenceReadPort;

  let freshnessStore:
    ServerRulesetFreshnessAnchorReadPort;

  try {
    const persistenceCandidate =
      dependencies.createLocalPersistence(
        workspaceRoot
      );

    const freshnessCandidate =
      dependencies.createFreshnessAnchorStore(
        workspaceRoot
      );

    if (
      !isLocalPersistencePort(
        persistenceCandidate
      ) ||
      !isFreshnessAnchorPort(
        freshnessCandidate
      )
    ) {
      return rejectedResult(
        "PERSISTENCE_INITIALIZATION_FAILED"
      );
    }

    persistence =
      persistenceCandidate;

    freshnessStore =
      freshnessCandidate;
  } catch {
    return rejectedResult(
      "PERSISTENCE_INITIALIZATION_FAILED"
    );
  }

  const readNowEpochMs =
    input.readNowEpochMs ??
    Date.now;

  const ports:
    Readonly<ServerRulesetExtensionProductionSupplyPorts> =
    Object.freeze({
      readDistributionChannel:
        () =>
          input.distributionChannel,

      readNowEpochMs:
        () =>
          readNowEpochMs(),

      readPinnedRootPublicKeyPem:
        () =>
          assetLoader
            .readPinnedRootPublicKeyPem(),

      readBundledFallbackRuleset:
        () =>
          assetLoader
            .readBundledFallbackRuleset(),

      readCurrentPackage:
        () =>
          null,

      readPersistedSupply:
        () =>
          readPersistedSupply(
            persistence,
            freshnessStore
          ),
    });

  return Object.freeze({
    status: "ENABLED",
    issue: "NONE",
    ports,
  });
}