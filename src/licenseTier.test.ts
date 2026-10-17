import test from "node:test";
import assert from "node:assert/strict";
import type { LicenseCapability, LicenseTier } from "./licenseTier";
import { LICENSE_TIER_ENV_VAR, getCapabilitiesForTier, getLicenseTier, isCapabilityAvailableForTier, isFreeLicenseTier, isProLicenseTier } from "./licenseTier";

test("getLicenseTier defaults to free for the current local build", async () => {
  const previous = process.env[LICENSE_TIER_ENV_VAR];
  delete process.env[LICENSE_TIER_ENV_VAR];
  try {
    const tier: LicenseTier = await getLicenseTier();
    assert.equal(tier, "free");
  } finally {
    if (previous === undefined) {
      delete process.env[LICENSE_TIER_ENV_VAR];
    } else {
      process.env[LICENSE_TIER_ENV_VAR] = previous;
    }
  }
});

test("getLicenseTier accepts a sanitized local env override", async () => {
  const previous = process.env[LICENSE_TIER_ENV_VAR];
  process.env[LICENSE_TIER_ENV_VAR] = " PRO ";
  try {
    const tier: LicenseTier = await getLicenseTier();
    assert.equal(tier, "pro");
  } finally {
    if (previous === undefined) {
      delete process.env[LICENSE_TIER_ENV_VAR];
    } else {
      process.env[LICENSE_TIER_ENV_VAR] = previous;
    }
  }
});

test("license tier helpers classify free and pro tiers", () => {
  assert.equal(isFreeLicenseTier("free"), true);
  assert.equal(isFreeLicenseTier("pro"), false);
  assert.equal(isProLicenseTier("pro"), true);
  assert.equal(isProLicenseTier("free"), false);
});

test("license capability gate allows current local free capabilities", () => {
  const capabilities: LicenseCapability[] = [
    "coreProtection",
    "workReceipt",
    "protectedTerminal",
    "aiExecutionGatewayMvp0",
    "aiCommandReview",
  ];

  for (const capability of capabilities) {
    assert.equal(isCapabilityAvailableForTier("free", capability), true);
    assert.equal(isCapabilityAvailableForTier("pro", capability), true);
  }
});
test("getLicenseTier ignores an invalid local env override", async () => {
  const previous = process.env[LICENSE_TIER_ENV_VAR];
  process.env[LICENSE_TIER_ENV_VAR] = "enterprise";
  try {
    const tier: LicenseTier = await getLicenseTier();
    assert.equal(tier, "free");
  } finally {
    if (previous === undefined) {
      delete process.env[LICENSE_TIER_ENV_VAR];
    } else {
      process.env[LICENSE_TIER_ENV_VAR] = previous;
    }
  }
});
test("getCapabilitiesForTier returns the current local capability list", () => {
  const expected = [
    "coreProtection",
    "workReceipt",
    "protectedTerminal",
    "aiExecutionGatewayMvp0",
    "aiCommandReview",
  ];
  assert.deepEqual(getCapabilitiesForTier("free"), expected);
  assert.deepEqual(getCapabilitiesForTier("pro"), expected);
});
test("getCapabilitiesForTier does not expose mutable internal capability arrays", () => {
  const mutableCopy = getCapabilitiesForTier("free") as string[];
  mutableCopy.pop();
  assert.deepEqual(getCapabilitiesForTier("free"), [
    "coreProtection",
    "workReceipt",
    "protectedTerminal",
    "aiExecutionGatewayMvp0",
    "aiCommandReview",
  ]);
});
