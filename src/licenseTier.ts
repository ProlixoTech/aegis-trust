export type LicenseTier = "free" | "pro";

export const LICENSE_TIER_ENV_VAR = "PROLIXO_AEGIS_LICENSE_TIER";

export type LicenseCapability =
  | "coreProtection"
  | "workReceipt"
  | "protectedTerminal"
  | "aiExecutionGatewayMvp0"
  | "aiCommandReview";

const LOCAL_FREE_CAPABILITIES: readonly LicenseCapability[] = [
  "coreProtection",
  "workReceipt",
  "protectedTerminal",
  "aiExecutionGatewayMvp0",
  "aiCommandReview",
];

const LOCAL_PRO_CAPABILITIES: readonly LicenseCapability[] = LOCAL_FREE_CAPABILITIES;

export function isProLicenseTier(tier: LicenseTier): boolean {
  return tier === "pro";
}

export function isFreeLicenseTier(tier: LicenseTier): boolean {
  return tier === "free";
}

export function getCapabilitiesForTier(tier: LicenseTier): readonly LicenseCapability[] {
  return [...(isProLicenseTier(tier) ? LOCAL_PRO_CAPABILITIES : LOCAL_FREE_CAPABILITIES)];
}

export function isCapabilityAvailableForTier(tier: LicenseTier, capability: LicenseCapability): boolean {
  return getCapabilitiesForTier(tier).includes(capability);
}

/**
 * Feature-flag seam for future licensing.
 * Current local/free build always returns "free".
 * Replace only this function body later with server-side tier verification.
 */
function readLocalLicenseTierFromEnvironment(): LicenseTier | undefined {
  const raw = process.env[LICENSE_TIER_ENV_VAR];
  const normalized = raw?.trim().toLowerCase();
  return normalized === "free" || normalized === "pro" ? normalized : undefined;
}

export async function getLicenseTier(): Promise<LicenseTier> {
  return readLocalLicenseTierFromEnvironment() ?? "free";
}