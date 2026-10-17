import * as crypto from "crypto";

import {
  createSafetyKernelV31NonceLifecycle,
} from "./safetyKernelV31NonceLifecyclePolicy";

import type {
  SafetyKernelV31NonceLifecycleRecord,
} from "./safetyKernelV31NonceLifecyclePolicy";

export interface SafetyKernelV31LocalNonceIssueResult {
  approvalNonce: string;
  lifecycle: SafetyKernelV31NonceLifecycleRecord;
  randomByteLength: number;
  randomSource: "crypto.randomBytes";
}

export const SAFETY_KERNEL_V31_LOCAL_NONCE_ISSUER_INVARIANT = {
  LOCAL_ONLY: true,
  CRYPTOGRAPHIC_RANDOM_SOURCE: true,
  GATEWAY_SUPPLIED_NONCE_ALLOWED: false,
  RAW_NONCE_PERSISTED: false,
  RAW_NONCE_LOGGED: false,
  RUNTIME_CONNECTED: false,
  EXECUTION_AUTHORITY_GRANTED: false,
} as const;

export const SAFETY_KERNEL_V31_LOCAL_NONCE_DEFAULT_BYTES = 32;
export const SAFETY_KERNEL_V31_LOCAL_NONCE_MIN_BYTES = 16;
export const SAFETY_KERNEL_V31_LOCAL_NONCE_MAX_BYTES = 64;

export function issueSafetyKernelV31LocalNonce(
  actionId: string,
  randomByteLength = SAFETY_KERNEL_V31_LOCAL_NONCE_DEFAULT_BYTES
): SafetyKernelV31LocalNonceIssueResult {
  if (!actionId.trim()) {
    throw new Error("INVALID_ACTION_ID");
  }

  if (
    !Number.isInteger(randomByteLength) ||
    randomByteLength < SAFETY_KERNEL_V31_LOCAL_NONCE_MIN_BYTES ||
    randomByteLength > SAFETY_KERNEL_V31_LOCAL_NONCE_MAX_BYTES
  ) {
    throw new Error("INVALID_NONCE_BYTE_LENGTH");
  }

  const approvalNonce = crypto.randomBytes(randomByteLength).toString("hex");
  const lifecycle = createSafetyKernelV31NonceLifecycle(actionId, approvalNonce);

  return {
    approvalNonce,
    lifecycle,
    randomByteLength,
    randomSource: "crypto.randomBytes",
  };
}
