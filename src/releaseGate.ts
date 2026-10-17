export type ReleaseStateClaim = "ready" | "not-ready";

export interface ReleaseGateCheckerResult {
  checkerId: string;
  passed?: boolean;
}

export interface ReleaseGateInput {
  identityInvariantPassed: boolean;
  requiredCheckerIds: readonly string[];
  checkerResults: readonly ReleaseGateCheckerResult[];
  releaseStateClaim: ReleaseStateClaim;
}

export interface ReleaseGateAssessment {
  passed: boolean;
  reason: string | null;
}

export function assessReleaseGate(input: ReleaseGateInput): ReleaseGateAssessment {
  if (input.releaseStateClaim !== "ready" && input.releaseStateClaim !== "not-ready") {
    return { passed: false, reason: "release-state claim is invalid" };
  }

  if (typeof input.identityInvariantPassed !== "boolean") {
    return { passed: false, reason: "identity invariant result is missing" };
  }

  if (input.requiredCheckerIds.length === 0) {
    return { passed: false, reason: "required checker list is empty" };
  }

  const requiredIds = new Set<string>();

  for (const checkerId of input.requiredCheckerIds) {
    if (typeof checkerId !== "string" || checkerId.trim() === "") {
      return { passed: false, reason: "required checker id is missing" };
    }

    if (requiredIds.has(checkerId)) {
      return { passed: false, reason: `duplicate required checker: ${checkerId}` };
    }

    requiredIds.add(checkerId);
  }

  const results = new Map<string, boolean | undefined>();

  for (const result of input.checkerResults) {
    if (typeof result.checkerId !== "string" || result.checkerId.trim() === "") {
      return { passed: false, reason: "checker result id is missing" };
    }

    if (results.has(result.checkerId)) {
      return { passed: false, reason: `duplicate checker result: ${result.checkerId}` };
    }

    results.set(result.checkerId, result.passed);
  }

  if (!input.identityInvariantPassed) {
    return { passed: false, reason: "identity invariant failed" };
  }

  for (const checkerId of requiredIds) {
    if (!results.has(checkerId) || typeof results.get(checkerId) !== "boolean") {
      return { passed: false, reason: `required checker result is missing: ${checkerId}` };
    }

    if (results.get(checkerId) !== true) {
      return { passed: false, reason: `required checker failed: ${checkerId}` };
    }
  }

  if (input.releaseStateClaim !== "ready") {
    return { passed: false, reason: "release-state claim does not match the gate result" };
  }

  return { passed: true, reason: null };
}