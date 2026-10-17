export const VERIFIER_GRAPH_CYCLE_GUARD_VERSION = 1 as const;

export type VerifierGraphCycleGuardIssueCode =
  | "INVALID_GRAPH_DECLARATION"
  | "INVALID_NODE_ID"
  | "DUPLICATE_NODE_ID"
  | "INVALID_DEPENDENCIES"
  | "INVALID_DEPENDENCY_ID"
  | "DUPLICATE_DEPENDENCY_ID"
  | "MISSING_DEPENDENCY"
  | "SELF_DEPENDENCY"
  | "CYCLE_DETECTED"
  | "INVALID_RUNTIME_VERIFIER_ID"
  | "RECURSION_REENTRY_BLOCKED"
  | "VERIFIER_EXECUTION_FAILED";

export interface VerifierGraphNodeDeclaration {
  readonly id: string;
  readonly dependencies: readonly string[];
}

export interface VerifierGraphDeclaration {
  readonly nodes: readonly VerifierGraphNodeDeclaration[];
}

export interface VerifierGraphVerificationResult {
  readonly guardVersion:
    typeof VERIFIER_GRAPH_CYCLE_GUARD_VERSION;
  readonly graphDeclared: boolean;
  readonly verified: boolean;
  readonly acyclic: boolean;
  readonly issueCodes:
    readonly VerifierGraphCycleGuardIssueCode[];
  readonly cyclePath: readonly string[];
  readonly trustedStatusAllowed: boolean;
  readonly safeStatusAllowed: boolean;
  readonly executionAllowed: boolean;
  readonly restoreAllowed: boolean;
  readonly exportAllowed: boolean;
  readonly releaseReadyAllowed: boolean;
  readonly callerVerificationBooleanAccepted: false;
}

export interface VerifierGraphGuardedExecutionSuccess<T> {
  readonly guardVersion:
    typeof VERIFIER_GRAPH_CYCLE_GUARD_VERSION;
  readonly ok: true;
  readonly value: T;
  readonly issueCodes: readonly [];
  readonly cyclePath: readonly [];
  readonly trustedStatusAllowed: true;
  readonly safeStatusAllowed: true;
  readonly executionAllowed: true;
  readonly restoreAllowed: true;
  readonly exportAllowed: true;
  readonly releaseReadyAllowed: true;
  readonly callerVerificationBooleanAccepted: false;
}

export interface VerifierGraphGuardedExecutionFailure {
  readonly guardVersion:
    typeof VERIFIER_GRAPH_CYCLE_GUARD_VERSION;
  readonly ok: false;
  readonly issueCodes:
    readonly VerifierGraphCycleGuardIssueCode[];
  readonly cyclePath: readonly string[];
  readonly trustedStatusAllowed: false;
  readonly safeStatusAllowed: false;
  readonly executionAllowed: false;
  readonly restoreAllowed: false;
  readonly exportAllowed: false;
  readonly releaseReadyAllowed: false;
  readonly callerVerificationBooleanAccepted: false;
}

export type VerifierGraphGuardedExecutionResult<T> =
  | VerifierGraphGuardedExecutionSuccess<T>
  | VerifierGraphGuardedExecutionFailure;

const VERIFIER_ID_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const ISSUE_ORDER:
  readonly VerifierGraphCycleGuardIssueCode[] =
  Object.freeze([
    "INVALID_GRAPH_DECLARATION",
    "INVALID_NODE_ID",
    "DUPLICATE_NODE_ID",
    "INVALID_DEPENDENCIES",
    "INVALID_DEPENDENCY_ID",
    "DUPLICATE_DEPENDENCY_ID",
    "MISSING_DEPENDENCY",
    "SELF_DEPENDENCY",
    "CYCLE_DETECTED",
    "INVALID_RUNTIME_VERIFIER_ID",
    "RECURSION_REENTRY_BLOCKED",
    "VERIFIER_EXECUTION_FAILED",
  ]);

function isRecord(
  value: unknown
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isVerifierId(
  value: unknown
): value is string {
  return (
    typeof value === "string" &&
    VERIFIER_ID_PATTERN.test(value)
  );
}

function orderedIssues(
  issues:
    ReadonlySet<VerifierGraphCycleGuardIssueCode>
): readonly VerifierGraphCycleGuardIssueCode[] {
  return Object.freeze(
    ISSUE_ORDER.filter(
      (issue) => issues.has(issue)
    )
  );
}

function frozenPath(
  path: readonly string[]
): readonly string[] {
  return Object.freeze([...path]);
}

function failClosedVerification(
  graphDeclared: boolean,
  issues:
    ReadonlySet<VerifierGraphCycleGuardIssueCode>,
  cyclePath: readonly string[] = []
): VerifierGraphVerificationResult {
  return Object.freeze({
    guardVersion:
      VERIFIER_GRAPH_CYCLE_GUARD_VERSION,
    graphDeclared,
    verified: false,
    acyclic: false,
    issueCodes: orderedIssues(issues),
    cyclePath: frozenPath(cyclePath),
    trustedStatusAllowed: false,
    safeStatusAllowed: false,
    executionAllowed: false,
    restoreAllowed: false,
    exportAllowed: false,
    releaseReadyAllowed: false,
    callerVerificationBooleanAccepted: false,
  });
}

function successfulVerification():
  VerifierGraphVerificationResult {
  return Object.freeze({
    guardVersion:
      VERIFIER_GRAPH_CYCLE_GUARD_VERSION,
    graphDeclared: true,
    verified: true,
    acyclic: true,
    issueCodes:
      Object.freeze([]) as
        readonly VerifierGraphCycleGuardIssueCode[],
    cyclePath:
      Object.freeze([]) as readonly string[],
    trustedStatusAllowed: true,
    safeStatusAllowed: true,
    executionAllowed: true,
    restoreAllowed: true,
    exportAllowed: true,
    releaseReadyAllowed: true,
    callerVerificationBooleanAccepted: false,
  });
}

function canonicalizeCycle(
  path: readonly string[]
): readonly string[] {
  const body = path.slice(0, -1);

  if (body.length === 0) {
    return Object.freeze([]);
  }

  let best = [...body];
  let bestKey = best.join("\u0000");

  for (
    let index = 1;
    index < body.length;
    index += 1
  ) {
    const rotation = [
      ...body.slice(index),
      ...body.slice(0, index),
    ];

    const key = rotation.join("\u0000");

    if (key < bestKey) {
      best = rotation;
      bestKey = key;
    }
  }

  return Object.freeze([
    ...best,
    best[0],
  ]);
}

function findDeterministicCycle(
  graph:
    ReadonlyMap<string, readonly string[]>
): readonly string[] {
  const state =
    new Map<string, 0 | 1 | 2>();

  const stack: string[] = [];

  const cycles =
    new Map<string, readonly string[]>();

  const visit = (
    nodeId: string
  ): void => {
    state.set(nodeId, 1);
    stack.push(nodeId);

    for (
      const dependencyId of
        graph.get(nodeId) ?? []
    ) {
      const dependencyState =
        state.get(dependencyId) ?? 0;

      if (dependencyState === 0) {
        visit(dependencyId);
      }
      else if (dependencyState === 1) {
        const start =
          stack.lastIndexOf(dependencyId);

        if (start >= 0) {
          const cycle =
            canonicalizeCycle([
              ...stack.slice(start),
              dependencyId,
            ]);

          cycles.set(
            cycle.join("\u0000"),
            cycle
          );
        }
      }
    }

    stack.pop();
    state.set(nodeId, 2);
  };

  for (
    const nodeId of
      [...graph.keys()].sort()
  ) {
    if (
      (state.get(nodeId) ?? 0) === 0
    ) {
      visit(nodeId);
    }
  }

  const firstKey =
    [...cycles.keys()].sort()[0];

  return firstKey === undefined
    ? Object.freeze([])
    : cycles.get(firstKey) ??
        Object.freeze([]);
}

export function verifyVerifierGraphAcyclic(
  input: unknown
): VerifierGraphVerificationResult {
  const issues =
    new Set<
      VerifierGraphCycleGuardIssueCode
    >();

  if (
    !isRecord(input) ||
    !Array.isArray(input.nodes) ||
    input.nodes.length === 0
  ) {
    issues.add(
      "INVALID_GRAPH_DECLARATION"
    );

    return failClosedVerification(
      false,
      issues
    );
  }

  const graph =
    new Map<
      string,
      readonly string[]
    >();

  for (const rawNode of input.nodes) {
    if (
      !isRecord(rawNode) ||
      !isVerifierId(rawNode.id)
    ) {
      issues.add("INVALID_NODE_ID");
      continue;
    }

    const nodeId = rawNode.id;

    if (graph.has(nodeId)) {
      issues.add("DUPLICATE_NODE_ID");
      continue;
    }

    if (
      !Array.isArray(
        rawNode.dependencies
      )
    ) {
      issues.add(
        "INVALID_DEPENDENCIES"
      );

      graph.set(
        nodeId,
        Object.freeze([])
      );

      continue;
    }

    const dependencies: string[] = [];
    const dependencySet =
      new Set<string>();

    for (
      const dependencyId of
        rawNode.dependencies
    ) {
      if (
        !isVerifierId(dependencyId)
      ) {
        issues.add(
          "INVALID_DEPENDENCY_ID"
        );

        continue;
      }

      if (
        dependencySet.has(
          dependencyId
        )
      ) {
        issues.add(
          "DUPLICATE_DEPENDENCY_ID"
        );

        continue;
      }

      dependencySet.add(dependencyId);
      dependencies.push(dependencyId);
    }

    graph.set(
      nodeId,
      Object.freeze(
        [...dependencies].sort()
      )
    );
  }

  for (
    const [
      nodeId,
      dependencies,
    ] of graph.entries()
  ) {
    for (
      const dependencyId of
        dependencies
    ) {
      if (
        dependencyId === nodeId
      ) {
        issues.add(
          "SELF_DEPENDENCY"
        );
      }

      if (
        !graph.has(dependencyId)
      ) {
        issues.add(
          "MISSING_DEPENDENCY"
        );
      }
    }
  }

  const structuralFailure = [
    "INVALID_NODE_ID",
    "DUPLICATE_NODE_ID",
    "INVALID_DEPENDENCIES",
    "INVALID_DEPENDENCY_ID",
    "DUPLICATE_DEPENDENCY_ID",
    "MISSING_DEPENDENCY",
  ].some(
    (issue) =>
      issues.has(
        issue as
          VerifierGraphCycleGuardIssueCode
      )
  );

  if (structuralFailure) {
    return failClosedVerification(
      true,
      issues
    );
  }

  const cyclePath =
    findDeterministicCycle(graph);

  if (cyclePath.length > 0) {
    issues.add("CYCLE_DETECTED");
  }

  if (issues.size > 0) {
    return failClosedVerification(
      true,
      issues,
      cyclePath
    );
  }

  return successfulVerification();
}

function failClosedExecution(
  issue:
    VerifierGraphCycleGuardIssueCode,
  cyclePath: readonly string[] = []
): VerifierGraphGuardedExecutionFailure {
  const issues =
    new Set<
      VerifierGraphCycleGuardIssueCode
    >([issue]);

  return Object.freeze({
    guardVersion:
      VERIFIER_GRAPH_CYCLE_GUARD_VERSION,
    ok: false,
    issueCodes: orderedIssues(issues),
    cyclePath: frozenPath(cyclePath),
    trustedStatusAllowed: false,
    safeStatusAllowed: false,
    executionAllowed: false,
    restoreAllowed: false,
    exportAllowed: false,
    releaseReadyAllowed: false,
    callerVerificationBooleanAccepted: false,
  });
}

function successfulExecution<T>(
  value: T
): VerifierGraphGuardedExecutionSuccess<T> {
  return Object.freeze({
    guardVersion:
      VERIFIER_GRAPH_CYCLE_GUARD_VERSION,
    ok: true,
    value,
    issueCodes:
      Object.freeze([]) as readonly [],
    cyclePath:
      Object.freeze([]) as readonly [],
    trustedStatusAllowed: true,
    safeStatusAllowed: true,
    executionAllowed: true,
    restoreAllowed: true,
    exportAllowed: true,
    releaseReadyAllowed: true,
    callerVerificationBooleanAccepted: false,
  });
}

function isGuardFailure(
  value: unknown
): value is
  VerifierGraphGuardedExecutionFailure {
  return (
    isRecord(value) &&
    value.guardVersion ===
      VERIFIER_GRAPH_CYCLE_GUARD_VERSION &&
    value.ok === false &&
    Array.isArray(value.issueCodes) &&
    value.trustedStatusAllowed === false &&
    value.safeStatusAllowed === false &&
    value.executionAllowed === false &&
    value.restoreAllowed === false &&
    value.exportAllowed === false &&
    value.releaseReadyAllowed === false
  );
}

export class VerifierRecursionGuard {
  private readonly activeVerifierIds:
    string[] = [];

  get activePath():
    readonly string[] {
    return frozenPath(
      this.activeVerifierIds
    );
  }

  async run<T>(
    verifierId: string,
    operation: () => T | Promise<T>
  ): Promise<
    VerifierGraphGuardedExecutionResult<T>
  > {
    if (
      !isVerifierId(verifierId) ||
      typeof operation !== "function"
    ) {
      return failClosedExecution(
        "INVALID_RUNTIME_VERIFIER_ID"
      );
    }

    const activeIndex =
      this.activeVerifierIds.indexOf(
        verifierId
      );

    if (activeIndex >= 0) {
      return failClosedExecution(
        "RECURSION_REENTRY_BLOCKED",
        [
          ...this.activeVerifierIds.slice(
            activeIndex
          ),
          verifierId,
        ]
      );
    }

    this.activeVerifierIds.push(
      verifierId
    );

    try {
      const value = await operation();

      if (isGuardFailure(value)) {
        return value;
      }

      return successfulExecution(value);
    }
    catch {
      return failClosedExecution(
        "VERIFIER_EXECUTION_FAILED"
      );
    }
    finally {
      const popped =
        this.activeVerifierIds.pop();

      if (popped !== verifierId) {
        this.activeVerifierIds.length = 0;
      }
    }
  }
}