import test from "node:test";
import assert from "node:assert/strict";
import type { ActionQualityResult } from "./types";
import {
  SAFETY_KERNEL_V31_TRANSACTION_INPUT_BUILDER_INVARIANT,
  buildDefaultSafetyKernelV31TransactionCapability,
  buildSafetyKernelV31TransactionInputBuilderResult,
  buildSafetyKernelV31TransactionServiceInputFromCallerContext,
  mapActionGateStatusToTransactionRiskClass,
} from "./safetyKernelV31TransactionInputBuilder";

function gate(status: ActionQualityResult["status"]): ActionQualityResult {
  return {
    status,
    userMessage: "test message",
    internalRuleId: "TEST_RULE",
    source: "vscode_command",
    reasons: [],
    detectedEffects: [],
  } as ActionQualityResult;
}

function caller() {
  return {
    action_id: "action-input",
    target: "src/example.ts",
    intent: "review action",
    proposed_action: "Get-Content src/example.ts",
    context_hash: "sha256:test",
    timestamp: "2026-01-01T00:00:00.000Z",
    adapter_id: "input-builder-test",
    policy_version: "policy-test",
    human_readable_summary: "Transaction input test",
  };
}

test("transaction input builder invariant is nonce-free, disconnected, and non-executing", () => {
  assert.deepEqual(SAFETY_KERNEL_V31_TRANSACTION_INPUT_BUILDER_INVARIANT, {
    SIDE_EFFECT_FREE: true,
    LOCAL_INPUT_ONLY: true,
    DIAGNOSTIC_PLACEHOLDER_ALLOWED: false,
    NONCE_ISSUED_BY_TRANSACTION_SERVICE: true,
    AUTOMATIC_EXECUTION_ALLOWED: false,
    RUNTIME_CONNECTED: false,
    EXECUTION_AUTHORITY_GRANTED: false,
  });
});

test("transaction input builder maps gate status and emits no nonce field", () => {
  assert.deepEqual(
    ["ALLOW", "REVIEW_NEEDED", "SPLIT_REQUIRED", "BLOCK"].map((status) =>
      mapActionGateStatusToTransactionRiskClass(status as ActionQualityResult["status"])
    ),
    ["low", "medium", "high", "critical"]
  );
  const built = buildSafetyKernelV31TransactionInputBuilderResult(
    caller(),
    gate("REVIEW_NEEDED")
  );
  assert.equal(built.transactionInput.risk_class, "medium");
  assert.deepEqual(built.transactionInput.capability_requested, {
    operation_class: "read",
    scope: "workspace",
    manner: "preview_only",
  });
  assert.deepEqual(built.transactionInput.mutation_scope, {
    scope: "workspace",
    target: "src/example.ts",
    protected_target: false,
  });
  assert.equal(
    Object.prototype.hasOwnProperty.call(built.transactionInput, "approval_nonce"),
    false
  );
});

test("transaction input builder normalizes inline fields and preserves proposed action", () => {
  const input = buildSafetyKernelV31TransactionServiceInputFromCallerContext(
    {
      ...caller(),
      action_id: " action-1\n",
      target: " src/example.ts\t",
      intent: " review\n action ",
      proposed_action: "  npm test\n",
      human_readable_summary: " summary\n text ",
    },
    gate("ALLOW")
  );
  assert.equal(input.action_id, "action-1");
  assert.equal(input.target, "src/example.ts");
  assert.equal(input.intent, "review action");
  assert.equal(input.proposed_action, "  npm test\n");
  assert.equal(input.human_readable_summary, "summary text");
});

test("transaction input builder rejects blank required values", () => {
  assert.throws(
    () =>
      buildSafetyKernelV31TransactionServiceInputFromCallerContext(
        { ...caller(), action_id: " " },
        gate("ALLOW")
      ),
    /INVALID_ACTION_ID/
  );
  assert.throws(
    () =>
      buildSafetyKernelV31TransactionServiceInputFromCallerContext(
        { ...caller(), proposed_action: "\n" },
        gate("ALLOW")
      ),
    /INVALID_PROPOSED_ACTION/
  );
});


test("transaction input builder validates ISO 8601 timestamps", () => {
  for (const timestamp of [
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T09:30:00+09:30",
    "2024-02-29T23:59:59.999Z",
  ]) {
    const input = buildSafetyKernelV31TransactionServiceInputFromCallerContext(
      { ...caller(), timestamp },
      gate("ALLOW")
    );
    assert.equal(input.timestamp, timestamp);
  }
  for (const timestamp of [
    "2026-01-01T00:00:00",
    "2026-13-01T00:00:00.000Z",
    "2026-02-30T00:00:00.000Z",
    "2023-02-29T00:00:00.000Z",
  ]) {
    assert.throws(
      () => buildSafetyKernelV31TransactionServiceInputFromCallerContext(
        { ...caller(), timestamp },
        gate("ALLOW")
      ),
      /INVALID_TIMESTAMP/
    );
  }
});


test("transaction input builder resolves source-specific manifest capability defaults", () => {
  const cases = [
    ["vscode_command", { operation_class: "read", scope: "workspace", manner: "preview_only" }],
    ["manual_review", { operation_class: "read", scope: "workspace", manner: "preview_only" }],
    ["protected_terminal", { operation_class: "execute", scope: "workspace", manner: "requires_review" }],
    ["ai_connector", { operation_class: "execute", scope: "workspace", manner: "requires_review" }],
  ] as const;

  for (const [source, expected] of cases) {
    const input = buildSafetyKernelV31TransactionServiceInputFromCallerContext(
      caller(),
      { ...gate("ALLOW"), source }
    );
    assert.deepEqual(input.capability_requested, expected);
  }
});

test("transaction input builder rejects source without trusted manifest capability", () => {
  assert.throws(
    () =>
      buildSafetyKernelV31TransactionServiceInputFromCallerContext(
        caller(),
        { ...gate("ALLOW"), source: "external_gateway" }
      ),
    /UNTRUSTED_ACTION_QUALITY_SOURCE/
  );
});

test("transaction input builder rejects capability source mismatch", () => {
  assert.throws(
    () =>
      buildSafetyKernelV31TransactionServiceInputFromCallerContext(
        {
          ...caller(),
          capability_requested: {
            operation_class: "execute",
            scope: "workspace",
            manner: "requires_review",
          },
        },
        gate("ALLOW")
      ),
    /CAPABILITY_SOURCE_MISMATCH/
  );
});

test("default transaction capability requires reviewed workspace execution", () => {
  assert.deepEqual(buildDefaultSafetyKernelV31TransactionCapability(), {
    operation_class: "execute",
    scope: "workspace",
    manner: "requires_review",
  });
});

import { buildDefaultSafetyKernelV31TransactionMutationScope } from "./safetyKernelV31TransactionInputBuilder";

test("transaction input builder preserves trusted overrides, default scopes, validation, and input immutability", () => {
  const explicitCapability = {
    operation_class: "execute",
    scope: "workspace",
    manner: "requires_review",
  } as const;
  const explicitMutationScope = {
    scope: "workspace",
    target: "src/explicit.ts",
    protected_target: false,
  } as const;
  const callerInput = {
    ...caller(),
    action_id: " action`explicit\n",
    target: " src/explicit.ts\t",
    intent: " inspect\n explicit ",
    context_hash: " sha256:explicit\t",
    timestamp: " 2026-07-16T23:40:00.000Z ",
    adapter_id: " adapter`explicit\r",
    policy_version: " policy\t3.1 ",
    human_readable_summary: " explicit\n summary ",
    risk_class: "high" as const,
    capability_requested: explicitCapability,
    mutation_scope: explicitMutationScope,
  };
  const actionQuality = {
    ...gate("ALLOW"),
    source: "ai_connector" as const,
  };
  const callerBefore = JSON.stringify(callerInput);
  const actionQualityBefore = JSON.stringify(actionQuality);

  const direct = buildSafetyKernelV31TransactionServiceInputFromCallerContext(
    callerInput,
    actionQuality
  );
  const wrapped = buildSafetyKernelV31TransactionInputBuilderResult(
    callerInput,
    actionQuality
  );

  assert.equal(direct.action_id, "action'explicit");
  assert.equal(direct.target, "src/explicit.ts");
  assert.equal(direct.intent, "inspect explicit");
  assert.equal(direct.context_hash, "sha256:explicit");
  assert.equal(direct.timestamp, "2026-07-16T23:40:00.000Z");
  assert.equal(direct.adapter_id, "adapter'explicit");
  assert.equal(direct.policy_version, "policy 3.1");
  assert.equal(direct.human_readable_summary, "explicit summary");
  assert.equal(direct.risk_class, "high");
  assert.equal(direct.capability_requested, explicitCapability);
  assert.deepEqual(direct.mutation_scope, explicitMutationScope);
  assert.notEqual(direct.mutation_scope, explicitMutationScope);
  assert.deepEqual(wrapped.transactionInput, direct);
  assert.equal(
    wrapped.invariant,
    SAFETY_KERNEL_V31_TRANSACTION_INPUT_BUILDER_INVARIANT
  );

  assert.deepEqual(
    buildDefaultSafetyKernelV31TransactionMutationScope(
      ".env",
      {
        operation_class: "execute",
        scope: "protected_file",
        manner: "requires_review",
      }
    ),
    {
      scope: "protected_file",
      target: ".env",
      protected_target: true,
    }
  );
  assert.deepEqual(
    buildDefaultSafetyKernelV31TransactionMutationScope(
      "src/example.ts",
      {
        operation_class: "read",
        scope: "workspace",
        manner: "preview_only",
      }
    ),
    {
      scope: "workspace",
      target: "src/example.ts",
      protected_target: false,
    }
  );

  const blankCases = [
    ["target", "INVALID_TARGET"],
    ["intent", "INVALID_INTENT"],
    ["context_hash", "INVALID_CONTEXT_HASH"],
    ["adapter_id", "INVALID_ADAPTER_ID"],
    ["policy_version", "INVALID_POLICY_VERSION"],
    ["human_readable_summary", "INVALID_HUMAN_READABLE_SUMMARY"],
  ] as const;
  for (const [field, code] of blankCases) {
    assert.throws(
      () =>
        buildSafetyKernelV31TransactionServiceInputFromCallerContext(
          { ...caller(), [field]: " \t\n" },
          gate("ALLOW")
        ),
      new RegExp(code)
    );
  }

  assert.equal(JSON.stringify(callerInput), callerBefore);
  assert.equal(JSON.stringify(actionQuality), actionQualityBefore);
});

test("transaction input builder rejects mutation scope mismatches", () => {
  const actionQuality = {
    ...gate("ALLOW"),
    source: "ai_connector" as const,
  };

  const matching = buildSafetyKernelV31TransactionServiceInputFromCallerContext(
    {
      ...caller(),
      target: " src/example.ts ",
      mutation_scope: {
        scope: "workspace",
        target: " src/example.ts ",
        protected_target: false,
      },
    },
    actionQuality
  );
  assert.deepEqual(matching.mutation_scope, {
    scope: "workspace",
    target: "src/example.ts",
    protected_target: false,
  });

  assert.throws(
    () =>
      buildSafetyKernelV31TransactionServiceInputFromCallerContext(
        {
          ...caller(),
          mutation_scope: {
            scope: "protected_file",
            target: "src/example.ts",
            protected_target: false,
          },
        },
        actionQuality
      ),
    /MUTATION_SCOPE_MISMATCH/
  );
  assert.throws(
    () =>
      buildSafetyKernelV31TransactionServiceInputFromCallerContext(
        {
          ...caller(),
          mutation_scope: {
            scope: "workspace",
            target: ".env",
            protected_target: false,
          },
        },
        actionQuality
      ),
    /MUTATION_SCOPE_MISMATCH/
  );
  assert.throws(
    () =>
      buildSafetyKernelV31TransactionServiceInputFromCallerContext(
        {
          ...caller(),
          mutation_scope: {
            scope: "workspace",
            target: "src/example.ts",
            protected_target: true,
          },
        },
        actionQuality
      ),
    /MUTATION_SCOPE_MISMATCH/
  );
  assert.throws(
    () =>
      buildSafetyKernelV31TransactionServiceInputFromCallerContext(
        {
          ...caller(),
          mutation_scope: {
            scope: "workspace",
            target: "   ",
            protected_target: false,
          },
        },
        actionQuality
      ),
    /INVALID_MUTATION_SCOPE_TARGET/
  );
});

test("transaction input builder isolates resolved defaults and preserves rejected inputs", () => {
  const firstCaller = caller();
  const firstActionQuality = {
    ...gate("ALLOW"),
    source: "ai_connector" as const,
  };
  const first = buildSafetyKernelV31TransactionServiceInputFromCallerContext(
    firstCaller,
    firstActionQuality
  );
  const second = buildSafetyKernelV31TransactionServiceInputFromCallerContext(
    firstCaller,
    firstActionQuality
  );

  assert.notEqual(first.capability_requested, second.capability_requested);
  assert.notEqual(first.mutation_scope, second.mutation_scope);

  Object.assign(
    first.capability_requested as {
      operation_class: string;
      scope: string;
      manner: string;
    },
    {
      operation_class: "read",
      scope: "protected_file",
      manner: "preview_only",
    }
  );
  Object.assign(
    first.mutation_scope as {
      scope: string;
      target: string;
      protected_target: boolean;
    },
    {
      scope: "protected_file",
      target: ".env",
      protected_target: true,
    }
  );

  const afterMutation = buildSafetyKernelV31TransactionServiceInputFromCallerContext(
    firstCaller,
    firstActionQuality
  );
  assert.deepEqual(afterMutation.capability_requested, {
    operation_class: "execute",
    scope: "workspace",
    manner: "requires_review",
  });
  assert.deepEqual(afterMutation.mutation_scope, {
    scope: "workspace",
    target: "src/example.ts",
    protected_target: false,
  });
  assert.deepEqual(second.capability_requested, afterMutation.capability_requested);
  assert.deepEqual(second.mutation_scope, afterMutation.mutation_scope);

  const rejectionCases = [
    {
      callerInput: caller(),
      actionQuality: {
        ...gate("ALLOW"),
        source: "external_gateway" as const,
      },
      code: /UNTRUSTED_ACTION_QUALITY_SOURCE/,
    },
    {
      callerInput: {
        ...caller(),
        capability_requested: {
          operation_class: "execute",
          scope: "workspace",
          manner: "requires_review",
        } as const,
      },
      actionQuality: gate("ALLOW"),
      code: /CAPABILITY_SOURCE_MISMATCH/,
    },
    {
      callerInput: {
        ...caller(),
        timestamp: "2026-02-30T00:00:00.000Z",
      },
      actionQuality: gate("ALLOW"),
      code: /INVALID_TIMESTAMP/,
    },
  ] as const;

  for (const rejectionCase of rejectionCases) {
    const callerBefore = JSON.stringify(rejectionCase.callerInput);
    const actionQualityBefore = JSON.stringify(rejectionCase.actionQuality);

    assert.throws(
      () =>
        buildSafetyKernelV31TransactionServiceInputFromCallerContext(
          rejectionCase.callerInput,
          rejectionCase.actionQuality
        ),
      rejectionCase.code
    );

    assert.equal(JSON.stringify(rejectionCase.callerInput), callerBefore);
    assert.equal(JSON.stringify(rejectionCase.actionQuality), actionQualityBefore);
  }
});
