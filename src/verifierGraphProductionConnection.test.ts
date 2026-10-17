import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";

function readExtensionSource(): string {
  return fs.readFileSync(
    path.join(
      process.cwd(),
      "src",
      "extension.ts"
    ),
    "utf8"
  );
}

function getExplicitExecutionBlock(
  extensionSource: string
): string {
  const startMarker =
    "// A2U CONTRACT A PRODUCT ENTRY CONNECTION START";

  const endMarker =
    "// A2U CONTRACT A PRODUCT ENTRY CONNECTION END";

  const start =
    extensionSource.indexOf(startMarker);

  const end =
    extensionSource.indexOf(
      endMarker,
      start
    );

  assert.ok(start >= 0);
  assert.ok(end > start);

  return extensionSource.slice(
    start,
    end + endMarker.length
  );
}

test(
  "C08 production connection imports the guard and declares the actual verifier graph",
  () => {
    const source =
      readExtensionSource();

    assert.match(
      source,
      /import\s*\{\s*VerifierRecursionGuard,\s*verifyVerifierGraphAcyclic,\s*\}\s*from\s*"\.\.\/packages\/aegis-core";/
    );

    assert.ok(
      source.includes(
        "VerifierRecursionGuard"
      )
    );

    assert.ok(
      source.includes(
        "verifyVerifierGraphAcyclic"
      )
    );

    assert.ok(
      source.includes(
        "const AEGIS_FINAL_PRODUCT_VERIFIER_GRAPH"
      )
    );

    for (const verifierId of [
      "explicit-execution-entry",
      "session-handoff-production-verification",
      "session-handoff-local-verification-adapter",
      "authority-snapshot-binding-verifier",
      "trusted-signature-verifier",
      "persistent-sequence-store",
      "receipt-ledger-binding-verifier",
      "session-handoff-runtime-gate",
    ]) {
      assert.ok(
        source.includes(
          `id: "${verifierId}"`
        ),
        verifierId
      );
    }
  }
);

test(
  "C08 graph verification precedes guarded production evaluation binding and coordination",
  () => {
    const block =
      getExplicitExecutionBlock(
        readExtensionSource()
      );

    const graphIndex =
      block.indexOf(
        "verifyVerifierGraphAcyclic("
      );

    const guardRunIndex =
      block.indexOf(
        "recursionGuard.run("
      );

    const evaluateIndex =
      block.indexOf(
        "productionComposition.evaluate({"
      );

    const readyIndex =
      block.indexOf(
        "const executionConnectionReady"
      );

    const bindIndex =
      block.indexOf(
        ".bindAllowedExecutionSessionAuthority("
      );

    const coordinateIndex =
      block.indexOf(
        ".coordinateAllowedExecutionSession("
      );

    assert.ok(graphIndex >= 0);
    assert.ok(guardRunIndex > graphIndex);
    assert.ok(evaluateIndex > guardRunIndex);
    assert.ok(readyIndex > evaluateIndex);
    assert.ok(bindIndex > readyIndex);
    assert.ok(coordinateIndex > bindIndex);
  }
);

test(
  "C08 recursion guard wraps production evaluation using a fixed verifier identity",
  () => {
    const block =
      getExplicitExecutionBlock(
        readExtensionSource()
      );

    const resultDeclarationIndex =
      block.indexOf(
        "const guardedSessionHandoffResult"
      );

    const guardRunIndex =
      block.indexOf(
        "await recursionGuard.run(",
        resultDeclarationIndex
      );

    const verifierIdentityIndex =
      block.indexOf(
        '"session-handoff-production-verification"',
        guardRunIndex
      );

    const callbackIndex =
      block.indexOf(
        "() =>",
        verifierIdentityIndex
      );

    const evaluateIndex =
      block.indexOf(
        "productionComposition.evaluate({",
        callbackIndex
      );

    const failureBranchIndex =
      block.indexOf(
        "if (!guardedSessionHandoffResult.ok)",
        evaluateIndex
      );

    const issueCodesIndex =
      block.indexOf(
        ".issueCodes",
        failureBranchIndex
      );

    const joinIndex =
      block.indexOf(
        '.join(",")',
        issueCodesIndex
      );

    assert.ok(resultDeclarationIndex >= 0);
    assert.ok(guardRunIndex > resultDeclarationIndex);
    assert.ok(verifierIdentityIndex > guardRunIndex);
    assert.ok(callbackIndex > verifierIdentityIndex);
    assert.ok(evaluateIndex > callbackIndex);
    assert.ok(failureBranchIndex > evaluateIndex);
    assert.ok(issueCodesIndex > failureBranchIndex);
    assert.ok(joinIndex > issueCodesIndex);
  }
);

test(
  "C08 guard failure remains fail closed before bind and coordinate",
  () => {
    const block =
      getExplicitExecutionBlock(
        readExtensionSource()
      );

    const failureIndex =
      block.indexOf(
        "if (!guardedSessionHandoffResult.ok)"
      );

    const readyIndex =
      block.indexOf(
        "const executionConnectionReady"
      );

    const executionGateIndex =
      block.indexOf(
        "if (executionConnectionReady)"
      );

    const bindIndex =
      block.indexOf(
        ".bindAllowedExecutionSessionAuthority("
      );

    const coordinateIndex =
      block.indexOf(
        ".coordinateAllowedExecutionSession("
      );

    assert.ok(failureIndex >= 0);
    assert.ok(readyIndex > failureIndex);
    assert.ok(executionGateIndex > readyIndex);
    assert.ok(bindIndex > executionGateIndex);
    assert.ok(coordinateIndex > bindIndex);
  }
);

test(
  "C08 execution readiness requires graph verification recursion guard and authorization",
  () => {
    const block =
      getExplicitExecutionBlock(
        readExtensionSource()
      );

    const readyStart =
      block.indexOf(
        "const executionConnectionReady"
      );

    const readyEnd =
      block.indexOf(
        "let executionStatus",
        readyStart
      );

    assert.ok(readyStart >= 0);
    assert.ok(readyEnd > readyStart);

    const readiness =
      block.slice(
        readyStart,
        readyEnd
      );

    assert.ok(
      readiness.includes(
        "executionConnectionPreconditionsReady"
      )
    );

    assert.ok(
      readiness.includes(
        "verifierGraphVerified"
      )
    );

    assert.ok(
      readiness.includes(
        "verifierRecursionGuardPassed"
      )
    );

    assert.ok(
      readiness.includes(
        "sessionHandoffAuthorized"
      )
    );

    assert.equal(
      block.includes(
        "callerVerifierGraphVerified"
      ),
      false
    );

    assert.equal(
      block.includes(
        "callerRecursionGuardPassed"
      ),
      false
    );
  }
);

test(
  "C08 guard lifecycle and result evidence are connected",
  () => {
    const source =
      readExtensionSource();

    const block =
      getExplicitExecutionBlock(source);

    assert.ok(
      source.includes(
        "let _verifierRecursionGuard: VerifierRecursionGuard | null = null;"
      )
    );

    assert.ok(
      source.includes(
        "_verifierRecursionGuard ="
      )
    );

    assert.ok(
      source.includes(
        "new VerifierRecursionGuard();"
      )
    );

    const deactivateStart =
      source.indexOf(
        "export async function deactivate(): Promise<void> {"
      );

    assert.ok(deactivateStart >= 0);

    const deactivateBodyStart =
      source.indexOf(
        "{",
        deactivateStart
      );

    assert.ok(deactivateBodyStart >= 0);

    let deactivateBraceDepth = 0;
    let deactivateEnd = -1;

    for (
      let sourceIndex = deactivateBodyStart;
      sourceIndex < source.length;
      sourceIndex += 1
    ) {
      const sourceCharacter =
        source[sourceIndex];

      if (sourceCharacter === "{") {
        deactivateBraceDepth += 1;
      } else if (sourceCharacter === "}") {
        deactivateBraceDepth -= 1;

        if (deactivateBraceDepth === 0) {
          deactivateEnd = sourceIndex + 1;
          break;
        }
      }
    }

    assert.ok(deactivateEnd > deactivateStart);

    const deactivateBlock =
      source.slice(
        deactivateStart,
        deactivateEnd
      );

    assert.ok(
      deactivateBlock.includes(
        "_verifierRecursionGuard = null;"
      )
    );

    for (const marker of [
      "verifier_graph_verified=",
      "verifier_graph_issue_codes=",
      "verifier_graph_cycle_path=",
      "verifier_recursion_guard_passed=",
      "verifier_recursion_guard_issue_codes=",
    ]) {
      assert.ok(
        block.includes(marker),
        marker
      );
    }
  }
);