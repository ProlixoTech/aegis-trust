import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  ABSOLUTE_SERVER_RULESET_JSON_BYTES,
  canonicalizeServerRulesetValue,
  type ServerRulesetTrustState,
  verifySignedServerRulesetPackageText,
} from "./serverRulesetTrustProvider";

const now =
  Date.parse(
    "2026-07-26T12:00:00.000Z"
  );

interface BuildOptions {
  readonly rootKeyPair?:
    crypto.KeyPairKeyObjectResult;
  readonly intermediateKeyPair?:
    crypto.KeyPairKeyObjectResult;
  readonly keyId?: string;
  readonly sequence?: number;
  readonly certificateNotBefore?: string;
  readonly certificateNotAfter?: string;
  readonly revoked?: boolean;
  readonly rulesetVersion?: number;
  readonly monotonicCounter?: number;
  readonly rulesetNotBefore?: string;
  readonly rulesetNotAfter?: string;
  readonly rules?: ReadonlyArray<{
    readonly ruleId: string;
    readonly category:
      | "catastrophic"
      | "destructive"
      | "secret-exposure"
      | "policy-bypass";
    readonly pattern: string;
  }>;
}

interface BuiltPackage {
  readonly rootKeyPair:
    crypto.KeyPairKeyObjectResult;
  readonly intermediateKeyPair:
    crypto.KeyPairKeyObjectResult;
  readonly rootPublicKeyPem: string;
  readonly packageValue:
    Record<string, unknown>;
  readonly text: string;
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

function cloneValue<T>(
  value: T
): T {
  return JSON.parse(
    JSON.stringify(value)
  ) as T;
}

function signEd25519(
  value: unknown,
  privateKey: crypto.KeyObject
): string {
  return crypto
    .sign(
      null,
      Buffer.from(
        canonicalizeServerRulesetValue(
          value
        ),
        "utf8"
      ),
      privateKey
    )
    .toString("base64");
}

function buildPackage(
  options: BuildOptions = {}
): BuiltPackage {
  const rootKeyPair =
    options.rootKeyPair ??
    crypto.generateKeyPairSync(
      "ed25519"
    );

  const intermediateKeyPair =
    options.intermediateKeyPair ??
    crypto.generateKeyPairSync(
      "ed25519"
    );

  const intermediatePublicKeyPem =
    publicKeyPem(
      intermediateKeyPair.publicKey
    );

  const certificatePayload = {
    schemaVersion: 1,
    keyId:
      options.keyId ??
      "intermediate-v1",
    sequence:
      options.sequence ?? 1,
    notBefore:
      options.certificateNotBefore ??
      "2026-07-01T00:00:00.000Z",
    notAfter:
      options.certificateNotAfter ??
      "2026-08-31T00:00:00.000Z",
    revoked:
      options.revoked ?? false,
    publicKeyPem:
      intermediatePublicKeyPem,
  };

  const certificate = {
    ...certificatePayload,
    signature:
      signEd25519(
        certificatePayload,
        rootKeyPair.privateKey
      ),
  };

  const ruleset = {
    schemaVersion: 1,
    rulesetId:
      "server-ruleset-v" +
      String(
        options.rulesetVersion ?? 1
      ),
    rulesetVersion:
      options.rulesetVersion ?? 1,
    monotonicCounter:
      options.monotonicCounter ?? 1,
    notBefore:
      options.rulesetNotBefore ??
      "2026-07-01T00:00:00.000Z",
    notAfter:
      options.rulesetNotAfter ??
      "2026-08-31T00:00:00.000Z",
    rules:
      options.rules ?? [
        {
          ruleId:
            "block-publish-secret",
          category:
            "secret-exposure" as const,
          pattern:
            "publish-secret",
        },
      ],
  };

  const packageValue:
    Record<string, unknown> = {
      schemaVersion: 1,
      intermediateCertificate:
        certificate,
      ruleset,
      rulesetSignature:
        intermediateKeyPair
          .privateKey
          .asymmetricKeyType ===
        "ed25519"
          ? signEd25519(
              ruleset,
              intermediateKeyPair
                .privateKey
            )
          : Buffer.alloc(64)
              .toString("base64"),
    };

  return {
    rootKeyPair,
    intermediateKeyPair,
    rootPublicKeyPem:
      publicKeyPem(
        rootKeyPair.publicKey
      ),
    packageValue,
    text:
      JSON.stringify(
        packageValue
      ),
  };
}

function verify(
  built: BuiltPackage,
  activeState:
    ServerRulesetTrustState | null = null
) {
  return verifySignedServerRulesetPackageText(
    built.text,
    {
      pinnedRootPublicKeyPem:
        built.rootPublicKeyPem,
      activeState,
      nowEpochMs: now,
    }
  );
}

test("valid pinned root intermediate and ruleset chain is accepted", () => {
  const built = buildPackage();
  const result = verify(built);

  assert.equal(result.accepted, true);
  assert.equal(result.error, null);
  assert.equal(
    result.ruleset?.rulesetVersion,
    1
  );
  assert.equal(
    result.nextState
      ?.highestIntermediateSequence,
    1
  );
});

test("tampered root signature is rejected", () => {
  const built = buildPackage();
  const mutated =
    cloneValue(built.packageValue);

  const certificate =
    mutated.intermediateCertificate as
      Record<string, unknown>;

  certificate.signature =
    Buffer.alloc(64, 7)
      .toString("base64");

  const result =
    verifySignedServerRulesetPackageText(
      JSON.stringify(mutated),
      {
        pinnedRootPublicKeyPem:
          built.rootPublicKeyPem,
        activeState: null,
        nowEpochMs: now,
      }
    );

  assert.equal(result.accepted, false);
  assert.equal(
    result.error,
    "INTERMEDIATE_CERTIFICATE_ROOT_SIGNATURE_INVALID"
  );
});

test("tampered ruleset signature is rejected", () => {
  const built = buildPackage();
  const mutated =
    cloneValue(built.packageValue);

  mutated.rulesetSignature =
    Buffer.alloc(64, 9)
      .toString("base64");

  const result =
    verifySignedServerRulesetPackageText(
      JSON.stringify(mutated),
      {
        pinnedRootPublicKeyPem:
          built.rootPublicKeyPem,
        activeState: null,
        nowEpochMs: now,
      }
    );

  assert.equal(result.accepted, false);
  assert.equal(
    result.error,
    "SERVER_RULESET_SIGNATURE_INVALID"
  );
});

test("non Ed25519 intermediate key is rejected", () => {
  const rootKeyPair =
    crypto.generateKeyPairSync(
      "ed25519"
    );

  const ecKeyPair =
    crypto.generateKeyPairSync(
      "ec",
      {
        namedCurve: "prime256v1",
      }
    );

  const built = buildPackage({
    rootKeyPair,
    intermediateKeyPair:
      ecKeyPair,
  });

  assert.equal(
    verify(built).error,
    "INVALID_INTERMEDIATE_PUBLIC_KEY"
  );
});

test("not yet valid intermediate certificate is rejected", () => {
  const built = buildPackage({
    certificateNotBefore:
      "2026-07-27T00:00:00.000Z",
  });

  assert.equal(
    verify(built).error,
    "INTERMEDIATE_CERTIFICATE_NOT_YET_VALID"
  );
});

test("expired intermediate certificate is rejected", () => {
  const built = buildPackage({
    certificateNotAfter:
      "2026-07-26T11:59:59.000Z",
  });

  assert.equal(
    verify(built).error,
    "INTERMEDIATE_CERTIFICATE_EXPIRED"
  );
});

test("revoked intermediate certificate is rejected", () => {
  const built = buildPackage({
    revoked: true,
  });

  assert.equal(
    verify(built).error,
    "INTERMEDIATE_CERTIFICATE_REVOKED"
  );
});

test("intermediate sequence rollback is rejected", () => {
  const activePackage =
    buildPackage({
      sequence: 2,
      rulesetVersion: 2,
      monotonicCounter: 2,
    });

  const activeResult =
    verify(activePackage);

  assert.equal(
    activeResult.accepted,
    true
  );

  const candidate =
    buildPackage({
      rootKeyPair:
        activePackage.rootKeyPair,
      sequence: 1,
      rulesetVersion: 3,
      monotonicCounter: 3,
    });

  assert.equal(
    verify(
      candidate,
      activeResult.nextState
    ).error,
    "INTERMEDIATE_KEY_SEQUENCE_ROLLBACK"
  );
});

test("same intermediate sequence with another key is rejected as rebound", () => {
  const activePackage =
    buildPackage({
      sequence: 4,
      rulesetVersion: 4,
      monotonicCounter: 4,
    });

  const activeResult =
    verify(activePackage);

  assert.equal(
    activeResult.accepted,
    true
  );

  const rebound =
    buildPackage({
      rootKeyPair:
        activePackage.rootKeyPair,
      sequence: 4,
      rulesetVersion: 5,
      monotonicCounter: 5,
    });

  assert.equal(
    verify(
      rebound,
      activeResult.nextState
    ).error,
    "INTERMEDIATE_KEY_SEQUENCE_REBOUND"
  );
});

test("ruleset version rollback is rejected by semantic validation", () => {
  const activePackage =
    buildPackage({
      sequence: 2,
      rulesetVersion: 5,
      monotonicCounter: 10,
    });

  const activeResult =
    verify(activePackage);

  const candidate =
    buildPackage({
      rootKeyPair:
        activePackage.rootKeyPair,
      sequence: 3,
      rulesetVersion: 4,
      monotonicCounter: 11,
    });

  const result =
    verify(
      candidate,
      activeResult.nextState
    );

  assert.equal(
    result.accepted,
    false
  );

  assert.match(
    String(result.error),
    /rulesetVersion/
  );
});

test("ruleset monotonic counter rollback is rejected", () => {
  const activePackage =
    buildPackage({
      sequence: 2,
      rulesetVersion: 5,
      monotonicCounter: 10,
    });

  const activeResult =
    verify(activePackage);

  const candidate =
    buildPackage({
      rootKeyPair:
        activePackage.rootKeyPair,
      sequence: 3,
      rulesetVersion: 6,
      monotonicCounter: 9,
    });

  const result =
    verify(
      candidate,
      activeResult.nextState
    );

  assert.equal(
    result.accepted,
    false
  );

  assert.match(
    String(result.error),
    /monotonicCounter/
  );
});

test("unsafe downloaded regex rejects the entire candidate", () => {
  const built = buildPackage({
    rules: [
      {
        ruleId:
          "unsafe-pattern",
        category:
          "policy-bypass",
        pattern:
          ".*secret",
      },
    ],
  });

  assert.equal(
    verify(built).error,
    "UNSAFE_SERVER_RULESET_PATTERN=UNSAFE_DOT_REPETITION"
  );
});

test("unknown executable field violates exact key data only schema", () => {
  const built = buildPackage();
  const mutated =
    cloneValue(built.packageValue);

  const ruleset =
    mutated.ruleset as
      Record<string, unknown>;

  ruleset.execute =
    "require('node:child_process')";

  const result =
    verifySignedServerRulesetPackageText(
      JSON.stringify(mutated),
      {
        pinnedRootPublicKeyPem:
          built.rootPublicKeyPem,
        activeState: null,
        nowEpochMs: now,
      }
    );

  assert.equal(
    result.error,
    "INVALID_SERVER_RULESET_PAYLOAD"
  );
});

test("duplicate rule identifiers are rejected", () => {
  const built = buildPackage({
    rules: [
      {
        ruleId: "duplicate",
        category: "destructive",
        pattern: "first",
      },
      {
        ruleId: "duplicate",
        category: "policy-bypass",
        pattern: "second",
      },
    ],
  });

  assert.equal(
    verify(built).error,
    "DUPLICATE_SERVER_RULESET_RULE_ID"
  );
});

test("strict Base64 rejects malformed certificate signatures", () => {
  const built = buildPackage();
  const mutated =
    cloneValue(built.packageValue);

  const certificate =
    mutated.intermediateCertificate as
      Record<string, unknown>;

  certificate.signature =
    "not-base64";

  const result =
    verifySignedServerRulesetPackageText(
      JSON.stringify(mutated),
      {
        pinnedRootPublicKeyPem:
          built.rootPublicKeyPem,
        activeState: null,
        nowEpochMs: now,
      }
    );

  assert.equal(
    result.error,
    "INVALID_INTERMEDIATE_CERTIFICATE_SIGNATURE"
  );
});

test("JSON size limits enforce configured and absolute bounds", () => {
  const built = buildPackage();

  const configured =
    verifySignedServerRulesetPackageText(
      built.text,
      {
        pinnedRootPublicKeyPem:
          built.rootPublicKeyPem,
        activeState: null,
        nowEpochMs: now,
        maximumJsonBytes: 32,
      }
    );

  assert.equal(
    configured.error,
    "SERVER_RULESET_JSON_TOO_LARGE"
  );

  const absolute =
    verifySignedServerRulesetPackageText(
      built.text,
      {
        pinnedRootPublicKeyPem:
          built.rootPublicKeyPem,
        activeState: null,
        nowEpochMs: now,
        maximumJsonBytes:
          ABSOLUTE_SERVER_RULESET_JSON_BYTES +
          1,
      }
    );

  assert.equal(
    absolute.error,
    "MAXIMUM_JSON_BYTES_EXCEEDS_ABSOLUTE_LIMIT"
  );
});

test("canonicalization is deterministic across object key order", () => {
  const first = {
    z: [
      {
        b: true,
        a: 1,
      },
    ],
    a: "value",
  };

  const second = {
    a: "value",
    z: [
      {
        a: 1,
        b: true,
      },
    ],
  };

  assert.equal(
    canonicalizeServerRulesetValue(
      first
    ),
    canonicalizeServerRulesetValue(
      second
    )
  );
});

test("production and test sources contain no embedded private key PEM", () => {
  const productionSource =
    fs.readFileSync(
      path.join(
        process.cwd(),
        "src",
        "serverRulesetTrustProvider.ts"
      ),
      "utf8"
    );

  const testSource =
    fs.readFileSync(
      path.join(
        process.cwd(),
        "src",
        "serverRulesetTrustProvider.test.ts"
      ),
      "utf8"
    );

  const privateKeyPemMarker =
    "BEGIN " + "PRIVATE KEY";

  assert.equal(
    productionSource.includes(
      privateKeyPemMarker
    ),
    false
  );

  assert.equal(
    testSource.includes(
      privateKeyPemMarker
    ),
    false
  );

  assert.equal(
    productionSource.includes(
      "node:http"
    ),
    false
  );

  assert.equal(
    productionSource.includes(
      "node:https"
    ),
    false
  );
});
