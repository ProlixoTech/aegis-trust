import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  compileServerRulesetSafeRegex,
  matchServerRulesetSafeRegex,
  MAX_SERVER_RULESET_INPUT_BYTES,
  MAX_SERVER_RULESET_PATTERN_LENGTH,
} from "./serverRulesetSafeRegex";

test("safe regex matches literal substrings without host RegExp execution", () => {
  assert.equal(
    matchServerRulesetSafeRegex(
      "publish-secret",
      "please publish-secret now"
    ).matched,
    true
  );

  assert.equal(
    matchServerRulesetSafeRegex(
      "publish-secret",
      "publish public metadata"
    ).matched,
    false
  );
});

test("safe regex enforces start and end anchors", () => {
  assert.equal(
    matchServerRulesetSafeRegex(
      "^git reset --hard$",
      "git reset --hard"
    ).matched,
    true
  );

  assert.equal(
    matchServerRulesetSafeRegex(
      "^git reset --hard$",
      "sudo git reset --hard"
    ).matched,
    false
  );
});

test("safe regex supports classes ranges and atom quantifiers", () => {
  assert.equal(
    matchServerRulesetSafeRegex(
      "^ab[c-e]+f?$",
      "abcddef"
    ).matched,
    true
  );

  assert.equal(
    matchServerRulesetSafeRegex(
      "^ab[^0-9]?z$",
      "abXz"
    ).matched,
    true
  );

  assert.equal(
    matchServerRulesetSafeRegex(
      "^ab[c-e]*z$",
      "abz"
    ).matched,
    true
  );
});

test("safe regex preserves escaped metacharacters and control escapes", () => {
  assert.equal(
    matchServerRulesetSafeRegex(
      "file\\.txt\\?",
      "inspect file.txt?"
    ).matched,
    true
  );

  assert.equal(
    matchServerRulesetSafeRegex(
      "^line\\nend$",
      "line\nend"
    ).matched,
    true
  );
});

test("safe regex rejects unsupported and dangerous constructs", () => {
  const patterns = [
    "(a+)+",
    "a|b",
    "a{1,3}",
    "\\1",
    "(?<=x)y",
    ".*secret",
    "a**",
    "^a$b",
    "\\d+",
  ];

  for (const pattern of patterns) {
    assert.equal(
      compileServerRulesetSafeRegex(pattern).accepted,
      false,
      pattern
    );
  }
});

test("safe regex rejects invalid character classes and ranges", () => {
  for (const pattern of ["[]", "[abc", "[z-a]", "[[a]"]) {
    assert.equal(
      compileServerRulesetSafeRegex(pattern).accepted,
      false,
      pattern
    );
  }
});

test("safe regex enforces pattern and UTF-8 input size limits", () => {
  assert.equal(
    compileServerRulesetSafeRegex(
      "a".repeat(
        MAX_SERVER_RULESET_PATTERN_LENGTH + 1
      )
    ).error,
    "PATTERN_TOO_LONG"
  );

  assert.equal(
    matchServerRulesetSafeRegex(
      "a",
      "x".repeat(
        MAX_SERVER_RULESET_INPUT_BYTES + 1
      )
    ).error,
    "INPUT_TOO_LARGE"
  );
});

test("safe regex fails closed when deterministic operation budget is insufficient", () => {
  const result = matchServerRulesetSafeRegex(
    "a+b+c+",
    "a".repeat(100) +
      "b".repeat(100) +
      "c".repeat(100),
    {
      operationBudget: 10,
      wallClockFuseMs: 1000,
    }
  );

  assert.equal(result.accepted, false);
  assert.equal(
    result.error,
    "OPERATION_BUDGET_EXCEEDED"
  );
});

test("safe regex fails closed for an invalid wall clock fuse", () => {
  const result = matchServerRulesetSafeRegex(
    "secret",
    "secret",
    {
      wallClockFuseMs: 0,
    }
  );

  assert.equal(result.accepted, false);
  assert.equal(
    result.error,
    "WALL_CLOCK_FUSE_EXCEEDED"
  );
});

test("safe regex source contains no dynamic host RegExp execution", () => {
  const sourcePath = path.join(
    process.cwd(),
    "src",
    "serverRulesetSafeRegex.ts"
  );

  const source = fs.readFileSync(
    sourcePath,
    "utf8"
  );

  assert.equal(
    source.includes("new RegExp"),
    false
  );

  assert.equal(
    source.includes("RegExp("),
    false
  );
});
