export const MAX_SERVER_RULESET_PATTERN_LENGTH = 512;
export const MAX_SERVER_RULESET_INPUT_BYTES = 16384;
export const MAX_SERVER_RULESET_RULE_OPERATIONS = 20000000;
export const MAX_SERVER_RULESET_RULE_WALL_CLOCK_MS = 25;

export type ServerRulesetSafeRegexError =
  | "EMPTY_PATTERN"
  | "PATTERN_TOO_LONG"
  | "INPUT_TOO_LARGE"
  | "UNSUPPORTED_GROUPING"
  | "UNSUPPORTED_ALTERNATION"
  | "UNSUPPORTED_BRACE_QUANTIFIER"
  | "UNSUPPORTED_BACKREFERENCE"
  | "UNSUPPORTED_ANCHOR_POSITION"
  | "UNSUPPORTED_ESCAPE"
  | "INVALID_ESCAPE"
  | "INVALID_CHARACTER_CLASS"
  | "INVALID_CHARACTER_RANGE"
  | "QUANTIFIER_WITHOUT_ATOM"
  | "NESTED_QUANTIFIER"
  | "UNSAFE_DOT_REPETITION"
  | "OPERATION_BUDGET_EXCEEDED"
  | "WALL_CLOCK_FUSE_EXCEEDED";

export interface ServerRulesetSafeRegexCompileResult {
  readonly accepted: boolean;
  readonly error: ServerRulesetSafeRegexError | null;
  readonly tokenCount: number;
}

export interface ServerRulesetSafeRegexMatchOptions {
  readonly operationBudget?: number;
  readonly wallClockFuseMs?: number;
}

export interface ServerRulesetSafeRegexMatchResult {
  readonly accepted: boolean;
  readonly matched: boolean;
  readonly error: ServerRulesetSafeRegexError | null;
  readonly operations: number;
}

type Quantifier =
  | "ONE"
  | "OPTIONAL"
  | "ZERO_OR_MORE";

interface CharacterRange {
  readonly first: number;
  readonly last: number;
}

type Atom =
  | {
      readonly kind: "LITERAL";
      readonly value: string;
    }
  | {
      readonly kind: "ANY";
    }
  | {
      readonly kind: "CLASS";
      readonly negated: boolean;
      readonly ranges: readonly CharacterRange[];
    };

interface Token {
  readonly atom: Atom;
  readonly quantifier: Quantifier;
}

interface Program {
  readonly anchoredStart: boolean;
  readonly anchoredEnd: boolean;
  readonly tokens: readonly Token[];
}

interface InternalCompileResult {
  readonly accepted: boolean;
  readonly error: ServerRulesetSafeRegexError | null;
  readonly program: Program | null;
}

interface CharacterClassItem {
  readonly value: string;
  readonly escaped: boolean;
}

const ESCAPABLE_LITERAL_CHARACTERS =
  new Set<string>([
    "\\",
    ".",
    "^",
    "$",
    "*",
    "+",
    "?",
    "[",
    "]",
    "(",
    ")",
    "{",
    "}",
    "|",
    "-",
  ]);

function isEscapedAt(
  characters: readonly string[],
  index: number
): boolean {
  let slashCount = 0;

  for (
    let cursor = index - 1;
    cursor >= 0 && characters[cursor] === "\\";
    cursor--
  ) {
    slashCount++;
  }

  return slashCount % 2 === 1;
}

function codePoint(value: string): number {
  const result = value.codePointAt(0);
  return result === undefined ? -1 : result;
}

function decodeEscape(
  value: string
): string | null {
  if (value === "n") {
    return "\n";
  }

  if (value === "r") {
    return "\r";
  }

  if (value === "t") {
    return "\t";
  }

  return ESCAPABLE_LITERAL_CHARACTERS.has(value)
    ? value
    : null;
}

function parseCharacterClass(
  characters: readonly string[],
  start: number
): {
  readonly atom: Atom | null;
  readonly next: number;
  readonly error: ServerRulesetSafeRegexError | null;
} {
  let cursor = start + 1;
  let negated = false;

  if (
    cursor < characters.length &&
    characters[cursor] === "^"
  ) {
    negated = true;
    cursor++;
  }

  const items: CharacterClassItem[] = [];
  let closed = false;

  while (cursor < characters.length) {
    const current = characters[cursor];

    if (current === "]" && items.length > 0) {
      closed = true;
      cursor++;
      break;
    }

    if (current === "\\") {
      if (cursor + 1 >= characters.length) {
        return {
          atom: null,
          next: cursor,
          error: "INVALID_ESCAPE",
        };
      }

      const escapedSource = characters[cursor + 1];

      if (
        escapedSource >= "0" &&
        escapedSource <= "9"
      ) {
        return {
          atom: null,
          next: cursor,
          error: "UNSUPPORTED_BACKREFERENCE",
        };
      }

      const decoded = decodeEscape(escapedSource);

      if (decoded === null) {
        return {
          atom: null,
          next: cursor,
          error: "UNSUPPORTED_ESCAPE",
        };
      }

      items.push({
        value: decoded,
        escaped: true,
      });

      cursor += 2;
      continue;
    }

    if (current === "[") {
      return {
        atom: null,
        next: cursor,
        error: "INVALID_CHARACTER_CLASS",
      };
    }

    items.push({
      value: current,
      escaped: false,
    });

    cursor++;
  }

  if (!closed || items.length === 0) {
    return {
      atom: null,
      next: cursor,
      error: "INVALID_CHARACTER_CLASS",
    };
  }

  const ranges: CharacterRange[] = [];

  for (let index = 0; index < items.length;) {
    if (
      index + 2 < items.length &&
      items[index + 1].value === "-" &&
      !items[index + 1].escaped
    ) {
      const first = codePoint(items[index].value);
      const last = codePoint(items[index + 2].value);

      if (first < 0 || last < 0 || first > last) {
        return {
          atom: null,
          next: cursor,
          error: "INVALID_CHARACTER_RANGE",
        };
      }

      ranges.push({ first, last });
      index += 3;
      continue;
    }

    const value = codePoint(items[index].value);

    if (value < 0) {
      return {
        atom: null,
        next: cursor,
        error: "INVALID_CHARACTER_CLASS",
      };
    }

    ranges.push({
      first: value,
      last: value,
    });

    index++;
  }

  return {
    atom: Object.freeze({
      kind: "CLASS" as const,
      negated,
      ranges: Object.freeze(
        ranges.map(range =>
          Object.freeze({ ...range })
        )
      ),
    }),
    next: cursor,
    error: null,
  };
}

function compileInternal(
  pattern: string
): InternalCompileResult {
  if (
    typeof pattern !== "string" ||
    pattern.length === 0
  ) {
    return {
      accepted: false,
      error: "EMPTY_PATTERN",
      program: null,
    };
  }

  const characters = Array.from(pattern);

  if (
    characters.length >
    MAX_SERVER_RULESET_PATTERN_LENGTH
  ) {
    return {
      accepted: false,
      error: "PATTERN_TOO_LONG",
      program: null,
    };
  }

  let anchoredStart = false;
  let anchoredEnd = false;

  if (characters[0] === "^") {
    anchoredStart = true;
    characters.shift();
  }

  if (
    characters.length > 0 &&
    characters[characters.length - 1] === "$" &&
    !isEscapedAt(
      characters,
      characters.length - 1
    )
  ) {
    anchoredEnd = true;
    characters.pop();
  }

  if (characters.length === 0) {
    return {
      accepted: false,
      error: "EMPTY_PATTERN",
      program: null,
    };
  }

  const tokens: Token[] = [];

  for (let cursor = 0; cursor < characters.length;) {
    const current = characters[cursor];
    let atom: Atom;

    if (current === "\\") {
      if (cursor + 1 >= characters.length) {
        return {
          accepted: false,
          error: "INVALID_ESCAPE",
          program: null,
        };
      }

      const escapedSource = characters[cursor + 1];

      if (
        escapedSource >= "0" &&
        escapedSource <= "9"
      ) {
        return {
          accepted: false,
          error: "UNSUPPORTED_BACKREFERENCE",
          program: null,
        };
      }

      const decoded = decodeEscape(escapedSource);

      if (decoded === null) {
        return {
          accepted: false,
          error: "UNSUPPORTED_ESCAPE",
          program: null,
        };
      }

      atom = {
        kind: "LITERAL",
        value: decoded,
      };

      cursor += 2;
    } else if (current === "[") {
      const parsed = parseCharacterClass(
        characters,
        cursor
      );

      if (
        parsed.error !== null ||
        parsed.atom === null
      ) {
        return {
          accepted: false,
          error:
            parsed.error ??
            "INVALID_CHARACTER_CLASS",
          program: null,
        };
      }

      atom = parsed.atom;
      cursor = parsed.next;
    } else if (current === ".") {
      atom = { kind: "ANY" };
      cursor++;
    } else if (
      current === "(" ||
      current === ")"
    ) {
      return {
        accepted: false,
        error: "UNSUPPORTED_GROUPING",
        program: null,
      };
    } else if (current === "|") {
      return {
        accepted: false,
        error: "UNSUPPORTED_ALTERNATION",
        program: null,
      };
    } else if (
      current === "{" ||
      current === "}"
    ) {
      return {
        accepted: false,
        error: "UNSUPPORTED_BRACE_QUANTIFIER",
        program: null,
      };
    } else if (
      current === "^" ||
      current === "$"
    ) {
      return {
        accepted: false,
        error: "UNSUPPORTED_ANCHOR_POSITION",
        program: null,
      };
    } else if (
      current === "*" ||
      current === "+" ||
      current === "?"
    ) {
      return {
        accepted: false,
        error: "QUANTIFIER_WITHOUT_ATOM",
        program: null,
      };
    } else {
      atom = {
        kind: "LITERAL",
        value: current,
      };
      cursor++;
    }

    let quantifier: Quantifier = "ONE";

    if (cursor < characters.length) {
      const candidate = characters[cursor];

      if (
        candidate === "*" ||
        candidate === "+" ||
        candidate === "?"
      ) {
        cursor++;

        if (
          cursor < characters.length &&
          (
            characters[cursor] === "*" ||
            characters[cursor] === "+" ||
            characters[cursor] === "?"
          )
        ) {
          return {
            accepted: false,
            error: "NESTED_QUANTIFIER",
            program: null,
          };
        }

        if (
          atom.kind === "ANY" &&
          (candidate === "*" || candidate === "+")
        ) {
          return {
            accepted: false,
            error: "UNSAFE_DOT_REPETITION",
            program: null,
          };
        }

        if (candidate === "?") {
          quantifier = "OPTIONAL";
        } else if (candidate === "*") {
          quantifier = "ZERO_OR_MORE";
        } else {
          tokens.push(
            Object.freeze({
              atom,
              quantifier: "ONE" as const,
            })
          );

          tokens.push(
            Object.freeze({
              atom,
              quantifier: "ZERO_OR_MORE" as const,
            })
          );

          continue;
        }
      }
    }

    tokens.push(
      Object.freeze({
        atom,
        quantifier,
      })
    );
  }

  return {
    accepted: true,
    error: null,
    program: Object.freeze({
      anchoredStart,
      anchoredEnd,
      tokens: Object.freeze(tokens),
    }),
  };
}

function atomMatches(
  atom: Atom,
  value: string
): boolean {
  if (atom.kind === "LITERAL") {
    return value === atom.value;
  }

  if (atom.kind === "ANY") {
    return value !== "\n" && value !== "\r";
  }

  const valueCodePoint = codePoint(value);
  const included = atom.ranges.some(
    range =>
      valueCodePoint >= range.first &&
      valueCodePoint <= range.last
  );

  return atom.negated ? !included : included;
}

export function compileServerRulesetSafeRegex(
  pattern: string
): ServerRulesetSafeRegexCompileResult {
  const compiled = compileInternal(pattern);

  return {
    accepted: compiled.accepted,
    error: compiled.error,
    tokenCount:
      compiled.program?.tokens.length ?? 0,
  };
}

export function matchServerRulesetSafeRegex(
  pattern: string,
  input: string,
  options: ServerRulesetSafeRegexMatchOptions = {}
): ServerRulesetSafeRegexMatchResult {
  const compiled = compileInternal(pattern);

  if (
    !compiled.accepted ||
    compiled.program === null
  ) {
    return {
      accepted: false,
      matched: false,
      error: compiled.error ?? "EMPTY_PATTERN",
      operations: 0,
    };
  }

  if (
    Buffer.byteLength(input, "utf8") >
    MAX_SERVER_RULESET_INPUT_BYTES
  ) {
    return {
      accepted: false,
      matched: false,
      error: "INPUT_TOO_LARGE",
      operations: 0,
    };
  }

  const operationBudget =
    options.operationBudget ??
    MAX_SERVER_RULESET_RULE_OPERATIONS;

  const wallClockFuseMs =
    options.wallClockFuseMs ??
    MAX_SERVER_RULESET_RULE_WALL_CLOCK_MS;

  if (
    !Number.isSafeInteger(operationBudget) ||
    operationBudget < 1
  ) {
    return {
      accepted: false,
      matched: false,
      error: "OPERATION_BUDGET_EXCEEDED",
      operations: 0,
    };
  }

  if (
    !Number.isFinite(wallClockFuseMs) ||
    wallClockFuseMs < 1
  ) {
    return {
      accepted: false,
      matched: false,
      error: "WALL_CLOCK_FUSE_EXCEEDED",
      operations: 0,
    };
  }

  const characters = Array.from(input);
  const program = compiled.program;
  const terminalState = program.tokens.length;
  const startedAt = Date.now();
  let operations = 0;
  let budgetExceeded = false;

  const countOperation = (): boolean => {
    operations++;

    if (operations > operationBudget) {
      budgetExceeded = true;
      return false;
    }

    return true;
  };

  const epsilonClosure = (
    seeds: ReadonlySet<number>
  ): Set<number> | null => {
    const closure = new Set<number>();
    const stack = Array.from(seeds);

    while (stack.length > 0) {
      const state = stack.pop();

      if (state === undefined || closure.has(state)) {
        continue;
      }

      if (!countOperation()) {
        return null;
      }

      closure.add(state);

      if (state >= terminalState) {
        continue;
      }

      const quantifier =
        program.tokens[state].quantifier;

      if (
        quantifier === "OPTIONAL" ||
        quantifier === "ZERO_OR_MORE"
      ) {
        stack.push(state + 1);
      }
    }

    return closure;
  };

  let active = epsilonClosure(new Set([0]));

  if (active === null) {
    return {
      accepted: false,
      matched: false,
      error: "OPERATION_BUDGET_EXCEEDED",
      operations,
    };
  }

  if (
    active.has(terminalState) &&
    (
      !program.anchoredEnd ||
      characters.length === 0
    )
  ) {
    return {
      accepted: true,
      matched: true,
      error: null,
      operations,
    };
  }

  for (
    let position = 0;
    position < characters.length;
    position++
  ) {
    if (
      position % 64 === 0 &&
      Date.now() - startedAt > wallClockFuseMs
    ) {
      return {
        accepted: false,
        matched: false,
        error: "WALL_CLOCK_FUSE_EXCEEDED",
        operations,
      };
    }

    if (!program.anchoredStart) {
      const withRestart = new Set(active);
      withRestart.add(0);
      active = epsilonClosure(withRestart);

      if (active === null) {
        return {
          accepted: false,
          matched: false,
          error: "OPERATION_BUDGET_EXCEEDED",
          operations,
        };
      }
    }

    const rawNext = new Set<number>();

    for (const state of active) {
      if (!countOperation()) {
        break;
      }

      if (state >= terminalState) {
        continue;
      }

      const token = program.tokens[state];

      if (!atomMatches(token.atom, characters[position])) {
        continue;
      }

      rawNext.add(
        token.quantifier === "ZERO_OR_MORE"
          ? state
          : state + 1
      );
    }

    if (budgetExceeded) {
      return {
        accepted: false,
        matched: false,
        error: "OPERATION_BUDGET_EXCEEDED",
        operations,
      };
    }

    active = epsilonClosure(rawNext);

    if (active === null) {
      return {
        accepted: false,
        matched: false,
        error: "OPERATION_BUDGET_EXCEEDED",
        operations,
      };
    }

    if (
      active.has(terminalState) &&
      (
        !program.anchoredEnd ||
        position === characters.length - 1
      )
    ) {
      return {
        accepted: true,
        matched: true,
        error: null,
        operations,
      };
    }
  }

  if (Date.now() - startedAt > wallClockFuseMs) {
    return {
      accepted: false,
      matched: false,
      error: "WALL_CLOCK_FUSE_EXCEEDED",
      operations,
    };
  }

  return {
    accepted: true,
    matched: active.has(terminalState),
    error: null,
    operations,
  };
}
