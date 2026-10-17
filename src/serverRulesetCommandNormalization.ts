export type ServerRulesetCommandNormalizationReason =
  | "COMMAND_CANDIDATES_DERIVED"
  | "MALFORMED_RECOGNIZED_WRAPPER";

export interface ServerRulesetCommandNormalizationResult {
  readonly accepted: boolean;
  readonly candidates: readonly string[];
  readonly reason: ServerRulesetCommandNormalizationReason;
}

interface ServerRulesetCommandUnwrapResult {
  readonly recognized: boolean;
  readonly accepted: boolean;
  readonly value: string;
}

const MAX_SERVER_RULESET_COMMAND_UNWRAP_DEPTH = 3;

function makeServerRulesetCommandNormalizationResult(
  accepted: boolean,
  candidates: readonly string[],
  reason: ServerRulesetCommandNormalizationReason
): ServerRulesetCommandNormalizationResult {
  return Object.freeze({
    accepted,
    candidates: Object.freeze([...candidates]),
    reason,
  });
}

function malformedRecognizedWrapper(): ServerRulesetCommandUnwrapResult {
  return Object.freeze({
    recognized: true,
    accepted: false,
    value: "",
  });
}

function unrecognizedCommand(): ServerRulesetCommandUnwrapResult {
  return Object.freeze({
    recognized: false,
    accepted: true,
    value: "",
  });
}

function acceptedUnwrap(value: string): ServerRulesetCommandUnwrapResult {
  return Object.freeze({
    recognized: true,
    accepted: true,
    value,
  });
}

function unwrapBalancedOuterQuotes(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed.length < 2) {
    return null;
  }

  const quote = trimmed[0];
  if (
    (quote !== "'" && quote !== '"') ||
    trimmed[trimmed.length - 1] !== quote
  ) {
    return null;
  }

  const inner = trimmed.slice(1, -1);
  if (inner.includes(quote)) {
    return null;
  }

  return inner;
}

function unwrapOptionalQuotedPayload(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }

  const startsQuoted = trimmed.startsWith("'") || trimmed.startsWith('"');
  const endsQuoted = trimmed.endsWith("'") || trimmed.endsWith('"');

  if (startsQuoted || endsQuoted) {
    return unwrapBalancedOuterQuotes(trimmed);
  }

  return trimmed;
}

function unwrapServerRulesetCommandOnce(
  input: string
): ServerRulesetCommandUnwrapResult {
  const shellRecognition =
    /^(?:(?:env|sudo)[ \t]+)?(?:\/bin\/sh|sh|bash|zsh)(?:[ \t]|$)/.test(input);

  if (shellRecognition) {
    const match =
      /^(?:(?:env|sudo)[ \t]+)?(?:\/bin\/sh|sh|bash|zsh)[ \t]+-c[ \t]+(.+)$/.exec(input);

    if (!match) {
      return malformedRecognizedWrapper();
    }

    const payload = unwrapBalancedOuterQuotes(match[1] ?? "");
    if (payload === null || !payload.trim()) {
      return malformedRecognizedWrapper();
    }

    return acceptedUnwrap(payload.trim());
  }

  const powershellRecognition =
    /^(?:pwsh|powershell|powershell\.exe|C:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe)(?:[ \t]|$)/i.test(input);

  if (powershellRecognition) {
    const match =
      /^(?:pwsh|powershell|powershell\.exe|C:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe)[ \t]+(?:-NoProfile[ \t]+)?-Command[ \t]+(.+)$/i.exec(input);

    if (!match) {
      return malformedRecognizedWrapper();
    }

    const payload = unwrapOptionalQuotedPayload(match[1] ?? "");
    if (payload === null || !payload.trim()) {
      return malformedRecognizedWrapper();
    }

    return acceptedUnwrap(payload.trim());
  }

  const cmdRecognition =
    /^(?:cmd|cmd\.exe|C:\\Windows\\System32\\cmd\.exe)(?:[ \t]|$)/i.test(input);

  if (cmdRecognition) {
    const match =
      /^(?:cmd|cmd\.exe|C:\\Windows\\System32\\cmd\.exe)[ \t]+\/c[ \t]+(.+)$/i.exec(input);

    if (!match) {
      return malformedRecognizedWrapper();
    }

    const payload = unwrapOptionalQuotedPayload(match[1] ?? "");
    if (payload === null || !payload.trim()) {
      return malformedRecognizedWrapper();
    }

    return acceptedUnwrap(payload.trim());
  }

  for (const [absoluteExecutable, commandName] of [
    ["/usr/bin/find", "find"],
    ["/bin/dd", "dd"],
    ["/usr/sbin/diskutil", "diskutil"],
  ] as const) {
    if (input === absoluteExecutable) {
      return malformedRecognizedWrapper();
    }

    const prefix = absoluteExecutable + " ";
    if (input.startsWith(prefix)) {
      const remainder = input.slice(prefix.length).trim();
      if (!remainder) {
        return malformedRecognizedWrapper();
      }

      return acceptedUnwrap(commandName + " " + remainder);
    }
  }

  return unrecognizedCommand();
}

export function deriveServerRulesetCommandCandidates(
  proposed: string
): ServerRulesetCommandNormalizationResult {
  if (typeof proposed !== "string") {
    return makeServerRulesetCommandNormalizationResult(
      false,
      [],
      "MALFORMED_RECOGNIZED_WRAPPER"
    );
  }

  const original = proposed;
  let current = proposed.trim();
  let interpretationApplied = false;
  let depth = 0;

  for (; depth < MAX_SERVER_RULESET_COMMAND_UNWRAP_DEPTH; depth++) {
    const unwrapped = unwrapServerRulesetCommandOnce(current);

    if (!unwrapped.recognized) {
      break;
    }

    if (!unwrapped.accepted || !unwrapped.value) {
      return makeServerRulesetCommandNormalizationResult(
        false,
        [],
        "MALFORMED_RECOGNIZED_WRAPPER"
      );
    }

    interpretationApplied = true;
    current = unwrapped.value;
  }

  if (
    depth === MAX_SERVER_RULESET_COMMAND_UNWRAP_DEPTH &&
    unwrapServerRulesetCommandOnce(current).recognized
  ) {
    return makeServerRulesetCommandNormalizationResult(
      false,
      [],
      "MALFORMED_RECOGNIZED_WRAPPER"
    );
  }

  const candidates = [original];
  if (interpretationApplied && current !== original) {
    candidates.push(current);
  }

  return makeServerRulesetCommandNormalizationResult(
    true,
    candidates,
    "COMMAND_CANDIDATES_DERIVED"
  );
}
