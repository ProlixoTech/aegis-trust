import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

import type {
  SafetyKernelV31AllowedExecutionAbortEvidence,
  SafetyKernelV31AllowedExecutionAbortReason,
  SafetyKernelV31AllowedExecutionCompletionBinding,
  SafetyKernelV31AllowedExecutionCompletionEvidence,
  SafetyKernelV31KernelDecision,
  SafetyKernelV31KernelDecisionResult,
  SafetyKernelV31WarnConfirmationEvidence,
  SafetyKernelV31WarnTerminalEvidence,
} from "./types";

export type SafetyKernelV31EvidenceEventType =
  | "kernel_decision"
  | "allowed_execution_completed"
  | "allowed_execution_aborted"
  | "warn_confirmed"
  | "warn_terminal";

export type SafetyKernelV31NonceStateAfterEvidence =
  | "ACTIVE_PENDING_EXECUTION"
  | "WARN_PENDING"
  | "ALLOW_PENDING_EXECUTION"
  | "CONSUMED"
  | "IDLE";

export interface SafetyKernelV31EvidenceRecord {
  schemaVersion: 1;
  eventType: SafetyKernelV31EvidenceEventType;
  timestamp: string;
  actionId: string;
  approvalNonceSha256: string;
  nonceStateAfterEvidence: SafetyKernelV31NonceStateAfterEvidence;
  receiptRequired: true;
  ledgerRequired: true;
  decision?: SafetyKernelV31KernelDecision;
  policyVersion?: string;
  reasons?: string[];
  detectedEffectCount?: number;
  humanReadableSummary?: string;
  warnReason?: SafetyKernelV31WarnTerminalEvidence["reason"];
  allowedExecutionAbortReason?: SafetyKernelV31AllowedExecutionAbortReason;
  executionCompleted?: false;
  executionBinding?: SafetyKernelV31AllowedExecutionCompletionBinding;
  warnConfirmed?: true;
  executionAuthorityGranted?: false;
  nonceConsumed?: true;
  returnState?: "IDLE";
  warnMustNeverAutoProceed?: true;
  evidenceChainVersion?: 1;
  evidenceSequence?: number;
  evidencePrevHash?: string;
  evidenceEventHash?: string;
}

export type SafetyKernelV31EvidenceWriteResult =
  | {
      ok: true;
      ledgerPath: string;
      receiptPath: string;
      reason: "success";
    }
  | {
      ok: false;
      ledgerPath: null;
      receiptPath: null;
      reason: "invalid_input" | "write_failed";
    };

export type SafetyKernelV31EvidenceIntegrityIssueCode =
  | "MALFORMED_EVENT"
  | "CHAIN_HASH_MISMATCH"
  | "CHAIN_PREV_HASH_MISMATCH"
  | "CHAIN_SEQUENCE_MISMATCH";

export type SafetyKernelV31EvidenceIntegrityReport =
  | {
      ok: true;
      ledgerExists: true;
      ledgerPath: string;
      eventCount: number;
      headHash: string;
      issueCode?: never;
      issueLineNumber?: never;
    }
  | {
      ok: true;
      ledgerExists: false;
      ledgerPath: string;
      eventCount: 0;
      headHash: string;
      issueCode?: never;
      issueLineNumber?: never;
    }
  | {
      ok: false;
      ledgerExists: true;
      ledgerPath: string;
      eventCount: number;
      headHash: string;
      issueCode: SafetyKernelV31EvidenceIntegrityIssueCode;
      issueLineNumber: number;
    }
  | {
      ok: false;
      ledgerExists: false;
      ledgerPath: string;
      eventCount: 0;
      headHash: string;
      issueCode: "READ_FAILED";
      issueLineNumber?: never;
    };

export const SAFETY_KERNEL_V31_EVIDENCE_WRITER_INVARIANT = {
  RUNTIME_CONNECTED: false,
  PROTECTED_FILE_LEDGER_REUSED: false,
  RAW_APPROVAL_NONCE_STORED: false,
  RECEIPT_AND_LEDGER_REQUIRED: true,
  APPEND_ONLY_HASH_CHAIN: true,
} as const;

const EVIDENCE_CHAIN_VERSION = 1 as const;
const EVIDENCE_GENESIS_HASH = "GENESIS";

function sha256(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

type SafetyKernelV31EvidenceChainHead = Record<string, unknown> & {
  evidenceSequence: number;
  evidenceEventHash: string;
};

type SafetyKernelV31ChainedEvidenceRecord = SafetyKernelV31EvidenceChainHead & {
  evidenceChainVersion: 1;
  evidencePrevHash: string;
};

function hasSafetyKernelV31EvidenceChainHead(
  value: unknown
): value is SafetyKernelV31EvidenceChainHead {
  return (
    value !== null &&
    typeof value === "object" &&
    "evidenceSequence" in value &&
    typeof value.evidenceSequence === "number" &&
    "evidenceEventHash" in value &&
    typeof value.evidenceEventHash === "string"
  );
}

function isSafetyKernelV31ChainedEvidenceRecord(
  value: unknown
): value is SafetyKernelV31ChainedEvidenceRecord {
  return (
    hasSafetyKernelV31EvidenceChainHead(value) &&
    "evidenceChainVersion" in value &&
    value.evidenceChainVersion === EVIDENCE_CHAIN_VERSION &&
    "evidencePrevHash" in value &&
    typeof value.evidencePrevHash === "string"
  );
}

function getErrorCode(error: unknown): string | undefined {
  if (error === null || typeof error !== "object" || !("code" in error)) return undefined;
  return typeof error.code === "string" ? error.code : undefined;
}

function getErrorMessage(error: unknown): unknown {
  if (error === null || typeof error !== "object" || !("message" in error)) return undefined;
  return error.message;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalJson(item)).join(",") + "]";
  }

  return "{" + Object.keys(value).sort().map((key) => {
    return JSON.stringify(key) + ":" + canonicalJson(Reflect.get(value, key));
  }).join(",") + "}";
}

function sanitizeText(value: string, maxLength = 240): string {
  return value
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/\b([A-Za-z_][A-Za-z0-9_]{1,40})\s*=\s*[^\s,;]+/g, "$1=[REDACTED]")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function requireNonEmpty(value: string): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

function nonceStateForDecision(decision: SafetyKernelV31KernelDecision): SafetyKernelV31NonceStateAfterEvidence {
  if (decision === "ALLOW") {
    return "ACTIVE_PENDING_EXECUTION";
  }
  if (decision === "WARN") {
    return "WARN_PENDING";
  }
  return "CONSUMED";
}

function buildReceipt(record: SafetyKernelV31EvidenceRecord): string {
  const lines = [
    "# Safety Kernel v3.1 Evidence Receipt",
    "",
    `- Event type: ${record.eventType}`,
    `- Timestamp: ${record.timestamp}`,
    `- Action ID: ${record.actionId}`,
    `- Approval nonce SHA-256: ${record.approvalNonceSha256}`,
    `- Nonce state: ${record.nonceStateAfterEvidence}`,
    `- Receipt required: ${record.receiptRequired}`,
    `- Ledger required: ${record.ledgerRequired}`,
  ];

  if (record.decision) {
    lines.push(`- Decision: ${record.decision}`);
  }
  if (record.policyVersion) {
    lines.push(`- Policy version: ${record.policyVersion}`);
  }
  if (record.warnReason) {
    lines.push(`- WARN terminal reason: ${record.warnReason}`);
  }
  if (record.returnState) {
    lines.push(`- Return state: ${record.returnState}`);
  }
  if (record.warnConfirmed) {
    lines.push("- WARN confirmed: true");
  }
  if (record.allowedExecutionAbortReason) {
    lines.push(`- Allowed execution abort reason: ${record.allowedExecutionAbortReason}`);
  }
  if (record.executionCompleted === false) {
    lines.push("- Execution completed: false");
  }
  if (record.executionAuthorityGranted === false) {
    lines.push("- Execution authority granted: false");
  }
  if (record.nonceConsumed) {
    lines.push("- Nonce consumed: true");
  }
  if (record.executionBinding) {
    lines.push(
      `- Authority revision: ${record.executionBinding.authority_revision}`
    );
    lines.push(
      `- Command SHA-256: ${record.executionBinding.command_sha256}`
    );
    lines.push(
      `- Snapshot binding SHA-256: ${record.executionBinding.snapshot_binding_sha256}`
    );
    lines.push(
      `- Exit code: ${record.executionBinding.exit_code}`
    );
    lines.push(
      `- stdout SHA-256: ${record.executionBinding.stdout_sha256}`
    );
    lines.push(
      `- stderr SHA-256: ${record.executionBinding.stderr_sha256}`
    );
    lines.push(
      `- stdout bytes: ${record.executionBinding.stdout_bytes}`
    );
    lines.push(
      `- stderr bytes: ${record.executionBinding.stderr_bytes}`
    );
  }
  if (record.warnMustNeverAutoProceed) {
    lines.push("- WARN auto-proceed allowed: false");
  }
  if (record.reasons && record.reasons.length > 0) {
    lines.push(`- Reasons: ${record.reasons.join(" | ")}`);
  }
  if (record.humanReadableSummary) {
    lines.push(`- Summary: ${record.humanReadableSummary}`);
  }

  lines.push(
    `- Evidence sequence: ${record.evidenceSequence}`,
    `- Previous hash: ${record.evidencePrevHash}`,
    `- Event hash: ${record.evidenceEventHash}`,
    ""
  );

  return lines.join("\n");
}

export class SafetyKernelV31EvidenceWriter {
  private readonly evidenceDir: string;
  private readonly ledgerFile: string;
  private readonly receiptsDir: string;
  private appendQueue: Promise<void> = Promise.resolve();

  constructor(aegisDir: string) {
    this.evidenceDir = path.join(aegisDir, "safety-kernel-v31");
    this.ledgerFile = path.join(this.evidenceDir, "evidence.jsonl");
    this.receiptsDir = path.join(this.evidenceDir, "receipts");
  }

  async ensureDirs(): Promise<void> {
    await fs.promises.mkdir(this.receiptsDir, { recursive: true });
  }

  async appendDecision(
    result: SafetyKernelV31KernelDecisionResult,
    timestamp = new Date().toISOString()
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    if (
      !requireNonEmpty(result.action_id) ||
      !requireNonEmpty(result.approval_nonce) ||
      !requireNonEmpty(result.policy_version) ||
      !requireNonEmpty(timestamp)
    ) {
      return { ok: false, ledgerPath: null, receiptPath: null, reason: "invalid_input" };
    }

    const record: SafetyKernelV31EvidenceRecord = {
      schemaVersion: 1,
      eventType: "kernel_decision",
      timestamp: sanitizeText(timestamp, 64),
      actionId: sanitizeText(result.action_id, 160),
      approvalNonceSha256: sha256(result.approval_nonce),
      nonceStateAfterEvidence: nonceStateForDecision(result.decision),
      receiptRequired: true,
      ledgerRequired: true,
      decision: result.decision,
      policyVersion: sanitizeText(result.policy_version, 120),
      reasons: result.reasons.map((reason) => sanitizeText(reason, 200)).filter(Boolean).slice(0, 20),
      detectedEffectCount: result.detectedEffects?.length ?? 0,
      humanReadableSummary: sanitizeText(result.human_readable_summary, 240),
    };

    return this.appendRecord(record);
  }

  async appendWarnConfirmation(
    evidence: SafetyKernelV31WarnConfirmationEvidence,
    timestamp = new Date().toISOString()
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    if (
      !requireNonEmpty(evidence.action_id) ||
      !requireNonEmpty(evidence.approval_nonce) ||
      !requireNonEmpty(timestamp)
    ) {
      return { ok: false, ledgerPath: null, receiptPath: null, reason: "invalid_input" };
    }

    const record: SafetyKernelV31EvidenceRecord = {
      schemaVersion: 1,
      eventType: "warn_confirmed",
      timestamp: sanitizeText(timestamp, 64),
      actionId: sanitizeText(evidence.action_id, 160),
      approvalNonceSha256: sha256(evidence.approval_nonce),
      nonceStateAfterEvidence: "ALLOW_PENDING_EXECUTION",
      receiptRequired: true,
      ledgerRequired: true,
      warnConfirmed: true,
      executionAuthorityGranted: false,
    };

    return this.appendRecord(record);
  }

  async appendAllowedExecutionCompletion(
    evidence: SafetyKernelV31AllowedExecutionCompletionEvidence,
    timestamp = new Date().toISOString()
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    if (
      !requireNonEmpty(evidence.action_id) ||
      !requireNonEmpty(evidence.approval_nonce) ||
      !requireNonEmpty(timestamp)
    ) {
      return {
        ok: false,
        ledgerPath: null,
        receiptPath: null,
        reason: "invalid_input",
      };
    }

    const rawBinding = (
      evidence as {
        execution_binding?: unknown;
      }
    ).execution_binding;

    let executionBinding:
      | SafetyKernelV31AllowedExecutionCompletionBinding
      | undefined;

    if (rawBinding !== undefined) {
      if (
        typeof rawBinding !== "object" ||
        rawBinding === null
      ) {
        return {
          ok: false,
          ledgerPath: null,
          receiptPath: null,
          reason: "invalid_input",
        };
      }

      const candidate = rawBinding as Partial<
        SafetyKernelV31AllowedExecutionCompletionBinding
      >;

      const valid =
        typeof candidate.authority_revision === "number" &&
        Number.isSafeInteger(candidate.authority_revision) &&
        candidate.authority_revision >= 0 &&
        /^sha256:[a-f0-9]{64}$/.test(
          candidate.command_sha256 ?? ""
        ) &&
        /^sha256:[a-f0-9]{64}$/.test(
          candidate.snapshot_binding_sha256 ?? ""
        ) &&
        candidate.exit_code === 0 &&
        /^sha256:[a-f0-9]{64}$/.test(
          candidate.stdout_sha256 ?? ""
        ) &&
        /^sha256:[a-f0-9]{64}$/.test(
          candidate.stderr_sha256 ?? ""
        ) &&
        typeof candidate.stdout_bytes === "number" &&
        Number.isSafeInteger(candidate.stdout_bytes) &&
        candidate.stdout_bytes >= 0 &&
        typeof candidate.stderr_bytes === "number" &&
        Number.isSafeInteger(candidate.stderr_bytes) &&
        candidate.stderr_bytes >= 0;

      if (!valid) {
        return {
          ok: false,
          ledgerPath: null,
          receiptPath: null,
          reason: "invalid_input",
        };
      }

      executionBinding = {
        authority_revision:
          candidate.authority_revision as number,
        command_sha256:
          candidate.command_sha256 as string,
        snapshot_binding_sha256:
          candidate.snapshot_binding_sha256 as string,
        exit_code: 0,
        stdout_sha256:
          candidate.stdout_sha256 as string,
        stderr_sha256:
          candidate.stderr_sha256 as string,
        stdout_bytes:
          candidate.stdout_bytes as number,
        stderr_bytes:
          candidate.stderr_bytes as number,
      };
    }

    const record: SafetyKernelV31EvidenceRecord = {
      schemaVersion: 1,
      eventType: "allowed_execution_completed",
      timestamp: sanitizeText(timestamp, 64),
      actionId: sanitizeText(evidence.action_id, 160),
      approvalNonceSha256: sha256(evidence.approval_nonce),
      nonceStateAfterEvidence: "CONSUMED",
      receiptRequired: true,
      ledgerRequired: true,
      nonceConsumed: true,
      ...(executionBinding
        ? { executionBinding }
        : {}),
    };

    return this.appendRecord(record);
  }

  async appendAllowedExecutionAbort(
    evidence: SafetyKernelV31AllowedExecutionAbortEvidence,
    timestamp = new Date().toISOString()
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    const validReason =
      evidence.reason === "snapshot_failed" ||
      evidence.reason === "authority_drift" ||
      evidence.reason === "execution_failed" ||
      evidence.reason === "cancel_by_user";

    if (
      !requireNonEmpty(evidence.action_id) ||
      !requireNonEmpty(evidence.approval_nonce) ||
      !requireNonEmpty(timestamp) ||
      !validReason
    ) {
      return {
        ok: false,
        ledgerPath: null,
        receiptPath: null,
        reason: "invalid_input",
      };
    }

    const record: SafetyKernelV31EvidenceRecord = {
      schemaVersion: 1,
      eventType: "allowed_execution_aborted",
      timestamp: sanitizeText(timestamp, 64),
      actionId: sanitizeText(evidence.action_id, 160),
      approvalNonceSha256: sha256(evidence.approval_nonce),
      nonceStateAfterEvidence: "IDLE",
      receiptRequired: true,
      ledgerRequired: true,
      allowedExecutionAbortReason: evidence.reason,
      executionCompleted: false,
      nonceConsumed: true,
      returnState: "IDLE",
    };

    return this.appendRecord(record);
  }

  async appendWarnTerminal(
    evidence: SafetyKernelV31WarnTerminalEvidence,
    timestamp = new Date().toISOString()
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    if (
      !requireNonEmpty(evidence.action_id) ||
      !requireNonEmpty(evidence.approval_nonce) ||
      !requireNonEmpty(timestamp)
    ) {
      return { ok: false, ledgerPath: null, receiptPath: null, reason: "invalid_input" };
    }

    const record: SafetyKernelV31EvidenceRecord = {
      schemaVersion: 1,
      eventType: "warn_terminal",
      timestamp: sanitizeText(timestamp, 64),
      actionId: sanitizeText(evidence.action_id, 160),
      approvalNonceSha256: sha256(evidence.approval_nonce),
      nonceStateAfterEvidence: "IDLE",
      receiptRequired: true,
      ledgerRequired: true,
      warnReason: evidence.reason,
      nonceConsumed: true,
      returnState: "IDLE",
      warnMustNeverAutoProceed: true,
    };

    return this.appendRecord(record);
  }

  async verifyIntegrity(): Promise<SafetyKernelV31EvidenceIntegrityReport> {
    try {
      const text = await fs.promises.readFile(this.ledgerFile, "utf8");
      const lines = text.split("\n").filter((line: string) => line.trim().length > 0);
      let previousHash = EVIDENCE_GENESIS_HASH;
      let expectedSequence = 1;

      for (let index = 0; index < lines.length; index++) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(lines[index]);
        } catch {
          return {
            ok: false,
            ledgerExists: true,
            ledgerPath: this.ledgerFile,
            eventCount: index,
            headHash: previousHash,
            issueCode: "MALFORMED_EVENT",
            issueLineNumber: index + 1,
          };
        }

        if (!isSafetyKernelV31ChainedEvidenceRecord(parsed)) {
          return {
            ok: false,
            ledgerExists: true,
            ledgerPath: this.ledgerFile,
            eventCount: index,
            headHash: previousHash,
            issueCode: "MALFORMED_EVENT",
            issueLineNumber: index + 1,
          };
        }

        if (parsed.evidenceSequence !== expectedSequence) {
          return {
            ok: false,
            ledgerExists: true,
            ledgerPath: this.ledgerFile,
            eventCount: index,
            headHash: previousHash,
            issueCode: "CHAIN_SEQUENCE_MISMATCH",
            issueLineNumber: index + 1,
          };
        }

        if (parsed.evidencePrevHash !== previousHash) {
          return {
            ok: false,
            ledgerExists: true,
            ledgerPath: this.ledgerFile,
            eventCount: index,
            headHash: previousHash,
            issueCode: "CHAIN_PREV_HASH_MISMATCH",
            issueLineNumber: index + 1,
          };
        }

        const { evidenceEventHash, ...withoutHash } = parsed;
        const expectedHash = sha256(canonicalJson(withoutHash));
        if (evidenceEventHash !== expectedHash) {
          return {
            ok: false,
            ledgerExists: true,
            ledgerPath: this.ledgerFile,
            eventCount: index,
            headHash: previousHash,
            issueCode: "CHAIN_HASH_MISMATCH",
            issueLineNumber: index + 1,
          };
        }

        previousHash = evidenceEventHash;
        expectedSequence += 1;
      }

      return {
        ok: true,
        ledgerExists: true,
        ledgerPath: this.ledgerFile,
        eventCount: lines.length,
        headHash: previousHash,
      };
    } catch (error) {
      const code = getErrorCode(error);
      if (code === "ENOENT") {
        return {
          ok: true,
          ledgerExists: false,
          ledgerPath: this.ledgerFile,
          eventCount: 0,
          headHash: EVIDENCE_GENESIS_HASH,
        };
      }
      return {
        ok: false,
        ledgerExists: false,
        ledgerPath: this.ledgerFile,
        eventCount: 0,
        headHash: EVIDENCE_GENESIS_HASH,
        issueCode: "READ_FAILED",
      };
    }
  }

  private async appendRecord(
    record: SafetyKernelV31EvidenceRecord
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    const operation = this.appendQueue.then(
      () => this.appendSerialized(record),
      () => this.appendSerialized(record)
    );

    this.appendQueue = operation.then(
      () => undefined,
      () => undefined
    );

    return operation;
  }

  private async appendSerialized(
    record: SafetyKernelV31EvidenceRecord
  ): Promise<SafetyKernelV31EvidenceWriteResult> {
    try {
      await this.ensureDirs();
      const chained = await this.buildChainedRecord(record);
      await this.appendDurableLine(JSON.stringify(chained) + "\n");

      const sequence = String(chained.evidenceSequence).padStart(6, "0");
      const receiptPath = path.join(
        this.receiptsDir,
        `receipt-${sequence}-${chained.evidenceEventHash?.slice(0, 16)}.md`
      );
      await this.writeDurableFile(receiptPath, buildReceipt(chained));

      return {
        ok: true,
        ledgerPath: this.ledgerFile,
        receiptPath,
        reason: "success",
      };
    } catch (error) {
      console.error("[Aegis Safety Kernel] Evidence write failed:", getErrorMessage(error));
      return {
        ok: false,
        ledgerPath: null,
        receiptPath: null,
        reason: "write_failed",
      };
    }
  }

  private async buildChainedRecord(
    record: SafetyKernelV31EvidenceRecord
  ): Promise<SafetyKernelV31EvidenceRecord> {
    let previousHash = EVIDENCE_GENESIS_HASH;
    let sequence = 1;

    const integrity = await this.verifyIntegrity();
    if (!integrity.ok) {
      throw new Error(`EVIDENCE_LEDGER_INTEGRITY_FAILED:${integrity.issueCode}`);
    }
    if (integrity.ledgerExists) {
      previousHash = integrity.headHash;
      sequence = integrity.eventCount + 1;
    }

    const withoutHash: SafetyKernelV31EvidenceRecord = {
      ...record,
      evidenceChainVersion: EVIDENCE_CHAIN_VERSION,
      evidenceSequence: sequence,
      evidencePrevHash: previousHash,
    };

    return {
      ...withoutHash,
      evidenceEventHash: sha256(canonicalJson(withoutHash)),
    };
  }

  private async appendDurableLine(line: string): Promise<void> {
    const handle = await fs.promises.open(this.ledgerFile, "a");
    try {
      await handle.writeFile(line, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  private async writeDurableFile(filePath: string, content: string): Promise<void> {
    const handle = await fs.promises.open(filePath, "wx");
    try {
      await handle.writeFile(content, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
}
