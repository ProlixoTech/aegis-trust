// src/types.ts - Type contracts for Prolixo Aegis Personal v0.1 Prototype
// Updated for Phase 2-A: added AegisStatus and AegisUiState
// Updated for Fix Phase 4: added "baseline_registration" BaselineSource value
//                          added "baseline_registration_snapshot_created" LedgerReason value
// Updated for Phase 5-E:  added "INACTIVE" AegisStatus value for no-folder-open display
// Updated for BLOCKER-01: added baseline_snapshot_file and baseline_content_sha256
//                         to LatestSafeSnapshotIndex to separate immutable baseline
//                         restore data from the rolling pre-save audit snapshot.

// Phase 1 types (unchanged)

/**
 * How the pre-save baseline content was obtained.
 *   "pre_save_disk"         - file existed; content read from disk before save
 *   "initial_creation"      - file did not exist; content is ""
 *   "baseline_registration" - first meaningful baseline; content read from disk
 *                             AFTER save, used only for the baseline registration
 *                             snapshot path in handleDidSave. Never produced by
 *                             capturePreSave - only by createBaselineSnapshotFromContent.
 */
export type BaselineSource = "pre_save_disk" | "initial_creation" | "baseline_registration";

/**
 * In-memory store of the file content before a save event.
 * NEVER written to console, UI messages, or any file other than the
 * snapshot itself. content may hold raw .env text - treat as a secret.
 */
export interface BaselineEntry {
  originalAbsPath: string;   // used for all fs read/write operations
  normalizedKey:   string;   // used as Map key (lowercase forward-slash)
  content:         string;   // pre-save file content - never logged
  sha256:          string;   // SHA-256 of content
  capturedAt:      string;   // ISO timestamp
  source:          BaselineSource;
}

/**
 * Written to .aegis/snapshots/<id>/manifest.json.
 * Contains only hashes and path references - no raw file content.
 */
export interface SnapshotManifest {
  snapshot_id:    string;
  created_at:     string;
  original_path:  string;   // absolute path - used for fs.writeFile on restore
  normalized_key: string;   // lowercase forward-slash key
  snapshot_file:  string;   // absolute path to the .snapshot content file
  source:         BaselineSource;
  content_sha256: string;
  byte_length:    number;
  encoding:       "utf8";
}

/**
 * Written to .aegis/latest-safe-snapshot.json (and per-target variants).
 *
 * BLOCKER-01: Two pointer/hash pairs are now present:
 *
   * Immutable baseline fields (written once at registration, never overwritten)
 *
 *   baseline_snapshot_file:  Absolute path to the snapshot file created at
 *                            initial baseline registration. Used as the restore
 *                            source by store.restore(). Never updated by later
 *                            protected-change saves.
 *
 *   baseline_content_sha256: SHA-256 of the original registered baseline content.
 *                            Used for post-restore disk verification and for
 *                            rehydration on VS Code reload/restart. Never updated
 *                            by later protected-change saves.
 *
   * Rolling audit fields (updated on every protected-change save)
 *
 *   snapshot_file:           Absolute path to the most recent pre-save snapshot.
 *                            Records the last-known safe disk content before a
 *                            protected change was saved. Used for audit/ledger
   *                            only - NOT used as the restore source.
 *
 *   content_sha256:          SHA-256 of the most recent pre-save snapshot content.
   *                            Rolling audit hash only - NOT used for restore
 *                            verification or rehydration.
 *
 * BACKWARD COMPATIBILITY:
 *   Old index files written before BLOCKER-01 will not have baseline_snapshot_file
 *   or baseline_content_sha256. Code that reads the index must treat their absence
 *   as a degraded/unsafe state and must not silently mark SAFE. Prefer BLOCKED or
 *   WARNING with a clear internal reason rather than optimistically assuming the
 *   rolling snapshot_file is safe to restore from.
 */
export interface LatestSafeSnapshotIndex {
  snapshot_id:              string;
  original_path:            string;
  normalized_key:           string;
  source:                   BaselineSource;
  created_at:               string;

  // Immutable baseline fields - written once, never overwritten
  baseline_snapshot_file:   string;   // restore source - always the registered baseline
  baseline_content_sha256:  string;   // verification ground truth for restore + rehydration

  // Rolling audit fields - updated on every protected-change save
  snapshot_file:            string;   // latest pre-save snapshot path (audit only)
  content_sha256:           string;   // latest pre-save snapshot hash (audit only)
}

/**
 * Returned by SnapshotStore.restore().
 *
 * lockedAbsPath is set as soon as engine.addRestoring() is called -
 * before any disk write - so it is present on BOTH success and failure.
 * The caller must call engine.removeRestoring(result.lockedAbsPath)
 * in its finally block for every path where the lock was acquired.
 *
 * restoredAbsPath is set only on verified disk success.
 */
export interface RestoreResult {
  success:          boolean;
  message:          string;
  lockedAbsPath?:   string;   // set when lock acquired; always unlock in finally
  restoredAbsPath?: string;   // set on disk-verified success only
}

// Phase 2-B types

/**
 * The three fact-recording event types for the Truthful Ledger.
 * No receipt, no PDF, no audit-chain events in Phase 2-B.
 *
 * Core, SnapshotStore, StateManager, and Webview must remain
 * unaware of these types - only extension.ts Orchestrator uses them.
 */
export type LedgerEventType =
  | "snapshot_created"
  | "restore_completed"
  | "restore_failed"
  | "protected_target_changed";

/**
 * Fixed error codes - typed union prevents free-form strings that could
 * accidentally contain file paths or content fragments.
 */
export type LedgerErrorCode =
  | "no_snapshot_found"
  | "snapshot_unreadable"
  | "sha256_mismatch"
  | "write_failed"
  | "readback_failed"
  | "content_mismatch"
  | "editor_refresh_failed"
  | "no_baseline_fields"
  | "unknown";

/**
 * Fixed reason strings - sourced from the Orchestrator, never from
 * result.message (which may contain ENOENT path fragments).
 *
 * "baseline_registration_snapshot_created" - Fix Phase 4 addition.
 * "restore_failed_no_baseline_fields"      - BLOCKER-01 addition.
 *   Used when an old index file is present but does not contain the
 *   immutable baseline fields introduced in BLOCKER-01. The rolling
 *   snapshot is not safe to use as a restore source.
 */
export type LedgerReason =
  | "pre_save_snapshot_created"
  | "baseline_registration_snapshot_created"
  | "verified_restore_completed"
  | "disk_restored_editor_refresh_failed"
  | "restore_failed_no_safe_snapshot"
  | "restore_failed_no_baseline_fields"
  | "restore_failed_snapshot_unreadable"
  | "restore_failed_sha256_mismatch"
  | "restore_failed_write_failed"
  | "restore_failed_readback_failed"
  | "restore_failed_content_mismatch"
  | "restore_failed_unknown"
  | "watcher_delete_detected"
  | "watcher_change_detected";

/**
 * One append-only event line in .aegis/ledger/events.jsonl.
 *
 * MUST NOT contain:
 *   - raw .env content
 *   - API keys, passwords, tokens, or secret values
 *   - absolute file paths (use relative protectedPath)
 *   - result.message strings (may contain ENOENT path fragments)
 *   - String(err) (may contain paths or content)
 *
 * MAY contain:
 *   - relative protectedPath (e.g. ".env")
 *   - snapshot id (random hex timestamp)
 *   - snapshotHash (SHA-256 hex, not the secret)
 *   - success / verified booleans
 *   - fixed reason / errorCode enum values
 *   - timestamp
 */
export interface LedgerEvent {
  schemaVersion:  1;
  eventType:      LedgerEventType;
  timestamp:      string;           // ISO 8601
  protectedPath:  string;           // relative path, e.g. ".env"
  snapshotId?:    string;
  success:        boolean;
  verified:       boolean;
  snapshotHash?:  string;           // SHA-256 hex of snapshot content - not the content itself
  reason:         LedgerReason;
  errorCode?:     LedgerErrorCode;

  // LEDGER_HASH_CHAIN_RUNTIME_GUARD_V1
  ledgerChainVersion?: 1;
  ledgerSequence?:     number;
  ledgerPrevHash?:     string;
  ledgerEventHash?:    string;
}


/**
 * Status held by StateManager in extension-host memory.
 * The Webview renders this but never owns it.
 *
 * Transition rules (enforced by StateManager):
 *   SAFE      - BLOCKED | WARNING | RESTORING
 *   WARNING   - BLOCKED | SAFE
 *   BLOCKED   - RESTORING            (user clicks Restore)
 *   BLOCKED   - SAFE                 only after verified restore success
 *   RESTORING - SAFE                 after disk verify + editor refresh
 *   RESTORING - BLOCKED              after restore failure
 *   RESTORING - WARNING              if disk OK but editor refresh failed
 *
 * Forbidden transitions:
 *   BLOCKED - SAFE because an unrelated file was saved
 *   BLOCKED - SAFE because Webview reopened or panel refreshed
 *   RESTORING - SAFE before disk verification
 *
 * INACTIVE is a display-only status used exclusively when no workspace
 * folder is open. It is never held by StateManager and never written to
 * the ledger. It is set directly on the inline AegisUiState object passed
 * to AegisWebviewPanel.show() in the no-folder-open branch of extension.ts.
 * No state machine transitions apply to INACTIVE.
 */
export type AegisStatus = "SAFE" | "WARNING" | "BLOCKED" | "RESTORING" | "INACTIVE";

/**
 * Authoritative UI state. Lives in StateManager (extension-host memory).
 * Webview receives a copy via postMessage and renders it.
 * Webview must never mutate state - it only sends command messages.
 */
export interface AegisUiState {
  status:             AegisStatus;
  message:            string;
  restoreAvailable:   boolean;
  isProcessing:       boolean;
  licenseTier?:       string;
  licenseCapabilities?: readonly string[];
  lastProtectedPath?: string;    // relative path of last protected .env change
  lastSnapshotId?:    string;    // snapshot_id of last safe restore point
  lastEventAt?:       string;    // ISO timestamp of last state-changing event
}

// Fix Phase 4 types

/**
 * Written to .aegis/baseline-registered.json after the first meaningful
 * .env baseline snapshot is verified. Secret-safe: contains no .env content,
 * no key names, no values, no snapshot content.
 *
 * Purpose: allows handleDidSave to distinguish "no meaningful baseline yet"
 * from "meaningful baseline already registered" across VS Code restarts.
 * Replaces store.hasIndex() as the reliable hadPreviousBaseline signal.
 */
export interface BaselineRegistrationMarker {
  schemaVersion:  1;
  registered:     true;
  registeredAt:   string;   // ISO 8601 timestamp
  protectedPath:  string;   // relative path, e.g. ".env" - no content
}

// ============================================================================
// AI Compliance Gate (Phase A) - additive types only
// ----------------------------------------------------------------------------
// Phase A scope: pure checker types + reviewAiComplianceText() in
// src/aiComplianceGate.ts. No webview, no command registration, no
// package.json change. These types are purely additive - nothing above
// this block in src/types.ts is modified.
//
// Append the block below to the end of src/types.ts.
// ============================================================================

/**
 * Overall classification returned by reviewAiComplianceText().
 *
 * - SAFE_TO_RUN: no BLOCK or WARNING findings.
 * - WARNING:     at least one WARNING finding, no BLOCK findings.
 * - BLOCKED:     at least one BLOCK finding.
 */
export type ReviewClassification = "SAFE_TO_RUN" | "WARNING" | "BLOCKED";

/**
 * The five AI Compliance Gate sub-gates, per
 * PHASE-5-CN-AI-COMPLIANCE-GATE-MINIMUM-DESIGN-LOCK.md and
 * PHASE-5-CN-AI-COMPLIANCE-GATE-OPTION-B-IMPLEMENTATION-PLAN-LOCK.md.
 */
export type ReviewSubGate =
  | "COMMAND_OUTPUT_CONTRACT"
  | "MANUAL_ACTION_CONTRACT"
  | "EVIDENCE_CLAIM"
  | "STATE_PHASE_BOUNDARY"
  | "RESTORE_RECOVERY_REPORTING";

/**
 * A single rule violation/observation found in the reviewed text.
 *
 * - excerpt is a short, sanitized snippet of the offending text. It must
 *   never contain raw secret-like values (the checker applies a masking
 *   pass before producing excerpts).
 * - explanation is a plain-language description of the risk, suitable for
 *   display directly to the user.
 */
export interface ReviewFinding {
  subGate:     ReviewSubGate;
  ruleId:      string;
  severity:    "BLOCK" | "WARNING";
  excerpt:     string;
  explanation: string;
}

/**
 * Result of reviewAiComplianceText().
 *
 * - checkedSubGates lists which sub-gates were actually evaluated. For
 *   non-empty input this is always all five sub-gates in Phase A. For
 *   empty/whitespace-only input it is empty, and isEmpty is true - this
 *   distinguishes "nothing to review" from "reviewed and found safe",
 *   so a UI must not present an empty-input result as a positive safety
 *   confirmation.
 */
export interface ReviewResult {
  classification:  ReviewClassification;
  findings:        ReviewFinding[];
  checkedSubGates: ReviewSubGate[];
  isEmpty:         boolean;
}

// =============================================================================
// ACTION QUALITY GATE TYPES
// Instructions: Append this entire block to the END of src/types.ts.
// Do NOT modify any existing type in types.ts.
// Do NOT merge with ReviewClassification = "SAFE_TO_RUN" | "WARNING" | "BLOCKED".
//
// Two distinct gate stages:
//   ReviewClassification - AI compliance check (what the AI said)
//   ActionGateStatus     - pre-execution command safety (what the command does)
//
// FINAL_PRODUCT_REQUIREMENT_AI_CONNECTED_AEGIS=True
// =============================================================================

/**
 * Pre-execution gate verdict for a proposed command or action.
 * Intentionally separate from ReviewClassification.
 */
export type ActionGateStatus =
  | "ALLOW"           // Cleared - safe to pass to the next gate
  | "REVIEW_NEEDED"   // Requires human review before execution
  | "SPLIT_REQUIRED"  // Must be split into single-purpose steps
  | "BLOCK";          // Blocked - must not proceed to execution

/**
 * Identifies which caller path invoked the Action Quality Gate.
 * MVP-0: "vscode_command" and "manual_review" only.
 * Future callers are reserved - do NOT remove.
 *
 * FINAL_PRODUCT_REQUIREMENT_AI_CONNECTED_AEGIS=True
 * Future callers: Aegis Protected Terminal, AI Connector, external execution bridge.
 */
export type ActionQualityCallerSource =
  | "vscode_command"        // MVP-0: VS Code command UI
  | "manual_review"         // MVP-0: manual clipboard / selection review (fallback/diagnostic)
  | "protected_terminal"    // future: Aegis Protected Terminal
  | "ai_connector"          // future: AI agent connector
  | "external_gateway";     // future: external AI execution bridge

/**
 * Passed by the caller to evaluateActionQuality().
 * Reserved for future source-specific gate behaviour.
 */
export interface ActionQualityOptions {
  source?: ActionQualityCallerSource;
}

/**
 * Result returned by evaluateActionQuality().
 * Produced for ALL statuses: ALLOW, REVIEW_NEEDED, SPLIT_REQUIRED, BLOCK.
 */
/**
 * SYNTACTIC Level 1 effect metadata detected from command/action text.
 *
 * This is intentionally syntactic metadata only. It records what the Action
 * Quality Gate recognized from text patterns; it does not execute commands,
 * prove semantic intent, or grant runtime authority.
 */
export type ActionQualityDetectedEffectKind =
  | "READ_ONLY_INSPECTION"
  | "CLIPBOARD_WRITE"
  | "REMOTE_SCRIPT_EXECUTION"
  | "DESTRUCTIVE_FILE_OPERATION"
  | "DESTRUCTIVE_GIT_OPERATION"
  | "BUILD_PACKAGE_INSTALL_OR_DEPLOY"
  | "RELEASE_STATE_CLAIM"
  | "LARGE_OR_COMPLEX_COMMAND"
  | "MIXED_OPERATION_CATEGORIES"
  | "UNKNOWN_COMMAND_EFFECT";

export type ActionQualityDetectedEffectLevel = "SYNTACTIC_LEVEL_1";

export type ActionQualityDetectedEffectConfidence = "HIGH" | "MEDIUM" | "LOW";

export interface ActionQualityDetectedEffect {
  level: ActionQualityDetectedEffectLevel;
  kind: ActionQualityDetectedEffectKind;
  confidence: ActionQualityDetectedEffectConfidence;
  sourceRuleId: string;
  description: string;
}
export interface ActionQualityResult {
  /** Pre-execution gate verdict */
  status: ActionGateStatus;
  /** Plain-language message for the user */
  userMessage: string;
  /** One entry per matched rule signal */
  reasons: string[];
  /**
   * SYNTACTIC Level 1 effect metadata detected from text patterns.
   * Always present, including ALLOW and REVIEW_NEEDED results.
   */
  detectedEffects: ActionQualityDetectedEffect[];
  /**
   * Concrete next step - always present when status is BLOCK or SPLIT_REQUIRED.
   */
  nextSafeStep?: string;
  /** Internal rule identifier for diagnostics and logging */
  internalRuleId: string;
  /** Caller source - echoed from ActionQualityOptions, defaults to "manual_review" */
  source: ActionQualityCallerSource;
}

// =============================================================================
// SAFETY KERNEL V3.1 TYPE MODEL
// =============================================================================
// Final-product model definitions only.
// This block is intentionally additive and does not change MVP0 Action Quality
// Gate runtime behavior. Do not merge these decisions with ActionGateStatus until
// a later explicitly approved behavior-connection action.

/**
 * Safety Kernel v3.1 operation capability level.
 */
export type SafetyKernelV31OperationClass =
  | "read"
  | "write"
  | "execute"
  | "network"
  | "delete"
  | "restore";

/**
 * Safety Kernel v3.1 capability scope level.
 */
export type SafetyKernelV31CapabilityScope =
  | "specific_file"
  | "workspace"
  | "protected_file"
  | "configuration"
  | "policy"
  | "policy_surface"
  | "external"
  | "system"
  | "generated_artifact"
  | "connector"
  | "ledger"
  | "receipt";

/**
 * Safety Kernel v3.1 capability manner level.
 */
export type SafetyKernelV31CapabilityManner =
  | "user_visible"
  | "silent"
  | "sandboxed"
  | "unsandboxed"
  | "preview_only"
  | "interactive"
  | "automated"
  | "recovery_only"
  | "auto_execute"
  | "requires_review";

/**
 * Requested capability taxonomy for a proposed action.
 */
export interface SafetyKernelV31CapabilityRequested {
  operation_class: SafetyKernelV31OperationClass;
  scope: SafetyKernelV31CapabilityScope;
  manner: SafetyKernelV31CapabilityManner;
}

/**
 * Declares the mutation boundary for a proposed action.
 */
export interface SafetyKernelV31MutationScope {
  scope: SafetyKernelV31CapabilityScope;
  target: string;
  protected_target: boolean;
}

/**
 * Self-describing handoff capsule ingestion types.
 *
 * SELF_DESCRIBING_HANDOFF_CAPSULE_INGESTION_TYPES_V1
 *
 * These types model the final-product requirement that one uploaded handoff
 * capsule can be detected, verified, and resumed without a separate
 * natural-language instruction.
 */
export type AegisHandoffCapsuleKind =
  | "HANDOFF_RESUME"
  | "RECOVERY_RESUME"
  | "AUDIT_ONLY"
  | "EVIDENCE_LOCK";

export type AegisCapsuleActionClass =
  | "READ_ONLY_VERIFY"
  | "PASSIVE_SCAN"
  | "STATE_INSPECTION"
  | "MUTATION"
  | "BUILD_OR_TEST"
  | "ARTIFACT_CREATE"
  | "FILE_MOVE_OR_DELETE"
  | "QUARANTINE_OR_ARCHIVE"
  | "INSTALL_OR_PACKAGE"
  | "NETWORK_OR_UPLOAD"
  | "FINALIZATION_OR_PRODUCT_PASS"
  | "UNKNOWN_OR_AMBIGUOUS";

export interface AegisCapsuleSafeNextAction {
  actionId: string;
  actionClass: AegisCapsuleActionClass;
  purpose: string;
  preconditions: string[];
  requiredCapability: SafetyKernelV31CapabilityRequested;
  requiredAuthoritySurface: string;
  mutationAllowed: boolean;
  exactMutationFiles: string[];
  forbiddenEffects: string[];
  expectedOutput: "clipboard_summary" | "receipt_ledger" | "ui_summary";
  verificationAfterAction: string;
  rollbackOrRecoveryRule: string;
  approvalRequired: boolean;
}

export interface AegisHandoffCapsuleDescriptor {
  capsuleSchemaVersion: "1.0.0";
  capsuleKind: AegisHandoffCapsuleKind;
  projectId: string;
  authoritySurfaceVersion: string;
  descriptorHash: string;
  /**
   * CAPSULE_DESCRIPTOR_NONCIRCULAR_HASH_MODEL_TYPES_V1
   *
   * The outer ZIP/capsule SHA256 is emitted by the compiler after ZIP creation
   * and must not be embedded inside the descriptor before ZIP creation, because
   * that would create a self-referential hash. The descriptor carries its own
   * canonical descriptorHash and declares where the outer capsule hash appears.
   */
  expectedCapsuleHash: "POST_ZIP_COMPILER_RECEIPT_ONLY_NON_EMBEDDED";
  expectedCapsuleHashModel: "outer_zip_sha256_emitted_after_zip_creation_not_embedded_to_avoid_self_reference";
  expectedCapsuleHashAvailability: "post_zip_compiler_summary";
  currentPhase: string;
  currentLock: string;
  currentResultLockHash: string;
  requiredEntries: string[];
  requiredEntryHashes: Record<string, string>;
  firstRequiredAction: "READ_ONLY_INITIAL_VERIFY_HANDOFF_CAPSULE_FROM_COMMAND_CAPSULE_V1";
  preVerificationForbiddenActions: string[];
  finalProductSafetyFlags: {
    productPassClaimed: false;
    finalZipClaimed: false;
    uploadReadyClaimed: false;
  };
  authorizedReadOnlyActions: string[];
  authorizedMutationActions: string[];
  postVerificationSafeNextActions: AegisCapsuleSafeNextAction[];
  handoffSequence: number;
}

/**
 * Safety Kernel v3.1 nonce value.
 *
 * Nonce lifecycle rules are enforced by the kernel implementation, not by this
 * type alias alone:
 * - ALLOW consumes nonce after execution.
 * - WARN keeps the same nonce pending only during user confirmation.
 * - WARN cancel/timeout consumes nonce and returns to IDLE.
 * - REQUIRE_REVIEW cannot execute until a new nonce is issued.
 * - SPLIT_REQUIRED invalidates the parent envelope and requires child nonces.
 */
export type SafetyKernelV31ApprovalNonce = string;

/**
 * Risk class used by envelope, receipt, and ledger surfaces.
 */
export type SafetyKernelV31RiskClass =
  | "safe"
  | "low"
  | "medium"
  | "high"
  | "critical";

/**
 * Safety Kernel v3.1 decision model.
 *
 * Distinct from MVP0 ActionGateStatus:
 * - WARN is a pending-confirmation decision and must never auto-proceed.
 * - REQUIRE_REVIEW is review-only and must not execute under the old nonce.
 * - SPLIT_REQUIRED requires new child envelopes/nonces.
 */
export type SafetyKernelV31KernelDecision =
  | "ALLOW"
  | "WARN"
  | "BLOCK"
  | "REQUIRE_REVIEW"
  | "SPLIT_REQUIRED";

/**
 * L3 canonical action proposal.
 *
 * This record contains no execution authority and no raw approval nonce.
 * Authority versions and workspace identity are bound locally from L2.
 */
export interface SafetyKernelV31ActionProposal {
  action_id: string;
  external_action_id: string;
  source: ActionQualityCallerSource;
  capability_id: string;
  intent: string;
  proposed_action: string;
  declared_effects: string[];
  target_paths: string[];
  command_template_hash: string;
  mutation_scope: SafetyKernelV31MutationScope;
  policy_version: string;
  ruleset_version: string;
  capability_manifest_version: string;
  workspace_id: string;
  session_id: string | null;
  approval_nonce_supplied: false;
  execution_authority_granted: false;
}

/**
 * Final-product action envelope required before kernel decision.
 */
export interface SafetyKernelV31ActionEnvelope {
  action_id: string;
  source: ActionQualityCallerSource;
  target: string;
  intent: string;
  proposed_action: string;
  risk_class: SafetyKernelV31RiskClass;
  context_hash: string;
  timestamp: string;
  adapter_id: string;
  human_readable_summary: string;

  capability_requested: SafetyKernelV31CapabilityRequested;
  mutation_scope: SafetyKernelV31MutationScope;
  approval_nonce: SafetyKernelV31ApprovalNonce;
  policy_version: string;
}

/**
 * Kernel decision result associated with an action envelope.
 */

/**
 * Explicit Safety Kernel v3.1 decision model anchor.
 *
 * Ties the action envelope, kernel decision enum, and decision result together.
 * WARN is pending-confirmation only, REQUIRE_REVIEW is review-only, and
 * SPLIT_REQUIRED invalidates the parent envelope and requires child nonces.
 */
export interface SafetyKernelV31DecisionModel {
  envelope: SafetyKernelV31ActionEnvelope;
  decision: SafetyKernelV31KernelDecision;
  result: SafetyKernelV31KernelDecisionResult;
}
export interface SafetyKernelV31KernelDecisionResult {
  action_id: string;
  decision: SafetyKernelV31KernelDecision;
  approval_nonce: SafetyKernelV31ApprovalNonce;
  policy_version: string;
  reasons: string[];
  detectedEffects?: ActionQualityDetectedEffect[];
  human_readable_summary: string;
  receipt_required: true;
  ledger_required: true;
}

/**
 * WARN pending-confirmation state.
 */
export interface SafetyKernelV31WarnPendingConfirmation {
  action_id: string;
  approval_nonce: SafetyKernelV31ApprovalNonce;
  timeout_seconds: number;
  timeout_default_seconds: 60;
  timeout_min_seconds: 15;
  timeout_max_seconds: 300;
  warn_must_never_auto_proceed: true;
}

/**
 * Receipt/ledger evidence required when WARN pending confirmation ends
 * without execution.
 *
 * timeout_expired and cancel_by_user consume the pending nonce, return the
 * session to IDLE, and must never auto-proceed.
 */
export type SafetyKernelV31WarnTerminalEvidenceReason =
  | "timeout_expired"
  | "cancel_by_user";

export interface SafetyKernelV31WarnTerminalEvidence {
  action_id: string;
  approval_nonce: SafetyKernelV31ApprovalNonce;
  reason: SafetyKernelV31WarnTerminalEvidenceReason;
  nonce_consumed: true;
  return_state: "IDLE";
  receipt_required: true;
  ledger_required: true;
  warn_must_never_auto_proceed: true;
}

export interface SafetyKernelV31WarnConfirmationEvidence {
  action_id: string;
  approval_nonce: SafetyKernelV31ApprovalNonce;
  nonce_consumed: false;
  next_state: "ALLOW_PENDING_EXECUTION";
  receipt_required: true;
  ledger_required: true;
  execution_authority_granted: false;
}

export interface SafetyKernelV31AllowedExecutionCompletionBinding {
  authority_revision: number;
  command_sha256: string;
  snapshot_binding_sha256: string;
  exit_code: 0;
  stdout_sha256: string;
  stderr_sha256: string;
  stdout_bytes: number;
  stderr_bytes: number;
}

export interface SafetyKernelV31AllowedExecutionCompletionEvidence {
  action_id: string;
  approval_nonce: SafetyKernelV31ApprovalNonce;
  nonce_consumed: true;
  receipt_required: true;
  ledger_required: true;
  execution_binding?: SafetyKernelV31AllowedExecutionCompletionBinding;
}

export type SafetyKernelV31AllowedExecutionAbortReason =
  | "snapshot_failed"
  | "authority_drift"
  | "execution_failed"
  | "cancel_by_user";

export interface SafetyKernelV31AllowedExecutionAbortEvidence {
  action_id: string;
  approval_nonce: SafetyKernelV31ApprovalNonce;
  reason: SafetyKernelV31AllowedExecutionAbortReason;
  nonce_consumed: true;
  execution_completed: false;
  return_state: "IDLE";
  receipt_required: true;
  ledger_required: true;
}

/**
 * Non-overridable final-product kernel invariants.
 */
export type SafetyKernelV31NonOverridableInvariant =
  | "deny_by_default"
  | "no_raw_command_auto_execution_without_kernel_allow"
  | "no_nonce_reuse"
  | "no_kernel_bypass"
  | "no_receipt_ledger_bypass"
  | "no_no_upload_bypass"
  | "no_protected_write_without_restore_point"
  | "adapter_cannot_override_kernel_decision"
  | "local_first_action_decision"
  | "server_cannot_decide_targeted_user_action_allow_block";

/**
 * Server revocation is metadata-only authority.
 *
 * The server may revoke ruleset, policy, signing-key, version, and freshness
 * metadata. It must not decide targeted allow/block outcomes for a specific
 * user action; the local client remains the decision authority.
 */
export type SafetyKernelV31ServerRevocationMetadataScope =
  | "ruleset_metadata"
  | "policy_metadata"
  | "signing_key_metadata"
  | "version_metadata"
  | "freshness_metadata";

export interface SafetyKernelV31ServerRevocationMetadataLimit {
  server_revocation_metadata_only: true;
  allowed_revocation_scopes: SafetyKernelV31ServerRevocationMetadataScope[];
  server_cannot_decide_targeted_user_action_allow_block: true;
  local_client_remains_decision_authority: true;
}

export const SAFETY_KERNEL_V31_SERVER_REVOCATION_METADATA_LIMIT: SafetyKernelV31ServerRevocationMetadataLimit = {
  server_revocation_metadata_only: true,
  allowed_revocation_scopes: [
    "ruleset_metadata",
    "policy_metadata",
    "signing_key_metadata",
    "version_metadata",
    "freshness_metadata"
  ],
  server_cannot_decide_targeted_user_action_allow_block: true,
  local_client_remains_decision_authority: true
};

/**
 * Workspace-local trusted capability constraints.
 *
 * Workspace-local trusted capabilities may only narrow or add allowed
 * capabilities and must not weaken non-overridable kernel invariants.
 */
export interface SafetyKernelV31WorkspaceLocalTrustedCapabilityConstraint {
  workspace_local_trusted_capability_source: "workspace_local_policy";
  may_only_narrow_or_add_allowed_capabilities: true;
  cannot_weaken_non_overridable_invariants: true;
  cannot_grant_silent_auto_execute: true;
  cannot_grant_system_scope_bypass: true;
  cannot_bypass_receipt_ledger: true;
  cannot_permit_nonce_reuse: true;
  cannot_bypass_kernel: true;
  cannot_bypass_no_upload: true;
}

export const SAFETY_KERNEL_V31_WORKSPACE_LOCAL_TRUSTED_CAPABILITY_CONSTRAINT: SafetyKernelV31WorkspaceLocalTrustedCapabilityConstraint = {
  workspace_local_trusted_capability_source: "workspace_local_policy",
  may_only_narrow_or_add_allowed_capabilities: true,
  cannot_weaken_non_overridable_invariants: true,
  cannot_grant_silent_auto_execute: true,
  cannot_grant_system_scope_bypass: true,
  cannot_bypass_receipt_ledger: true,
  cannot_permit_nonce_reuse: true,
  cannot_bypass_kernel: true,
  cannot_bypass_no_upload: true
};

// =============================================================================
// SAFETY KERNEL V3.1 ACTION QUALITY BRIDGE HELPERS
// =============================================================================
// Bridge-only helpers for connecting the existing MVP0 Action Quality Gate model
// to the Safety Kernel v3.1 decision vocabulary.
//
// This block is intentionally side-effect free:
// - It does not call evaluateActionQuality.
// - It does not execute commands.
// - It does not consume or issue nonces.
// - It does not create WARN pending-confirmation state.
// - It does not write receipts or ledger entries.
// - It does not change runtime behavior unless a later approved caller imports it.

/**
 * Safety Kernel v3.1 decision subset that can be derived from the existing
 * MVP0 ActionGateStatus.
 *
 * WARN is intentionally excluded. WARN requires pending-confirmation state,
 * same-nonce review semantics, timeout handling, and receipt/ledger recording.
 * Existing REVIEW_NEEDED maps to REQUIRE_REVIEW, not WARN.
 */
export type SafetyKernelV31ActionQualityBridgeDecision = Exclude<
  SafetyKernelV31KernelDecision,
  "WARN"
>;

/**
 * Bridge-only result for diagnostics and future connection work.
 */
export interface SafetyKernelV31ActionQualityBridgeResult {
  action_gate_status: ActionGateStatus;
  kernel_decision: SafetyKernelV31ActionQualityBridgeDecision;
  internalRuleId: string;
  source: ActionQualityCallerSource;
  detectedEffects: ActionQualityDetectedEffect[];
  bridge_only: true;
  runtime_enforced: false;
  warning: string;
}

/**
 * Maps the existing MVP0 ActionGateStatus vocabulary into the Safety Kernel
 * v3.1 decision vocabulary without changing runtime behavior.
 */
export function mapActionGateStatusToSafetyKernelV31Decision(
  status: ActionGateStatus
): SafetyKernelV31ActionQualityBridgeDecision {
  switch (status) {
    case "ALLOW":
      return "ALLOW";
    case "REVIEW_NEEDED":
      return "REQUIRE_REVIEW";
    case "SPLIT_REQUIRED":
      return "SPLIT_REQUIRED";
    case "BLOCK":
      return "BLOCK";
    default: {
      const exhaustive: never = status;
      return exhaustive;
    }
  }
}

/**
 * Converts an existing ActionQualityResult into a bridge-only Safety Kernel v3.1
 * diagnostic result.
 *
 * This is not a kernel decision transaction and must not be treated as nonce
 * execution authority.
 */
export function bridgeActionQualityResultToSafetyKernelV31Decision(
  result: ActionQualityResult
): SafetyKernelV31ActionQualityBridgeResult {
  return {
    action_gate_status: result.status,
    kernel_decision: mapActionGateStatusToSafetyKernelV31Decision(result.status),
    internalRuleId: result.internalRuleId,
    source: result.source,
  detectedEffects: result.detectedEffects,
    bridge_only: true,
    runtime_enforced: false,
    warning:
      "Bridge-only mapping. This does not execute, consume a nonce, create WARN pending state, or write receipt/ledger evidence.",
  };
}


// =============================================================================
// SAFETY KERNEL V3.1 CAPABILITY MANIFEST SOURCE OF TRUTH
// =============================================================================
// This block is local-client source-of-truth metadata for final-product Safety
// Kernel v3.1 capability evaluation. It is intentionally data/type-only.
// It does not execute commands, consume nonces, bypass receipts, or create
// upload/final/product-pass authority.

export type SafetyKernelV31CapabilityManifestId =
  | "local_client_default_v1";

export type SafetyKernelV31CapabilityActionKind =
  | "review_ai_command_or_action"
  | "protected_terminal_insert_review"
  | "ai_execution_gateway_review";

export type SafetyKernelV31CapabilityEffectScope =
  | "review_output_only"
  | "terminal_text_insert_only";

export type SafetyKernelV31CapabilityTargetScope = "workspace_only";
export type SafetyKernelV31CapabilityApprovalRequirement =
  "safety_kernel_review_required";

export interface SafetyKernelV31CapabilityManifestEntry {
  capability_id: string;
  action_kind: SafetyKernelV31CapabilityActionKind;
  artifact_kinds: string[];
  command_template_hashes: string[];
  effect_scope: SafetyKernelV31CapabilityEffectScope;
  target_scope: SafetyKernelV31CapabilityTargetScope;
  approval_requirement: SafetyKernelV31CapabilityApprovalRequirement;
  handler_id: string;
  operation_class: SafetyKernelV31OperationClass;
  scope: SafetyKernelV31CapabilityScope;
  manner: SafetyKernelV31CapabilityManner;
  allowed_sources: ActionQualityCallerSource[];
  user_configurable: boolean;
  non_overridable_invariants: SafetyKernelV31NonOverridableInvariant[];
}

export interface SafetyKernelV31CapabilityManifest {
  manifest_id: SafetyKernelV31CapabilityManifestId;
  manifest_version: string;
  policy_version: string;
  source_of_truth: "local_client_capability_manifest";
  trusted_capabilities: SafetyKernelV31CapabilityManifestEntry[];
  non_overridable_invariants: SafetyKernelV31NonOverridableInvariant[];
  server_may_only_narrow_or_add_allowed_capabilities: true;
  server_cannot_grant_bypass: true;
}

export const SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH: SafetyKernelV31CapabilityManifest = {
  manifest_id: "local_client_default_v1",
  manifest_version: "0.1.0-mvp0",
  policy_version: "safety-kernel-v3.1-local-client-mvp0",
  source_of_truth: "local_client_capability_manifest",
  trusted_capabilities: [
    {
      capability_id: "manual_review_preview_only",
      action_kind: "review_ai_command_or_action",
      artifact_kinds: [],
      command_template_hashes: [],
      effect_scope: "review_output_only",
      target_scope: "workspace_only",
      approval_requirement: "safety_kernel_review_required",
      handler_id: "aegis.reviewAiCommandOrAction",
      operation_class: "read",
      scope: "workspace",
      manner: "preview_only",
      allowed_sources: ["manual_review", "vscode_command"],
      user_configurable: true,
      non_overridable_invariants: [
        "deny_by_default",
        "no_kernel_bypass",
        "no_receipt_ledger_bypass",
        "local_first_action_decision"
      ]
    },
    {
      capability_id: "protected_terminal_user_visible_insert_only",
      action_kind: "protected_terminal_insert_review",
      artifact_kinds: [],
      command_template_hashes: [],
      effect_scope: "terminal_text_insert_only",
      target_scope: "workspace_only",
      approval_requirement: "safety_kernel_review_required",
      handler_id: "aegis.protectedTerminal",
      operation_class: "execute",
      scope: "workspace",
      manner: "requires_review",
      allowed_sources: ["protected_terminal"],
      user_configurable: true,
      non_overridable_invariants: [
        "deny_by_default",
        "no_raw_command_auto_execution_without_kernel_allow",
        "no_nonce_reuse",
        "no_kernel_bypass",
        "no_receipt_ledger_bypass",
        "local_first_action_decision"
      ]
    },
    {
      capability_id: "ai_gateway_review_only",
      action_kind: "ai_execution_gateway_review",
      artifact_kinds: [],
      command_template_hashes: [],
      effect_scope: "review_output_only",
      target_scope: "workspace_only",
      approval_requirement: "safety_kernel_review_required",
      handler_id: "aegis.aegisExecutionGatewayMvp0",
      operation_class: "execute",
      scope: "workspace",
      manner: "requires_review",
      allowed_sources: ["ai_connector"],
      user_configurable: true,
      non_overridable_invariants: [
        "deny_by_default",
        "no_raw_command_auto_execution_without_kernel_allow",
        "no_nonce_reuse",
        "no_kernel_bypass",
        "no_receipt_ledger_bypass",
        "local_first_action_decision",
        "server_cannot_decide_targeted_user_action_allow_block"
      ]
    }
  ],
  non_overridable_invariants: [
    "deny_by_default",
    "no_raw_command_auto_execution_without_kernel_allow",
    "no_nonce_reuse",
    "no_kernel_bypass",
    "no_receipt_ledger_bypass",
    "no_no_upload_bypass",
    "no_protected_write_without_restore_point",
    "adapter_cannot_override_kernel_decision",
    "local_first_action_decision",
    "server_cannot_decide_targeted_user_action_allow_block"
  ],
  server_may_only_narrow_or_add_allowed_capabilities: true,
  server_cannot_grant_bypass: true
};

/**
 * FINAL_PRODUCT_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS_V1
 *
 * Final-product contract:
 * - Known preconditions supplied by a handoff/capsule are active contract state.
 * - A confirmed missing authorized path with a recovery objective is RECOVERY_REQUIRED,
 *   not a reason to rediscover the path or stop the objective.
 * - Denial labels are evidence, not schema or capability authority.
 * - getRuleset recovery must proceed only through an owner-approved recovery envelope.
 */
export type SafetyKernelV31KnownPreconditionStatus =
  | "confirmed"
  | "unconfirmed"
  | "superseded";

export type SafetyKernelV31KnownPreconditionTreatment =
  | "do_not_rediscover"
  | "investigate";

export type SafetyKernelV31KnownPreconditionNextState =
  | "RECOVERY_REQUIRED"
  | "ALLOW_READ_ONLY"
  | "BLOCK_REDISCOVERY_FORBIDDEN"
  | "BLOCK_OBJECTIVE_REVERSAL";

export interface SafetyKernelV31KnownPrecondition {
  id: "AUTHORIZED_PATH_MISSING_DENIAL_GETRULESET" | string;
  status: SafetyKernelV31KnownPreconditionStatus;
  treatment: SafetyKernelV31KnownPreconditionTreatment;
  rediscoveryForbidden: boolean;
  objective?: "CREATE_AUTHORIZED_RECOVERY_PATH" | string;
  nextState: SafetyKernelV31KnownPreconditionNextState | string;
}

export interface SafetyKernelV31KnownPreconditionLedger {
  knownPreconditions: SafetyKernelV31KnownPrecondition[];
  forbiddenFirstActions: string[];
  requiredFirstActionClass:
    | "PATCH_ANCHOR_CAPTURE_OR_RECOVERY_ENVELOPE"
    | "OWNER_AUTHORIZED_RECOVERY_MUTATION"
    | string;
  objective: {
    id: "CREATE_AUTHORIZED_RECOVERY_PATH" | string;
    immutable: true;
  };
}

export const SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS = {
  known_precondition_ledger_required: true,
  handoff_contract_semantic_ingestion_gate_required: true,
  objective_preservation_gate_required: true,
  rediscovery_loop_guard_required: true,
  missing_path_recovery_classifier_required: true,
  owner_recovery_envelope_required: true,
  denial_label_is_evidence_not_schema: true,
  getRuleset_authorized_recovery_path_required: true,
  confirmed_missing_path_with_recovery_objective_is_recovery_required_not_stop: true,
  negative_selftests: [
    "BLOCK_REDISCOVERY_FORBIDDEN",
    "BLOCK_OBJECTIVE_REVERSAL",
    "ALLOW_READ_ONLY_PATCH_ANCHOR_CAPTURE",
    "ALLOW_OWNER_RECOVERY_ENVELOPE_VALID"
  ]
} as const;

/**
 * FINAL_PRODUCT_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS_V1
 *
 * Top-priority final-product contract:
 * - Do not infer or assume file names, helper names, function signatures,
 *   script names, required ZIP entries, currentPhase, lock files, checker
 *   results, runner authority, compiler surfaces, or final/upload/product
 *   status.
 * - Verify the actual authority surface before deciding or mutating.
 * - The exception is a confirmed Known Precondition Ledger fact marked
 *   rediscoveryForbidden=true, which must be preserved instead of rechecked.
 */
export type SafetyKernelV31NoGuessingVerificationTarget =
  | "file"
  | "helper"
  | "function_signature"
  | "script"
  | "required_zip_entry"
  | "current_phase"
  | "lock_file"
  | "checker_result"
  | "runner_authority"
  | "compiler_surface"
  | "final_status";

export interface SafetyKernelV31NoGuessingAlwaysVerifyPolicy {
  topPriorityRule: "NO_GUESSING_ALWAYS_VERIFY";
  assumptionForbidden: true;
  verifyBeforeDecision: true;
  verifyBeforeMutation: true;
  verifyTargets: SafetyKernelV31NoGuessingVerificationTarget[];
  knownPreconditionRediscoveryException: "PRESERVE_DO_NOT_REDISCOVER_CONFIRMED_KPL_FACTS";
  finalStatusMustComeFromExplicitGateResult: true;
}

/**
 * FINAL_PRODUCT_SOURCE_OF_TRUTH_DISCIPLINE_REQUIREMENTS_V1
 */
export type SafetyKernelV31SourceOfTruthFactCategory =
  | "VERIFIED_FROM_PRIMARY_SOURCE"
  | "ESTABLISHED_PRIOR_FACT"
  | "UNVERIFIED_APPEARANCE";

export const SAFETY_KERNEL_V31_SOURCE_OF_TRUTH_DISCIPLINE_REQUIREMENTS = {
  gate: "SOURCE_OF_TRUTH_DISCIPLINE_GATE",
  categories: ["VERIFIED_FROM_PRIMARY_SOURCE", "ESTABLISHED_PRIOR_FACT", "UNVERIFIED_APPEARANCE"] as const,
  failure_label_is_not_schema_authority: true,
  filename_or_shape_is_not_authorized_provenance: true,
  sandbox_artifact_requires_authorized_provenance: true,
  assistant_claim_is_not_source_of_truth: true,
  established_prior_fact_must_not_be_rediscovered: true,
  receipt_is_past_decision_not_current_truth: true,
  written_requirement_overrides_chat_paraphrase: true,
  stale_in_context_summary_forbidden_for_decision: true,
  approval_scope_creep_forbidden: true,
  prior_fact_value_change_requires_supersession: true,
} as const;

export const SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS = {
  top_priority_rule: "NO_GUESSING_ALWAYS_VERIFY",
  assumption_forbidden: true,
  verify_before_decision: true,
  verify_before_mutation: true,
  final_status_must_come_from_explicit_gate_result: true,
  required_requirements: [
    "FINAL_PRODUCT_REQUIREMENT=NO_GUESSING_ALWAYS_VERIFY",
    "FINAL_PRODUCT_REQUIREMENT=ASSUMPTION_FREE_AUTHORITY",
    "FINAL_PRODUCT_REQUIREMENT=VERIFY_BEFORE_DECISION",
    "FINAL_PRODUCT_REQUIREMENT=EXPLICIT_GATE_RESULT_FOR_FINAL_STATUS"
  ],
  forbidden_inferences: [
    "helper_name_guess",
    "function_signature_guess",
    "required_zip_entry_guess",
    "current_phase_guess",
    "lock_file_guess",
    "compiler_surface_guess",
    "final_product_pass_guess",
    "upload_ready_guess",
    "final_zip_guess"
  ],
  rediscovery_exception: "do_not_rediscover_confirmed_known_preconditions"
} as const;
