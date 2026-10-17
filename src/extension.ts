import { evaluateAiExecutionGatewayExplicitExecutionMvp0Capability } from "./aiExecutionGatewayExplicitExecutionMvp0Capability";
import {
  clearEditorSaveWatcherEvent,
  consumeEditorSaveWatcherEvent,
  markEditorSaveWatcherEvent,
} from "./oneShotSaveWatcherSuppression";
//
// WHAT CHANGED IN PHASE 2-A
//
//   Added:  aegis.showProtectionPanel command
//   Changed: handleDidSave now updates StateManager instead of only showing messages
//   Changed: handleRestore now updates StateManager through all transitions
//
// WHAT CHANGED IN PHASE 2-B
//
//   Changed: handleDidSave appends snapshot_created after verified snapshot
//   Changed: handleRestore appends restore_completed or restore_failed after result
//
// WHAT CHANGED IN FIX PHASE 4
//
//   Problem: store.hasIndex() was not a reliable signal for "meaningful baseline
//   exists." VS Code Explorer auto-save of an empty .env could create
//   latest-safe-snapshot.json before the user's first intentional two-line save,
//   causing that first save to incorrectly trigger BLOCKED (Layer 1 bug).
//   Additionally, the pre-save snapshot of the first meaningful save contained
//   "" (empty string), so Restore would return an empty .env, not the two-line
//   baseline (Layer 2 bug).
//
//   Fix:
//   - Added readBaselineMarker() / writeBaselineMarker() helpers that read/write
//   - handleDidSave now uses the marker (not store.hasIndex()) to determine
//     whether a meaningful baseline has been registered.
//   - If no marker: baseline registration path.
//       - Post-save content read from disk after onDidSaveTextDocument.
//       - If empty/whitespace: keep SAFE, no marker, no snapshot update.
//       - If non-empty: call store.createBaselineSnapshotFromContent() to create
//         a verified snapshot of the two-line content. Write marker only after
//         snapshot verification succeeds. Keep SAFE.
//   - If marker present: existing pre-save snapshot path. BLOCKED as before.
//   - Pre-save baseline (capturePreSave / consumePending) is still consumed in
//     all paths to prevent stale pending entries accumulating.
//   - createSnapshot() is NOT called in the baseline registration path so that
//     latest-safe-snapshot.json is never poisoned with empty content.
//
// WHAT CHANGED IN FIX PHASE 5-C-FIX-01
//
//   Problem: StateManager always initialises with status="SAFE". On every VS Code
//   reload or restart, initializeAegis() created a fresh StateManager() and never
//   compared the current on-disk .env against the stored safe baseline. The result:
//   BLOCKED was silently reset to SAFE on every reload, even if .env still contained
//   a protected change.
//
//   Fix:
//     after watchers are registered, before the Risk Scan.
//   - Reads baseline marker: if absent, no rehydration needed (workspace unregistered).
//   - Reads latest-safe-snapshot.json: if absent or corrupt, sets WARNING.
//   - Reads current .env from disk: if absent, SAFE (nothing to protect).
//   - Computes SHA-256 of current .env and compares to index.content_sha256.
//   - Raw .env content is NEVER logged, stored, or written to UI/ledger/receipt.
//     a new user action. Ledger truthfulness is preserved.
//
// WHAT IS UNCHANGED FROM PHASE 1 / PHASE 2-A / PHASE 2-B / FIX PHASE 4
//
//   onWillSaveTextDocument + event.waitUntil baseline capture
//   capturePreSave / consumePending pattern
//   initial_creation handling
//   createSnapshot() used for all protected-change saves (marker present)
//   latest-safe-snapshot.json only updated after full verification
//   lockedAbsPath / removeRestoring in finally
//   refreshEditor returns boolean; handleRestore branches on it
//
// ORCHESTRATOR RESPONSIBILITIES (this file)
//
//   [1] Register commands (synchronous, before any I/O)
//   [3] Wire up StateManager
//   [4] Wire up AegisWebviewPanel as dumb subscriber
//       Fix Phase 4: baseline registration path uses post-save content
//   [8] rehydrateStateOnActivation: Fix Phase 5-C-FIX-01
//       On every activation, compare current .env hash to safe baseline hash.
//       Set BLOCKED if they differ. No ledger event. No raw content logged.

import * as vscode   from "vscode";
import * as nodePath from "path";
import * as fs       from "fs";

import { LedgerErrorCode, LedgerReason, BaselineRegistrationMarker, AegisUiState } from "../packages/aegis-core";
import { EnvCoreEngine }     from "./envCoreEngine";
import { SnapshotStore }     from "./snapshotStore";
import { StateManager }      from "../packages/aegis-core";
import { CanonicalAuthorityStateStore, type CanonicalAuthorityKernelLifecyclePhase, type CanonicalAuthorityKernelTerminalReason } from "./canonicalAuthorityState";
import { CanonicalAuthorityStateFilePersistence } from "./canonicalAuthorityStateFilePersistence";
import { compileArtifact } from "./artifactCompiler";
import { preflightArtifactIntent } from "./artifactIntentPreflight";
import { classifyArtifactAuthoritySurface } from "./authoritySurfaceClassifier";
import { verifyPostArtifactInternalAuthority } from "./postArtifactAuthorityVerifier";
import { buildVerifiedArtifactResponsePlan } from "./responseRenderingGate";
import { LedgerWriter }      from "./ledgerWriter";
import { ReceiptWriter }     from "./receiptWriter";   // Phase 2-C2
import { AegisWebviewPanel } from "./webviewPanel";
import { getCapabilitiesForTier, getLicenseTier, isCapabilityAvailableForTier, type LicenseCapability, type LicenseTier } from "./licenseTier";
import {
  createServerRulesetExtensionProductionComposition,
  type ServerRulesetExtensionProductionComposition,
  type ServerRulesetExtensionProductionEvaluationResult,
} from "./serverRulesetExtensionProductionComposition";
import {
  createServerRulesetExtensionProductionSupplyAdapter,
  type ServerRulesetExtensionProductionSupplyAdapterIssue,
  type ServerRulesetExtensionProductionSupplyAdapterStatus,
} from "./serverRulesetExtensionProductionSupplyAdapter";
import { isInsideAegisDir, sha256OfString, isProtectedTargetFile, describeRealpathTargetBinding } from "./pathUtils";
import { runRiskScan, RiskScanResult } from "./riskScan";  // Phase 3-A
import {
  getProtectedTargets,
  getTargetByRelPath,
  type ProtectedTarget,
}                                      from "../packages/aegis-core";  // Phase 5-M / Phase 5-P


import {
  buildReviewAiCommandMvp0ClipboardText,
  buildReviewAiCommandMvp0Markdown,
  classifyReviewAiCommandMvp0Action,
  combineReviewAiCommandMvp0WithActionQuality,
  sanitizeReviewAiCommandMvp0Text,
  type ReviewAiCommandMvp0InputSource,
} from "./reviewAiCommandMvp0Policy";
import { evaluateActionQuality } from "../packages/aegis-core";
import { formatActionGateSection } from "../packages/aegis-core";
import { spawnNodeProcess } from "./nodeProcessExecutionAdapter";
import { createSafetyKernelV31NodeProcessExtensionBootstrapComposition } from "./safetyKernelV31NodeProcessExtensionBootstrapComposition";
import type { SafetyKernelV31AuthoritySnapshotBindingComposition } from "../packages/aegis-core";
import { createSafetyKernelV31SnapshotTargetIndexReaderCollection } from "./safetyKernelV31SnapshotTargetIndexReaderCollectionFactory";
import { SafetyKernelV31RuntimeController } from "./safetyKernelV31RuntimeController";
import {
  createSessionHandoffExtensionProductionVerificationComposition,
  type SessionHandoffProductionVerificationComposition,
} from "./sessionHandoffProductionVerificationComposition";
import {
  VerifierRecursionGuard,
  verifyVerifierGraphAcyclic,
} from "../packages/aegis-core";
import { createVscodePlatformPorts } from "./vscodePlatformAdapter";
import {
  buildAiExecutionGatewayMvp0CanonicalProposal,
  buildAiExecutionGatewayMvp0FinalReviewedOnlyReceiptLines,
  buildAiExecutionGatewayMvp0InvalidBootstrapCapsuleReceiptLines,
  buildAiExecutionGatewayMvp0InvalidEnvelopeReceiptLines,
  buildAiExecutionGatewayMvp0NoAuthorizedSurfaceReceiptLines,
  buildAiExecutionGatewayMvp0WorkflowDriftBlockedReceiptLines,
  detectAiExecutionGatewayMvp0WorkflowDrift,
  evaluateAiExecutionGatewayMvp0ActionQuality,
  enforceAiExecutionGatewayMvp0EffectPreflight,
  hasAuthorizedAiExecutionGatewayMvp0Surface,
  parseAiExecutionGatewayMvp0Envelope,
  validateAiExecutionGatewayMvp0BootstrapCapsule,
  validateAiExecutionGatewayMvp0UserDefinedRuleSet,
  evaluateAiExecutionGatewayMvp0UserDefinedRules,
  buildAiExecutionGatewayMvp0UserDefinedRuleBlockedReceiptLines,
  buildAiExecutionGatewayMvp0InvalidUserDefinedRuleSetReceiptLines,
  buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines,
  type AiExecutionGatewayMvp0UserDefinedRuleSet,
} from "./aiExecutionGatewayMvp0Policy";
import {
  buildProtectedTerminalMvp0AutosnapshotBlockedMarkdown,
  buildProtectedTerminalMvp0AutosnapshotClipboardText,
  evaluateProtectedTerminalMvp0Review,
} from "./protectedTerminalMvp0Policy";

const _platformPorts = createVscodePlatformPorts();
let _licenseTier: LicenseTier = "free";
let _serverRulesetProductionComposition:
  ServerRulesetExtensionProductionComposition | null =
  null;

let _serverRulesetProductionAdapterStatus:
  ServerRulesetExtensionProductionSupplyAdapterStatus =
  "DISABLED";

let _serverRulesetProductionAdapterIssue:
  ServerRulesetExtensionProductionSupplyAdapterIssue =
  "CANONICAL_TRUST_MATERIAL_ABSENT";

let _serverRulesetExtensionRoot:
  string | null =
  null;

function withLicenseTier(state: AegisUiState): AegisUiState {
  return { ...state, licenseTier: _licenseTier, licenseCapabilities: getCapabilitiesForTier(_licenseTier) };
}

function isCurrentLicenseCapabilityAvailable(capability: LicenseCapability): boolean {
  return isCapabilityAvailableForTier(_licenseTier, capability);
}

function resolveServerRulesetExtensionRoot(
  context: vscode.ExtensionContext
): string {
  const extensionUriPath =
    context.extensionUri?.fsPath;

  if (
    typeof extensionUriPath === "string" &&
    extensionUriPath.trim().length > 0
  ) {
    return nodePath.resolve(
      extensionUriPath
    );
  }

  const extensionPath =
    context.extensionPath;

  if (
    typeof extensionPath === "string" &&
    extensionPath.trim().length > 0
  ) {
    return nodePath.resolve(
      extensionPath
    );
  }

  return nodePath.resolve(
    __dirname,
    ".."
  );
}

function serverRulesetDistributionChannelForLicenseTier(
  tier: LicenseTier
): "free-stable" | "fast-strict" {
  return (
    tier === "pro"
      ? "fast-strict"
      : "free-stable"
  );
}

function resetServerRulesetProductionConnection(): void {
  _serverRulesetProductionComposition =
    null;

  _serverRulesetProductionAdapterStatus =
    "DISABLED";

  _serverRulesetProductionAdapterIssue =
    "CANONICAL_TRUST_MATERIAL_ABSENT";

  _serverRulesetExtensionRoot =
    null;
}

async function initializeServerRulesetProductionConnection(
  context: vscode.ExtensionContext,
  projectRoot: string
): Promise<void> {
  const extensionRoot =
    resolveServerRulesetExtensionRoot(
      context
    );

  _serverRulesetExtensionRoot =
    extensionRoot;

  _serverRulesetProductionComposition =
    null;

  try {
    const adapter =
      await createServerRulesetExtensionProductionSupplyAdapter({
        extensionRoot,
        workspaceRoot:
          projectRoot,
        distributionChannel:
          serverRulesetDistributionChannelForLicenseTier(
            _licenseTier
          ),
      });

    _serverRulesetProductionAdapterStatus =
      adapter.status;

    _serverRulesetProductionAdapterIssue =
      adapter.issue;

    if (
      adapter.status ===
      "DISABLED"
    ) {
      return;
    }

    if (
      adapter.status ===
      "REJECTED"
    ) {
      return;
    }

    try {
      _serverRulesetProductionComposition =
        createServerRulesetExtensionProductionComposition(
          adapter.ports
        );
    } catch {
      _serverRulesetProductionComposition =
        null;

      _serverRulesetProductionAdapterStatus =
        "REJECTED";

      _serverRulesetProductionAdapterIssue =
        "DEPENDENCIES_INVALID";
    }
  } catch {
    _serverRulesetProductionComposition =
      null;

    _serverRulesetProductionAdapterStatus =
      "REJECTED";

    _serverRulesetProductionAdapterIssue =
      "PERSISTENCE_INITIALIZATION_FAILED";
  }
}

function buildServerRulesetProductionConnectionBlockedReceiptLines(
  status:
    ServerRulesetExtensionProductionSupplyAdapterStatus,
  issue:
    ServerRulesetExtensionProductionSupplyAdapterIssue
): readonly string[] {
  return Object.freeze([
    ...buildAiExecutionGatewayMvp0ServerRulesetBlockedReceiptLines({
      resolutionAccepted:
        false,
      resolutionSource:
        null,
      matchedRuleId:
        "",
      matchedCategory:
        null,
      reason:
        "SERVER_RULESET_RESOLUTION_REJECTED",
    }),
    "SERVER_RULESET_EXTENSION_ADAPTER_STATUS=" +
      status,
    "SERVER_RULESET_EXTENSION_ADAPTER_ISSUE=" +
      issue,
  ]);
}

async function writeServerRulesetProductionBlockedReceipt(
  receiptLines:
    readonly string[],
  warning:
    string
): Promise<void> {
  await _platformPorts
    .clipboard
    .writeText(
      receiptLines.join(
        "\n"
      )
    );

  await _platformPorts
    .ui
    .showWarning(
      warning
    );
}

/**
 * RULESET_ANTI_ROLLBACK_STANDARD_V1
 *
 * Final-product requirement anchor:
 * signed ruleset metadata must enforce monotonic version progression and
 * validity windows. A downloaded or cached ruleset must not replace the active
 * policy when its rulesetVersion moves backward, when notBefore is in the
 * future, when notAfter is expired, or when anti-rollback freshness metadata is
 * missing.
 *
 * This helper is side-effect free and diagnostic-only in this phase. It does
 * not fetch network rules, does not persist policy state, and does not mark
 * product pass.
 */
interface RulesetAntiRollbackMetadata {
  rulesetVersion: number;
  notBefore?: string;
  notAfter?: string;
  monotonicCounter?: number;
}

interface RulesetAntiRollbackAssessment {
  accepted: boolean;
  reason: string | null;
}

function assessRulesetAntiRollbackCandidate(
  active: RulesetAntiRollbackMetadata | null,
  candidate: RulesetAntiRollbackMetadata,
  nowEpochMs: number
): RulesetAntiRollbackAssessment {
  if (!Number.isFinite(candidate.rulesetVersion) || candidate.rulesetVersion < 0) {
    return { accepted: false, reason: "rulesetVersion is missing or invalid" };
  }

  if (active && candidate.rulesetVersion < active.rulesetVersion) {
    return { accepted: false, reason: "anti-rollback: candidate rulesetVersion is older than active rulesetVersion" };
  }

  if (typeof candidate.monotonicCounter === "number" && active && typeof active.monotonicCounter === "number") {
    if (candidate.monotonicCounter < active.monotonicCounter) {
      return { accepted: false, reason: "anti-rollback: candidate monotonicCounter is older than active monotonicCounter" };
    }
  }

  if (candidate.notBefore) {
    const notBeforeMs = Date.parse(candidate.notBefore);
    if (!Number.isFinite(notBeforeMs) || notBeforeMs > nowEpochMs) {
      return { accepted: false, reason: "ruleset notBefore is invalid or in the future" };
    }
  }

  if (candidate.notAfter) {
    const notAfterMs = Date.parse(candidate.notAfter);
    if (!Number.isFinite(notAfterMs) || notAfterMs <= nowEpochMs) {
      return { accepted: false, reason: "ruleset notAfter is invalid or expired" };
    }
  }

  return { accepted: true, reason: null };
}

let _engine:          EnvCoreEngine                          | null = null;
let _stores:          Map<string, SnapshotStore>             | null = null;  // Phase 5-P: keyed by target_id
let _stateMgr:        StateManager                           | null = null;
let _canonicalAuthorityState: CanonicalAuthorityStateStore | null = null;
let _canonicalAuthorityPersistence: CanonicalAuthorityStateFilePersistence | null = null;
let _canonicalAuthorityPersistenceQueue: Promise<void> = Promise.resolve();
let _ledger:          LedgerWriter                           | null = null;   // Phase 2-B
let _receipt:         ReceiptWriter                          | null = null;   // Phase 2-C2
let _riskScanResult:  RiskScanResult                         | null = null;   // Phase 3-A
let _projectRoot:     string                                 | null = null;
let _aegisDir:        string                                 | null = null;
let _safetyKernelV31RuntimeController: SafetyKernelV31RuntimeController | null = null;
let _safetyKernelV31AuthorityBindingComposition: SafetyKernelV31AuthoritySnapshotBindingComposition | null = null;
let _sessionHandoffProductionVerificationComposition: SessionHandoffProductionVerificationComposition | null = null;
let _verifierRecursionGuard: VerifierRecursionGuard | null = null;

const AEGIS_FINAL_PRODUCT_VERIFIER_GRAPH =
  Object.freeze({
    nodes: Object.freeze([
      Object.freeze({
        id: "explicit-execution-entry",
        dependencies: Object.freeze([
          "session-handoff-production-verification",
        ]),
      }),
      Object.freeze({
        id: "session-handoff-production-verification",
        dependencies: Object.freeze([
          "session-handoff-local-verification-adapter",
        ]),
      }),
      Object.freeze({
        id: "session-handoff-local-verification-adapter",
        dependencies: Object.freeze([
          "authority-snapshot-binding-verifier",
          "persistent-sequence-store",
          "receipt-ledger-binding-verifier",
          "session-handoff-runtime-gate",
          "trusted-signature-verifier",
        ]),
      }),
      Object.freeze({
        id: "authority-snapshot-binding-verifier",
        dependencies: Object.freeze([]),
      }),
      Object.freeze({
        id: "persistent-sequence-store",
        dependencies: Object.freeze([]),
      }),
      Object.freeze({
        id: "receipt-ledger-binding-verifier",
        dependencies: Object.freeze([]),
      }),
      Object.freeze({
        id: "session-handoff-runtime-gate",
        dependencies: Object.freeze([]),
      }),
      Object.freeze({
        id: "trusted-signature-verifier",
        dependencies: Object.freeze([]),
      }),
    ]),
  });

let _initialized                                                    = false;
// I_P0_1_WORKSPACE_TRUST_LIMITED_MODE_GUARD_V1
const I_P0_1_WORKSPACE_TRUST_RESTRICTED_MODE_WARNING =
  "Aegis is disabled in Restricted Mode. Trust this workspace to use Aegis.";

let _workspaceTrustInitializationPromise: Promise<void> | null = null;

function isAegisWorkspaceTrusted(): boolean {
  return vscode.workspace.isTrusted !== false;
}

function ensureAegisWorkspaceTrustedForCommand(): boolean {
  if (isAegisWorkspaceTrusted()) {
    return true;
  }

  showWarningMessageBestEffort(
    I_P0_1_WORKSPACE_TRUST_RESTRICTED_MODE_WARNING
  );

  return false;
}

async function initializeAegisOnce(
  context: vscode.ExtensionContext
): Promise<void> {
  if (_initialized || !isAegisWorkspaceTrusted()) {
    return;
  }

  if (_workspaceTrustInitializationPromise) {
    await _workspaceTrustInitializationPromise;
    return;
  }

  const pendingInitialization = initializeAegis(context);
  _workspaceTrustInitializationPromise = pendingInitialization;

  try {
    await pendingInitialization;
  } finally {
    if (_workspaceTrustInitializationPromise === pendingInitialization) {
      _workspaceTrustInitializationPromise = null;
    }
  }
}

// All watchers are disposed during extension deactivation / cleanup.
let _watchers: vscode.Disposable[] = [];

// Phase 5-BT: Per-target debounce timers for watcher events.
// Key = target.relative_path (e.g. ".env").
// Value = NodeJS timer handle from setTimeout.
// When a watcher fires, any pending timer for that target is cleared
// and a new 300ms timer is started. The handler runs once after silence.
const _debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
const _safetyKernelV31WarnTimeoutTimers = new Map<string, ReturnType<typeof setTimeout>>();

function showWarningMessageBestEffort(message: string): void {
  void vscode.window.showWarningMessage(message).then(undefined, () => undefined);
}

function showInformationMessageBestEffort(message: string): void {
  void vscode.window.showInformationMessage(message).then(undefined, () => undefined);
}

async function queueCanonicalAuthorityPersistence(
  reason: string
): Promise<void> {
  const persistence =
    _canonicalAuthorityPersistence;

  const store =
    _canonicalAuthorityState;

  if (
    persistence === null ||
    store === null
  ) {
    throw new Error(
      "CANONICAL_AUTHORITY_PERSISTENCE_UNAVAILABLE"
    );
  }

  const detachedSnapshot =
    CanonicalAuthorityStateStore
      .hydrateSnapshotJson(
        store.serializeSnapshotEnvelope()
      );

  const pending =
    _canonicalAuthorityPersistenceQueue
      .then(() =>
        persistence.save(
          detachedSnapshot
        )
      );

  _canonicalAuthorityPersistenceQueue =
    pending.catch(error => {
      logAegisError(
        "[Aegis] Canonical authority persistence failed (" +
          reason +
          "):",
        error
      );

      try {
        if (
          _stateMgr !== null &&
          _stateMgr.getState().status !== "WARNING"
        ) {
          _stateMgr.setWarning(
            "Aegis could not persist canonical authority state. " +
              "Authority continuity cannot be confirmed."
          );
        }
      } catch (warningError) {
        logAegisError(
          "[Aegis] Could not set Warning state after canonical authority persistence failure:",
          warningError
        );
      }
    });

  await pending;
}

function synchronizeCanonicalAuthorityFromSafetyKernel(input: {
  actionId: string;
  sessionId: string | null;
  approvalNonceSha256: string;
  lifecyclePhase: CanonicalAuthorityKernelLifecyclePhase;
  terminalReason?: CanonicalAuthorityKernelTerminalReason;
}): void {
  const canonicalAuthorityState =
    _canonicalAuthorityState;

  if (
    canonicalAuthorityState === null
  ) {
    return;
  }

  canonicalAuthorityState
    .synchronizeSafetyKernelState(
      input
    );

  void queueCanonicalAuthorityPersistence(
    "safety-kernel-sync"
  ).catch(() => undefined);
}

/**
 * Phase 2-C1: Orchestrator-level duplicate-restore guard.
 *
 * True while a restore operation initiated by handleRestore() is in progress.
 * A second handleRestore() invocation while this is true is rejected
 *
 * This is distinct from SnapshotStore._isRestoring, which guards against
 * concurrent calls to store.restore(). This flag guards at the Orchestrator
 * level and prevents the duplicate from:
 *   1. Calling _stateMgr.setRestoring() (which would leave UI stuck)
 *   2. Calling _store.restore() (which would return "already running")
 *   3. Writing a false restore_failed ledger event
 */
let _restoreCommandInFlight = false;



// =============================================================================
// Phase 5-CN AI Command Review Handler MVP
// Local-only review. No network. Does not read project files or raw secret files.
// =============================================================================

function getSelectedTextForAiCommandReview(): string {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    return "";
  }

  return editor.selections
    .filter((selection) => !selection.isEmpty)
    .map((selection) => editor.document.getText(selection))
    .filter((value) => value.trim().length > 0)
    .join("\n\n")
    .trim();
}
async function handleReviewAiCommandOrAction(): Promise<void> {
  try {
    let inputSource: ReviewAiCommandMvp0InputSource = "selection";
    let proposedText = getSelectedTextForAiCommandReview();

        if (!proposedText) {
      // Clipboard is offered only as an editable default, never silently accepted.
      // The user must explicitly confirm the text with Enter.
      const clipboardText = await vscode.env.clipboard.readText();
      const typed = await vscode.window.showInputBox({
        prompt: "Paste or type the AI-generated command or action to review",
        placeHolder: "e.g. Get-Content package.json",
        value: clipboardText,
        valueSelection: [0, clipboardText.length],
      });
      if (typed && typed.trim().length > 0) {
        proposedText = typed.trim();
        inputSource = "input";
      }
    }

    if (!proposedText) {
      showWarningMessageBestEffort("Aegis: Select or copy a command first, then run Review AI Command / Action.");
      return;
    }

    // evaluateActionQuality() is a caller-independent core engine.
    // MVP-0 caller: "vscode_command".
    // Future callers (unchanged function): "protected_terminal", "ai_connector", "external_gateway".
    // FINAL_PRODUCT_REQUIREMENT_AI_CONNECTED_AEGIS=True
    const initialGateResult = evaluateActionQuality(proposedText, { source: "vscode_command" });
    const complianceResult = initialGateResult.status === "ALLOW"
      ? classifyReviewAiCommandMvp0Action(proposedText, inputSource)
      : null;
    const gateResult = complianceResult
      ? combineReviewAiCommandMvp0WithActionQuality(initialGateResult, complianceResult)
      : initialGateResult;
    let reviewSafetyKernelV31RuntimeClipboardDetails = [
      "COMMAND_DELEGATION_CONNECTED=False",
      "RUNTIME_CONTROLLER_AVAILABLE=False",
      "NO_FOLDER_REVIEW_FALLBACK=True",
      "REVIEW_RUNTIME_CONNECTED=False",
      "EXECUTION_RUNTIME_CONNECTED=False",
      "AUTOMATIC_EXECUTION_ALLOWED=False",
      "EXECUTION_AUTHORITY_GRANTED=False",
    ].join("\n");
    let reviewSafetyKernelV31RuntimeMarkdownSection = [
      "## Safety Kernel v3.1 Runtime Controller Review",
      "",
      "Command delegation connected: False (no-folder diagnostic fallback).",
    ].join("\n");
    if (_safetyKernelV31RuntimeController) {
      const runtimeTimestamp = new Date().toISOString();
      const runtimeResult = await _safetyKernelV31RuntimeController.review(
        {
          action_id: "vscode-review-ai-command-" + Date.now().toString(10) + "-" + sha256OfString(proposedText + runtimeTimestamp).slice(0, 16),
          target: "vscode-review-ai-command-or-action",
          intent: "vscode_review_ai_command_or_action",
          proposed_action: proposedText,
          context_hash: "sha256:" + sha256OfString(["vscode_command", proposedText].join("\n")),
          timestamp: runtimeTimestamp,
          adapter_id: "aegis-review-ai-command-or-action-runtime-controller",
          policy_version: "safety-kernel-v31-runtime-controller-review-v1",
          human_readable_summary: "Review AI Command / Action through Safety Kernel v3.1 Runtime Controller.",
        },
        gateResult
      );
      const runtimeSession = runtimeResult.session;
      if (runtimeResult.output.record) {
        synchronizeCanonicalAuthorityFromSafetyKernel({
          actionId: runtimeResult.output.record.actionId,
          sessionId: runtimeSession?.sessionId ?? null,
          approvalNonceSha256:
            runtimeResult.output.record.approvalNonceSha256,
          lifecyclePhase:
            runtimeResult.output.record.lifecyclePhase,
        });
      }
      if (runtimeResult.session) {
        scheduleSafetyKernelV31WarnTimeout(runtimeResult.session);
      }
      reviewSafetyKernelV31RuntimeClipboardDetails = [
        "COMMAND_DELEGATION_CONNECTED=True",
        "RUNTIME_CONTROLLER_AVAILABLE=True",
        runtimeResult.output.clipboardSummary,
        "SESSION_ID=" + (runtimeSession?.sessionId ?? ""),
        "SESSION_PHASE=" + (runtimeSession?.lifecyclePhase ?? ""),
        "RAW_APPROVAL_NONCE_EXPOSED=False",
        "REVIEW_RUNTIME_CONNECTED=True",
        "EXECUTION_RUNTIME_CONNECTED=False",
        "AUTOMATIC_EXECUTION_ALLOWED=False",
        "EXECUTION_AUTHORITY_GRANTED=False",
      ].join("\n");
      reviewSafetyKernelV31RuntimeMarkdownSection = [
        "## Safety Kernel v3.1 Runtime Controller Review",
        "",
        "Command delegation connected: True (review only; no execution authority).",
        "",
        runtimeResult.output.markdown,
        ...(runtimeSession ? ["", "Session ID: " + runtimeSession.sessionId, "Session phase: " + runtimeSession.lifecyclePhase] : []),
      ].join("\n");
    }
    const gateSection = formatActionGateSection(gateResult);
    if (gateResult.status !== "ALLOW") {
      // Always produce review output for BLOCK/SPLIT_REQUIRED.
      // AI Compliance Gate is skipped, but markdown doc and clipboard are created.
      const sanitizedPreview = sanitizeReviewAiCommandMvp0Text(proposedText);
      const blockMarkdown = [
        "# Aegis AI Command / Action Review",
        "",
        gateSection,
        "",
        reviewSafetyKernelV31RuntimeMarkdownSection,
        "",
        "## Sanitized Preview",
        "",
        "```text",
        sanitizedPreview,
        "```",
      ].join("\n");

      const blockClipboard = [
        "=== AEGIS AI COMMAND REVIEW RESULT ===",
        "ACTION_QUALITY_GATE_STATUS=" + gateResult.status,
        "ACTION_QUALITY_GATE_RULE=" + gateResult.internalRuleId,
        "ACTION_QUALITY_GATE_SOURCE=" + gateResult.source,
        "ACTION_QUALITY_GATE_REASONS=" + gateResult.reasons.join("; "),
        "ACTION_QUALITY_GATE_NEXT_SAFE_STEP=" + (gateResult.nextSafeStep ?? ""),
        reviewSafetyKernelV31RuntimeClipboardDetails,
        "AI_COMPLIANCE_GATE_SKIPPED=" + (complianceResult ? "False" : "True"),
        "SANITIZED_PREVIEW_BEGIN",
        sanitizedPreview,
        "SANITIZED_PREVIEW_END",
      ].join("\n");

      await vscode.env.clipboard.writeText(blockClipboard);

      const blockDoc = await vscode.workspace.openTextDocument({
        content: blockMarkdown,
        language: "markdown",
      });
      await vscode.window.showTextDocument(blockDoc, { preview: false });

      showWarningMessageBestEffort(
        "Aegis Action Quality Gate: " + gateResult.status + ". Sanitized result copied to clipboard."
      );
      return;
    }
    // Only a final ALLOW reaches the detailed safe review output below.
    const result = complianceResult!;
    const markdown = [
      gateSection,
      "",
      reviewSafetyKernelV31RuntimeMarkdownSection,
      "",
      buildReviewAiCommandMvp0Markdown(result),
    ].join("\n");
    const clipboardText = [
      "=== AEGIS ACTION QUALITY GATE RESULT ===",
      "ACTION_QUALITY_GATE_STATUS=" + gateResult.status,
      "ACTION_QUALITY_GATE_RULE=" + gateResult.internalRuleId,
      "ACTION_QUALITY_GATE_SOURCE=" + gateResult.source,
      "ACTION_QUALITY_GATE_REASONS=" + gateResult.reasons.join("; "),
      "ACTION_QUALITY_GATE_NEXT_SAFE_STEP=" + (gateResult.nextSafeStep ?? ""),
      reviewSafetyKernelV31RuntimeClipboardDetails,
      "",
      buildReviewAiCommandMvp0ClipboardText(result),
    ].join("\n");

    await vscode.env.clipboard.writeText(clipboardText);

    const doc = await vscode.workspace.openTextDocument({
      content: markdown,
      language: "markdown",
    });
    await vscode.window.showTextDocument(doc, { preview: false });

    showInformationMessageBestEffort("Aegis review: SAFE_TO_RUN. Sanitized result copied to clipboard.");
  } catch (err) {
    logAegisError("[Aegis] reviewAiCommandOrAction error:", err);
    showWarningMessageBestEffort("Aegis could not complete AI command review.");
  }
}


function clearSafetyKernelV31WarnTimeout(sessionId: string): void {
  const timer = _safetyKernelV31WarnTimeoutTimers.get(sessionId);
  if (timer !== undefined) {
    clearTimeout(timer);
    _safetyKernelV31WarnTimeoutTimers.delete(sessionId);
  }
}

function scheduleSafetyKernelV31WarnTimeout(
  pendingSession: {
    sessionId: string;
    lifecyclePhase: string;
    expiresAt: string | null;
  }
): void {
  clearSafetyKernelV31WarnTimeout(pendingSession.sessionId);
  if (
    !_safetyKernelV31RuntimeController ||
    pendingSession.lifecyclePhase !== "WARN_PENDING" ||
    !pendingSession.expiresAt
  ) {
    return;
  }

  const sessionId = pendingSession.sessionId;
  const expiresAt = pendingSession.expiresAt;
  const delayMs = Math.max(0, Date.parse(expiresAt) - Date.now());
  const timer = setTimeout(async () => {
    if (_safetyKernelV31WarnTimeoutTimers.get(sessionId) === timer) {
      _safetyKernelV31WarnTimeoutTimers.delete(sessionId);
    }
    try {
      if (!_safetyKernelV31RuntimeController) return;
      const session = _safetyKernelV31RuntimeController.readSession(sessionId);
      if (
        !session ||
        session.lifecyclePhase !== "WARN_PENDING" ||
        session.expiresAt !== expiresAt
      ) {
        return;
      }
      const result =
        await _safetyKernelV31RuntimeController.terminateWarnSession(
          sessionId,
          "timeout_expired"
        );
      if (result?.session) {
        synchronizeCanonicalAuthorityFromSafetyKernel({
          actionId: result.session.actionId,
          sessionId: null,
          approvalNonceSha256:
            result.session.approvalNonceSha256,
          lifecyclePhase: result.session.lifecyclePhase,
          terminalReason: "timeout_expired",
        });
      }
      showWarningMessageBestEffort("Aegis Safety Kernel WARN session expired; no action was executed.");
    } catch (err) {
      logAegisError("[Aegis] Safety Kernel WARN timeout termination error:", err);
    }
  }, delayMs);
  _safetyKernelV31WarnTimeoutTimers.set(sessionId, timer);
}

async function handleReadSafetyKernelV31Session(): Promise<void> {
  try {
    if (!_safetyKernelV31RuntimeController) {
      showWarningMessageBestEffort("Aegis Safety Kernel session lookup requires an open folder.");
      return;
    }

    const typed = await vscode.window.showInputBox({
      prompt: "Enter the 48-character Safety Kernel v3.1 session ID",
      placeHolder: "48 lowercase hexadecimal characters",
      ignoreFocusOut: true,
    });
    const sessionId = typed?.trim() ?? "";
    if (!sessionId) return;
    if (!/^[a-f0-9]{48}$/.test(sessionId)) {
      showWarningMessageBestEffort("Aegis Safety Kernel session ID must be 48 lowercase hexadecimal characters.");
      return;
    }

    const session = _safetyKernelV31RuntimeController.readSession(sessionId);
    if (!session) {
      showWarningMessageBestEffort("Aegis Safety Kernel session was not found or is no longer pending.");
      return;
    }

    const clipboardText = [
      "SAFETY_KERNEL_V31_SESSION_READ=True",
      "SESSION_FOUND=True",
      "SESSION_ID=" + session.sessionId,
      "ACTION_ID=" + session.actionId,
      "APPROVAL_NONCE_SHA256=" + session.approvalNonceSha256,
      "SESSION_PHASE=" + session.lifecyclePhase,
      "NONCE_CONSUMED=" + (session.nonceConsumed ? "True" : "False"),
      "MEMORY_ONLY=True",
      "RAW_APPROVAL_NONCE_EXPOSED=False",
      "EXECUTION_RUNTIME_CONNECTED=False",
      "AUTOMATIC_EXECUTION_ALLOWED=False",
      "EXECUTION_AUTHORITY_GRANTED=False",
    ].join("\n");
    const markdown = [
      "## Safety Kernel v3.1 Session",
      "",
      "- Session ID: " + session.sessionId,
      "- Action ID: " + session.actionId,
      "- Approval nonce SHA-256: " + session.approvalNonceSha256,
      "- Lifecycle phase: " + session.lifecyclePhase,
      "- Nonce consumed: " + (session.nonceConsumed ? "True" : "False"),
      "- Memory only: True",
      "- Raw approval nonce exposed: False",
      "- Execution runtime connected: False",
      "- Automatic execution allowed: False",
      "- Execution authority granted: False",
    ].join("\n");

    await vscode.env.clipboard.writeText(clipboardText);
    const doc = await vscode.workspace.openTextDocument({ content: markdown, language: "markdown" });
    await vscode.window.showTextDocument(doc, { preview: false });
    showInformationMessageBestEffort("Aegis Safety Kernel session status copied to clipboard.");
  } catch (err) {
    logAegisError("[Aegis] readSafetyKernelV31Session error:", err);
    showWarningMessageBestEffort("Aegis could not read the Safety Kernel session.");
  }
}

async function handleConfirmSafetyKernelV31WarnSession(): Promise<void> {
  try {
    if (!_safetyKernelV31RuntimeController) {
      showWarningMessageBestEffort("Aegis Safety Kernel WARN confirmation requires an open folder.");
      return;
    }

    const typed = await vscode.window.showInputBox({
      prompt: "Enter the 48-character Safety Kernel v3.1 WARN session ID to confirm",
      placeHolder: "48 lowercase hexadecimal characters",
      ignoreFocusOut: true,
    });
    const sessionId = typed?.trim() ?? "";
    if (!sessionId) return;
    if (!/^[a-f0-9]{48}$/.test(sessionId)) {
      showWarningMessageBestEffort("Aegis Safety Kernel session ID must be 48 lowercase hexadecimal characters.");
      return;
    }

    const session = _safetyKernelV31RuntimeController.readSession(sessionId);
    if (!session) {
      showWarningMessageBestEffort("Aegis Safety Kernel session was not found or is no longer pending.");
      return;
    }
    if (session.lifecyclePhase !== "WARN_PENDING") {
      showWarningMessageBestEffort("Aegis Safety Kernel session is not awaiting WARN confirmation.");
      return;
    }

    const result = await _safetyKernelV31RuntimeController.confirmWarnSession(sessionId);
    synchronizeCanonicalAuthorityFromSafetyKernel({
      actionId: result.session.actionId,
      sessionId: result.session.sessionId,
      approvalNonceSha256: result.session.approvalNonceSha256,
      lifecyclePhase: result.session.lifecyclePhase,
    });
    clearSafetyKernelV31WarnTimeout(sessionId);
    const clipboardText = [
      "SAFETY_KERNEL_V31_WARN_CONFIRMED=True",
      "SESSION_ID=" + result.session.sessionId,
      "ACTION_ID=" + result.session.actionId,
      "APPROVAL_NONCE_SHA256=" + result.session.approvalNonceSha256,
      "SESSION_PHASE=" + result.session.lifecyclePhase,
      "NONCE_CONSUMED=" + (result.session.nonceConsumed ? "True" : "False"),
      result.output.clipboardSummary,
      "CONFIRMATION_EXECUTED_ACTION=False",
      "RAW_APPROVAL_NONCE_EXPOSED=False",
      "AUTOMATIC_EXECUTION_ALLOWED=False",
      "EXECUTION_AUTHORITY_GRANTED=False",
    ].join("\n");
    const markdown = [
      result.output.markdown,
      "",
      "- Confirmation executed action: False",
      "- Automatic execution allowed: False",
      "- Execution authority granted: False",
    ].join("\n");

    await vscode.env.clipboard.writeText(clipboardText);
    const doc = await vscode.workspace.openTextDocument({ content: markdown, language: "markdown" });
    await vscode.window.showTextDocument(doc, { preview: false });
    showInformationMessageBestEffort("Aegis Safety Kernel WARN session confirmed; no action was executed.");
  } catch (err) {
    logAegisError("[Aegis] confirmSafetyKernelV31WarnSession error:", err);
    showWarningMessageBestEffort("Aegis could not confirm the Safety Kernel WARN session.");
  }
}

async function handleCancelSafetyKernelV31WarnSession(): Promise<void> {
  try {
    if (!_safetyKernelV31RuntimeController) {
      showWarningMessageBestEffort("Aegis Safety Kernel WARN cancellation requires an open folder.");
      return;
    }

    const typed = await vscode.window.showInputBox({
      prompt: "Enter the 48-character Safety Kernel v3.1 WARN session ID to cancel",
      placeHolder: "48 lowercase hexadecimal characters",
      ignoreFocusOut: true,
    });
    const sessionId = typed?.trim() ?? "";
    if (!sessionId) return;
    if (!/^[a-f0-9]{48}$/.test(sessionId)) {
      showWarningMessageBestEffort("Aegis Safety Kernel session ID must be 48 lowercase hexadecimal characters.");
      return;
    }

    const session = _safetyKernelV31RuntimeController.readSession(sessionId);
    if (!session) {
      showWarningMessageBestEffort("Aegis Safety Kernel session was not found or is no longer pending.");
      return;
    }
    if (session.lifecyclePhase !== "WARN_PENDING") {
      showWarningMessageBestEffort("Aegis Safety Kernel session is not awaiting WARN cancellation.");
      return;
    }

    const result = await _safetyKernelV31RuntimeController.terminateWarnSession(
      sessionId,
      "cancel_by_user"
    );
    synchronizeCanonicalAuthorityFromSafetyKernel({
      actionId: result.session.actionId,
      sessionId: null,
      approvalNonceSha256: result.session.approvalNonceSha256,
      lifecyclePhase: result.session.lifecyclePhase,
      terminalReason: "cancel_by_user",
    });
    clearSafetyKernelV31WarnTimeout(sessionId);
    const clipboardText = [
      "SAFETY_KERNEL_V31_WARN_CANCELLED=True",
      "SESSION_ID=" + result.session.sessionId,
      "ACTION_ID=" + result.session.actionId,
      "APPROVAL_NONCE_SHA256=" + result.session.approvalNonceSha256,
      "SESSION_PHASE=" + result.session.lifecyclePhase,
      "NONCE_CONSUMED=" + (result.session.nonceConsumed ? "True" : "False"),
      result.output.clipboardSummary,
      "CANCELLATION_EXECUTED_ACTION=False",
      "RAW_APPROVAL_NONCE_EXPOSED=False",
      "AUTOMATIC_EXECUTION_ALLOWED=False",
      "EXECUTION_AUTHORITY_GRANTED=False",
    ].join("\n");
    const markdown = [
      result.output.markdown,
      "",
      "- Cancellation executed action: False",
      "- Automatic execution allowed: False",
      "- Execution authority granted: False",
    ].join("\n");

    await vscode.env.clipboard.writeText(clipboardText);
    const doc = await vscode.workspace.openTextDocument({ content: markdown, language: "markdown" });
    await vscode.window.showTextDocument(doc, { preview: false });
    showInformationMessageBestEffort("Aegis Safety Kernel WARN session cancelled with evidence; no action was executed.");
  } catch (err) {
    logAegisError("[Aegis] cancelSafetyKernelV31WarnSession error:", err);
    showWarningMessageBestEffort("Aegis could not cancel the Safety Kernel WARN session.");
  }
}

async function ensureProtectedTerminalSnapshotsBeforeHandoff(): Promise<{
  ok: boolean;
  snapshotCount: number;
  baselineRegistrationCount: number;
  skippedMissingCount: number;
  reasons: string[];
}> {
  // AUTOSNAPSHOT_PROTECTED_TERMINAL_PREFLIGHT_STAGE2_V1
  if (!_engine || !_stores || !_projectRoot || !_aegisDir) {
    return { ok: false, snapshotCount: 0, baselineRegistrationCount: 0, skippedMissingCount: 0, reasons: ["Aegis workspace is not initialized."] };
  }

  let snapshotCount = 0;
  let baselineRegistrationCount = 0;
  let skippedMissingCount = 0;

  for (const target of getProtectedTargets().filter(t => t.restore_enabled)) {
    const store = _stores.get(target.target_id);
    if (!store) {
      return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": snapshot store missing."] };
    }

    const absPath = nodePath.join(_projectRoot, target.relative_path);
    try { await fs.promises.access(absPath); }
    catch {
      skippedMissingCount++;
      continue;
    }

    const existingIndex = await readSnapshotIndexOrNull(store, "[Aegis] baseline registration index read threw:");
    const indexHasBaseline = !!(existingIndex && existingIndex.baseline_snapshot_file && existingIndex.baseline_content_sha256);
    const markerPresent = await readBaselineMarker(_aegisDir, target.marker_file);

    if (markerPresent && !indexHasBaseline) {
      return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": marker exists but immutable baseline index is missing."] };
    }

    if (!markerPresent && existingIndex && !indexHasBaseline) {
      return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": degraded snapshot index blocks terminal handoff."] };
    }

    if (!indexHasBaseline) {
      let content: string;
      try { content = await fs.promises.readFile(absPath, "utf8"); }
      catch {
        return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": could not read file for baseline snapshot."] };
      }

      const snapshotId = await createBaselineSnapshotFromContentOrNull(store, content, absPath, target.relative_path, "[Aegis] baseline snapshot creation threw:");
      if (!snapshotId) {
        return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": baseline snapshot creation failed."] };
      }

      const markerWritten = await writeBaselineMarker(_aegisDir, target.marker_file, target.relative_path);
      if (!markerWritten) {
        return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": baseline marker write failed after snapshot creation."] };
      }

      baselineRegistrationCount++;
      snapshotCount++;
      continue;
    }

    if (!markerPresent) {
      const markerWritten = await writeBaselineMarker(_aegisDir, target.marker_file, target.relative_path);
      if (!markerWritten) {
        return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": baseline marker repair failed."] };
      }
    }

    try { await _engine.capturePreSave(absPath); }
    catch {
      return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": pre-mutation capture failed."] };
    }

    const baseline = _engine.consumePending(absPath);
    if (!baseline) {
      return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": pre-mutation baseline was not available."] };
    }

    const snapshotId = await createSnapshotOrNull(store, baseline, target.relative_path);
    if (!snapshotId) {
      return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: [target.relative_path + ": pre-mutation snapshot creation failed."] };
    }

    snapshotCount++;
  }

  if (snapshotCount === 0) {
    return { ok: false, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: ["No existing protected target could be snapshotted before terminal handoff."] };
  }

  return { ok: true, snapshotCount, baselineRegistrationCount, skippedMissingCount, reasons: ["AutoSnapshot preflight completed before terminal handoff."] };
}

async function handleProtectedTerminalMvp0(): Promise<void> {
  try {
    const typed = await _platformPorts.ui.showInputBox({
      prompt: "Aegis Protected Terminal: paste one command for pre-execution review",
      placeHolder: "One short command only. Aegis reviews before terminal handoff.",
    });

    const proposed = (typed ?? "").trim();
    if (!proposed) { return; }

    const review = evaluateProtectedTerminalMvp0Review(proposed);
    const clipboardText = review.clipboardText;

    await _platformPorts.clipboard.writeText(clipboardText);

    if (review.terminalHandoffBlocked) {
      await _platformPorts.documents.showTextDocument(review.blockedMarkdown, "markdown", false);
      await _platformPorts.ui.showWarning("Aegis Protected Terminal: command blocked. Result copied to clipboard.");
      return;
    }

    const snapshotPreflight = await ensureProtectedTerminalSnapshotsBeforeHandoff();
    const autosnapshotClipboardText = buildProtectedTerminalMvp0AutosnapshotClipboardText(
      clipboardText,
      snapshotPreflight
    );
    await _platformPorts.clipboard.writeText(autosnapshotClipboardText);

    if (!snapshotPreflight.ok) {
      await _platformPorts.documents.showTextDocument(
        buildProtectedTerminalMvp0AutosnapshotBlockedMarkdown(snapshotPreflight),
        "markdown",
        false
      );
      await _platformPorts.ui.showWarning("Aegis Protected Terminal: AutoSnapshot failed. Terminal handoff blocked.");
      return;
    }
    const terminal = _platformPorts.terminalHost.createDedicatedTerminal("Aegis Protected Terminal");
    terminal.show();
    terminal.sendText(proposed, false);
    await _platformPorts.ui.showInfo("Aegis Protected Terminal: command reviewed and inserted, not executed.");
  } catch (err) {
    logAegisError("[Aegis] protectedTerminal error:", err);
    await _platformPorts.ui.showWarning("Aegis Protected Terminal could not complete the review.").catch(() => undefined);
  }
}

async function handleAegisExecutionGatewayMvp0(rawEnvelope?: string): Promise<void> {
  try {
  const typed =
    typeof rawEnvelope === "string" && rawEnvelope.trim().length > 0
      ? rawEnvelope
      : await _platformPorts.ui.showInputBox({
          prompt: "Aegis AI Execution Gateway MVP-0: paste AI action envelope",
          placeHolder: '{"source":"ai_connector","intent":"propose_terminal_command","actionId":"AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY","capabilityId":"ai_gateway_review_only","proposedCommand":"npm run compile"}'
        });

  const raw = (typed ?? "").trim();
  if (!raw) { return; }

  const envelopeParseResult = parseAiExecutionGatewayMvp0Envelope(raw);
  const envelopeValid = envelopeParseResult.envelopeValid;
  const envelopeError = envelopeParseResult.envelopeError;
  const envelopeSource = envelopeParseResult.envelopeSource;
  const envelopeIntent = envelopeParseResult.envelopeIntent;
  const proposed = envelopeParseResult.proposed;
  const envelopeTargetPath = envelopeParseResult.envelopeTargetPath;
  const envelopeActionId = envelopeParseResult.envelopeActionId;
  const envelopeCapabilityId = envelopeParseResult.envelopeCapabilityId;
  if (!envelopeValid) {
    const out = buildAiExecutionGatewayMvp0InvalidEnvelopeReceiptLines({
      envelopeError
    }).join("\n");

    await _platformPorts.clipboard.writeText(out);
    await _platformPorts.ui.showWarning("Aegis AI Execution Gateway MVP-0: invalid AI action envelope blocked.");
    return;
  }
    // A2U CONTRACT A PRODUCT ENTRY CONNECTION START
  const explicitEnvelope = JSON.parse(raw) as {
    readonly actionKind?: unknown;
    readonly userExecutionConfirmed?: unknown;
    readonly automaticExecutionRequested?: unknown;
    readonly runtimeReviewStatus?: unknown;
    readonly approvalNonceSha256?: unknown;
    readonly sessionId?: unknown;
  };

  const explicitActionKind =
    typeof explicitEnvelope.actionKind === "string"
      ? explicitEnvelope.actionKind
      : "";

  if (
    envelopeCapabilityId === "ai_gateway_explicit_execution" ||
    explicitActionKind === "ai_execution_gateway_execute"
  ) {
    const explicitSessionId =
      typeof explicitEnvelope.sessionId === "string"
        ? explicitEnvelope.sessionId.trim()
        : "";

    let authorityBindingVerificationResult:
      | "verified"
      | "authority_drift"
      | "snapshot_failed" =
      "authority_drift";

    let currentAuthorityBindingAvailable =
      false;

    let currentAuthorityBinding:
      | {
          readonly authorityRevision: number;
          readonly workspaceId: string;
          readonly snapshotBindingSha256: string;
        }
      | null =
      null;

    let verifiedCurrentAuthorityBinding:
      | {
          readonly authorityRevision: number;
          readonly workspaceId: string;
          readonly snapshotBindingSha256: string;
        }
      | null =
      null;

    if (
      _safetyKernelV31AuthorityBindingComposition !== null
    ) {
      if (explicitSessionId.length > 0) {
        try {
          currentAuthorityBinding =
            await _safetyKernelV31AuthorityBindingComposition
              .readPort
              .readCurrentBinding();

          authorityBindingVerificationResult =
            await _safetyKernelV31AuthorityBindingComposition
              .verifier
              .verify({
                authorityRevision:
                  currentAuthorityBinding.authorityRevision,
                workspaceId:
                  currentAuthorityBinding.workspaceId,
                actionId:
                  "AEGIS_AI_EXECUTION_GATEWAY_MVP0_EXPLICIT_PRODUCT_ENTRY_CONNECTION",
                sessionId:
                  explicitSessionId,
                approvalNonceSha256:
                  typeof explicitEnvelope.approvalNonceSha256 === "string"
                    ? explicitEnvelope.approvalNonceSha256
                    : "",
                commandSha256:
                  "sha256:" + sha256OfString(raw),
                snapshotBindingSha256:
                  currentAuthorityBinding.snapshotBindingSha256,
              });

          currentAuthorityBindingAvailable =
            authorityBindingVerificationResult ===
            "verified";

          if (currentAuthorityBindingAvailable) {
            verifiedCurrentAuthorityBinding =
              currentAuthorityBinding;
          }
        } catch {
          authorityBindingVerificationResult =
            "authority_drift";

          currentAuthorityBindingAvailable =
            false;

          currentAuthorityBinding =
            null;

          verifiedCurrentAuthorityBinding =
            null;
        }
      }
    }

    const capabilityDecision =
      evaluateAiExecutionGatewayExplicitExecutionMvp0Capability({
        capabilityId: envelopeCapabilityId,
        actionKind: explicitActionKind,
        userExecutionConfirmed:
          explicitEnvelope.userExecutionConfirmed === true,
        automaticExecutionRequested:
          explicitEnvelope.automaticExecutionRequested === true,
        runtimeReviewStatus:
          typeof explicitEnvelope.runtimeReviewStatus === "string"
            ? explicitEnvelope.runtimeReviewStatus
            : "",
        approvalNonceSha256:
          typeof explicitEnvelope.approvalNonceSha256 === "string"
            ? explicitEnvelope.approvalNonceSha256
            : "",
        currentAuthorityBindingAvailable,
      });

    const runtimeController =
      _safetyKernelV31RuntimeController;

    const projectRoot =
      _projectRoot;

    const executionConnectionPreconditionsReady =
      capabilityDecision.product_entrypoint_capability_ready === true &&
      capabilityDecision.execution_authority_granted === true &&
      authorityBindingVerificationResult === "verified" &&
      currentAuthorityBindingAvailable === true &&
      runtimeController !== null &&
      projectRoot !== null &&
      explicitSessionId.length > 0 &&
      verifiedCurrentAuthorityBinding !== null;

    const verifierGraphVerification =
      verifyVerifierGraphAcyclic(
        AEGIS_FINAL_PRODUCT_VERIFIER_GRAPH
      );

    const verifierGraphVerified =
      verifierGraphVerification.verified === true;

    const verifierGraphIssueCodes =
      verifierGraphVerification.issueCodes
        .join(",");

    const verifierGraphCyclePath =
      verifierGraphVerification.cyclePath
        .join(">");

    let verifierRecursionGuardPassed = false;
    let verifierRecursionGuardIssueCodes = "";

    let sessionHandoffAuthorized = false;
    let sessionHandoffRuntimeState = "NOT_EVALUATED";
    let sessionHandoffCompositionIssueCodes = "";
    let sessionHandoffAdapterIssueCodes = "";
    let sessionHandoffSequenceClaimed = false;

    if (
      executionConnectionPreconditionsReady &&
      verifierGraphVerified
    ) {
      const productionComposition =
        _sessionHandoffProductionVerificationComposition;

      const recursionGuard =
        _verifierRecursionGuard;

      if (recursionGuard === null) {
        verifierRecursionGuardIssueCodes =
          "RECURSION_GUARD_UNAVAILABLE";
      } else if (
        productionComposition === null
      ) {
        sessionHandoffCompositionIssueCodes =
          "PRODUCTION_COMPOSITION_UNAVAILABLE";
      } else {
        try {
          const guardedSessionHandoffResult =
            await recursionGuard.run(
              "session-handoff-production-verification",
              () =>
                productionComposition.evaluate({
                  operationClass: "EXECUTE",
                  presentedSessionId:
                    explicitSessionId,
                  presentedApprovalNonceSha256:
                    typeof explicitEnvelope.approvalNonceSha256 === "string"
                      ? explicitEnvelope.approvalNonceSha256
                      : "",
                })
            );

          if (!guardedSessionHandoffResult.ok) {
            verifierRecursionGuardIssueCodes =
              guardedSessionHandoffResult
                .issueCodes
                .join(",");

            if (
              guardedSessionHandoffResult
                .issueCodes
                .includes(
                  "VERIFIER_EXECUTION_FAILED"
                )
            ) {
              sessionHandoffCompositionIssueCodes =
                "PRODUCTION_COMPOSITION_EVALUATION_FAILED";
            }
          } else {
            verifierRecursionGuardPassed = true;

            const sessionHandoffResult =
              guardedSessionHandoffResult.value;

            sessionHandoffAuthorized =
              sessionHandoffResult.authorized === true;

            sessionHandoffRuntimeState =
              sessionHandoffResult.adapterResult
                .gateResult.runtimeState;

            sessionHandoffCompositionIssueCodes =
              sessionHandoffResult.compositionIssueCodes
                .join(",");

            sessionHandoffAdapterIssueCodes =
              sessionHandoffResult.adapterResult
                .adapterIssueCodes
                .join(",");

            sessionHandoffSequenceClaimed =
              sessionHandoffResult.adapterResult
                .sequenceClaimed === true;
          }
        } catch {
          verifierRecursionGuardIssueCodes =
            "VERIFIER_EXECUTION_FAILED";

          sessionHandoffCompositionIssueCodes =
            "PRODUCTION_COMPOSITION_EVALUATION_FAILED";
        }
      }
    }

    const executionConnectionReady =
      executionConnectionPreconditionsReady &&
      verifierGraphVerified &&
      verifierRecursionGuardPassed &&
      sessionHandoffAuthorized;

    let executionStatus =
      "not_connected";

    let executionExitCode =
      "";

    let executionAbortReason =
      "";

    let executionEvidenceCommitted =
      "";

    let executionRejectionCode =
      "";

    let executionErrorMessage =
      "";

    let runtimeProcessExecutionLine =
      "runtime_process_execution_performed=false";

    if (executionConnectionReady) {
      if (
        runtimeController === null ||
        projectRoot === null ||
        verifiedCurrentAuthorityBinding === null
      ) {
        throw new Error(
          "CONTRACT_C_CONNECTION_GATE_INVARIANT"
        );
      }

      try {
        runtimeController
          .bindAllowedExecutionSessionAuthority(
            explicitSessionId,
            {
              authorityRevision:
                verifiedCurrentAuthorityBinding.authorityRevision,
              workspaceId:
                verifiedCurrentAuthorityBinding.workspaceId,
              snapshotBindingSha256:
                verifiedCurrentAuthorityBinding.snapshotBindingSha256,
              cwd:
                projectRoot,
            }
          );

        const coordinated =
          await runtimeController
            .coordinateAllowedExecutionSession(
              explicitSessionId
            );

        if (coordinated.status === "completed") {
          executionStatus =
            "completed";

          executionExitCode =
            "0";

          runtimeProcessExecutionLine =
            "runtime_process_execution_performed=true";
        } else if (coordinated.status === "aborted") {
          executionStatus =
            "aborted";

          executionAbortReason =
            coordinated.reason;

          executionEvidenceCommitted =
            String(coordinated.evidenceCommitted);
        } else {
          executionStatus =
            "rejected";

          executionRejectionCode =
            coordinated.code;
        }
      } catch (error) {
        executionStatus =
          "failed";

        executionErrorMessage =
          error instanceof Error &&
          error.message.trim().length > 0
            ? error.message.trim()
            : String(error);
      }
    }

    const explicitConnectionOutput = [
      "AEGIS_AI_EXECUTION_GATEWAY_MVP0_EXPLICIT_PRODUCT_ENTRY_CONNECTION",
      `capability_id=${envelopeCapabilityId}`,
      `action_kind=${explicitActionKind}`,
      `session_id=${explicitSessionId}`,
      `authority_binding_verification_result=${authorityBindingVerificationResult}`,
      `product_entrypoint_capability_ready=${String(
        capabilityDecision.product_entrypoint_capability_ready
      )}`,
      `execution_authority_granted=${String(
        capabilityDecision.execution_authority_granted
      )}`,
      `authority_reason_code=${capabilityDecision.authority_reason_code}`,
      `capability_reason_code=${capabilityDecision.capability_reason_code}`,
      `verifier_graph_verified=${String(verifierGraphVerified)}`,
      `verifier_graph_issue_codes=${verifierGraphIssueCodes}`,
      `verifier_graph_cycle_path=${verifierGraphCyclePath}`,
      `verifier_recursion_guard_passed=${String(verifierRecursionGuardPassed)}`,
      `verifier_recursion_guard_issue_codes=${verifierRecursionGuardIssueCodes}`,
      `session_handoff_authorized=${String(sessionHandoffAuthorized)}`,
      `session_handoff_runtime_state=${sessionHandoffRuntimeState}`,
      `session_handoff_composition_issue_codes=${sessionHandoffCompositionIssueCodes}`,
      `session_handoff_adapter_issue_codes=${sessionHandoffAdapterIssueCodes}`,
      `session_handoff_sequence_claimed=${String(sessionHandoffSequenceClaimed)}`,
      `status=${executionStatus}`,
      `exit_code=${executionExitCode}`,
      `reason=${executionAbortReason}`,
      `evidence_committed=${executionEvidenceCommitted}`,
      `code=${executionRejectionCode}`,
      `error_message=${executionErrorMessage}`,
      runtimeProcessExecutionLine,
    ].join("\n");

    await _platformPorts.clipboard.writeText(
      explicitConnectionOutput
    );

    await _platformPorts.ui.showInfo(
      executionStatus === "not_connected"
        ? "Aegis AI Execution Gateway MVP-0: explicit authority evaluated; runtime process execution remains disconnected."
        : "Aegis AI Execution Gateway MVP-0: explicit execution connection result copied."
    );

    return;
  }
  // A2U CONTRACT A PRODUCT ENTRY CONNECTION END

  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";
  const capsulePath = workspaceRoot ? nodePath.join(workspaceRoot, "AEGIS-HANDOFF-CAPSULE.json") : "";
  let bootstrapCapsuleOk = false;
  let bootstrapCapsuleError = "";

  try {
    if (!capsulePath || !fs.existsSync(capsulePath)) {
      bootstrapCapsuleError = "BOOTSTRAP_CAPSULE_ABSENT";
    } else {
      const capsuleValidation = validateAiExecutionGatewayMvp0BootstrapCapsule(
        JSON.parse(fs.readFileSync(capsulePath, "utf8"))
      );
      bootstrapCapsuleOk = capsuleValidation.valid;
      bootstrapCapsuleError = capsuleValidation.error;
    }
  } catch {
    bootstrapCapsuleError = "BOOTSTRAP_CAPSULE_INVALID_JSON";
  }

  if (!bootstrapCapsuleOk) {
    const out = buildAiExecutionGatewayMvp0InvalidBootstrapCapsuleReceiptLines({
      bootstrapCapsuleError,
      envelopeSource,
      envelopeIntent
    }).join("\n");

    await _platformPorts.clipboard.writeText(out);
    await _platformPorts.ui.showWarning("Aegis AI Execution Gateway MVP-0: bootstrap capsule missing or invalid.");
    return;
  }

  const authorizedSurfaceExists = hasAuthorizedAiExecutionGatewayMvp0Surface(
    envelopeActionId,
    envelopeCapabilityId
  );

  if (!authorizedSurfaceExists) {
    const out = buildAiExecutionGatewayMvp0NoAuthorizedSurfaceReceiptLines({
      envelopeSource,
      envelopeIntent,
      envelopeActionId,
      envelopeCapabilityId
    }).join("\n");

    await _platformPorts.clipboard.writeText(out);
    await _platformPorts.ui.showWarning("Aegis AI Execution Gateway MVP-0: no authorized surface for this action.");
    return;
  }

  if (!_canonicalAuthorityState) {
    if (!_safetyKernelV31RuntimeController) {
      await _platformPorts.ui.showWarning(
        "Aegis AI Execution Gateway MVP-0 requires Safety Kernel v3.1 Runtime Controller."
      );
    } else {
      await _platformPorts.ui.showWarning(
        "Aegis AI Execution Gateway MVP-0: canonical authority state is unavailable."
      );
    }
    return;
  }

  const canonicalAuthority =
    _canonicalAuthorityState.getState();
  const localActionId =
    "aegis-action-" +
    sha256OfString(
      [
        canonicalAuthority.workspaceId,
        envelopeActionId,
        proposed,
        new Date().toISOString(),
      ].join("\n")
    );

  const canonicalProposal =
    buildAiExecutionGatewayMvp0CanonicalProposal(
      envelopeParseResult,
      {
        localActionId,
        workspaceId: canonicalAuthority.workspaceId,
        policyVersion: canonicalAuthority.policyVersion,
        rulesetVersion: canonicalAuthority.rulesetVersion,
        capabilityManifestVersion:
          canonicalAuthority.capabilityManifestVersion,
        sessionId: canonicalAuthority.sessionId,
      },
      "sha256:" + sha256OfString(proposed)
    );

  _canonicalAuthorityState.update(
    canonicalAuthority.revision,
    { actionId: canonicalProposal.action_id }
  );

  await queueCanonicalAuthorityPersistence(
    "ai-action-update"
  );

  const userRulePath = workspaceRoot ? nodePath.join(workspaceRoot, "AEGIS-USER-RULES.json") : "";
  let userRuleSet: AiExecutionGatewayMvp0UserDefinedRuleSet | null = null;

  if (userRulePath && fs.existsSync(userRulePath)) {
    let userRuleError = "";

    try {
      const userRuleValidation = validateAiExecutionGatewayMvp0UserDefinedRuleSet(
        JSON.parse(fs.readFileSync(userRulePath, "utf8"))
      );

      if (!userRuleValidation.valid || !userRuleValidation.ruleSet) {
        userRuleError = userRuleValidation.error || "INVALID_USER_RULE_SET";
      } else {
        userRuleSet = userRuleValidation.ruleSet;
      }
    } catch {
      userRuleError = "INVALID_JSON_USER_RULE_SET";
    }

    if (userRuleError) {
      const out = buildAiExecutionGatewayMvp0InvalidUserDefinedRuleSetReceiptLines({
        envelopeSource,
        envelopeIntent,
        userRuleError
      }).join("\n");

      await _platformPorts.clipboard.writeText(out);
      await _platformPorts.ui.showWarning("Aegis AI Execution Gateway MVP-0: user-defined rule set is invalid.");
      return;
    }
  }

  if (userRuleSet) {
    const userRuleResult = evaluateAiExecutionGatewayMvp0UserDefinedRules(proposed, userRuleSet);

    if (userRuleResult.blocked) {
      const out = buildAiExecutionGatewayMvp0UserDefinedRuleBlockedReceiptLines({
        envelopeSource,
        envelopeIntent,
        ruleSetId: userRuleResult.ruleSetId,
        matchedRule: userRuleResult.matchedRule,
        sanitizedCommandPreview: proposed.replace(/\s+/g, " ").replace(/(=)[^\s]+/g, "$1<redacted>").slice(0, 160)
      }).join("\n");

      await _platformPorts.clipboard.writeText(out);
      await _platformPorts.ui.showWarning("Aegis AI Execution Gateway MVP-0: blocked by a user-defined workspace rule.");
      return;
    }
  }

  if (
    _serverRulesetProductionAdapterStatus ===
    "DISABLED"
  ) {
    // Canonical production trust material is not provisioned.
    // Preserve the existing local Gateway flow.
  } else if (
    _serverRulesetProductionAdapterStatus ===
    "REJECTED"
  ) {
    await writeServerRulesetProductionBlockedReceipt(
      buildServerRulesetProductionConnectionBlockedReceiptLines(
        _serverRulesetProductionAdapterStatus,
        _serverRulesetProductionAdapterIssue
      ),
      "Aegis AI Execution Gateway MVP-0: production server ruleset supply was rejected."
    );

    return;
  } else {
    const serverRulesetComposition =
      _serverRulesetProductionComposition;

    if (
      serverRulesetComposition ===
      null
    ) {
      _serverRulesetProductionAdapterStatus =
        "REJECTED";

      _serverRulesetProductionAdapterIssue =
        "DEPENDENCIES_INVALID";

      await writeServerRulesetProductionBlockedReceipt(
        buildServerRulesetProductionConnectionBlockedReceiptLines(
          _serverRulesetProductionAdapterStatus,
          _serverRulesetProductionAdapterIssue
        ),
        "Aegis AI Execution Gateway MVP-0: production server ruleset composition is unavailable."
      );

      return;
    }

    let serverRulesetResult:
      ServerRulesetExtensionProductionEvaluationResult;

    try {
      serverRulesetResult =
        await serverRulesetComposition
          .evaluate(
            proposed
          );
    } catch {
      _serverRulesetProductionComposition =
        null;

      _serverRulesetProductionAdapterStatus =
        "REJECTED";

      _serverRulesetProductionAdapterIssue =
        "DEPENDENCIES_INVALID";

      await writeServerRulesetProductionBlockedReceipt(
        buildServerRulesetProductionConnectionBlockedReceiptLines(
          _serverRulesetProductionAdapterStatus,
          _serverRulesetProductionAdapterIssue
        ),
        "Aegis AI Execution Gateway MVP-0: production server ruleset evaluation failed closed."
      );

      return;
    }

    if (
      serverRulesetResult.blocked ||
      !serverRulesetResult.accepted
    ) {
      const serverRulesetReceiptLines =
        serverRulesetResult
          .receiptLines
          .length > 0
          ? serverRulesetResult
              .receiptLines
          : buildServerRulesetProductionConnectionBlockedReceiptLines(
              _serverRulesetProductionAdapterStatus,
              _serverRulesetProductionAdapterIssue
            );

      await writeServerRulesetProductionBlockedReceipt(
        Object.freeze([
          ...serverRulesetReceiptLines,
          "SERVER_RULESET_EXTENSION_ADAPTER_STATUS=" +
            _serverRulesetProductionAdapterStatus,
          "SERVER_RULESET_EXTENSION_ADAPTER_ISSUE=" +
            _serverRulesetProductionAdapterIssue,
          "SERVER_RULESET_SUPPLY_ISSUE=" +
            serverRulesetResult
              .supplyIssue,
        ]),
        "Aegis AI Execution Gateway MVP-0: blocked by the production server ruleset gate."
      );

      return;
    }
  }
  const workflowDriftResult = detectAiExecutionGatewayMvp0WorkflowDrift(proposed);
  const workflowDriftBlocked = workflowDriftResult.blocked;
  const workflowDriftPattern = workflowDriftResult.pattern;
  if (workflowDriftBlocked) {
    const out = buildAiExecutionGatewayMvp0WorkflowDriftBlockedReceiptLines({
      envelopeSource,
      envelopeIntent,
      workflowDriftPattern,
      sanitizedCommandPreview: proposed.replace(/\s+/g, " ").replace(/(=)[^\s]+/g, "$1<redacted>").slice(0, 160)
    }).join("\n");

    await _platformPorts.clipboard.writeText(out);
    await _platformPorts.ui.showWarning("Aegis AI Execution Gateway MVP-0: workflow drift blocked before execution.");
    return;
  }

  const actionQualityResult =
    evaluateAiExecutionGatewayMvp0ActionQuality(proposed);
  const gateResult =
    enforceAiExecutionGatewayMvp0EffectPreflight(
      canonicalProposal,
      actionQualityResult
    );
  const blocked = gateResult.status !== "ALLOW";
  let gatewayRuntimeControllerReviewConnected = false;
  let gatewayRuntimeControllerAvailable = false;
  let gatewayRuntimeControllerClipboardSummary = "";
  let gatewayRuntimeSessionId = "";
  let gatewayRuntimeSessionPhase = "";
  if (!_safetyKernelV31RuntimeController) {
    await _platformPorts.ui.showWarning("Aegis AI Execution Gateway MVP-0 requires Safety Kernel v3.1 Runtime Controller.");
    return;
  }
  if (_safetyKernelV31RuntimeController) {
    const runtimeTimestamp = new Date().toISOString();
    const runtimeResult = await _safetyKernelV31RuntimeController.review(
      {
        action_id: canonicalProposal.action_id,
        target: canonicalProposal.target_paths[0],
        intent: canonicalProposal.intent,
        proposed_action: canonicalProposal.proposed_action,
        context_hash: "sha256:" + sha256OfString(["ai_execution_gateway_mvp0", envelopeSource, envelopeIntent, proposed].join("\n")),
        timestamp: runtimeTimestamp,
        adapter_id: "aegis-ai-execution-gateway-mvp0-runtime-controller",
        policy_version: "safety-kernel-v31-runtime-controller-review-v1",
        human_readable_summary: "Review AI Execution Gateway MVP-0 envelope through Safety Kernel v3.1 Runtime Controller.",
      },
      gateResult
    );
    gatewayRuntimeControllerReviewConnected = true;
    gatewayRuntimeControllerAvailable = true;
    gatewayRuntimeControllerClipboardSummary = runtimeResult.output.clipboardSummary;
    gatewayRuntimeSessionId = runtimeResult.session?.sessionId ?? "";
    gatewayRuntimeSessionPhase = runtimeResult.session?.lifecyclePhase ?? "";
    if (runtimeResult.output.record) {
      synchronizeCanonicalAuthorityFromSafetyKernel({
        actionId: runtimeResult.output.record.actionId,
        sessionId: runtimeResult.session?.sessionId ?? null,
        approvalNonceSha256:
          runtimeResult.output.record.approvalNonceSha256,
        lifecyclePhase:
          runtimeResult.output.record.lifecyclePhase,
      });
    }
    if (runtimeResult.session) {
      scheduleSafetyKernelV31WarnTimeout(runtimeResult.session);
    }
  }

  const out = buildAiExecutionGatewayMvp0FinalReviewedOnlyReceiptLines({
    envelopeSource,
    envelopeIntent,
    envelopeActionId,
    envelopeCapabilityId,
    gateResult,
    sanitizedCommandPreview: proposed.replace(/\s+/g, " ").replace(/(=)[^\s]+/g, "$1<redacted>").slice(0, 160),
    gatewayHandoffBlocked: blocked,
    runtimeControllerReviewConnected: gatewayRuntimeControllerReviewConnected,
    runtimeControllerAvailable: gatewayRuntimeControllerAvailable,
    runtimeControllerClipboardSummary: gatewayRuntimeControllerClipboardSummary,
    runtimeSessionId: gatewayRuntimeSessionId,
    runtimeSessionPhase: gatewayRuntimeSessionPhase
  }).join("\n");

  await _platformPorts.clipboard.writeText(out);
  await _platformPorts.ui.showInfo("Aegis AI Execution Gateway MVP-0: envelope reviewed only; no execution performed.");
  } catch (err) {
    logAegisError("[Aegis] aiExecutionGatewayMvp0 error:", err);
    try {
      await _platformPorts.ui.showWarning("Aegis AI Execution Gateway MVP-0 could not complete review.");
    } catch {
      // Best-effort warning only.
    }
  }
}

function listTrustedLocalVerificationEvidenceFiles(root: string): string[] {
  if (!fs.existsSync(root)) {
    return [];
  }

  const files: string[] = [];
  const directories: string[] = [root];

  while (directories.length > 0) {
    const current = directories.pop();

    if (!current) {
      continue;
    }

    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolutePath = nodePath.join(current, entry.name);

      if (entry.isDirectory()) {
        directories.push(absolutePath);
      } else {
        files.push(absolutePath);
      }
    }
  }

  return files.sort();
}

async function handleRunTrustedLocalVerification(): Promise<void> {
  const lines: string[] = [
    "STEP=TRUSTED_LOCAL_VERIFICATION",
    "COMMAND=aegis.runTrustedLocalVerification",
    "PROTECTED_TARGET=.env"
  ];

  let mutationMayHaveStarted = false;

  try {
    if (
      !_engine ||
      !_stores ||
      !_stateMgr ||
      !_projectRoot ||
      !_aegisDir
    ) {
      throw new Error("OPEN_FOLDER_REQUIRED");
    }

    const expectedBaselineContent =
      "AEGIS_TRUSTED_VSIX_BASELINE=TRUE\n" +
      "AEGIS_PROOF_TARGET=.env\n";

    const target = getProtectedTargets().find(
      candidate =>
        candidate.relative_path === ".env" &&
        candidate.restore_enabled
    );

    if (!target) {
      throw new Error(
        "TRUSTED_VERIFICATION_TARGET_NOT_CONFIGURED"
      );
    }

    const targetPath = nodePath.join(
      _projectRoot,
      target.relative_path
    );

    const baselineContent = await fs.promises.readFile(
      targetPath,
      "utf8"
    );

    if (baselineContent !== expectedBaselineContent) {
      throw new Error(
        "TRUSTED_VERIFICATION_REFUSED_NON_ISOLATED_WORKSPACE"
      );
    }

    const baselineSha256 = sha256OfString(baselineContent);
    const store = _stores.get(target.target_id);

    if (!store) {
      throw new Error(
        "TRUSTED_VERIFICATION_STORE_UNAVAILABLE"
      );
    }

    const markerPresent = await readBaselineMarker(
      _aegisDir,
      target.marker_file
    );

    const existingIndex = await readSnapshotIndexOrNull(
      store,
      "[Aegis] trusted verification index read threw:"
    );

    if (markerPresent || existingIndex) {
      throw new Error(
        "TRUSTED_VERIFICATION_REQUIRES_FRESH_ISOLATED_WORKSPACE"
      );
    }

    const snapshotId =
      await createBaselineSnapshotFromContentOrNull(
        store,
        baselineContent,
        targetPath,
        target.relative_path,
        "[Aegis] trusted verification baseline creation threw:"
      );

    if (!snapshotId) {
      throw new Error(
        "TRUSTED_VERIFICATION_BASELINE_CREATION_FAILED"
      );
    }

    const markerWritten = await writeBaselineMarker(
      _aegisDir,
      target.marker_file,
      target.relative_path
    );

    if (!markerWritten) {
      throw new Error(
        "TRUSTED_VERIFICATION_BASELINE_MARKER_FAILED"
      );
    }

    lines.push("BASELINE_REGISTERED=True");
    lines.push("BASELINE_SHA256=" + baselineSha256);

    const gatewayEnvelope = JSON.stringify({
      source: "ai_connector",
      intent: "propose_terminal_command",
      actionId: "AEGIS_AI_EXECUTION_GATEWAY_MVP0_REVIEW_ONLY",
      capabilityId: "ai_gateway_review_only",
      targetPath: "package.json",
      proposedCommand: "node --version"
    });

    await vscode.commands.executeCommand(
      "aegis.aegisExecutionGatewayMvp0",
      gatewayEnvelope
    );

    const gatewayReceipt = await vscode.env.clipboard.readText();
    const gatewayReviewCompleted =
      gatewayReceipt.trim().length > 0;

    lines.push(
      "PRODUCT_GATEWAY_REVIEW_COMPLETED=" +
      String(gatewayReviewCompleted)
    );

    const runtimeController =
      _safetyKernelV31RuntimeController;

    const authorityComposition =
      _safetyKernelV31AuthorityBindingComposition;

    if (!runtimeController || !authorityComposition) {
      throw new Error(
        "TRUSTED_VERIFICATION_RUNTIME_NOT_CONNECTED"
      );
    }

    const mutationMarker =
      "\nAEGIS_TRUSTED_LOCAL_VERIFICATION=" +
      Date.now().toString() +
      "\n";

    const mutationMarkerBase64 =
      Buffer.from(mutationMarker, "utf8").toString("base64");

    const mutationCommand =
      "node -e \"require('fs').appendFileSync('.env'," +
      "Buffer.from('" +
      mutationMarkerBase64 +
      "','base64'))\"";

    const reviewed = await runtimeController.review(
      {
        action_id:
          "trusted-local-verification-" +
          Date.now().toString(),
        target: ".env",
        intent:
          "execute isolated trusted local verification mutation",
        proposed_action: mutationCommand,
        context_hash:
          "sha256:" +
          sha256OfString(
            "trusted-local-verification-mutation"
          ),
        timestamp: new Date().toISOString(),
        adapter_id:
          "aegis-trusted-local-verification-command",
        policy_version:
          "safety-kernel-v31-trusted-local-verification",
        human_readable_summary:
          "Append one marker to the isolated verification .env."
      },
      {
        status: "ALLOW",
        userMessage:
          "Approved isolated trusted-local verification mutation.",
        internalRuleId:
          "TRUSTED_LOCAL_VERIFICATION_ALLOW",
        source: "vscode_command",
        reasons: [
          "Exact isolated verification baseline matched",
          "Single protected target",
          "Verified restore required"
        ],
        detectedEffects: []
      }
    );

    if (
      reviewed.session === null ||
      reviewed.session.lifecyclePhase !==
        "ALLOW_PENDING_EXECUTION"
    ) {
      throw new Error(
        "TRUSTED_VERIFICATION_ALLOW_SESSION_NOT_CREATED"
      );
    }

    const currentAuthorityBinding =
      await authorityComposition.readPort.readCurrentBinding();

    const bound =
      runtimeController.bindAllowedExecutionSessionAuthority(
        reviewed.session.sessionId,
        {
          authorityRevision:
            currentAuthorityBinding.authorityRevision,
          workspaceId:
            currentAuthorityBinding.workspaceId,
          snapshotBindingSha256:
            currentAuthorityBinding.snapshotBindingSha256,
          cwd: _projectRoot
        }
      );

    if (!bound.authorityBound) {
      throw new Error(
        "TRUSTED_VERIFICATION_AUTHORITY_BINDING_FAILED"
      );
    }

    mutationMayHaveStarted = true;

    const coordinated =
      await runtimeController.coordinateAllowedExecutionSession(
        reviewed.session.sessionId
      );

    const mutatedContent = await fs.promises.readFile(
      targetPath,
      "utf8"
    );

    const mutatedSha256 = sha256OfString(mutatedContent);
    const mutationChanged =
      mutatedSha256 !== baselineSha256;

    lines.push("AUTHORITY_BOUND=True");
    lines.push(
      "COORDINATION_STATUS=" + coordinated.status
    );
    lines.push(
      "SESSION_CONSUMED=" +
      String(
        coordinated.status === "completed" &&
        coordinated.session.lifecyclePhase === "CONSUMED"
      )
    );
    lines.push(
      "PROTECTED_MUTATION_EXECUTED=" +
      String(mutationChanged)
    );
    lines.push("MUTATED_SHA256=" + mutatedSha256);

    if (
      coordinated.status !== "completed" ||
      coordinated.session.lifecyclePhase !== "CONSUMED" ||
      !mutationChanged
    ) {
      throw new Error(
        "TRUSTED_VERIFICATION_RUNTIME_MUTATION_FAILED"
      );
    }

    await handleRestore();

    const restoredContent = await fs.promises.readFile(
      targetPath,
      "utf8"
    );

    const restoredSha256 = sha256OfString(restoredContent);
    const restoredMatchesBaseline =
      restoredSha256 === baselineSha256 &&
      restoredContent === expectedBaselineContent;

    lines.push("RESTORE_EXECUTED=True");
    lines.push("RESTORED_SHA256=" + restoredSha256);
    lines.push(
      "RESTORED_HASH_MATCHES_BASELINE=" +
      String(restoredMatchesBaseline)
    );

    if (!restoredMatchesBaseline) {
      throw new Error(
        "TRUSTED_VERIFICATION_RESTORE_ROUND_TRIP_FAILED"
      );
    }

    mutationMayHaveStarted = false;

    const evidenceRoot = nodePath.join(
      _aegisDir,
      "safety-kernel-v31"
    );

    const evidenceFiles =
      listTrustedLocalVerificationEvidenceFiles(evidenceRoot);

    const evidenceJsonlPath = nodePath.join(
      evidenceRoot,
      "evidence.jsonl"
    );

    const runtimeEvidencePresent =
      fs.existsSync(evidenceJsonlPath) &&
      fs.statSync(evidenceJsonlPath).size > 0;

    lines.push(
      "RUNTIME_EVIDENCE_PRESENT=" +
      String(runtimeEvidencePresent)
    );

    lines.push(
      "RUNTIME_EVIDENCE_FILE_COUNT=" +
      evidenceFiles.length.toString()
    );

    for (const evidenceFile of evidenceFiles) {
      lines.push(
        "RUNTIME_EVIDENCE_FILE=" +
        nodePath.relative(_projectRoot, evidenceFile)
      );
    }

    const green =
      gatewayReviewCompleted &&
      bound.authorityBound &&
      coordinated.status === "completed" &&
      coordinated.session.lifecyclePhase === "CONSUMED" &&
      mutationChanged &&
      restoredMatchesBaseline &&
      runtimeEvidencePresent &&
      evidenceFiles.length > 0;

    lines.push(
      "TRUSTED_LOCAL_VSIX=" + String(green)
    );

    lines.push(
      "RESULT=" +
      (
        green
          ? "TRUSTED_LOCAL_VERIFICATION_GREEN"
          : "TRUSTED_LOCAL_VERIFICATION_FAILED"
      )
    );

    await _platformPorts.clipboard.writeText(
      lines.join("\n")
    );

    if (green) {
      await _platformPorts.ui.showInfo(
        "Aegis trusted local verification passed. Result copied to clipboard."
      );
    } else {
      await _platformPorts.ui.showWarning(
        "Aegis trusted local verification failed. Result copied to clipboard."
      );
    }
  } catch (err) {
    if (mutationMayHaveStarted) {
      lines.push("EMERGENCY_RESTORE_ATTEMPTED=True");

      try {
        await handleRestore();
        lines.push("EMERGENCY_RESTORE_COMPLETED=True");
      } catch {
        lines.push("EMERGENCY_RESTORE_COMPLETED=False");
      }
    }

    lines.push(
      "FAILURE_MESSAGE=" +
      (
        err instanceof Error
          ? err.message
          : String(err)
      )
    );

    lines.push("TRUSTED_LOCAL_VSIX=False");
    lines.push(
      "RESULT=TRUSTED_LOCAL_VERIFICATION_FAILED"
    );

    await _platformPorts.clipboard.writeText(
      lines.join("\n")
    ).catch(() => undefined);

    await _platformPorts.ui.showWarning(
      "Aegis trusted local verification failed. Result copied to clipboard."
    ).catch(() => undefined);
  }
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  try {
    _licenseTier = await getLicenseTier();
  } catch (err) {
    logAegisWarning("[Aegis] license tier initialization failed; defaulting to free:", err);
    _licenseTier = "free";
  }
  context.subscriptions.push(
    vscode.commands.registerCommand("aegis.protectedTerminal", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      if (!isCurrentLicenseCapabilityAvailable("protectedTerminal")) { showWarningMessageBestEffort("Aegis Protected Terminal is not available for the current license tier."); return; }
      await handleProtectedTerminalMvp0();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aegis.aegisExecutionGatewayMvp0", async (rawEnvelope?: unknown) => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!isCurrentLicenseCapabilityAvailable("aiExecutionGatewayMvp0")) { showWarningMessageBestEffort("Aegis AI Execution Gateway MVP-0 is not available for the current license tier."); return; }
        await handleAegisExecutionGatewayMvp0(
          typeof rawEnvelope === "string"
            ? rawEnvelope
            : undefined
        );
      } catch (err) {
        logAegisError("[Aegis] aiExecutionGateway command callback error:", err);
      }
    })
  );


  context.subscriptions.push(
    vscode.commands.registerCommand("aegis.runTrustedLocalVerification", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (
          !isCurrentLicenseCapabilityAvailable("coreProtection") ||
          !isCurrentLicenseCapabilityAvailable("aiExecutionGatewayMvp0")
        ) {
          showWarningMessageBestEffort(
            "Aegis trusted local verification is not available for the current license tier."
          );
          return;
        }

        await handleRunTrustedLocalVerification();
      } catch (err) {
        logAegisError(
          "[Aegis] trustedLocalVerification command callback error:",
          err
        );
        showWarningMessageBestEffort(
          "Aegis trusted local verification could not complete."
        );
      }
    })
  );

  // AI Compliance review is exposed through aegis.reviewAiCommandOrAction.
  // No environment-gated auto-open path is retained.


  // All three commands are registered here. If initializeAegis() fails,
  // the commands still exist and show a sensible message.

  
  context.subscriptions.push(
    vscode.commands.registerCommand("aegis.reviewAiCommandOrAction", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!isCurrentLicenseCapabilityAvailable("aiCommandReview")) { showWarningMessageBestEffort("Aegis Review AI Command is not available for the current license tier."); return; }
        await handleReviewAiCommandOrAction();
      } catch (err) {
        logAegisError("[Aegis] reviewAiCommand command callback error:", err);
      }
})
  );
context.subscriptions.push(
    vscode.commands.registerCommand("aegis.readSafetyKernelV31Session", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!isCurrentLicenseCapabilityAvailable("aiCommandReview")) {
          showWarningMessageBestEffort("Aegis Safety Kernel session lookup is not available for the current license tier.");
          return;
        }
        await handleReadSafetyKernelV31Session();
      } catch (err) {
        logAegisError("[Aegis] readSafetyKernelV31Session command callback error:", err);
      }
    })
  );
context.subscriptions.push(
    vscode.commands.registerCommand("aegis.confirmSafetyKernelV31WarnSession", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!isCurrentLicenseCapabilityAvailable("aiCommandReview")) {
          showWarningMessageBestEffort("Aegis Safety Kernel WARN confirmation is not available for the current license tier.");
          return;
        }
        await handleConfirmSafetyKernelV31WarnSession();
      } catch (err) {
        logAegisError("[Aegis] confirmSafetyKernelV31WarnSession command callback error:", err);
      }
    })
  );
context.subscriptions.push(
    vscode.commands.registerCommand("aegis.cancelSafetyKernelV31WarnSession", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!isCurrentLicenseCapabilityAvailable("aiCommandReview")) {
          showWarningMessageBestEffort("Aegis Safety Kernel WARN cancellation is not available for the current license tier.");
          return;
        }
        await handleCancelSafetyKernelV31WarnSession();
      } catch (err) {
        logAegisError("[Aegis] cancelSafetyKernelV31WarnSession command callback error:", err);
      }
    })
  );
context.subscriptions.push(

    vscode.commands.registerCommand("aegis.showProtectionPanel", () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!_initialized || !_stateMgr || !_engine || !_stores) {
          // Phase 5-E: status is INACTIVE (not SAFE) so the panel does not
          // falsely claim workspace protection when no folder is open.
          AegisWebviewPanel.show(
            {
              status: "INACTIVE",
              message: "Open a folder first to use Aegis.",
              restoreAvailable: false,
              isProcessing: false,
              licenseTier: _licenseTier,
          licenseCapabilities: getCapabilitiesForTier(_licenseTier),
            },
            async () => {
              showWarningMessageBestEffort("Open a folder first to use Aegis.");
            },
            () => ({
              status: "INACTIVE",
              message: "Open a folder first to use Aegis.",
              restoreAvailable: false,
              isProcessing: false,
              licenseTier: _licenseTier,
          licenseCapabilities: getCapabilitiesForTier(_licenseTier),
            }),
            () => null   // no risk scan without a workspace
          );
          return;
        }
        if (!isCurrentLicenseCapabilityAvailable("coreProtection")) { showWarningMessageBestEffort("Aegis core protection is not available for the current license tier."); return; }
        AegisWebviewPanel.show(
          withLicenseTier(_stateMgr.getState()),
          handleRestore,
          () => withLicenseTier(_stateMgr!.getState()),
      () => _riskScanResult   // Phase 3-A - always use current cached result
        );
      } catch (err) {
        logAegisError("[Aegis] showProtectionPanel error:", err);
      }
    }),

    vscode.commands.registerCommand("aegis.phase1.status", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!_initialized || !_stateMgr) {
          showInformationMessageBestEffort("Open a folder first to use Aegis Phase 1.");
          return;
        }
        const s = _stateMgr.getState();
        const tier = _licenseTier;
        const capabilities = getCapabilitiesForTier(tier).join(", ");
        showInformationMessageBestEffort(
          `Aegis: ${s.status} - ${s.message} (tier: ${tier}; capabilities: ${capabilities})`
        );
      } catch (err) {
        logAegisError("[Aegis] status command error:", err);
      }
    }),

    vscode.commands.registerCommand("aegis.phase1.restoreLastSafeState", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!_initialized || !_engine || !_stores || !_stateMgr) {
          showWarningMessageBestEffort("Open a folder first to use Aegis Phase 1.");
          return;
        }
        if (!isCurrentLicenseCapabilityAvailable("coreProtection")) { showWarningMessageBestEffort("Aegis core protection is not available for the current license tier."); return; }
        await handleRestore();
      } catch (err) {
        logAegisError("[Aegis] restoreLastSafeState command error:", err);
        showWarningMessageBestEffort("Aegis could not complete verified restore.");
      }
    }),

    vscode.commands.registerCommand("aegis.generateWorkReceipt", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!_initialized || !_receipt) {
          showWarningMessageBestEffort("Open a folder first to use Aegis.");
          return;
        }
        if (!isCurrentLicenseCapabilityAvailable("workReceipt")) { showWarningMessageBestEffort("Aegis Work Receipt is not available for the current license tier."); return; }
        await handleGenerateReceipt();
      } catch (err) {
        logAegisError("[Aegis] generateWorkReceipt command error:", err);
        showWarningMessageBestEffort("Aegis could not generate the Work Receipt.");
      }
    }),

    vscode.commands.registerCommand("aegis.registerCleanBaseline", async () => {
      if (!ensureAegisWorkspaceTrustedForCommand()) { return; }
      try {
        if (!_initialized || !_stateMgr || !_engine || !_stores) {
          showWarningMessageBestEffort("Open a folder first to use Aegis.");
          return;
        }
        if (!isCurrentLicenseCapabilityAvailable("coreProtection")) { showWarningMessageBestEffort("Aegis core protection is not available for the current license tier."); return; }
        await handleRegisterCleanBaseline();
      } catch (err) {
        logAegisError("[Aegis] registerCleanBaseline command error:", err);
        showWarningMessageBestEffort("Aegis could not complete baseline registration.");
      }
    })
  );


  const trustGrantDisposable =
    vscode.workspace.onDidGrantWorkspaceTrust?.(() =>
      initializeAegisOnce(context).catch((err) => {
        logAegisError(
          "[Aegis] Workspace trust initialization error:",
          err
        );
      })
    );

  if (trustGrantDisposable) {
    context.subscriptions.push(trustGrantDisposable);
  }
  try {
    await initializeAegisOnce(context);
  } catch (err) {
    logAegisError("[Aegis] Unexpected activation error:", err);
  }
}

export async function deactivate(): Promise<void> {
  while (true) {
    const pendingPersistence =
      _canonicalAuthorityPersistenceQueue;

    await pendingPersistence;

    if (
      pendingPersistence ===
      _canonicalAuthorityPersistenceQueue
    ) {
      break;
    }
  }

  resetServerRulesetProductionConnection();
  _sessionHandoffProductionVerificationComposition = null;
  _verifierRecursionGuard = null;
  _safetyKernelV31AuthorityBindingComposition = null;
  _stateMgr?.dispose();
  _canonicalAuthorityPersistence = null;
  _canonicalAuthorityPersistenceQueue = Promise.resolve();
  _canonicalAuthorityState = null;
  // Phase 5-BT: dispose all FileSystemWatchers on extension deactivation.
  _watchers.forEach(w => w.dispose());
  _watchers = [];
  _debounceTimers.forEach(t => clearTimeout(t));
  _debounceTimers.clear();
  _safetyKernelV31WarnTimeoutTimers.forEach(t => clearTimeout(t));
  _safetyKernelV31WarnTimeoutTimers.clear();
}


async function initializeAegis(context: vscode.ExtensionContext): Promise<void> {
  if (!isAegisWorkspaceTrusted()) {
    return;
  }

  if (_initialized) {
    return;
  }

  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return;  // commands show "Open a folder first"
  }

  const projectRoot = folders[0].uri.fsPath;
  const aegisDir    = nodePath.join(projectRoot, ".aegis");

  _projectRoot = projectRoot;
  _aegisDir    = aegisDir;

  await initializeServerRulesetProductionConnection(context, projectRoot);
  _engine      = new EnvCoreEngine();
  // Phase 5-P: create one SnapshotStore per registered protected target.
  // Each store uses the target's snapshot_index_file so indexes are independent.
  // so all existing .env snapshots on disk remain fully compatible.
  _stores      = new Map<string, SnapshotStore>();
  for (const target of getProtectedTargets()) {
    const expectedRestoreAbsPath = nodePath.join(projectRoot, target.relative_path);
    _stores.set(target.target_id, new SnapshotStore(aegisDir, target.snapshot_index_file, expectedRestoreAbsPath));
  }
  _stateMgr    = new StateManager();

  const canonicalAuthorityWorkspaceId =
    "sha256:" +
    sha256OfString(
      [
        "aegis-workspace-v1",
        projectRoot,
      ].join("\n")
    );

  const canonicalAuthoritySnapshotPath =
    nodePath.join(
      aegisDir,
      "canonical-authority-state.json"
    );

  _canonicalAuthorityPersistence =
    new CanonicalAuthorityStateFilePersistence(
      canonicalAuthoritySnapshotPath
    );

  _canonicalAuthorityPersistenceQueue =
    Promise.resolve();

  const persistedCanonicalAuthority =
    await _canonicalAuthorityPersistence
      .load();

  if (
    persistedCanonicalAuthority !== null
  ) {
    if (
      persistedCanonicalAuthority
        .getState()
        .workspaceId !==
      canonicalAuthorityWorkspaceId
    ) {
      throw new Error(
        "CANONICAL_AUTHORITY_WORKSPACE_BINDING_MISMATCH"
      );
    }

    _canonicalAuthorityState =
      persistedCanonicalAuthority;
  } else {
    _canonicalAuthorityState =
      CanonicalAuthorityStateStore.create({
        workspaceId:
          canonicalAuthorityWorkspaceId,

        protectedTargets:
          getProtectedTargets(),

        initialUserVisibleState:
          _stateMgr.getState().status,
      });

    await _canonicalAuthorityPersistence
      .save(
        _canonicalAuthorityState
      );
  }

  const safetyKernelV31TargetReaders =
    createSafetyKernelV31SnapshotTargetIndexReaderCollection({
      targets: getProtectedTargets(),
      stores: _stores,
    });

  const safetyKernelV31BootstrapComposition =
    createSafetyKernelV31NodeProcessExtensionBootstrapComposition({
      authorityReader: _canonicalAuthorityState,
      targetReaders: safetyKernelV31TargetReaders,
      projectRoot,
      aegisDir,
      nodeProcessSpawner: spawnNodeProcess,
    });

  _safetyKernelV31AuthorityBindingComposition =
    safetyKernelV31BootstrapComposition.authorityBindingComposition;

  _safetyKernelV31RuntimeController =
    safetyKernelV31BootstrapComposition
      .nodeProcessExtensionComposition
      .extensionComposition
      .runtimeController;

  _verifierRecursionGuard =
    new VerifierRecursionGuard();

  _sessionHandoffProductionVerificationComposition =
    createSessionHandoffExtensionProductionVerificationComposition(
      projectRoot,
      {
        canonicalAuthorityReader:
          _canonicalAuthorityState,
        runtimeSessionReader:
          _safetyKernelV31RuntimeController,
        authorityBindingReadPort:
          _safetyKernelV31AuthorityBindingComposition.readPort,
        authorityBindingVerifier:
          _safetyKernelV31AuthorityBindingComposition.verifier,
      }
    );

  _ledger      = new LedgerWriter(aegisDir);   // Phase 2-B
  _receipt     = new ReceiptWriter(aegisDir);  // Phase 2-C2
  _initialized = true;

  context.subscriptions.push(_stateMgr);

  // Push every state change to the Webview (if open)
  context.subscriptions.push(
    _stateMgr.onDidChangeState((state) => {
      const canonicalAuthorityState =
        _canonicalAuthorityState;

      if (
        canonicalAuthorityState !== null
      ) {
        canonicalAuthorityState
          .synchronizeUserVisibleState(
            state.status
          );

        void queueCanonicalAuthorityPersistence(
          "visible-state-sync"
        ).catch(() => undefined);
      }

      AegisWebviewPanel.pushState(withLicenseTier(state));
    })
  );

  try {
    // Ensure the shared snapshots directory exists for all stores.
    // only the index file differs per target.
    for (const store of _stores.values()) {
      await store.ensureDirs();
    }
    await _ledger.ensureDirs();
  } catch (err) {
    logAegisError("[Aegis] Ledger directory init failed:", err);
  }

  // Phase 2-C2: initialise receipts directory (.aegis/receipts/)
  try {
    await _receipt.ensureDirs();
  } catch (err) {
    logAegisError("[Aegis] Receipts directory init failed:", err);
  }

  const engine   = _engine;
  const stores   = _stores;   // Phase 5-P: Map<target_id, SnapshotStore>
  const stateMgr = _stateMgr;

  try {
    for (const store of stores.values()) {
      await store.ensureDirs();
      const startupRecovery = await store.recoverStartupArtifacts();
      if (startupRecovery.removed > 0 || startupRecovery.failed > 0) {
        // Startup temp artifact recovery is intentionally silent during normal activation.
      }
      break;  // ensureDirs only needs to run once (shared snapshotsDir)
    }
  } catch (err) {
    logAegisError("[Aegis] Storage init failed:", err);
    showWarningMessageBestEffort(
      "Aegis: Could not create local storage. Restore may be unavailable."
    );
  }

  // Phase 2-B: initialise ledger directory (.aegis/ledger/)
  try {
  const ledger   = _ledger;   // Phase 2-B

  // Pre-compute the list of protected relative paths for the watcher filter.
  // This avoids importing protectedTargets inside the watcher closure.
  const protectedRelPaths = getProtectedTargets().map(t => t.relative_path);

  //
  // event.waitUntil() makes the OS save wait until capturePreSave resolves.
  // At that moment the disk still holds the pre-save content.
  // For a brand-new .env: capturePreSave stores content="" safely.
  context.subscriptions.push(
    vscode.workspace.onWillSaveTextDocument((event) => {
      try {
        const absPath = event.document.uri.fsPath;
        // Phase 5-P: detect any registered protected target, not just .env
        if (!isProtectedTargetFile(absPath, protectedRelPaths, projectRoot)) { return; }
        if (isInsideAegisDir(absPath, aegisDir))                { return; }
  // REALPATH_TARGET_BINDING_RUNTIME_GUARD_V1
  const realpathBinding = describeRealpathTargetBinding(absPath, projectRoot);
  if (realpathBinding.mayBeSymlinkOrJunction || realpathBinding.mayHaveHardlinkAlias || realpathBinding.mayResolveThroughAlias) {
    stateMgr.setWarning(
      "Aegis blocked protected target handling because the file resolves through a symlink, junction, hardlink, or filesystem alias."
    );
    return;
  }
        if (engine.isRestoring(absPath))                        { return; }

        event.waitUntil(
          engine.capturePreSave(absPath).catch((err) => {
            logAegisError("[Aegis] capturePreSave error:", err);
          })
        );
      } catch (err) {
        logAegisError("[Aegis] onWillSaveTextDocument error:", err);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      let savedHashForWatcherDedup: string | null = null;
      try {
        try {
          const savedContent = await fs.promises.readFile(doc.uri.fsPath, "utf8");
          savedHashForWatcherDedup = sha256OfString(savedContent);
          markEditorSaveWatcherEvent(doc.uri.fsPath, savedHashForWatcherDedup);
        } catch {
          logAegisWarning("[Aegis] Could not mark editor save for watcher deduplication.");
        }
        await handleDidSave(doc, projectRoot, aegisDir, engine, stores, stateMgr, ledger, protectedRelPaths);
      } catch (err) {
        if (savedHashForWatcherDedup) {
          clearEditorSaveWatcherEvent(doc.uri.fsPath, savedHashForWatcherDedup);
        }
        logAegisError("[Aegis] onDidSaveTextDocument error:", err);
      }
    })
  );

  showInformationMessageBestEffort(
    "Aegis is active. Open and save a protected target to begin protection."
  );

  //
  // Watches for deletion and external modification of registered protected
  // targets between save events. This closes the detection gap identified in
  // Phase 5-BP T1/T2: a file deleted outside VS Code produced no save event
  // and the panel remained Safe.
  //
  // Design decisions (per Phase 5-BS design lock):
  //     index with baseline fields) trigger BLOCKED.
  //   - SAFE is never set by a watcher event.
  //   - Watchers stored in _watchers for disposal on deactivation.
  _watchers.forEach(w => w.dispose());
  _watchers = [];
  // FIX-01: Clear any pending debounce timers from the previous watcher set.
  // Without this, a stale delayed callback from a disposed watcher could fire
  // after the new watcher set is installed, causing a spurious state change.
  _debounceTimers.forEach(t => clearTimeout(t));
  _debounceTimers.clear();

  for (const target of getProtectedTargets()) {
    const pattern = new vscode.RelativePattern(
      vscode.Uri.file(projectRoot),
      target.relative_path
    );
    const watcher = vscode.workspace.createFileSystemWatcher(
      pattern,
      /* ignoreCreateEvents */ true,
      /* ignoreChangeEvents */ false,
      /* ignoreDeleteEvents */ false
    );

    watcher.onDidDelete(() => {
      scheduleWatcherAction(target, "delete", projectRoot, aegisDir, stores, stateMgr, ledger);
    });
    watcher.onDidChange(() => {
      scheduleWatcherAction(target, "change", projectRoot, aegisDir, stores, stateMgr, ledger);
    });

    _watchers.push(watcher);
  }

  //
  // StateManager always starts SAFE. After VS Code reload/restart, the
  // in-memory state is lost. We must re-derive the correct state from
  // disk before showing the UI or running the Risk Scan.
  //
  // This call is non-fatal: if rehydration fails for any reason, the
  // extension continues in SAFE state. That is preferable to crashing,
  // but the user may see an incorrect SAFE. The error is logged.
  //
  // IMPORTANT: rehydration does NOT write any ledger event. It is a
  // startup state check, not a new user action. Ledger truthfulness
  // requires that events reflect actual user-initiated facts only.
  try {
    await rehydrateStateOnActivation(projectRoot, aegisDir, stores, stateMgr);
  } catch (err) {
    logAegisError("[Aegis] State rehydration failed:", err);
    // BLOCKER-03: Do NOT fall back to SAFE on rehydration failure.
    // If we cannot verify disk state, we cannot claim the workspace is safe.
    // Set WARNING so the user knows Aegis could not confirm protection.
    try {
      stateMgr.setWarning(
        "Aegis could not verify workspace safety on activation. " +
        "Save protected files to re-establish protection status."
      );
    } catch (err) {
      logAegisError("[Aegis] Could not set Warning state after rehydration failure:", err);
    }
  }


  // LEDGER_STARTUP_INTEGRITY_EXTENSION_WIRING_RUNTIME_GUARD_V1
  // Startup-only evidence check: no ledger event is written here.
  try {
    const ledgerStartupIntegrity = await _ledger.verifyStartupIntegrity();
    if (ledgerStartupIntegrity.issueCode === "RECOVERED_MALFORMED_LEDGER_TAIL") {
      stateMgr.setWarning(
        "Aegis recovered a malformed ledger tail on startup. Check local evidence before relying on receipts."
      );
      logAegisWarning("[Aegis] Ledger startup tail recovery completed:", ledgerStartupIntegrity.issueLineNumber);
    } else if (!ledgerStartupIntegrity.ok) {
      stateMgr.setWarning(
        "Aegis ledger integrity could not be verified on startup. Check local evidence before relying on receipts."
      );
      logAegisError("[Aegis] Ledger startup integrity check failed:", ledgerStartupIntegrity.issueCode);
    }
  } catch (err) {
    logAegisError("[Aegis] Ledger startup integrity check threw:", err);
    stateMgr.setWarning(
      "Aegis ledger integrity check failed on startup. Check local evidence before relying on receipts."
    );
  }

  //
  // Run once after workspace is fully initialized. Wrapped in try/catch so
  // scan failure NEVER affects the protection or restore flow.
  // Results are cached in _riskScanResult and re-sent whenever the Webview
  // opens or its JS context reloads (via the "ready" handler below).
  try {
    _riskScanResult = await runRiskScan(projectRoot);
    AegisWebviewPanel.pushRiskScan(_riskScanResult);
  } catch (err) {
    logAegisError("[Aegis] Risk scan failed (non-fatal):", err);
  }
}
  catch (err) {
    throw err;
  }
}


/**
 * Re-derive the correct SAFE/BLOCKED/WARNING state from disk on every
 * extension activation (initial open, VS Code reload, VS Code restart).
 *
 * Phase 5-P: loops over all registered protected targets.
 * If ANY target has a registered baseline AND its current disk content
 * differs from the safe snapshot hash, state becomes BLOCKED.
 * If ALL targets with registered baselines match their snapshots, SAFE.
 *
 * CONTENT SAFETY:
 *   Raw file content is read into a local variable, hashed, and discarded.
 *   It is NEVER logged, stored, written to ledger, or shown in the UI.
 *   Only SHA-256 hex strings are compared.
 *
 * LEDGER SAFETY:
 *   No ledger event is written. Rehydration is a startup state check only.
 */
async function rehydrateStateOnActivation(
  projectRoot: string,
  aegisDir:    string,
  stores:      Map<string, SnapshotStore>,
  stateMgr:    StateManager
): Promise<void> {
  const targets = getProtectedTargets();
  let anyBlocked      = false;
  let anyWarning      = false;
  let anyVerifiedSafe = false;   // true if at least one target was checked and matched baseline
  let firstBlockedRelPath: string | undefined;
  let firstBlockedSnapshotId: string | undefined;

  for (const target of targets) {
    const store = stores.get(target.target_id);
    if (!store) { continue; }

    //
    // BLOCKER-03: Use both marker AND index to determine registration status.
    // If either indicates a prior registration, treat as registered.
    const markerPresent = await readBaselineMarker(aegisDir, target.marker_file);
    const idx           = await readSnapshotIndexOrNull(store, "[Aegis] baseline registration status index read threw:");
    const idxHasBaseline = !!(idx &&
                               idx.baseline_snapshot_file &&
                               idx.baseline_content_sha256);

    // Do not assume safe. Treat as a warning condition.
    if (!markerPresent && !idx) {
      // Check if the protected file actually exists on disk.
      const absPath = nodePath.join(projectRoot, target.relative_path);
      let fileExists = false;
      try { await fs.promises.access(absPath); fileExists = true; } catch { /* absent */ }

      if (fileExists) {
        // Protected file exists on disk but has no baseline evidence.
        // BLOCKER-03: Do not show Safe in this state.
        // The file may have content but Aegis has not verified it.
        anyWarning = true;
      }
      continue;
    }

    if (idx && !idxHasBaseline) {
      anyWarning = true;
      continue;
    }

    // Marker present but no index (index was deleted/corrupted after registration).
    if (markerPresent && !idx) {
      anyWarning = true;
      continue;
    }

    // At this point: we have an index with valid baseline fields.
    // Either marker is present, or index-with-baseline is present (or both).
    // idx is guaranteed non-null and idxHasBaseline is true.

    const absPath = nodePath.join(projectRoot, target.relative_path);
    let currentContent: string;
    try {
      currentContent = await fs.promises.readFile(absPath, "utf8");
    } catch {
      continue;
    }

    //
    // BLOCKER-01/03: Use the immutable baseline hash, never rolling content_sha256.
    const currentHash  = sha256OfString(currentContent);
    const baselineHash = idx!.baseline_content_sha256;

    if (currentHash !== baselineHash) {
      anyBlocked = true;
      if (!firstBlockedRelPath) {
        firstBlockedRelPath    = target.relative_path;
        firstBlockedSnapshotId = idx!.snapshot_id;
      }
    } else {
      anyVerifiedSafe = true;
    }
  }

  //
  // BLOCKER-03: setSafe is only called when at least one target was verified
  // clean AND no target is blocked or warning. If all protected files are
  // "Aegis is protecting this workspace" would be misleading when no baseline
  // has been verified.
  if (anyBlocked) {
    stateMgr.setBlocked(
      "Aegis detected a protected file change. Restore is available.",
      firstBlockedRelPath,
      firstBlockedSnapshotId
    );
  } else if (anyWarning) {
    stateMgr.setWarning(
      "Aegis: Protected baseline is not fully registered. " +
      "Save protected files once to complete baseline registration before AI edits."
    );
  } else if (anyVerifiedSafe) {
    // At least one target was checked against its baseline and matched.
    // All checked targets are at their baselines. Safe is correct.
    stateMgr.setSafe("Aegis is protecting this workspace.");
  } else {
    // No targets had registration evidence and no targets exist on disk.
    // let the StateManager initial SAFE stand (no state call needed).
    // setSafe is called explicitly for clarity.
    stateMgr.setSafe("Aegis is active. Save a protected file to register a baseline.");
  }
}


/**
 * Absolute path to a target's baseline registration marker file.
 * Phase 5-P: markerFileName is per-target (e.g. "baseline-registered.json"
 * for .env, "baseline-registered.env_local.json" for .env.local).
 */
function baselineMarkerPath(aegisDir: string, markerFileName: string): string {
  return nodePath.join(aegisDir, markerFileName);
}

/**
 * Read the baseline registration marker for a specific target.
 *
 *
 *
 * @param aegisDir       Absolute path to .aegis directory.
 * @param markerFileName Per-target marker filename from the registry.
 */
async function readBaselineMarker(aegisDir: string, markerFileName: string): Promise<boolean> {
  try {
    const raw    = await fs.promises.readFile(baselineMarkerPath(aegisDir, markerFileName), "utf8");
    const parsed = JSON.parse(raw) as BaselineRegistrationMarker;
    return parsed.registered === true;
  } catch {
    return false;
  }
}

/**
 * Write the baseline registration marker for a specific target after
 * verified snapshot creation.
 *
 * Must be called ONLY after store.createBaselineSnapshotFromContent() returns
 * a non-null snapshotId. Never call if snapshot creation failed.
 *
 * Marker content is secret-safe: no file content, no key names, no values.
 *
 * Returns true on success, false on failure.
 *
 * @param aegisDir       Absolute path to .aegis directory.
 * @param markerFileName Per-target marker filename from the registry.
 */
async function writeExtensionDurableUtf8File(targetPath: string, content: string): Promise<void> {
  // EXTENSION_CRASH_SAFE_DURABLE_WRITE_RUNTIME_GUARD_V1
  const targetDir = nodePath.dirname(targetPath);
  const tempPath = nodePath.join(
    targetDir,
    `.${nodePath.basename(targetPath)}.${process.pid}.${Date.now()}.tmp`
  );

  let keepTemp = true;
  try {
    const handle = await fs.promises.open(tempPath, "w");
    try {
      await handle.writeFile(content, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }

    await fs.promises.rename(tempPath, targetPath);
    keepTemp = false;
    await bestEffortSyncExtensionDirectory(targetDir);
  } finally {
    if (keepTemp) {
      try { await fs.promises.unlink(tempPath); } catch { /* best effort cleanup */ }
    }
  }
}

async function bestEffortSyncExtensionDirectory(targetDir: string): Promise<void> {
  // EXTENSION_DIRECTORY_SYNC_BEST_EFFORT_GUARD_V1
  try {
    const dirHandle = await fs.promises.open(targetDir, "r");
    try {
      await dirHandle.sync();
    } finally {
      await dirHandle.close();
    }
  } catch {
    // Directory fsync is best-effort across platforms.
  }
}

async function writeBaselineMarker(
  aegisDir:      string,
  markerFileName: string,
  protectedPath: string
): Promise<boolean> {
  const marker: BaselineRegistrationMarker = {
    schemaVersion:  1,
    registered:     true,
    registeredAt:   new Date().toISOString(),
    protectedPath,
  };
  try {
    await writeExtensionDurableUtf8File(
      baselineMarkerPath(aegisDir, markerFileName),
      JSON.stringify(marker, null, 2));
    return true;
  } catch (err) {
    logAegisError("[Aegis] Baseline marker write failed:", err);
    return false;
  }
}


async function handleDidSave(
  doc:              vscode.TextDocument,
  projectRoot:      string,
  aegisDir:         string,
  engine:           EnvCoreEngine,
  stores:           Map<string, SnapshotStore>,
  stateMgr:         StateManager,
  ledger:           LedgerWriter | null,
  protectedRelPaths: ReadonlyArray<string>
): Promise<void> {
  const absPath = doc.uri.fsPath;

  if (!isProtectedTargetFile(absPath, protectedRelPaths, projectRoot)) { return; }
  if (isInsideAegisDir(absPath, aegisDir))                { return; }
  // REALPATH_TARGET_BINDING_RUNTIME_GUARD_V1
  const realpathBinding = describeRealpathTargetBinding(absPath, projectRoot);
  if (realpathBinding.mayBeSymlinkOrJunction || realpathBinding.mayHaveHardlinkAlias || realpathBinding.mayResolveThroughAlias) {
    stateMgr.setWarning(
      "Aegis blocked protected target handling because the file resolves through a symlink, junction, hardlink, or filesystem alias."
    );
    return;
  }
  if (engine.isRestoring(absPath))                        { return; }

  const relPath = nodePath.relative(projectRoot, absPath).replace(/\\/g, "/");

  // Look up which registered target this save belongs to.
  const target = getTargetByRelPath(relPath);
  if (!target) {
    return;
  }

  const store = stores.get(target.target_id);
  if (!store) {
    logAegisError("[Aegis] No store found for target:", target.target_id);
    return;
  }

  const baseline = engine.consumePending(absPath);

  if (!baseline) {
    stateMgr.setWarning(
      `Aegis detected a ${target.relative_path} change, but no pre-save baseline is available. ` +
      `Save ${target.relative_path} again to create a restore point.`
    );
    return;
  }

  //
  // BLOCKER-03: Baseline registration must be one-time and conservative.
  // The previous design used only the marker as the gate. If the marker was
  // transiently unreadable or absent (e.g. not yet written on first session),
  // the registration path ran with the current (possibly contaminated) content.
  //
  // Required gate: treat the target as registered if EITHER:
  //   (a) marker exists, OR
  //   (b) index exists with both baseline_snapshot_file and baseline_content_sha256
  //
  // Only allow first-time registration when BOTH marker AND index are absent.
  //

  const markerRegistered = await readBaselineMarker(aegisDir, target.marker_file);
  const existingIndex    = await readSnapshotIndexOrNull(store, "[Aegis] protected-change registration index read threw:");

  // Determine evidence of prior registration
  const indexHasBaseline = !!(existingIndex &&
                              existingIndex.baseline_snapshot_file &&
                              existingIndex.baseline_content_sha256);
  const indexExists      = !!existingIndex;

  const isFirstRegistration = !markerRegistered && !indexExists;
  const isMarkerLossReregistration = !markerRegistered && indexHasBaseline;
  const isDegradedIndex = indexExists && !indexHasBaseline;

  if (!markerRegistered && !isFirstRegistration && !isMarkerLossReregistration && isDegradedIndex) {
    // Do not register a new baseline. Cannot prove safety.
    stateMgr.setBlocked(
      `Aegis: ${target.relative_path} restore index is degraded (missing baseline fields). ` +
      `Delete .aegis and save the file again to re-register a clean baseline.`,
      relPath,
      undefined
    );
    showWarningMessageBestEffort(
      `Aegis: ${target.relative_path} index is degraded. Delete .aegis and re-register.`
    );
    return;
  }

  if (isFirstRegistration || isMarkerLossReregistration) {
    // BASELINE REGISTRATION PATH for this target
    //
    // Reached for either first registration or E-P0-2 marker-loss recovery.
    // Marker-loss recovery requires an existing index with immutable baseline fields.

    let postSaveContent: string;
    try {
      postSaveContent = await fs.promises.readFile(absPath, "utf8");
    } catch (err) {
      logAegisError(`[Aegis] Could not read post-save ${target.relative_path} for baseline registration:`, err);
      return;
    }

    if (postSaveContent.trim().length === 0) {
      return;
    }

    // Create verified baseline snapshot from post-save content.
    // postSaveContent is treated as secret: never logged, never in ledger.
    // createBaselineSnapshotFromContent has its own overwrite guard (BLOCKER-03)
    // as a final backstop.
    const snapshotId = isMarkerLossReregistration
      ? await recreateBaselineSnapshotAfterMarkerLossOrNull(
          store,
          postSaveContent,
          absPath,
          relPath,
          "[Aegis] marker-loss baseline re-registration snapshot creation threw:"
        )
      : await createBaselineSnapshotFromContentOrNull(
          store,
          postSaveContent,
          absPath,
          relPath,
          "[Aegis] baseline registration snapshot creation threw:"
        );

    if (!snapshotId) {
      stateMgr.setWarning(
        `Aegis detected a ${target.relative_path} change, but snapshot creation failed. ` +
        `Restore point not updated.`
      );
      showWarningMessageBestEffort(
        `Aegis: ${target.relative_path} snapshot creation failed. Restore point not updated.`
      );
      return;
    }

    const markerWritten = await writeBaselineMarker(aegisDir, target.marker_file, relPath);

    if (!markerWritten) {
      stateMgr.setWarning(
        `Aegis: ${target.relative_path} baseline snapshot created, but the registration marker ` +
        `could not be written. Save again to retry.`
      );
      showWarningMessageBestEffort(
        `Aegis: ${target.relative_path} baseline snapshot created but registration marker failed. ` +
        `Save again to confirm.`
      );
      if (ledger) {
        await appendLedgerEventOrFalse(ledger, {
          schemaVersion:  1,
          eventType:      "snapshot_created",
          timestamp:      new Date().toISOString(),
          protectedPath:  relPath,
          snapshotId,
          success:        true,
          verified:       true,
          snapshotHash:   (await readSnapshotIndexOrNull(store, "[Aegis] marker-failure ledger index read threw:"))?.content_sha256 ?? "",
          reason:         "baseline_registration_snapshot_created",
        }, "[Aegis Ledger] baseline_registration marker_failure snapshot_created append threw:");
      }
      return;
    }

    // Full baseline registration success for this target.
    // Do not clear a prior BLOCKED state until the newly written immutable
    // baseline index is read back and verified against the saved content.
    const verifiedRegistrationIndex = await readSnapshotIndexOrNull(
      store,
      "[Aegis] baseline registration verification index read threw:"
    );
    const expectedRegistrationHash = sha256OfString(postSaveContent);

    if (
      !verifiedRegistrationIndex ||
      verifiedRegistrationIndex.baseline_content_sha256 !== expectedRegistrationHash ||
      verifiedRegistrationIndex.content_sha256 !== expectedRegistrationHash
    ) {
      stateMgr.setWarning(
        `Aegis: ${target.relative_path} baseline registration completed, but the new baseline ` +
        `could not be verified. Protection remains degraded.`
      );
      showWarningMessageBestEffort(
        `Aegis: ${target.relative_path} baseline registration could not be verified.`
      );
      return;
    }

    if (ledger) {
      const ok = await appendLedgerEventOrFalse(ledger, {
        schemaVersion:  1,
        eventType:      "snapshot_created",
        timestamp:      new Date().toISOString(),
        protectedPath:  relPath,
        snapshotId,
        success:        true,
        verified:       true,
        snapshotHash:   verifiedRegistrationIndex.content_sha256,
        reason:         "baseline_registration_snapshot_created",
      }, "[Aegis Ledger] baseline_registration snapshot_created append threw:");
      if (!ok) {
        logAegisWarning("[Aegis Ledger] baseline_registration snapshot_created could not be recorded.");
      }
    }

    // E-P0-4-ACTIVITY-MARKER-RECOVERY-FIX
    // Automatic first registration and marker-loss re-registration must leave
    // the durable activity marker available before the state can become SAFE.
    // Preserve an existing marker and its counters without overwriting it.
    const automaticRegistrationActivityMarkerPath =
      nodePath.join(aegisDir, "activity-marker.json");
    let automaticRegistrationActivityMarkerMissing = false;
    
    try {
      await fs.promises.access(automaticRegistrationActivityMarkerPath);
    } catch {
      automaticRegistrationActivityMarkerMissing = true;
    }
    
    if (automaticRegistrationActivityMarkerMissing) {
      try {
        await initActivityMarker(aegisDir);
      } catch (err) {
        logAegisWarning(
          "[Aegis] Activity marker initialization failed after baseline registration:",
          err
        );
        stateMgr.setWarning(
          `Aegis: ${target.relative_path} baseline registered, but activity marker could not be written.`
        );
        showWarningMessageBestEffort(
          `Aegis: ${target.relative_path} baseline registered, but activity marker could not be written.`
        );
        return;
      }
    }

    stateMgr.setSafe("Aegis is protecting this workspace.");
    showInformationMessageBestEffort(
      `Aegis: ${target.relative_path} baseline registered. Protected from now on.`
    );
    return;
  }

  // If we reach here, at least one of (marker, index with baseline) is present.
  // Use the protected-change path with the existing index's baseline fields.
  //
  // BLOCKER-02 redesign:
  //   Previously: setBlocked() was gated behind createSnapshot() returning
  //   a non-null snapshotId. Any createSnapshot failure caused setWarning()
  //   instead of setBlocked(), allowing Aegis to remain Safe while a
  //   protected file contained injected changes on disk.
  //
  //   Fixed: Content comparison against baseline_content_sha256 happens
  //   first. setBlocked() is called immediately if the file differs from
  //   the immutable registered baseline. createSnapshot() is then attempted
  //   as best-effort audit/restore-support work. Whether it succeeds or
  //   fails, the state remains BLOCKED. setWarning() is never used as a
  //   substitute for setBlocked() in this path.
  //
  // Step order:
  //   1. Read the index for this target.
  //   2. Require immutable baseline fields (baseline_content_sha256).
  //   3. Read current disk content (post-save).
  //   4. Compare disk hash to baseline_content_sha256.
  //   6. If blocked (step 5a), attempt createSnapshot for audit/restore.

  //
  // BLOCKER-03: existingIndex was read in the registration gate above.
  // Re-using it avoids a second disk read and ensures consistency.
  // The variable name 'index' is kept to minimize changes to the
  // downstream steps which reference it throughout.
  const index = existingIndex;

  if (!index) {
    // No index at all. Baseline marker exists but index is gone or corrupt.
    // We cannot verify whether the file is at baseline. Treat as BLOCKED
    stateMgr.setBlocked(
      `Aegis: ${target.relative_path} baseline index is missing or unreadable. ` +
      `Aegis cannot verify this file is safe. Save again to rebuild the restore point.`,
      relPath,
      undefined
    );
    showWarningMessageBestEffort(
      `Aegis: ${target.relative_path} baseline index missing. Cannot verify safety.`
    );
    return;
  }

  //
  // If the index lacks baseline_content_sha256 (old pre-BLOCKER-01 format),
  // we cannot compare the current file against the true registered baseline.
  // The rolling content_sha256 may reflect contaminated content.
  if (!index.baseline_snapshot_file || !index.baseline_content_sha256) {
    stateMgr.setBlocked(
      `Aegis: ${target.relative_path} restore index is missing immutable baseline fields. ` +
      `Delete .aegis and save the file again to re-register the baseline.`,
      relPath,
      undefined
    );
    showWarningMessageBestEffort(
      `Aegis: ${target.relative_path} baseline fields missing. Re-register by deleting .aegis.`
    );
    return;
  }

  //
  // Read the file as it now exists on disk after VS Code has completed the
  // save. This is the ground truth for what the user just saved.
  let currentDiskContent: string;
  try {
    currentDiskContent = await fs.promises.readFile(absPath, "utf8");
  } catch (err) {
    // Cannot read the just-saved file. Cannot verify safety. Stay BLOCKED.
    stateMgr.setBlocked(
      `Aegis: Could not read ${target.relative_path} after save. Cannot verify baseline.`,
      relPath,
      undefined
    );
    showWarningMessageBestEffort(
      `Aegis: Could not read ${target.relative_path} after save.`
    );
    return;
  }

  //
  // baseline_content_sha256 is the immutable hash of the original registered
  // baseline content, written once at registration and never overwritten.
  // This is the ground truth for what "safe" means for this target.
  const currentDiskHash = sha256OfString(currentDiskContent);
  const baselineHash    = index.baseline_content_sha256;

  if (currentDiskHash === baselineHash) {
    //
    // The save returned the file to the baseline state (e.g. user reverted
    // global state. If another target is currently BLOCKED, it must remain so.
    // determined by the full multi-target state, not by a single-file save.
    //
    // We still consume the pre-save baseline (already done above) and may
    // create an audit snapshot if desired, but no state change is needed.
    // For simplicity in v0.1 scope: if the file is back at baseline, do nothing.
    return;
  }

  //
  // The current file content does not match the immutable registered baseline.
  // This is the protected change. Blocked must be set NOW, before attempting
  // any snapshot creation. The snapshot is audit/restore work, not the cause
  // of Blocked.
  //
  // below and the state updated with the snapshotId if successful.
  stateMgr.setBlocked(
    `Aegis detected a protected ${target.relative_path} change. Restore is available.`,
    relPath,
    undefined
  );

  //
  // createSnapshot uses the pre-save baseline (captured before the save)
  // to create an audit snapshot of the pre-change content. This is used for
  // the rolling audit trail. Whether it succeeds or fails, state remains BLOCKED.
  // Phase 5-CQ-DURABLE-ACTIVITY-MARKER-IMPLEMENTATION-STEP-2
  // Increment post_baseline_ops_count only in the protected-change path.
  // currentDiskHash !== baselineHash is already confirmed at this point.
  // BLOCKED state is already set. Increment failure does not downgrade BLOCKED.
  try {
    await incrementActivityMarkerOpsCount(aegisDir);
  } catch (_markerIncrErr) {
    logAegisWarning("[Aegis] Activity marker ops count could not be incremented:", (_markerIncrErr instanceof Error) ? _markerIncrErr.message : String(_markerIncrErr));
  }
  const snapshotId = await createSnapshotOrNull(store, baseline, relPath, "[Aegis] protected-change audit snapshot creation threw:");

  if (snapshotId) {
    //
    // Now that we have a snapshotId, update setBlocked with the snapshotId so
    // the UI knows a restore point is available. State remains BLOCKED.
    stateMgr.setBlocked(
      `Aegis detected a protected ${target.relative_path} change. Restore is available.`,
      relPath,
      snapshotId
    );

    if (ledger) {
      const ok = await appendLedgerEventOrFalse(ledger, {
        schemaVersion:  1,
        eventType:      "snapshot_created",
        timestamp:      new Date().toISOString(),
        protectedPath:  relPath,
        snapshotId,
        success:        true,
        verified:       true,
        snapshotHash:   baseline.sha256,   // SHA-256 hex - not the content
        reason:         "pre_save_snapshot_created",
      }, "[Aegis Ledger] pre_save_snapshot_created append threw:");
      if (!ok) {
        logAegisWarning("[Aegis Ledger] snapshot_created event could not be recorded.");
      }
    }

    vscode.window.showWarningMessage(
          `Aegis: ${target.relative_path} changed - restore point created.`,
      "Open Panel"
    ).then((choice) => {
      if (choice === "Open Panel") {
        void vscode.commands.executeCommand("aegis.showProtectionPanel");
      }
    }, () => undefined);

  } else {
    //
    // Snapshot creation failed (e.g. baseline fields not carried forward,
    // transient I/O error). Aegis already set BLOCKED above. Do NOT call
    // The file is still changed on disk. Show a truthful message about the
    // audit failure but do not imply the file is safe.
    //
    // setBlocked was already called above without snapshotId. Restore button
    // will be disabled (no snapshotId) but the Blocked state is preserved.
    showWarningMessageBestEffort(
          `Aegis: ${target.relative_path} changed - but audit snapshot could not be created. ` +
      `Aegis remains Blocked. Save again to retry creating a restore point.`
    );
    // Note: setWarning is intentionally NOT called here.
    // setBlocked was already set and must not be downgraded.
  }
}



async function handleRestore(): Promise<void> {
  if (!_engine || !_stores || !_stateMgr) {
    showWarningMessageBestEffort("Open a folder first to use Aegis.");
    return;
  }

  if (_restoreCommandInFlight) {
    showWarningMessageBestEffort("Aegis restore is already running. Please wait.");
    return;
  }

  _restoreCommandInFlight = true;

  try {
    _stateMgr.setRestoring();

    const targets             = getProtectedTargets().filter(t => t.restore_enabled);
    let   anyAttempted        = false;
    let   anyStoreFailed      = false;
    let   editorRefreshFailed = false;

    //
    // Phase 5-AF-FIX-01: The previous implementation had an "already at
    // baseline" skip that compared current disk hash to the pre-restore
    // snapshot index hash before calling store.restore(). If this comparison
    // fired incorrectly (stale index, snapshot pointing to wrong content, or
    // any mismatch between what was snapshotted and what was expected), targets
    //
    // Fix: Remove the pre-restore optimistic skip entirely. Attempt restore
    // for every target with a registered baseline marker and a valid index.
    // After all restore attempts, run a post-restore disk verification pass:
    // read each target's current disk content and compare its SHA-256 hash to
    // the baseline snapshot hash. SAFE is only declared if every registered
    // target matches its baseline hash on disk after all restores complete.
    //
    // Attempting restore on a target already at its baseline is a harmless
    // no-op (snapshot bytes written back, verified, same result). The small
    // disk I/O cost is accepted for correctness and fake-SAFE prevention.

    for (const target of targets) {
      const store = _stores.get(target.target_id);
      if (!store) { continue; }

      // Only restore targets that have a registered baseline.
      const markerExists = await readBaselineMarker(_aegisDir!, target.marker_file);
      if (!markerExists) { continue; }

      // Read index before restore for ledger recording.
      const preRestoreIndex    = await readSnapshotIndexOrNull(store, "[Aegis] restore preflight index read threw:");
      const ledgerSnapshotId   = preRestoreIndex?.snapshot_id;
      const ledgerSnapshotHash = preRestoreIndex?.content_sha256;

      // No index = no baseline to restore to. Record failure.
      if (!preRestoreIndex) {
        anyStoreFailed = true;
        await appendLedgerSafe({
          schemaVersion:  1,
          eventType:      "restore_failed",
          timestamp:      new Date().toISOString(),
          protectedPath:  target.relative_path,
          snapshotId:     undefined,
          success:        false,
          verified:       false,
          reason:         "restore_failed_no_safe_snapshot",
          errorCode:      "no_snapshot_found",
        }, "Restore failed and ledger recording also failed.");
        continue;
      }

      anyAttempted = true;
      const result = await restoreSnapshotOrFailure(store, _engine);

      try {
        if (result.success && result.restoredAbsPath) {
          const refreshed = await refreshEditor(result.restoredAbsPath);

          if (refreshed) {
            await appendLedgerSafe({
              schemaVersion:  1,
              eventType:      "restore_completed",
              timestamp:      new Date().toISOString(),
              protectedPath:  target.relative_path,
              snapshotId:     ledgerSnapshotId,
              success:        true,
              verified:       true,
              snapshotHash:   ledgerSnapshotHash,
              reason:         "verified_restore_completed",
            }, "Restore succeeded but ledger recording failed.");
          } else {
            editorRefreshFailed = true;
            await appendLedgerSafe({
              schemaVersion:  1,
              eventType:      "restore_completed",
              timestamp:      new Date().toISOString(),
              protectedPath:  target.relative_path,
              snapshotId:     ledgerSnapshotId,
              success:        true,
              verified:       true,
              snapshotHash:   ledgerSnapshotHash,
              reason:         "disk_restored_editor_refresh_failed",
              errorCode:      "editor_refresh_failed",
            }, "Restore succeeded but ledger recording failed.");
          }

        } else {
          anyStoreFailed = true;
          showWarningMessageBestEffort(result.message);

          const { errorCode, reason } = classifyRestoreFailure(result.message);
          await appendLedgerSafe({
            schemaVersion:  1,
            eventType:      "restore_failed",
            timestamp:      new Date().toISOString(),
            protectedPath:  target.relative_path,
            snapshotId:     ledgerSnapshotId,
            success:        false,
            verified:       false,
            reason,
            errorCode,
          }, "Restore failed and ledger recording also failed.");
        }
      } finally {
        if (result.lockedAbsPath) {
          _engine.removeRestoring(result.lockedAbsPath);
        }
      }
    }

    //
    // After all restore attempts, re-read every registered target's current
    // disk content and compare its SHA-256 to its baseline snapshot hash.
    // SAFE is only declared when every target with a registered baseline
    // currently matches its baseline on disk.
    //
    // This is the correctness gate that prevents fake SAFE regardless of
    // what happened in the restore loop above.
    //
    // Raw content is read for hash comparison only. Never logged, never
    // written to ledger, never shown in UI.

    if (!_projectRoot) {
      _stateMgr.setBlocked(
        "Aegis could not verify restore results. Project root is unavailable."
      );
      return;
    }

    let anyStillChanged = false;
    for (const target of targets) {
      const store = _stores.get(target.target_id);
      if (!store) { continue; }

      const markerExists = await readBaselineMarker(_aegisDir!, target.marker_file);
      if (!markerExists) { continue; }

      const index = await readSnapshotIndexOrNull(store, "[Aegis] verify-restored index read threw:");
      if (!index) {
        anyStillChanged = true;
        continue;
      }

      //
      // If baseline fields are absent (old index format), we cannot verify
      // the disk against the true registered baseline. Treat as still changed
      // rather than silently declaring SAFE. The rolling content_sha256 is
      if (!index.baseline_snapshot_file || !index.baseline_content_sha256) {
        anyStillChanged = true;
        continue;
      }

      const absPath = nodePath.join(_projectRoot, target.relative_path);
      try {
        const currentContent = await fs.promises.readFile(absPath, "utf8");
        // BLOCKER-01: compare against baseline_content_sha256 (immutable),
        // NOT content_sha256 (rolling, may reflect contaminated saves).
        if (sha256OfString(currentContent) !== index.baseline_content_sha256) {
          anyStillChanged = true;
        }
      } catch {
        anyStillChanged = true;
      }
    }

    //
    // The only path to SAFE is: post-restore disk verification confirms every
    // registered target matches its baseline hash on disk right now.

    if (anyStillChanged) {
      _stateMgr.setBlocked(
        "Aegis could not restore all protected files to their safe baselines. " +
        "Check the ledger for details. Restore is still available."
      );
    } else if (anyStoreFailed) {
      // All targets match baselines on disk but a store call failed.
      // Show WARNING rather than SAFE to prompt user attention.
      _stateMgr.setWarning(
        "Aegis: Some restore operations reported failures, but all protected " +
        "files now match their safe baselines. Check the ledger for details."
      );
    } else if (!anyAttempted) {
      // No targets had a registered baseline with a valid index.
      _stateMgr.setSafe("Aegis is protecting this workspace.");
    } else if (editorRefreshFailed) {
      _stateMgr.setWarning(
        "Disk restored, but editor refresh failed. Please reopen the protected file(s)."
      );
      showWarningMessageBestEffort(
        "Disk restored, but editor refresh failed. Please reopen the protected file(s)."
      );
    } else {
      // All targets match baselines on disk. All restores succeeded.
      // No editor refresh failure. This is the only genuine SAFE path.
      // Phase 5-CQ-DURABLE-ACTIVITY-MARKER-IMPLEMENTATION-STEP-3
      // Update marker only in the verified genuine restore Safe branch.
      // If marker update fails, downgrade to Warning and do not show success.
      let markerRestoreOk = true;
      try {
        await updateActivityMarkerOnRestore(_aegisDir!);
      } catch (_markerRestoreErr) {
        markerRestoreOk = false;
        logAegisWarning("[Aegis] Activity marker could not be updated after restore:", (_markerRestoreErr instanceof Error) ? _markerRestoreErr.message : String(_markerRestoreErr));
      }

      if (markerRestoreOk) {
        _stateMgr.setSafe(
          "Aegis restored protected file(s) from verified safe snapshot(s)."
        );
        showInformationMessageBestEffort(
          "Aegis restored protected file(s) from verified safe snapshot(s)."
        );
      } else {
        _stateMgr.setWarning(
          "Aegis restore completed but activity marker could not be updated. " +
          "Evidence may be incomplete. Please re-register the baseline if this persists."
        );
        showWarningMessageBestEffort(
          "Aegis restore completed but activity marker could not be updated. Evidence may be incomplete."
        );
      }
    }

  } finally {
    _restoreCommandInFlight = false;
  }
}


/**
 * Force the VS Code editor buffer to reload from disk after a verified restore.
 *
 *
 * HARDENED SEQUENCE:
 *      (not guarded by isDirty: after an extension-host writeFile the buffer
 *       may appear clean to VS Code but still hold stale content)
 *
 * The restoring lock (engine.isRestoring) is still active during this call.
 * Any save event triggered by the revert command is ignored by the watcher.
 * Lock is removed in handleRestore's finally block after this returns.
 */
async function refreshEditor(restoredAbsPath: string): Promise<boolean> {
  try {
    const uri = vscode.Uri.file(restoredAbsPath);

    // Step 1: Open and show the document to make it the active editor.
    // Required so workbench.action.files.revert targets the right file.
    let doc = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(doc, { preview: false });

    // regardless of whether the buffer appears dirty.
    // After fs.writeFile from the extension host, the buffer may not be
    // marked dirty but can still contain stale pre-restore content.
    try {
      await vscode.commands.executeCommand("workbench.action.files.revert");
    } catch (e) {
      logAegisWarning("[Aegis] revert command failed:", e);
      return false;
    }

    // Step 3: Re-open and show to pick up the freshly reverted buffer.
    doc = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(doc, { preview: false });

    return true;
  } catch (err) {
    logAegisWarning("[Aegis] Editor refresh failed:", err);
    return false;
  }
}


/**
 * Append a ledger event. If the write fails, show a sanitized warning.
 *
 * LEDGER FAILURE RULE: a failed ledger write must NEVER change the restore
 * result, the UI state, or the disk content. It is a recording failure only.
 *
 * warningOnFailure must not contain file content, paths, or error text.
 */
async function appendLedgerSafe(
  event:            Parameters<LedgerWriter["append"]>[0],
  warningOnFailure: string
): Promise<void> {
  if (!_ledger) { return; }
  const ok = await _ledger.append(event).catch(() => false);
  if (!ok) {
    logAegisWarning("[Aegis Ledger] Event could not be recorded:", event.eventType);
    showWarningMessageBestEffort(warningOnFailure);
  }
}

/**
 * Map a restore result.message to fixed LedgerErrorCode + LedgerReason.
 *
 * CRITICAL: result.message comes from snapshotStore.ts and may contain
 * ENOENT path fragments from String(err). This classifier maps to fixed
 *
 * Patterns match the known fixed message strings in snapshotStore.restore().
 */
function classifyRestoreFailure(message: string): {
  errorCode: LedgerErrorCode;
  reason:    LedgerReason;
} {
  const m = message.toLowerCase();

  if (m.includes("no safe snapshot") || m.includes("no_snapshot")) {
    return { errorCode: "no_snapshot_found",   reason: "restore_failed_no_safe_snapshot"    };
  }
  if (
    m.includes("could not read snapshot") ||
    m.includes("could not read baseline snapshot file") ||
    m.includes("unreadable")
  ) {
    return { errorCode: "snapshot_unreadable", reason: "restore_failed_snapshot_unreadable" };
  }
  if (m.includes("sha-256 mismatch") || m.includes("sha256")) {
    return { errorCode: "sha256_mismatch",     reason: "restore_failed_sha256_mismatch"     };
  }
  if (m.includes("could not write")) {
    return { errorCode: "write_failed",        reason: "restore_failed_write_failed"        };
  }
  if (m.includes("could not read back")) {
    return { errorCode: "readback_failed",     reason: "restore_failed_readback_failed"     };
  }
  if (m.includes("content mismatch")) {
    return { errorCode: "content_mismatch",    reason: "restore_failed_content_mismatch"    };
  }

  return   { errorCode: "unknown",             reason: "restore_failed_unknown"             };
}


/**
 * Generate a local Markdown Work Receipt from .aegis/ledger/events.jsonl.
 *
 * Rules:
 *   - Does NOT change SAFE/BLOCKED/WARNING/RESTORING state.
 *   - Shows a sanitized message on success or failure.
 *   - Never exposes raw error text to the user.
 */
async function handleGenerateReceipt(): Promise<void> {
  if (!_receipt) {
    showWarningMessageBestEffort("Open a folder first to use Aegis.");
    return;
  }

  const result = await _receipt.generate().catch(() => ({ ok: false, receiptPath: null, reason: "unknown" as const }));

  if (result.ok && result.receiptPath) {
    let artifactManifestCreated = false;
    let artifactManifestPath: string | null = null;
    let artifactResponsePlan:
      Awaited<
        ReturnType<
          typeof buildVerifiedArtifactResponsePlan
        >
      > | null = null;

    try {
      if (!_canonicalAuthorityState) {
        throw new Error("CANONICAL_AUTHORITY_STATE_UNAVAILABLE");
      }

      const receiptBytes = await fs.promises.readFile(
        result.receiptPath
      );
      const authorityState =
        _canonicalAuthorityState.getState();
      const receiptEntryPath =
        "receipts/" +
        nodePath.basename(result.receiptPath);

      const preflight = preflightArtifactIntent({
        intent: {
          schemaVersion: "1.0.0",
          intentId: "generate-work-receipt-artifact",
          artifactKind: "work_receipt",
          provenance: "local_user_command",
          targetPath: ".aegis/receipts",
          entryPaths: [receiptEntryPath],
          authorityBinding: {
            revision: authorityState.revision,
            workspaceId: authorityState.workspaceId,
            policyVersion: authorityState.policyVersion,
            rulesetVersion: authorityState.rulesetVersion,
            capabilityManifestVersion:
              authorityState.capabilityManifestVersion,
            actionId: authorityState.actionId,
            sessionId: authorityState.sessionId,
            approvalNonceSha256:
              authorityState.approvalNonceSha256,
          },
        },
        authorityState,
        allowedArtifactKinds: ["work_receipt"],
        allowedTargetPrefixes: [".aegis/receipts"],
      });

      const authorityClassification =
        classifyArtifactAuthoritySurface({
          intent: preflight.normalizedIntent,
        });

      if (
        authorityClassification.authoritySurface !==
        "receipt"
      ) {
        throw new Error(
          "ARTIFACT_AUTHORITY_SURFACE_NOT_RECEIPT"
        );
      }

      const compiledArtifact = compileArtifact({
        artifactKind: "work_receipt",
        authorityState,
        entries: [
          {
            path: receiptEntryPath,
            contentSha256:
              "sha256:" +
              sha256OfString(receiptBytes.toString("utf8")),
            byteLength: receiptBytes.byteLength,
          },
        ],
      });

      if (
        compiledArtifact.manifest.authorityStateSha256 !==
        preflight.authorityStateSha256
      ) {
        throw new Error(
          "ARTIFACT_PREFLIGHT_AUTHORITY_HASH_MISMATCH"
        );
      }

      const persistedArtifactRecord = {
        preflightId: preflight.preflightId,
        preflightAuthorityStateSha256:
          preflight.authorityStateSha256,
        intent: preflight.normalizedIntent,
        authoritySurfaceClassificationId:
          authorityClassification.classificationId,
        authoritySurface:
          authorityClassification.authoritySurface,
        authoritySurfaceRuleId:
          authorityClassification.matchedRuleId,
        artifactId: compiledArtifact.artifactId,
        manifest: compiledArtifact.manifest,
      };

      const finalArtifactManifestPath =
        result.receiptPath + ".artifact.json";
      const temporaryArtifactManifestPath =
        finalArtifactManifestPath +
        "." +
        process.pid +
        "." +
        Date.now() +
        ".tmp";

      try {
        await fs.promises.writeFile(
          temporaryArtifactManifestPath,
          JSON.stringify(
            persistedArtifactRecord,
            null,
            2
          ) + "\n",
          "utf8"
        );
        await fs.promises.rename(
          temporaryArtifactManifestPath,
          finalArtifactManifestPath
        );
      } catch {
        try {
          await fs.promises.unlink(
            temporaryArtifactManifestPath
          );
        } catch {
          // Best-effort temporary artifact cleanup.
        }
        throw new Error("ARTIFACT_MANIFEST_WRITE_FAILED");
      }

      let postArtifactAuthorityState;

      try {
        postArtifactAuthorityState =
          _canonicalAuthorityState.update(
            authorityState.revision,
            {
              currentArtifactId:
                compiledArtifact.artifactId,
            }
          );

        await queueCanonicalAuthorityPersistence(
          "artifact-id-update"
        );
      } catch {
        try {
          await fs.promises.unlink(
            finalArtifactManifestPath
          );
        } catch {
          // Best-effort rollback of an unbound manifest.
        }
        throw new Error(
          "ARTIFACT_AUTHORITY_BINDING_FAILED"
        );
      }

      let postArtifactVerification;

      try {
        postArtifactVerification =
          verifyPostArtifactInternalAuthority({
            artifact: persistedArtifactRecord,
            preArtifactAuthorityState:
              authorityState,
            postArtifactAuthorityState,
            allowedArtifactKinds: ["work_receipt"],
            allowedTargetPrefixes:
              [".aegis/receipts"],
            expectedAuthoritySurface: "receipt",
            expectedAuthoritySurfaceRuleId:
              "work-receipt-receipt-surface-v1",
          });
      } catch {
        try {
          await fs.promises.unlink(
            finalArtifactManifestPath
          );
        } catch {
          // Best-effort removal of an unverified manifest.
        }
        throw new Error(
          "POST_ARTIFACT_AUTHORITY_VERIFICATION_FAILED"
        );
      }

      const verifiedArtifactRecord = {
        ...persistedArtifactRecord,
        postArtifactAuthorityVerificationId:
          postArtifactVerification.verificationId,
        postArtifactAuthorityStateSha256:
          postArtifactVerification
            .postArtifactAuthorityStateSha256,
        postArtifactAuthorityRevision:
          postArtifactVerification
            .postArtifactAuthorityRevision,
      };

      const verifiedArtifactManifestPath =
        finalArtifactManifestPath +
        "." +
        process.pid +
        "." +
        Date.now() +
        ".verified.tmp";

      try {
        await fs.promises.writeFile(
          verifiedArtifactManifestPath,
          JSON.stringify(
            verifiedArtifactRecord,
            null,
            2
          ) + "\n",
          "utf8"
        );

        await fs.promises.rename(
          verifiedArtifactManifestPath,
          finalArtifactManifestPath
        );
      } catch {
        try {
          await fs.promises.unlink(
            verifiedArtifactManifestPath
          );
        } catch {
          // Best-effort verified temporary cleanup.
        }

        try {
          await fs.promises.unlink(
            finalArtifactManifestPath
          );
        } catch {
          // Best-effort removal of an unverified manifest.
        }

        throw new Error(
          "POST_ARTIFACT_AUTHORITY_VERIFICATION_PERSIST_FAILED"
        );
      }

      try {
        artifactResponsePlan =
          await buildVerifiedArtifactResponsePlan({
            workspaceRoot: nodePath.dirname(
              nodePath.dirname(
                nodePath.dirname(result.receiptPath)
              )
            ),
            receiptPath: result.receiptPath,
            manifestPath:
              finalArtifactManifestPath,
            artifact: verifiedArtifactRecord,
            preArtifactAuthorityState:
              authorityState,
            postArtifactAuthorityState,
          });

        if (
          !artifactResponsePlan.renderAllowed ||
          !artifactResponsePlan.downloadLinkAllowed
        ) {
          throw new Error(
            "VERIFIED_ARTIFACT_RESPONSE_NOT_AUTHORIZED"
          );
        }
      } catch {
        try {
          await fs.promises.unlink(
            finalArtifactManifestPath
          );
        } catch {
          // Best-effort removal of a non-renderable manifest.
        }

        try {
          _canonicalAuthorityState.update(
            postArtifactAuthorityState.revision,
            {
              currentArtifactId: null,
            }
          );

          await queueCanonicalAuthorityPersistence(
            "artifact-id-rollback"
          );
        } catch {
          throw new Error(
            "VERIFIED_ARTIFACT_RESPONSE_AUTHORITY_ROLLBACK_FAILED"
          );
        }

        throw new Error(
          "VERIFIED_ARTIFACT_RESPONSE_RENDERING_FAILED"
        );
      }

      artifactManifestPath = finalArtifactManifestPath;
      artifactManifestCreated = true;
    } catch (err) {
      logAegisError(
        "[Aegis] Work Receipt artifact compilation error:",
        err
      );
      showWarningMessageBestEffort(
        "Aegis Work Receipt was generated, but verified artifact rendering was blocked."
      );
    }

    if (
      !artifactResponsePlan ||
      !artifactManifestCreated ||
      !artifactManifestPath
    ) {
      return;
    }

    try {
      const selectedAction =
        await vscode.window.showInformationMessage(
          `${artifactResponsePlan.displayTitle}: ${artifactResponsePlan.trustedArtifactName}`,
          "Open Receipt",
          "Open Verified Manifest"
        );

      if (selectedAction === "Open Receipt") {
        const receiptDocument =
          await vscode.workspace.openTextDocument(
            vscode.Uri.parse(
              artifactResponsePlan.receiptLink.uri,
              true
            )
          );

        await vscode.window.showTextDocument(
          receiptDocument,
          { preview: false }
        );
      } else if (
        selectedAction === "Open Verified Manifest"
      ) {
        const manifestDocument =
          await vscode.workspace.openTextDocument(
            vscode.Uri.parse(
              artifactResponsePlan.manifestLink.uri,
              true
            )
          );

        await vscode.window.showTextDocument(
          manifestDocument,
          { preview: false }
        );
      }
    } catch {
      showWarningMessageBestEffort(
        "Aegis verified artifact could not be opened."
      );
    }

    return;
  }

  if (result.reason === "no_ledger") {
    showWarningMessageBestEffort(
      "No Aegis ledger found. Save .env to create one."
    );
  } else {
    showWarningMessageBestEffort(
      "Aegis could not generate the Work Receipt."
    );
  }
}


/**
 * Handle the "Aegis: Register Current Clean Baseline" command.
 *
 * PURPOSE:
 *   After BLOCKER-03, Aegis shows Warning when protected files exist on disk
 *   but no baseline marker/index evidence is registered. Ctrl+S on a clean
 *   unmodified file does not fire a VS Code save event (the buffer is not dirty),
 *   so save-event-triggered baseline registration cannot help.
 *
 *   This command is the v0.1-safe explicit registration path.
 *
 * SAFETY RULES:
 *   1. Shows a user confirmation prompt before registering anything.
 *   2. Never overwrites an existing baseline (checked via marker AND index).
 *   3. Skips targets that are already registered.
 *   4. Skips targets whose files do not exist on disk.
 *   6. After all targets processed, re-runs rehydration to update panel state.
 *   7. Does not read or log raw file content.
 *   8. Does not write ledger events (registration via explicit command is not
 *      a user-initiated save-event; follows same ledger-silence rule as rehydration).
 *
 * OVERWRITE PROTECTION:
 *   This function checks marker + index before calling createBaselineSnapshotFromContent.
 *   Additionally, createBaselineSnapshotFromContent has its own BLOCKER-03 guard that
 */

// Phase 5-CQ-DURABLE-ACTIVITY-MARKER-IMPLEMENTATION-STEP-1
// Writes .aegis/activity-marker.json with zero-initialized counters.
function logAegisError(message: string, err: unknown): void {
  console.error(message, err);
}

function logAegisWarning(message: string, detail?: unknown): void {
  console.warn(...(typeof detail === "undefined" ? [message] : [message, detail]));
}

async function restoreSnapshotOrFailure(
  store: SnapshotStore,
  engine: Parameters<SnapshotStore["restore"]>[0]
): Promise<Awaited<ReturnType<SnapshotStore["restore"]>>> {
  return await store.restore(engine).catch(err => {
    logAegisWarning("[Aegis] restore call threw:", err);
    return {
      success: false,
      message: `Aegis: Restore operation threw before result handling: ${String(err)}`,
    } as Awaited<ReturnType<SnapshotStore["restore"]>>;
  });
}

async function appendLedgerEventOrFalse(
  ledger: LedgerWriter,
  event: Parameters<LedgerWriter["append"]>[0],
  warningMessage: string
): Promise<boolean> {
  return await ledger.append(event).catch(err => {
    logAegisWarning(warningMessage, err);
    return false;
  });
}

async function createSnapshotOrNull(
  store: SnapshotStore,
  baseline: Parameters<SnapshotStore["createSnapshot"]>[0],
  relPath: string,
  warningMessage?: string
): Promise<string | null> {
  return await store.createSnapshot(baseline, relPath).catch(err => {
    if (warningMessage) {
      logAegisWarning(warningMessage, err);
    }
    return null;
  });
}

async function createBaselineSnapshotFromContentOrNull(
  store: SnapshotStore,
  content: string,
  absPath: string,
  relPath: string,
  warningMessage: string
): Promise<string | null> {
  return await store.createBaselineSnapshotFromContent(content, absPath, relPath).catch(err => {
    logAegisWarning(warningMessage, err);
    return null;
  });
}

async function recreateBaselineSnapshotAfterMarkerLossOrNull(
  store: SnapshotStore,
  content: string,
  absPath: string,
  relPath: string,
  warningMessage: string
): Promise<string | null> {
  return await store.recreateBaselineSnapshotAfterMarkerLoss(content, absPath, relPath).catch(err => {
    logAegisWarning(warningMessage, err);
    return null;
  });
}

// Called only after every protected target registered successfully.
async function initActivityMarker(aegisDir: string): Promise<void> {
  const markerPath = nodePath.join(aegisDir, "activity-marker.json");
  const marker: Record<string, unknown> = {
    schema_version:           1,
    post_baseline_ops_count:  0,
    post_baseline_generation: 0,
  };

  await writeExtensionDurableUtf8File(
    markerPath,
    JSON.stringify(marker, null, 2));
}

// Phase 5-CQ-DURABLE-ACTIVITY-MARKER-IMPLEMENTATION-STEP-2
// Increments post_baseline_ops_count in .aegis/activity-marker.json by 1.
// Called only in the protected-change path after currentDiskHash !== baselineHash.
// post_baseline_generation is preserved unchanged in this step.
async function readSnapshotIndexOrNull(store: SnapshotStore, warningMessage: string) {
  return await store.readIndex().catch(err => {
    logAegisWarning(warningMessage, err);
    return null;
  });
}

function throwActivityMarkerValidationError(message: string): never {
  throw new Error(message);
}
async function readActivityMarkerForUpdate(aegisDir: string): Promise<{
  markerPath: string;
  marker: Record<string, unknown>;
}> {
  const markerPath = nodePath.join(aegisDir, "activity-marker.json");

  let raw: string;
  try {
    raw = await fs.promises.readFile(markerPath, "utf8");
  } catch {
    throwActivityMarkerValidationError("activity-marker.json not found");
  }

  let marker: Record<string, unknown>;
  try {
    marker = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throwActivityMarkerValidationError("activity-marker.json is not valid JSON");
  }

  if (marker["schema_version"] !== 1) {
    throwActivityMarkerValidationError("activity-marker.json has unknown schema_version");
  }

  if (
    typeof marker["post_baseline_ops_count"] !== "number" ||
    !Number.isInteger(marker["post_baseline_ops_count"]) ||
    (marker["post_baseline_ops_count"] as number) < 0
  ) {
    throwActivityMarkerValidationError("activity-marker.json post_baseline_ops_count is invalid");
  }

  if (
    typeof marker["post_baseline_generation"] !== "number" ||
    !Number.isInteger(marker["post_baseline_generation"]) ||
    (marker["post_baseline_generation"] as number) < 0
  ) {
    throwActivityMarkerValidationError("activity-marker.json post_baseline_generation is invalid");
  }

  return { markerPath, marker };
}

// Phase 5-CQ-DURABLE-ACTIVITY-MARKER-IMPLEMENTATION-STEP-2
// Increments post_baseline_ops_count in .aegis/activity-marker.json by 1.
// Called only in the protected-change path after currentDiskHash !== baselineHash.
// post_baseline_generation is preserved unchanged in this step.
async function incrementActivityMarkerOpsCount(aegisDir: string): Promise<void> {
  const { markerPath, marker } = await readActivityMarkerForUpdate(aegisDir);

  marker["post_baseline_ops_count"] =
    (marker["post_baseline_ops_count"] as number) + 1;

  await writeExtensionDurableUtf8File(
    markerPath,
    JSON.stringify(marker, null, 2));
}

// Phase 5-CQ-DURABLE-ACTIVITY-MARKER-IMPLEMENTATION-STEP-3
// Increments both post_baseline_ops_count and post_baseline_generation by 1
// after a fully verified successful Restore Last Safe State.
// Never called in Warning or Blocked restore branches.
// Never resets either counter to zero.
async function updateActivityMarkerOnRestore(aegisDir: string): Promise<void> {
  const { markerPath, marker } = await readActivityMarkerForUpdate(aegisDir);

  marker["post_baseline_ops_count"] =
    (marker["post_baseline_ops_count"] as number) + 1;
  marker["post_baseline_generation"] =
    (marker["post_baseline_generation"] as number) + 1;

  await writeExtensionDurableUtf8File(
    markerPath,
    JSON.stringify(marker, null, 2));
}
async function handleRegisterCleanBaseline(): Promise<void> {
  if (!_engine || !_stores || !_stateMgr || !_projectRoot || !_aegisDir) {
    showWarningMessageBestEffort("Open a folder first to use Aegis.");
    return;
  }

  const choice = await vscode.window.showWarningMessage(
    "Register current protected files as the clean baseline? " +
    "Only do this if these files are safe and unchanged. " +
    "Existing baselines will not be overwritten.",
    { modal: true },
    "Register Clean Baseline"
  );
  if (choice !== "Register Clean Baseline") {
    return;
  }

  const targets    = getProtectedTargets();
  const aegisDir   = _aegisDir;
  const projectRoot = _projectRoot;
  let   anySuccess = false;
  let   anyFailed  = false;
  let   registeredTargetCount = 0;
  let   presentTargetCount = 0;
  let   activityMarkerInitialized = false;
  const messages: string[] = [];

  for (const target of targets) {
    const relPath = target.relative_path;
    const absPath = nodePath.join(projectRoot, relPath);

    let fileExists = false;
    try { await fs.promises.access(absPath); fileExists = true; } catch { /* absent */ }
    if (!fileExists) {
      messages.push(`${relPath}: skipped (file not found on disk)`);
      continue;
    }

    presentTargetCount++;

    const store = _stores.get(target.target_id);
    if (!store) {
      messages.push(`${relPath}: skipped (snapshot store unavailable)`);
      anyFailed = true;
      continue;
    }

    //
    // Check BOTH marker and index. If either indicates prior registration,
    const markerPresent  = await readBaselineMarker(aegisDir, target.marker_file);
    const existingIndex  = await readSnapshotIndexOrNull(store, "[Aegis] bulk registration index read threw:");
    const indexHasBaseline = !!(existingIndex &&
                                 existingIndex.baseline_snapshot_file &&
                                 existingIndex.baseline_content_sha256);

    if (markerPresent || indexHasBaseline) {
      if (markerPresent && indexHasBaseline) {
        registeredTargetCount++;
      }
      messages.push(`${relPath}: already registered - skipped`);
      continue;
    }

    if (existingIndex && !indexHasBaseline) {
      messages.push(
          `${relPath}: degraded index (missing baseline fields) - skipped. ` +
        `Delete .aegis and re-register.`
      );
      anyFailed = true;
      continue;
    }

    //
    let content: string;
    try {
      content = await fs.promises.readFile(absPath, "utf8");
    } catch (err) {
      messages.push(`${relPath}: could not read file - skipped`);
      logAegisError(`[Aegis] registerCleanBaseline: could not read ${relPath}:`, err);
      anyFailed = true;
      continue;
    }

    if (content.trim().length === 0) {
      messages.push(`${relPath}: file is empty - skipped`);
      continue;
    }

    // Create baseline snapshot. createBaselineSnapshotFromContent has its own
    // BLOCKER-03 overwrite guard as a second layer of protection.
    const snapshotId = await createBaselineSnapshotFromContentOrNull(store, content, absPath, relPath, "[Aegis] baseline bulk snapshot creation threw:");
    if (!snapshotId) {
        messages.push(`${relPath}: baseline snapshot creation failed - skipped`);
      anyFailed = true;
      continue;
    }

    // Write the marker. If marker write fails, the snapshot exists but the
    // gate logic will re-detect via the index on future saves.
    const markerWritten = await writeBaselineMarker(aegisDir, target.marker_file, relPath);
    if (!markerWritten) {
      messages.push(
        `${relPath}: snapshot created but marker write failed. ` +
        `Run Register again to retry.`
      );
      anyFailed = true;
      continue;
    }

    messages.push(`${relPath}: baseline registered`);
    anySuccess = true;
    registeredTargetCount++;
  }

  // Show a concise notification. Detailed results go to the output channel
  // if it existed; for now, show up to the first 4 messages in a single
  // notification. No raw content is shown.
  // Phase 5-CQ-DURABLE-ACTIVITY-MARKER-IMPLEMENTATION-STEP-1
  // Create the activity marker only when it is missing and every protected
  // target has both its baseline marker and verified baseline index.
  // An existing activity marker is never overwritten here.
  let activityMarkerMissing = false;
  try {
    await fs.promises.access(
      nodePath.join(aegisDir, "activity-marker.json")
    );
  } catch {
    activityMarkerMissing = true;
  }

  if (
    activityMarkerMissing === true &&
    targets.length > 0 &&
    presentTargetCount > 0 &&
    registeredTargetCount === presentTargetCount &&
    anyFailed === false
  ) {
    try {
      await initActivityMarker(aegisDir);
      activityMarkerInitialized = true;
    } catch {
      anyFailed = true;
      messages.push(
        "Activity marker could not be written. Please re-register the baseline."
      );
    }
  }
  const summary = messages.join("\n");
  if (anyFailed) {
    showWarningMessageBestEffort(
      `Aegis baseline registration completed with issues:\n${summary}`
    );
  } else if (activityMarkerInitialized) {
    showInformationMessageBestEffort(
      "Aegis: Activity marker restored for existing clean baselines."
    );
  } else if (anySuccess) {
    showInformationMessageBestEffort(
      `Aegis: Clean baseline registered for protected files.`
    );
  } else {
    // All skipped (already registered or files absent)
    showInformationMessageBestEffort(
      `Aegis: All protected targets already registered. No changes made.`
    );
  }

  //
  // After registration, the panel state may still show Warning (from the
  // initial rehydration at activation). Re-run rehydration to update the
  // state based on the newly registered baselines.
  if (anySuccess || activityMarkerInitialized) {
    try {
      await rehydrateStateOnActivation(projectRoot, aegisDir, _stores, _stateMgr);
    } catch (err) {
      logAegisError("[Aegis] rehydrateStateOnActivation after registerCleanBaseline failed:", err);
      try {
        _stateMgr.setWarning("Aegis registered baseline but could not refresh state. Open panel to verify.");
      } catch (warningErr) { logAegisWarning("[Aegis] setWarning after registerCleanBaseline refresh failure threw:", warningErr); }
    }
  }
}


/**
 * Debounce gate for watcher events.
 *
 * Clears any pending timer for this target and starts a new 300ms timer.
 * After 300ms of silence on this target, executes the actual handler once.
 * This coalesces burst events from atomic writes or tool-generated sequences
 * (e.g. delete + create + change from a formatter rewrite) into one action.
 *
 * The 300ms delay is long enough to absorb typical tool write bursts
 * and short enough to feel immediate to the user.
 */
function scheduleWatcherAction(
  target:      ProtectedTarget,
  kind:        "delete" | "change",
  projectRoot: string,
  aegisDir:    string,
  stores:      Map<string, SnapshotStore>,
  stateMgr:    StateManager,
  ledger:      LedgerWriter | null
): void {
  const key = target.relative_path;
  const existing = _debounceTimers.get(key);
  if (existing !== undefined) { clearTimeout(existing); }

  const timer = setTimeout(async () => {
    _debounceTimers.delete(key);
    try {
      if (kind === "delete") {
        await handleWatcherDelete(target, projectRoot, aegisDir, stores, stateMgr, ledger);
      } else {
        await handleWatcherChange(target, projectRoot, aegisDir, stores, stateMgr, ledger);
      }
    } catch (err) {
      logAegisError(`[Aegis] Watcher ${kind} handler error for ${target.relative_path}:`, err);
    }
  }, 300);

  _debounceTimers.set(key, timer);
}

/**
 * Handle a FileSystemWatcher onDidDelete event for a registered protected target.
 *
 * Phase 5-BS design rules enforced here:
 *   - Extension-initialized guard.
 *   - Restore-in-progress guard (isRestoring).
 *   - Registration gate: only act strongly if marker + index with baseline fields exist.
 *   - If registered: setBlocked, write ledger event (watcher_delete_detected).
 *   - If unregistered/degraded: setWarning (consistent with rehydration behavior).
 *   - SAFE is never set by this handler.
 *   - No disk content read (file is gone; hash not applicable for delete event).
 *   - No raw content or secrets logged.
 */
async function handleWatcherDelete(
  target:      ProtectedTarget,
  projectRoot: string,
  aegisDir:    string,
  stores:      Map<string, SnapshotStore>,
  stateMgr:    StateManager,
  ledger:      LedgerWriter | null
): Promise<void> {
  // Guard: extension must be fully initialized
  if (!_initialized || !_engine) { return; }

  const absPath = nodePath.join(projectRoot, target.relative_path);
  const relPath = target.relative_path;

  // Guard: ignore watcher events during active restore to avoid false BLOCKED
  // while Aegis itself is writing the baseline content back to disk.
  if (_engine.isRestoring(absPath)) { return; }

  //
  // FIX-01: Per Phase 5-BS design lock, a target is registered-valid only when
  // BOTH marker AND index-with-baseline-fields are present. marker-missing +
  //
  //         (this was the bug: previously fell through to setBlocked)

  const markerPresent  = await readBaselineMarker(aegisDir, target.marker_file);
  const store          = stores.get(target.target_id);
  const idx            = store ? await readSnapshotIndexOrNull(store, "[Aegis] protected-change status index read threw:") : null;
  const idxHasBaseline = !!(idx &&
                             idx.baseline_snapshot_file &&
                             idx.baseline_content_sha256);

  const registeredValid = markerPresent && idxHasBaseline;
  const unregistered    = !markerPresent && !idxHasBaseline;
  // degraded = any other combination (marker without valid index, or index without marker)

  if (unregistered) {
    stateMgr.setWarning(
      `Aegis: ${relPath} was deleted but has no registered baseline. ` +
      `Register a baseline before AI edits.`
    );
    return;
  }

  if (!registeredValid) {
    // Degraded: marker-without-valid-index OR index-without-marker.
    // Both are inconsistent evidence states. Do not set BLOCKED.
    // Do not write watcher BLOCKED ledger event.
    stateMgr.setWarning(
      `Aegis: ${relPath} was deleted but baseline evidence is inconsistent or degraded. ` +
      `Delete .aegis and re-register the baseline.`
    );
    return;
  }

  stateMgr.setBlocked(
    `Aegis: ${relPath} was deleted. Restore will recover it from the registered baseline.`,
    relPath,
    idx?.snapshot_id
  );

  if (ledger) {
    await appendLedgerEventOrFalse(ledger, {
      schemaVersion: 1,
      eventType:     "protected_target_changed",
      timestamp:     new Date().toISOString(),
      protectedPath: relPath,
      success:       false,
      verified:      false,
      reason:        "watcher_delete_detected",
    }, "[Aegis Ledger] watcher_delete_detected event could not be recorded:");
  }
}

/**
 * Handle a FileSystemWatcher onDidChange event for a registered protected target.
 *
 * Phase 5-BS design rules enforced here:
 *   - Extension-initialized guard.
 *   - Restore-in-progress guard (isRestoring).
 *   - Registration gate: only act strongly if marker + index with baseline fields exist.
 *   - Compares disk hash against index.baseline_content_sha256 (immutable ground truth).
 *   - If hash differs: setBlocked, write ledger event (watcher_change_detected).
 *   - SAFE is never set by this handler.
 *   - No raw content or secrets logged.
 */
async function handleWatcherChange(
  target:      ProtectedTarget,
  projectRoot: string,
  aegisDir:    string,
  stores:      Map<string, SnapshotStore>,
  stateMgr:    StateManager,
  ledger:      LedgerWriter | null
): Promise<void> {
  // Guard: extension must be fully initialized
  if (!_initialized || !_engine) { return; }

  const absPath = nodePath.join(projectRoot, target.relative_path);
  const relPath = target.relative_path;

  // Guard: ignore watcher events during active restore.
  if (_engine.isRestoring(absPath)) { return; }

  //
  // FIX-01: Same correction as handleWatcherDelete.
  // marker-missing + index-present is degraded, not registered-valid.
  //
  //         (this was the bug: previously fell through to hash comparison + setBlocked)

  const markerPresent  = await readBaselineMarker(aegisDir, target.marker_file);
  const store          = stores.get(target.target_id);
  const idx            = store ? await readSnapshotIndexOrNull(store, "[Aegis] scan-safety status index read threw:") : null;
  const idxHasBaseline = !!(idx &&
                             idx.baseline_snapshot_file &&
                             idx.baseline_content_sha256);

  const registeredValid = markerPresent && idxHasBaseline;
  const unregistered    = !markerPresent && !idxHasBaseline;

  if (unregistered) {
    return;
  }

  if (!registeredValid) {
    // Degraded: marker-without-valid-index OR index-without-marker.
    // Do not set BLOCKED. Do not write watcher BLOCKED ledger event.
    stateMgr.setWarning(
      `Aegis: ${relPath} changed externally but baseline evidence is inconsistent or degraded. ` +
      `Delete .aegis and re-register the baseline.`
    );
    return;
  }

  // Content is NEVER logged, stored in ledger, or sent to UI.
  let diskContent: string;
  try {
    diskContent = await fs.promises.readFile(absPath, "utf8");
  } catch (err) {
    // File may have been deleted after the change event; let onDidDelete handle it.
      logAegisWarning(`[Aegis] Watcher change: could not read ${relPath} - may have been deleted.`);
    return;
  }

  const diskHash     = sha256OfString(diskContent);
  const baselineHash = idx!.baseline_content_sha256;

  // A VS Code editor save also emits a FileSystemWatcher change event.
  // Consume the matching one-shot marker so one save creates one ledger event.
  if (consumeEditorSaveWatcherEvent(absPath, diskHash)) {
    return;
  }

  if (diskHash === baselineHash) {
    // External tool restored the file to baseline content.
    // Leave state unchanged.
    return;
  }

  stateMgr.setBlocked(
    `Aegis: ${relPath} was modified externally. Restore is available.`,
    relPath,
    idx?.snapshot_id
  );

  if (ledger) {
    await appendLedgerEventOrFalse(ledger, {
      schemaVersion: 1,
      eventType:     "protected_target_changed",
      timestamp:     new Date().toISOString(),
      protectedPath: relPath,
      success:       false,
      verified:      false,
      reason:        "watcher_change_detected",
    }, "[Aegis Ledger] watcher_change_detected event could not be recorded:");
  }
}
