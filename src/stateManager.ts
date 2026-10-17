// src/stateManager.ts - Authoritative UI state for Prolixo Aegis Personal v0.1 Prototype
//
// STATE OWNERSHIP RULE:
//   StateManager holds the single authoritative AegisUiState in extension-host memory.
//   The Webview is a dumb renderer - it receives state copies via postMessage.
//   When the Webview is closed and reopened, it requests the current state and
//   StateManager provides it. BLOCKED never silently resets to SAFE on panel reopen.
//
// TRANSITION RULES (see AegisStatus in types.ts for the full table):
//   - BLOCKED -> SAFE is only allowed via setSafe(), which is called only after
//     verified disk restore success. No other code path may call setSafe().
//   - RESTORING -> SAFE same rule.
//   - Saving an unrelated file must not call setSafe(). Only the Orchestrator
//     (extension.ts) controls which transitions happen and when.
//
// This file has NO imports from envCoreEngine, snapshotStore, or webviewPanel.
// It knows nothing about the filesystem. It only holds and broadcasts state.

/**
 * PLATFORM_PORTABILITY_STANDARD_V1_STATE_MANAGER_NEUTRAL_EVENT_EMITTER
 *
 * StateManager is a core state holder and must not import VS Code APIs.
 * This small structural event type preserves the existing onDidChangeState
 * call shape used by extension.ts while keeping the state core host-neutral.
 */
export interface AegisStateSubscription {
  dispose(): void;
}

export type AegisStateEvent<T> = (listener: (event: T) => unknown) => AegisStateSubscription;

class AegisStateEmitter<T> {
  private readonly listeners = new Set<(event: T) => unknown>();

  readonly event: AegisStateEvent<T> = (listener: (event: T) => unknown): AegisStateSubscription => {
    this.listeners.add(listener);
    return {
      dispose: (): void => {
        this.listeners.delete(listener);
      },
    };
  };

  fire(event: T): void {
    for (const listener of [...this.listeners]) {
      listener(event);
    }
  }

  dispose(): void {
    this.listeners.clear();
  }
}
import { AegisUiState, AegisStatus } from "./types";

const INITIAL_STATE: AegisUiState = {
  status:           "SAFE",
  message:          "Aegis is protecting this workspace.",
  restoreAvailable: false,
  isProcessing:     false,
};

export class StateManager {
  private _state: AegisUiState = { ...INITIAL_STATE };
  private readonly _emitter = new AegisStateEmitter<AegisUiState>();

  /** Fired whenever state changes. Webview subscribes to this. */
  readonly onDidChangeState: AegisStateEvent<AegisUiState> = this._emitter.event;

  // Read

  getState(): AegisUiState {
    return { ...this._state };   // return a copy - caller must not mutate
  }

  // Transitions

  /**
   * Call when a verified safe snapshot was created after a .env BLOCK save.
   * Sets BLOCKED, restoreAvailable=true, isProcessing=false.
   */
  setBlocked(message: string, path?: string, snapshotId?: string): void {
    this._setState({
      status:           "BLOCKED",
      message,
      restoreAvailable: true,
      isProcessing:     false,
      lastProtectedPath: path,
      lastSnapshotId:   snapshotId,
      lastEventAt:      new Date().toISOString(),
    });
  }

  /**
   * Call when no pre-save baseline was available, or snapshot creation failed.
   * restoreAvailable=false because there is no known safe snapshot.
   */
  setWarning(message: string): void {
    this._setState({
      status:           "WARNING",
      message,
      restoreAvailable: false,
      isProcessing:     false,
      lastEventAt:      new Date().toISOString(),
    });
  }

  /**
   * Call when restore starts.
   * Disables the Restore button while operation is in progress.
   */
  setRestoring(message = "Aegis is restoring your safe version..."): void {
    this._setState({
      status:           "RESTORING",
      message,
      restoreAvailable: false,
      isProcessing:     true,
      lastEventAt:      new Date().toISOString(),
    });
  }

  /**
   * Call ONLY after verified disk restore success (disk write + read-back
   * + equality + SHA-256 all passed). Never call this to "optimistically"
   * show success before verification.
   */
  setSafe(message: string): void {
    this._setState({
      status:           "SAFE",
      message,
      restoreAvailable: false,
      isProcessing:     false,
      lastEventAt:      new Date().toISOString(),
    });
  }

  // Private

  private _setState(partial: Partial<AegisUiState>): void {
    // Merge: preserve fields not explicitly set (e.g. lastProtectedPath)
    this._state = {
      ...this._state,
      ...partial,
    };
    this._emitter.fire({ ...this._state });
  }

  dispose(): void {
    this._emitter.dispose();
  }
}
