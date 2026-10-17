import test from "node:test";
import assert from "node:assert/strict";

import { StateManager, type AegisStateSubscription } from "./stateManager";
import type { AegisUiState } from "../packages/aegis-core";

test("stateManager starts safe and returns defensive state copies", () => {
  const manager = new StateManager();

  const first = manager.getState();
  assert.equal(first.status, "SAFE");
  assert.equal(first.message, "Aegis is protecting this workspace.");
  assert.equal(first.restoreAvailable, false);
  assert.equal(first.isProcessing, false);

  (first as AegisUiState).status = "BLOCKED";
  (first as AegisUiState).message = "mutated copy";

  const second = manager.getState();
  assert.equal(second.status, "SAFE");
  assert.equal(second.message, "Aegis is protecting this workspace.");

  manager.dispose();
});

test("stateManager emits blocked and warning transitions while preserving protected metadata", () => {
  const manager = new StateManager();
  const events: AegisUiState[] = [];

  const subscription: AegisStateSubscription = manager.onDidChangeState((event) => {
    events.push(event);
  });

  manager.setBlocked("blocked", "C:\\workspace\\.env", "snapshot-1");

  const blocked = manager.getState();
  assert.equal(blocked.status, "BLOCKED");
  assert.equal(blocked.message, "blocked");
  assert.equal(blocked.restoreAvailable, true);
  assert.equal(blocked.isProcessing, false);
  assert.equal(blocked.lastProtectedPath, "C:\\workspace\\.env");
  assert.equal(blocked.lastSnapshotId, "snapshot-1");
  assert.equal(typeof blocked.lastEventAt, "string");

  manager.setWarning("no baseline");

  const warning = manager.getState();
  assert.equal(warning.status, "WARNING");
  assert.equal(warning.message, "no baseline");
  assert.equal(warning.restoreAvailable, false);
  assert.equal(warning.isProcessing, false);
  assert.equal(warning.lastProtectedPath, "C:\\workspace\\.env");
  assert.equal(warning.lastSnapshotId, "snapshot-1");

  assert.equal(events.length, 2);
  assert.equal(events[0].status, "BLOCKED");
  assert.equal(events[1].status, "WARNING");

  subscription.dispose();
  manager.setSafe("safe after unsubscribe");
  assert.equal(events.length, 2);

  manager.dispose();
});

test("stateManager restoring and safe transitions control restore availability and processing flags", () => {
  const manager = new StateManager();
  const events: AegisUiState[] = [];

  manager.onDidChangeState((event) => {
    events.push(event);
  });

  manager.setBlocked("blocked", "C:\\workspace\\.env", "snapshot-2");
  manager.setRestoring();
  const restoring = manager.getState();

  assert.equal(restoring.status, "RESTORING");
  assert.equal(restoring.message, "Aegis is restoring your safe version...");
  assert.equal(restoring.restoreAvailable, false);
  assert.equal(restoring.isProcessing, true);
  assert.equal(restoring.lastProtectedPath, "C:\\workspace\\.env");
  assert.equal(restoring.lastSnapshotId, "snapshot-2");

  manager.setSafe("restored");
  const safe = manager.getState();

  assert.equal(safe.status, "SAFE");
  assert.equal(safe.message, "restored");
  assert.equal(safe.restoreAvailable, false);
  assert.equal(safe.isProcessing, false);
  assert.equal(safe.lastProtectedPath, "C:\\workspace\\.env");
  assert.equal(safe.lastSnapshotId, "snapshot-2");

  assert.deepEqual(events.map((event) => event.status), ["BLOCKED", "RESTORING", "SAFE"]);

  manager.dispose();
});

test("stateManager dispose clears registered listeners", () => {
  const manager = new StateManager();
  const events: AegisUiState[] = [];

  manager.onDidChangeState((event) => {
    events.push(event);
  });

  manager.dispose();
  manager.setWarning("after dispose");

  assert.equal(events.length, 0);
});
