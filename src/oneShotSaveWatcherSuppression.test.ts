import test from "node:test";
import assert from "node:assert/strict";

import { OneShotSaveWatcherSuppression } from "./oneShotSaveWatcherSuppression";

test("matching editor-save watcher event is consumed exactly once", () => {
  let now = 1_000;
  const suppression = new OneShotSaveWatcherSuppression(2_000, () => now);

  suppression.mark("/workspace/.env", "hash-a");

  assert.equal(suppression.consume("/workspace/.env", "hash-a"), true);
  assert.equal(suppression.consume("/workspace/.env", "hash-a"), false);
});

test("different content hash is not suppressed", () => {
  let now = 1_000;
  const suppression = new OneShotSaveWatcherSuppression(2_000, () => now);

  suppression.mark("/workspace/.env", "hash-a");

  assert.equal(suppression.consume("/workspace/.env", "hash-b"), false);
  assert.equal(suppression.consume("/workspace/.env", "hash-a"), false);
});

test("expired editor-save marker is not suppressed", () => {
  let now = 1_000;
  const suppression = new OneShotSaveWatcherSuppression(2_000, () => now);

  suppression.mark("/workspace/.env", "hash-a");
  now = 3_001;

  assert.equal(suppression.consume("/workspace/.env", "hash-a"), false);
});
