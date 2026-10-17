import test from "node:test";
import assert from "node:assert/strict";

import {
  SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH,
  SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS,
  SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS,
  SAFETY_KERNEL_V31_SERVER_REVOCATION_METADATA_LIMIT,
  SAFETY_KERNEL_V31_SOURCE_OF_TRUTH_DISCIPLINE_REQUIREMENTS,
  SAFETY_KERNEL_V31_WORKSPACE_LOCAL_TRUSTED_CAPABILITY_CONSTRAINT,
} from "./types";

test("types exports server revocation metadata as metadata-only local-client authority limit", () => {
  assert.equal(SAFETY_KERNEL_V31_SERVER_REVOCATION_METADATA_LIMIT.server_revocation_metadata_only, true);
  assert.deepEqual(SAFETY_KERNEL_V31_SERVER_REVOCATION_METADATA_LIMIT.allowed_revocation_scopes, [
    "ruleset_metadata",
    "policy_metadata",
    "signing_key_metadata",
    "version_metadata",
    "freshness_metadata",
  ]);
  assert.equal(
    SAFETY_KERNEL_V31_SERVER_REVOCATION_METADATA_LIMIT.server_cannot_decide_targeted_user_action_allow_block,
    true
  );
  assert.equal(SAFETY_KERNEL_V31_SERVER_REVOCATION_METADATA_LIMIT.local_client_remains_decision_authority, true);
});

test("types exports workspace-local trusted capability constraints that cannot weaken kernel invariants", () => {
  assert.deepEqual(SAFETY_KERNEL_V31_WORKSPACE_LOCAL_TRUSTED_CAPABILITY_CONSTRAINT, {
    workspace_local_trusted_capability_source: "workspace_local_policy",
    may_only_narrow_or_add_allowed_capabilities: true,
    cannot_weaken_non_overridable_invariants: true,
    cannot_grant_silent_auto_execute: true,
    cannot_grant_system_scope_bypass: true,
    cannot_bypass_receipt_ledger: true,
    cannot_permit_nonce_reuse: true,
    cannot_bypass_kernel: true,
    cannot_bypass_no_upload: true,
  });
});

test("types exports local-client capability manifest source of truth", () => {
  const manifest = SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH;

  assert.equal(manifest.manifest_id, "local_client_default_v1");
  assert.equal(manifest.manifest_version, "0.1.0-mvp0");
  assert.equal(manifest.policy_version, "safety-kernel-v3.1-local-client-mvp0");
  assert.equal(manifest.source_of_truth, "local_client_capability_manifest");
  assert.equal(manifest.server_may_only_narrow_or_add_allowed_capabilities, true);
  assert.equal(manifest.server_cannot_grant_bypass, true);

  assert.deepEqual(
    manifest.trusted_capabilities.map(entry => entry.capability_id),
    [
      "manual_review_preview_only",
      "protected_terminal_user_visible_insert_only",
      "ai_gateway_review_only",
    ]
  );

  assert.deepEqual(manifest.non_overridable_invariants, [
    "deny_by_default",
    "no_raw_command_auto_execution_without_kernel_allow",
    "no_nonce_reuse",
    "no_kernel_bypass",
    "no_receipt_ledger_bypass",
    "no_no_upload_bypass",
    "no_protected_write_without_restore_point",
    "adapter_cannot_override_kernel_decision",
    "local_first_action_decision",
    "server_cannot_decide_targeted_user_action_allow_block",
  ]);
});

test("types capability manifest entries preserve source-specific capability boundaries", () => {
  const manifest = SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH;
  const manual = manifest.trusted_capabilities.find(entry => entry.capability_id === "manual_review_preview_only");
  const terminal = manifest.trusted_capabilities.find(entry => entry.capability_id === "protected_terminal_user_visible_insert_only");
  const gateway = manifest.trusted_capabilities.find(entry => entry.capability_id === "ai_gateway_review_only");

  assert.ok(manual);
  assert.equal(manual.operation_class, "read");
  assert.equal(manual.scope, "workspace");
  assert.equal(manual.manner, "preview_only");
  assert.deepEqual(manual.allowed_sources, ["manual_review", "vscode_command"]);
  assert.equal(manual.user_configurable, true);

  assert.ok(terminal);
  assert.equal(terminal.operation_class, "execute");
  assert.equal(terminal.scope, "workspace");
  assert.equal(terminal.manner, "requires_review");
  assert.deepEqual(terminal.allowed_sources, ["protected_terminal"]);
  assert.ok(terminal.non_overridable_invariants.includes("no_raw_command_auto_execution_without_kernel_allow"));

  assert.ok(gateway);
  assert.equal(gateway.operation_class, "execute");
  assert.equal(gateway.scope, "workspace");
  assert.equal(gateway.manner, "requires_review");
  assert.deepEqual(gateway.allowed_sources, ["ai_connector"]);
  assert.ok(gateway.non_overridable_invariants.includes("server_cannot_decide_targeted_user_action_allow_block"));
});

test("capability manifest contains complete review-only authority metadata", () => {
  const entries =
    SAFETY_KERNEL_V31_CAPABILITY_MANIFEST_SOURCE_OF_TRUTH
      .trusted_capabilities;

  assert.deepEqual(
    entries.map(entry => entry.handler_id),
    [
      "aegis.reviewAiCommandOrAction",
      "aegis.protectedTerminal",
      "aegis.aegisExecutionGatewayMvp0",
    ]
  );
  assert.deepEqual(
    entries.map(entry => entry.action_kind),
    [
      "review_ai_command_or_action",
      "protected_terminal_insert_review",
      "ai_execution_gateway_review",
    ]
  );

  for (const entry of entries) {
    assert.deepEqual(entry.artifact_kinds, []);
    assert.deepEqual(entry.command_template_hashes, []);
    assert.equal(entry.target_scope, "workspace_only");
    assert.equal(
      entry.approval_requirement,
      "safety_kernel_review_required"
    );
  }
});

test("types exports known precondition ledger requirements with recovery and anti-rediscovery guards", () => {
  assert.equal(SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS.known_precondition_ledger_required, true);
  assert.equal(SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS.handoff_contract_semantic_ingestion_gate_required, true);
  assert.equal(SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS.objective_preservation_gate_required, true);
  assert.equal(SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS.rediscovery_loop_guard_required, true);
  assert.equal(SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS.missing_path_recovery_classifier_required, true);
  assert.equal(SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS.owner_recovery_envelope_required, true);
  assert.equal(SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS.denial_label_is_evidence_not_schema, true);
  assert.deepEqual(SAFETY_KERNEL_V31_KNOWN_PRECONDITION_LEDGER_REQUIREMENTS.negative_selftests, [
    "BLOCK_REDISCOVERY_FORBIDDEN",
    "BLOCK_OBJECTIVE_REVERSAL",
    "ALLOW_READ_ONLY_PATCH_ANCHOR_CAPTURE",
    "ALLOW_OWNER_RECOVERY_ENVELOPE_VALID",
  ]);
});

test("types exports source-of-truth discipline requirements for provenance and stale-context blocking", () => {
  assert.equal(SAFETY_KERNEL_V31_SOURCE_OF_TRUTH_DISCIPLINE_REQUIREMENTS.gate, "SOURCE_OF_TRUTH_DISCIPLINE_GATE");
  assert.deepEqual([...SAFETY_KERNEL_V31_SOURCE_OF_TRUTH_DISCIPLINE_REQUIREMENTS.categories], [
    "VERIFIED_FROM_PRIMARY_SOURCE",
    "ESTABLISHED_PRIOR_FACT",
    "UNVERIFIED_APPEARANCE",
  ]);
  assert.equal(SAFETY_KERNEL_V31_SOURCE_OF_TRUTH_DISCIPLINE_REQUIREMENTS.sandbox_artifact_requires_authorized_provenance, true);
  assert.equal(SAFETY_KERNEL_V31_SOURCE_OF_TRUTH_DISCIPLINE_REQUIREMENTS.assistant_claim_is_not_source_of_truth, true);
  assert.equal(SAFETY_KERNEL_V31_SOURCE_OF_TRUTH_DISCIPLINE_REQUIREMENTS.stale_in_context_summary_forbidden_for_decision, true);
  assert.equal(SAFETY_KERNEL_V31_SOURCE_OF_TRUTH_DISCIPLINE_REQUIREMENTS.approval_scope_creep_forbidden, true);
});

test("types exports no-guessing always-verify requirements and forbidden inference classes", () => {
  assert.equal(SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS.top_priority_rule, "NO_GUESSING_ALWAYS_VERIFY");
  assert.equal(SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS.assumption_forbidden, true);
  assert.equal(SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS.verify_before_decision, true);
  assert.equal(SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS.verify_before_mutation, true);
  assert.equal(SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS.final_status_must_come_from_explicit_gate_result, true);
  assert.deepEqual(SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS.required_requirements, [
    "FINAL_PRODUCT_REQUIREMENT=NO_GUESSING_ALWAYS_VERIFY",
    "FINAL_PRODUCT_REQUIREMENT=ASSUMPTION_FREE_AUTHORITY",
    "FINAL_PRODUCT_REQUIREMENT=VERIFY_BEFORE_DECISION",
    "FINAL_PRODUCT_REQUIREMENT=EXPLICIT_GATE_RESULT_FOR_FINAL_STATUS",
  ]);
  assert.deepEqual(SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS.forbidden_inferences, [
    "helper_name_guess",
    "function_signature_guess",
    "required_zip_entry_guess",
    "current_phase_guess",
    "lock_file_guess",
    "compiler_surface_guess",
    "final_product_pass_guess",
    "upload_ready_guess",
    "final_zip_guess",
  ]);
  assert.equal(
    SAFETY_KERNEL_V31_NO_GUESSING_ALWAYS_VERIFY_REQUIREMENTS.rediscovery_exception,
    "do_not_rediscover_confirmed_known_preconditions"
  );
});