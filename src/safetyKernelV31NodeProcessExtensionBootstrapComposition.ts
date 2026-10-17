import {
  NodeProcessExecutionAdapter,
  type NodeProcessSpawner,
} from "./nodeProcessExecutionAdapter";

import type {
  SafetyKernelV31CanonicalAuthorityReader,
  SafetyKernelV31SnapshotTargetIndexReader,
} from "../packages/aegis-core";

import {
  createSafetyKernelV31AuthoritySnapshotBindingComposition,
  type SafetyKernelV31AuthoritySnapshotBindingComposition,
} from "../packages/aegis-core";

import {
  createSafetyKernelV31AllowedExecutionCoordinatorComposition,
} from "../packages/aegis-core";

import {
  createSafetyKernelV31TransactionReviewPipelineComposition,
} from "../packages/aegis-core";

import {
  createSafetyKernelV31RuntimeControllerComposition,
} from "./safetyKernelV31RuntimeControllerComposition";

import {
  createSafetyKernelV31ExtensionComposition,
} from "./safetyKernelV31ExtensionComposition";

import {
  createSafetyKernelV31NodeProcessExecutionAdapterComposition,
} from "./safetyKernelV31NodeProcessExecutionAdapterComposition";

import {
  createSafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition,
} from "./safetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition";

import {
  createSafetyKernelV31NodeProcessTransactionReviewPipelineComposition,
} from "./safetyKernelV31NodeProcessTransactionReviewPipelineComposition";

import {
  createSafetyKernelV31NodeProcessRuntimeControllerComposition,
} from "./safetyKernelV31NodeProcessRuntimeControllerComposition";

import {
  createSafetyKernelV31NodeProcessExtensionComposition,
  type SafetyKernelV31NodeProcessExtensionComposition,
} from "./safetyKernelV31NodeProcessExtensionComposition";

import {
  SafetyKernelV31TransactionService,
} from "../packages/aegis-core";

import {
  SafetyKernelV31TransactionSessionStore,
} from "../packages/aegis-core";

import {
  SafetyKernelV31AllowedExecutionSessionBindingStore,
} from "../packages/aegis-core";

export interface SafetyKernelV31NodeProcessExtensionBootstrapCompositionInput {
  readonly authorityReader:
    SafetyKernelV31CanonicalAuthorityReader;

  readonly targetReaders:
    readonly SafetyKernelV31SnapshotTargetIndexReader[];

  readonly projectRoot: string;
  readonly aegisDir: string;

  readonly nodeProcessSpawner:
    NodeProcessSpawner;
}

export interface SafetyKernelV31NodeProcessExtensionBootstrapComposition {
  readonly nodeProcessExtensionComposition:
    SafetyKernelV31NodeProcessExtensionComposition;

  readonly authorityBindingComposition:
    SafetyKernelV31AuthoritySnapshotBindingComposition;

  readonly nodeProcessExecutionAdapter:
    NodeProcessExecutionAdapter;

  readonly transactionService:
    SafetyKernelV31TransactionService;

  readonly transactionSessionStore:
    SafetyKernelV31TransactionSessionStore;

  readonly allowedExecutionBindingStore:
    SafetyKernelV31AllowedExecutionSessionBindingStore;
}

export const
  SAFETY_KERNEL_V31_NODE_PROCESS_EXTENSION_BOOTSTRAP_COMPOSITION_INVARIANT =
    Object.freeze({
      DEVELOPMENT_COMPLETE_BEFORE_CONNECTION: true,
      REQUIRED_INPUT_COUNT: 5,
      OPTIONAL_INPUT_COUNT: 0,
      REQUIRED_NODE_PROCESS_SPAWNER_INPUT: true,
      DEFAULT_REAL_SPAWNER_USED: false,
      NODE_PROCESS_EXECUTION_ADAPTER_CONSTRUCTED_EXACTLY_ONCE: true,
      NODE_PROCESS_ADAPTER_RECEIVES_EXACT_INPUT_SPAWNER: true,
      TRANSACTION_SERVICE_CREATE_FOR_AEGIS_DIR_CALLED_EXACTLY_ONCE: true,
      TRANSACTION_SESSION_STORE_CONSTRUCTED_EXACTLY_ONCE: true,
      ALLOWED_EXECUTION_BINDING_STORE_CONSTRUCTED_EXACTLY_ONCE: true,
      A2F_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2G_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2H_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2I_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2J_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2K_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2L_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2M_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2N_FACTORY_CALLED_EXACTLY_ONCE: true,
      A2O_FACTORY_CALLED_EXACTLY_ONCE: true,
      INPUT_REFERENCES_CLONED: false,
      CONSTRUCTED_REFERENCES_REUSED_UNCHANGED: true,
      AUTHORITY_READ_DURING_COMPOSITION: false,
      INDEX_READ_DURING_COMPOSITION: false,
      BASELINE_FILE_READ_DURING_COMPOSITION: false,
      NODE_PROCESS_SPAWNER_CALLED_DURING_COMPOSITION: false,
      REVIEW_CALL_DURING_COMPOSITION: false,
      SESSION_CREATED_DURING_COMPOSITION: false,
      BINDING_REGISTERED_DURING_COMPOSITION: false,
      AUTHORITY_BOUND_DURING_COMPOSITION: false,
      COORDINATION_CALL_DURING_COMPOSITION: false,
      EXECUTION_CALL_DURING_COMPOSITION: false,
      EVIDENCE_WRITE_DURING_COMPOSITION: false,
      RECEIPT_WRITE_DURING_COMPOSITION: false,
      LEDGER_WRITE_DURING_COMPOSITION: false,
      AEGIS_DIR_FILE_CREATION_DURING_COMPOSITION: false,
      OUTPUT_OBJECT_FROZEN: true,
      EXTENSION_TS_MODIFIED: false,
      EXTENSION_ACTIVATION_CONNECTED: false,
      VSCODE_COMMAND_REGISTRATION_DURING_COMPOSITION: false,
      VSCODE_SUBSCRIPTION_MUTATION_DURING_COMPOSITION: false,
      EXISTING_EXTENSION_REVIEW_ONLY_PATH_UNCHANGED: true,
      DIRECT_RUNTIME_CONTROLLER_BOOTSTRAP_UNCHANGED: true,
      CONNECTION_SPECIFIC_READER_ADAPTER_DEVELOPMENT_COMPLETE: false,
      CONNECTION_ALLOWED_AFTER_A2P: false,
      REAL_PROCESS_EXECUTION_REQUIRED: false,
      REAL_COMMAND_EXECUTION_REQUIRED: false,
      FULL_L5C_COMPLETE: false,
      PRODUCT_PASS: false,
      FINAL_PASS: false,
      RELEASE_READY: false,
      UPLOAD_READY: false,
    } as const);

export function createSafetyKernelV31NodeProcessExtensionBootstrapComposition(
  input:
    SafetyKernelV31NodeProcessExtensionBootstrapCompositionInput
): SafetyKernelV31NodeProcessExtensionBootstrapComposition {
  const nodeProcessExecutionAdapter =
    new NodeProcessExecutionAdapter(
      input.nodeProcessSpawner
    );

  const transactionService =
    SafetyKernelV31TransactionService.createForAegisDir(
      input.aegisDir
    );

  const transactionSessionStore =
    new SafetyKernelV31TransactionSessionStore();

  const allowedExecutionBindingStore =
    new SafetyKernelV31AllowedExecutionSessionBindingStore();

  const authorityBindingComposition =
    createSafetyKernelV31AuthoritySnapshotBindingComposition({
      authorityReader:
        input.authorityReader,
      targetReaders:
        input.targetReaders,
      projectRoot:
        input.projectRoot,
      aegisDir:
        input.aegisDir,
    });

  const allowedExecutionCoordinatorComposition =
    createSafetyKernelV31AllowedExecutionCoordinatorComposition({
      execution:
        nodeProcessExecutionAdapter,
      authorityBindingComposition,
    });

  const transactionReviewPipelineComposition =
    createSafetyKernelV31TransactionReviewPipelineComposition({
      transactionService,
      transactionSessionStore,
      allowedExecutionBindingStore,
      allowedExecutionCoordinatorComposition,
    });

  const runtimeControllerComposition =
    createSafetyKernelV31RuntimeControllerComposition({
      transactionReviewPipelineComposition,
    });

  const extensionComposition =
    createSafetyKernelV31ExtensionComposition({
      runtimeControllerComposition,
    });

  const nodeProcessExecutionAdapterComposition =
    createSafetyKernelV31NodeProcessExecutionAdapterComposition({
      nodeProcessExecutionAdapter,
      extensionComposition,
    });

  const nodeProcessAllowedExecutionCoordinatorComposition =
    createSafetyKernelV31NodeProcessAllowedExecutionCoordinatorComposition({
      nodeProcessExecutionAdapterComposition,
    });

  const nodeProcessTransactionReviewPipelineComposition =
    createSafetyKernelV31NodeProcessTransactionReviewPipelineComposition({
      transactionService,
      transactionSessionStore,
      allowedExecutionBindingStore,
      nodeProcessAllowedExecutionCoordinatorComposition,
    });

  const nodeProcessRuntimeControllerComposition =
    createSafetyKernelV31NodeProcessRuntimeControllerComposition({
      nodeProcessTransactionReviewPipelineComposition,
    });

  const nodeProcessExtensionComposition =
    createSafetyKernelV31NodeProcessExtensionComposition({
      nodeProcessRuntimeControllerComposition,
    });

  return Object.freeze({
    nodeProcessExtensionComposition,
    authorityBindingComposition,
    nodeProcessExecutionAdapter,
    transactionService,
    transactionSessionStore,
    allowedExecutionBindingStore,
  });
}