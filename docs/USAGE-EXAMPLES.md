# AEGIS Trust — practical use cases

Use the following as guides for AEGIS-managed VS Code workflows, **not** as proof that the extension blocks every possible AI, shell, or filesystem operation. For a first hands-on exercise, start with [Getting Started](GETTING-STARTED.md).

## 1. Changing a protected file

**Situation:** an AI coding assistant suggests changing `package.json`, `tsconfig.json`, or `.env`.

**Before the change:** check that the current file is correct, keep a separate backup, and confirm its baseline has been registered through the extension's local protected-file workflow.

**What AEGIS does:** for supported target paths in a trusted workspace, the extension can keep local baseline/snapshot state and can mark a protected-file change as **Blocked**. For an eligible registered baseline it can provide **Restore Last Safe State**.

**What you do:** inspect both the actual file and the panel; decide whether restoration is appropriate. Restore can write to **more than one registered target**. Never test with real credentials or unbacked-up production files.

**Try this yourself:** follow the [10-minute fictional `.env` exercise](GETTING-STARTED.md#the-10-minute-practice-exercise).

## 2. Reviewing an AI-proposed command

**Situation:** an assistant suggests a shell command, and you want to inspect it rather than immediately paste it into a terminal.

1. Open the VS Code Command Palette, then run **`Aegis: Review AI Command / Action`**.
2. With no editor selection, the extension asks **`Paste or type the AI-generated command or action to review`**. Enter the proposed text yourself and press Enter.
3. Read the resulting review and any allowed/blocked next step. AEGIS does **not** execute the command simply because you requested a review.
4. If you use **`Aegis: Protected Terminal (MVP-0)`**, a permitted command is handed to a dedicated terminal **without being run automatically**. Review it again before executing.

**Boundary:** commands run in an ordinary terminal, or edits by other extensions and external agents, are not automatically covered. An allowed result is not an all-purpose safety guarantee.

## 3. Reading a Work Receipt

**Situation:** you want a local record of AEGIS-managed work.

1. After supported protected activity, run **`Aegis: Generate Work Receipt`** from the Command Palette.
2. If local ledger records are available and the operation succeeds, the extension writes a Markdown receipt under the workspace's local **`.aegis/receipts/`** area.
3. Read the receipt's event timeline, success/verification fields and warnings. Compare it to the actual project state.

**Boundary:** a Work Receipt is local evidence of specified AEGIS events—not an independent audit, cloud attestation, or a record of all external changes. Do not share unsanitized local data.

## 4. Reading the Workspace Risk Scan

**Situation:** you open a project and want a quick prompt about filenames worth checking.

1. Open **`Aegis: Show Protection Panel`** and locate **WORKSPACE RISK SCAN**.
2. Review any listed filenames and the accompanying reason. The current scan considers common top-level configuration files and selected shallow paths, returning up to three suggestions.
3. Independently review real file contents and the project's context before making decisions.

**Boundary:** it is a **limited filename-based local scan**, not a vulnerability scanner, content inspection, or security clearance. “No high-risk files detected” does not imply a safe project.

## What files are in scope?

The current public source includes a **static registry** of eligible protected paths. These include `.env`, `.env.local`, `package.json`, `tsconfig.json`, and specified `src/*.ts` implementation files. **Not every file with the same extension is registered**, and the scan's filenames do not necessarily match the protected-target registry.

Some operations require an existing valid baseline, a trusted workspace, and other local state. A button being visible is not a promise it will be available in every situation.

## What AEGIS Trust does not promise

- Universal protection against every AI agent, shell command, edit, malware program or file operation.
- Complete recovery without an eligible local baseline or separate backups.
- Safe handling of genuine private keys in a demo; use only fictional test values.
- A current company-operated remote ruleset-update or signing service in release 0.1.0.
- An independently audited guarantee across every operating system or negative-path scenario.

**Continue:** [Step-by-step practice](GETTING-STARTED.md) · [FAQ](FAQ.md) · [Security Model](SECURITY-MODEL.md) · [Install](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust)

