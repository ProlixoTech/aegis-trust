# AEGIS Trust: everyday use cases

These examples explain **where AEGIS Trust can help** and where the developer must still make the final decision. They describe supported AEGIS-managed workflows, not a guarantee that all changes by AI assistants are intercepted.

## 1. Before changing a configuration file

**Situation:** an AI assistant proposes editing `.env`, `package.json`, or `tsconfig.json`.

**What you can do:**

1. Keep a separate backup and confirm the current file is correct.
2. In a trusted VS Code workspace, open **`Aegis: Show Protection Panel`**.
3. Use the extension's supported baseline/snapshot workflow for an eligible protected target before relying on its restore functionality.
4. Review any proposed edit yourself and check the resulting file. The availability of restore depends on a valid local snapshot and the particular workflow.

**Boundary:** only specific registered targets and AEGIS-managed paths are in scope. A normal shell command or another extension can change a file outside AEGIS's controls. Never test recovery against production secrets.

## 2. When an AI assistant suggests a terminal command

**Situation:** an assistant proposes a shell command that might change your project or its configuration.

**What you can do:**

1. Read the command and understand the files or processes it may affect.
2. Open **`Aegis: Review AI Command / Action`** or **`Aegis: Protected Terminal (MVP-0)`** from the VS Code Command Palette.
3. Follow the review result. AEGIS may block a handoff or allow you to insert a permitted command into a terminal.
4. **Decide yourself whether to run it.** Terminal handoff is not automatic execution.

**Boundary:** a regular terminal, outside process, or unintegrated AI agent is not automatically governed by AEGIS. Do not interpret an allowed handoff as proof that a command is universally harmless.

## 3. When you need a record of protected work

**Situation:** after working in a supported workflow, you want to inspect the local evidence of relevant events.

**What you can do:**

1. Open the Command Palette and choose **`Aegis: Generate Work Receipt`**.
2. Review the resulting Markdown receipt, if local ledger events are available.
3. Check the reported events and status against the actual workspace before sharing any summary.

**Boundary:** the receipt describes locally available AEGIS ledger information. It is **not** a cloud verification, external audit, or proof that no other changes occurred. Do not share unsanitized local logs or sensitive file contents.

## 4. When you open an unfamiliar project

**Situation:** you want a quick visual indication of common files that deserve extra care before editing.

**What you can do:** open **`Aegis: Show Protection Panel`** in a trusted workspace and read **Workspace Risk Scan**.

**What you should expect:** up to three filenames are highlighted using limited local heuristics. The scan considers file names and selected shallow locations; it **does not read the contents of those files**. A result such as “No high-risk files detected by static scan” is not a security clearance.

## AEGIS Trust is not

- A universal sandbox, malware scanner, or filesystem firewall.
- A guarantee that every VS Code extension, AI agent, or terminal command is covered.
- A replacement for backups, secrets management, access controls, or careful human review.
- A live remotely signed ruleset-update service in version 0.1.0.

**Start here:** [Getting started](GETTING-STARTED.md) · [Security model](SECURITY-MODEL.md) · [Install](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust) · [Back to README](../README.md)
