# AEGIS Trust

**Before acting on an AI-suggested change, take a closer look at the files and commands that matter.**

AEGIS Trust is a **free, open-source VS Code extension** for local snapshots, recoverability checks, command review, and work receipts in **AEGIS-managed workflows**. It helps developers make more deliberate decisions around selected important project files. It does not intercept every AI tool or protect every filesystem operation.

**[Install from the VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust)** · [Get started](docs/GETTING-STARTED.md) · [See real-world use cases](docs/USAGE-EXAMPLES.md) · [Security model](docs/SECURITY-MODEL.md)

## Why AEGIS Trust?

AI coding assistants can suggest changes to configuration files, dependencies, or shell commands. Those suggestions can be useful, but a quick review and a recoverable starting point matter before you act.

AEGIS Trust provides a **local checkpoint within its supported workflows**:

| What you want to do | How AEGIS Trust helps |
| --- | --- |
| Notice sensitive project files | The Workspace Risk Scan highlights up to three filenames worth reviewing; it is a limited, local, filename-based scan, **not** a content or malware scan. |
| Prepare for edits to selected files | Supported protected targets have baseline, snapshot, and restore-oriented workflows. Examples include `.env`, `.env.local`, `package.json`, `tsconfig.json`, and selected source files. |
| Consider an AI-suggested command | **Aegis: Review AI Command / Action** and **Aegis: Protected Terminal (MVP-0)** offer review paths; when a command is permitted for terminal handoff, the user still chooses whether to execute it. |
| Keep a local record | **Aegis: Generate Work Receipt** produces a Markdown receipt from local AEGIS ledger information where available. |

## Your first 3 minutes

1. [Install AEGIS Trust](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust) in VS Code (compatible with VS Code `^1.85.0`).
2. Open a **new, disposable test folder** in VS Code, and trust that folder if you created it and know its contents.
3. Open the Command Palette (**Cmd+Shift+P** on macOS or **Ctrl+Shift+P** on Windows/Linux).
4. Run **`Aegis: Show Protection Panel`**. The panel displays AEGIS's local status, restore availability, and limited Workspace Risk Scan.
5. Follow the [step-by-step guide](docs/GETTING-STARTED.md) before experimenting with a protected file or a proposed command.

> **What does “Safe” mean?** The panel status describes the AEGIS-controlled state, not a guarantee that your computer, repository, or all AI-generated changes are safe. **Restore Last Safe State** may be disabled until there is an eligible snapshot.

## Use cases

- **Before configuration edits:** start from a known-good state and use a supported protected-target workflow. [See the example](docs/USAGE-EXAMPLES.md#1-before-changing-a-configuration-file).
- **Before a proposed terminal command:** review the command through an AEGIS-provided command path; never assume ordinary terminals are covered. [See the example](docs/USAGE-EXAMPLES.md#2-when-an-ai-assistant-suggests-a-terminal-command).
- **When you want a local record:** generate a work receipt for review; it is not an independent audit. [See the example](docs/USAGE-EXAMPLES.md#3-when-you-need-a-record-of-protected-work).

## Important security boundaries

- **Not a universal firewall or sandbox.** Operations in regular terminals, external agents, or other extensions can bypass AEGIS-controlled workflows.
- **Not a backup service.** Keep independent backups, access controls, and human review.
- **Keep local snapshots private.** The `.aegis/` working directory can contain snapshots of sensitive content. Never commit it, real `.env` values, private keys, credentials, or unsanitized logs.
- **No live managed ruleset updates in 0.1.0.** ProlixoTech Inc. does not currently operate a server ruleset service for AEGIS Trust. The bundled public key and local fallback do not imply an active signing service.
- **No independent security-audit claim.** Internal tests are useful evidence, not a guarantee across every workflow or platform.

Read the [security model](docs/SECURITY-MODEL.md) and [security reporting policy](SECURITY.md) for details.

## Project and community

- **Release:** 0.1.0 — [Marketplace](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust)
- **Publisher:** `prolixotech` · **Extension ID:** `prolixotech.aegis-trust`
- **License:** [Apache-2.0](LICENSE)
- **Report a reproducible bug or request an improvement:** [GitHub Issues](https://github.com/ProlixoTech/aegis-trust/issues)
- **Propose a code change:** [Pull Requests](https://github.com/ProlixoTech/aegis-trust/pulls) · read [CONTRIBUTING.md](CONTRIBUTING.md)
- **Report a security vulnerability privately:** follow [SECURITY.md](SECURITY.md). Do not post secrets or exploitable details to a public issue.

Maintained by **ProlixoTech Inc.** · [Website](https://prolixotech.com/) · Contact: **mathew.lee@prolixotech.com**
