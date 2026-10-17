# AEGIS Trust

**Review AI-suggested actions and prepare a recoverable starting point for important project files.**

AEGIS Trust is a **free, open-source VS Code extension** for selected local file-protection workflows: baselines, snapshots, restore checks, command review, and work receipts. It helps developers pause before acting on risky changes **inside AEGIS-managed workflows**; it does not monitor every command or AI assistant.

**[Install AEGIS Trust (https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust)](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust)** · **[Start in 3 minutes](docs/GETTING-STARTED.md)** · [Try a 10-minute practice exercise](docs/GETTING-STARTED.md#the-10-minute-practice-exercise) · [FAQ](docs/FAQ.md)

## Why would I use this?

An AI coding assistant may suggest changing a configuration file or running a terminal command. Before acting, you may want to know which files deserve care, whether an eligible local baseline exists, and what the proposed command would do.

| Your question | What AEGIS Trust helps you do |
| --- | --- |
| Which files should I check? | View the **Workspace Risk Scan**, which highlights up to three likely important filenames in a shallow, local scan. It does **not** inspect file contents. |
| Can I recover a supported file? | Use baseline, snapshot, and restore-oriented workflows for registered targets, such as `.env`, `.env.local`, `package.json`, `tsconfig.json`, and selected source files. Restore requires a usable baseline. |
| Should I run this AI-proposed command? | Review it with **Aegis: Review AI Command / Action** or the **Aegis Protected Terminal** workflow. A permitted terminal handoff still needs **your** decision to execute. |
| What happened during protected work? | Generate a local Markdown Work Receipt from available AEGIS ledger events. It is a local record, not independent verification of everything that happened. |

## What does AEGIS look like?

![Illustrated reference to the Aegis Protection panel: Safe status, Restore Last Safe State button, and Workspace Risk Scan](docs/assets/aegis-protection-panel-guide.svg)

*Illustrated guide based on the real AEGIS Trust 0.1.0 protection panel observed during the Marketplace installation check. This is a simplified diagram, not an unedited screenshot. The panel's wording and available actions depend on workspace state.*

**How to interpret the screen:** **Safe** means the AEGIS-controlled local state is currently safe—not that your computer or every AI-generated change is safe. **Restore Last Safe State** can be disabled before an eligible snapshot exists. **No high-risk files detected** means only that the limited filename scan had no match; it is not a security clearance.

## Get started in 3 minutes

1. **Install** [AEGIS Trust from the VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust) and open a new, empty practice folder in VS Code.
2. **Trust only that new folder** if VS Code shows Restricted Mode and you created the folder yourself.
3. Open the Command Palette (**Cmd+Shift+P** on macOS / **Ctrl+Shift+P** on Windows or Linux), run **`Aegis: Show Protection Panel`**, and look for the **Aegis Protection** tab.

That's enough to explore the interface without touching a real project. For a complete, safe first exercise, follow [Getting Started](docs/GETTING-STARTED.md).

## Four everyday situations

- **Before editing `.env` or `package.json`:** register a known-good baseline in a disposable practice folder and learn when recovery becomes available. [Walkthrough](docs/USAGE-EXAMPLES.md#1-changing-a-protected-file).
- **When an AI assistant suggests a shell command:** enter the proposed text in AEGIS's review command and inspect the result before making your own decision. [Walkthrough](docs/USAGE-EXAMPLES.md#2-reviewing-an-ai-proposed-command).
- **After supported protected activity:** generate and read a Work Receipt without exposing secrets. [Walkthrough](docs/USAGE-EXAMPLES.md#3-reading-a-work-receipt).
- **When starting an unfamiliar workspace:** read the filename-based Workspace Risk Scan with the correct expectations. [Walkthrough](docs/USAGE-EXAMPLES.md#4-reading-the-workspace-risk-scan).

## Boundaries you should understand

- **AEGIS controls only its supported workflows.** Ordinary terminals, other VS Code extensions, operating-system processes and unintegrated AI agents are not universally blocked.
- **AEGIS is not a sandbox, an antivirus product, a secrets manager, or a backup replacement.** Keep independent backups and review any proposed change.
- **Snapshots can contain sensitive file contents.** The local `.aegis/` folder must not be committed to Git, shared publicly or treated as a secure vault.
- **No live company-operated remote ruleset-update service is included in version 0.1.0.** The included public-key trust material and bundled fallback are not evidence of an active signing service.
- **No independent security audit has been completed or claimed.** Internal tests and an installed-extension smoke check do not guarantee all platforms or failure paths.

Read [Security Model](docs/SECURITY-MODEL.md), [FAQ](docs/FAQ.md) and [Security Policy](SECURITY.md).

## Open source and support

- **Current Marketplace release:** [AEGIS Trust 0.1.0](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust) — extension ID `prolixotech.aegis-trust`.
- **License:** [Apache-2.0](LICENSE).
- **Bugs and feature requests:** [GitHub Issues](https://github.com/ProlixoTech/aegis-trust/issues).
- **Source changes:** [Pull Requests](https://github.com/ProlixoTech/aegis-trust/pulls) — please read [CONTRIBUTING.md](CONTRIBUTING.md).
- **Sensitive security reports:** follow [SECURITY.md](SECURITY.md); do not publish credentials, customer files or exploit details.

Maintained by **ProlixoTech Inc.** · [Website](https://prolixotech.com/) · **mathew.lee@prolixotech.com**

