# AEGIS Trust — frequently asked questions

These answers describe version **0.1.0**. Start with [Getting Started](GETTING-STARTED.md) if this is your first time using the extension.

## I installed AEGIS Trust. What do I click first?

Open a folder you trust in VS Code, press **Cmd+Shift+P** on macOS or **Ctrl+Shift+P** on Windows/Linux, enter **`Aegis: Show Protection Panel`**, and press Enter. The panel is called **Aegis Protection**.

## Why does it say “Restricted Mode” or “Aegis is disabled”?

VS Code does not trust the current workspace yet. If **you created the folder and know its contents**, use VS Code's workspace-trust control to trust it. Do not trust unknown repositories merely to make the extension run.

## Why is “Restore Last Safe State” greyed out?

There may be no eligible snapshot or the current AEGIS state may not permit restoration. In a fresh, empty workspace this is expected. Practice first with a fictional file using the [getting-started exercise](GETTING-STARTED.md#the-10-minute-practice-exercise). Do not assume a green “Safe” card means there is something to restore.

## How do I register a clean baseline?

For a normal first nonempty save of a supported target in a trusted workspace, the extension can register a verified baseline automatically. You can also run **`Aegis: Register Current Clean Baseline`**; it asks for confirmation and reviews **all present registered protected targets**, not just the current editor. Existing baselines are not overwritten by that command. Use the command only when you know the currently present files are safe.

## Can AEGIS reverse any edit by any AI tool?

**No.** Its checks apply to supported protected targets and AEGIS-managed workflows. Ordinary terminal commands, external agents, and other extensions are not universally intercepted. Restoration also requires a valid, appropriate baseline. Keep independent backups.

## Why does the panel say “No high-risk files detected”?

The Workspace Risk Scan looks for known filenames in a small part of the project. It does not read file contents, scan all subdirectories, or inspect malware. Zero results do **not** mean the project is risk-free.

## I saved a protected file but expected a status change. What now?

Confirm you opened a trusted workspace folder and that the file is at a registered relative path (for example, `.env` at the workspace root). On the first nonempty save, the extension may register a baseline rather than report a protected change. Only after a baseline exists does a later change typically enter a blocked/recovery workflow. If the result still looks wrong, file a bug with **version, platform, reproduction steps and redacted messages**—never with real `.env` values.

## What happens if I click Restore?

Depending on the registered state, the restore operation can write baseline data back to **all eligible protected targets** in that workspace, not merely the active file. It can replace your newer edits. Try it only in a disposable folder with fictional values until you understand the behavior. Keep backups independently.

## Does “Protected Terminal” automatically run a permitted command?

**No.** The managed handoff inserts a permitted command for the user to decide whether to execute. A separate, ordinary terminal is not under universal AEGIS control.

## Where does AEGIS store local information?

AEGIS uses a workspace-local **`.aegis/`** directory for state, snapshots and related local records. Snapshots may contain complete sensitive file contents. Keep `.aegis/` out of Git, public archives, screenshots and issue attachments.

## Are there automatic server security-rule updates?

**Not in 0.1.0.** The current release does not have a live ProlixoTech-operated remote ruleset-update service. A bundled fallback or public key does not imply live delivery.

## How do I report a problem or contribute code?

Use [GitHub Issues](https://github.com/ProlixoTech/aegis-trust/issues) for ordinary bugs and suggestions, and [Pull Requests](https://github.com/ProlixoTech/aegis-trust/pulls) for code changes. Include the installed extension version and clear, sanitized steps. For exploitable security issues follow [SECURITY.md](../SECURITY.md) **privately**.

## Where can I read the security limitations?

See the [Security Model](SECURITY-MODEL.md) and [Security Policy](../SECURITY.md). Publication and smoke-test success do not constitute an independent security audit.

**[Back to AEGIS Trust](../README.md)** · **[Getting started](GETTING-STARTED.md)**

