# Getting started with AEGIS Trust

**Goal:** understand the AEGIS Protection panel in a few minutes, using a safe practice folder rather than a real project.

## 1. Install

1. Open [AEGIS Trust on the VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust) and choose **Install**. You can also open VS Code's Extensions view and search for **AEGIS Trust** by **ProlixoTech Inc.**
2. Check that the installed extension is **`prolixotech.aegis-trust`**, version **0.1.0**.
3. Use VS Code `^1.85.0` or a newer compatible version. The initial installed-extension smoke check was performed in a VS Code environment; this is not a claim that every platform or workflow has undergone independent testing.

## 2. Start in a disposable folder

1. Create an **empty folder for practice**, not a folder containing real credentials or valuable project files.
2. In VS Code, choose **File → Open Folder**, and open the practice folder.
3. If VS Code shows **Restricted Mode**, trust the folder **only because you created it and know its contents**. AEGIS intentionally limits its operations in untrusted workspaces.

## 3. Open the protection panel

1. Open the Command Palette: **Cmd+Shift+P** on macOS, or **Ctrl+Shift+P** on Windows/Linux.
2. Type **`Aegis: Show Protection Panel`** and press Enter.
3. Look for the **Aegis Protection** tab. Its status card may show **`OK Aegis: Safe`** in a fresh, trusted practice workspace.

**How to read the panel:**

| Area | What it means |
| --- | --- |
| **Aegis: Safe / Warning / Blocked** | AEGIS's current local workflow status. A green status does **not** certify the whole computer or repository. |
| **Restore Last Safe State** | Used for an eligible protected-file restore. It can be disabled when there is no usable prior state. |
| **Workspace Risk Scan** | A limited, local filename-based suggestion of up to three files to review. It does **not** inspect file contents or prove the absence of hazards. |

## 4. Optional: explore a protected file safely

Only in your **disposable practice folder**, make a file named `.env` containing a clearly fictional value, such as:

```dotenv
AEGIS_DEMO_VALUE=example_only_not_a_secret
```

Save the file in VS Code, then look at the protection panel again. `.env` is one of the selected protected paths in the local target registry. The extension supports clean-baseline, snapshot, and restore-oriented workflows for supported targets. The exact state and available actions depend on your workspace's history; **do not use this exercise to test real secrets or production recovery**.

To explore the explicit baseline command, open the Command Palette and find **`Aegis: Register Current Clean Baseline`**. Only register a baseline when the file is in a state you actually want to keep. Do not use **Restore Last Safe State** in a real project as an experiment.

## 5. Explore commands, without running risky operations

These commands are provided by the installed extension:

- **`Aegis: Review AI Command / Action`** — review a proposed operation through AEGIS's command-review flow.
- **`Aegis: Protected Terminal (MVP-0)`** — use AEGIS's reviewed terminal handoff instead of assuming an ordinary terminal is protected. A permitted handoff is **not automatic execution**.
- **`Aegis: Generate Work Receipt`** — request a local Markdown receipt based on available AEGIS ledger events.

Some commands require an appropriate file, an established baseline, or other local state. Seeing a command in the palette does not mean every operation is available in an empty folder.

## 6. Before trying AEGIS Trust on real work

- Keep separate, tested backups. AEGIS is not a substitute for a backup system.
- Check the [security boundaries](SECURITY-MODEL.md) first: AEGIS-managed paths are narrower than all possible editor, shell, or agent activity.
- Treat `.aegis/` as potentially sensitive local state; keep it out of Git repositories and public file sharing.
- Use a trusted folder. Restricted Mode deliberately prevents AEGIS operations.
- Remember that the initial release does **not** provide live ProlixoTech-operated server ruleset updates.

## Need help?

- [Common workflows and examples](USAGE-EXAMPLES.md)
- [Report a non-sensitive bug or improvement](https://github.com/ProlixoTech/aegis-trust/issues)
- [Report a sensitive security issue privately](../SECURITY.md)
- [Back to AEGIS Trust](../README.md)
