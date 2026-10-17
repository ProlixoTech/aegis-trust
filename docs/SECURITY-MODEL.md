# AEGIS Security Model (Draft)

## Scope

AEGIS aims to improve the safety of AI-assisted development within supported VS Code extension workflows. It provides policy checks, protected-target registration, snapshot and restore capabilities, and evidence-driven decisions about selected operations.

## Trust boundaries

- **Inside an AEGIS-managed workflow:** the extension can review a proposed action and enforce its documented preflight and fail-closed behavior.
- **Outside an AEGIS-managed workflow:** ordinary shell sessions, filesystem APIs, editor extensions, and external processes are outside any universal enforcement claim.
- **Local sensitive data:** protected snapshots may contain complete copies of files, including `.env` data. Git and cloud-sync hygiene, local OS permissions, and recovery policies remain necessary.
- **External integrations:** connectors or future execution gateways must not be assumed trusted merely because they are integrated with VS Code.

## Known validation boundary

Earlier internal testing reported 1,044 passing isolated tests and module-level checks for snapshot write/readback failures leading to no execution and unchanged protected file/index state. These tests alone do not establish that all product end-to-end paths, platforms, or failure modes are secure. A full installed-extension negative-path verification remains a separate release gate.

## Responsible claims

Do not market AEGIS as a universal malware defense, a guaranteed secrets vault, a sandbox for every AI agent, or a substitute for backups. Public feature descriptions must correspond to the final tested source release.
