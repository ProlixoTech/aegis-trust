# AEGIS Trust — security model (0.1.0)

## Scope

AEGIS Trust is a free, open-source VS Code extension intended to improve developer awareness and recoverability **within supported, AEGIS-managed workflows**. Version 0.1.0 is publicly available on the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust).

Supported concepts include selected protected targets, local baseline and snapshot handling, restore validation, command review and evidence-oriented Work Receipts. The extension is **not** a universal filesystem access-control mechanism.

## Trust boundaries

- **AEGIS-managed workflows:** the extension can evaluate supported proposed operations and apply their documented preflight, command-review, protected-target, and fail-closed behaviors.
- **Outside managed workflows:** arbitrary commands in ordinary terminals, other extensions, operating-system processes, unintegrated AI agents and external filesystem APIs are not universally intercepted.
- **Sensitive local state:** snapshots may include full contents of files such as `.env`. Keep `.aegis/` protected by local permissions and excluded from Git and public sharing. AEGIS is not a secrets manager.
- **Workspace trust:** VS Code Restricted Mode limits AEGIS operations until the user explicitly trusts the workspace. Never trust an unfamiliar folder merely to activate an extension.
- **External rule delivery:** ProlixoTech Inc. does not currently operate a live remote signed-ruleset update service for version 0.1.0. Bundled public-key material and fallback data are not a live update channel.

## What validation supports the release?

Prior internal isolated regression tests, failure-injection checks and a Marketplace-install smoke test exist in the development history. The Marketplace smoke test confirmed installation and activation of the Aegis Protection panel in a disposable VS Code workspace; it did **not** exercise every recovery, adversarial, or cross-platform scenario.

Earlier internal test counts appeared in older draft documents. They should **not** be interpreted as a current independent security certificate or proof that the public checkout reproduces every historical test result. No independent security audit or complete public end-to-end verification matrix is claimed.

## Responsible claims

Do not describe this release as universal AI-agent interception, malware prevention, guaranteed restoration of any file, a secure secrets vault, or a replacement for backups and human review. A green **Aegis: Safe** card is a local workflow state only; likewise, a blank Workspace Risk Scan is not a security clearance.

## Security reports

Follow [SECURITY.md](../SECURITY.md) for private disclosure. **Never** post exploit details, tokens, real `.env` values, complete snapshots, or customer information in public issues.

