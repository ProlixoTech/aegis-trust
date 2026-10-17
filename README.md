# AEGIS Trust

**A free, open-source safety layer for AI-assisted development in VS Code.**

[Install AEGIS Trust from the VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust)

AEGIS Trust is a VS Code extension under active development. Its goal is to help developers protect important workspace files by checking recoverability and evaluating proposed operations before handing them off through AEGIS-controlled workflows.

> **Initial Marketplace release (0.1.0).** AEGIS Trust is available on the VS Code Marketplace, and its source is publicly available here. Public build instructions and security claims remain subject to verification. AEGIS Trust does not replace normal backups, access controls, credential management, or careful review of AI-generated changes.

## What AEGIS is designed to do

- Manage selected protected workspace targets and local snapshots, including baseline registration for supported files.
- Verify snapshots before supported protected operations; reject the handoff when the required snapshot step fails.
- Review a proposed terminal command through the AEGIS Protected Terminal workflow. When permitted, the command is inserted for the user to execute rather than automatically run.
- Support restore-oriented workflows, integrity checks, and policy-driven safety decisions.

The latest internal evidence includes passing isolated regression tests and module-level failure-injection checks. That evidence is **not** a completed independent security audit or a guarantee of every end-to-end execution path.

## Security boundaries

AEGIS is **not** an operating-system sandbox, a universal filesystem firewall, or a replacement for a secrets manager. The AEGIS Protected Terminal workflow cannot prevent arbitrary edits made in an ordinary terminal, by external processes, or by integrations outside its control.

Snapshots may contain copies of sensitive file contents. Never commit `.env` files, personal snapshots, private keys, live credentials, or AEGIS local runtime state to a Git repository. See [Security Model](docs/SECURITY-MODEL.md) and [Security Policy](SECURITY.md).

## Project status

- Source license: Apache-2.0 (see [LICENSE](LICENSE)).
- Public source release: published at https://github.com/ProlixoTech/aegis-trust.
- VS Code Marketplace release: [AEGIS Trust 0.1.0](https://marketplace.visualstudio.com/items?itemName=prolixotech.aegis-trust).
- Separate platform support matrix: not yet published.
- Project name: AEGIS Trust; VS Code extension identifier: `prolixotech.aegis-trust`.

## Contributing

We welcome thoughtful bug reports, tests, documentation improvements, and narrowly scoped code contributions. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first. Do not post security vulnerabilities publicly; use the process in [SECURITY.md](SECURITY.md).

## Stewardship and contact

Maintained as an open-source initiative by **ProlixoTech Inc.**  
Project contact: **mathew.lee@prolixotech.com**  
Website: https://prolixotech.com/

For license terms, see [LICENSE](LICENSE).

## Server ruleset service availability

ProlixoTech Inc. does not currently operate a server ruleset service for AEGIS Trust.
This release does **not** include live, company-managed remote ruleset updates.
Features requiring an authenticated server-signed ruleset may be unavailable or disabled.

The included Ed25519 public key is a client trust anchor; it is not proof that a
live signing service exists. The bundled catastrophic fallback is local data,
not a live or remotely delivered server-signed ruleset. Do not rely on this
release for automatic server ruleset updates.
