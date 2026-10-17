# AEGIS Trust

**A free, open-source safety layer for AI-assisted development in VS Code.**

AEGIS is a VS Code extension under active development. Its goal is to help developers protect important workspace files by checking recoverability and evaluating proposed operations before handing them off through AEGIS-controlled workflows.

> **Pre-release project.** The source, public build instructions, and security claims are subject to verification. Do not assume that a public release is available or that AEGIS replaces normal backups, access controls, credential management, or careful review of AI-generated changes.

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

- License target: Apache-2.0, **to be applied only after copyright and third-party rights clearance**.
- Public source release: pending publication review.
- Official release packages and platform support matrix: not yet published.
- Project working name: AEGIS; the existing internal extension package identifier may change before public release.

## Contributing

We welcome thoughtful bug reports, tests, documentation improvements, and narrowly scoped code contributions once the public repository is opened. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first. Do not post security vulnerabilities publicly; use the process in [SECURITY.md](SECURITY.md).

## Stewardship and contact

Maintained as an open-source initiative by **ProlixoTech Inc.**  
Project contact: **mathew.lee@prolixotech.com**  
Website: https://prolixotech.com/

Copyright ownership and the source license will be finalized before the actual first public source release.

## Server ruleset service availability

ProlixoTech Inc. does not currently operate a server ruleset service for AEGIS Trust.
This release does **not** include live, company-managed remote ruleset updates.
Features requiring an authenticated server-signed ruleset may be unavailable or disabled.

The included Ed25519 public key is a client trust anchor; it is not proof that a
live signing service exists. The bundled catastrophic fallback is local data,
not a live or remotely delivered server-signed ruleset. Do not rely on this
release for automatic server ruleset updates.
