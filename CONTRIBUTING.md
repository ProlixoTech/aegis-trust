# Contributing to AEGIS Trust

Thank you for helping developers use AI-assisted workflows more carefully. AEGIS Trust is a security-sensitive VS Code extension, so proposals need clear scope, reproducible evidence, and respect for users' local data.

## Reporting an ordinary bug

1. Search [existing GitHub Issues](https://github.com/ProlixoTech/aegis-trust/issues) and [Pull Requests](https://github.com/ProlixoTech/aegis-trust/pulls) for the same problem.
2. Open an Issue describing the installed extension version, operating system, VS Code version, exact user action, expected result, actual result and safe reproduction steps.
3. Attach **redacted** messages or an example using fictional values. Never include real `.env` contents, snapshots, tokens, private keys, customer data or unfiltered local paths.
4. For new exploitable security vulnerabilities, use [private security reporting](SECURITY.md), **not** a public Issue.

## Proposing source changes

1. For substantial behavior or security-policy changes, discuss the design with maintainers in an Issue **before** starting.
2. Keep Pull Requests narrowly scoped; describe changes in behavior, security boundaries, compatibility, storage and rollback risks.
3. Include relevant tests for behavior changes, especially failure paths and no-mutation/fail-closed outcomes. Explain how to reproduce the result.
4. Do not weaken a fail-closed policy simply to make a test pass. Specify whether snapshot integrity, Protected Terminal, authorization, local storage or external integrations are affected.
5. Keep public code comments, issue reports, user-facing text and PR descriptions in English. Disclose origin and license of third-party code/assets.

## Building and testing

The public source includes TypeScript/npm scripts for `compile` and `test`. Use the project's published lockfiles and an isolated checkout when checking changes. Commands listed in `package.json` include:

```bash
npm run compile
npm test
```

Do not treat older internal test totals or local developer-tree evidence as a replacement for results from your own clean checkout. There is no claim here that a comprehensive public CI / platform support matrix is already configured.

## Maintainer review

Maintainers may request revisions or decline changes that increase credential exposure, weaken safety boundaries or cannot be reproduced. ProlixoTech Inc. retains final merge and release approval; submitting a PR never automatically changes the Marketplace release.

**For users:** [Getting Started](docs/GETTING-STARTED.md) · [FAQ](docs/FAQ.md) · [Security Model](docs/SECURITY-MODEL.md)

