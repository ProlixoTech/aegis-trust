# Contributing to AEGIS

Thank you for helping make AI-assisted development safer. AEGIS is a security-sensitive VS Code extension, so changes must be reviewable, testable, and careful about local user data.

## Before contributing

1. Check existing issues and discussions before proposing large changes.
2. Open an issue describing the problem, expected behavior, and affected AEGIS-controlled workflow.
3. For significant architecture or security-policy changes, obtain maintainer agreement before starting work.
4. Do not attach actual `.env` contents, snapshots, private keys, access tokens, user directories, or unsanitized logs.

## Pull requests

- Keep each pull request narrowly scoped and describe its security and compatibility impact.
- Add or update tests for behavioral changes, including failure paths and rollback or no-mutation expectations.
- Document whether the change touches snapshot integrity, the Protected Terminal, authorization, local storage, or external integrations.
- Do not weaken a fail-closed safety rule merely to make a test pass.
- Keep public documentation, code comments, user-facing messages, and pull-request descriptions in English.
- Include a license/provenance explanation when adding third-party code or assets.

## Local validation

The existing project uses TypeScript and npm scripts including `compile` and `test`. After the public source tree and its package lockfiles are verified, follow the repository's documented install process, then run:

```bash
npm run compile
npm test
```

The public CI configuration and supported Node.js version will be published after clean staging verification. Test results from a private developer tree are not a substitute for clean-checkout verification.

## Reviews and project governance

The maintainers may request corrections or decline a change that increases credential exposure, weakens safety boundaries, or cannot be tested reproducibly. ProlixoTech Inc. administers the project, and maintainers retain final merge and release approval.

## Vulnerabilities

Please **do not** open a public issue describing a new exploitable security vulnerability. Follow [SECURITY.md](SECURITY.md).
