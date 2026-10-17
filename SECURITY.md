# Security Policy

AEGIS handles operations around important developer files. We appreciate responsible vulnerability disclosure and treat reports about unintended file changes, unsafe command handoff, snapshot corruption, credential leakage, and authorization bypass as security-relevant.

## Reporting a vulnerability

Please report sensitive findings privately to **mathew.lee@prolixotech.com**, with the subject line **`AEGIS security report`**.

Once enabled for the public repository, GitHub private vulnerability reporting may also be used. Do not assume that the feature is active before checking the repository's Security page.

Include the affected version or commit, platform, concise reproduction steps, actual and expected behavior, and a redacted minimal reproduction. **Never email actual credentials or attach real `.env` data, complete local snapshots, private keys, or customer information.**

We will review reports and coordinate reasonable next steps; specific response or fix-time guarantees have not been established. Please allow time to assess impact before public disclosure.

## Public release status

**AEGIS Trust 0.1.0** is publicly available on the VS Code Marketplace. This is an initial release; publication does not imply an independent security audit or guaranteed protection across every workflow or platform. No fixed support period or security response-time commitment has been established.

## Important limits

- AEGIS-controlled execution paths are not equivalent to system-wide process isolation.
- AEGIS cannot guarantee that ordinary terminals or arbitrary external agents cannot modify files.
- Local snapshots can reproduce sensitive content and require appropriate storage controls.
- No claim is made that the project has completed an independent security audit.
