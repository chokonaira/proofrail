# Security Policy

PermitRail is security-sensitive software. It is designed to sit between AI agents
and tools that can send messages, spend money, mutate data, or access private
systems.

## Supported Versions

Security fixes target the main branch and the most recently published packages.

## Reporting Vulnerabilities

Please do not open public issues for exploitable vulnerabilities.

Report privately through GitHub: open a private advisory from the repository's
Security tab ("Report a vulnerability"), or contact the maintainer through GitHub.

Include:

- affected package and version or commit
- proof of concept or reproduction steps
- expected impact
- suggested fix, if known

## Security Design Principles

- Default deny for unconfigured or risky tool calls.
- Proofs are purpose-bound and short-lived.
- Agents receive signed boolean or scoped claims, not raw identity documents.
- High-risk action inputs are hashed into receipts.
- Replay protection is required for proof challenges.
- Approval screens must show the exact action, target, and risk reason.
- Logs and receipts must avoid secrets and raw personal data.

## Non-Goals

PermitRail does not make unsafe tools safe by itself. It provides a policy and
proof layer. Tool implementers remain responsible for validating inputs,
enforcing authorization, and limiting side effects.
