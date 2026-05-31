# Threat Model

PermitRail protects risky agent tool calls from running without appropriate proof.

## Assets

- external system access
- user approval intent
- private data
- money movement
- signed action receipts
- policy configuration
- provider signing keys

## Main Threats

### Prompt Injection

An untrusted email, webpage, document, or chat message instructs the agent to
perform an unsafe action.

Mitigation:

- risky tools require proofs
- approval surfaces show source, target, and exact purpose
- action input hash binds proof to parameters
- receipts record what was allowed or blocked

### Excessive Agency

An agent has more ability than it needs, such as deleting rows or spending money
without approval.

Mitigation:

- default deny
- per-tool policy
- short proof TTL
- risk-based approval rules

### Proof Replay

A proof issued for one action is reused for a different action.

Mitigation:

- purpose binding
- audience binding
- subject binding
- expiration
- nonce
- optional action input hash

### Confused Deputy

An agent uses a valid proof for the wrong system or user.

Mitigation:

- `audience` must match the receiving agent or system
- `subject` must match the user or actor
- policy verifies both fields

### Log Leakage

Receipts or logs accidentally store secrets or raw personal data.

Mitigation:

- receipts store input hashes, not raw high-risk inputs where possible
- providers should avoid raw identity document storage
- logs should redact access tokens, passwords, API keys, and personal data

### Provider Compromise

A provider signing key is compromised.

Mitigation:

- provider public keys are explicit trust inputs
- key rotation must be supported before production use
- receipts preserve issuer key id
- production deployments should monitor unexpected proof volume

## Out Of Scope

PermitRail does not:

- validate every downstream tool input
- replace application authorization
- guarantee provider truthfulness
- stop all prompt injection
- replace secure secrets management

It provides a policy and proof gate. Applications still need normal security.
