# Architecture

PermitRail is a small runtime layer for proof-gated agent actions.

```txt
          untrusted context
        email / page / PDF
                |
                v
AI Agent -> PermitRail Gateway -> Tool Adapter -> External System
                |
                v
        Proof Provider
        local / OAuth / passkey / IDV / wallet
```

## Components

### Core

`packages/core` owns primitives that should remain portable:

- canonical JSON
- Ed25519 signed envelopes
- proof creation and verification
- action receipts
- policy evaluation

### Gateway

`packages/mcp-gateway` mediates tool calls. It accepts an action, checks policy,
verifies proof if present, and either:

- allows execution
- denies execution
- returns a proof challenge

### Provider

`packages/local-provider` is the first proof provider. It lets demos and
internal tools request local human approval.

Future providers can implement the same shape:

- email OTP
- GitHub org membership
- Google or Microsoft OAuth
- passkeys
- Stripe Identity
- OpenID4VP / EUDI
- WalletGate

## Data Flow

1. The agent proposes a tool call.
2. The gateway turns it into an `action`.
3. The gateway resolves the policy rule for `action.tool`.
4. If proof is required and missing, the gateway creates a proof challenge.
5. A provider approves or denies the challenge.
6. If approved, the provider signs a proof envelope.
7. The agent retries the tool call with the proof.
8. The gateway verifies the proof and action binding.
9. The tool call runs only if the proof satisfies policy.
10. The gateway signs an action receipt.

## Design Principles

- Default deny for unknown tools.
- Purpose binding is mandatory for sensitive actions.
- Action input hashes prevent proof replay against changed parameters.
- Providers are pluggable and replaceable.
- Proofs carry claims, not raw identity documents.
- Receipts are signed and safe to store.
