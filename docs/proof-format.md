# Proof Format

PermitRail proofs are signed envelopes.

```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "permitrail-local-dev",
    "typ": "permitrail.proof.v1"
  },
  "payload": {
    "kind": "permitrail.proof.v1",
    "id": "proof_...",
    "claim": "human.approved_action",
    "value": true,
    "subject": "user_123",
    "audience": "email-agent",
    "purpose": "Send invoice INV-123 to client@example.com",
    "provider": "permitrail-local",
    "assurance": "human_approved",
    "nonce": "...",
    "issuedAt": "2026-05-31T12:00:00.000Z",
    "expiresAt": "2026-05-31T12:05:00.000Z",
    "actionInputHash": "sha256:..."
  },
  "signature": "..."
}
```

## Required Fields

- `kind`: proof schema version
- `id`: proof id
- `claim`: what is being proven
- `value`: claim value
- `subject`: who the proof is about
- `audience`: which agent or system can use the proof
- `purpose`: exact reason for the proof
- `provider`: issuer of the proof
- `assurance`: how strong the proof is
- `nonce`: replay-resistant random value
- `issuedAt`: issue time
- `expiresAt`: expiration time

## Assurance Levels

PermitRail uses explicit assurance labels instead of pretending all proofs are the
same.

| Level | Meaning |
| --- | --- |
| `self_attested` | User or app made a claim without independent verification |
| `account_controlled` | User controls an account, email, or OAuth identity |
| `human_approved` | Human approved the exact action |
| `provider_verified` | External provider verified the claim |
| `credential_verified` | Cryptographic credential verified the claim |
| `high_assurance` | Certified or regulated high-assurance verification |

## Purpose Binding

Proofs are not reusable blanket permissions. A proof should be valid only for
the exact `purpose` and `audience` it was issued for.

## Action Input Hashing

For sensitive actions, policies can require `bindActionInputHash`. This binds
the proof to the exact tool parameters.

Example:

```json
{
  "tool": "payments.create_transfer",
  "input": {
    "amount": 5000,
    "recipient": "acct_123"
  }
}
```

If the agent changes `amount` or `recipient`, the input hash changes and the old
proof no longer satisfies policy.
