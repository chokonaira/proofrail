# Provider Model

Providers issue proofs. PermitRail should stay provider-neutral so it works across
countries, identity systems, and enterprise stacks.

## Provider Interface

A provider needs to support:

- request a proof challenge
- approve or deny the challenge
- return a signed proof or denial receipt
- publish or expose a public key for proof verification

The local provider demonstrates this shape.

## Providers To Build

### Local Approval

Useful immediately for demos, internal tools, and human-in-the-loop workflows.

Assurance: `human_approved`

### Email OTP

Proves control of an email address.

Assurance: `account_controlled`

### GitHub Provider

Proves account control, org membership, team membership, or repository role.

Assurance: `account_controlled` or `provider_verified`

### OAuth Provider

Proves Google, Microsoft, or enterprise identity account control.

Assurance: `account_controlled`

### Passkey Provider

Proves the same returning human or device using WebAuthn.

Assurance: `human_approved` or `provider_verified`

### Identity Verification Provider

Wraps providers like Stripe Identity, Persona, Veriff, or Sumsub.

Assurance: `provider_verified`

### Credential Wallet Provider

Wraps OpenID4VP, EUDI wallets, or other verifiable credential wallets.

Assurance: `credential_verified` or `qualified_trust`

## Provider Neutrality

PermitRail should not become an identity vendor. It should be the control plane
that lets agents consume proofs from many sources without receiving raw
documents or credentials.
