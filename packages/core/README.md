# @permitrail/core

Core proof, policy, and receipt primitives for PermitRail.

PermitRail is an authorization, proof, and audit layer for AI agent tool calls.
This package contains the portable protocol pieces: canonical JSON, Ed25519
envelopes, policy evaluation, proof creation and verification, and signed action
receipts.

## Install

```bash
npm install @permitrail/core
```

## Use

```ts
import {
  createPermitRailKeyPair,
  createProof,
  evaluatePolicy,
  verifyProof,
} from '@permitrail/core';
```

Use `@permitrail/mcp-gateway` when you want a ready-made enforcement gateway for
tool calls. Use this package directly when another runtime or language boundary
needs to verify PermitRail proofs and receipts.

## Links

- Repository: https://github.com/chokonaira/permitrail
- Sandbox: https://chokonaira.github.io/permitrail/
- Threat model: https://github.com/chokonaira/permitrail/blob/main/docs/threat-model.md
- Protocol schema: https://github.com/chokonaira/permitrail/blob/main/spec/permitrail.schema.json

## License

Apache-2.0
