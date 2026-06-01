# @permitrail/provider-local

In-process approval provider for PermitRail demos, tests, and internal tools.

The local provider creates proof challenges, lets trusted code approve or deny
them, and signs PermitRail proofs with its own key pair. It is intentionally
simple and useful for sandboxes and development workflows.

## Install

```bash
npm install @permitrail/provider-local
```

## Use

```ts
import { LocalApprovalProvider } from '@permitrail/provider-local';

const provider = await LocalApprovalProvider.create();
const challenge = await provider.requestProof(request);
const proofEnvelope = await provider.approve(challenge.id);
```

For production approval channels, implement the same `ProofProvider` interface
or use `@permitrail/provider-webhook`.

## Links

- Repository: https://github.com/chokonaira/permitrail
- Approval provider docs: https://github.com/chokonaira/permitrail#approval-providers
- Threat model: https://github.com/chokonaira/permitrail/blob/main/docs/threat-model.md

## License

Apache-2.0
