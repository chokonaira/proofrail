# @permitrail/mcp-gateway

Policy enforcement gateway for PermitRail agent tool calls.

This package checks a tool call against policy, requests a proof when approval is
required, verifies proof binding, enforces single-use replay protection, executes
the approved handler, and writes a signed receipt.

## Install

```bash
npm install @permitrail/core @permitrail/mcp-gateway
```

## Use

```ts
import { createPermitRailKeyPair } from '@permitrail/core';
import { PermitRailGateway } from '@permitrail/mcp-gateway';

const gateway = new PermitRailGateway({
  policy,
  provider,
  trustedProofKeys: [provider.publicKeyPem],
  receiptKeyPair: await createPermitRailKeyPair(),
});

const decision = await gateway.authorize(action);
```

The gateway can also expose MCP-ready tool definitions through
`createPermitRailMcpTools`.

## Links

- Repository: https://github.com/chokonaira/permitrail
- MCP docs: https://github.com/chokonaira/permitrail/blob/main/docs/mcp.md
- Policy model: https://github.com/chokonaira/permitrail/blob/main/docs/policy.md

## License

Apache-2.0
