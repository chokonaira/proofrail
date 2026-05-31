# PermitRail

[![CI](https://github.com/chokonaira/permitrail/actions/workflows/test.yml/badge.svg)](https://github.com/chokonaira/permitrail/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](tsconfig.json)

**Proof-gated tool calls for AI agents.**

PermitRail is an open-source permission layer for agents that use tools. It
sits between the agent and sensitive actions, requires a short-lived
purpose-bound proof when policy says approval is needed, then writes a signed
receipt for the audit trail.

[Hosted sandbox](https://chokonaira.github.io/permitrail/) ·
[Integration guide](docs/integration.md) ·
[Protocol schema](spec/permitrail.schema.json)

```txt
Agent -> PermitRail -> email.send / payments.create_transfer / github.merge_pr / database.delete_rows
```

## Why

Agents are starting to send messages, change data, open pull requests, and move
money. The hard question is no longer only "can the model call the tool?" It is:

- was this exact action approved?
- was the approval bound to the same subject, audience, purpose, and input?
- can a proof be replayed against a different recipient, amount, branch, or row?
- can the team audit what happened after the agent acted?

PermitRail gives developers a small, inspectable control point for those
questions.

## What It Provides

- TypeScript-first SDK with strict public types
- policy-gated tool-call authorization
- purpose-bound proof requests
- Ed25519 signed proof envelopes
- action input hashing to block replay
- signed action receipts
- local approval provider for demos and internal tools
- MCP-ready tool definitions and router
- language-agnostic JSON protocol for other stacks

## Run It

Requirements:

- Node 24+
- npm

```bash
git clone https://github.com/chokonaira/permitrail.git
cd permitrail
npm install
npm run check
```

The demo flow blocks a suspicious payment, records the denial, requests approval
for a legitimate email, verifies the proof, runs the tool, and writes a signed
receipt.

```bash
npm run demo
```

## Use In TypeScript

```ts
import type { AgentAction, PermitRailPolicy } from '@permitrail/core';
import { LocalApprovalProvider } from '@permitrail/provider-local';
import { PermitRailGateway } from '@permitrail/mcp-gateway';

const provider = new LocalApprovalProvider();

const policy = {
  version: 'permitrail.policy.v1',
  id: 'agent-policy',
  defaults: { unconfiguredTool: 'deny' },
  tools: {
    'email.send': {
      id: 'email-send-human-approval',
      require: {
        claim: 'human.approved_action',
        value: true,
        assurance: ['human_approved'],
        maxAgeSeconds: 300,
        bindActionInputHash: true,
      },
    },
  },
} satisfies PermitRailPolicy;

const gateway = new PermitRailGateway({
  policy,
  provider,
  trustedProofKeys: [provider.publicKeyPem],
});

const action = {
  tool: 'email.send',
  audience: 'sales-agent',
  subject: 'user_123',
  purpose: 'Send invoice INV-123 to client@example.com',
  input: {
    to: 'client@example.com',
    subject: 'Invoice INV-123',
  },
} satisfies AgentAction;

const decision = await gateway.authorize(action);

if (decision.outcome === 'require_proof') {
  if (!decision.challenge) {
    throw new Error('PermitRail did not return an approval challenge');
  }

  const proof = await provider.approve(decision.challenge.id);
  const result = await gateway.execute(action, sendEmail, { proofEnvelope: proof });
  console.log(result.receipt.payload.id);
}
```

## Plug Into MCP

PermitRail exposes MCP-ready tool definitions without forcing a specific MCP
server package. Register the tools with your server, then route tool calls
through PermitRail before the agent reaches sensitive adapters.

```ts
import { createPermitRailMcpTools } from '@permitrail/mcp-gateway';

const permitrail = createPermitRailMcpTools({ gateway, provider });

for (const tool of permitrail.tools) {
  server.registerTool(tool.name, {
    description: tool.description,
    inputSchema: tool.inputSchema,
  }, async (input) => permitrail.callTool(tool.name, input));
}
```

Core MCP tools:

- `permitrail_authorize_tool_call`
- `permitrail_get_challenge`
- `permitrail_verify_proof`
- `permitrail_write_receipt`

## Approval Providers

Proofs come from providers. The first provider is local approval, which is
useful for demos, tests, and internal workflows. Future providers can wrap:

- passkeys
- email magic links
- Slack or Teams approvals
- GitHub review approvals
- OAuth account control
- credential wallets
- identity verification providers

Applications do not need to change policy logic when providers change. Every
provider issues the same proof envelope.

## Other Stacks

PermitRail starts with a TypeScript SDK, but the protocol is portable:

- policies are JSON
- proofs are signed JSON envelopes
- receipts are signed JSON envelopes
- tool input binding uses canonical JSON plus SHA-256

Java, Go, Python, Ruby, Rust, and .NET services can integrate through an HTTP
sidecar or implement the protocol directly from the schema.

See [docs/integration.md](docs/integration.md) for the integration paths.

## Project Status

Pre-1.0 alpha. The proof format, policy model, and MCP surface are intentionally
small so they can be reviewed, tested, and extended without hiding behavior
behind a large framework.

## License

Apache-2.0. See [LICENSE](LICENSE).
