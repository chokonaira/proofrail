# Integration Guide

PermitRail has three integration paths.

## 1. TypeScript SDK

Use the SDK when your agent runtime or tool gateway runs in TypeScript.

```txt
agent runtime -> PermitRailGateway -> tool adapter
```

Flow:

1. Define a policy for risky tools.
2. Wrap tool execution with `PermitRailGateway`.
3. Call `authorize(action)` before the tool runs.
4. If the result is `require_proof`, send the challenge to a provider.
5. Call `execute(action, handler, { proofEnvelope })`.
6. Store the signed receipt.

The local provider is intentionally simple. It proves the shape of the system
without requiring external accounts.

## 2. MCP Tool Gateway

Use the MCP surface when an agent reaches tools through an MCP server.

PermitRail exposes a dependency-free router:

- tool definitions
- JSON input schemas
- a `callTool` function

Register these tools with your MCP server, then let the agent request
authorization before calling sensitive tools.

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

Recommended runtime pattern:

```txt
Agent
  -> permitrail_authorize_tool_call
  -> approval provider if proof is required
  -> sensitive tool only after PermitRail allows
  -> permitrail_write_receipt
```

## 3. Other Languages

Use this path when your application is written in Java, Go, Python, Ruby, Rust,
or .NET.

The portable contract is:

- policy documents are JSON
- actions are JSON
- proofs are Ed25519-signed JSON envelopes
- action receipts are Ed25519-signed JSON envelopes
- input binding uses canonical JSON plus SHA-256

Two options are planned:

- run PermitRail as an HTTP sidecar
- implement the protocol directly from `spec/permitrail.schema.json`

Planned HTTP sidecar endpoints:

```http
POST /v1/authorize
POST /v1/challenges/{id}/approve
POST /v1/challenges/{id}/deny
POST /v1/proofs/verify
POST /v1/receipts/verify
```

The TypeScript SDK is the reference implementation for v0.x. Other
implementations should match the schema, proof format, receipt format, and test
vectors.

## Proof Providers

A provider is anything that can answer a proof request and sign a proof
envelope.

Examples:

- local approval provider
- passkey approval
- email magic link
- Slack or Teams approval
- GitHub review approval
- credential wallet proof
- identity verification proof

Providers should issue short-lived proofs and bind approvals to the exact
action purpose and input hash whenever a tool can mutate state, communicate
externally, or move money.
