# Roadmap

## Shipped

- Signed proof envelopes and purpose-bound action receipts
- Policy evaluator with default deny and per-tool rules
- Single-use proofs (replay guard) and a pluggable audit sink
- Isomorphic Web Crypto core (Node, browsers, Deno, Bun, edge), zero dependencies
- Multi-agent chain correlation (chainId and parentId on signed receipts)
- Local approval provider
- Runnable stdio MCP server (`@permitrail/mcp`)
- Installable packages with ESM and type declarations
- Live in-browser sandbox

## Next

- Provider adapters: passkey and WebAuthn, email one-time code, OAuth, Slack, GitHub review, custom webhook
- Key rotation helpers and receipt export
- OpenTelemetry audit sink
- Policy test runner and a prompt-injection demo suite

## Later

- Identity verification adapters (for example Persona or Stripe Identity)
- Verifiable credential provider adapters
- HTTP sidecar for non-JavaScript stacks
- Hosted approval service
