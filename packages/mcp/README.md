# @permitrail/mcp

Runnable stdio MCP server for PermitRail.

Use this package when an MCP client should ask PermitRail to authorize AI agent
tool calls, create proof challenges, check challenge status, and verify proofs.
The server does not expose a public receipt-signing tool.

## Install

```bash
npm install @permitrail/mcp
```

## Run

```bash
npx @permitrail/mcp
```

Example MCP client config:

```json
{
  "mcpServers": {
    "permitrail": {
      "command": "npx",
      "args": ["-y", "@permitrail/mcp"]
    }
  }
}
```

Set `PERMITRAIL_POLICY` to a policy JSON file and `PERMITRAIL_RECEIPT_KEY` to a
persisted receipt key file for production.

## Links

- Repository: https://github.com/chokonaira/permitrail
- MCP docs: https://github.com/chokonaira/permitrail/blob/main/docs/mcp.md
- Sandbox: https://chokonaira.github.io/permitrail/

## License

Apache-2.0
