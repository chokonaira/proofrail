#!/usr/bin/env node
import { loadServerFromEnv } from './config.ts';
import { createPermitRailRpcHandler } from './server.ts';
import { runStdioServer } from './jsonrpc.ts';

const { gateway, provider } = await loadServerFromEnv();
const handler = createPermitRailRpcHandler({
  gateway,
  provider,
  devApproval: true,
  name: 'permitrail',
  version: '0.1.0',
});

process.stderr.write('[permitrail] MCP server ready on stdio.\n');
runStdioServer(handler);
