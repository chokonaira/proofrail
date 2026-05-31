#!/usr/bin/env node
import { loadServerFromEnv } from './config.ts';
import { createProofrailRpcHandler } from './server.ts';
import { runStdioServer } from './jsonrpc.ts';

const { gateway, provider } = await loadServerFromEnv();
const handler = createProofrailRpcHandler({
  gateway,
  provider,
  devApproval: true,
  name: 'proofrail',
  version: '0.1.0',
});

process.stderr.write('[proofrail] MCP server ready on stdio.\n');
runStdioServer(handler);
