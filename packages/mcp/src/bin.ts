#!/usr/bin/env node
import { loadServerFromEnv } from './config.ts';
import { createPermitRailRpcHandler } from './server.ts';
import { runStdioServer } from './jsonrpc.ts';

const { gateway, provider } = await loadServerFromEnv();

// Self-approval is OFF by default. The permitrail_approve_challenge tool lets a
// caller approve its own action, which is only acceptable for local testing.
const devApproval =
  process.env.PERMITRAIL_DEV_APPROVAL === '1' || process.env.PERMITRAIL_DEV_APPROVAL === 'true';
if (devApproval) {
  process.stderr.write(
    '[permitrail] WARNING: PERMITRAIL_DEV_APPROVAL is on. permitrail_approve_challenge lets the caller approve its own actions. Local development only, never production.\n',
  );
}

const handler = createPermitRailRpcHandler({
  gateway,
  provider,
  devApproval,
  name: 'permitrail',
  version: '0.1.0',
});

process.stderr.write('[permitrail] MCP server ready on stdio.\n');
runStdioServer(handler);
