import assert from 'node:assert/strict';
import test from 'node:test';

import { createPermitRailKeyPair } from '@permitrail/core';
import type { PermitRailPolicy } from '@permitrail/core';
import { PermitRailGateway } from '@permitrail/mcp-gateway';
import { LocalApprovalProvider } from '@permitrail/provider-local';

import { createPermitRailRpcHandler } from '../src/index.ts';

const policy = {
  version: 'permitrail.policy.v1',
  id: 'mcp-security',
  defaults: { unconfiguredTool: 'deny' },
  tools: {},
} satisfies PermitRailPolicy;

test('self-approval is off by default: no approve tool, and calling it fails', async () => {
  const provider = await LocalApprovalProvider.create();
  const receiptKeyPair = await createPermitRailKeyPair({ kid: 'mcp-sec' });
  const gateway = new PermitRailGateway({ policy, provider, trustedProofKeys: [provider.publicKeyPem], receiptKeyPair });
  // devApproval omitted, so it must default to off.
  const handler = createPermitRailRpcHandler({ gateway, provider });

  const list = (await handler('tools/list', {})) as { tools: { name: string }[] };
  assert.ok(!list.tools.some((tool) => tool.name === 'permitrail_approve_challenge'));

  const result = (await handler('tools/call', {
    name: 'permitrail_approve_challenge',
    arguments: { challengeId: 'anything' },
  })) as { isError?: boolean; content: { text: string }[] };
  assert.equal(result.isError, true);
});
