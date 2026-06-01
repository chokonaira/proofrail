import assert from 'node:assert/strict';
import test from 'node:test';

import { createPermitRailKeyPair } from '@permitrail/core';
import type { PermitRailPolicy } from '@permitrail/core';
import { MCP_TOOL_DEFINITIONS, PermitRailGateway, createPermitRailMcpTools } from '../src/index.ts';
import { LocalApprovalProvider } from '@permitrail/provider-local';

const policy = {
  version: 'permitrail.policy.v1',
  id: 'gateway-security',
  defaults: { unconfiguredTool: 'deny' },
  tools: {
    'email.send': {
      id: 'email-send',
      require: { claim: 'human.approved_action', value: true, assurance: ['human_approved'], bindActionInputHash: true },
    },
  },
} satisfies PermitRailPolicy;

const action = { tool: 'email.send', audience: 'agent', subject: 'u', purpose: 'send', input: { to: 'x@y.z' } };

async function buildMcp() {
  const provider = await LocalApprovalProvider.create();
  const receiptKeyPair = await createPermitRailKeyPair({ kid: 'gw-sec' });
  const gateway = new PermitRailGateway({ policy, provider, trustedProofKeys: [provider.publicKeyPem], receiptKeyPair });
  return { provider, mcp: createPermitRailMcpTools({ gateway, provider }) };
}

test('the receipt-forging write_receipt tool is not exposed over MCP', async () => {
  const { mcp } = await buildMcp();
  assert.ok(!MCP_TOOL_DEFINITIONS.some((tool) => tool.name === ('permitrail_write_receipt' as never)));
  await assert.rejects(() => mcp.callTool('permitrail_write_receipt' as never, {}), /Unknown/);
});

test('MCP authorization is single-use: the same proof cannot authorize twice', async () => {
  const { provider, mcp } = await buildMcp();

  const pending = (await mcp.callTool('permitrail_authorize_tool_call', { action })) as {
    outcome: string;
    challenge?: { id: string };
  };
  assert.equal(pending.outcome, 'require_proof');
  const proof = await provider.approve(pending.challenge!.id, { approvedBy: 'u' });

  const allow = (await mcp.callTool('permitrail_authorize_tool_call', { action, proofEnvelope: proof })) as {
    outcome: string;
  };
  assert.equal(allow.outcome, 'allow');

  const replay = (await mcp.callTool('permitrail_authorize_tool_call', { action, proofEnvelope: proof })) as {
    outcome: string;
    reason: string;
  };
  assert.equal(replay.outcome, 'deny');
  assert.match(replay.reason, /replay/i);
});
