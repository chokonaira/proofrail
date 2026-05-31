import assert from 'node:assert/strict';
import test from 'node:test';

import { createProofrailKeyPair } from '@proofrail/core';
import type { ProofrailPolicy } from '@proofrail/core';
import { ProofrailGateway } from '@proofrail/mcp-gateway';
import { LocalApprovalProvider } from '@proofrail/provider-local';

import { createProofrailRpcHandler } from '../src/index.ts';

const policy = {
  version: 'proofrail.policy.v1',
  id: 'mcp-test',
  defaults: { unconfiguredTool: 'deny' },
  tools: {
    'email.send': {
      id: 'email-send',
      require: {
        claim: 'human.approved_action',
        value: true,
        assurance: ['human_approved'],
        bindActionInputHash: true,
      },
    },
  },
} satisfies ProofrailPolicy;

const emailAction = {
  tool: 'email.send',
  audience: 'sales-agent',
  subject: 'user_1',
  purpose: 'Send invoice INV-1',
  input: { to: 'client@example.com' },
};

async function buildHandler() {
  const provider = await LocalApprovalProvider.create();
  const receiptKeyPair = await createProofrailKeyPair({ kid: 'mcp-test' });
  const gateway = new ProofrailGateway({
    policy,
    provider,
    trustedProofKeys: [provider.publicKeyPem],
    receiptKeyPair,
  });
  return createProofrailRpcHandler({ gateway, provider, devApproval: true });
}

test('initialize returns protocol version and server info', async () => {
  const handler = await buildHandler();
  const result = (await handler('initialize', { protocolVersion: '2025-06-18' })) as {
    protocolVersion: string;
    serverInfo: { name: string };
    capabilities: { tools: unknown };
  };
  assert.equal(result.protocolVersion, '2025-06-18');
  assert.equal(result.serverInfo.name, 'proofrail');
  assert.ok(result.capabilities.tools);
});

test('tools/list exposes the proofrail tools', async () => {
  const handler = await buildHandler();
  const result = (await handler('tools/list', {})) as { tools: { name: string }[] };
  const names = result.tools.map((tool) => tool.name);
  assert.ok(names.includes('proofrail_authorize_tool_call'));
  assert.ok(names.includes('proofrail_write_receipt'));
  assert.ok(names.includes('proofrail_approve_challenge'));
});

test('tools/call authorize then approve completes the loop over MCP', async () => {
  const handler = await buildHandler();

  const authorize = (await handler('tools/call', {
    name: 'proofrail_authorize_tool_call',
    arguments: { action: emailAction },
  })) as { content: { text: string }[]; isError?: boolean };
  assert.ok(!authorize.isError);
  const decision = JSON.parse(authorize.content[0]!.text) as { outcome: string; challenge?: { id: string } };
  assert.equal(decision.outcome, 'require_proof');
  assert.ok(decision.challenge?.id);

  const approve = (await handler('tools/call', {
    name: 'proofrail_approve_challenge',
    arguments: { challengeId: decision.challenge!.id, approvedBy: 'tester' },
  })) as { content: { text: string }[]; isError?: boolean };
  assert.ok(!approve.isError);
  const proof = JSON.parse(approve.content[0]!.text) as { payload: { kind: string } };
  assert.equal(proof.payload.kind, 'proofrail.proof.v1');
});

test('unknown methods return a JSON-RPC method-not-found error', async () => {
  const handler = await buildHandler();
  await assert.rejects(() => Promise.resolve(handler('resources/list', {})), /Method not found/);
});
