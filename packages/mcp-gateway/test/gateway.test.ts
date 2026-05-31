import assert from 'node:assert/strict';
import test from 'node:test';

import { PermitRailGateway, createPermitRailMcpTools } from '../src/index.ts';
import { LocalApprovalProvider } from '@permitrail/provider-local';
import type { PermitRailPolicy } from '@permitrail/core';

const policy = {
  version: 'permitrail.policy.v1',
  id: 'gateway-test',
  tools: {
    'database.delete_rows': {
      id: 'delete-requires-approval',
      require: {
        claim: 'admin.approved_action',
        value: true,
        assurance: ['human_approved'],
        bindActionInputHash: true,
      },
    },
  },
} satisfies PermitRailPolicy;

test('gateway returns proof challenge when tool call is not authorized yet', async () => {
  const provider = new LocalApprovalProvider();
  const gateway = new PermitRailGateway({
    policy,
    provider,
    trustedProofKeys: [provider.publicKeyPem],
  });

  const decision = await gateway.authorize({
    tool: 'database.delete_rows',
    audience: 'db-agent',
    subject: 'admin_1',
    purpose: 'Delete expired sandbox rows',
    input: { table: 'sandbox_events', where: { expired: true } },
  });

  assert.equal(decision.outcome, 'require_proof');
  if (decision.outcome !== 'require_proof' || !decision.challenge) {
    throw new Error('Expected proof challenge');
  }
  assert.ok(decision.challenge.id);
});

test('mcp tools authorize calls and expose challenge status', async () => {
  const provider = new LocalApprovalProvider();
  const gateway = new PermitRailGateway({
    policy,
    provider,
    trustedProofKeys: [provider.publicKeyPem],
  });
  const mcp = createPermitRailMcpTools({ gateway, provider });

  const decision = await mcp.callTool('permitrail_authorize_tool_call', {
    action: {
      tool: 'database.delete_rows',
      audience: 'db-agent',
      subject: 'admin_1',
      purpose: 'Delete expired sandbox rows',
      input: { table: 'sandbox_events', where: { expired: true } },
    },
  });

  assert.equal(typeof decision, 'object');
  assert.ok(decision);
  const authorization = decision as Awaited<ReturnType<PermitRailGateway['authorize']>>;
  assert.equal(authorization.outcome, 'require_proof');
  if (authorization.outcome !== 'require_proof' || !authorization.challenge) {
    throw new Error('Expected proof challenge');
  }

  const challenge = await mcp.callTool('permitrail_get_challenge', {
    challengeId: authorization.challenge.id,
  });

  assert.equal(typeof challenge, 'object');
  assert.ok(challenge);
  assert.equal((challenge as { status: string }).status, 'pending');
});
