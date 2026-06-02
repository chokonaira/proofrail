import assert from 'node:assert/strict';
import test from 'node:test';

import { createPermitRailKeyPair } from '@permitrail/core';
import { PermitRailGateway } from '@permitrail/mcp-gateway';
import { LocalApprovalProvider } from '@permitrail/provider-local';
import { startApprovalServer } from '../src/server.ts';
import { startLocalApproval } from '../src/index.ts';

async function setup() {
  const provider = await LocalApprovalProvider.create();
  const server = await startApprovalServer({ provider, host: '127.0.0.1', port: 0 });
  return { provider, server, base: server.url };
}

test('pending lists a challenge, approve signs it', async () => {
  const { provider, server, base } = await setup();
  try {
    const challenge = await provider.requestProof({
      claim: 'human.approved_action',
      subject: 'user_1',
      audience: 'agent',
      purpose: 'Send invoice',
      action: {
        tool: 'email.send',
        audience: 'agent',
        subject: 'user_1',
        purpose: 'Send invoice',
        input: { to: 'a@b.com' },
      },
    });

    const pending = (await (await fetch(base + '/api/pending')).json()) as Array<{ tool: string }>;
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.tool, 'email.send');

    const res = await fetch(base + '/api/approve/' + challenge.id, { method: 'POST' });
    assert.equal(((await res.json()) as { ok: boolean }).ok, true);

    const status = (await (await fetch(base + '/api/challenge/' + challenge.id)).json()) as {
      status: string;
    };
    assert.equal(status.status, 'approved');
  } finally {
    await server.stop();
  }
});

test('serves the approval page at /', async () => {
  const { server, base } = await setup();
  try {
    const res = await fetch(base + '/');
    assert.equal(res.status, 200);
    assert.match(await res.text(), /PermitRail local approval/);
  } finally {
    await server.stop();
  }
});

test('end to end: authorize, approve via API, waitForProof, execute once, replay refused', async () => {
  const approval = await startLocalApproval({ port: 0 });
  try {
    const policy = {
      version: 'permitrail.policy.v1',
      id: 'test',
      defaults: { unconfiguredTool: 'deny' as const },
      tools: {
        'payments.create_transfer': {
          require: {
            claim: 'human.approved_spend',
            value: true,
            assurance: ['human_approved' as const],
            bindActionInputHash: true,
          },
        },
      },
    };
    const gateway = new PermitRailGateway({
      policy,
      provider: approval.provider,
      trustedProofKeys: [approval.publicKeyPem],
      receiptKeyPair: await createPermitRailKeyPair({ kid: 'test-receipts' }),
    });
    const action = {
      tool: 'payments.create_transfer',
      audience: 'agent',
      subject: 'u1',
      purpose: 'pay',
      input: { amount: 10 },
    };

    const decision = await gateway.authorize(action);
    assert.equal(decision.outcome, 'require_proof');
    if (decision.outcome !== 'require_proof' || !decision.challenge) {
      throw new Error('expected require_proof');
    }

    await fetch(approval.url + '/api/approve/' + decision.challenge.id, { method: 'POST' });
    const proof = await approval.waitForProof(decision.challenge.id, { pollMs: 20 });

    const result = await gateway.execute(action, () => ({ ran: true }), { proofEnvelope: proof });
    assert.equal(result.ok, true);

    const replay = await gateway.execute(action, () => ({ ran: true }), { proofEnvelope: proof });
    assert.equal(replay.ok, false);
  } finally {
    await approval.stop();
  }
});
