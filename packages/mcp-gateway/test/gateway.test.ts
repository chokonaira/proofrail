import assert from 'node:assert/strict';
import test from 'node:test';

import { PermitRailGateway, InMemoryAuditLog, createPermitRailMcpTools } from '../src/index.ts';
import { LocalApprovalProvider } from '@permitrail/provider-local';
import { createPermitRailKeyPair, verifyActionReceipt } from '@permitrail/core';
import type { PermitRailPolicy } from '@permitrail/core';
import type { AuditSink } from '../src/index.ts';

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

const deleteAction = {
  tool: 'database.delete_rows',
  audience: 'db-agent',
  subject: 'admin_1',
  purpose: 'Delete expired sandbox rows',
  input: { table: 'sandbox_events', where: { expired: true } },
};

async function buildGateway(auditSink?: AuditSink) {
  const provider = await LocalApprovalProvider.create();
  const receiptKeyPair = await createPermitRailKeyPair({ kid: 'gateway-test-receipts' });
  const gateway = new PermitRailGateway({
    policy,
    provider,
    trustedProofKeys: [provider.publicKeyPem],
    receiptKeyPair,
    auditSink,
  });
  return { provider, gateway, receiptKeyPair };
}

test('gateway requires a receipt key pair', () => {
  // @ts-expect-error receiptKeyPair is required
  assert.throws(() => new PermitRailGateway({ policy }), /receiptKeyPair/);
});

test('gateway returns proof challenge when tool call is not authorized yet', async () => {
  const { gateway } = await buildGateway();

  const decision = await gateway.authorize(deleteAction);

  assert.equal(decision.outcome, 'require_proof');
  if (decision.outcome !== 'require_proof' || !decision.challenge) {
    throw new Error('Expected proof challenge');
  }
  assert.ok(decision.challenge.id);
});

test('gateway executes a tool only after a bound proof and writes a receipt', async () => {
  const { provider, gateway } = await buildGateway();

  const pending = await gateway.authorize(deleteAction);
  if (pending.outcome !== 'require_proof' || !pending.challenge) {
    throw new Error('Expected proof challenge');
  }

  const proofEnvelope = await provider.approve(pending.challenge.id, { approvedBy: 'admin_1' });

  let ran = false;
  const result = await gateway.execute(
    deleteAction,
    () => {
      ran = true;
      return { deleted: 3 };
    },
    { proofEnvelope },
  );

  assert.equal(result.ok, true);
  assert.equal(ran, true);
  assert.equal(result.receipt.payload.decision, 'allowed');
  assert.ok(result.receipt.payload.inputHash);
});

test('a proof is single-use: replaying it for the same action is blocked', async () => {
  const { provider, gateway } = await buildGateway();

  const pending = await gateway.authorize(deleteAction);
  if (pending.outcome !== 'require_proof' || !pending.challenge) {
    throw new Error('Expected proof challenge');
  }
  const proofEnvelope = await provider.approve(pending.challenge.id, { approvedBy: 'admin_1' });

  let runs = 0;
  const handler = () => {
    runs += 1;
    return { deleted: 3 };
  };

  const first = await gateway.execute(deleteAction, handler, { proofEnvelope });
  const second = await gateway.execute(deleteAction, handler, { proofEnvelope });

  assert.equal(first.ok, true);
  assert.equal(second.ok, false);
  assert.equal(runs, 1, 'the tool must run exactly once');
  assert.equal(second.receipt.payload.decision, 'denied');
  assert.match(second.receipt.payload.reason ?? '', /replay/i);
});

test('every execution receipt reaches the audit sink and verifies', async () => {
  const auditLog = new InMemoryAuditLog();
  const { provider, gateway, receiptKeyPair } = await buildGateway(auditLog);

  const pending = await gateway.authorize(deleteAction);
  if (pending.outcome !== 'require_proof' || !pending.challenge) {
    throw new Error('Expected proof challenge');
  }
  const proofEnvelope = await provider.approve(pending.challenge.id, { approvedBy: 'admin_1' });
  await gateway.execute(deleteAction, () => ({ deleted: 3 }), { proofEnvelope });

  assert.equal(auditLog.receipts.length, 1);
  const recorded = auditLog.receipts[0];
  assert.ok(recorded);
  const payload = await verifyActionReceipt(recorded, { publicKeyPem: receiptKeyPair.publicKeyPem });
  assert.equal(payload.decision, 'allowed');
});

test('mcp tools authorize calls and expose challenge status', async () => {
  const { provider, gateway } = await buildGateway();
  const mcp = createPermitRailMcpTools({ gateway, provider });

  const decision = await mcp.callTool('permitrail_authorize_tool_call', { action: deleteAction });

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
