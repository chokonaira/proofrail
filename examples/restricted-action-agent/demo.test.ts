import assert from 'node:assert/strict';
import test from 'node:test';

import { PermitRailGateway } from '@permitrail/mcp-gateway';
import { LocalApprovalProvider } from '@permitrail/provider-local';
import { policy } from './policy.ts';

test('restricted action demo blocks first and allows after proof', async () => {
  const provider = new LocalApprovalProvider();
  const gateway = new PermitRailGateway({
    policy,
    provider,
    trustedProofKeys: [provider.publicKeyPem],
  });

  const action = {
    tool: 'email.send',
    audience: 'sales-agent',
    subject: 'user_1',
    purpose: 'Send invoice INV-1',
    input: { to: 'a@example.com', body: 'invoice' },
  };

  const firstDecision = await gateway.authorize(action);
  assert.equal(firstDecision.outcome, 'require_proof');
  if (firstDecision.outcome !== 'require_proof' || !firstDecision.challenge) {
    throw new Error('Expected proof challenge');
  }
  assert.ok(firstDecision.challenge.id);

  const proof = await provider.approve(firstDecision.challenge.id);
  const execution = await gateway.execute(action, async () => ({ sent: true }), {
    proofEnvelope: proof,
  });

  assert.equal(execution.ok, true);
  assert.equal(execution.receipt.payload.decision, 'allowed');
});
