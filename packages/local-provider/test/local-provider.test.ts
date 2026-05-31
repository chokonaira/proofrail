import assert from 'node:assert/strict';
import test from 'node:test';

import { verifyActionReceipt, verifyProof } from '@permitrail/core';
import { LocalApprovalProvider } from '../src/index.ts';

test('local provider approves proof challenge', async () => {
  const provider = new LocalApprovalProvider();
  const challenge = await provider.requestProof({
    claim: 'human.approved_action',
    subject: 'user_1',
    audience: 'agent',
    purpose: 'Send email',
  });

  const proof = await provider.approve(challenge.id);
  const payload = verifyProof(proof, {
    publicKeyPem: provider.publicKeyPem,
    audience: 'agent',
    subject: 'user_1',
    purpose: 'Send email',
  });

  assert.equal(payload.claim, 'human.approved_action');
});

test('local provider denial creates receipt', async () => {
  const provider = new LocalApprovalProvider();
  const challenge = await provider.requestProof({
    claim: 'human.approved_action',
    subject: 'user_1',
    audience: 'agent',
    purpose: 'Send email',
    metadata: { tool: 'email.send', policyId: 'email-rule' },
  });

  const receipt = await provider.deny(challenge.id, { reason: 'Looks suspicious' });
  const payload = verifyActionReceipt(receipt, { publicKeyPem: provider.publicKeyPem });

  assert.equal(payload.decision, 'denied');
  assert.equal(payload.reason, 'Looks suspicious');
});
