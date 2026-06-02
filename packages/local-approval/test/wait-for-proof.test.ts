import assert from 'node:assert/strict';
import test from 'node:test';

import { LocalApprovalProvider } from '@permitrail/provider-local';
import { waitForProof } from '../src/wait-for-proof.ts';

async function pendingChallenge(provider: LocalApprovalProvider) {
  return provider.requestProof({
    claim: 'human.approved_action',
    subject: 'user_1',
    audience: 'agent',
    purpose: 'Send email',
  });
}

test('waitForProof resolves with the signed proof after approval', async () => {
  const provider = await LocalApprovalProvider.create();
  const challenge = await pendingChallenge(provider);
  setTimeout(() => provider.approve(challenge.id, { approvedBy: 'tester' }), 50);

  const proof = await waitForProof(provider, challenge.id, { pollMs: 20 });
  assert.equal(proof.payload.kind, 'permitrail.proof.v1');
});

test('waitForProof rejects after a denial', async () => {
  const provider = await LocalApprovalProvider.create();
  const challenge = await pendingChallenge(provider);
  setTimeout(() => provider.deny(challenge.id, { reason: 'nope' }), 50);

  await assert.rejects(() => waitForProof(provider, challenge.id, { pollMs: 20 }), /nope/);
});

test('waitForProof rejects on timeout when nobody decides', async () => {
  const provider = await LocalApprovalProvider.create();
  const challenge = await pendingChallenge(provider);

  await assert.rejects(
    () => waitForProof(provider, challenge.id, { pollMs: 20, timeoutMs: 80 }),
    /Timed out/,
  );
});
