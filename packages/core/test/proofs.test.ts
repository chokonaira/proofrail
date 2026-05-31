import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createActionReceipt,
  createPermitRailKeyPair,
  createProof,
  verifyActionReceipt,
  verifyProof,
} from '../src/index.ts';

test('createProof signs and verifies purpose-bound proof', async () => {
  const keys = await createPermitRailKeyPair({ kid: 'test-key' });
  const proof = await createProof(
    {
      claim: 'human.approved_action',
      value: true,
      subject: 'user_1',
      audience: 'email-agent',
      purpose: 'Send invoice INV-1',
      provider: 'permitrail-local',
      assurance: 'human_approved',
      ttlSeconds: 60,
    },
    keys,
  );

  const payload = await verifyProof(proof, {
    publicKeyPem: keys.publicKeyPem,
    audience: 'email-agent',
    subject: 'user_1',
    purpose: 'Send invoice INV-1',
    claim: 'human.approved_action',
  });

  assert.equal(payload.value, true);
  assert.equal(payload.assurance, 'human_approved');
});

test('verifyProof rejects a tampered payload', async () => {
  const keys = await createPermitRailKeyPair({ kid: 'test-key' });
  const proof = await createProof(
    {
      claim: 'human.approved_action',
      subject: 'user_1',
      audience: 'email-agent',
      purpose: 'Send invoice INV-1',
      provider: 'permitrail-local',
    },
    keys,
  );

  const tampered = { ...proof, payload: { ...proof.payload, subject: 'attacker' } };

  await assert.rejects(
    () => verifyProof(tampered, { publicKeyPem: keys.publicKeyPem }),
    /signature is invalid/,
  );
});

test('verifyProof rejects expired proof', async () => {
  const keys = await createPermitRailKeyPair({ kid: 'test-key' });
  const issued = new Date('2026-01-01T00:00:00Z');
  const proof = await createProof(
    {
      claim: 'human.approved_action',
      subject: 'user_1',
      audience: 'email-agent',
      purpose: 'Send invoice INV-1',
      provider: 'permitrail-local',
      now: issued,
      ttlSeconds: 1,
    },
    keys,
  );

  await assert.rejects(
    () =>
      verifyProof(proof, {
        publicKeyPem: keys.publicKeyPem,
        now: new Date('2026-01-01T00:00:02Z'),
      }),
    /expired/,
  );
});

test('action receipts include input hashes', async () => {
  const keys = await createPermitRailKeyPair({ kid: 'receipt-key' });
  const receipt = await createActionReceipt(
    {
      action: {
        tool: 'email.send',
        audience: 'email-agent',
        subject: 'user_1',
        purpose: 'Send invoice INV-1',
        input: { to: 'client@example.com' },
      },
      decision: 'allowed',
      reason: 'Proof satisfies policy',
      policyId: 'policy-1',
    },
    keys,
  );

  const payload = await verifyActionReceipt(receipt, { publicKeyPem: keys.publicKeyPem });
  assert.equal(payload.kind, 'permitrail.action_receipt.v1');
  assert.ok(payload.inputHash);
  assert.match(payload.inputHash, /^sha256:/);
});
