import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createActionReceipt,
  createPermitRailKeyPair,
  createProof,
  verifyActionReceipt,
  verifyProof,
} from '../src/index.ts';

test('createProof signs and verifies purpose-bound proof', () => {
  const keys = createPermitRailKeyPair({ kid: 'test-key' });
  const proof = createProof(
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

  const payload = verifyProof(proof, {
    publicKeyPem: keys.publicKeyPem,
    audience: 'email-agent',
    subject: 'user_1',
    purpose: 'Send invoice INV-1',
    claim: 'human.approved_action',
  });

  assert.equal(payload.value, true);
  assert.equal(payload.assurance, 'human_approved');
});

test('verifyProof rejects expired proof', () => {
  const keys = createPermitRailKeyPair({ kid: 'test-key' });
  const issued = new Date('2026-01-01T00:00:00Z');
  const proof = createProof(
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

  assert.throws(
    () =>
      verifyProof(proof, {
        publicKeyPem: keys.publicKeyPem,
        now: new Date('2026-01-01T00:00:02Z'),
      }),
    /expired/,
  );
});

test('action receipts include input hashes', () => {
  const keys = createPermitRailKeyPair({ kid: 'receipt-key' });
  const receipt = createActionReceipt(
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

  const payload = verifyActionReceipt(receipt, { publicKeyPem: keys.publicKeyPem });
  assert.equal(payload.kind, 'permitrail.action_receipt.v1');
  assert.ok(payload.inputHash);
  assert.match(payload.inputHash, /^sha256:/);
});
