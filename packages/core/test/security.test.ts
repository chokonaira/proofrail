import assert from 'node:assert/strict';
import test from 'node:test';

import { createPermitRailKeyPair, createProof, evaluatePolicy, stableStringify, verifyProof } from '../src/index.ts';
import type { AgentAction, PermitRailPolicy } from '../src/index.ts';

test('canonical JSON rejects prototype-pollution keys', () => {
  assert.throws(() => stableStringify(JSON.parse('{"__proto__":{"x":1}}')), /unsafe object key/i);
  assert.throws(() => stableStringify({ constructor: 1 }), /unsafe object key/i);
  assert.throws(() => stableStringify({ prototype: {} }), /unsafe object key/i);
});

test('verifyProof rejects a future-dated proof so maxAge cannot be bypassed', async () => {
  const keys = await createPermitRailKeyPair();
  const future = new Date(Date.now() + 10 * 60 * 1000);
  const proof = await createProof(
    { claim: 'c', subject: 's', audience: 'a', purpose: 'p', provider: 'local', now: future, ttlSeconds: 600 },
    keys,
  );
  await assert.rejects(() => verifyProof(proof, { publicKeyPem: keys.publicKeyPem }), /future/i);
});

const policy = {
  version: 'permitrail.policy.v1',
  id: 'sec',
  defaults: { unconfiguredTool: 'deny' },
  tools: {
    'payments.create_transfer': {
      id: 'pay',
      require: { claim: 'human.approved_action', value: true, assurance: ['human_approved'], bindActionInputHash: true },
    },
  },
} satisfies PermitRailPolicy;

test('a proof minted for a different tool cannot satisfy the policy', async () => {
  const keys = await createPermitRailKeyPair();
  const benign = {
    tool: 'email.send',
    audience: 'agent',
    subject: 'u',
    purpose: 'same purpose',
    input: { x: 1 },
  } satisfies AgentAction;
  const proof = await createProof(
    { claim: 'human.approved_action', subject: 'u', audience: 'agent', purpose: 'same purpose', provider: 'local', action: benign },
    keys,
  );

  const dangerous = { ...benign, tool: 'payments.create_transfer' };
  const result = await evaluatePolicy(policy, dangerous, proof, { publicKeyPem: keys.publicKeyPem });
  assert.equal(result.outcome, 'deny');
  assert.match(result.reason, /different tool/i);
});

test('bindActionInputHash binds a no-input action by tuple and rejects added input', async () => {
  const keys = await createPermitRailKeyPair();
  const noInputPolicy = {
    version: 'permitrail.policy.v1',
    id: 'ni',
    defaults: { unconfiguredTool: 'deny' },
    tools: {
      'db.flush': {
        id: 'flush',
        require: { claim: 'admin.ok', value: true, assurance: ['human_approved'], bindActionInputHash: true },
      },
    },
  } satisfies PermitRailPolicy;

  const action = { tool: 'db.flush', audience: 'agent', subject: 'admin', purpose: 'flush' } satisfies AgentAction;
  const proof = await createProof(
    { claim: 'admin.ok', subject: 'admin', audience: 'agent', purpose: 'flush', provider: 'local', action },
    keys,
  );

  const ok = await evaluatePolicy(noInputPolicy, action, proof, { publicKeyPem: keys.publicKeyPem });
  assert.equal(ok.outcome, 'allow');

  const tampered = { ...action, input: { danger: true } };
  const denied = await evaluatePolicy(noInputPolicy, tampered, proof, { publicKeyPem: keys.publicKeyPem });
  assert.equal(denied.outcome, 'deny');
});
