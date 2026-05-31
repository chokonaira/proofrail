import assert from 'node:assert/strict';
import test from 'node:test';

import { createPermitRailKeyPair, createProof, evaluatePolicy } from '../src/index.ts';
import type { AgentAction, PermitRailPolicy } from '../src/index.ts';

const policy = {
  version: 'permitrail.policy.v1',
  id: 'test-policy',
  defaults: { unconfiguredTool: 'deny' },
  tools: {
    'email.send': {
      id: 'email-rule',
      require: {
        claim: 'human.approved_action',
        value: true,
        assurance: ['human_approved'],
        bindActionInputHash: true,
      },
    },
  },
} satisfies PermitRailPolicy;

const action = {
  tool: 'email.send',
  audience: 'email-agent',
  subject: 'user_1',
  purpose: 'Send invoice INV-1',
  input: { to: 'client@example.com' },
} satisfies AgentAction<{ to: string }>;

test('policy requires proof when rule has proof requirement', () => {
  const result = evaluatePolicy(policy, action);
  assert.equal(result.outcome, 'require_proof');
  assert.equal(result.allowed, false);
  assert.equal(result.requiredProof.claim, 'human.approved_action');
});

test('policy allows action when proof is bound to exact input', () => {
  const keys = createPermitRailKeyPair({ kid: 'policy-key' });
  const proof = createProof(
    {
      claim: 'human.approved_action',
      subject: action.subject,
      audience: action.audience,
      purpose: action.purpose,
      provider: 'permitrail-local',
      action,
    },
    keys,
  );

  const result = evaluatePolicy(policy, action, proof, { publicKeyPem: keys.publicKeyPem });
  assert.equal(result.outcome, 'allow');
  assert.equal(result.allowed, true);
});

test('policy denies action when proof is replayed with different input', () => {
  const keys = createPermitRailKeyPair({ kid: 'policy-key' });
  const proof = createProof(
    {
      claim: 'human.approved_action',
      subject: action.subject,
      audience: action.audience,
      purpose: action.purpose,
      provider: 'permitrail-local',
      action,
    },
    keys,
  );

  const tamperedAction = {
    ...action,
    input: { to: 'attacker@example.com' },
  };

  const result = evaluatePolicy(policy, tamperedAction, proof, {
    publicKeyPem: keys.publicKeyPem,
  });

  assert.equal(result.outcome, 'deny');
  assert.match(result.reason, /input/);
});
