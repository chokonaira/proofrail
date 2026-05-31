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

test('policy requires proof when rule has proof requirement', async () => {
  const result = await evaluatePolicy(policy, action);
  assert.equal(result.outcome, 'require_proof');
  assert.equal(result.allowed, false);
  if (result.outcome !== 'require_proof') throw new Error('expected require_proof');
  assert.equal(result.requiredProof.claim, 'human.approved_action');
});

test('policy denies unconfigured tools by default', async () => {
  const result = await evaluatePolicy(policy, { ...action, tool: 'unknown.tool' });
  assert.equal(result.outcome, 'deny');
});

test('policy allows action when proof is bound to exact input', async () => {
  const keys = await createPermitRailKeyPair({ kid: 'policy-key' });
  const proof = await createProof(
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

  const result = await evaluatePolicy(policy, action, proof, { publicKeyPem: keys.publicKeyPem });
  assert.equal(result.outcome, 'allow');
  assert.equal(result.allowed, true);
});

test('policy denies action when proof is replayed with different input', async () => {
  const keys = await createPermitRailKeyPair({ kid: 'policy-key' });
  const proof = await createProof(
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

  const result = await evaluatePolicy(policy, tamperedAction, proof, {
    publicKeyPem: keys.publicKeyPem,
  });

  assert.equal(result.outcome, 'deny');
  assert.match(result.reason, /input/);
});

test('policy matches structured (object) claim values by deep equality', async () => {
  const keys = await createPermitRailKeyPair({ kid: 'policy-key' });
  const objectPolicy = {
    version: 'permitrail.policy.v1',
    id: 'object-value-policy',
    defaults: { unconfiguredTool: 'deny' },
    tools: {
      'flags.set': {
        id: 'flags-rule',
        require: { claim: 'config.scope', value: { env: 'prod', tier: 'high' } },
      },
    },
  } satisfies PermitRailPolicy;

  const flagAction = {
    tool: 'flags.set',
    audience: 'ops-agent',
    subject: 'user_1',
    purpose: 'Enable feature flag',
  } satisfies AgentAction;

  // The proof carries the same object with keys in a different order. A naive
  // === check would reject this; canonical comparison accepts it.
  const proof = await createProof(
    {
      claim: 'config.scope',
      value: { tier: 'high', env: 'prod' },
      subject: flagAction.subject,
      audience: flagAction.audience,
      purpose: flagAction.purpose,
      provider: 'permitrail-local',
    },
    keys,
  );

  const result = await evaluatePolicy(objectPolicy, flagAction, proof, {
    publicKeyPem: keys.publicKeyPem,
  });
  assert.equal(result.outcome, 'allow');
});
