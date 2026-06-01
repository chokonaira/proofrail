import assert from 'node:assert/strict';
import test from 'node:test';

import { WebhookApprovalProvider } from '../src/index.ts';
import type { WebhookTransport } from '../src/index.ts';

const request = { claim: 'c', subject: 's', audience: 'a', purpose: 'p' };

test('only an explicit true approves; a truthy non-true value denies', async () => {
  const sketchy: WebhookTransport = async () => ({ approved: 'yes' as unknown as boolean });
  const provider = await WebhookApprovalProvider.create({ endpoint: 'https://approve.example', transport: sketchy });
  const challenge = await provider.requestProof(request);
  assert.equal(challenge.status, 'denied');
  assert.equal(challenge.proofEnvelope, undefined);
});

test('a malformed (non-object) response denies instead of throwing', async () => {
  const bad: WebhookTransport = async () => null as unknown as { approved: boolean };
  const provider = await WebhookApprovalProvider.create({ endpoint: 'https://approve.example', transport: bad });
  const challenge = await provider.requestProof(request);
  assert.equal(challenge.status, 'denied');
});

test('the endpoint cannot escalate the assurance level', async () => {
  const escalate: WebhookTransport = async () =>
    ({ approved: true, assurance: 'high_assurance' } as unknown as { approved: boolean });
  const provider = await WebhookApprovalProvider.create({
    endpoint: 'https://approve.example',
    transport: escalate,
    assurance: 'account_controlled',
  });
  const challenge = await provider.requestProof(request);
  assert.equal(challenge.status, 'approved');
  assert.equal(challenge.proofEnvelope!.payload.assurance, 'account_controlled');
});

test('the endpoint must use https (http allowed only for localhost)', async () => {
  await assert.rejects(() => WebhookApprovalProvider.create({ endpoint: 'http://evil.example' }), /https/i);
});
