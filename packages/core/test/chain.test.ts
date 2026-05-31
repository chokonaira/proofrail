import assert from 'node:assert/strict';
import test from 'node:test';

import { createProofrailKeyPair, createActionReceipt, verifyActionReceipt } from '../src/index.ts';

test('receipts carry multi-agent chain correlation and stay signed', async () => {
  const keys = await createProofrailKeyPair();
  const chainId = 'chain_demo_1';

  // Step 1: a research agent acts.
  const first = await createActionReceipt(
    {
      action: {
        tool: 'research.fetch',
        audience: 'researcher-agent',
        subject: 'user_1',
        purpose: 'Gather sources for the weekly report',
        chainId,
      },
      decision: 'allowed',
    },
    keys,
  );

  // Step 2: a writer agent acts downstream, linking back to step 1's receipt.
  const second = await createActionReceipt(
    {
      action: {
        tool: 'email.send',
        audience: 'writer-agent',
        subject: 'user_1',
        purpose: 'Send the weekly report',
        chainId,
        parentId: first.payload.id,
      },
      decision: 'allowed',
    },
    keys,
  );

  const p1 = await verifyActionReceipt(first, { publicKeyPem: keys.publicKeyPem });
  const p2 = await verifyActionReceipt(second, { publicKeyPem: keys.publicKeyPem });

  assert.equal(p1.chainId, chainId);
  assert.equal(p2.chainId, chainId);
  assert.equal(p2.parentId, first.payload.id, 'the downstream step links to the upstream receipt');
});
