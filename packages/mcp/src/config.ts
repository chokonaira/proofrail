import { readFileSync } from 'node:fs';

import { createProofrailKeyPair } from '@proofrail/core';
import type { ProofrailKeyPair, ProofrailPolicy } from '@proofrail/core';
import { InMemoryAuditLog, ProofrailGateway } from '@proofrail/mcp-gateway';
import { LocalApprovalProvider } from '@proofrail/provider-local';

// A safe default policy: read-only calendar is allowed, email and payments need
// human approval bound to the exact input, and everything else is denied.
const SAMPLE_POLICY: ProofrailPolicy = {
  version: 'proofrail.policy.v1',
  id: 'proofrail-sample',
  defaults: { unconfiguredTool: 'deny' },
  tools: {
    'calendar.read': { id: 'calendar-read', mode: 'allow', risk: 'low', reason: 'Read-only calendar access.' },
    'email.send': {
      id: 'email-send',
      risk: 'medium',
      reason: 'External email can leak data or trigger irreversible actions.',
      require: {
        claim: 'human.approved_action',
        value: true,
        assurance: ['human_approved'],
        maxAgeSeconds: 300,
        bindActionInputHash: true,
      },
    },
    'payments.create_transfer': {
      id: 'payments-transfer',
      risk: 'high',
      reason: 'Moving money needs explicit approval of the exact amount and recipient.',
      require: {
        claim: 'human.approved_spend',
        value: true,
        assurance: ['human_approved'],
        maxAgeSeconds: 120,
        bindActionInputHash: true,
      },
    },
  },
};

export interface LoadedServer {
  readonly gateway: ProofrailGateway;
  readonly provider: LocalApprovalProvider;
  readonly auditLog: InMemoryAuditLog;
}

export async function loadServerFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<LoadedServer> {
  const policy = readPolicy(env.PROOFRAIL_POLICY);
  const provider = await LocalApprovalProvider.create();
  const receiptKeyPair = await readReceiptKey(env.PROOFRAIL_RECEIPT_KEY);
  const auditLog = new InMemoryAuditLog();
  const gateway = new ProofrailGateway({
    policy,
    provider,
    trustedProofKeys: [provider.publicKeyPem],
    receiptKeyPair,
    auditSink: auditLog,
  });
  return { gateway, provider, auditLog };
}

function readPolicy(path: string | undefined): ProofrailPolicy {
  if (!path) return SAMPLE_POLICY;
  return JSON.parse(readFileSync(path, 'utf8')) as ProofrailPolicy;
}

async function readReceiptKey(path: string | undefined): Promise<ProofrailKeyPair> {
  if (path) {
    return JSON.parse(readFileSync(path, 'utf8')) as ProofrailKeyPair;
  }
  process.stderr.write(
    '[proofrail] WARNING: PROOFRAIL_RECEIPT_KEY is not set. Generated an ephemeral receipt key; receipts will not verify across restarts. Set PROOFRAIL_RECEIPT_KEY to a persisted key file in production.\n',
  );
  return createProofrailKeyPair({ kid: 'proofrail-mcp-dev' });
}
