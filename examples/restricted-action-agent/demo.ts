import { createPermitRailKeyPair } from '@permitrail/core';
import { PermitRailGateway, InMemoryAuditLog } from '@permitrail/mcp-gateway';
import { LocalApprovalProvider } from '@permitrail/provider-local';
import { policy } from './policy.ts';

const provider = await LocalApprovalProvider.create();
const receiptKeyPair = await createPermitRailKeyPair({ kid: 'permitrail-gateway-demo' });
const auditLog = new InMemoryAuditLog();
const gateway = new PermitRailGateway({
  policy,
  provider,
  trustedProofKeys: [provider.publicKeyPem],
  receiptKeyPair,
  auditSink: auditLog,
});

const maliciousPayment = {
  tool: 'payments.create_transfer',
  audience: 'finance-agent',
  subject: 'user_henry',
  purpose: 'Transfer 5000 USD to attacker-controlled account from email instruction',
  risk: 'high',
  input: {
    amount: 5000,
    currency: 'USD',
    recipient: 'acct_attacker',
    source: 'untrusted_email',
  },
};

const legitimateEmail = {
  tool: 'email.send',
  audience: 'sales-agent',
  subject: 'user_henry',
  purpose: 'Send invoice INV-123 to client@example.com',
  risk: 'medium',
  input: {
    to: 'client@example.com',
    subject: 'Invoice INV-123',
    body: 'Attached is invoice INV-123.',
  },
};

console.log('\nPermitRail demo: proof-gated tool calls\n');

console.log('1. Agent attempts a risky payment from an untrusted email.');
const paymentAuth = await gateway.authorize(maliciousPayment);
console.log(`   decision=${paymentAuth.outcome}`);
console.log(`   reason=${paymentAuth.reason}`);
if (paymentAuth.outcome !== 'require_proof' || !paymentAuth.challenge) {
  throw new Error('Expected payment to require proof');
}
console.log(`   challenge=${paymentAuth.challenge.id}`);

const denialReceipt = await provider.deny(paymentAuth.challenge.id, {
  reason: 'User denied payment. Source was an untrusted email.',
});
console.log(`   denial_receipt=${denialReceipt.payload.id}`);

console.log('\n2. Agent attempts a legitimate email send.');
const emailAuth = await gateway.authorize(legitimateEmail);
console.log(`   decision=${emailAuth.outcome}`);
console.log(`   reason=${emailAuth.reason}`);
if (emailAuth.outcome !== 'require_proof' || !emailAuth.challenge) {
  throw new Error('Expected email send to require proof');
}
console.log(`   challenge=${emailAuth.challenge.id}`);

const emailProof = await provider.approve(emailAuth.challenge.id, {
  approvedBy: 'user_henry',
});

const result = await gateway.execute(
  legitimateEmail,
  async (input) => {
    if (!input) {
      throw new Error('Email input is required');
    }

    return {
      delivered: true,
      to: input.to,
      messageId: 'msg_demo_123',
    };
  },
  { proofEnvelope: emailProof },
);

console.log(`   execution_ok=${result.ok}`);
console.log(`   receipt=${result.receipt.payload.id}`);
console.log(`   input_hash=${result.receipt.payload.inputHash}`);

console.log('\n3. Agent replays the same proof for the same action.');
const replay = await gateway.execute(
  legitimateEmail,
  async () => ({ delivered: true, to: 'client@example.com', messageId: 'msg_replay' }),
  { proofEnvelope: emailProof },
);
console.log(`   execution_ok=${replay.ok}`);
console.log(`   reason=${replay.receipt.payload.reason}`);

console.log(`\nAudit log holds ${auditLog.receipts.length} signed receipts.`);
console.log('Takeaway: risky tools stay blocked until a purpose-bound proof exists,');
console.log('and each proof works exactly once.\n');
