import type { ActionReceiptPayload, SignedEnvelope } from '@permitrail/core';

/**
 * An AuditSink receives every signed receipt the gateway produces, for allowed
 * and denied actions alike. Point it at a database, an append-only log, an
 * OpenTelemetry exporter, or any durable store. Receipts are signed envelopes,
 * so a sink can persist them as-is and anyone can verify them later.
 */
export interface AuditSink {
  record(receipt: SignedEnvelope<ActionReceiptPayload>): Promise<void> | void;
}

/** Collects receipts in memory. Useful for tests, demos, and local inspection. */
export class InMemoryAuditLog implements AuditSink {
  readonly receipts: SignedEnvelope<ActionReceiptPayload>[] = [];

  record(receipt: SignedEnvelope<ActionReceiptPayload>): void {
    this.receipts.push(receipt);
  }
}
