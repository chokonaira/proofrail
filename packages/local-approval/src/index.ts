import { LocalApprovalProvider } from '@permitrail/provider-local';
import type { ProofPayload, SignedEnvelope } from '@permitrail/core';

import { startApprovalServer } from './server.ts';
import { waitForProof } from './wait-for-proof.ts';
import type { WaitForProofOptions } from './wait-for-proof.ts';

export { waitForProof } from './wait-for-proof.ts';
export type { WaitForProofOptions } from './wait-for-proof.ts';

export interface StartLocalApprovalOptions {
  // localhost port, default 4677
  readonly port?: number;
  // an existing provider to reuse, otherwise one is created
  readonly provider?: LocalApprovalProvider;
}

export interface LocalApproval {
  readonly provider: LocalApprovalProvider;
  readonly publicKeyPem: string;
  readonly url: string;
  waitForProof(challengeId: string, options?: WaitForProofOptions): Promise<SignedEnvelope<ProofPayload>>;
  stop(): Promise<void>;
}

// Start a localhost approval server and page for PermitRail tool calls.
// Local only: single user, in memory, no auth. For demos and internal tools.
export async function startLocalApproval(
  options: StartLocalApprovalOptions = {},
): Promise<LocalApproval> {
  const provider = options.provider ?? (await LocalApprovalProvider.create());
  const server = await startApprovalServer({
    provider,
    host: '127.0.0.1',
    port: options.port ?? 4677,
  });

  return {
    provider,
    publicKeyPem: provider.publicKeyPem,
    url: server.url,
    waitForProof: (challengeId, waitOptions) => waitForProof(provider, challengeId, waitOptions),
    stop: () => server.stop(),
  };
}
