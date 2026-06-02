import type { ProofPayload, ProofProvider, SignedEnvelope } from '@permitrail/core';

export interface WaitForProofOptions {
  // Reject after this many ms with no decision. Default 300000 (5 minutes).
  readonly timeoutMs?: number;
  // Poll interval in ms. Default 400.
  readonly pollMs?: number;
}

// Wait for a human (or other authority) to approve a pending challenge.
// Resolves with the signed proof on approval, rejects on denial or timeout.
// No new crypto: provider.approve already signed the proof, this only waits.
export async function waitForProof(
  provider: Pick<ProofProvider, 'getChallenge'>,
  challengeId: string,
  options: WaitForProofOptions = {},
): Promise<SignedEnvelope<ProofPayload>> {
  if (!provider.getChallenge) {
    throw new Error('Provider does not support getChallenge, cannot wait for approval');
  }
  const timeoutMs = options.timeoutMs ?? 300_000;
  const pollMs = options.pollMs ?? 400;
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    const challenge = await provider.getChallenge(challengeId);
    if (!challenge) {
      throw new Error(`Unknown challenge: ${challengeId}`);
    }
    if (challenge.status === 'approved') {
      if (!challenge.proofEnvelope) {
        throw new Error('Approved challenge has no proof envelope');
      }
      return challenge.proofEnvelope;
    }
    if (challenge.status === 'denied') {
      throw new Error(challenge.denialReason || 'Approval was denied');
    }
    if (Date.now() >= deadline) {
      throw new Error('Timed out waiting for approval');
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}
