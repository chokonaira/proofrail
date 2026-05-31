import {
  createActionReceipt,
  createPermitRailKeyPair,
  createId,
  createProof,
} from '@permitrail/core';
import type {
  ActionReceiptPayload,
  AssuranceLevel,
  JsonValue,
  PermitRailKeyPair,
  ProofChallenge,
  ProofPayload,
  ProofRequest,
  SignedEnvelope,
} from '@permitrail/core';

export interface LocalApprovalProviderOptions {
  readonly provider?: string;
  readonly keyPair?: PermitRailKeyPair;
}

export interface ApproveProofOptions {
  readonly value?: JsonValue;
  readonly subject?: string;
  readonly assurance?: AssuranceLevel;
  readonly approvedBy?: string;
}

export interface DenyProofOptions {
  readonly reason?: string;
}

export class LocalApprovalProvider {
  readonly provider: string;
  readonly keyPair: PermitRailKeyPair;
  readonly challenges: Map<string, ProofChallenge>;

  constructor(options: LocalApprovalProviderOptions = {}) {
    this.provider = options.provider || 'permitrail-local';
    this.keyPair = options.keyPair || createPermitRailKeyPair({ kid: `${this.provider}-dev` });
    this.challenges = new Map();
  }

  get publicKeyPem() {
    return this.keyPair.publicKeyPem;
  }

  async requestProof<TInput = unknown>(input: ProofRequest<TInput>): Promise<ProofChallenge<TInput>> {
    const challenge: ProofChallenge<TInput> = {
      id: createId('challenge'),
      status: 'pending',
      provider: this.provider,
      request: {
        ...input,
        requestId: input.requestId || createId('request'),
      },
      approvalUrl: `permitrail://approve/${createId('approval')}`,
      createdAt: new Date().toISOString(),
    };

    this.challenges.set(challenge.id, challenge);
    return challenge;
  }

  async approve(
    challengeId: string,
    options: ApproveProofOptions = {},
  ): Promise<SignedEnvelope<ProofPayload>> {
    const challenge = this.#getPendingChallenge(challengeId);
    const proofEnvelope = createProof(
      {
        ...challenge.request,
        id: createId('proof'),
        challengeId,
        provider: this.provider,
        value: options.value ?? challenge.request.value ?? true,
        subject: options.subject || challenge.request.subject,
        assurance: options.assurance || 'human_approved',
        metadata: {
          ...challenge.request.metadata,
          approvedBy: options.approvedBy || 'local-user',
        },
      },
      this.keyPair,
    );

    challenge.status = 'approved';
    challenge.proofEnvelope = proofEnvelope;
    challenge.completedAt = new Date().toISOString();
    return proofEnvelope;
  }

  async deny(
    challengeId: string,
    options: DenyProofOptions = {},
  ): Promise<SignedEnvelope<ActionReceiptPayload>> {
    const challenge = this.#getPendingChallenge(challengeId);
    challenge.status = 'denied';
    challenge.denialReason = options.reason || 'User denied proof request';
    challenge.completedAt = new Date().toISOString();
    const metadataTool = challenge.request.metadata?.tool;
    const metadataRisk = challenge.request.metadata?.risk;
    const metadataPolicyId = challenge.request.metadata?.policyId;

    return createActionReceipt(
      {
        action: challenge.request.action || {
          tool: typeof metadataTool === 'string' ? metadataTool : 'unknown',
          purpose: challenge.request.purpose,
          subject: challenge.request.subject,
          audience: challenge.request.audience,
          risk: typeof metadataRisk === 'string' ? metadataRisk : undefined,
        },
        decision: 'denied',
        reason: challenge.denialReason,
        policyId: typeof metadataPolicyId === 'string' ? metadataPolicyId : undefined,
      },
      this.keyPair,
    );
  }

  async getChallenge(challengeId: string): Promise<ProofChallenge | null> {
    return this.challenges.get(challengeId) || null;
  }

  #getPendingChallenge(challengeId: string): ProofChallenge {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) {
      throw new Error(`Unknown challenge: ${challengeId}`);
    }

    if (challenge.status !== 'pending') {
      throw new Error(`Challenge is already ${challenge.status}`);
    }

    return challenge;
  }
}
