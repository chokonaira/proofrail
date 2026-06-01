import { createId, createPermitRailKeyPair, createProof } from '@permitrail/core';
import type {
  AssuranceLevel,
  JsonValue,
  PermitRailKeyPair,
  ProofChallenge,
  ProofPayload,
  ProofProvider,
  ProofRequest,
  SignedEnvelope,
} from '@permitrail/core';

// The decision your endpoint returns. Approve and the provider signs a proof
// bound to the exact request; deny and the challenge is recorded as denied.
export interface WebhookDecision {
  readonly approved: boolean;
  readonly approvedBy?: string;
  readonly reason?: string;
  readonly value?: JsonValue;
  // Note: the endpoint cannot set the assurance level. Assurance is fixed by the
  // provider's operator configuration so a compromised endpoint cannot escalate.
}

export interface WebhookRequestPayload<TInput = unknown> {
  readonly challengeId: string;
  readonly request: ProofRequest<TInput> & { readonly requestId: string };
}

// How the challenge reaches your approver. The default posts JSON with fetch;
// inject your own to add auth, signing, queues, or to test without a network.
export type WebhookTransport = (input: {
  readonly url: string;
  readonly headers: Record<string, string>;
  readonly payload: WebhookRequestPayload;
}) => Promise<WebhookDecision>;

export interface WebhookApprovalProviderOptions {
  readonly endpoint: string;
  readonly keyPair: PermitRailKeyPair;
  readonly provider?: string;
  readonly headers?: Record<string, string>;
  readonly assurance?: AssuranceLevel;
  readonly transport?: WebhookTransport;
  // Aborts the default fetch transport after this many milliseconds so a hung
  // approval endpoint cannot stall the gateway. Defaults to 10000.
  readonly timeoutMs?: number;
}

function createFetchTransport(timeoutMs: number): WebhookTransport {
  return async ({ url, headers, payload }) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) {
      throw new Error(`Webhook approval endpoint returned ${response.status}`);
    }
    return (await response.json()) as WebhookDecision;
  };
}

/**
 * Routes each approval request to an HTTP endpoint (a Slack bot, a risk engine,
 * an internal approval service) and signs a proof when the endpoint approves.
 * The same policy and proof format work unchanged; only the approval source
 * differs from the local provider.
 */
export class WebhookApprovalProvider implements ProofProvider {
  readonly endpoint: string;
  readonly provider: string;
  readonly keyPair: PermitRailKeyPair;
  readonly challenges: Map<string, ProofChallenge>;
  readonly #headers: Record<string, string>;
  readonly #assurance: AssuranceLevel;
  readonly #transport: WebhookTransport;

  constructor(options: WebhookApprovalProviderOptions) {
    if (!options?.endpoint) {
      throw new Error('WebhookApprovalProvider requires an endpoint URL.');
    }
    let parsed: URL;
    try {
      parsed = new URL(options.endpoint);
    } catch {
      throw new Error('WebhookApprovalProvider endpoint must be a valid absolute URL.');
    }
    const isLocal =
      parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '::1';
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLocal)) {
      throw new Error('WebhookApprovalProvider endpoint must use https (http is allowed only for localhost).');
    }
    if (!options?.keyPair?.privateKeyPem) {
      throw new Error(
        'WebhookApprovalProvider requires a keyPair. Use "await WebhookApprovalProvider.create({ endpoint })" to generate one, or pass your own.',
      );
    }
    this.endpoint = options.endpoint;
    this.provider = options.provider || 'permitrail-webhook';
    this.keyPair = options.keyPair;
    this.challenges = new Map();
    this.#headers = options.headers || {};
    this.#assurance = options.assurance || 'human_approved';
    this.#transport = options.transport || createFetchTransport(options.timeoutMs ?? 10_000);
  }

  static async create(
    options: Omit<WebhookApprovalProviderOptions, 'keyPair'>,
  ): Promise<WebhookApprovalProvider> {
    const provider = options.provider || 'permitrail-webhook';
    const keyPair = await createPermitRailKeyPair({ kid: `${provider}-dev` });
    return new WebhookApprovalProvider({ ...options, keyPair });
  }

  get publicKeyPem() {
    return this.keyPair.publicKeyPem;
  }

  async requestProof<TInput = unknown>(input: ProofRequest<TInput>): Promise<ProofChallenge<TInput>> {
    const request = { ...input, requestId: input.requestId || createId('request') };
    const challenge: ProofChallenge<TInput> = {
      id: createId('challenge'),
      status: 'pending',
      provider: this.provider,
      request,
      approvalUrl: this.endpoint,
      createdAt: new Date().toISOString(),
    };
    this.challenges.set(challenge.id, challenge as ProofChallenge);

    const decision = await this.#transport({
      url: this.endpoint,
      headers: this.#headers,
      payload: { challengeId: challenge.id, request: request as ProofRequest & { requestId: string } },
    });

    challenge.completedAt = new Date().toISOString();

    // Only an explicit boolean true approves. Anything else (false, missing, or
    // a non-object response) denies. Assurance is fixed by operator config, so
    // the endpoint cannot escalate it.
    if (!decision || typeof decision !== 'object' || decision.approved !== true) {
      challenge.status = 'denied';
      const reason =
        decision && typeof decision === 'object' && typeof decision.reason === 'string'
          ? decision.reason
          : undefined;
      challenge.denialReason = reason || 'Webhook endpoint did not approve the request';
      return challenge;
    }

    challenge.proofEnvelope = await createProof(
      {
        ...request,
        id: createId('proof'),
        challengeId: challenge.id,
        provider: this.provider,
        value: decision.value ?? request.value ?? true,
        subject: request.subject,
        assurance: this.#assurance,
        metadata: {
          ...request.metadata,
          approvedBy: typeof decision.approvedBy === 'string' ? decision.approvedBy : 'webhook',
        },
      },
      this.keyPair,
    );
    challenge.status = 'approved';
    return challenge;
  }

  async getChallenge(challengeId: string): Promise<ProofChallenge | null> {
    return this.challenges.get(challengeId) || null;
  }
}

export type { ProofPayload, SignedEnvelope };
