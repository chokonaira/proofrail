import {
  DEFAULT_POLICY,
  buildProofRequestFromPolicy,
  createActionReceipt,
  evaluatePolicy,
  verifyProof,
} from '@proofrail/core';
import type {
  ActionReceiptPayload,
  AgentAction,
  ProofrailKeyPair,
  ProofrailPolicy,
  PolicyDecision,
  ProofChallenge,
  ProofPayload,
  ProofProvider,
  SignedEnvelope,
} from '@proofrail/core';

import { InMemoryReplayGuard } from './replay-guard.ts';
import type { ReplayGuard } from './replay-guard.ts';
import type { AuditSink } from './audit.ts';

export { InMemoryReplayGuard } from './replay-guard.ts';
export { InMemoryAuditLog } from './audit.ts';
export type { ReplayGuard } from './replay-guard.ts';
export type { AuditSink } from './audit.ts';

export interface ProofrailGatewayOptions {
  readonly policy?: ProofrailPolicy;
  readonly provider?: ProofProvider;
  // Required. Generate once with createProofrailKeyPair() and persist it so
  // receipts stay verifiable across restarts. A gateway that mints a throwaway
  // key on every boot produces an audit trail nobody can later verify.
  readonly receiptKeyPair: ProofrailKeyPair;
  readonly trustedProofKeys?: readonly string[];
  // Enforces single-use proofs. Defaults to an in-process guard; supply a
  // shared implementation (for example Redis-backed) for multi-instance setups.
  readonly replayGuard?: ReplayGuard;
  // Receives every signed receipt for durable audit. Optional.
  readonly auditSink?: AuditSink;
}

export interface GatewayAuthorizeOptions {
  readonly proofEnvelope?: SignedEnvelope<ProofPayload>;
  readonly now?: Date | number | string;
}

export type GatewayAuthorization<TInput = unknown> = PolicyDecision<TInput> & {
  readonly challenge?: ProofChallenge<TInput>;
  readonly proof?: ProofPayload;
  readonly verificationError?: unknown;
};

export type ToolHandler<TInput, TResult> = (input: TInput | undefined) => Promise<TResult> | TResult;

export interface GatewayExecutionResult<TInput = unknown, TResult = unknown> {
  readonly ok: boolean;
  readonly result?: TResult;
  readonly authorization: GatewayAuthorization<TInput>;
  readonly receipt: SignedEnvelope<ActionReceiptPayload>;
}

export interface McpToolDefinition {
  readonly name: ProofrailMcpToolName;
  readonly description: string;
  readonly inputSchema: {
    readonly type: 'object';
    readonly properties: Record<string, unknown>;
    readonly required?: readonly string[];
    readonly additionalProperties: boolean;
  };
}

export interface ProofrailMcpToolsOptions {
  readonly gateway: ProofrailGateway;
  readonly provider?: ProofProvider;
}

export type ProofrailMcpToolName =
  | 'proofrail_authorize_tool_call'
  | 'proofrail_get_challenge'
  | 'proofrail_verify_proof'
  | 'proofrail_write_receipt';

export interface ProofrailMcpToolRouter {
  readonly tools: readonly McpToolDefinition[];
  callTool(name: ProofrailMcpToolName, input: Record<string, unknown>): Promise<unknown>;
}

export class ProofrailGateway {
  readonly policy?: ProofrailPolicy;
  readonly provider?: ProofProvider;
  readonly receiptKeyPair: ProofrailKeyPair;
  readonly trustedProofKeys: readonly string[];
  readonly replayGuard: ReplayGuard;
  readonly auditSink?: AuditSink;

  constructor(options: ProofrailGatewayOptions) {
    if (!options?.receiptKeyPair?.privateKeyPem) {
      throw new Error(
        'ProofrailGateway requires a receiptKeyPair. Generate one with createProofrailKeyPair() and persist it so receipts stay verifiable across restarts.',
      );
    }
    this.policy = options.policy;
    this.provider = options.provider;
    this.receiptKeyPair = options.receiptKeyPair;
    this.trustedProofKeys = options.trustedProofKeys || [];
    this.replayGuard = options.replayGuard ?? new InMemoryReplayGuard();
    this.auditSink = options.auditSink;
  }

  async authorize<TInput = unknown>(
    action: AgentAction<TInput>,
    options: GatewayAuthorizeOptions = {},
  ): Promise<GatewayAuthorization<TInput>> {
    let verifiedProof: ProofPayload | null = null;
    let verificationError: unknown = null;
    let matchedPublicKeyPem = this.trustedProofKeys[0];

    if (options.proofEnvelope) {
      for (const publicKeyPem of this.trustedProofKeys) {
        try {
          verifiedProof = await verifyProof(options.proofEnvelope, {
            publicKeyPem,
            audience: action.audience,
            subject: action.subject,
            purpose: action.purpose,
            now: options.now,
          });
          matchedPublicKeyPem = publicKeyPem;
          verificationError = null;
          break;
        } catch (error) {
          verificationError = error;
        }
      }
    }

    const activePolicy = this.policy || DEFAULT_POLICY;
    const decision = await evaluatePolicy(activePolicy, action, options.proofEnvelope, {
      publicKeyPem: matchedPublicKeyPem,
      audience: action.audience,
      subject: action.subject,
      purpose: action.purpose,
      now: options.now,
    });

    if (decision.outcome === 'require_proof' && this.provider) {
      const proofRequest = buildProofRequestFromPolicy(activePolicy, action);
      const challenge = await this.provider.requestProof(proofRequest);
      return {
        ...decision,
        challenge,
      };
    }

    return {
      ...decision,
      proof: verifiedProof || (decision.outcome === 'allow' ? decision.proof : undefined),
      verificationError,
    };
  }

  async execute<TInput = unknown, TResult = unknown>(
    action: AgentAction<TInput>,
    handler: ToolHandler<TInput, TResult>,
    options: GatewayAuthorizeOptions = {},
  ): Promise<GatewayExecutionResult<TInput, TResult>> {
    const authorization = await this.authorize(action, options);

    if (!authorization.allowed) {
      const receipt = await this.#writeReceipt(action, authorization.outcome, authorization.reason, authorization.policyId, options.proofEnvelope);
      return { ok: false, authorization, receipt };
    }

    // Single-use enforcement: a verified proof may drive exactly one execution.
    // Without this, a still-valid proof could be replayed for the same action
    // until it expires. The guard consumes the proof id before the tool runs.
    const proofId = authorization.proof?.id;
    if (proofId) {
      const fresh = await this.replayGuard.consume(proofId, authorization.proof?.expiresAt);
      if (!fresh) {
        const receipt = await this.#writeReceipt(action, 'denied', 'Proof has already been used (replay blocked)', authorization.policyId, options.proofEnvelope);
        return { ok: false, authorization, receipt };
      }
    }

    const result = await handler(action.input);
    const receipt = await this.#writeReceipt(action, 'allowed', authorization.reason, authorization.policyId, options.proofEnvelope);
    return { ok: true, result, authorization, receipt };
  }

  async #writeReceipt<TInput>(
    action: AgentAction<TInput>,
    decision: string,
    reason: string | undefined,
    policyId: string | undefined,
    proofEnvelope: SignedEnvelope<ProofPayload> | undefined,
  ): Promise<SignedEnvelope<ActionReceiptPayload>> {
    const receipt = await createActionReceipt(
      { action, decision, reason, policyId, proofEnvelope },
      this.receiptKeyPair,
    );
    await this.auditSink?.record(receipt);
    return receipt;
  }
}

export const MCP_TOOL_DEFINITIONS: readonly McpToolDefinition[] = Object.freeze([
  {
    name: 'proofrail_authorize_tool_call',
    description: 'Authorize an agent tool call and request proof when policy requires it.',
    inputSchema: {
      type: 'object',
      required: ['action'],
      additionalProperties: false,
      properties: {
        action: {
          type: 'object',
          required: ['tool', 'audience', 'subject', 'purpose'],
          additionalProperties: false,
          properties: {
            tool: { type: 'string', description: 'Dotted tool id, for example email.send or payments.create_transfer.' },
            audience: { type: 'string', description: 'The agent or system that will use the proof.' },
            subject: { type: 'string', description: 'The user or actor the action is on behalf of.' },
            purpose: { type: 'string', description: 'Exact, human-readable reason for this action.' },
            risk: { type: 'string', description: 'Optional risk label, for example low, medium, or high.' },
            input: { type: 'object', description: 'The exact tool input. Bound by hash when the policy requires it.' },
            chainId: { type: 'string', description: 'Correlation id shared by every action in one multi-agent workflow.' },
            parentId: { type: 'string', description: 'Receipt id of the upstream step that led to this action.' },
          },
        },
        proofEnvelope: { type: 'object' },
      },
    },
  },
  {
    name: 'proofrail_get_challenge',
    description: 'Read the status of a pending, approved, or denied proof challenge.',
    inputSchema: {
      type: 'object',
      required: ['challengeId'],
      additionalProperties: false,
      properties: {
        challengeId: { type: 'string' },
      },
    },
  },
  {
    name: 'proofrail_verify_proof',
    description: 'Verify a signed Proofrail proof envelope.',
    inputSchema: {
      type: 'object',
      required: ['proofEnvelope'],
      additionalProperties: false,
      properties: {
        proofEnvelope: { type: 'object' },
        publicKeyPem: { type: 'string' },
      },
    },
  },
  {
    name: 'proofrail_write_receipt',
    description: 'Create a signed receipt for an allowed, blocked, or denied action.',
    inputSchema: {
      type: 'object',
      required: ['action', 'decision'],
      additionalProperties: false,
      properties: {
        action: {
          type: 'object',
          required: ['tool', 'audience', 'subject', 'purpose'],
          additionalProperties: false,
          properties: {
            tool: { type: 'string', description: 'Dotted tool id, for example email.send or payments.create_transfer.' },
            audience: { type: 'string', description: 'The agent or system that will use the proof.' },
            subject: { type: 'string', description: 'The user or actor the action is on behalf of.' },
            purpose: { type: 'string', description: 'Exact, human-readable reason for this action.' },
            risk: { type: 'string', description: 'Optional risk label, for example low, medium, or high.' },
            input: { type: 'object', description: 'The exact tool input. Bound by hash when the policy requires it.' },
            chainId: { type: 'string', description: 'Correlation id shared by every action in one multi-agent workflow.' },
            parentId: { type: 'string', description: 'Receipt id of the upstream step that led to this action.' },
          },
        },
        decision: { type: 'string' },
        reason: { type: 'string' },
        policyId: { type: 'string' },
        proofEnvelope: { type: 'object' },
      },
    },
  },
]);

export function createProofrailMcpTools(options: ProofrailMcpToolsOptions): ProofrailMcpToolRouter {
  return {
    tools: MCP_TOOL_DEFINITIONS,
    async callTool(name, input) {
      switch (name) {
        case 'proofrail_authorize_tool_call':
          return options.gateway.authorize(
            input.action as AgentAction,
            { proofEnvelope: input.proofEnvelope as SignedEnvelope<ProofPayload> | undefined },
          );

        case 'proofrail_get_challenge':
          if (!options.provider?.getChallenge) {
            throw new Error('This Proofrail provider does not expose challenge lookup');
          }
          return options.provider.getChallenge(String(input.challengeId));

        case 'proofrail_verify_proof':
          return verifyWithTrustedKeys(
            options.gateway.trustedProofKeys,
            input.proofEnvelope as SignedEnvelope<ProofPayload>,
            typeof input.publicKeyPem === 'string' ? input.publicKeyPem : undefined,
          );

        case 'proofrail_write_receipt':
          return createActionReceipt(
            {
              action: input.action as AgentAction,
              decision: String(input.decision),
              reason: typeof input.reason === 'string' ? input.reason : undefined,
              policyId: typeof input.policyId === 'string' ? input.policyId : undefined,
              proofEnvelope: input.proofEnvelope as SignedEnvelope<ProofPayload> | undefined,
            },
            options.gateway.receiptKeyPair,
          );

        default:
          throw new Error(`Unknown Proofrail MCP tool: ${String(name)}`);
      }
    },
  };
}

async function verifyWithTrustedKeys(
  trustedProofKeys: readonly string[],
  proofEnvelope: SignedEnvelope<ProofPayload>,
  explicitPublicKeyPem?: string,
): Promise<{ readonly ok: true; readonly proof: ProofPayload } | { readonly ok: false; readonly error: string }> {
  const keys = explicitPublicKeyPem ? [explicitPublicKeyPem] : trustedProofKeys;

  for (const publicKeyPem of keys) {
    try {
      return {
        ok: true,
        proof: await verifyProof(proofEnvelope, { publicKeyPem }),
      };
    } catch {
      continue;
    }
  }

  return {
    ok: false,
    error: 'Proof could not be verified with the configured trusted keys',
  };
}
