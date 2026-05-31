export type DateInput = Date | number | string;

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue | undefined };
export type JsonObject = { [key: string]: JsonValue | undefined };

export interface PermitRailKeyPair {
  readonly alg: 'EdDSA';
  readonly kid: string;
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

export interface EnvelopeHeader {
  readonly alg: 'EdDSA';
  readonly kid: string;
  readonly typ: string;
  readonly [key: string]: JsonValue | undefined;
}

export interface SignedEnvelope<TPayload extends object> {
  readonly protected: EnvelopeHeader;
  readonly payload: TPayload;
  readonly signature: string;
}

export type AssuranceLevel =
  | 'self_attested'
  | 'account_controlled'
  | 'human_approved'
  | 'provider_verified'
  | 'credential_verified'
  | 'qualified_trust';

export interface AgentAction<TInput = unknown> {
  readonly tool: string;
  readonly audience: string;
  readonly subject: string;
  readonly purpose: string;
  readonly risk?: string;
  readonly input?: TInput;
}

export interface ProofAction {
  readonly tool: string;
  readonly purpose: string;
  readonly subject: string;
  readonly audience: string;
  readonly risk?: string;
}

export interface CreateProofInput<TInput = unknown> {
  readonly id?: string;
  readonly requestId?: string;
  readonly challengeId?: string;
  readonly claim: string;
  readonly value?: JsonValue;
  readonly subject: string;
  readonly audience: string;
  readonly purpose: string;
  readonly provider: string;
  readonly assurance?: AssuranceLevel;
  readonly nonce?: string;
  readonly now?: DateInput;
  readonly ttlSeconds?: number;
  readonly action?: AgentAction<TInput>;
  readonly evidence?: unknown;
  readonly metadata?: JsonObject;
}

export interface ProofPayload {
  readonly kind: 'permitrail.proof.v1';
  readonly id: string;
  readonly requestId?: string;
  readonly challengeId?: string;
  readonly claim: string;
  readonly value: JsonValue;
  readonly subject: string;
  readonly audience: string;
  readonly purpose: string;
  readonly provider: string;
  readonly assurance: AssuranceLevel;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly action?: ProofAction;
  readonly actionInputHash?: string;
  readonly evidenceHash?: string;
  readonly metadata?: JsonObject;
}

export interface VerifyProofOptions {
  readonly publicKeyPem: string;
  readonly kid?: string;
  readonly now?: DateInput;
  readonly audience?: string;
  readonly claim?: string;
  readonly subject?: string;
  readonly purpose?: string;
  readonly minAssurance?: AssuranceLevel;
}

export interface CreateActionReceiptInput<TInput = unknown> {
  readonly id?: string;
  readonly action: AgentAction<TInput>;
  readonly decision: string;
  readonly reason?: string;
  readonly policyId?: string;
  readonly proofEnvelope?: SignedEnvelope<ProofPayload>;
  readonly now?: DateInput;
  readonly metadata?: JsonObject;
}

export interface ActionReceiptPayload {
  readonly kind: 'permitrail.action_receipt.v1';
  readonly id: string;
  readonly action: ProofAction;
  readonly decision: string;
  readonly reason?: string;
  readonly policyId?: string;
  readonly proofId?: string;
  readonly proofClaim?: string;
  readonly proofAssurance?: AssuranceLevel;
  readonly inputHash?: string;
  readonly issuedAt: string;
  readonly metadata?: JsonObject;
}

export interface VerifyActionReceiptOptions {
  readonly publicKeyPem: string;
  readonly kid?: string;
}

export type ToolDefaultDecision = 'allow' | 'deny';
export type PolicyRuleMode = 'allow' | 'deny';
export type PolicyDecisionOutcome = 'allow' | 'deny' | 'require_proof';
export type AssuranceRequirement = AssuranceLevel | readonly AssuranceLevel[];

export interface ProofRequirement {
  readonly claim: string;
  readonly value?: JsonValue;
  readonly subject?: string;
  readonly audience?: string;
  readonly purpose?: string;
  readonly assurance?: AssuranceRequirement;
  readonly minAssurance?: AssuranceLevel;
  readonly maxAgeSeconds?: number;
  readonly ttlSeconds?: number;
  readonly bindActionInputHash?: boolean;
}

export interface PolicyRule {
  readonly id?: string;
  readonly mode?: PolicyRuleMode;
  readonly reason?: string;
  readonly risk?: string;
  readonly require?: ProofRequirement;
}

export interface PermitRailPolicy {
  readonly version: 'permitrail.policy.v1' | string;
  readonly id?: string;
  readonly defaults?: {
    readonly unconfiguredTool?: ToolDefaultDecision;
  };
  readonly tools: Record<string, PolicyRule>;
}

export interface ProofRequest<TInput = unknown> {
  readonly requestId?: string;
  readonly claim: string;
  readonly value?: JsonValue;
  readonly subject: string;
  readonly audience: string;
  readonly purpose: string;
  readonly ttlSeconds?: number;
  readonly action?: AgentAction<TInput>;
  readonly metadata?: JsonObject;
}

export interface AllowDecision {
  readonly outcome: 'allow';
  readonly allowed: true;
  readonly reason: string;
  readonly policyId: string;
  readonly proof?: ProofPayload;
}

export interface DenyDecision {
  readonly outcome: 'deny';
  readonly allowed: false;
  readonly reason: string;
  readonly policyId: string;
  readonly code?: string;
}

export interface RequireProofDecision<TInput = unknown> {
  readonly outcome: 'require_proof';
  readonly allowed: false;
  readonly reason: string;
  readonly policyId: string;
  readonly requiredProof: ProofRequest<TInput>;
}

export type PolicyDecision<TInput = unknown> =
  | AllowDecision
  | DenyDecision
  | RequireProofDecision<TInput>;

export type ProofChallengeStatus = 'pending' | 'approved' | 'denied';

export interface ProofChallenge<TInput = unknown> {
  readonly id: string;
  status: ProofChallengeStatus;
  readonly provider: string;
  readonly request: ProofRequest<TInput> & { readonly requestId: string };
  readonly approvalUrl: string;
  readonly createdAt: string;
  completedAt?: string;
  denialReason?: string;
  proofEnvelope?: SignedEnvelope<ProofPayload>;
}

export interface ProofProvider {
  readonly publicKeyPem: string;
  requestProof<TInput = unknown>(input: ProofRequest<TInput>): Promise<ProofChallenge<TInput>>;
  getChallenge?(challengeId: string): Promise<ProofChallenge | null>;
}
