import { createId, randomId, sha256, signEnvelope, verifyEnvelope } from './crypto.ts';
import { invariant } from './errors.ts';
import type {
  ActionReceiptPayload,
  AgentAction,
  AssuranceLevel,
  CreateActionReceiptInput,
  CreateProofInput,
  DateInput,
  ProofrailKeyPair,
  ProofAction,
  ProofPayload,
  SignedEnvelope,
  VerifyActionReceiptOptions,
  VerifyProofOptions,
} from './types.ts';

export const PROOF_KIND = 'proofrail.proof.v1';
export const ACTION_RECEIPT_KIND = 'proofrail.action_receipt.v1';

export const ASSURANCE_LEVELS = Object.freeze([
  'self_attested',
  'account_controlled',
  'human_approved',
  'provider_verified',
  'credential_verified',
  'high_assurance',
]) satisfies readonly AssuranceLevel[];

export async function createProof<TInput = unknown>(
  input: CreateProofInput<TInput>,
  keyPair: ProofrailKeyPair,
): Promise<SignedEnvelope<ProofPayload>> {
  const now = toDate(input.now || new Date());
  const ttlSeconds = input.ttlSeconds ?? 5 * 60;
  invariant(ttlSeconds > 0 && ttlSeconds <= 24 * 60 * 60, 'INVALID_TTL', 'Proof ttl must be between 1 second and 24 hours');

  const assurance = input.assurance || 'human_approved';
  invariant(ASSURANCE_LEVELS.includes(assurance), 'INVALID_ASSURANCE', `Unsupported assurance level: ${assurance}`);
  invariant(input.claim, 'MISSING_CLAIM', 'Proof claim is required');
  invariant(input.subject, 'MISSING_SUBJECT', 'Proof subject is required');
  invariant(input.audience, 'MISSING_AUDIENCE', 'Proof audience is required');
  invariant(input.purpose, 'MISSING_PURPOSE', 'Proof purpose is required');
  invariant(input.provider, 'MISSING_PROVIDER', 'Proof provider is required');

  const actionInputHash = input.action?.input === undefined ? undefined : await sha256(input.action.input);
  const evidenceHash = input.evidence === undefined ? undefined : await sha256(input.evidence);

  const payload: ProofPayload = {
    kind: PROOF_KIND,
    id: input.id || createId('proof'),
    requestId: input.requestId,
    challengeId: input.challengeId,
    claim: input.claim,
    value: input.value ?? true,
    subject: input.subject,
    audience: input.audience,
    purpose: input.purpose,
    provider: input.provider,
    assurance,
    nonce: input.nonce || randomId(24),
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
    action: input.action ? normalizeActionForProof(input.action) : undefined,
    actionInputHash,
    evidenceHash,
    metadata: input.metadata,
  };

  return signEnvelope(payload, keyPair);
}

export async function verifyProof(
  envelope: SignedEnvelope<ProofPayload>,
  options: VerifyProofOptions,
): Promise<ProofPayload> {
  const payload = await verifyEnvelope(envelope, options.publicKeyPem, { kind: PROOF_KIND, kid: options.kid });
  const now = toDate(options.now || new Date());

  invariant(new Date(payload.expiresAt).getTime() > now.getTime(), 'PROOF_EXPIRED', 'Proof has expired');

  if (options.audience) {
    invariant(payload.audience === options.audience, 'AUDIENCE_MISMATCH', 'Proof audience does not match');
  }

  if (options.claim) {
    invariant(payload.claim === options.claim, 'CLAIM_MISMATCH', 'Proof claim does not match');
  }

  if (options.subject) {
    invariant(payload.subject === options.subject, 'SUBJECT_MISMATCH', 'Proof subject does not match');
  }

  if (options.purpose) {
    invariant(payload.purpose === options.purpose, 'PURPOSE_MISMATCH', 'Proof purpose does not match');
  }

  if (options.minAssurance) {
    invariant(
      assuranceRank(payload.assurance) >= assuranceRank(options.minAssurance),
      'ASSURANCE_TOO_LOW',
      `Proof assurance ${payload.assurance} is below ${options.minAssurance}`,
    );
  }

  return payload;
}

export async function createActionReceipt<TInput = unknown>(
  input: CreateActionReceiptInput<TInput>,
  keyPair: ProofrailKeyPair,
): Promise<SignedEnvelope<ActionReceiptPayload>> {
  invariant(input.action?.tool, 'MISSING_TOOL', 'Receipt action tool is required');
  invariant(input.action?.purpose, 'MISSING_PURPOSE', 'Receipt action purpose is required');
  invariant(input.decision, 'MISSING_DECISION', 'Receipt decision is required');

  const now = toDate(input.now || new Date());
  const proofPayload = input.proofEnvelope?.payload;
  const inputHash = input.action.input === undefined ? undefined : await sha256(input.action.input);

  const payload: ActionReceiptPayload = {
    kind: ACTION_RECEIPT_KIND,
    id: input.id || createId('receipt'),
    action: normalizeActionForProof(input.action),
    decision: input.decision,
    reason: input.reason,
    policyId: input.policyId,
    chainId: input.action.chainId,
    parentId: input.action.parentId,
    proofId: proofPayload?.id,
    proofClaim: proofPayload?.claim,
    proofAssurance: proofPayload?.assurance,
    inputHash,
    issuedAt: now.toISOString(),
    metadata: input.metadata,
  };

  return signEnvelope(payload, keyPair);
}

export async function verifyActionReceipt(
  envelope: SignedEnvelope<ActionReceiptPayload>,
  options: VerifyActionReceiptOptions,
): Promise<ActionReceiptPayload> {
  return verifyEnvelope(envelope, options.publicKeyPem, {
    kind: ACTION_RECEIPT_KIND,
    kid: options.kid,
  });
}

export function assuranceRank(level: AssuranceLevel): number {
  const index = ASSURANCE_LEVELS.indexOf(level);
  invariant(index !== -1, 'INVALID_ASSURANCE', `Unsupported assurance level: ${level}`);
  return index;
}

function normalizeActionForProof(action: AgentAction): ProofAction {
  return {
    tool: action.tool,
    purpose: action.purpose,
    subject: action.subject,
    audience: action.audience,
    risk: action.risk,
  };
}

function toDate(value: DateInput): Date {
  const date = value instanceof Date ? value : new Date(value);
  invariant(!Number.isNaN(date.getTime()), 'INVALID_DATE', 'Invalid date');
  return date;
}
