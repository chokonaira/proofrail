import { sha256 } from './crypto.ts';
import { assuranceRank, verifyProof } from './proofs.ts';
import type {
  AgentAction,
  AssuranceLevel,
  AssuranceRequirement,
  PermitRailPolicy,
  PolicyDecision,
  PolicyDecisionOutcome,
  PolicyRule,
  ProofPayload,
  ProofRequest,
  SignedEnvelope,
  VerifyProofOptions,
} from './types.ts';

export const DEFAULT_POLICY: PermitRailPolicy = Object.freeze({
  version: 'permitrail.policy.v1',
  id: 'default-deny',
  defaults: {
    unconfiguredTool: 'deny' as const,
  },
  tools: {},
});

type PolicyVerificationOptions = Partial<VerifyProofOptions>;

export function evaluatePolicy<TInput = unknown>(
  policy: PermitRailPolicy | undefined,
  action: AgentAction<TInput>,
  proofEnvelope?: SignedEnvelope<ProofPayload>,
  verificationOptions: PolicyVerificationOptions = {},
): PolicyDecision<TInput> {
  const activePolicy = policy || DEFAULT_POLICY;
  const rule = resolveRule(activePolicy, action.tool);
  const policyId = rule?.id || activePolicy.id || 'inline-policy';

  if (!rule) {
    if (activePolicy.defaults?.unconfiguredTool === 'allow') {
      return decision('allow', 'Tool is unconfigured and policy default allows it', policyId);
    }
    return decision('deny', 'Tool is not configured in policy', policyId);
  }

  if (rule.mode === 'deny') {
    return decision('deny', rule.reason || 'Policy denies this tool', policyId);
  }

  if (rule.mode === 'allow' && !rule.require) {
    return decision('allow', rule.reason || 'Policy allows this tool without proof', policyId);
  }

  const required = rule.require;
  if (!required) {
    return decision('allow', 'No proof requirement for this rule', policyId);
  }

  if (!proofEnvelope) {
    return decision('require_proof', 'This tool call requires a proof', policyId, {
      requiredProof: buildProofRequestFromPolicy(activePolicy, action, rule),
    });
  }

  if (!verificationOptions.publicKeyPem) {
    return decision('deny', 'No trusted public key is configured for proof verification', policyId);
  }

  try {
    const proof = verifyProof(proofEnvelope, {
      ...verificationOptions,
      publicKeyPem: verificationOptions.publicKeyPem,
      audience: required.audience || action.audience,
      claim: required.claim,
      subject: required.subject || action.subject,
      purpose: required.purpose || action.purpose,
      minAssurance: required.minAssurance || firstAssurance(required.assurance),
    });

    const valueOk = required.value === undefined || proof.value === required.value;
    if (!valueOk) {
      return decision('deny', 'Proof value does not satisfy policy', policyId);
    }

    const acceptedAssurance = normalizeAssuranceRequirement(required.assurance);
    if (acceptedAssurance.length > 0 && !acceptedAssurance.includes(proof.assurance)) {
      return decision('deny', `Proof assurance ${proof.assurance} is not accepted by policy`, policyId);
    }

    if (required.maxAgeSeconds) {
      const issuedAt = new Date(proof.issuedAt).getTime();
      const now = new Date(verificationOptions.now || new Date()).getTime();
      if (now - issuedAt > required.maxAgeSeconds * 1000) {
        return decision('deny', 'Proof is older than policy maxAgeSeconds', policyId);
      }
    }

    if (required.bindActionInputHash) {
      const expectedHash = action.input === undefined ? undefined : sha256(action.input);
      if (!expectedHash || proof.actionInputHash !== expectedHash) {
        return decision('deny', 'Proof is not bound to this action input', policyId);
      }
    }

    return decision('allow', 'Proof satisfies policy', policyId, { proof });
  } catch (error) {
    const err = error as { readonly message?: string; readonly code?: string };
    return decision('deny', err.message || 'Proof verification failed', policyId, {
      code: err.code,
    });
  }
}

export function buildProofRequestFromPolicy<TInput = unknown>(
  policy: PermitRailPolicy,
  action: AgentAction<TInput>,
  rule: PolicyRule | null = resolveRule(policy, action.tool),
): ProofRequest<TInput> {
  const required = rule?.require;
  if (!required) {
    throw new Error(`Policy rule for ${action.tool} does not define a proof requirement`);
  }

  return {
    claim: required.claim,
    value: required.value ?? true,
    subject: required.subject || action.subject,
    audience: required.audience || action.audience,
    purpose: required.purpose || action.purpose,
    ttlSeconds: required.ttlSeconds || 5 * 60,
    action: required.bindActionInputHash ? action : undefined,
    metadata: {
      tool: action.tool,
      risk: action.risk || rule?.risk,
      reason: rule?.reason,
      policyId: rule?.id || policy?.id,
    },
  };
}

export function resolveRule(policy: PermitRailPolicy | undefined, tool: string): PolicyRule | null {
  return policy?.tools?.[tool] || policy?.tools?.['*'] || null;
}

function firstAssurance(assurance: AssuranceRequirement | undefined): AssuranceLevel | undefined {
  if (!assurance) return undefined;
  const levels = normalizeAssuranceRequirement(assurance);
  return levels.reduce<AssuranceLevel | undefined>((lowest, current) => {
    if (!lowest) return current;
    return assuranceRank(current) < assuranceRank(lowest) ? current : lowest;
  }, undefined);
}

function normalizeAssuranceRequirement(
  assurance: AssuranceRequirement | undefined,
): readonly AssuranceLevel[] {
  if (!assurance) return [];
  return typeof assurance === 'string' ? [assurance] : assurance;
}

function decision<TInput = unknown>(
  outcome: PolicyDecisionOutcome,
  reason: string,
  policyId: string,
  extra: Partial<PolicyDecision<TInput>> = {},
): PolicyDecision<TInput> {
  return {
    outcome,
    allowed: outcome === 'allow',
    reason,
    policyId,
    ...extra,
  } as PolicyDecision<TInput>;
}
