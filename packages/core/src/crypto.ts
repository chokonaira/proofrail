import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from 'node:crypto';

import { stableStringify } from './canonical-json.ts';
import { invariant } from './errors.ts';
import type { EnvelopeHeader, JsonValue, PermitRailKeyPair, SignedEnvelope } from './types.ts';

export function createPermitRailKeyPair(
  { kid = `permitrail-${randomId(8)}` }: { readonly kid?: string } = {},
): PermitRailKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');

  return {
    alg: 'EdDSA',
    kid,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

export function randomId(bytes = 16): string {
  return randomBytes(bytes).toString('base64url');
}

export function createId(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

export function sha256(value: unknown): string {
  const input = typeof value === 'string' ? value : stableStringify(value);
  return `sha256:${createHash('sha256').update(input).digest('hex')}`;
}

export function signEnvelope<TPayload extends object>(
  payload: TPayload & { readonly kind?: string },
  keyPair: PermitRailKeyPair,
  header: Record<string, JsonValue | undefined> = {},
): SignedEnvelope<TPayload> {
  invariant(payload && typeof payload === 'object', 'INVALID_PAYLOAD', 'Payload must be an object');
  invariant(keyPair?.privateKeyPem, 'MISSING_PRIVATE_KEY', 'A private key is required');
  invariant(keyPair?.kid, 'MISSING_KEY_ID', 'A key id is required');

  const protectedHeader: EnvelopeHeader = {
    ...header,
    alg: 'EdDSA',
    kid: keyPair.kid,
    typ: payload.kind || 'permitrail.payload',
  };

  const signingInput = stableStringify({
    protected: protectedHeader,
    payload,
  });

  const privateKey = createPrivateKey(keyPair.privateKeyPem);
  const signature = sign(null, Buffer.from(signingInput), privateKey).toString('base64url');

  return {
    protected: protectedHeader,
    payload,
    signature,
  };
}

export function verifyEnvelope<TPayload extends object>(
  envelope: SignedEnvelope<TPayload>,
  publicKeyPem: string,
  expectations: { readonly kid?: string; readonly kind?: string } = {},
): TPayload {
  invariant(envelope && typeof envelope === 'object', 'INVALID_ENVELOPE', 'Envelope must be an object');
  invariant(envelope.protected && typeof envelope.protected === 'object', 'INVALID_ENVELOPE', 'Envelope is missing protected header');
  invariant(envelope.payload && typeof envelope.payload === 'object', 'INVALID_ENVELOPE', 'Envelope is missing payload');
  invariant(typeof envelope.signature === 'string', 'INVALID_ENVELOPE', 'Envelope is missing signature');
  invariant(publicKeyPem, 'MISSING_PUBLIC_KEY', 'A public key is required');

  invariant(envelope.protected.alg === 'EdDSA', 'UNSUPPORTED_ALGORITHM', 'Only EdDSA envelopes are supported');

  if (expectations.kid) {
    invariant(envelope.protected.kid === expectations.kid, 'KEY_ID_MISMATCH', 'Envelope key id does not match expected key id');
  }

  if (expectations.kind) {
    const payloadKind = (envelope.payload as { readonly kind?: string }).kind;
    invariant(payloadKind === expectations.kind, 'KIND_MISMATCH', 'Envelope payload kind does not match expected kind');
  }

  const signingInput = stableStringify({
    protected: envelope.protected,
    payload: envelope.payload,
  });

  const publicKey = createPublicKey(publicKeyPem);
  const valid = verify(
    null,
    Buffer.from(signingInput),
    publicKey,
    Buffer.from(envelope.signature, 'base64url'),
  );

  invariant(valid, 'BAD_SIGNATURE', 'Envelope signature is invalid');

  return envelope.payload;
}
