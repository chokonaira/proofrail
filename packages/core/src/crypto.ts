import { stableStringify } from './canonical-json.ts';
import { invariant } from './errors.ts';
import type { EnvelopeHeader, JsonValue, PermitRailKeyPair, SignedEnvelope } from './types.ts';

// Ed25519 over the Web Crypto API. The same code runs on Node 20+, modern
// browsers, Deno, Bun, and edge runtimes, with no native or third-party
// dependency. Signing and verification are async because SubtleCrypto is async.
const EDDSA = { name: 'Ed25519' };

const encoder = new TextEncoder();

function getSubtle() {
  const webcrypto = globalThis.crypto;
  invariant(
    webcrypto && webcrypto.subtle,
    'NO_WEBCRYPTO',
    'PermitRail needs the Web Crypto API. Run on Node 20+, a modern browser, Deno, Bun, or an edge runtime.',
  );
  return webcrypto.subtle;
}

function getRandomBytes(length: number): Uint8Array {
  const webcrypto = globalThis.crypto;
  invariant(
    webcrypto && webcrypto.getRandomValues,
    'NO_WEBCRYPTO',
    'PermitRail needs a secure random source (globalThis.crypto.getRandomValues).',
  );
  return webcrypto.getRandomValues(new Uint8Array(length));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  const restored = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (restored.length % 4)) % 4;
  return base64ToBytes(restored + '='.repeat(padding));
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return hex;
}

function toPem(der: ArrayBuffer, label: 'PUBLIC KEY' | 'PRIVATE KEY'): string {
  const base64 = bytesToBase64(new Uint8Array(der));
  const lines = base64.match(/.{1,64}/g) ?? [base64];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

function pemToBytes(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [A-Z ]+-----/, '')
    .replace(/-----END [A-Z ]+-----/, '')
    .replace(/\s+/g, '');
  return base64ToBytes(body);
}

export async function createPermitRailKeyPair(
  { kid }: { readonly kid?: string } = {},
): Promise<PermitRailKeyPair> {
  const generated = await getSubtle().generateKey(EDDSA, true, ['sign', 'verify']);
  if (!('publicKey' in generated)) {
    throw new Error('Ed25519 key generation did not return a key pair');
  }
  const spki = await getSubtle().exportKey('spki', generated.publicKey);
  const pkcs8 = await getSubtle().exportKey('pkcs8', generated.privateKey);

  return {
    alg: 'EdDSA',
    kid: kid || `permitrail-${randomId(8)}`,
    publicKeyPem: toPem(spki, 'PUBLIC KEY'),
    privateKeyPem: toPem(pkcs8, 'PRIVATE KEY'),
  };
}

export function randomId(bytes = 16): string {
  return bytesToBase64Url(getRandomBytes(bytes));
}

export function createId(prefix: string): string {
  const webcrypto = globalThis.crypto;
  invariant(
    webcrypto && webcrypto.randomUUID,
    'NO_WEBCRYPTO',
    'PermitRail needs globalThis.crypto.randomUUID for identifiers.',
  );
  return `${prefix}_${webcrypto.randomUUID()}`;
}

export async function sha256(value: unknown): Promise<string> {
  const input = typeof value === 'string' ? value : stableStringify(value);
  const digest = await getSubtle().digest('SHA-256', encoder.encode(input));
  return `sha256:${bytesToHex(new Uint8Array(digest))}`;
}

export async function signEnvelope<TPayload extends object>(
  payload: TPayload & { readonly kind?: string },
  keyPair: PermitRailKeyPair,
  header: Record<string, JsonValue | undefined> = {},
): Promise<SignedEnvelope<TPayload>> {
  invariant(payload && typeof payload === 'object', 'INVALID_PAYLOAD', 'Payload must be an object');
  invariant(keyPair?.privateKeyPem, 'MISSING_PRIVATE_KEY', 'A private key is required');
  invariant(keyPair?.kid, 'MISSING_KEY_ID', 'A key id is required');

  const protectedHeader: EnvelopeHeader = {
    ...header,
    alg: 'EdDSA',
    kid: keyPair.kid,
    typ: payload.kind || 'permitrail.payload',
  };

  const signingInput = stableStringify({ protected: protectedHeader, payload });
  const privateKey = await getSubtle().importKey('pkcs8', pemToBytes(keyPair.privateKeyPem), EDDSA, false, ['sign']);
  const signature = await getSubtle().sign(EDDSA, privateKey, encoder.encode(signingInput));

  return {
    protected: protectedHeader,
    payload,
    signature: bytesToBase64Url(new Uint8Array(signature)),
  };
}

export async function verifyEnvelope<TPayload extends object>(
  envelope: SignedEnvelope<TPayload>,
  publicKeyPem: string,
  expectations: { readonly kid?: string; readonly kind?: string } = {},
): Promise<TPayload> {
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

  const signingInput = stableStringify({ protected: envelope.protected, payload: envelope.payload });
  const publicKey = await getSubtle().importKey('spki', pemToBytes(publicKeyPem), EDDSA, false, ['verify']);
  const valid = await getSubtle().verify(EDDSA, publicKey, base64UrlToBytes(envelope.signature), encoder.encode(signingInput));

  invariant(valid, 'BAD_SIGNATURE', 'Envelope signature is invalid');
  return envelope.payload;
}
