import { invariant } from './errors.ts';
import type { JsonObject, JsonValue } from './types.ts';

export function canonicalize(value: unknown): JsonValue {
  if (value === null) return null;

  if (typeof value === 'string' || typeof value === 'boolean') return value;

  if (typeof value === 'number') {
    invariant(Number.isFinite(value), 'INVALID_NUMBER', 'Canonical JSON only supports finite numbers');
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === 'object') {
    const result: JsonObject = {};
    const input = value as Record<string, unknown>;
    for (const key of Object.keys(input).sort()) {
      const child = input[key];
      if (child !== undefined) {
        result[key] = canonicalize(child);
      }
    }
    return result;
  }

  throw new Error(`Unsupported JSON value type: ${typeof value}`);
}

export function stableStringify(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}
