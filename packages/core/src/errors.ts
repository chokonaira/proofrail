export class PermitRailError extends Error {
  readonly code: string;
  readonly details: unknown;

  constructor(code: string, message: string, details: unknown = undefined) {
    super(message);
    this.name = 'PermitRailError';
    this.code = code;
    this.details = details;
  }
}

export function invariant(
  condition: unknown,
  code: string,
  message: string,
  details: unknown = undefined,
): asserts condition {
  if (!condition) {
    throw new PermitRailError(code, message, details);
  }
}
