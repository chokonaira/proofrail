// A small, dependency-free JSON-RPC 2.0 loop over stdio. The Model Context
// Protocol uses newline-delimited JSON-RPC on stdin/stdout, with all logging on
// stderr so it never corrupts the protocol stream. Input is bounded and shape-
// checked so a hostile client cannot exhaust memory or smuggle malformed frames
// into the handler.

export type JsonRpcId = string | number | null;

export interface JsonRpcRequest {
  readonly jsonrpc: '2.0';
  readonly id?: JsonRpcId;
  readonly method: string;
  readonly params?: unknown;
}

export interface JsonRpcResponse {
  readonly jsonrpc: '2.0';
  readonly id: JsonRpcId;
  readonly result?: unknown;
  readonly error?: { readonly code: number; readonly message: string; readonly data?: unknown };
}

export type RpcHandler = (method: string, params: unknown) => Promise<unknown> | unknown;

const MAX_MESSAGE_BYTES = 1_000_000;

export function runStdioServer(handle: RpcHandler): void {
  let buffer = '';
  process.stdin.setEncoding('utf8');

  process.stdin.on('data', (chunk: string) => {
    buffer += chunk;

    // Bound a single oversized line so a client cannot exhaust memory by never
    // sending a newline.
    if (buffer.length > MAX_MESSAGE_BYTES && !buffer.includes('\n')) {
      buffer = '';
      write({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Request too large' } });
      return;
    }

    let newline = buffer.indexOf('\n');
    while (newline !== -1) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line.length > MAX_MESSAGE_BYTES) {
        write({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Request too large' } });
      } else if (line) {
        void dispatch(line);
      }
      newline = buffer.indexOf('\n');
    }
  });

  async function dispatch(line: string): Promise<void> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }

    if (!isJsonRpcRequest(parsed)) {
      const id = isObject(parsed) && isId(parsed.id) ? (parsed.id as JsonRpcId) : null;
      write({ jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } });
      return;
    }

    // A request without an id is a notification: handle it, but never reply.
    const isNotification = parsed.id === undefined;
    try {
      const result = await handle(parsed.method, parsed.params);
      if (!isNotification) {
        write({ jsonrpc: '2.0', id: parsed.id ?? null, result: result ?? {} });
      }
    } catch (error) {
      const err = error as { code?: number; message?: string };
      if (!isNotification) {
        write({
          jsonrpc: '2.0',
          id: parsed.id ?? null,
          error: {
            code: typeof err.code === 'number' ? err.code : -32603,
            message: typeof err.message === 'string' ? err.message : 'Internal error',
          },
        });
      }
    }
  }

  function write(message: JsonRpcResponse): void {
    process.stdout.write(`${JSON.stringify(message)}\n`);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isId(value: unknown): boolean {
  return value === undefined || value === null || typeof value === 'string' || typeof value === 'number';
}

function isJsonRpcRequest(value: unknown): value is JsonRpcRequest {
  return isObject(value) && value.jsonrpc === '2.0' && typeof value.method === 'string' && isId(value.id);
}
