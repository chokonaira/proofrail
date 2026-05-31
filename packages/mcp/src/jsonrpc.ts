import { createInterface } from 'node:readline';

// A small, dependency-free JSON-RPC 2.0 loop over stdio. The Model Context
// Protocol uses newline-delimited JSON-RPC on stdin/stdout, with all logging on
// stderr so it never corrupts the protocol stream.

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

export function runStdioServer(handle: RpcHandler): void {
  const reader = createInterface({ input: process.stdin, crlfDelay: Number.POSITIVE_INFINITY });

  reader.on('line', (line) => {
    const trimmed = line.trim();
    if (trimmed) void dispatch(trimmed);
  });

  async function dispatch(line: string): Promise<void> {
    let request: JsonRpcRequest;
    try {
      request = JSON.parse(line) as JsonRpcRequest;
    } catch {
      write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }

    // A request without an id is a notification: handle it, but never reply.
    const isNotification = request.id === undefined;
    try {
      const result = await handle(request.method, request.params);
      if (!isNotification) {
        write({ jsonrpc: '2.0', id: request.id ?? null, result: result ?? {} });
      }
    } catch (error) {
      const err = error as { code?: number; message?: string };
      if (!isNotification) {
        write({
          jsonrpc: '2.0',
          id: request.id ?? null,
          error: { code: err.code ?? -32603, message: err.message ?? 'Internal error' },
        });
      }
    }
  }

  function write(message: JsonRpcResponse): void {
    process.stdout.write(`${JSON.stringify(message)}\n`);
  }
}
