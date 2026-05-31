import { MCP_TOOL_DEFINITIONS, createProofrailMcpTools } from '@proofrail/mcp-gateway';
import type { ProofrailGateway, ProofrailMcpToolName } from '@proofrail/mcp-gateway';
import { LocalApprovalProvider } from '@proofrail/provider-local';
import type { ProofProvider } from '@proofrail/core';

import type { RpcHandler } from './jsonrpc.ts';

export interface ProofrailMcpServerOptions {
  readonly gateway: ProofrailGateway;
  readonly provider?: ProofProvider;
  readonly name?: string;
  readonly version?: string;
  // Expose a development-only approve tool so the local approval loop is
  // callable over MCP. In production, approval comes from a real provider
  // channel (passkey, email, Slack, and so on), not this tool.
  readonly devApproval?: boolean;
}

interface ListedTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: unknown;
}

const DEFAULT_PROTOCOL_VERSION = '2025-06-18';

const APPROVE_TOOL: ListedTool = {
  name: 'proofrail_approve_challenge',
  description:
    'Development only. Approve a pending local proof challenge and return a signed proof. In production, approvals come from a real provider channel, not this tool.',
  inputSchema: {
    type: 'object',
    required: ['challengeId'],
    additionalProperties: false,
    properties: {
      challengeId: { type: 'string', description: 'The challenge id returned by proofrail_authorize_tool_call.' },
      approvedBy: { type: 'string', description: 'Optional identifier for who approved.' },
    },
  },
};

function rpcError(code: number, message: string): Error {
  const error = new Error(message) as Error & { code: number };
  error.code = code;
  return error;
}

export function createProofrailRpcHandler(options: ProofrailMcpServerOptions): RpcHandler {
  const router = createProofrailMcpTools({ gateway: options.gateway, provider: options.provider });
  const name = options.name ?? 'proofrail';
  const version = options.version ?? '0.1.0';
  const localProvider =
    options.devApproval && options.provider instanceof LocalApprovalProvider ? options.provider : undefined;

  const tools: ListedTool[] = [...MCP_TOOL_DEFINITIONS, ...(localProvider ? [APPROVE_TOOL] : [])];

  const callTool = async (params: unknown): Promise<unknown> => {
    const { name: toolName, arguments: args } = (params ?? {}) as {
      name?: string;
      arguments?: Record<string, unknown>;
    };
    const toolArgs = args ?? {};
    if (!toolName) throw rpcError(-32602, 'tools/call requires a tool name');

    try {
      let result: unknown;
      if (localProvider && toolName === APPROVE_TOOL.name) {
        result = await localProvider.approve(String(toolArgs.challengeId), {
          approvedBy: typeof toolArgs.approvedBy === 'string' ? toolArgs.approvedBy : 'mcp-dev-approver',
        });
      } else {
        result = await router.callTool(toolName as ProofrailMcpToolName, toolArgs);
      }
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { content: [{ type: 'text', text: message }], isError: true };
    }
  };

  return async (method, params) => {
    switch (method) {
      case 'initialize': {
        const requested = (params as { protocolVersion?: string } | null | undefined)?.protocolVersion;
        return {
          protocolVersion: requested ?? DEFAULT_PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name, version },
        };
      }
      case 'notifications/initialized':
      case 'notifications/cancelled':
        return undefined;
      case 'ping':
        return {};
      case 'tools/list':
        return { tools };
      case 'tools/call':
        return callTool(params);
      default:
        throw rpcError(-32601, `Method not found: ${method}`);
    }
  };
}
