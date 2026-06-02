import http from 'node:http';
import type { AddressInfo } from 'node:net';

import type { LocalApprovalProvider } from '@permitrail/provider-local';
import { APPROVAL_PAGE } from './page.ts';

export interface ApprovalServerOptions {
  readonly provider: LocalApprovalProvider;
  readonly host?: string;
  readonly port?: number;
}

export interface ApprovalServer {
  readonly url: string;
  stop(): Promise<void>;
}

function send(res: http.ServerResponse, status: number, body: string, type = 'application/json') {
  res.writeHead(status, { 'content-type': type });
  res.end(body);
}

async function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 64_000) throw new Error('Body too large');
    chunks.push(chunk as Buffer);
  }
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
}

export async function startApprovalServer(options: ApprovalServerOptions): Promise<ApprovalServer> {
  const provider = options.provider;
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 4677;

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://localhost');
      const path = url.pathname;

      if (req.method === 'GET' && path === '/') {
        return send(res, 200, APPROVAL_PAGE, 'text/html; charset=utf-8');
      }

      if (req.method === 'GET' && path === '/api/pending') {
        const pending = [...provider.challenges.values()]
          .filter((c) => c.status === 'pending')
          .map((c) => ({
            id: c.id,
            tool:
              c.request.action?.tool ??
              (typeof c.request.metadata?.tool === 'string' ? c.request.metadata.tool : 'unknown'),
            audience: c.request.audience,
            subject: c.request.subject,
            purpose: c.request.purpose,
            input: c.request.action?.input ?? null,
            risk:
              c.request.action?.risk ??
              (typeof c.request.metadata?.risk === 'string' ? c.request.metadata.risk : undefined),
            createdAt: c.createdAt,
          }));
        return send(res, 200, JSON.stringify(pending));
      }

      const challengeId = path.match(/^\/api\/challenge\/([^/]+)$/)?.[1];
      if (req.method === 'GET' && challengeId) {
        const challenge = await provider.getChallenge(challengeId);
        if (!challenge) return send(res, 404, JSON.stringify({ error: 'not found' }));
        return send(res, 200, JSON.stringify({ status: challenge.status }));
      }

      const approveId = path.match(/^\/api\/approve\/([^/]+)$/)?.[1];
      if (req.method === 'POST' && approveId) {
        const body = await readJson(req);
        await provider.approve(approveId, {
          approvedBy: typeof body.approvedBy === 'string' ? body.approvedBy : 'local-user',
        });
        return send(res, 200, JSON.stringify({ ok: true }));
      }

      const denyId = path.match(/^\/api\/deny\/([^/]+)$/)?.[1];
      if (req.method === 'POST' && denyId) {
        const body = await readJson(req);
        await provider.deny(denyId, {
          reason: typeof body.reason === 'string' ? body.reason : 'Denied from local approval page',
        });
        return send(res, 200, JSON.stringify({ ok: true }));
      }

      send(res, 404, JSON.stringify({ error: 'not found' }));
    } catch (error) {
      send(res, 400, JSON.stringify({ error: String(error instanceof Error ? error.message : error) }));
    }
  });

  await new Promise<void>((resolve) => server.listen(port, host, resolve));
  const address = server.address() as AddressInfo;
  const url = `http://${host}:${address.port}`;

  return {
    url,
    stop: () =>
      new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
  };
}
