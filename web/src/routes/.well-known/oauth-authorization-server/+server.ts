import { env } from '$env/dynamic/private';
import { ssrTimeoutMs } from '$lib/server/api';
import type { RequestHandler } from './$types';

// RFC 8414 discovery for the MCP authorization server. This is a proxy, for the
// same reason the OJCP manifest is: nginx serves /.well-known/ from this Node
// process, and the Go service is what knows the issuer and the endpoint paths.
export const GET: RequestHandler = async ({ fetch }) => {
  const base = env.API_INTERNAL_URL ?? '';
  let upstream: Response;
  try {
    upstream = await fetch(`${base}/api/v1/oauth/authorization-server`, {
      signal: AbortSignal.timeout(ssrTimeoutMs()),
    });
  } catch {
    return metadataUnavailable();
  }
  if (!upstream.ok) return metadataUnavailable();
  return new Response(await upstream.text(), { headers: metadataHeaders() });
};

function metadataHeaders(): HeadersInit {
  return {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    'cache-control': 'public, max-age=3600',
  };
}

function metadataUnavailable(): Response {
  return new Response('{"error":"metadata unavailable"}', {
    status: 503,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
    },
  });
}
