import { env } from '$env/dynamic/private';
import { ssrTimeoutMs } from '$lib/server/api';
import type { RequestHandler } from './$types';

// Protected-resource metadata for the account MCP. The WWW-Authenticate
// challenge names this path; nginx serves /.well-known/ from Node, so this
// route proxies the document Go renders.
export const GET: RequestHandler = async ({ fetch }) => {
  const base = env.API_INTERNAL_URL ?? '';
  let upstream: Response;
  try {
    upstream = await fetch(`${base}/api/v1/oauth/protected-resource`, {
      signal: AbortSignal.timeout(ssrTimeoutMs()),
    });
  } catch {
    return metadataUnavailable();
  }
  if (!upstream.ok) return metadataUnavailable();
  return new Response(await upstream.text(), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'cache-control': 'public, max-age=3600',
    },
  });
};

function metadataUnavailable(): Response {
  return new Response('{"error":"metadata unavailable"}', {
    status: 503,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
    },
  });
}
