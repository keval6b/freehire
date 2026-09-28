import { env } from '$env/dynamic/private';
import { signinUrl } from '$lib/signin';
import { ssrTimeoutMs } from '$lib/server/api';
import { error, redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

// The consent stop on the MCP authorization-code flow. The API sends a visitor
// here when authorize has no explicit allow or deny yet. Signing in happens on
// the usual page; this one only asks for the click.
export const load: PageServerLoad = async ({ parent, url, fetch }) => {
  const clientID = url.searchParams.get('client_id') ?? '';
  const redirectURI = url.searchParams.get('redirect_uri') ?? '';
  const codeChallenge = url.searchParams.get('code_challenge') ?? '';
  const resource = url.searchParams.get('resource') ?? '';
  if (!clientID || !redirectURI || !codeChallenge || !resource) {
    error(400, 'This page is opened by an AI host connecting to freehire.');
  }

  const { user } = await parent();
  if (!user) {
    redirect(302, signinUrl({ returnTo: url.pathname + url.search, cancelTo: '/', mode: 'login' }));
  }

  return {
    clientName: await clientName(fetch, clientID),
    emailVerified: user.email_verified,
    error: url.searchParams.get('error') ?? '',
    fields: {
      client_id: clientID,
      redirect_uri: redirectURI,
      response_type: url.searchParams.get('response_type') ?? 'code',
      code_challenge: codeChallenge,
      code_challenge_method: url.searchParams.get('code_challenge_method') ?? 'S256',
      resource,
      scope: url.searchParams.get('scope') ?? 'account',
      state: url.searchParams.get('state') ?? '',
    },
  };
};

async function clientName(fetch: typeof globalThis.fetch, clientID: string): Promise<string> {
  const base = env.API_INTERNAL_URL ?? '';
  try {
    const res = await fetch(`${base}/api/v1/oauth/client?client_id=${encodeURIComponent(clientID)}`, {
      signal: AbortSignal.timeout(ssrTimeoutMs()),
    });
    if (!res.ok) return clientID;
    const body = (await res.json()) as { data?: { client_name?: string } };
    return body.data?.client_name || clientID;
  } catch {
    return clientID;
  }
}
