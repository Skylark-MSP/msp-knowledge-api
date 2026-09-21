import { githubFetch, isActiveOrgMember, jsonHeaders, optionsResponse, readSession, withCors } from '../lib.js';

export default async function handler(request) {
  if (request.method === 'OPTIONS') return optionsResponse(request);
  if (request.method !== 'GET') return new Response('Method Not Allowed', { status: 405, headers: withCors(request, { Allow: 'GET, OPTIONS' }) });

  try {
    const session = readSession(request);
    const meResponse = await githubFetch('/user', session.ghToken);
    const me = await meResponse.json().catch(() => null);
    if (!meResponse.ok || !me?.login || !(await isActiveOrgMember(session.ghToken))) {
      return new Response(JSON.stringify({ error: 'GitHub session is no longer valid.' }), { status: 401, headers: withCors(request, jsonHeaders) });
    }

    return new Response(JSON.stringify({
      user: session.user,
      expires_at: session.exp,
    }), { status: 200, headers: withCors(request, jsonHeaders) });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Unauthorized.' }), { status: 401, headers: withCors(request, jsonHeaders) });
  }
}
