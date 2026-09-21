import {
  ALLOWED_REPOS,
  githubFetch,
  isActiveOrgMember,
  jsonHeaders,
  optionsResponse,
  readJson,
  readSession,
  repoMeta,
  withCors,
} from '../lib.js';

async function getAccessibleRepos(token) {
  const results = await Promise.all(ALLOWED_REPOS.map(async (repo) => {
    const response = await githubFetch(`/repos/${encodeURIComponent(process.env.GITHUB_ORG || 'Skylark-MSP')}/${encodeURIComponent(repo)}`, token);
    if (!response.ok) return null;
    const data = await readJson(response);
    if (!data?.name) return null;
    return {
      name: data.name,
      full_name: data.full_name,
      private: Boolean(data.private),
      default_branch: data.default_branch || 'main',
      html_url: data.html_url,
      ...repoMeta(repo),
    };
  }));

  return results.filter(Boolean);
}

export default async function handler(request) {
  if (request.method === 'OPTIONS') return optionsResponse(request);
  if (request.method !== 'GET') return new Response('Method Not Allowed', { status: 405, headers: withCors(request, { Allow: 'GET, OPTIONS' }) });

  try {
    const session = readSession(request);
    if (!(await isActiveOrgMember(session.ghToken))) {
      return new Response(JSON.stringify({ error: 'Your GitHub account is not an active member of the Skylark-MSP organization.' }), { status: 403, headers: withCors(request, jsonHeaders) });
    }
    const repos = await getAccessibleRepos(session.ghToken);
    return new Response(JSON.stringify({ repositories: repos, user: session.user, expires_at: session.exp }), {
      status: 200,
      headers: withCors(request, jsonHeaders),
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Unauthorized.' }), {
      status: 401,
      headers: withCors(request, jsonHeaders),
    });
  }
}
