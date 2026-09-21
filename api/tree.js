import {
  ALLOWED_REPOS,
  ORG,
  githubFetch,
  isActiveOrgMember,
  jsonHeaders,
  optionsResponse,
  readJson,
  readSession,
  safeRepo,
  withCors,
} from '../lib.js';

export default async function handler(request) {
  if (request.method === 'OPTIONS') return optionsResponse(request);
  if (request.method !== 'GET') return new Response('Method Not Allowed', { status: 405, headers: withCors(request, { Allow: 'GET, OPTIONS' }) });

  try {
    const session = readSession(request);
    if (!(await isActiveOrgMember(session.ghToken))) {
      return new Response(JSON.stringify({ error: 'Organization membership is not active.' }), { status: 403, headers: withCors(request, jsonHeaders) });
    }
    const url = new URL(request.url);
    const repo = url.searchParams.get('repo');

    if (!safeRepo(repo) || !ALLOWED_REPOS.includes(repo)) {
      return new Response(JSON.stringify({ error: 'Repository is not allowed.' }), { status: 400, headers: withCors(request, jsonHeaders) });
    }

    // Git tree API accepts a branch/ref name and can recursively return files.
    const branch = 'main';
    const response = await githubFetch(
      `/repos/${encodeURIComponent(ORG)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
      session.ghToken,
    );
    const data = await readJson(response);

    if (response.status === 401) {
      return new Response(JSON.stringify({ error: 'GitHub session expired.' }), { status: 401, headers: withCors(request, jsonHeaders) });
    }
    if (!response.ok) {
      return new Response(JSON.stringify({ error: 'Repository is not accessible.' }), { status: 404, headers: withCors(request, jsonHeaders) });
    }

    const entries = Array.isArray(data?.tree) ? data.tree : [];
    const files = entries
      .filter((entry) => entry.type === 'blob')
      .filter((entry) => /\.(pdf|png|jpe?g|webp)$/i.test(entry.path))
      .map((entry) => ({
        path: entry.path,
        name: entry.path.split('/').pop(),
        size: entry.size ?? null,
        sha: entry.sha,
      }));

    return new Response(JSON.stringify({ repository: repo, files, truncated: Boolean(data?.truncated) }), {
      status: 200,
      headers: withCors(request, jsonHeaders),
    });
  } catch (error) {
    console.error('Tree error:', error);
    return new Response(JSON.stringify({ error: 'Unauthorized or repository lookup failed.' }), {
      status: 401,
      headers: withCors(request, jsonHeaders),
    });
  }
}
