import {
  ALLOWED_REPOS,
  ORG,
  encodePath,
  isPreviewableFile,
  optionsResponse,
  readSession,
  safeFilePath,
  safeRepo,
  githubFetch,
  isActiveOrgMember,
  withCors,
} from '../lib.js';

function contentType(path) {
  if (/\.pdf$/i.test(path)) return 'application/pdf';
  if (/\.png$/i.test(path)) return 'image/png';
  if (/\.jpe?g$/i.test(path)) return 'image/jpeg';
  if (/\.webp$/i.test(path)) return 'image/webp';
  return 'application/octet-stream';
}

export default async function handler(request) {
  if (request.method === 'OPTIONS') return optionsResponse(request);
  if (request.method !== 'GET') return new Response('Method Not Allowed', { status: 405, headers: withCors(request, { Allow: 'GET, OPTIONS' }) });

  try {
    const session = readSession(request);
    if (!(await isActiveOrgMember(session.ghToken))) {
      return new Response('Forbidden.', { status: 403, headers: withCors(request) });
    }
    const url = new URL(request.url);
    const repo = url.searchParams.get('repo');
    const path = url.searchParams.get('path');

    if (!safeRepo(repo) || !ALLOWED_REPOS.includes(repo) || !safeFilePath(path) || !isPreviewableFile(path)) {
      return new Response('Not Found', { status: 404, headers: withCors(request) });
    }

    const range = request.headers.get('range');
    const headers = {};
    if (range) headers.Range = range;

    const response = await githubFetch(
      `/repos/${encodeURIComponent(ORG)}/${encodeURIComponent(repo)}/contents/${encodePath(path)}?ref=main`,
      session.ghToken,
      { accept: 'application/vnd.github.raw+json', headers },
    );

    if (!response.ok || !response.body) {
      const status = response.status === 401 ? 401 : response.status === 404 ? 404 : 502;
      return new Response(status === 404 ? 'Document not found.' : 'Document could not be retrieved.', {
        status,
        headers: withCors(request, { 'Cache-Control': 'no-store' }),
      });
    }

    const responseHeaders = withCors(request, {
      'Content-Type': contentType(path),
      'Content-Disposition': `inline; filename="${encodeURIComponent(path.split('/').pop())}"`,
      'Cache-Control': 'private, no-store',
      'X-Content-Type-Options': 'nosniff',
    });

    if (response.headers.get('content-length')) responseHeaders['Content-Length'] = response.headers.get('content-length');
    if (response.headers.get('content-range')) responseHeaders['Content-Range'] = response.headers.get('content-range');
    if (response.headers.get('accept-ranges')) responseHeaders['Accept-Ranges'] = response.headers.get('accept-ranges');

    return new Response(response.body, { status: response.status, headers: responseHeaders });
  } catch (error) {
    console.error('File error:', error);
    return new Response('Unauthorized.', { status: 401, headers: withCors(request) });
  }
}
