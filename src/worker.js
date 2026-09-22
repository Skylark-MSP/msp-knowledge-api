const GITHUB_API = 'https://api.github.com';
const GITHUB_API_VERSION = '2026-03-10';

const DEFAULT_REPOS = [
  'l1-knowledge-base',
  'l2-knowledge-base',
  'shared-knowledge-base',
];

const REPO_META = {
  'l1-knowledge-base': {
    title: 'L1 Support',
    subtitle: 'Standard operating procedures, monitoring and first-level troubleshooting.',
    icon: 'L1',
  },
  'l2-knowledge-base': {
    title: 'L2 Support',
    subtitle: 'Advanced infrastructure troubleshooting, engineering procedures and RCA.',
    icon: 'L2',
  },
  'shared-knowledge-base': {
    title: 'Shared Knowledge',
    subtitle: 'Common SOPs, incident management, monitoring standards and escalation guides.',
    icon: 'KB',
  },
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

function config(env) {
  return {
    org: env.GITHUB_ORG || 'Skylark-MSP',
    frontendUrl: (env.FRONTEND_URL || 'https://skylark-msp.github.io/msp-knowledge-hub/').replace(/\/$/, ''),
    frontendOrigin: env.FRONTEND_ORIGIN || 'https://skylark-msp.github.io',
    repos: (env.KB_REPOS || DEFAULT_REPOS.join(','))
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean),
  };
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const headers = {
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
  if (origin === config(env).frontendOrigin) {
    headers['Access-Control-Allow-Origin'] = origin;
  }
  return headers;
}

function withCors(response, request, env, extra = {}) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(request, env))) headers.set(k, v);
  for (const [k, v] of Object.entries(extra)) headers.set(k, v);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function options(request, env) {
  return new Response(null, { status: 204, headers: corsHeaders(request, env) });
}

function randomBytes(size) {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
}

function b64url(bytes) {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64urlToBytes(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  const str = atob(base64);
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i);
  return out;
}

function utf8(value) {
  return new TextEncoder().encode(value);
}

function text(bytes) {
  return new TextDecoder().decode(bytes);
}

async function importHmac(secretHex) {
  const bytes = hexToBytes(secretHex);
  return crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function importAes(secretHex) {
  const bytes = hexToBytes(secretHex);
  return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

function hexToBytes(hex) {
  if (!/^[0-9a-fA-F]{64}$/.test(hex || '')) throw new Error('Secret must be 64 hexadecimal characters.');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function sign(value, secretHex) {
  const key = await importHmac(secretHex);
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(value))));
}

async function secureRandomToken() {
  return b64url(randomBytes(32));
}

function parseCookies(request) {
  const raw = request.headers.get('Cookie') || '';
  const result = {};
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    result[key] = value;
  }
  return result;
}

function cookie(name, value, attrs = {}) {
  const parts = [`${name}=${value}`];
  if (attrs.maxAge !== undefined) parts.push(`Max-Age=${attrs.maxAge}`);
  if (attrs.path) parts.push(`Path=${attrs.path}`);
  if (attrs.httpOnly) parts.push('HttpOnly');
  if (attrs.secure) parts.push('Secure');
  if (attrs.sameSite) parts.push(`SameSite=${attrs.sameSite}`);
  return parts.join('; ');
}

async function encryptJson(payload, secretHex) {
  const key = await importAes(secretHex);
  const iv = randomBytes(12);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(JSON.stringify(payload))));
  return `${b64url(iv)}.${b64url(encrypted)}`;
}

async function decryptJson(token, secretHex) {
  const [ivPart, cipherPart] = String(token || '').split('.');
  if (!ivPart || !cipherPart) throw new Error('Invalid session.');
  const key = await importAes(secretHex);
  const iv = b64urlToBytes(ivPart);
  const ciphertext = b64urlToBytes(cipherPart);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(text(new Uint8Array(plain)));
}

async function createState(env) {
  const nonce = await secureRandomToken();
  const issued = Date.now().toString();
  const body = `${issued}.${nonce}`;
  const signature = await sign(body, env.STATE_SECRET_HEX);
  return `${body}.${signature}`;
}

async function verifyState(state, env, maxAgeMs = 10 * 60 * 1000) {
  try {
    const [issued, nonce, signature] = String(state || '').split('.');
    if (!issued || !nonce || !signature || !/^\d+$/.test(issued)) return false;
    const age = Date.now() - Number(issued);
    if (age < 0 || age > maxAgeMs) return false;
    const body = `${issued}.${nonce}`;
    const key = await importHmac(env.STATE_SECRET_HEX);
    return crypto.subtle.verify('HMAC', key, b64urlToBytes(signature), utf8(body));
  } catch {
    return false;
  }
}

async function githubFetch(path, token, init = {}) {
  const url = path.startsWith('http') ? path : `${GITHUB_API}${path}`;
  const headers = new Headers(init.headers || {});
  headers.set('Accept', headers.get('Accept') || 'application/vnd.github+json');
  headers.set('X-GitHub-Api-Version', GITHUB_API_VERSION);
  headers.set('User-Agent', 'Skylark-MSP-Knowledge-Hub');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return fetch(url, { ...init, headers });
}

async function readJson(response) {
  try { return await response.json(); } catch { return null; }
}

function redirect(url) {
  return new Response(null, { status: 302, headers: { Location: url } });
}

function redirectError(env, message) {
  const url = new URL(env.FRONTEND_URL || 'https://skylark-msp.github.io/msp-knowledge-hub/');
  url.searchParams.set('error', message);
  return redirect(url.toString());
}

function clearCookie() {
  return cookie('skylark_session', '', { maxAge: 0, path: '/', httpOnly: true, secure: true, sameSite: 'None' });
}

async function sessionCookie(session, maxAge) {
  return cookie('skylark_session', session, {
    maxAge: Math.max(60, Math.floor(maxAge / 1000)),
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'None',
  });
}

async function loadSession(request, env) {
  const cfg = config(env);
  const cookies = parseCookies(request);
  const token = cookies.skylark_session;
  if (!token) return { session: null, setCookie: null };

  let session = await decryptJson(token, env.SESSION_SECRET_HEX);
  if (!session?.ghToken || !session?.exp) throw new Error('Invalid session.');

  // Refresh the GitHub App user token when it is close to expiry.
  if (session.refreshToken && Number(session.exp) - Date.now() < 2 * 60 * 1000) {
    const refreshed = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'Skylark-MSP-Knowledge-Hub' },
      body: JSON.stringify({
        client_id: env.GITHUB_APP_CLIENT_ID,
        client_secret: env.GITHUB_APP_CLIENT_SECRET,
        grant_type: 'refresh_token',
        refresh_token: session.refreshToken,
      }),
    });
    const data = await readJson(refreshed);
    if (refreshed.ok && data?.access_token) {
      const expiresIn = Number(data.expires_in || 8 * 60 * 60);
      session = {
        ...session,
        ghToken: data.access_token,
        refreshToken: data.refresh_token || session.refreshToken,
        exp: Date.now() + expiresIn * 1000,
      };
      const encrypted = await encryptJson(session, env.SESSION_SECRET_HEX);
      return { session, setCookie: await sessionCookie(encrypted, expiresIn * 1000) };
    }
  }

  if (Date.now() >= Number(session.exp)) throw new Error('Session expired.');
  return { session, setCookie: null };
}

async function hasRepoAccess(token, org, repo) {
  const response = await githubFetch(`/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo)}`, token);
  if (!response.ok) return null;
  const data = await readJson(response);
  if (!data) return null;
  if (data.permissions && data.permissions.pull === false) return null;
  return data;
}

function repoMeta(repo) {
  return REPO_META[repo] || { title: repo, subtitle: '', icon: 'KB' };
}

function safeRepo(repo, cfg) {
  return typeof repo === 'string' && cfg.repos.includes(repo);
}

function safePath(path) {
  if (!path || typeof path !== 'string') return false;
  const normalized = path.replaceAll('\\', '/');
  if (normalized.startsWith('/') || normalized.includes('../') || normalized === '..') return false;
  return !normalized.includes('\0');
}

function isDocumentFile(path) {
  return /\.(pdf|md|txt|docx|png|jpe?g|webp)$/i.test(path);
}

async function login(request, env) {
  if (!env.GITHUB_APP_CLIENT_ID || !env.GITHUB_APP_CLIENT_SECRET || !env.STATE_SECRET_HEX || !env.SESSION_SECRET_HEX) {
    return new Response('GitHub App backend is not configured yet.', { status: 500 });
  }
  const state = await createState(env);
  const callback = new URL('/auth/callback', request.url).toString();
  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', env.GITHUB_APP_CLIENT_ID);
  url.searchParams.set('redirect_uri', callback);
  url.searchParams.set('state', state);
  // No additional scope is requested. GitHub App permissions are defined by the App installation.
  return new Response(null, {
    status: 302,
    headers: {
      Location: url.toString(),
      'Set-Cookie': cookie('skylark_oauth_state', state, {
        maxAge: 600,
        path: '/auth/callback',
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      }),
      'Cache-Control': 'no-store',
    },
  });
}

async function callback(request, env) {
  try {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const githubError = url.searchParams.get('error');
    if (githubError) return redirectError(env, `GitHub authorization was cancelled (${githubError}).`);

    const cookies = parseCookies(request);
    if (!state || !cookies.skylark_oauth_state || state !== cookies.skylark_oauth_state) {
      return redirectError(env, 'Authentication request was invalid or expired. Please sign in again.');
    }
    if (!(await verifyState(state, env))) {
      return redirectError(env, 'Authentication request was invalid or expired. Please sign in again.');
    }
    if (!code) return redirectError(env, 'GitHub did not return an authorization code.');

    const callbackUrl = new URL('/auth/callback', request.url).toString();
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'Skylark-MSP-Knowledge-Hub' },
      body: JSON.stringify({
        client_id: env.GITHUB_APP_CLIENT_ID,
        client_secret: env.GITHUB_APP_CLIENT_SECRET,
        code,
        redirect_uri: callbackUrl,
      }),
    });
    const token = await readJson(tokenResponse);
    if (!tokenResponse.ok || !token?.access_token) return redirectError(env, 'GitHub token exchange failed. Please try again.');

    const meResponse = await githubFetch('/user', token.access_token);
    const me = await readJson(meResponse);
    if (!meResponse.ok || !me?.login) return redirectError(env, 'Could not verify the GitHub account.');

    const membershipResponse = await githubFetch(`/user/memberships/orgs/${encodeURIComponent(config(env).org)}`, token.access_token);
    const membership = await readJson(membershipResponse);
    if (!membershipResponse.ok || membership?.state !== 'active') {
      return redirectError(env, `Your GitHub account is not an active member of ${config(env).org}.`);
    }

    const expiresIn = Number(token.expires_in || 8 * 60 * 60);
    const payload = {
      v: 1,
      iat: Date.now(),
      exp: Date.now() + expiresIn * 1000,
      ghToken: token.access_token,
      refreshToken: token.refresh_token || '',
      user: {
        id: me.id,
        login: me.login,
        name: me.name || me.login,
        avatar_url: me.avatar_url || '',
        html_url: me.html_url || '',
      },
    };
    const encrypted = await encryptJson(payload, env.SESSION_SECRET_HEX);
    return new Response(null, {
      status: 302,
      headers: {
        Location: `${config(env).frontendUrl}/`,
        'Set-Cookie': [
          await sessionCookie(encrypted, expiresIn * 1000),
          cookie('skylark_oauth_state', '', { maxAge: 0, path: '/auth/callback', httpOnly: true, secure: true, sameSite: 'Lax' }),
        ],
        'Cache-Control': 'no-store',
      },
    });
  } catch (error) {
    console.error('OAuth callback error', error);
    return redirectError(env, 'Authentication failed unexpectedly. Please try again.');
  }
}

async function apiMe(request, env) {
  try {
    const result = await loadSession(request, env);
    if (!result.session) return withCors(json({ authenticated: false }, 401), request, env);
    const response = json({ authenticated: true, user: result.session.user });
    return withCors(response, request, env, result.setCookie ? { 'Set-Cookie': result.setCookie } : {});
  } catch (error) {
    return withCors(json({ authenticated: false, error: error.message || 'Not authenticated.' }, 401), request, env, { 'Set-Cookie': clearCookie() });
  }
}

async function apiRepositories(request, env) {
  try {
    const result = await loadSession(request, env);
    if (!result.session) return withCors(json({ error: 'Not authenticated.' }, 401), request, env);
    const cfg = config(env);
    const repositories = [];
    for (const repo of cfg.repos) {
      const info = await hasRepoAccess(result.session.ghToken, cfg.org, repo);
      if (info) {
        repositories.push({
          name: repo,
          ...repoMeta(repo),
          default_branch: info.default_branch,
        });
      }
    }
    const response = json({ user: result.session.user, repositories });
    return withCors(response, request, env, result.setCookie ? { 'Set-Cookie': result.setCookie } : {});
  } catch (error) {
    return withCors(json({ error: error.message || 'Could not load repositories.' }, 401), request, env, { 'Set-Cookie': clearCookie() });
  }
}

async function apiTree(request, env, url) {
  try {
    const result = await loadSession(request, env);
    if (!result.session) return withCors(json({ error: 'Not authenticated.' }, 401), request, env);
    const cfg = config(env);
    const repo = url.searchParams.get('repo');
    if (!safeRepo(repo, cfg)) return withCors(json({ error: 'Invalid repository.' }, 400), request, env);

    const info = await hasRepoAccess(result.session.ghToken, cfg.org, repo);
    if (!info) return withCors(json({ error: 'Repository not accessible.' }, 403), request, env);

    const treeResponse = await githubFetch(
      `/repos/${encodeURIComponent(cfg.org)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(info.default_branch)}?recursive=1`,
      result.session.ghToken,
    );
    const tree = await readJson(treeResponse);
    if (!treeResponse.ok || !tree?.tree) return withCors(json({ error: 'Could not load repository tree.' }, 502), request, env);

    const files = tree.tree
      .filter((entry) => entry.type === 'blob' && isDocumentFile(entry.path))
      .map((entry) => ({
        path: entry.path,
        name: entry.path.split('/').pop(),
        size: entry.size || 0,
        sha: entry.sha,
      }));

    const response = json({ repository: repo, files, truncated: Boolean(tree.truncated) });
    return withCors(response, request, env, result.setCookie ? { 'Set-Cookie': result.setCookie } : {});
  } catch (error) {
    return withCors(json({ error: error.message || 'Could not load document tree.' }, 500), request, env);
  }
}

async function apiFile(request, env, url) {
  try {
    const result = await loadSession(request, env);
    if (!result.session) return withCors(json({ error: 'Not authenticated.' }, 401), request, env);
    const cfg = config(env);
    const repo = url.searchParams.get('repo');
    const path = url.searchParams.get('path');
    if (!safeRepo(repo, cfg) || !safePath(path) || !isDocumentFile(path)) {
      return withCors(json({ error: 'Invalid document request.' }, 400), request, env);
    }

    const info = await hasRepoAccess(result.session.ghToken, cfg.org, repo);
    if (!info) return withCors(json({ error: 'Repository not accessible.' }, 403), request, env);

    const contentResponse = await githubFetch(
      `/repos/${encodeURIComponent(cfg.org)}/${encodeURIComponent(repo)}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(info.default_branch)}`,
      result.session.ghToken,
      { headers: { Accept: 'application/vnd.github.raw+json' } },
    );
    if (!contentResponse.ok) return withCors(json({ error: 'Document could not be retrieved.' }, contentResponse.status === 404 ? 404 : 502), request, env);

    const headers = new Headers();
    headers.set('Content-Type', contentResponse.headers.get('Content-Type') || mime(path));
    headers.set('Content-Disposition', `inline; filename="${path.split('/').pop().replaceAll('"', '')}"`);
    headers.set('Cache-Control', 'private, no-store');
    if (result.setCookie) headers.set('Set-Cookie', result.setCookie);
    const response = new Response(contentResponse.body, { status: 200, headers });
    return withCors(response, request, env);
  } catch (error) {
    return withCors(json({ error: error.message || 'Could not retrieve document.' }, 500), request, env);
  }
}

function mime(path) {
  const lower = path.toLowerCase();
  if (lower.endsWith('.pdf')) return 'application/pdf';
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
  if (lower.endsWith('.webp')) return 'image/webp';
  if (lower.endsWith('.md')) return 'text/markdown; charset=utf-8';
  if (lower.endsWith('.txt')) return 'text/plain; charset=utf-8';
  if (lower.endsWith('.docx')) return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  return 'application/octet-stream';
}

function logout(request, env) {
  return withCors(new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': clearCookie() },
  }), request, env);
}

export default {
  async fetch(request, env) {
    try {
      if (request.method === 'OPTIONS') return options(request, env);
      const url = new URL(request.url);

      if (url.pathname === '/auth/login' && request.method === 'GET') return login(request, env);
      if (url.pathname === '/auth/callback' && request.method === 'GET') return callback(request, env);
      if (url.pathname === '/auth/logout' && request.method === 'POST') return logout(request, env);
      if (url.pathname === '/api/me' && request.method === 'GET') return apiMe(request, env);
      if (url.pathname === '/api/repositories' && request.method === 'GET') return apiRepositories(request, env);
      if (url.pathname === '/api/tree' && request.method === 'GET') return apiTree(request, env, url);
      if (url.pathname === '/api/file' && request.method === 'GET') return apiFile(request, env, url);

      return json({ error: 'Not found.' }, 404, corsHeaders(request, env));
    } catch (error) {
      console.error('Unhandled worker error', error);
      return json({ error: 'Internal server error.' }, 500, corsHeaders(request, env));
    }
  },
};
